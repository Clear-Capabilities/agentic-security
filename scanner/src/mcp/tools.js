// MCP tool implementations — PRD Feature 2, hardened against the OWASP MCP
// Top 10 (see ./redact.js, ./audit.js, ./server.js for sibling controls).
//
// Trust model:
//   - Session root fixed at server boot. No per-call retargeting.
//   - Path arguments lstat-checked (symlinks refused, OWASP MCP05) and
//     realpath-confined to session root.
//   - Tool outputs marked _meta.untrusted_excerpts:true (OWASP MCP03/MCP06)
//     because they may contain text from scanned files, which is adversary-
//     controlled in any context where the agent might read malicious code.
//   - Secret-shaped strings redacted on the way out (OWASP MCP01/MCP10).
//   - `apply_fix` requires confirm:true, valid HMAC signature on
//     last-scan.json, non-shadow finding, and confined file path.

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { applyFix as applyFixHistory, fixAcceptanceRate } from '../posture/fix-history.js';
import { verifyLastScan } from '../posture/integrity.js';
import { redactString, redactFinding } from './redact.js';

// Lazy-loaded: these transitively pull in npm packages (fast-glob,
// @babel/core) that aren't available in the plugin-cache install path
// (no node_modules). Deferring keeps the MCP server bootable everywhere;
// the import only runs when a tool that needs them is actually called.
let _runScan;
async function getRunScan() {
  if (!_runScan) _runScan = (await import('../runScan.js')).runScan;
  return _runScan;
}
let _verifyFixCore;
async function getVerifyFixCore() {
  if (!_verifyFixCore) _verifyFixCore = (await import('../posture/fix-verify.js')).verifyFix;
  return _verifyFixCore;
}

const MAX_FILES_PER_SCAN = 1024;
const MAX_FILE_BYTES = 500_000;
const MAX_TOTAL_SCAN_BYTES = 50_000_000;
const META = { source: 'agentic-security-mcp', untrusted_excerpts: true };

// OWASP A01 — refuse writes to paths that could subvert the security tool
// itself or the host's source-control / dependency state. A forged finding
// could otherwise tell apply_fix to overwrite our own rules.yml, our audit
// log, a .git/hooks/post-commit payload, a CI workflow, an IaC file, or a
// dependency manifest (premortem #3 expansion).
//
// Two kinds of guard:
//   - DIR-prefix matches anywhere under one of these directories
//   - FILE-suffix matches any path whose basename ends with one of these
const RESERVED_WRITE_PREFIXES = [
  '.git/',
  '.github/',
  '.gitlab/',
  '.circleci/',
  '.buildkite/',
  '.agentic-security/',
  'node_modules/',
  '.terraform/',
  '.aws/',
  'k8s/',
  'kubernetes/',
];
const RESERVED_WRITE_BASENAMES = new Set([
  'Dockerfile',
  'Jenkinsfile',
  '.gitlab-ci.yml',
  '.gitlab-ci.yaml',
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'pyproject.toml',
  'Pipfile',
  'Pipfile.lock',
  'poetry.lock',
  'requirements.txt',
  'go.mod',
  'go.sum',
  'Cargo.toml',
  'Cargo.lock',
  'composer.json',
  'composer.lock',
  'Gemfile',
  'Gemfile.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
]);
const RESERVED_WRITE_SUFFIXES = [
  '.tf',
  '.tfvars',
  'docker-compose.yml',
  'docker-compose.yaml',
];
function _isReservedWritePath(sessionRoot, absFile) {
  // Resolve sessionRoot symlinks so the relative path is computed against
  // the same canonical root as `absFile` (which _confine already realpath'd).
  // On macOS /tmp → /private/tmp; without this normalization the relative
  // would contain "../" and the prefix check would miss the reserved path.
  const rootReal = fs.realpathSync(path.resolve(sessionRoot));
  const rel = path.relative(rootReal, absFile).replace(/\\/g, '/');
  if (RESERVED_WRITE_PREFIXES.some(p => rel === p.replace(/\/$/, '') || rel.startsWith(p))) return true;
  const base = rel.split('/').pop() || '';
  if (RESERVED_WRITE_BASENAMES.has(base)) return true;
  if (RESERVED_WRITE_SUFFIXES.some(s => base === s || base.endsWith(s))) return true;
  return false;
}

// LangChain harness-anatomy recommendation: the filesystem is the right
// collaboration / scratchpad surface for subagents. We carve out one writable
// directory inside the otherwise-reserved `.agentic-security/` tree —
// `.agentic-security/agent-scratchpad/<agent>/<session>/` — and expose
// `append_scratchpad` / `read_scratchpad` for in-progress agent state.
//
// Confinement rules:
//   - relative path required (no absolute / no `..`)
//   - must start with `agent-scratchpad/<agent>/<session>/`
//   - `<agent>` and `<session>` are restricted to `[A-Za-z0-9_.-]{1,64}`
//     (no slashes — keeps the prefix exactly three components deep)
//   - file basename: same charset rules
//   - max scratchpad bytes per file: SCRATCHPAD_MAX_FILE_BYTES
const SCRATCHPAD_PREFIX = '.agentic-security/agent-scratchpad/';
const SCRATCHPAD_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const SCRATCHPAD_MAX_FILE_BYTES = 2 * 1024 * 1024;   // 2 MB per file
const SCRATCHPAD_MAX_TOTAL_BYTES = 50 * 1024 * 1024; // 50 MB per scan root

function _validateScratchpadPath(relPath) {
  if (typeof relPath !== 'string' || !relPath.length) {
    return { ok: false, reason: 'path: not a string' };
  }
  if (path.isAbsolute(relPath)) return { ok: false, reason: 'path: must be relative' };
  if (relPath.includes('..')) return { ok: false, reason: 'path: must not contain ..' };
  const normalized = relPath.replace(/\\/g, '/');
  if (!normalized.startsWith(SCRATCHPAD_PREFIX)) {
    return { ok: false, reason: `path: must start with "${SCRATCHPAD_PREFIX}"` };
  }
  const rest = normalized.slice(SCRATCHPAD_PREFIX.length);
  const parts = rest.split('/');
  if (parts.length < 3) {
    return { ok: false, reason: 'path: must be agent-scratchpad/<agent>/<session>/<file>' };
  }
  const [agent, session, ...fileParts] = parts;
  if (!SCRATCHPAD_NAME_RE.test(agent)) return { ok: false, reason: `path: agent name "${agent}" not in [A-Za-z0-9_.-]{1,64}` };
  if (!SCRATCHPAD_NAME_RE.test(session)) return { ok: false, reason: `path: session id "${session}" not in [A-Za-z0-9_.-]{1,64}` };
  for (const p of fileParts) {
    if (!SCRATCHPAD_NAME_RE.test(p)) return { ok: false, reason: `path: file part "${p}" not in [A-Za-z0-9_.-]{1,64}` };
  }
  return { ok: true, agent, session, fileParts };
}

function _scratchpadAbs(sessionRoot, relPath) {
  return path.resolve(sessionRoot, relPath.replace(/\\/g, '/'));
}

function _scratchpadTotalBytes(sessionRoot) {
  const base = path.join(sessionRoot, '.agentic-security', 'agent-scratchpad');
  if (!fs.existsSync(base)) return 0;
  let total = 0;
  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const fp = path.join(dir, e.name);
      try {
        if (e.isFile()) { total += fs.statSync(fp).size; }
        else if (e.isDirectory()) walk(fp);
      } catch { /* skip */ }
    }
  };
  walk(base);
  return total;
}

// ─── Path confinement ────────────────────────────────────────────────────────
// Lexical check + lstat symlink reject + realpath re-check. OWASP MCP05.
//
// For non-existent paths (apply_fix to a new file is a possible legitimate
// case; in practice we re-check existence at the use-site) we walk up the
// deepest existing ancestor and realpath that, so a parent-symlink can't
// silently relocate writes.
function _confine(sessionRoot, candidate, label) {
  if (typeof candidate !== 'string' || !candidate) throw new Error(`${label}: not a string`);
  const rootReal = fs.realpathSync(path.resolve(sessionRoot));
  const abs = path.isAbsolute(candidate) ? candidate : path.resolve(rootReal, candidate);

  // Lexical pre-check: rejects "../../etc/passwd" before any fs call.
  const relLex = path.relative(rootReal, path.resolve(abs));
  if (relLex === '' || relLex.startsWith('..') || path.isAbsolute(relLex)) {
    throw new Error(`${label}: path "${candidate}" escapes session root`);
  }

  // If the path exists, the leaf must not be a symlink and its realpath
  // must still be under rootReal.
  if (fs.existsSync(abs)) {
    if (fs.lstatSync(abs).isSymbolicLink()) {
      throw new Error(`${label}: path "${candidate}" is a symbolic link (refused)`);
    }
    const real = fs.realpathSync(abs);
    if (path.relative(rootReal, real).startsWith('..')) {
      throw new Error(`${label}: path "${candidate}" resolves outside session root via symlink`);
    }
    return real;
  }

  // Path doesn't exist — walk up to the deepest existing ancestor and
  // realpath that. If a parent dir is a symlink pointing outside rootReal
  // we catch it here.
  let parent = path.dirname(abs);
  while (parent !== path.dirname(parent) && !fs.existsSync(parent)) {
    parent = path.dirname(parent);
  }
  const parentReal = fs.realpathSync(parent);
  if (path.relative(rootReal, parentReal).startsWith('..')) {
    throw new Error(`${label}: path "${candidate}" parent resolves outside session root`);
  }
  const suffix = path.relative(parent, abs);
  return path.resolve(parentReal, suffix);
}

function _readLastScanVerified(sessionRoot, { allowUnsigned = false } = {}) {
  const stateDir = path.join(sessionRoot, '.agentic-security');
  const scanFile = path.join(stateDir, 'last-scan.json');
  const sigFile = scanFile + '.sig';
  if (!fs.existsSync(scanFile)) return { scan: null, status: 'missing' };
  const body = fs.readFileSync(scanFile, 'utf8');
  const ok = verifyLastScan(body, sigFile);
  if (ok === false) return { scan: null, status: 'tampered' };
  if (ok === null && !allowUnsigned) return { scan: null, status: 'unsigned' };
  let parsed;
  try { parsed = JSON.parse(body); }
  catch { return { scan: null, status: 'unparseable' }; }
  return { scan: parsed, status: ok ? 'verified' : 'unsigned' };
}

function _findById(scan, id) {
  if (!scan) return null;
  return (scan.findings || []).find(f => f.id === id)
      || (scan.secrets || []).find(f => f.id === id)
      || (scan.supplyChain || []).find(f => f.id === id)
      || (scan.logicVulns || []).find(f => f.id === id)
      || null;
}

// ─── Tool-output offloading (harness-anatomy #1) ────────────────────────────
// LangChain post: "the harness keeps the head and tail tokens of tool outputs
// above a threshold number of tokens and offloads the full output to the
// filesystem." We apply this to any MCP tool response whose findings array
// exceeds OFFLOAD_THRESHOLD entries: write the full list to a scratchpad
// file, return only head[0..3] + tail[-2..] + total + path. The agent can
// call `read_scratchpad(path)` to page through the rest.
//
// Design choices:
//   - Threshold is conservative (10) — anything bigger than a casual UI page
//     gets offloaded. Tunable via $AGENTIC_SECURITY_MCP_OFFLOAD_THRESHOLD.
//   - Offload location is the agent-scratchpad (not a separate dir) so the
//     same cleanup + size caps apply.
//   - File names are deterministic per response (sha256 of JSON.stringify)
//     so two identical responses share the same offload file.
//   - The session id is process.pid + boot timestamp short hash — collides
//     only across restarts within a millisecond, which is fine for cache.
const OFFLOAD_THRESHOLD = (() => {
  const v = parseInt(process.env.AGENTIC_SECURITY_MCP_OFFLOAD_THRESHOLD || '10', 10);
  return Number.isFinite(v) && v >= 1 ? v : 10;
})();
const MCP_SESSION_ID = `${process.pid}-${Date.now().toString(36).slice(-6)}`;

function _maybeOffload(sessionRoot, toolName, items) {
  if (!Array.isArray(items) || items.length <= OFFLOAD_THRESHOLD) {
    return { offloaded: false, items, total: items.length };
  }
  const head = items.slice(0, 3);
  const tail = items.slice(-2);
  const json = JSON.stringify({ tool: toolName, total: items.length, items }, null, 2);
  const hashShort = crypto.createHash('sha256').update(json).digest('hex').slice(0, 10);
  const rel = `.agentic-security/agent-scratchpad/mcp-offload/${MCP_SESSION_ID}/${toolName}-${hashShort}.json`;
  const abs = path.resolve(sessionRoot, rel);
  try {
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, json);
  } catch (e) {
    // If we can't write to disk for some reason, fall back to returning
    // everything — the alternative would be silently dropping data, which
    // is worse than blowing the context.
    return { offloaded: false, items, total: items.length, offloadError: e.message };
  }
  return {
    offloaded: true,
    head, tail, total: items.length,
    scratchpadPath: rel,
    pagingHint: `call read_scratchpad({ path: "${rel}", offset, limit }) to page through; the file is { tool, total, items: [...] } JSON`,
  };
}

// ─── scan_diff ───────────────────────────────────────────────────────────────
export const scan_diff = {
  name: 'scan_diff',
  description: 'Scan a list of files for security findings. Use BEFORE writing a Write/Edit to disk so the agent can self-correct. Returns findings with severity, file:line, title, remediation. Snippets are redacted of obvious secret patterns. Paths confined to the session root; symlinks are refused.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      files: {
        type: 'array', minItems: 1, maxItems: MAX_FILES_PER_SCAN,
        items: { type: 'string', minLength: 1, maxLength: 4096 },
      },
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
    },
    required: ['files'],
  },
  async handler({ files, severity }, ctx) {
    const sessionRoot = ctx.sessionRoot;
    const abs = files.map(f => _confine(sessionRoot, f, 'files[]'));

    const fileContents = {};
    let totalBytes = 0;
    for (const a of abs) {
      let stat;
      try { stat = fs.statSync(a); } catch { continue; }
      if (!stat.isFile()) continue;
      if (stat.size > MAX_FILE_BYTES) continue;
      totalBytes += stat.size;
      if (totalBytes > MAX_TOTAL_SCAN_BYTES) {
        throw new Error(`scan_diff: total scan size exceeds ${MAX_TOTAL_SCAN_BYTES} bytes`);
      }
      let content;
      try { content = fs.readFileSync(a, 'utf8'); } catch { continue; }
      const rel = path.relative(sessionRoot, a).replace(/\\/g, '/');
      fileContents[rel] = content;
    }

    const runScan = await getRunScan();
    const result = await runScan(sessionRoot, { network: false, fileContents });
    const wantSet = new Set(Object.keys(fileContents));
    const sevRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const min = sevRank[severity] ?? 0;
    const findings = (result.scan.findings || [])
      .filter(f => wantSet.has(String(f.file || '').replace(/\\/g, '/')) && (sevRank[f.severity] ?? 0) >= min)
      .map(f => redactFinding({
        id: f.id, severity: f.severity, file: f.file, line: f.line,
        title: f.title || f.vuln, cwe: f.cwe,
        description: f.description, remediation: f.remediation,
      }));
    // Harness-anatomy #1: offload when the result exceeds OFFLOAD_THRESHOLD.
    // The agent gets a head+tail preview plus a path it can page through;
    // the full finding list lives on disk. This is the documented fix for
    // "context rot" — large tool outputs eat the model's attention budget.
    const off = _maybeOffload(sessionRoot, 'scan_diff', findings);
    if (off.offloaded) {
      return {
        _meta: META,
        scannedFiles: Object.keys(fileContents).length,
        findingCount: off.total,
        offloaded: true,
        head: off.head, tail: off.tail,
        scratchpadPath: off.scratchpadPath,
        pagingHint: off.pagingHint,
      };
    }
    return {
      _meta: META,
      scannedFiles: Object.keys(fileContents).length,
      findingCount: findings.length,
      findings,
    };
  },
};

// ─── query_taint ─────────────────────────────────────────────────────────────
export const query_taint = {
  name: 'query_taint',
  description: 'Query whether the last verified scan found a taint path involving a given source and sink. Paginated — returns up to `limit` matches (default 10, max 50) starting at `offset` (default 0); set `truncated:true` and `totalMatches` tell you when to page.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      source: { type: 'string', minLength: 1, maxLength: 256 },
      sink: { type: 'string', minLength: 1, maxLength: 256 },
      limit: { type: 'integer', minimum: 1, maximum: 50 },
      offset: { type: 'integer', minimum: 0, maximum: 10000 },
    },
    required: ['source', 'sink'],
  },
  async handler({ source, sink, limit, offset }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
    if (!scan) {
      return { _meta: META, hasResult: false, status, message: `No usable scan state (${status}).` };
    }
    const lim = Number.isInteger(limit) ? Math.min(50, Math.max(1, limit)) : 10;
    const off = Number.isInteger(offset) ? Math.max(0, offset) : 0;
    const srcL = String(source).toLowerCase();
    const sinkL = String(sink).toLowerCase();
    // Filter first (cheap), then paginate (so totalMatches is accurate).
    // Harness-engineering note (post-derived): "context window != context
    // attention." Returning hundreds of matches to the agent in one shot
    // dilutes its reasoning; the agent receives a bounded slice plus the
    // cursor to fetch the rest if it wants.
    const all = (scan.findings || []).filter(f => {
      const hay = [f.description, f.title, f.vuln, f.snippet, JSON.stringify(f.trace || '')].join(' ').toLowerCase();
      return hay.includes(srcL) && hay.includes(sinkL);
    });
    const page = all.slice(off, off + lim).map(f => redactFinding({
      id: f.id, severity: f.severity, file: f.file, line: f.line,
      title: f.title || f.vuln, description: f.description,
      trace: f.trace || null,
    }));
    return {
      _meta: META,
      hasResult: true,
      integrity: status,
      scanStartedAt: scan.startedAt || scan.meta?.startedAt || null,
      totalMatches: all.length,
      matchCount: page.length,
      offset: off,
      limit: lim,
      truncated: off + page.length < all.length,
      nextOffset: off + page.length < all.length ? off + page.length : null,
      matches: page,
    };
  },
};

// ─── explain_finding ─────────────────────────────────────────────────────────
export const explain_finding = {
  name: 'explain_finding',
  description: 'Return full details for a single finding from the last verified scan. Snippet/description redacted of secret patterns.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
    },
    required: ['finding_id'],
  },
  async handler({ finding_id }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
    if (!scan) throw new Error(`No usable scan state (${status}).`);
    const f = _findById(scan, finding_id);
    if (!f) throw new Error(`Finding not found: ${finding_id}`);
    const redacted = redactFinding({
      id: f.id, severity: f.severity, file: f.file, line: f.line,
      title: f.title || f.vuln, cwe: f.cwe,
      description: f.description, remediation: f.remediation,
      snippet: f.snippet || null,
      trace: f.trace || null,
    });
    // Harness-anatomy #1: explain_finding's trace is the most-likely-large
    // field on a single finding. Offload when it crosses the threshold so
    // the agent gets a head/tail preview, not a 50-step trace dumped into
    // its context.
    let traceTrimmed = redacted.trace;
    let traceMeta = null;
    if (Array.isArray(redacted.trace) && redacted.trace.length > OFFLOAD_THRESHOLD) {
      const off = _maybeOffload(ctx.sessionRoot, 'explain_finding-trace', redacted.trace);
      if (off.offloaded) {
        traceTrimmed = [...off.head, { _gap: `... ${off.total - off.head.length - off.tail.length} more steps elided; read scratchpad ...` }, ...off.tail];
        traceMeta = {
          totalSteps: off.total,
          scratchpadPath: off.scratchpadPath,
          pagingHint: off.pagingHint,
        };
      }
    }
    return {
      _meta: META,
      ...redacted,
      trace: traceTrimmed,
      traceOffload: traceMeta,
      confidence: f.confidence ?? null,
      hasReplacementFix: typeof f.fix?.replacement === 'string',
      integrity: status,
      // Risk-signal passthrough so agents can decide priority without
      // re-reading last-scan.json or re-fetching OSV/KEV/EPSS. compositeRisk
      // is the canonical sort key; the other fields are its provenance.
      compositeRisk: f.compositeRisk ?? null,
      compositeRiskTier: f.compositeRiskTier ?? null,
      compositeRiskFactors: Array.isArray(f.compositeRiskFactors) ? f.compositeRiskFactors : [],
      exploitability: f.exploitability ?? null,
      exploitabilityTier: f.exploitabilityTier ?? null,
      mitigationVerdict: f.mitigationVerdict ?? null,
      kev: !!(f.kev || f.kevListed || f.weaponized),
      epssScore: typeof f.epssScore === 'number' ? f.epssScore : null,
      epssPercentile: typeof f.epssPercentile === 'number' ? f.epssPercentile : null,
      exploitedNow: !!f.exploitedNow,
    };
  },
};

// ─── apply_fix ───────────────────────────────────────────────────────────────
export const apply_fix = {
  name: 'apply_fix',
  description: 'Apply the stored replacement fix for a finding. Refuses if last-scan.json fails its HMAC check, if the finding is shadow-marked, or if its file path escapes the session root via lexical traversal OR a symlink. Requires confirm:true. Supports dry_run:true to preview without writing.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
      confirm: { type: 'boolean' },
      dry_run: { type: 'boolean' },
    },
    required: ['finding_id', 'confirm'],
  },
  async handler({ finding_id, confirm, dry_run = false }, ctx) {
    if (confirm !== true) {
      return { _meta: META, applied: false, reason: 'apply_fix requires confirm: true.' };
    }
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: false });
    if (!scan) {
      return { _meta: META, applied: false, reason: `last-scan.json failed integrity check: ${status}. Run a fresh scan.` };
    }
    const f = _findById(scan, finding_id);
    if (!f) return { _meta: META, applied: false, reason: `Finding not found: ${finding_id}` };
    if (f._shadow === true) {
      return { _meta: META, applied: false, reason: 'shadow findings cannot be auto-applied' };
    }
    if (typeof f.fix?.replacement !== 'string') {
      // Premortem #2: templates are patch-shaped text. Same reasoning as
      // the replacement path — do NOT pass through redactString here.
      return {
        _meta: META, applied: false,
        reason: 'No full replacement available — only a template. Apply the template manually.',
        template: f.fix?.code || '',
        file: f.file, line: f.line,
      };
    }
    let absFile;
    try { absFile = _confine(ctx.sessionRoot, f.file, 'finding.file'); }
    catch (e) {
      return { _meta: META, applied: false, reason: `path-escape refused: ${e.message}` };
    }
    if (_isReservedWritePath(ctx.sessionRoot, absFile)) {
      return { _meta: META, applied: false, reason: `reserved path refused: writes to .git/, .agentic-security/, or node_modules/ are not permitted via apply_fix` };
    }
    if (!fs.existsSync(absFile)) {
      return { _meta: META, applied: false, reason: `File not found: ${absFile}` };
    }
    const originalContent = await fsp.readFile(absFile, 'utf8');

    if (dry_run) {
      return {
        _meta: META,
        applied: false, dryRun: true,
        file: f.file,
        originalSize: originalContent.length,
        newSize: f.fix.replacement.length,
        diffSummary: `${originalContent.length} → ${f.fix.replacement.length} bytes`,
      };
    }

    let entry;
    try {
      entry = await applyFixHistory({
        scanRoot: ctx.sessionRoot,
        file: f.file,
        originalContent,
        newContent: f.fix.replacement,
        findingId: f.id,
        stableId: f.stableId || null,   // premortem 4R-8
        ruleId: f.rule || null,
        vuln: f.vuln || f.title || null,
      });
    } catch (e) {
      // Harness-engineering: step-budget refusal (post-derived). The
      // deterministic layer enforces at-most-N attempts per stableId. When
      // exceeded, surface it as a structured `budget-exceeded` outcome the
      // agent can recognize — not a generic error.
      if (e && e.name === 'FixAttemptBudgetExceededError') {
        return {
          _meta: META,
          applied: false,
          reason: `budget-exceeded: ${e.message}`,
          budgetExceeded: true,
          attempts: e.attempts,
          maxAttempts: e.max,
          key: e.key,
        };
      }
      throw e;
    }
    // R25 (PRD §5): surface the running auto-fix acceptance rate after each
    // applied fix, so the closed loop reports its own success metric.
    let acceptance = null;
    try { acceptance = fixAcceptanceRate(ctx.sessionRoot); } catch { /* metric is best-effort */ }
    return { _meta: META, applied: true, historyId: entry.id, file: f.file, backupPath: entry.backupPath, integrity: status, attemptOrdinal: entry.attemptOrdinal, acceptance };
  },
};

// ─── verify_fix ──────────────────────────────────────────────────────────────
// Closed-loop verification of a proposed patch BEFORE the agent applies it.
// Re-scans the patched files in-memory (no disk write), confirms the original
// stableId is gone, and runs the project's existing linter on the patched
// files. Returns a structured verdict the agent can use to decide whether to
// proceed with apply_fix.
export const verify_fix = {
  name: 'verify_fix',
  description: 'Verify a proposed patch before applying. Re-scans the patched files in memory and runs the project linter. Returns { ok, rescan, lint, summary }. No filesystem writes.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      stable_id: { type: 'string', minLength: 8, maxLength: 64 },
      files: {
        type: 'object',
        additionalProperties: { type: 'string', maxLength: 500_000 },
        minProperties: 1,
        maxProperties: 8,
      },
    },
    required: ['stable_id', 'files'],
  },
  async handler({ stable_id, files }, ctx) {
    // Confine every file path before passing to the verifier.
    const confined = {};
    for (const [relPath, content] of Object.entries(files || {})) {
      try {
        _confine(ctx.sessionRoot, relPath, 'files key');
      } catch (e) {
        return { _meta: META, ok: false, reason: `path-escape refused: ${e.message}` };
      }
      confined[relPath] = String(content);
    }
    try {
      const verifyFixCore = await getVerifyFixCore();
      const r = await verifyFixCore({
        scanRoot: ctx.sessionRoot,
        originalFindingStableId: stable_id,
        files: confined,
      });
      return {
        _meta: META,
        ok: r.ok,
        rescan: { ok: r.rescan.ok, reason: r.rescan.reason, introduced: r.rescan.introduced || [] },
        lint: { runner: r.lint.runner, ok: r.lint.ok, skipped: r.lint.skipped || false, output: redactString(r.lint.output || '').slice(0, 1500) },
        summary: r.summary,
      };
    } catch (e) {
      return { _meta: META, ok: false, reason: `verify_fix failed: ${e.message}` };
    }
  },
};

// ─── synthesize_fix ──────────────────────────────────────────────────────────
// Return the stored fix replacement + regression-test scaffold for a finding,
// WITHOUT applying anything. The agent can call verify_fix → apply_fix in
// sequence with the returned blob.
export const synthesize_fix = {
  name: 'synthesize_fix',
  description: 'Return the stored fix replacement for a finding (replacement text + remediation + plan if the patch is too large). Read-only; never writes to disk. Use verify_fix → apply_fix to deploy.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
    },
    required: ['finding_id'],
  },
  async handler({ finding_id }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: false });
    if (!scan) {
      return { _meta: META, ok: false, reason: `last-scan.json failed integrity check: ${status}` };
    }
    const f = _findById(scan, finding_id);
    if (!f) return { _meta: META, ok: false, reason: `Finding not found: ${finding_id}` };
    if (f._shadow === true) return { _meta: META, ok: false, reason: 'shadow findings have no synthesized fix' };
    const fix = f.fix || {};
    const hasReplacement = typeof fix.replacement === 'string' && fix.replacement.length > 0;
    // Patch bounds: count files touched + LoC delta.
    let touchedFiles = 1;
    let locDelta = 0;
    if (hasReplacement) {
      let orig = '';
      try {
        const abs = _confine(ctx.sessionRoot, f.file, 'finding.file');
        orig = fs.readFileSync(abs, 'utf8');
      } catch { /* ignore — counts will reflect new-only LoC */ }
      locDelta = Math.abs(fix.replacement.split('\n').length - orig.split('\n').length);
    }
    const oversized = touchedFiles > 3 || locDelta > 100;
    // Premortem #2: `replacement` is a *patch* (the code we'll write to disk),
    // not a finding excerpt. Running it through redactString silently corrupts
    // valid patches whose content happens to match a secret-shape (e.g. a
    // placeholder like `password = "loadFromEnv"`). Patches MUST pass through
    // verbatim. Snippet/description/etc. continue to be redacted in
    // explain_finding / scan_diff — that's the right surface for redaction.
    return {
      _meta: META,
      ok: true,
      stable_id: f.stableId || null,
      file: f.file, line: f.line,
      vuln: f.vuln,
      severity: f.severity,
      hasReplacement,
      replacement: hasReplacement ? fix.replacement : null,
      template: fix.code || null,
      remediation: typeof fix.description === 'string' ? fix.description : (typeof fix === 'string' ? fix : null),
      patchBounds: { touchedFiles, locDelta, oversized },
      recommendsFixPlan: oversized && !hasReplacement,
    };
  },
};

// ─── find_rule_module ───────────────────────────────────────────────────────
// Codebase-navigation helper (C.6). Answers "which file under scanner/src/
// implements the detector for CWE-X / family Y" by scanning the SAST and
// posture sources for `cwe:` / `family:` literals. Cheaper and more reliable
// than asking the agent to grep — premortem note: "grep for a common function
// name in a large codebase returns thousands of matches."
//
// Read-only; no findings consumed. Output is a list of file paths + the
// matching literal lines so the agent can verify before editing.
export const find_rule_module = {
  name: 'find_rule_module',
  description: 'Find the file(s) under scanner/src/{sast,posture}/ that emit findings for a given CWE id or family name. Use BEFORE editing a rule — answers "where is the SQL-injection detector?" without grepping the whole tree. Returns at most 20 hits; refine the query if too broad.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      cwe: { type: 'string', minLength: 5, maxLength: 16 },
      family: { type: 'string', minLength: 2, maxLength: 64 },
    },
  },
  async handler({ cwe, family }, ctx) {
    if (!cwe && !family) {
      return { _meta: META, ok: false, reason: 'provide cwe (e.g. "CWE-89") or family (e.g. "sql-injection")' };
    }
    // Pattern enforcement — the mini-schema validator doesn't do `pattern`.
    if (cwe && !/^CWE-\d+$/.test(cwe)) {
      return { _meta: META, ok: false, reason: 'cwe must match /^CWE-\\d+$/ (e.g. "CWE-89")' };
    }
    if (family && !/^[a-z][a-z0-9-]+$/.test(family)) {
      return { _meta: META, ok: false, reason: 'family must match /^[a-z][a-z0-9-]+$/ (e.g. "sql-injection")' };
    }
    const sessionRoot = ctx.sessionRoot;
    const roots = [
      path.join(sessionRoot, 'scanner', 'src', 'sast'),
      path.join(sessionRoot, 'scanner', 'src', 'posture'),
    ];
    const hits = [];
    const cweLit = cwe ? new RegExp(`['"\`]${cwe.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"\`]`) : null;
    // Family match is broader on purpose: detectors often emit findings
    // without an explicit `family:` field (it's backfilled by
    // posture/finding-defaults.js). We match the family literal anywhere in
    // the file (vuln-name strings, comments, ids) so e.g. searching for "csrf"
    // surfaces sast/csrf.js even though it doesn't tag findings with the field.
    const famLit = family ? new RegExp(`\\b${family.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/-/g, '[-_ ]?')}\\b`, 'i') : null;
    // Also try a filename-stem match when only family is given.
    const famFilename = family ? family.toLowerCase() : null;
    for (const root of roots) {
      if (!fs.existsSync(root)) continue;
      let entries;
      try { entries = fs.readdirSync(root); } catch { continue; }
      for (const entry of entries) {
        if (!entry.endsWith('.js')) continue;
        const abs = path.join(root, entry);
        let stat;
        try { stat = fs.statSync(abs); } catch { continue; }
        if (!stat.isFile() || stat.size > MAX_FILE_BYTES) continue;
        let body;
        try { body = fs.readFileSync(abs, 'utf8'); } catch { continue; }
        const lines = body.split('\n');
        const matches = [];
        const stem = entry.replace(/\.js$/, '').toLowerCase();
        const filenameMatchesFamily = famFilename && (stem === famFilename || stem.includes(famFilename));
        if (filenameMatchesFamily) {
          matches.push({ line: 1, text: `<filename "${entry}" matches family>`, kind: 'filename' });
        }
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (cweLit && cweLit.test(line)) matches.push({ line: i + 1, text: line.trim().slice(0, 200), kind: 'cwe' });
          else if (famLit && famLit.test(line)) matches.push({ line: i + 1, text: line.trim().slice(0, 200), kind: 'family' });
          if (matches.length >= 5) break;
        }
        if (matches.length) {
          hits.push({
            file: path.relative(sessionRoot, abs).replace(/\\/g, '/'),
            matchCount: matches.length,
            matches,
          });
          if (hits.length >= 20) break;
        }
      }
      if (hits.length >= 20) break;
    }
    return {
      _meta: META,
      ok: true,
      query: { cwe: cwe || null, family: family || null },
      hitCount: hits.length,
      hits,
      truncated: hits.length >= 20,
    };
  },
};

// ─── append_scratchpad / read_scratchpad ───────────────────────────────────
// LangChain harness-anatomy: the filesystem is the durable agent scratchpad.
// These tools expose a tightly-confined slice of the project tree for
// in-progress agent state: PLAN.md decompositions, offloaded tool outputs,
// session notes that survive context resets.
//
// Confinement (validated in `_validateScratchpadPath`):
//   ALL paths must start with `.agentic-security/agent-scratchpad/<agent>/<session>/`
//   and consist of [A-Za-z0-9_.-]{1,64} path components — no `..`, no
//   absolute paths, no shell metacharacters. This is the ONE place inside
//   the otherwise-reserved `.agentic-security/` tree where agents can write.
// Limits:
//   - 2 MB per file (write attempts beyond this are refused).
//   - 50 MB total across the scratchpad — protects against runaway agents.
// Operators who want to clean up: `rm -rf .agentic-security/agent-scratchpad`.
//
// The post: "Agents can store intermediate outputs and maintain state that
// outlasts a single session." This is that mechanism.

export const append_scratchpad = {
  name: 'append_scratchpad',
  description: 'Append text to a file under .agentic-security/agent-scratchpad/<agent>/<session>/. The ONLY writable location for in-progress agent state (PLAN.md, notes, offloaded tool outputs, decision logs). Path must start with that prefix; <agent>/<session>/file parts are restricted to [A-Za-z0-9_.-]{1,64}. Caps: 2 MB per file, 50 MB total across the scratchpad.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      path: { type: 'string', minLength: 1, maxLength: 256 },
      content: { type: 'string', minLength: 1, maxLength: 256 * 1024 },
    },
    required: ['path', 'content'],
  },
  async handler({ path: relPath, content }, ctx) {
    const v = _validateScratchpadPath(relPath);
    if (!v.ok) return { _meta: META, ok: false, reason: v.reason };
    const abs = _scratchpadAbs(ctx.sessionRoot, relPath);
    const total = _scratchpadTotalBytes(ctx.sessionRoot);
    if (total + content.length > SCRATCHPAD_MAX_TOTAL_BYTES) {
      return {
        _meta: META, ok: false,
        reason: `scratchpad-total-exceeded: ${total} + ${content.length} > ${SCRATCHPAD_MAX_TOTAL_BYTES}. Clean up via "rm -rf .agentic-security/agent-scratchpad" or rotate sessions.`,
      };
    }
    let existing = 0;
    try { if (fs.existsSync(abs)) existing = fs.statSync(abs).size; } catch {}
    if (existing + content.length > SCRATCHPAD_MAX_FILE_BYTES) {
      return {
        _meta: META, ok: false,
        reason: `scratchpad-file-exceeded: ${existing} + ${content.length} > ${SCRATCHPAD_MAX_FILE_BYTES}. Start a new file.`,
      };
    }
    try {
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.appendFileSync(abs, content);
      return {
        _meta: META, ok: true,
        path: relPath, bytesWritten: content.length, fileSize: existing + content.length,
        scratchpadTotal: total + content.length,
      };
    } catch (e) {
      return { _meta: META, ok: false, reason: `write-failed: ${e.message}` };
    }
  },
};

export const read_scratchpad = {
  name: 'read_scratchpad',
  description: 'Read a file under .agentic-security/agent-scratchpad/<agent>/<session>/. Paginated for large files via `offset` (default 0) and `limit` (default 4096 bytes, max 64 KB). Returns bytesRead, truncated, nextOffset for paging.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      path: { type: 'string', minLength: 1, maxLength: 256 },
      offset: { type: 'integer', minimum: 0, maximum: 100 * 1024 * 1024 },
      limit: { type: 'integer', minimum: 1, maximum: 64 * 1024 },
    },
    required: ['path'],
  },
  async handler({ path: relPath, offset, limit }, ctx) {
    const v = _validateScratchpadPath(relPath);
    if (!v.ok) return { _meta: META, ok: false, reason: v.reason };
    const abs = _scratchpadAbs(ctx.sessionRoot, relPath);
    if (!fs.existsSync(abs)) return { _meta: META, ok: false, reason: 'not-found' };
    let stat;
    try { stat = fs.statSync(abs); } catch (e) { return { _meta: META, ok: false, reason: `stat-failed: ${e.message}` }; }
    if (!stat.isFile()) return { _meta: META, ok: false, reason: 'not-a-file' };
    const off = Number.isInteger(offset) ? Math.max(0, offset) : 0;
    const lim = Number.isInteger(limit) ? Math.min(64 * 1024, Math.max(1, limit)) : 4096;
    let buf;
    try {
      const fd = fs.openSync(abs, 'r');
      const tmp = Buffer.alloc(lim);
      const read = fs.readSync(fd, tmp, 0, lim, off);
      fs.closeSync(fd);
      buf = tmp.slice(0, read);
    } catch (e) { return { _meta: META, ok: false, reason: `read-failed: ${e.message}` }; }
    const text = buf.toString('utf8');
    return {
      _meta: META, ok: true,
      path: relPath,
      offset: off, limit: lim, bytesRead: buf.length,
      totalSize: stat.size,
      truncated: off + buf.length < stat.size,
      nextOffset: off + buf.length < stat.size ? off + buf.length : null,
      content: text,
    };
  },
};

// ─── append_agents_memory / read_agents_memory ─────────────────────────────
// LangChain harness-anatomy #2: AGENTS.md as continual-learning surface.
// Lazy-import to keep the MCP module dependency-light.
import { appendAgentsMemory as _appendAgentsMemory, readAgentsMemory as _readAgentsMemory } from '../posture/agents-memory.js';
import { lookupCve as _lookupCve } from '../posture/cve-lookup.js';

export const append_agents_memory = {
  name: 'append_agents_memory',
  description: 'Append a short narrative entry to AGENTS.md — agent-authored continual-learning notes. Use at session end to record "what worked / what didn\'t / what I\'d try differently next time" so the next agent can pick up the lesson. Bounded: 2 KB per entry, 20 KB total before rotation to AGENTS.md.archive. Use sparingly — narrative, not structured data.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      agent: { type: 'string', minLength: 1, maxLength: 64 },
      body: { type: 'string', minLength: 1, maxLength: 4096 },
    },
    required: ['agent', 'body'],
  },
  async handler({ agent, body }, ctx) {
    const r = _appendAgentsMemory(ctx.sessionRoot, { agent, body });
    return { _meta: META, ...r };
  },
};

export const read_agents_memory = {
  name: 'read_agents_memory',
  description: 'Read the AGENTS.md continual-learning file (and AGENTS.md.archive if needed). Returns the most-recent ~6 KB tail by default; pass `full: true` for everything. The SessionStart hook already surfaces a summary; use this when an agent wants to look up specifics mid-session.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      full: { type: 'boolean' },
    },
  },
  async handler({ full }, ctx) {
    const body = _readAgentsMemory(ctx.sessionRoot);
    if (!body) return { _meta: META, present: false };
    if (full) return { _meta: META, present: true, length: body.length, content: body };
    // Tail-only — same logic as summarizeForSession but inlined to avoid a
    // second import surface.
    const limit = 6 * 1024;
    if (body.length <= limit) return { _meta: META, present: true, length: body.length, content: body };
    const tail = body.slice(-limit);
    const firstSection = tail.indexOf('\n## ');
    const slice = firstSection >= 0 ? tail.slice(firstSection) : tail;
    return { _meta: META, present: true, length: body.length, truncated: true, content: slice };
  },
};

// ─── query_triage_memory ───────────────────────────────────────────────────
// Natural-language Q&A over past triage decisions (wont-fix / false-positive
// markings + reasons). Backed by .agentic-security/triage-memory.jsonl, which
// is auto-populated by triage.transition(). Returns at most 10 most-relevant
// past decisions.

export const query_triage_memory = {
  name: 'query_triage_memory',
  description: 'Search past triage decisions (wont-fix / false-positive) by natural-language query. Returns up to 10 most-relevant past decisions with their reasons. Use when you see a new finding and want to know "did we already decide on something like this?" — answers in seconds without re-reading the full AGENTS.md narrative.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      query: { type: 'string', description: 'Free-text terms to match against past reasons / vuln text / file paths / family names.' },
    },
  },
  async handler({ query }, ctx) {
    const { queryMemory } = await import('../posture/triage-memory.js');
    const results = queryMemory(ctx.sessionRoot, query || '');
    return {
      _meta: META,
      count: results.length,
      results,
    };
  },
};

// ─── query_findings_memory ─────────────────────────────────────────────────
// Natural-language Q&A across the scanner's accumulated institutional
// memory: current findings + past triage decisions + scan history +
// AGENTS.md narrative. Use to answer "have we seen something like this
// before?" without reading multiple files.

export const query_findings_memory = {
  name: 'query_findings_memory',
  description: 'Search the scanner accumulated memory (current scan findings + past wont-fix/false-positive decisions + scan history + AGENTS.md narrative) by natural-language terms. Returns top-10 results scored by term-match count and ranked finding > triage > history > AGENTS.md.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      query: { type: 'string', description: 'Natural-language search terms (2+ chars each).' },
    },
    required: ['query'],
  },
  async handler({ query }, ctx) {
    const { queryFindingsMemory } = await import('../posture/findings-memory.js');
    return { _meta: META, ...queryFindingsMemory(ctx.sessionRoot, query || '') };
  },
};

// ─── lookup_cve ────────────────────────────────────────────────────────────
// LangChain harness-anatomy #8: bridge the knowledge-cutoff gap by exposing
// the local OSV / KEV / EPSS cache as a structured tool. Read-only — never
// triggers a network fetch from the MCP path.
export const lookup_cve = {
  name: 'lookup_cve',
  description: 'Look up a CVE id in the local OSV / KEV / EPSS caches. Returns staleness-tiered cached data (fresh / recent / stale / very-stale). Read-only — does NOT fetch fresh data; the scan pipeline is the only thing that populates the cache. Use to inform reasoning about an SCA finding without relying on the model\'s training cutoff.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      cve: { type: 'string', minLength: 9, maxLength: 20 },
    },
    required: ['cve'],
  },
  async handler({ cve }, _ctx) {
    const r = _lookupCve(cve);
    return { _meta: META, ...r };
  },
};

// ─── synthesize_sca_upgrade ───────────────────────────────────────────────
// Phase 3 / Item 5 of the SCA improvement plan. Read-only counterpart to
// apply_sca_upgrade — produces a structured upgrade plan via the
// ecosystem's native --dry-run command. Safe to call any number of times.
let _scaUpgrade;
async function _getScaUpgrade() {
  if (!_scaUpgrade) _scaUpgrade = await import('../posture/sca-upgrade.js');
  return _scaUpgrade;
}
export const synthesize_sca_upgrade = {
  name: 'synthesize_sca_upgrade',
  description: 'Generate an upgrade plan for a single SCA finding. Runs the ecosystem dry-run (npm install --dry-run, pip install --dry-run, cargo update --dry-run). Returns { ecosystem, package, currentVersion, targetVersion, isBreaking, command, manifestFiles, dryRun, testCommand }. No writes.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
    },
    required: ['finding_id'],
  },
  async handler({ finding_id }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
    if (!scan) throw new Error(`No usable scan state (${status}).`);
    const f = _findById(scan, finding_id);
    if (!f) throw new Error(`Finding not found: ${finding_id}`);
    if (f.type !== 'vulnerable_dep') {
      return { _meta: META, ok: false, reason: 'finding is not an SCA vulnerable_dep — use synthesize_fix for SAST findings' };
    }
    const { planScaUpgrade } = await _getScaUpgrade();
    const plan = await planScaUpgrade({ scanRoot: ctx.sessionRoot, finding: f });
    return { _meta: META, ...plan };
  },
};

// ─── apply_sca_upgrade ────────────────────────────────────────────────────
// Phase 3 / Item 5 of the SCA improvement plan. The MCP `apply_fix` path
// refuses every package-manager manifest by design. This tool bypasses
// that ONLY for the install pathway — it shells out to the ecosystem's
// native package manager (npm / pip / cargo / go) which is the right
// surface for safely modifying manifests + lockfiles. Backs up affected
// manifests before the install; runs the project's test command (if
// detected); rolls back manifests if tests fail.
export const apply_sca_upgrade = {
  name: 'apply_sca_upgrade',
  description: 'Apply a vulnerable_dep upgrade. Backs up manifests, runs the package manager, runs the project test command, restores manifests on test failure. Requires confirm:true. Set run_tests:false to skip the test gate (NOT recommended).',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
      confirm: { type: 'boolean' },
      run_tests: { type: 'boolean' },
    },
    required: ['finding_id', 'confirm'],
  },
  async handler({ finding_id, confirm, run_tests = true }, ctx) {
    if (confirm !== true) {
      return { _meta: META, applied: false, reason: 'apply_sca_upgrade requires confirm: true.' };
    }
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: false });
    if (!scan) {
      return { _meta: META, applied: false, reason: `last-scan.json failed integrity check: ${status}. Run a fresh scan.` };
    }
    const f = _findById(scan, finding_id);
    if (!f) return { _meta: META, applied: false, reason: `Finding not found: ${finding_id}` };
    if (f.type !== 'vulnerable_dep') {
      return { _meta: META, applied: false, reason: 'finding is not an SCA vulnerable_dep — use apply_fix for SAST findings' };
    }
    const { applyScaUpgrade } = await _getScaUpgrade();
    const result = await applyScaUpgrade({ scanRoot: ctx.sessionRoot, finding: f, runTests: run_tests });
    return { _meta: META, ...result };
  },
};

export const ALL_TOOLS = [scan_diff, query_taint, explain_finding, apply_fix, verify_fix, synthesize_fix, find_rule_module, append_scratchpad, read_scratchpad, append_agents_memory, read_agents_memory, lookup_cve, synthesize_sca_upgrade, apply_sca_upgrade, query_triage_memory, query_findings_memory];
