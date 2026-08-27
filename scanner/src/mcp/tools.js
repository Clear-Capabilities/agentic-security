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
import { applyFix as applyFixHistory, fixAcceptanceRate, revertEntryById as revertFixEntry } from '../posture/fix-history.js';
import { applyVerifiedFix } from '../fix/apply-fix-service.js';
import { classifyFixMaterialRisk } from '../posture/material-change.js';
import { loadApproverRegistry, verifyApprover, requiredRolesFor, checkSeparationOfDuties } from '../fix/approver-registry.js';
import { synthesizeDeterministicPatch } from '../posture/deterministic-fix.js';
import { verifyLastScan } from '../posture/integrity.js';
import { withStateWritesDisabled } from '../posture/state-dir.js';
import { analyzeTranscript, formatCacheReport, renderCacheStatusLine } from '../posture/cache-economics.js';
import { redactString, redactFinding } from './redact.js';
import { _remediationOf, normalizeFindings } from '../report/index.js';
// Git-origin provenance (Finding Provenance M0/M1). Distinct from
// `finding.provenance` (AI-authorship) and from an SCA entry's `provenance`
// (Sigstore/SLSA attestation) — see report/index.js's import comment.
import { redactFindingProvenance } from '../posture/provenance/schema.js';

// Lazy-loaded: these transitively pull in npm packages (@babel/core and
// friends) that aren't available in the plugin-cache install path
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
  // _CONFINEMENT rule 3 — backup and lock files. The specific lock BASENAMES
  // above cover the ecosystems we know; this catches the rest (`deps.lock`,
  // `foo.bak`) without needing to enumerate them. Nothing an autofix should
  // ever be rewriting: a `.bak` is someone's safety copy and a `.lock` is
  // generated state.
  '.bak',
  '.lock',
];
// _CONFINEMENT rule 3 — build output. Matched as a PATH SEGMENT at any depth,
// not as a top-level prefix, because build output is routinely nested
// (`packages/web/dist/`, `services/api/target/`) and a top-level-only check
// would refuse the monorepo root and allow every package inside it.
//
// This matters most in THIS repository: `scanner/dist/` holds the shipped
// bundle, which carries its own SHA-256 integrity sidecar precisely because
// what it contains matters. Before this, `apply_fix` would rewrite it and
// report success.
//
// NOTE for a future change, deliberately not made here: the PREFIX list above
// (`node_modules/`, `.git/`, …) is still top-level-only, so a nested
// `packages/a/node_modules/` is not covered by it. That is a separate widening
// with its own blast radius and belongs in its own change with its own tests.
const RESERVED_WRITE_DIR_SEGMENTS = new Set(['dist', 'build', 'target']);
function _isReservedWritePath(sessionRoot, absFile) {
  // Resolve sessionRoot symlinks so the relative path is computed against
  // the same canonical root as `absFile` (which _confine already realpath'd).
  // On macOS /tmp → /private/tmp; without this normalization the relative
  // would contain "../" and the prefix check would miss the reserved path.
  const rootReal = fs.realpathSync(path.resolve(sessionRoot));
  const rel = path.relative(rootReal, absFile).replace(/\\/g, '/');
  if (RESERVED_WRITE_PREFIXES.some(p => rel === p.replace(/\/$/, '') || rel.startsWith(p))) return true;
  const segments = rel.split('/');
  const base = segments[segments.length - 1] || '';
  if (RESERVED_WRITE_BASENAMES.has(base)) return true;
  if (RESERVED_WRITE_SUFFIXES.some(s => base === s || base.endsWith(s))) return true;
  // Any DIRECTORY segment that names build output — checked over
  // `segments.length - 1` so a source file legitimately called `build` or
  // `dist` is not refused for its own name; only living inside such a
  // directory counts.
  if (segments.slice(0, -1).some(seg => RESERVED_WRITE_DIR_SEGMENTS.has(seg))) return true;
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

// Routes through the same lstat+realpath confinement every other write/
// path-taking tool uses (OWASP MCP05) — a lexical prefix/charset check
// alone doesn't stop a pre-planted symlink at any path component from
// relocating the write/read outside the session root. Throws on escape;
// callers must catch (see append_scratchpad / read_scratchpad).
function _scratchpadAbs(sessionRoot, relPath) {
  return _confine(sessionRoot, relPath.replace(/\\/g, '/'), 'scratchpad path');
}

function _scratchpadTotalBytes(sessionRoot) {
  const base = statePath(sessionRoot, 'agent-scratchpad');
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
  const stateDirPath = stateDir(sessionRoot);
  const scanFile = path.join(stateDirPath, 'last-scan.json');
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
// Test seam for the write boundary (PRD F6.4).
//
// `_confine` and `isReservedWrite` ARE the confinement contract in
// agents/_CONFINEMENT.md. A boundary is only worth what its refusals are worth,
// and refusals cannot be adversarially tested through the public tools without
// also exercising a real scan, a real patch and a real filesystem write — so
// the check would be measuring four things and attributing failure to one.
//
// Exported under the `_internals` convention this codebase already uses
// (see posture/poc-inprocess.js). Not part of the MCP tool surface.
export const _internals = { _confine, isReservedWrite: _isReservedWritePath };

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

    // PRD R1 (docs/DETECTION_GAP_REMEDIATION_PRD.md): deep mode is default-on
    // for the interactive CLI scan but was never requested here, so an
    // agent's pre-write self-correction scan was regex/AST-only — blind to
    // any bug whose source and sink are connected only through a call
    // (`fileContents` scopes the deep engine's IR to exactly the files
    // passed in, same bound this tool already enforces via MAX_FILES_PER_SCAN
    // / MAX_TOTAL_SCAN_BYTES, so this does not turn scan_diff into a
    // full-project deep scan).
    const runScan = await getRunScan();
    // FR-704 (assurance-hardening PRD): this tool's own description promises
    // "runs scan in memory" — without this, runFullScan's own state writers
    // (dpia.md, ropa.md, privacy-framework.json, threat-model.json, and
    // others) fire unconditionally on every call, silently mutating the
    // user's real project on every pre-write self-correction scan. Confirmed
    // by direct execution before this fix (11 state artifacts written by a
    // single scan_diff-shaped call).
    const result = await withStateWritesDisabled(() =>
      runScan(sessionRoot, { network: false, fileContents, deep: true, deepInCi: true }));
    const wantSet = new Set(Object.keys(fileContents));
    const sevRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const min = sevRank[severity] ?? 0;
    // Stage 6 correctness audit (historical): this used to only read
    // result.scan.findings (the SAST channel) — scan.secrets and
    // scan.logicVulns are separate arrays on the raw runScan() result, and a
    // hand-rolled 3-channel concat here was a second, divergent copy of the
    // merge report/index.js's normalizeFindings() already does (four
    // channels, plus per-channel defaulting and remediation-string
    // resolution the old concat re-implemented separately and could drift
    // from). Assurance-hardening PRD FR-105 ("JSON, SARIF, HTML, CSV, JUnit,
    // and MCP outputs derive from the same validated object"): route through
    // the same canonical merge every other output format uses.
    //
    // This closes the field-mapping/dedup divergence, but does NOT make
    // scan_diff surface SCA/supply-chain findings end to end: this handler
    // never builds a `depFileContents` map (everything a caller passes in
    // `files`, manifests included, lands in `fileContents`), and manifest-
    // based supply-chain detection in engine.js reads only `depFileContents`
    // — so `result.scan.supplyChain` is always empty for this tool today
    // regardless of this fix. That is a separate, real limitation (scan_diff
    // was designed for pre-write code self-correction, not manifest
    // scanning), left as-is rather than silently claimed fixed here.
    const findings = normalizeFindings(result.scan)
      .filter(f => wantSet.has(String(f.file || '').replace(/\\/g, '/')) && (sevRank[f.severity] ?? 0) >= min)
      .map(f => redactFinding({
        id: f.id, severity: f.severity, file: f.file, line: f.line,
        title: f.vuln, cwe: f.cwe,
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
      // Which commit introduced this finding. Redacted with the DEFAULT
      // options (includeEmail:false) unconditionally — unlike the JSON report
      // there is no operator-set env escape here, because the consumer is an
      // agent that has no business receiving a committer's email address.
      findingProvenance: f.findingProvenance ? redactFindingProvenance(f.findingProvenance) : null,
    };
  },
};

// ─── apply_fix ───────────────────────────────────────────────────────────────
export const apply_fix = {
  name: 'apply_fix',
  description: 'Apply a fix for a finding. Two modes: (1) the stored fix.replacement, or (2) a caller-supplied `patch` (a files map) which is RE-VERIFIED inline (rescan-clean + no new ≥medium + lint) before any write — this unblocks findings that ship only a template or description. Refuses if last-scan.json fails its HMAC check, if the finding is shadow-marked, or if a path escapes the session root via lexical traversal OR a symlink. Requires confirm:true. Supports dry_run:true to preview without writing. On success, `verified:true` means verification passed but `verifiedFull:true` is the honest signal that every required leg (lint when configured, tests when a runner exists) genuinely ran — a false `verifiedFull` with `verified:true` means the pass is real but degraded (see `verify.degradedLegs`), not a full verification.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
      confirm: { type: 'boolean' },
      dry_run: { type: 'boolean' },
      patch: {
        type: 'object',
        additionalProperties: { type: 'string', maxLength: 500_000 },
        minProperties: 1, maxProperties: 8,
      },
      // Stage 6 correctness audit: same gap and same fix as verify_fix — the
      // honesty gate is reachable but was never wired to any real caller.
      // Here it's stronger than advisory: the inline re-verify below already
      // gates the WRITE on `verdict.ok`, and verifyFixCore's own `ok`
      // formula already folds in `honesty.ok` when fixMeta is supplied — so
      // passing it through here makes a dishonest fixMeta (hand-wave
      // residual, uncited false-positive verdict) block the write itself,
      // not just report a verdict.
      fixMeta: {
        type: 'object',
        additionalProperties: false,
        properties: {
          residual: { type: 'string', maxLength: 2000 },
          verdict: { type: 'string', maxLength: 64 },
          evidence: { type: 'array', items: { type: 'string', maxLength: 500 }, maxItems: 20 },
          signals: {
            type: 'object',
            additionalProperties: false,
            properties: {
              sinkSignatureChanged: { type: 'boolean' },
              allCallersRouted: { type: 'boolean' },
              testDiscriminates: { type: 'boolean' },
              rateLimitOnly: { type: 'boolean' },
              docsOnly: { type: 'boolean' },
              logOnlyNoReject: { type: 'boolean' },
              partialSanitization: { type: 'boolean' },
            },
          },
          // FR-307/FR-1002: this schema had `additionalProperties: false`
          // and never declared `approval` — the property apply-fix-
          // service.js's high-impact-change gate has required since FR-307
          // was built. A real MCP caller supplying fixMeta.approval was
          // rejected by validate.js at the schema layer before the handler
          // ever ran, silently making the approval gate (and FR-1002's
          // identity check layered on it) unreachable from this tool's
          // only real production entry point. See D-0024.
          approval: {
            type: 'object',
            additionalProperties: false,
            properties: {
              approvedBy: { type: 'string', minLength: 1, maxLength: 200 },
              reason: { type: 'string', minLength: 1, maxLength: 1000 },
            },
          },
          // FR-1003: separation-of-duties. Self-reported the same way
          // approvedBy is — this tool has no way to determine who actually
          // wrote a patch, so `author` is a claim, checked against a
          // configurable policy the same way `approval` is.
          author: { type: 'string', minLength: 1, maxLength: 200 },
        },
      },
    },
    required: ['finding_id', 'confirm'],
  },
  async handler({ finding_id, confirm, dry_run = false, patch = null, fixMeta = null }, ctx) {
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

    // #3 — verifier-approved patch path. When the caller supplies `patch` (a
    // files map, same shape as verify_fix), apply_fix re-runs the verifier
    // INLINE and writes only if it passes: the original finding's stableId is
    // gone, no new ≥medium finding was introduced, and lint is clean. This lets
    // a deterministic OR LLM-synthesized patch be applied for the ~100% of
    // findings that ship only a template/description (no stored fix.replacement).
    // Security: all existing gates hold (confirm, last-scan HMAC, reserved
    // paths, confinement, fix-history backup + attempt budget); the write is
    // additionally gated on a FRESH verification, so a stale/forged patch can't
    // slip through — there is no token to replay, the verify runs here and now.
    if (patch && typeof patch === 'object' && Object.keys(patch).length) {
      if (!f.stableId) {
        return { _meta: META, applied: false, reason: 'finding has no stableId — cannot verify a patch against it' };
      }
      const confinedAbs = {};
      for (const [rel, content] of Object.entries(patch)) {
        let abs;
        try { abs = _confine(ctx.sessionRoot, rel, 'patch key'); }
        catch (e) { return { _meta: META, applied: false, reason: `path-escape refused: ${e.message}` }; }
        if (_isReservedWritePath(ctx.sessionRoot, abs)) {
          return { _meta: META, applied: false, reason: `reserved path refused: ${rel}` };
        }
        confinedAbs[rel] = { abs, content: String(content) };
      }
      // Inline re-verify — the load-bearing gate. Must pass to write.
      let verdict;
      try {
        const _files = Object.fromEntries(Object.entries(confinedAbs).map(([rel, v]) => [rel, v.content]));
        if (process.env.AGENTIC_SECURITY_FIX_RUN_TESTS === '1') {
          // Addition #7 — connect the closed-loop verifier: add the project test
          // suite as a fourth verification leg (scan + lint + tests). Opt-in
          // because many repos have no runner and we must not fail-closed by
          // default. Normalized to the scan+lint verdict shape used below.
          const { verifyFixWithTests } = await import('../posture/fix-verify-loop.js');
          const t = await verifyFixWithTests({ scanRoot: ctx.sessionRoot, originalFindingStableId: f.stableId, files: _files });
          verdict = { ok: t.ok, summary: t.summary, rescan: t.legs?.scan?.detail, lint: t.legs?.lint?.detail, tests: t.legs?.tests, testVerdict: t.verdict };
        } else {
          const verifyFixCore = await getVerifyFixCore();
          verdict = await verifyFixCore({
            scanRoot: ctx.sessionRoot,
            originalFindingStableId: f.stableId,
            files: _files,
            fixMeta,
          });
        }
      } catch (e) {
        return { _meta: META, applied: false, reason: `patch verification failed: ${e.message}` };
      }
      if (!verdict.ok) {
        return {
          _meta: META, applied: false,
          reason: `patch rejected by verifier: ${verdict.summary || verdict.rescan?.reason || 'did not verify'}`,
          verify: { rescan: verdict.rescan, lint: { runner: verdict.lint?.runner, ok: verdict.lint?.ok }, honesty: verdict.honesty || null },
        };
      }
      // FR-307/FR-1002/D-0024: this caller-supplied-patch branch writes via
      // applyFixHistory() directly and never called applyVerifiedFix() — so
      // the high-impact-change approval gate (auth/authZ/crypto/PII/schema/
      // infra-privilege/public-API) built for the OTHER apply_fix branch
      // (stored fix.replacement) never ran here at all, for any input. Since
      // this is the branch the tool's own description calls the one that
      // covers "~100% of findings that ship only a template," that gap was
      // the larger of the two found this cycle. Same before/after content
      // shape `apply-fix-service.js` already uses — read-first-in-try/catch
      // (D-0012), never existsSync-then-readFileSync.
      const filesForMaterialClassification = {};
      for (const [rel, v] of Object.entries(confinedAbs)) {
        let before = '';
        try { before = await fsp.readFile(v.abs, 'utf8'); } catch { /* new file — before stays '' */ }
        filesForMaterialClassification[rel] = { before, after: v.content };
      }
      const materialClassification = classifyFixMaterialRisk(filesForMaterialClassification);
      if (dry_run) {
        return { _meta: META, applied: false, dryRun: true, verified: true, files: Object.keys(confinedAbs), summary: verdict.summary, materialClassification };
      }
      if (materialClassification.highImpactCategories.length) {
        const approval = fixMeta && typeof fixMeta === 'object' ? fixMeta.approval : null;
        const hasApprovalEvidence = !!(approval && typeof approval === 'object' &&
          typeof approval.approvedBy === 'string' && approval.approvedBy.trim().length > 0 &&
          typeof approval.reason === 'string' && approval.reason.trim().length > 0);
        if (!hasApprovalEvidence) {
          return {
            _meta: META, applied: false,
            reason: `high-impact change (${materialClassification.highImpactCategories.join(', ')}) requires approval evidence — pass fixMeta.approval: {approvedBy, reason} — before it can be applied`,
            materialClassification,
          };
        }
        const approverRegistry = loadApproverRegistry(ctx.sessionRoot);
        const requiredRoles = requiredRolesFor(approverRegistry, materialClassification.highImpactCategories);
        const identityCheck = verifyApprover(approverRegistry, approval.approvedBy, requiredRoles);
        if (!identityCheck.verified) {
          return {
            _meta: META, applied: false,
            reason: `high-impact change (${materialClassification.highImpactCategories.join(', ')}) approval rejected: ${identityCheck.reason}`,
            materialClassification,
          };
        }
        // FR-1003: separation-of-duties, same no-op-unless-configured gate
        // as apply-fix-service.js's own copy — see approver-registry.js.
        const sodCheck = checkSeparationOfDuties(approverRegistry, fixMeta?.author, approval.approvedBy);
        if (!sodCheck.ok) {
          return {
            _meta: META, applied: false,
            reason: `high-impact change (${materialClassification.highImpactCategories.join(', ')}) approval rejected: ${sodCheck.reason}`,
            materialClassification,
          };
        }
      }
      const written = [];
      try {
        for (const [rel, v] of Object.entries(confinedAbs)) {
          const fileExisted = fs.existsSync(v.abs);
          const originalContent = fileExisted ? await fsp.readFile(v.abs, 'utf8') : '';
          const entry = await applyFixHistory({
            scanRoot: ctx.sessionRoot, file: rel, originalContent, newContent: v.content, fileExisted,
            findingId: f.id, stableId: f.stableId, ruleId: f.ruleId || f.cwe || f.family || null, vuln: f.vuln || f.title || null,
          });
          written.push({ file: rel, historyId: entry.id, backupPath: entry.backupPath });
        }
      } catch (e) {
        // FR-306: roll back every file THIS batch already wrote before the
        // failure — applyFixHistory already restored the one file that just
        // failed; this covers the rest, so a multi-file patch never leaves
        // some files patched and others not.
        for (const w of written) {
          try { await revertFixEntry(ctx.sessionRoot, w.historyId); } catch { /* best-effort; original error still propagates below */ }
        }
        if (e && e.name === 'FixAttemptBudgetExceededError') {
          return { _meta: META, applied: false, reason: `budget-exceeded: ${e.message}`, budgetExceeded: true, attempts: e.attempts, maxAttempts: e.max, key: e.key };
        }
        throw e;
      }
      let acceptance = null;
      try { acceptance = fixAcceptanceRate(ctx.sessionRoot); } catch { /* best-effort */ }
      return { _meta: META, applied: true, verified: true, patched: written, integrity: status, verify: { summary: verdict.summary }, acceptance, materialClassification };
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

    // FR-301/A-08 (assurance-hardening PRD): this branch used to write
    // f.fix.replacement straight to disk with NO fresh verification — no
    // rescan, no lint, nothing confirming the stored replacement actually
    // closes the finding it claims to fix. The caller-patch branch above
    // already required this; there is no reason a STORED fix should be
    // trusted more than a caller-supplied one just because it shipped with
    // the finding. Routed through the same applyVerifiedFix() service the
    // CLI's `fix --apply` now also uses (src/fix/apply-fix-service.js) —
    // confinement/reserved-path are re-checked there too (harmless
    // redundancy with the dry_run preview above, kept for that preview's
    // size-diff shape) but the load-bearing addition is the verification
    // gate before the write.
    if (!f.stableId) {
      return { _meta: META, applied: false, reason: 'finding has no stableId — cannot verify a stored fix against it' };
    }
    const result = await applyVerifiedFix({
      scanRoot: ctx.sessionRoot,
      finding: f,
      files: { [f.file]: f.fix.replacement },
      fixMeta,
    });
    if (!result.ok) {
      if (result.budgetExceeded) {
        return { _meta: META, applied: false, reason: result.reason, budgetExceeded: true, attempts: result.attempts, maxAttempts: result.maxAttempts, key: result.key };
      }
      return { _meta: META, applied: false, reason: result.reason, verify: result.verify || null };
    }
    // R25 (PRD §5): surface the running auto-fix acceptance rate after each
    // applied fix, so the closed loop reports its own success metric.
    let acceptance = null;
    try { acceptance = fixAcceptanceRate(ctx.sessionRoot); } catch { /* metric is best-effort */ }
    const entry = result.written[0];
    return {
      // FR-305: verifiedFull distinguishes "every required leg (lint, tests)
      // genuinely ran and passed" from "passed, but a required leg was
      // skipped or unavailable" — verified:true alone conflates them.
      _meta: META, applied: true, verified: true, verifiedFull: result.verifiedFull,
      historyId: entry.historyId, file: entry.file, backupPath: entry.backupPath,
      integrity: status, attemptOrdinal: entry.attemptOrdinal, acceptance,
      verify: result.verify,
    };
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
  description: 'Verify a proposed patch before applying. Re-scans the patched files in memory, runs the project linter, runs the project test suite, checks fix honesty (FULL/MITIGATION/WORKAROUND) when fixMeta is supplied, and re-runs the PoC when one exists. Returns { ok, rescan, lint, tests, honesty, poc, summary }. Does not write to the target project’s own files, but DOES append one record per attempt to .agentic-security/fix-metrics.jsonl for the measured fix-loop.',
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
      // Stage 6 correctness audit: posture/fix-honesty-gate.js's deterministic
      // honesty checks (vague-assurance residual prose, unbacked false-
      // positive verdicts, tier/residual consistency) were fully built and
      // fix-verify.js already consulted them when given a `fixMeta` — but
      // this schema never had a `fixMeta` property, so no call through the
      // MCP surface could ever supply one. The gate can only run against
      // claims the AGENT self-reports (residual risk, verdict, evidence,
      // completeness signals) — nothing here is server-computable — so
      // fixing this meant exposing the property, not inventing a lookup.
      fixMeta: {
        type: 'object',
        additionalProperties: false,
        properties: {
          residual: { type: 'string', maxLength: 2000 },
          verdict: { type: 'string', maxLength: 64 },
          evidence: { type: 'array', items: { type: 'string', maxLength: 500 }, maxItems: 20 },
          signals: {
            type: 'object',
            additionalProperties: false,
            properties: {
              sinkSignatureChanged: { type: 'boolean' },
              allCallersRouted: { type: 'boolean' },
              testDiscriminates: { type: 'boolean' },
              rateLimitOnly: { type: 'boolean' },
              docsOnly: { type: 'boolean' },
              logOnlyNoReject: { type: 'boolean' },
              partialSanitization: { type: 'boolean' },
            },
          },
        },
      },
    },
    required: ['stable_id', 'files'],
  },
  async handler({ stable_id, files, fixMeta }, ctx) {
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
      // The PoC-re-check leg (verifyFixCore's `pocLeg`) needs a `poc` param
      // to do anything — until now nothing supplied one, so it always
      // reported {status:'not-requested'} through this surface (see
      // posture/CLAUDE.md's disclosure). Rather than widening inputSchema
      // to make the CALLER pass PoC data back, look it up server-side: the
      // scan pipeline already attaches an HTTP-shaped f.poc to matching
      // findings by default (engine.js's annotatePocs), and last-scan.json
      // already carries it under the same stableId this handler receives.
      // Best-effort: a missing/unsigned/tampered scan just means no PoC is
      // available to re-check, not a verify_fix failure — the rescan/lint/
      // tests legs below are independent of this and still apply.
      let poc = null;
      try {
        const { scan: lastScan } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
        const orig = lastScan && (lastScan.findings || []).find(f => f.stableId === stable_id);
        if (orig && orig.poc && orig.poc.code) poc = { ...orig.poc, finding: orig };
      } catch { /* best-effort lookup; poc stays null */ }

      const verifyFixCore = await getVerifyFixCore();
      const r = await verifyFixCore({
        scanRoot: ctx.sessionRoot,
        originalFindingStableId: stable_id,
        files: confined,
        poc,
        fixMeta,
      });
      return {
        _meta: META,
        ok: r.ok,
        rescan: { ok: r.rescan.ok, reason: r.rescan.reason, introduced: r.rescan.introduced || [] },
        lint: { runner: r.lint.runner, ok: r.lint.ok, skipped: r.lint.skipped || false, output: redactString(r.lint.output || '').slice(0, 1500) },
        // verifyFix computes five legs, not two — tests/honesty/poc were
        // being silently dropped here, leaving an agent with no structured
        // way to see WHY verification failed when the failure was in one
        // of those three (only the free-text summary carried it).
        // test-runner.js's runProjectTests never returns raw stdout/stderr,
        // so no redaction is needed there; honesty.violations are static,
        // code-generated strings; poc.reason is redacted defensively since
        // it can echo proof-harness detail derived from scanned source.
        tests: r.tests,
        honesty: r.honesty,
        poc: r.poc ? { ...r.poc, reason: r.poc.reason ? redactString(r.poc.reason) : r.poc.reason } : r.poc,
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
    // #1 — deterministic autofix: for classes with a safe context-independent
    // swap (weak hash, TLS verify-off), materialize a full-file patch from the
    // live file. The agent passes `autofix.patch` straight to apply_fix, which
    // re-verifies it (rescan-clean + no new ≥medium + lint) before writing — so
    // even a mis-attributed swap can't land a bad edit. No stored replacement,
    // no per-finding bloat in last-scan.json.
    let autofix = null;
    if (!hasReplacement) {
      try {
        const abs = _confine(ctx.sessionRoot, f.file, 'finding.file');
        const det = synthesizeDeterministicPatch(f, fs.readFileSync(abs, 'utf8'));
        if (det) autofix = { deterministic: true, ruleId: det.ruleId, patch: det.patch };
      } catch { /* best-effort — no file / no rule → no autofix */ }
    }
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
      autofix,
      // #15 — the regression test the scan annotator already generated for this
      // finding (present when a PoC was built). Surfaced here so the fix flow
      // writes the test alongside the patch; fix-verify-loop then runs it, so an
      // applied fix ships with a test that fails pre-fix and passes post-fix.
      regression_test: f.regression_test || null,
      remediation: typeof fix.description === 'string' ? fix.description : (typeof fix === 'string' ? fix : null),
      patchBounds: { touchedFiles, locDelta, oversized },
      // oversized can only be true when hasReplacement is true (locDelta is
      // only computed in that branch, and touchedFiles never varies) — a
      // `!hasReplacement` conjunct here was a structural contradiction that
      // made this permanently false. The correct signal: the stored
      // replacement itself is too big to trust auto-applying, and there's
      // no safer deterministic alternative.
      recommendsFixPlan: oversized && !autofix,
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
    let abs;
    try { abs = _scratchpadAbs(ctx.sessionRoot, relPath); }
    catch (e) { return { _meta: META, ok: false, reason: `path-escape refused: ${e.message}` }; }
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
    let abs;
    try { abs = _scratchpadAbs(ctx.sessionRoot, relPath); }
    catch (e) { return { _meta: META, ok: false, reason: `path-escape refused: ${e.message}` }; }
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

import { stateDir, statePath } from '../posture/state-dir.js';
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
    const raw = queryMemory(ctx.sessionRoot, query || '');
    // Stage 6 correctness audit: this returned queryMemory's output
    // verbatim, with no redaction pass — every other tool that echoes
    // scanned-source-derived text redacts it (mcp/CLAUDE.md's "Adding a new
    // tool" step 3). Round-trip through redactString the same way
    // redactFinding already does for its own opaque `.trace` field: results
    // here mix shapes (a triage decision's free-text `reason`, a finding's
    // `vuln`/`family`/file path), so scrubbing the whole serialized
    // structure catches secret-shaped substrings regardless of which field
    // they landed in, rather than hardcoding a field allowlist that could
    // miss one.
    let results;
    try { results = JSON.parse(redactString(JSON.stringify(raw))); }
    catch { results = raw; }
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
    const raw = queryFindingsMemory(ctx.sessionRoot, query || '');
    // Stage 6 correctness audit — same redaction gap and same fix as
    // query_triage_memory just above: this mixes four differently-shaped
    // result kinds (finding / triage / history / AGENTS.md text), so a
    // whole-structure redactString round-trip is applied rather than a
    // per-field allowlist that could miss one of the four shapes.
    let body;
    try { body = JSON.parse(redactString(JSON.stringify(raw))); }
    catch { body = raw; }
    return { _meta: META, ...body };
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

export const query_cache_telemetry = {
  name: 'query_cache_telemetry',
  description: 'Read prompt-cache economics for the current session from the Claude Code transcript: cache-hit %, $ saved by caching, $ wasted on avoidable cache misses (model switches / TTL gaps / prefix changes), and a per-model breakdown. Read-only, no network. Use to reason about token-cost efficiency and whether a model switch is worth the cache rewarm.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      // Optional explicit transcript path; otherwise derived from the session root.
      transcript_path: { type: 'string', minLength: 1, maxLength: 4096 },
    },
    required: [],
  },
  async handler({ transcript_path } = {}, ctx) {
    const result = analyzeTranscript({ transcriptPath: transcript_path, projectDir: ctx?.sessionRoot || process.cwd() });
    if (!result.ok) return { _meta: META, ok: false, reason: result.reason };
    return {
      _meta: META,
      ok: true,
      metrics: result.metrics,
      leaks: result.leaks,
      report: formatCacheReport(result),
      statusline: renderCacheStatusLine(result.metrics),
    };
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

export const ALL_TOOLS = [scan_diff, query_taint, explain_finding, apply_fix, verify_fix, synthesize_fix, find_rule_module, append_scratchpad, read_scratchpad, append_agents_memory, read_agents_memory, lookup_cve, synthesize_sca_upgrade, apply_sca_upgrade, query_triage_memory, query_findings_memory, query_cache_telemetry];
