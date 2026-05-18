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
import { runScan } from '../runScan.js';
import { applyFix as applyFixHistory } from '../posture/fix-history.js';
import { verifyLastScan } from '../posture/integrity.js';
import { redactString, redactFinding } from './redact.js';

const MAX_FILES_PER_SCAN = 1024;
const MAX_FILE_BYTES = 500_000;
const MAX_TOTAL_SCAN_BYTES = 50_000_000;
const META = { source: 'agentic-security-mcp', untrusted_excerpts: true };

// OWASP A01 — refuse writes to paths that could subvert the security tool
// itself or the host's source-control / dependency state. A forged finding
// could otherwise tell apply_fix to overwrite our own rules.yml, our audit
// log, a .git/hooks/post-commit payload, or a node_modules package.
const RESERVED_WRITE_PREFIXES = [
  '.git/',
  '.agentic-security/',
  'node_modules/',
];
function _isReservedWritePath(sessionRoot, absFile) {
  // Resolve sessionRoot symlinks so the relative path is computed against
  // the same canonical root as `absFile` (which _confine already realpath'd).
  // On macOS /tmp → /private/tmp; without this normalization the relative
  // would contain "../" and the prefix check would miss the reserved path.
  const rootReal = fs.realpathSync(path.resolve(sessionRoot));
  const rel = path.relative(rootReal, absFile).replace(/\\/g, '/');
  return RESERVED_WRITE_PREFIXES.some(p => rel === p.replace(/\/$/, '') || rel.startsWith(p));
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
      || null;
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
  description: 'Query whether the last verified scan found a taint path involving a given source and sink.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      source: { type: 'string', minLength: 1, maxLength: 256 },
      sink: { type: 'string', minLength: 1, maxLength: 256 },
    },
    required: ['source', 'sink'],
  },
  async handler({ source, sink }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
    if (!scan) {
      return { _meta: META, hasResult: false, status, message: `No usable scan state (${status}).` };
    }
    const srcL = String(source).toLowerCase();
    const sinkL = String(sink).toLowerCase();
    const matches = (scan.findings || []).filter(f => {
      const hay = [f.description, f.title, f.vuln, f.snippet, JSON.stringify(f.trace || '')].join(' ').toLowerCase();
      return hay.includes(srcL) && hay.includes(sinkL);
    }).map(f => redactFinding({
      id: f.id, severity: f.severity, file: f.file, line: f.line,
      title: f.title || f.vuln, description: f.description,
      trace: f.trace || null,
    }));
    return {
      _meta: META,
      hasResult: true,
      integrity: status,
      scanStartedAt: scan.startedAt || scan.meta?.startedAt || null,
      matchCount: matches.length,
      matches,
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
    return {
      _meta: META,
      ...redacted,
      confidence: f.confidence ?? null,
      hasReplacementFix: typeof f.fix?.replacement === 'string',
      integrity: status,
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
      return {
        _meta: META, applied: false,
        reason: 'No full replacement available — only a template. Apply the template manually.',
        template: redactString(f.fix?.code || ''),
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

    const entry = await applyFixHistory({
      scanRoot: ctx.sessionRoot,
      file: f.file,
      originalContent,
      newContent: f.fix.replacement,
      findingId: f.id,
      ruleId: f.rule || null,
      vuln: f.vuln || f.title || null,
    });
    return { _meta: META, applied: true, historyId: entry.id, file: f.file, backupPath: entry.backupPath, integrity: status };
  },
};

export const ALL_TOOLS = [scan_diff, query_taint, explain_finding, apply_fix];
