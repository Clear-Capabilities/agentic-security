// Intent-aware false-positive suppression.
//
// Reads project / file / Claude-session context to detect when code is
// deliberately vulnerable (CTF challenge, sandbox, tutorial, example,
// fixture) so the scanner can demote findings rather than presenting them
// as production-grade issues.
//
// Signal sources (in order of strength):
//
//   1. .agentic-security/current-intent.md
//      A file Claude (or the user) writes to declare the current
//      session's intent. The PreToolUse / SessionStart hook can populate
//      this from the recent transcript. Format:
//        # Intent
//        - tutorial: building an intentional SQLi demo for our security training
//        - excluded-paths: ["examples/sqli-demo/**"]
//
//   2. File header comments (first ~1500 chars):
//      @sandbox / @example / @intentionally-vulnerable / @ctf-challenge /
//      @demo / @tutorial / // INTENTIONALLY VULNERABLE
//
//   3. Path patterns: examples/, demo/, demos/, tutorial/, sandbox/,
//      playground/, challenges/, ctf/
//
//   4. CLAUDE.md section headed "Intentionally vulnerable" / "Out of scope"
//
// Opt-out: AGENTIC_SECURITY_NO_INTENT_CTX=1

import * as fs from 'node:fs';
import * as path from 'node:path';

const INTENT_PATH_RE = /(?:^|\/)(?:examples?|demos?|tutorials?|sandbox|playground|challenges?|ctf)(?:\/|$)/i;

const FILE_HEADER_MARKERS = [
  /@sandbox\b/i,
  /@example\b/i,
  /@intentionally[-_]?vulnerable\b/i,
  /@ctf[-_]?challenge\b/i,
  /@demo\b/i,
  /@tutorial\b/i,
  /(?:^|[^A-Za-z])INTENTIONALLY[- ]?VULNERABLE(?:[^A-Za-z]|$)/,
  /(?:^|[^A-Za-z])DELIBERATELY[- ]?UNSAFE(?:[^A-Za-z]|$)/,
];

const HEADER_BUDGET = 1500;

function _readSafely(fp) {
  try { return fs.readFileSync(fp, 'utf8'); } catch { return ''; }
}

function _readIntentDeclaration(scanRoot) {
  const fp = path.join(scanRoot, '.agentic-security', 'current-intent.md');
  if (!fs.existsSync(fp)) return null;
  const body = _readSafely(fp);
  if (!body) return null;
  const exMatch = body.match(/excluded-paths\s*:\s*\[([\s\S]*?)\]/);
  let excludedPaths = [];
  if (exMatch) {
    excludedPaths = (exMatch[1].match(/"([^"]+)"|'([^']+)'/g) || [])
      .map(s => s.replace(/['"]/g, ''));
  }
  return { body, excludedPaths };
}

function _claudeMdHasOutOfScope(scanRoot) {
  const fp = path.join(scanRoot, 'CLAUDE.md');
  if (!fs.existsSync(fp)) return [];
  const body = _readSafely(fp);
  const out = [];
  const re = /^#{1,3}\s+(?:Out[- ]of[- ]scope|Intentionally vulnerable|Sandbox|Examples?)[\s\S]*?(?=\n#{1,3}\s|$(?![\s\S]))/gim;
  let m;
  while ((m = re.exec(body))) {
    const sec = m[0];
    // Pull file globs / paths from the section.
    const paths = (sec.match(/`([^`]+)`/g) || []).map(s => s.replace(/`/g, ''));
    out.push(...paths.filter(p => /\/|\*/.test(p)));
  }
  return out;
}

function _fileHeaderHasIntent(file) {
  if (!file) return false;
  try {
    const fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(HEADER_BUDGET);
    fs.readSync(fd, buf, 0, HEADER_BUDGET, 0);
    fs.closeSync(fd);
    const head = buf.toString('utf8');
    return FILE_HEADER_MARKERS.some(re => re.test(head));
  } catch { return false; }
}

function _globMatch(pattern, p) {
  // Minimal glob: `**` → `.*`, `*` → `[^/]*`. Path separators normalized.
  const norm = String(p).replace(/\\/g, '/');
  const re = new RegExp(
    '^' + String(pattern).replace(/\\/g, '/')
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '###DSTAR###')
      .replace(/\*/g, '[^/]*')
      .replace(/###DSTAR###/g, '.*')
    + '$',
  );
  return re.test(norm);
}

/**
 * Extract intent signals once per scan.
 */
export function extractIntentSignals(scanRoot) {
  if (process.env.AGENTIC_SECURITY_NO_INTENT_CTX === '1') {
    return { declaredExcludedPaths: [], claudeMdExcludedPaths: [], intent: null };
  }
  const decl = _readIntentDeclaration(scanRoot);
  const claudeMdPaths = _claudeMdHasOutOfScope(scanRoot);
  return {
    declaredExcludedPaths: decl ? decl.excludedPaths : [],
    claudeMdExcludedPaths: claudeMdPaths,
    intent: decl ? decl.body : null,
  };
}

/**
 * Per-finding suppression. Returns the count of findings demoted.
 * Findings are mutated in place — sets `intentSuppressed=true`, drops
 * confidence by 50%, adds 'intent-suppressed' tag.
 */
export function suppressByIntent(scanRoot, findings) {
  if (process.env.AGENTIC_SECURITY_NO_INTENT_CTX === '1') return { applied: 0 };
  if (!Array.isArray(findings) || findings.length === 0) return { applied: 0 };
  const signals = extractIntentSignals(scanRoot);
  const allExcluded = [...signals.declaredExcludedPaths, ...signals.claudeMdExcludedPaths];

  let applied = 0;
  const fileHeaderCache = new Map();

  for (const f of findings) {
    const file = f.file || '';
    const rel = path.isAbsolute(file) ? path.relative(scanRoot, file) : file;
    let suppress = false;
    let reason = null;

    if (INTENT_PATH_RE.test(rel)) { suppress = true; reason = 'intent-path-pattern'; }

    if (!suppress && allExcluded.length) {
      for (const pat of allExcluded) {
        if (_globMatch(pat, rel)) { suppress = true; reason = 'intent-declared-exclusion'; break; }
      }
    }

    if (!suppress && file) {
      let hdr = fileHeaderCache.get(file);
      if (hdr === undefined) {
        hdr = _fileHeaderHasIntent(file);
        fileHeaderCache.set(file, hdr);
      }
      if (hdr) { suppress = true; reason = 'intent-file-header'; }
    }

    if (suppress) {
      f.intentSuppressed = true;
      f.intentReason = reason;
      if (typeof f.confidence === 'number') f.confidence = Math.max(0.15, f.confidence * 0.5);
      f.tags = Array.isArray(f.tags) ? f.tags : [];
      if (!f.tags.includes('intent-suppressed')) f.tags.push('intent-suppressed');
      applied++;
    }
  }
  return { applied, total: findings.length };
}

export const _internals = {
  INTENT_PATH_RE, FILE_HEADER_MARKERS,
  _readIntentDeclaration, _claudeMdHasOutOfScope, _fileHeaderHasIntent, _globMatch,
};
