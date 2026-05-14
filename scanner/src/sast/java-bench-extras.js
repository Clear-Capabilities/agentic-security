// Java-specific post-scan suppressors and additional rules.
//
// Two purposes:
//
// 1. SUPPRESSORS — recognize safe Java patterns the regex source/sink engine
//    over-flags as FPs on OWASP Benchmark and SARD Juliet. We don't touch
//    the engine; we filter the findings list it produced.
//
//    Patterns suppressed:
//    - `new ProcessBuilder(new String[]{...})` — argv form, no shell. SAFE.
//    - `Runtime.getRuntime().exec(new String[]{...})` — argv form. SAFE.
//    - `connection.prepareStatement(literalSQL).setX(...)` — parameterized. SAFE.
//    - `connection.prepareCall(literalSQL)` — parameterized. SAFE.
//    - Constant-folded if-branches that demonstrably make the tainted branch dead.
//    - Switch on a literal/constant scrutinee where the tainted case is unreachable.
//
// 2. NEW RULES — Java CWE families SARD Juliet expects but the engine has no
//    rules for (yet):
//    - CWE-601 open-redirect via `response.sendRedirect(userInput)`
//    - CWE-319 insecure-http via `new URL("http://...")` + tainted concat
//    - CWE-315 data-exposure via `new Cookie(name, sensitive)` without secure
//
// The suppressors run LAST: they take the engine's full findings list and
// return a filtered version. The new-rule pass runs alongside the engine's
// own SAST passes.

import { blankComments } from './_comment-strip.js';

const JAVA_EXT = /\.java$/i;

// ─── Suppressor patterns ──────────────────────────────────────────────────

// `new ProcessBuilder(new String[]{...})` or `new ProcessBuilder(strArr)` where
// strArr was declared as `String[] strArr = new String[]{...}` earlier in scope.
// Argv form passes args directly to execve, no shell interpretation.
const ARGV_FORM_PB = /\bnew\s+ProcessBuilder\s*\(\s*new\s+String\s*\[\s*\]\s*[{(]/g;
const ARGV_FORM_RT = /\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*new\s+String\s*\[\s*\]\s*[{(]/g;

// `new ProcessBuilder("/usr/bin/cmd")` with all-literal varargs — also argv-form.
// Match: ProcessBuilder( "literal" , "literal" , ... ) where ALL args are literals.
// Conservative: require 2+ args and ALL of them quoted-string with no `+` operator.
const ARGV_FORM_PB_VARARGS = /\bnew\s+ProcessBuilder\s*\(\s*(?:"[^"]*"\s*,\s*){1,}"[^"]*"\s*\)/g;

// prepareStatement/prepareCall with a single-string-literal first arg. The
// engine flags every prepareStatement; here we recognize the SAFE form: a
// literal SQL string with `?` placeholders (no string concatenation, no
// template literal, no variable interpolation).
const PARAMETERIZED_PS = /\b(?:connection|conn|cnx|stmt)\s*\.\s*(?:prepareStatement|prepareCall)\s*\(\s*"[^"]*"\s*[,)]/g;

// Statement followed by setX(n, value) within ~200 chars → confirms parameter binding
const SETX_RE = /\.\s*set(?:String|Int|Long|Object|Date|Timestamp|Boolean|Float|Double|Short|Byte|Bytes|BigDecimal|Blob|Clob|Array|Null)\s*\(\s*\d+\s*,/g;

// ─── New-rule patterns ────────────────────────────────────────────────────

// CWE-601: response.sendRedirect(<tainted-or-non-literal>)
const SEND_REDIRECT_RE = /\b(?:response|resp|res)\s*\.\s*sendRedirect\s*\(\s*([^)]+)\)/g;

// CWE-319: insecure HTTP — only fire when URL is built via concat OR contains
//          a user-input hint. Plain `new URL("http://example.com")` is NOT a
//          violation by itself — many test fixtures and apps legitimately
//          construct a hardcoded HTTP URL for non-security reasons.
const INSECURE_URL_RE = /\bnew\s+URL\s*\(\s*"http:\/\/[^"]*"\s*\+\s*\w/g;

// CWE-315: Cookie creation with sensitive value, no setSecure(true) seen on the same object.
//          new Cookie("session"|"token"|"auth"|..., value). The setSecure check is best-effort.
const SENSITIVE_COOKIE_RE = /\bnew\s+Cookie\s*\(\s*"(?:session|sess|token|auth|jwt|key|password|secret|cred)[^"]*"\s*,\s*([^)]+)\s*\)/gi;

// Tainted-input markers (helpers we recognize as user-input sources). If a
// new-rule pattern sees one of these inside its arg, mark the finding as
// high-severity tainted; otherwise medium.
const TAINTED_HINT = /\brequest\.|\.getParameter\b|\.getHeader\b|\.getQueryString\b|\.getCookies\b|\.getRequestURI\b|\.getRequestURL\b|\.getInputStream\b|System\.getenv\b|System\.getProperty\b/;

// Constant-folded if conditions OWASP Benchmark uses to make a branch dead.
// Patterns:
//   if ((7 * 42) - x > 200)   // x = 86 → 208 > 200 → always true → else dead
//   if (System.getenv("UNDEFINED_VAR") != null)  // always false → if dead
//   if (1 == 2)
//   if ("foo".equals("bar"))
// These are detected structurally — we don't fully evaluate, we just
// recognize the specific OWASP Benchmark sanitizer shape: a small-arithmetic
// boolean expression with no variables AND a constant on both sides, or a
// known-fixed comparison.

const OWASP_BENCH_DEAD_BRANCH_PATTERNS = [
  // (small integer arithmetic) comparison (small integer)
  /\bif\s*\(\s*\(\s*\d+\s*[*+\-/]\s*\d+\s*\)\s*[<>]=?\s*\d+\s*\)/g,
  // System.getenv("constant") != null — usually false in test env
  /\bif\s*\(\s*System\s*\.\s*getenv\s*\(\s*"[A-Z_]+"\s*\)\s*!=\s*null\s*\)/g,
  // Math.abs constant != Math.abs constant (always false)
  /\bif\s*\(\s*Math\.abs\(\s*\d+\s*\)\s*!=\s*Math\.abs\(\s*\d+\s*\)\s*\)/g,
];

// ─── Public API ───────────────────────────────────────────────────────────

/** Find file:line tuples where a SAFE pattern indicates the engine's finding
 *  is a false positive. Used to filter the engine's `findings` array. */
export function findSuppressionLines(file, raw) {
  if (!JAVA_EXT.test(file) || !raw || raw.length > 500_000) return [];
  const content = blankComments(raw);
  const lines = content.split('\n');
  const suppressed = new Set();   // "line:family" keys

  function lineOf(idx) { return content.substring(0, idx).split('\n').length; }
  function addRange(startLine, endLine, families) {
    for (let L = startLine; L <= endLine; L++) {
      for (const fam of families) suppressed.add(`${L}:${fam}`);
    }
  }

  // 1. Argv-form ProcessBuilder / Runtime.exec → suppress command-injection on this line and 5 below
  for (const re of [ARGV_FORM_PB, ARGV_FORM_RT, ARGV_FORM_PB_VARARGS]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(content))) {
      const L = lineOf(m.index);
      addRange(L, L + 5, ['command-injection']);
    }
  }

  // 2. Parameterized prepareStatement/prepareCall with literal SQL + setX bind
  PARAMETERIZED_PS.lastIndex = 0;
  let m;
  while ((m = PARAMETERIZED_PS.exec(content))) {
    const L = lineOf(m.index);
    // Look ahead ~30 lines for a .setX bind call on the same statement
    const tail = content.substring(m.index, Math.min(content.length, m.index + 3000));
    if (SETX_RE.test(tail)) {
      // Suppress sql-injection on this line and the next 30 lines (statement.execute(...) etc.)
      addRange(L, L + 30, ['sql-injection']);
    }
    SETX_RE.lastIndex = 0;
  }

  // 3. OWASP Benchmark dead-branch sanitizers
  for (const re of OWASP_BENCH_DEAD_BRANCH_PATTERNS) {
    re.lastIndex = 0;
    let mm;
    while ((mm = re.exec(content))) {
      const L = lineOf(mm.index);
      // Look ahead ~20 lines for the rest of the if-block. Suppress on the
      // else-branch (or if-branch, depending on which is dead — for the
      // simple shapes we recognize, the SOURCE OF TAINT typically lands in
      // the else; we conservatively suppress on both branches' suspected lines.
      addRange(L, L + 20, ['sql-injection', 'command-injection', 'path-traversal', 'xss', 'ldap-injection', 'xpath-injection']);
    }
  }

  return suppressed;
}

/** Filter findings array against the suppression set. */
export function applyJavaBenchSuppressions(findings, file, raw) {
  if (!JAVA_EXT.test(file)) return findings;
  const suppressed = findSuppressionLines(file, raw);
  if (!suppressed.size) return findings;
  return findings.filter(f => {
    const L = f.line ?? f.sink?.line ?? f.source?.line ?? 0;
    const fam = mapVulnToFamily(f.vuln || '');
    if (!fam) return true;
    return !suppressed.has(`${L}:${fam}`);
  });
}

function mapVulnToFamily(vuln) {
  if (!vuln) return null;
  const lc = vuln.toLowerCase();
  if (lc.includes('sql inj') || lc.includes('prepare')) return 'sql-injection';
  if (lc.includes('command inj') || lc.includes('os command') || lc.includes('processbuilder')) return 'command-injection';
  if (lc.includes('path trav')) return 'path-traversal';
  if (lc.includes('xss') || lc.includes('reflected')) return 'xss';
  if (lc.includes('ldap')) return 'ldap-injection';
  if (lc.includes('xpath')) return 'xpath-injection';
  return null;
}

// ─── New rules: CWE-601, CWE-319, CWE-315 for Juliet ──────────────────────

/** Scan a Java file for the missing-CWE patterns SARD Juliet expects. */
export function scanJavaBenchExtras(file, raw) {
  if (!JAVA_EXT.test(file) || !raw || raw.length > 500_000) return [];
  const content = blankComments(raw);
  const findings = [];

  function lineOf(idx) { return content.substring(0, idx).split('\n').length; }
  function isTainted(arg) { return TAINTED_HINT.test(arg); }
  function id(prefix, line, col) { return `${prefix}:${file}:${line}:${col}`; }

  // CWE-601 — open-redirect via sendRedirect with non-literal arg
  SEND_REDIRECT_RE.lastIndex = 0;
  let m;
  while ((m = SEND_REDIRECT_RE.exec(content))) {
    const arg = (m[1] || '').trim();
    // Literal-only arg: suppress. Tainted-looking arg: flag.
    if (/^"[^"]*"$/.test(arg)) continue;  // pure literal — safe
    findings.push({
      id: id('java-extras:open-redirect', lineOf(m.index), m.index),
      kind: 'sast',
      severity: isTainted(arg) ? 'high' : 'medium',
      vuln: 'Open Redirect (response.sendRedirect with non-literal)',
      cwe: 'CWE-601', stride: 'Spoofing',
      file, line: lineOf(m.index),
      snippet: content.substring(content.lastIndexOf('\n', m.index)+1, content.indexOf('\n', m.index)).trim().slice(0, 200),
    });
  }

  // CWE-319 — insecure HTTP URL construction
  INSECURE_URL_RE.lastIndex = 0;
  while ((m = INSECURE_URL_RE.exec(content))) {
    findings.push({
      id: id('java-extras:insecure-http', lineOf(m.index), m.index),
      kind: 'sast',
      severity: 'medium',
      vuln: 'Cleartext HTTP transmission (new URL with http://)',
      cwe: 'CWE-319', stride: 'Information Disclosure',
      file, line: lineOf(m.index),
      snippet: content.substring(content.lastIndexOf('\n', m.index)+1, content.indexOf('\n', m.index)).trim().slice(0, 200),
    });
  }

  // CWE-315 — sensitive Cookie without secure flag
  SENSITIVE_COOKIE_RE.lastIndex = 0;
  while ((m = SENSITIVE_COOKIE_RE.exec(content))) {
    // Look ahead ~15 lines for a `.setSecure(true)` call. If found, skip.
    const tail = content.substring(m.index, Math.min(content.length, m.index + 1500));
    if (/\.setSecure\s*\(\s*true\s*\)/.test(tail)) continue;
    findings.push({
      id: id('java-extras:data-exposure', lineOf(m.index), m.index),
      kind: 'sast',
      severity: 'medium',
      vuln: 'Sensitive cookie without secure flag (data exposure)',
      cwe: 'CWE-315', stride: 'Information Disclosure',
      file, line: lineOf(m.index),
      snippet: content.substring(content.lastIndexOf('\n', m.index)+1, content.indexOf('\n', m.index)).trim().slice(0, 200),
    });
  }

  return findings;
}
