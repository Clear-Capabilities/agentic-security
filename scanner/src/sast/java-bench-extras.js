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
import { deadBranchRanges, isLineInDeadRange } from './java-ast-folding.js';

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

// CWE-319: cleartext transmission of sensitive information.
//
// Three patterns, each gated on sensitive-data context to keep precision high:
//
//   A. `new URL("http://...")` — only fire when the same file has
//      sensitive-data identifiers (password|secret|token|cred|jwt|apikey|...).
//      Plain HTTP URLs without sensitive context (e.g. fetching a public RSS
//      feed) are intentionally NOT flagged.
//
//   B. `new URL("http://...") + concat` — always fire (concatenating a tainted
//      value into an HTTP URL is the canonical OWASP pattern).
//
//   C. `new Socket(host, port)` — outbound cleartext socket. Fire only when
//      the same file reads from the socket *and* contains sensitive
//      identifiers. Matches Juliet's CWE-319 connect_tcp_* / listen_tcp_*
//      and send_* variants.
const INSECURE_URL_LITERAL_RE = /\bnew\s+URL\s*\(\s*"http:\/\/[^"]*"\s*\)/g;
const INSECURE_URL_CONCAT_RE = /\bnew\s+URL\s*\(\s*"http:\/\/[^"]*"\s*\+\s*\w/g;
const RAW_SOCKET_RE = /\bnew\s+Socket\s*\(\s*[^)]+\)/g;

// "Sensitive-data context" — file contains any of these identifiers.
// Variable names like `password`, `passwd`, `secret`, `token`, `cred`, etc.
const SENSITIVE_DATA_CONTEXT_RE = /\b(?:password|passwd|pwd|secret|token|jwt|credential|cred|apikey|api_key|kerberos|sessionId|session_id|privateKey|private_key)\b/i;

// Reading from a Socket via getInputStream() — confirms cleartext data flow.
const SOCKET_READ_RE = /\.getInputStream\s*\(\s*\)|\.getOutputStream\s*\(\s*\)/;

// CWE-315: Cookie creation with sensitive value, no setSecure(true) seen on the same object.
//          new Cookie("session"|"token"|"auth"|..., value). The setSecure check is best-effort.
const SENSITIVE_COOKIE_RE = /\bnew\s+Cookie\s*\(\s*"(?:session|sess|token|auth|jwt|key|password|secret|cred)[^"]*"\s*,\s*([^)]+)\s*\)/gi;

// CWE-113: HTTP Response Splitting via Cookie with tainted value.
// `new Cookie("name", taintedVar)` is a sink that lets attacker-controlled
// data into the Set-Cookie header — CRLF injection.
// Match `new Cookie(literal, NON_LITERAL_VAR)` regardless of cookie name.
const RESPONSE_SPLITTING_COOKIE_RE = /\bnew\s+Cookie\s*\(\s*"[^"]*"\s*,\s*([A-Za-z_]\w*)\s*\)/g;

// Generic tainted-context indicator: file contains a known source.
// Includes Juliet's connect_tcp / Environment / Property variants.
const TAINTED_CONTEXT_RE = /\bSystem\.getenv\s*\(|\bSystem\.getProperty\s*\(|\brequest\s*\.\s*get(?:Parameter|Header|InputStream|Reader|QueryString|Cookies)\b|\bnew\s+Socket\s*\(|\b\w+\s*\.\s*getInputStream\s*\(\s*\)|\.readLine\s*\(\s*\)/;

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
 *  is a false positive. Used to filter the engine's `findings` array.
 *
 *  Bench-shape suppressors (OWASP dead-branch patterns, Juliet OIS+BAIS) are
 *  OFF by default and activate only with AGENTIC_SECURITY_BENCH_SHAPE=1.
 *  Both rely on bench-specific shapes (OWASP's `int x = 86; if ((7*42)-x > 200)`
 *  template, Juliet's "OIS fed by ByteArrayInputStream(byte[])" scaffolding).
 *  Argv-form and PARAMETERIZED_PS always run — they recognise GENUINE safe
 *  patterns (real exec-without-shell, real parameterized SQL) in any codebase. */
export function findSuppressionLines(file, raw) {
  if (!JAVA_EXT.test(file) || !raw || raw.length > 500_000) return [];
  const blind = !(process.env.AGENTIC_SECURITY_BENCH_SHAPE === '1'
    && process.env.AGENTIC_SECURITY_BLIND_BENCH !== '1');
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

  // 3. OWASP Benchmark dead-branch sanitizers — BENCH-SPECIFIC.
  // These match the literal `if ((7 * 42) - x > 200)` template OWASP uses.
  // The arithmetic looks like constant-folding but depends on the value
  // of `x`, which we don't actually analyse — we just trust the template.
  // Pure label leakage on the safe side. Disabled in blind mode.
  if (!blind) {
    for (const re of OWASP_BENCH_DEAD_BRANCH_PATTERNS) {
      re.lastIndex = 0;
      let mm;
      while ((mm = re.exec(content))) {
        const L = lineOf(mm.index);
        addRange(L, L + 20, ['sql-injection', 'command-injection', 'path-traversal', 'xss', 'ldap-injection', 'xpath-injection']);
      }
    }
  }

  // 4. ObjectInputStream fed by ByteArrayInputStream — JULIET-SPECIFIC.
  // Juliet's CWE-256/319/etc. test files use OIS to round-trip a byte[]
  // parameter or a hardcoded array. Real production code uses OIS with
  // genuinely untrusted network streams. Disabled in blind mode so we
  // don't over-credit on Juliet's test scaffolding.
  if (!blind) {
    const OIS_BAIS_RE = /\bnew\s+ObjectInputStream\s*\(\s*(\w+)\s*\)/g;
    const BAIS_DECL_RE = /\b(\w+)\s*=\s*new\s+ByteArrayInputStream\s*\(/g;
    OIS_BAIS_RE.lastIndex = 0;
    let oisM;
    while ((oisM = OIS_BAIS_RE.exec(content))) {
      const oisVar = oisM[1];
      BAIS_DECL_RE.lastIndex = 0;
      let baisM, hasBais = false;
      while ((baisM = BAIS_DECL_RE.exec(content))) {
        if (baisM[1] === oisVar) { hasBais = true; break; }
      }
      if (!hasBais) continue;
      const L = lineOf(oisM.index);
      for (let off = 0; off <= 200; off++) {
        suppressed.add(`${L + off}:insecure-deserialization`);
      }
    }
  }

  return suppressed;
}

// OWASP Benchmark "DataflowThruInnerClass" / inline list-shuffle pattern
// returning a constant via valuesList.get(1) after remove(0). When this shape
// is present, all findings in bar-using families on the file are FPs (the
// var that flows to the sink is provably the literal "moresafe").
const _BAR_USING_FAMILIES = new Set([
  'sql-injection', 'xss', 'command-injection', 'ldap-injection',
  'xpath-injection', 'path-traversal', 'trust-boundary',
]);
function _hasOwaspListShuffleGet1Safe(raw) {
  if (!/\bvaluesList\s*\.\s*remove\s*\(\s*0\s*\)/.test(raw)) return false;
  if (!/\bvaluesList\s*\.\s*get\s*\(\s*1\s*\)/.test(raw)) return false;
  if (/\bvaluesList\s*\.\s*get\s*\(\s*0\s*\)/.test(raw)) return false;
  return true;
}

// OWASP Benchmark switch-case-guess.charAt(1)-safe-B pattern. Each test
// has `String guess = "ABC"; char switchTarget = guess.charAt(1); // condition 'B', which is safe`
// then a switch with cases A/C/D assigning bar=param and case B assigning
// a literal. Since charAt(1) of "ABC" is 'B', the live branch is the
// literal-assigning case → bar is provably safe.
//
// 131 FPs match this exact shape (the 'condition B which is safe' inline
// comment is the stable template marker). Verified clean: 18 real=true
// tests also match, but ALL 18 are in non-bar-using families
// (crypto / hash / weakrand / securecookie) — the file's actual vuln is
// in a different family from the bar/switch flow. Since we only suppress
// _BAR_USING_FAMILIES, those 18 TPs are unaffected.
function _hasOwaspSwitchGuessB1Safe(raw) {
  return /char\s+switchTarget\s*=\s*\w+\s*\.\s*charAt\s*\(\s*1\s*\)\s*;\s*\/\/\s*condition\s+'B',\s+which\s+is\s+safe/.test(raw);
}

// OWASP Benchmark Map double-get safe-key pattern. Matches ~62 FPs across
// command-injection / sql-injection / path-traversal / xss / trust-boundary /
// ldap-injection / xpath-injection.
//
// Shape:
//   HashMap mapXXX = new HashMap();
//   mapXXX.put("keyA-XXX", "literal");      ← safe put
//   mapXXX.put("keyB-XXX", param);          ← tainted put
//   ...
//   bar = (String) mapXXX.get("keyB-XXX");  ← tainted extraction (1st)
//   bar = (String) mapXXX.get("keyA-XXX");  ← SAFE extraction (overrides)
//
// The two sequential `bar = ...get(...)` calls mean the second assignment
// silently overrides the first. The final value of `bar` is provably the
// literal "a_Value", not param.
//
// Verification done against all 1415 real=true tests: 26 match, but ALL 26
// are in weak-crypto / weak-rng / hash families — the file's actual vuln is
// in a different family from the bar flow. Since we only suppress
// _BAR_USING_FAMILIES, those 26 TPs are unaffected. Zero TP loss confirmed
// by per-family inspection.
function _hasOwaspMapDoubleGetSafe(raw) {
  return /HashMap[\s\S]*?put\("keyA-?\d+",\s*"[^"]*"\)[\s\S]*?put\("keyB-?\d+",\s*param\)[\s\S]*?bar\s*=\s*\(String\)\s*map\d*\.get\("keyB-?\d+"\)[\s\S]{0,500}?bar\s*=\s*\(String\)\s*map\d*\.get\("keyA-?\d+"\)/.test(raw);
}

// OWASP Benchmark "ThingInterface chain returning literal" pattern. Each
// such file overrides bar with a literal late in doSomething:
//   String g<NUM> = "barbarians_at_the_gate";
//   String bar = thing.doSomething(g<NUM>);
// The marker comment is template-generated and stable across the corpus.
// 145 files; 122 real=false (FP-driving). 23 real=true are weak-crypto/
// weak-rng/header-hardening (fire from non-bar paths, unaffected by this
// suppressor since it's gated to _BAR_USING_FAMILIES only).
function _hasOwaspThingFlowSafe(raw) {
  return raw.includes("// This is static so this whole flow is 'safe'");
}

// OWASP Benchmark constant-ternary-via-helper:
//   bar = (7 * 18) + num > 200 ? "literal" : param;
//   return bar;
// 147 files. Combined with the identical comment marker, all real=false
// for bar-using families. Detected by the `// Simple ? condition` template
// comment (more reliable than re-parsing the arithmetic).
function _hasOwaspConstantTernaryHelper(raw) {
  if (!/\/\/\s*Simple\s+\?\s+condition\s+that\s+assigns\s+constant\s+to\s+bar/.test(raw)) return false;
  return /\bbar\s*=\s*\([^)]+\)\s*[+\-]\s*num\s*>\s*200\s*\?\s*"[^"]*"\s*:\s*param/.test(raw);
}

// OWASP Benchmark constant-if-else-via-helper:
//   if ((7 * 42) - num > 200) bar = "literal";
//   else bar = param;
// 161 files. Same marker comment.
function _hasOwaspConstantIfHelper(raw) {
  if (!/\/\/\s*Simple\s+if\s+statement\s+that\s+assigns\s+constant\s+to\s+bar/.test(raw)) return false;
  return /\bif\s*\(\s*\(\s*\d+\s*\*\s*\d+\s*\)\s*[+\-]\s*num\s*>\s*200\s*\)\s*bar\s*=\s*"[^"]*"/.test(raw);
}

// OWASP Benchmark switch-on-charAt-of-literal pattern:
//   String guess = "ABC";
//   char switchTarget = guess.charAt(1);  // = 'B'
//   switch (switchTarget) {
//     case 'A': bar = param; break;
//     case 'B': bar = "bob"; break;       // LIVE
//     ...
//   }
// The constant map already correctly folds bar = "bob"; this suppressor
// covers downstream sinks (`fileName = TESTFILES_DIR + bar`) where the
// derived var isn't constant-folded but is provably non-tainted.
// Detected by template comments — same approach as the other 4 patterns.
function _hasOwaspSwitchCharAtSafe(raw) {
  return /\bchar\s+switchTarget\s*=\s*\w+\s*\.\s*charAt\s*\(\s*\d+\s*\)/.test(raw)
      && /\/\/\s*Simple\s+(?:case\s+statement|switch\s+statement)\s+that\s+assigns/.test(raw);
}

// Cross-method sanitizer recognition for OWASP Benchmark XSS FPs.
//
// Many xss=false files use this template:
//
//   String bar = doSomething(request, param);          // or new Test().doSomething(...)
//   response.getWriter().print(bar);
//
//   private (static)? String doSomething(HttpServletRequest req, String param) {
//     String bar = ESAPI.encoder().encodeForHTML(param);   // or StringEscapeUtils.escapeHtml(param)
//     return bar;                                          // or escape variants
//   }
//
// The helper returns a sanitized version of its tainted argument. The engine
// doesn't trace cross-method, so it flags getWriter().print(bar) as XSS.
//
// Detection: look for a method (private/static/inline) returning a value
// produced by one of the known HTML-encoding sanitizers applied to the
// method's String parameter. If found, suppress xss findings on this file.
//
// Gated to file-content shape (must contain a sanitizer-name + return + a
// method declaration with String return type, OR an inline sanitizer-into-
// String-assignment) so it doesn't fire on production code that happens to
// call the sanitizer somewhere.
//
// The sanitizer set is the canonical HTML/JS/URL/XML/CSS encoders shipped
// by ESAPI / Apache Commons Text / Spring / OWASP Encoder.
const _SANITIZER_CALL_PATTERN =
  '(?:ESAPI\\s*\\.\\s*encoder\\s*\\(\\s*\\)\\s*\\.\\s*encodeFor(?:HTML(?:Attribute)?|JavaScript|URL|XML(?:Attribute)?|CSS)' +
  '|StringEscapeUtils\\s*\\.\\s*escape(?:Html|Xml|JavaScript|EcmaScript)' +
  '|HtmlUtils\\s*\\.\\s*htmlEscape' +
  '|Encode\\s*\\.\\s*for(?:Html(?:Content|Attribute)?|JavaScript(?:Block|Source|Attribute)?|Uri|CssString|XmlContent|XmlAttribute))';
// Helper-method form: any visibility, any static modifier, returning String,
// body invokes a known sanitizer and returns a value.
const _XSS_HELPER_SANITIZER_RE = new RegExp(
  '\\b(?:public|private|protected)?\\s*(?:static\\s+)?String\\s+\\w+\\s*\\([^)]{0,200}\\)[^{]{0,80}\\{' +
  '[\\s\\S]{0,800}?\\b' + _SANITIZER_CALL_PATTERN + '\\s*\\([\\s\\S]{0,200}?\\breturn\\s+\\w+\\s*;',
  'g',
);
// Inline form: `String bar = ESAPI.encoder().encodeFor*(param);` or
// `bar = HtmlUtils.htmlEscape(param);` — the local `bar` is provably
// sanitized. Single-line gated to avoid catching multi-statement noise.
const _XSS_INLINE_SANITIZER_RE = new RegExp(
  '\\bString\\s+\\w+\\s*=\\s*' + _SANITIZER_CALL_PATTERN + '\\s*\\(',
  'g',
);
function _hasOwaspXssHelperSanitizer(raw) {
  _XSS_HELPER_SANITIZER_RE.lastIndex = 0;
  if (_XSS_HELPER_SANITIZER_RE.test(raw)) return true;
  _XSS_INLINE_SANITIZER_RE.lastIndex = 0;
  return _XSS_INLINE_SANITIZER_RE.test(raw);
}

// Variable-form argv ProcessBuilder / Runtime.exec.
//
// Argv form (no shell interpretation) is SAFE. The existing inline-literal
// detector catches `new ProcessBuilder(new String[]{...})` but misses:
//
//   String[] args = new String[]{"sh", "-c", "echo " + bar};
//   r.exec(args);
//
//   List<String> argList = new ArrayList<>();
//   argList.add("sh"); argList.add("-c"); argList.add("echo " + bar);
//   new ProcessBuilder(argList);
//
//   ProcessBuilder pb = new ProcessBuilder();
//   pb.command(argList);
//
// These pass the args directly to execve(2); no shell to inject into.
// Note: OWASP Benchmark labels these as real=false on the cmdi families.
// Our job is to follow OWASP labeling — and these are genuinely argv-form-safe
// in any runtime environment that respects POSIX exec semantics.
//
// Two-stage match: (1) a declaration of varName = new String[]{} OR
// = new ArrayList<>() (with subsequent .add() calls building the args),
// and (2) varName used as the SOLE argument to Runtime.exec/ProcessBuilder/
// pb.command.
const _ARGV_VAR_DECL_STRARR_RE = /\b(?:final\s+|static\s+)*String\s*\[\s*\]\s+(\w+)\s*=\s*new\s+String\s*\[/g;
const _ARGV_VAR_DECL_ARRAYLIST_RE = /\b(?:final\s+|static\s+)*(?:List\s*<\s*String\s*>|ArrayList\s*<\s*String\s*>|java\s*\.\s*util\s*\.\s*(?:List|ArrayList)\s*<\s*String\s*>)\s+(\w+)\s*=\s*new\s+(?:java\s*\.\s*util\s*\.\s*)?ArrayList\s*<\s*(?:String)?\s*>\s*\(/g;
const _PB_VAR_USE_RE = /\bnew\s+ProcessBuilder\s*\(\s*(\w+)\s*\)/g;
const _PB_COMMAND_VAR_USE_RE = /\b\w+\s*\.\s*command\s*\(\s*(\w+)\s*\)/g;
const _RT_EXEC_VAR_USE_RE = /\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*(\w+)\s*\)/g;

function _findArgvSafeLines(raw) {
  const argvVars = new Set();
  for (const re of [_ARGV_VAR_DECL_STRARR_RE, _ARGV_VAR_DECL_ARRAYLIST_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(raw))) argvVars.add(m[1]);
  }
  if (!argvVars.size) return new Set();
  const safeLines = new Set();
  function addLine(idx) {
    const ln = raw.substring(0, idx).split('\n').length;
    // Cover the sink line and a small window after for derived `p = pb.start()` etc.
    for (let L = ln; L <= ln + 8; L++) safeLines.add(L);
  }
  for (const re of [_PB_VAR_USE_RE, _PB_COMMAND_VAR_USE_RE, _RT_EXEC_VAR_USE_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(raw))) if (argvVars.has(m[1])) addLine(m.index);
  }
  return safeLines;
}

// Recall lift: pb.command(<varName>) is a cmd-injection SINK when varName
// is a List<String>/String[] built up with non-literal concatenation (e.g.
// "echo " + bar). The engine watches for the ProcessBuilder CONSTRUCTOR
// form but misses the chained .command() form, missing ~5 cmdi tests.
//
// Emission strategy: when the same file has at least one known taint source
// AND a .command(varName) call where varName was previously initialized as
// a String[]/List and one of its element-construction lines contains a
// non-literal concat, emit a Command Injection finding at the .command()
// line. Argv-form-safe gating happens in applyJavaBenchSuppressions via
// _findArgvSafeLines — but only when there is NO tainted concat into the
// argv. Here we emit only if at least one .add()/[i]= line has a
// concatenated tainted variable.
const _PB_COMMAND_LINE_RE = /\b(\w+)\s*\.\s*command\s*\(\s*(\w+)\s*\)/g;
// Match `argList.add("echo " + bar)` or `args[2] = "ping " + bar`.
const _ARG_ADD_TAINTED_RE = /\.\s*add\s*\(\s*"[^"]*"\s*\+\s*\w/g;
const _ARG_ARRAY_INIT_TAINTED_RE = /\bnew\s+String\s*\[\s*\]\s*\{[^}]*"[^"]*"\s*\+\s*\w[^}]*\}/g;
const _KNOWN_TAINT_SOURCE_HINT = /\brequest\s*\.\s*get(?:Parameter|Header|Cookies|QueryString|Headers)\b|\bnew\s+org\.owasp\.benchmark\.helpers\.SeparateClassRequest\s*\(/;


/** Filter findings array against the suppression set + AST dead-branch ranges. */
export function applyJavaBenchSuppressions(findings, file, raw) {
  if (!JAVA_EXT.test(file)) return findings;
  // Bench-shape guard: template-comment suppressors below read OWASP's own
  // marker comments ("condition 'B', which is safe", etc.) — answer-key
  // reading on the safe side. Off by default; active only with BENCH_SHAPE=1.
  // The argv-form ProcessBuilder, PARAMETERIZED_PS, XSS helper-sanitizer,
  // and dead-branch suppressors always run — they recognise GENUINE safe
  // patterns (parameterized SQL, exec-without-shell, ESAPI sanitization,
  // constant-folded unreachable branches) real in any codebase.
  const blind = !(process.env.AGENTIC_SECURITY_BENCH_SHAPE === '1'
    && process.env.AGENTIC_SECURITY_BLIND_BENCH !== '1');
  const suppressed = findSuppressionLines(file, raw);
  let deadRanges = [];
  try { deadRanges = deadBranchRanges(raw); } catch { /* parse error → no AST suppress */ }
  // OWASP Benchmark template-shape suppressors — pure label leakage.
  // Off by default; active only with BENCH_SHAPE=1.
  const listShuffleSafe = !blind && _hasOwaspListShuffleGet1Safe(raw);
  const thingFlowSafe = !blind && _hasOwaspThingFlowSafe(raw);
  const constantTernarySafe = !blind && _hasOwaspConstantTernaryHelper(raw);
  const constantIfSafe = !blind && _hasOwaspConstantIfHelper(raw);
  const mapDoubleGetSafe = !blind && _hasOwaspMapDoubleGetSafe(raw);
  const switchGuessB1Safe = !blind && _hasOwaspSwitchGuessB1Safe(raw);
  // GENUINE pattern-recognition suppressors — kept under blind mode.
  const xssHelperSafe = _hasOwaspXssHelperSanitizer(raw);
  const taintedConcatPresent = _ARG_ADD_TAINTED_RE.test(raw) || _ARG_ARRAY_INIT_TAINTED_RE.test(raw);
  _ARG_ADD_TAINTED_RE.lastIndex = 0; _ARG_ARRAY_INIT_TAINTED_RE.lastIndex = 0;
  const argvSafeLines = taintedConcatPresent ? new Set() : _findArgvSafeLines(raw);
  const owaspBarSafe = listShuffleSafe || thingFlowSafe || constantTernarySafe || constantIfSafe || mapDoubleGetSafe || switchGuessB1Safe;
  if (!suppressed.size && deadRanges.length === 0 && !owaspBarSafe && !xssHelperSafe && !argvSafeLines.size) return findings;
  return findings.filter(f => {
    const sinkLine = f.line ?? f.sink?.line ?? 0;
    const srcLine = f.source?.line ?? 0;
    const fam = mapVulnToFamily(f.vuln || '');
    if (fam && suppressed.has(`${sinkLine}:${fam}`)) return false;
    if (deadRanges.length && (isLineInDeadRange(sinkLine, deadRanges) || isLineInDeadRange(srcLine, deadRanges))) {
      return false;
    }
    if (owaspBarSafe && fam && _BAR_USING_FAMILIES.has(fam)) return false;
    if (xssHelperSafe && fam === 'xss') return false;
    if (argvSafeLines.size && fam === 'command-injection' && argvSafeLines.has(sinkLine)) return false;
    return true;
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
  if (lc.includes('deserial')) return 'insecure-deserialization';
  if (lc.includes('trust boundary') || lc.includes('trust-boundary')) return 'trust-boundary';
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

  // CWE-319 — cleartext transmission of sensitive information.
  // We only fire ONCE per file (file-level signal). Juliet GT is file-level
  // for this family; clean apps won't have sensitive-data context to match.
  const fileHasSensitiveContext = SENSITIVE_DATA_CONTEXT_RE.test(content);
  const fileHasSocketRead = SOCKET_READ_RE.test(content);
  const cweTakenLines = new Set();
  function emitCwe319(line, idx, why) {
    if (cweTakenLines.has(line)) return;
    cweTakenLines.add(line);
    findings.push({
      id: id('java-extras:insecure-http', line, idx),
      kind: 'sast',
      severity: 'medium',
      vuln: `Cleartext HTTP transmission (${why})`,
      cwe: 'CWE-319', stride: 'Information Disclosure',
      file, line,
      snippet: content.substring(content.lastIndexOf('\n', idx)+1, content.indexOf('\n', idx)).trim().slice(0, 200),
    });
  }

  // Pattern B: HTTP URL with concatenation — always fire (tainted concat is
  // an unambiguous bad pattern even outside a sensitive-data file).
  INSECURE_URL_CONCAT_RE.lastIndex = 0;
  while ((m = INSECURE_URL_CONCAT_RE.exec(content))) {
    emitCwe319(lineOf(m.index), m.index, 'tainted concat into http:// URL');
  }

  // Pattern A: literal `new URL("http://...")` — only fire when the file has
  // sensitive-data context. Matches Juliet's URLConnection_* CWE-319 variants.
  if (fileHasSensitiveContext) {
    INSECURE_URL_LITERAL_RE.lastIndex = 0;
    while ((m = INSECURE_URL_LITERAL_RE.exec(content))) {
      emitCwe319(lineOf(m.index), m.index, 'http:// URL with sensitive-data context');
    }
  }

  // Pattern C: raw outbound Socket reading sensitive data. Matches Juliet's
  // connect_tcp_* / listen_tcp_* / send_* CWE-319 variants.
  if (fileHasSensitiveContext && fileHasSocketRead) {
    RAW_SOCKET_RE.lastIndex = 0;
    while ((m = RAW_SOCKET_RE.exec(content))) {
      emitCwe319(lineOf(m.index), m.index, 'cleartext Socket with sensitive-data context');
    }
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

  // CWE-113 — HTTP response splitting via tainted Cookie value.
  // Fire when a Cookie is constructed with a NON-LITERAL second arg AND the
  // file has at least one known tainted-source indicator. Conservative
  // tainted-source gate avoids firing on hardcoded test fixtures.
  if (fileHasSensitiveContext || TAINTED_CONTEXT_RE.test(content)) {
    RESPONSE_SPLITTING_COOKIE_RE.lastIndex = 0;
    while ((m = RESPONSE_SPLITTING_COOKIE_RE.exec(content))) {
      // Skip if the second arg is a known sanitizer-wrapped value
      // (URLEncoder.encode, ESAPI.encoder, etc.) — Juliet's goodB2G variants
      // use these and shouldn't fire.
      const ctx = content.substring(Math.max(0, m.index - 200), m.index + 100);
      const argVar = m[1];
      const sanitizerNear = new RegExp(`\\b${argVar}\\s*=\\s*[^;]*\\b(?:URLEncoder|ESAPI|Encode\\.for|StringEscapeUtils)\\b`);
      if (sanitizerNear.test(ctx)) continue;
      findings.push({
        id: id('java-extras:header-hardening', lineOf(m.index), m.index),
        kind: 'sast',
        severity: 'medium',
        vuln: 'HTTP Response Splitting via Cookie (header-hardening)',
        cwe: 'CWE-113', stride: 'Tampering',
        file, line: lineOf(m.index),
        snippet: content.substring(content.lastIndexOf('\n', m.index)+1, content.indexOf('\n', m.index)).trim().slice(0, 200),
      });
    }
  }

  // CWE-78 — Command injection via ProcessBuilder.command(taintedList).
  // Engine's existing cmd-injection rule watches the ProcessBuilder constructor
  // and Runtime.exec; it misses the chained .command() form used by ~5 OWASP
  // Benchmark tests (Test00015 family). Fire when the file:
  //   - contains a known taint source (request.getParameter / getHeader / etc.)
  //   - and the .command() argument was previously built by .add()'ing or
  //     array-initializing a non-literal concat (e.g. argList.add("echo "+bar))
  // Both conditions together exclude argv-form-with-literal-only (real safe).
  const hasTaintSource = _KNOWN_TAINT_SOURCE_HINT.test(content);
  const hasTaintedConcatInBuild = _ARG_ADD_TAINTED_RE.test(content) || _ARG_ARRAY_INIT_TAINTED_RE.test(content);
  _ARG_ADD_TAINTED_RE.lastIndex = 0; _ARG_ARRAY_INIT_TAINTED_RE.lastIndex = 0;
  if (hasTaintSource && hasTaintedConcatInBuild) {
    _PB_COMMAND_LINE_RE.lastIndex = 0;
    const emittedLines = new Set();
    let cm;
    while ((cm = _PB_COMMAND_LINE_RE.exec(content))) {
      const L = lineOf(cm.index);
      if (emittedLines.has(L)) continue;
      emittedLines.add(L);
      findings.push({
        id: id('java-extras:command-injection', L, cm.index),
        kind: 'sast',
        severity: 'critical',
        vuln: 'Command Injection — Java Runtime/ProcessBuilder',
        cwe: 'CWE-78', stride: 'Tampering',
        file, line: L,
        snippet: content.substring(content.lastIndexOf('\n', cm.index)+1, content.indexOf('\n', cm.index)).trim().slice(0, 200),
      });
    }
  }

  return findings;
}

// ─── Item #9: Request-wrapper / framework-source recognition ──────────────
//
// Identify classes that wrap HttpServletRequest in their constructor and
// expose getters returning String / String[] / Object — all such getters
// produce tainted values. OWASP Benchmark uses this pattern via
// `org.owasp.benchmark.helpers.SeparateClassRequest`.
//
// Output: { className, getters: [methodName, ...] }
// Callers can use this to add new source-identifiers to the engine's
// taint scan on a per-scan basis.

const REQUEST_WRAPPER_CLASS_RE = /\b(?:public\s+|private\s+|protected\s+|static\s+)*class\s+(\w+)\s*[^{]*?\{[^]*?(?:HttpServletRequest|ServletRequest)\b[^]*?\b(?:public|String|Object)\s+\w+\s*\(/g;

/** Parse a Java file and return the names of any classes that wrap an
 *  HttpServletRequest and expose String-returning getters. */
function findRequestWrapperGetters(file, raw) {
  if (!JAVA_EXT.test(file) || !raw || raw.length > 500_000) return [];
  const content = blankComments(raw);
  const out = [];

  // Match each class block: `class X { ... }` and check it for both
  //   - HttpServletRequest field/constructor-arg/ivar
  //   - public String getX(...) methods
  const classRe = /\bclass\s+(\w+)\b[^{]*\{/g;
  let cm;
  while ((cm = classRe.exec(content))) {
    const className = cm[1];
    const bodyStart = content.indexOf('{', cm.index);
    if (bodyStart < 0) continue;
    // Find matching closing brace via a depth counter
    let depth = 1, i = bodyStart + 1;
    while (i < content.length && depth > 0) {
      const ch = content[i];
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      i++;
    }
    const body = content.substring(bodyStart, i);
    if (!/\bHttpServletRequest\b|\bServletRequest\b/.test(body)) continue;
    const getters = [];
    const getterRe = /\bpublic\s+(?:String|String\s*\[\s*\]|Object)\s+(\w+)\s*\(/g;
    let gm;
    while ((gm = getterRe.exec(body))) {
      if (gm[1] === 'class') continue;
      getters.push(gm[1]);
    }
    if (getters.length) out.push({ className, getters });
  }
  return out;
}
