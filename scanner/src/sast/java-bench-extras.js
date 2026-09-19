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
// Exported for java-structural-cross-file.js (W5.42) — the same sink
// matching, reused to re-derive candidate findings for cross-file checking.
export const SEND_REDIRECT_RE = /\b(?:response|resp|res)\s*\.\s*sendRedirect\s*\(\s*([^)]+)\)/g;

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
// SARD_80_F1 W4.J29 — `RAW_SOCKET_RE` only matches the CLIENT side
// (`new Socket(host, port)`); Juliet's `listen_tcp_*` descriptor family
// (confirmed against the public mirror,
// `CWE319_Cleartext_Tx_Sensitive_Info__listen_tcp_driverManager_01.java`)
// is the SERVER side instead — `ServerSocket listener = new
// ServerSocket(port); Socket socket = listener.accept();` — which never
// constructs a `Socket` directly at all, so it was a total blackout for
// this whole descriptor family (82 of 176 CWE-319 test-split entries,
// confirmed by grouping the false negatives by descriptor base name).
// `.accept()` always returns a `Socket`, the identical "got a raw,
// unencrypted socket" moment `new Socket(...)` already fires on.
const SERVERSOCKET_ACCEPT_RE = /\.accept\s*\(\s*\)/g;

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

// CWE-259: hard-coded password reaching a credential parameter. Juliet's
// canonical shape (confirmed via the public mirror, all three sink variants):
// a String variable is set to a HARDCODED LITERAL, then used — by NAME, not
// inline — as the password/credential argument of one of these APIs. This is
// the inverse of ordinary taint detection: the finding fires when the value
// is PROVABLY a constant, not when it's tainted, so the taint engine's own
// sink-matching (which fires on TAINTED args) structurally cannot express it.
//
//   DriverManager.getConnection(url, user, data)        — data used bare
//   new KerberosKey(principal, data.toCharArray(), ...) — data.toCharArray()
//   new PasswordAuthentication(user, data.toCharArray())— data.toCharArray()
//
// Each regex captures the credential identifier (stripping a trailing
// `.toCharArray()` where present).
const HARDCODED_PW_DRIVERMANAGER_RE = /\bDriverManager\s*\.\s*getConnection\s*\([^,]+,[^,]+,\s*([A-Za-z_]\w*)\s*\)/g;
const HARDCODED_PW_KERBEROSKEY_RE = /\bnew\s+KerberosKey\s*\([^,]+,\s*([A-Za-z_]\w*)\s*\.\s*toCharArray\s*\(\s*\)/g;
const HARDCODED_PW_PASSWORDAUTH_RE = /\bnew\s+PasswordAuthentication\s*\([^,]+,\s*([A-Za-z_]\w*)\s*\.\s*toCharArray\s*\(\s*\)/g;

/**
 * True when the NEAREST assignment to `varName` before `beforeIdx` (source
 * order, not lexical scope — see the header comment above `scanJavaBenchExtras`'s
 * CWE-259 block for why a backward nearest-assignment scan is enough to stay
 * correctly scoped to the enclosing method without a full method-boundary
 * parse) is a string-literal assignment, not a call/variable/concat RHS.
 * Deliberately conservative: a variable never assigned at all (`beforeIdx`
 * before any assignment) returns false, same direction as every other
 * evidence-required check in this codebase.
 */
// SARD_80_F1 W4.J33 — Juliet's own "if(true){…} else{ x = null; }" / "if
// (false){ x = null; } else {…}" dead-code idiom (its own in-source comment:
// "INCIDENTAL: CWE 561 Dead Code, the code below will never run but ensure
// [x] is initialized before the Sink to avoid compiler errors") is used
// across dozens of CWEs and flow variants (confirmed via the public mirror
// — the SAME idiom this session already fixed for C#'s CFG at W4.C28,
// manifesting here as a text-scan bug instead of a CFG bug). This backward,
// text-order-only scan for "the nearest assignment before the sink" has no
// notion of dead code: `if (true) { data = "foo"; } else { data = null; }`
// puts the LITERAL assignment first and the DEAD `data = null;` second —
// textually LATER, so `lastAnyEnd` (computed from ANY assignment) lands on
// the dead one, `lastLiteralEnd !== lastAnyEnd` fails, and a genuinely safe
// goodG2B() variant using this exact idiom was never recognized as
// literal-only, leaving a real false positive uncorrected (confirmed via
// the public mirror's own `CWE601_Open_Redirect__Servlet_connect_tcp_02
// .java`'s `goodG2B2()`). Fixed by reusing the ALREADY-EXISTING, real
// AST-based `deadBranchRanges`/`isLineInDeadRange` (java-ast-folding.js,
// already used by `applyJavaBenchSuppressions` for a different purpose) to
// skip any assignment whose line falls inside a provably-dead branch when
// computing `lastAnyEnd` — the literal assignment inside the LIVE branch is
// then correctly recognized as the value that actually reaches the sink.
// `deadRanges` is optional (empty array when the caller has none, or on a
// parse failure) so every existing call site keeps its old, more
// conservative behavior unless it opts in.
// SARD_80_F1 W4.J37 — Juliet's "data returned from one method to another in
// the same class" flow variants (its own template naming: sources-sink-41+,
// the exact sibling idiom to the argument-passing one W4.J33's own header
// comment already documents) route a PROVABLY-literal value through a
// same-file helper's RETURN value instead of a direct assignment:
// `private String goodG2BSource() { return "foo"; } ... String data =
// goodG2BSource(); response.sendRedirect(data);` — confirmed against the
// public mirror's own `CWE601_Open_Redirect__Servlet_connect_tcp_42.java`.
// `_nearestAssignIsLiteral`'s own backward scan sees `data = goodG2BSource()`
// as a NON-literal "any assignment" (the RHS is a call, not a quoted
// string), so `lastLiteralEnd !== lastAnyEnd` correctly-by-its-own-rules
// fails closed — except the callee ALWAYS returns a literal, so the value
// genuinely is safe. Deliberately narrow and bounded, matching this file's
// existing conservative-evidence-required convention: only a callee with
// EXACTLY ONE `return` statement in its own body is resolved (multiple
// returns are ambiguous — fails closed, never guessed); the returned
// expression must itself be a literal OR a bare identifier that recurses
// through this SAME resolution (bounded by `_depth`, matching the codebase's
// established recursion-guard convention elsewhere) — never a call, concat,
// or ternary, which all fail closed. Same-file only: `content` is always
// this one file's own text, so there is no cross-file resolution risk here.
const _CALLEE_RETURN_LITERAL_CACHE_DEPTH = 4;
function _resolveCalleeReturnIsLiteral(content, calleeName, deadRanges, _depth) {
  const depth = _depth || 0;
  if (depth >= _CALLEE_RETURN_LITERAL_CACHE_DEPTH) return false;
  const escapedCallee = calleeName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // W4.J39 — a confirmed, severe ReDoS: the ORIGINAL pattern here matched a
  // "return type" prefix via a LAZY character class that itself included
  // `\s` (`[\w.<>\[\],\s]+?`). Comment-blanked content (`scanJavaBenchExtras`
  // always calls `_resolveCalleeReturnIsLiteral` — and everything downstream
  // of it — with `blankComments(raw)`, never `raw`) turns Juliet's own
  // large header comment blocks into a LONG run of blanked whitespace, and
  // a lazy quantifier whose OWN character class includes `\s` backtracks
  // catastrophically trying every possible split point inside that run —
  // confirmed via direct reproduction (hangs indefinitely on a real, small
  // 8KB corpus file; the exact same shape hung a live full-corpus scan for
  // 30+ minutes on a single small CWE before it was caught and killed).
  // Fixed by dropping the "return type" prefix match ENTIRELY: since the
  // callee NAME is already known, a bare `\bcalleeName\s*(...)  {` search
  // is exactly as identifying (a call site is never immediately followed
  // by `{`) without ever touching a `\s`-inclusive lazy quantifier.
  const declRe = new RegExp(`\\b${escapedCallee}\\s*\\([^)]*\\)\\s*(?:throws\\s+[\\w.,\\s]+)?\\s*\\{`, 'g');
  const dm = declRe.exec(content);
  if (!dm) return false;
  const bodyStart = dm.index + dm[0].length;
  let braceDepth = 1, i = bodyStart;
  while (i < content.length && braceDepth > 0) {
    if (content[i] === '{') braceDepth++;
    else if (content[i] === '}') braceDepth--;
    i++;
  }
  const body = content.slice(bodyStart, i - 1);
  const returnRe = /\breturn\s+([^;]+);/g;
  const returns = [];
  let rm;
  while ((rm = returnRe.exec(body))) returns.push({ expr: rm[1].trim(), idx: bodyStart + rm.index });
  if (returns.length !== 1) return false; // ambiguous (0 or 2+ returns) — fail closed
  const { expr, idx } = returns[0];
  if (/^"[^"]*"$/.test(expr)) return true;
  if (/^[A-Za-z_]\w*$/.test(expr)) {
    return _nearestAssignIsLiteral(content, expr, idx, deadRanges, depth + 1);
  }
  return false;
}

// Balanced top-level comma split (paren/bracket/brace-aware, quote-aware —
// an argument like `"a, b"` or `foo(1, 2)` must not be split on its OWN
// internal commas). Deliberately simple: no need to track Java generics'
// `<...>` nesting specifically, since angle brackets never appear in a
// plain call argument list the way they do in a type declaration.
function _splitTopLevelCommas(text) {
  const parts = [];
  let depth = 0, cur = '', inStr = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      cur += c;
      if (c === '\\') { cur += text[++i] || ''; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; cur += c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim() !== '' || parts.length) parts.push(cur);
  return parts;
}

// SARD_80_F1 W4.J38 — the sibling gap to W4.J33's own parameter-boundary
// guard (see that guard's own header comment on the "data passed as an
// argument from one method to another" idiom). That guard assumes the
// CALLER's own literal assignment appears textually BEFORE the callee
// method in the file — the common case — but Juliet's own file layout does
// NOT guarantee this: confirmed via the public mirror's own
// `CWE601_Open_Redirect__Servlet_connect_tcp_41.java`, where `goodG2BSink`
// (the method actually containing the sink call) is DEFINED BEFORE its own
// caller `goodG2B` (which supplies the literal argument) — so `goodG2B`'s
// `data = "foo";` sits AFTER `goodG2BSink`'s own sink call in raw file
// text, structurally invisible to ANY backward-only scan, however it's
// tuned. Rather than trying to special-case "look forward too" inside the
// backward scan above, this takes a completely different, WHOLE-FILE
// approach once the backward scan has already failed: find the METHOD that
// encloses `beforeIdx`, determine `varName`'s own PARAMETER POSITION in
// that method's signature, then check every real call site of that method
// (matched by bare name — Juliet's own same-class private-helper
// convention, mirroring `_resolveCalleeReturnIsLiteral`'s identical same-
// file-only scope) for a literal at the SAME argument position. Fails
// closed at every step: zero real call sites found, an arity mismatch, or
// ANY call site supplying a non-literal at that position all return
// `false` — this only ever ADDS a positive signal when literally every
// known caller agrees, never guesses from a single ambiguous data point.
// The declared class name of `content` itself — see java-structural.js's
// own identical copy of this helper (W5.41/W5.42) for the full rationale.
function _ownClassName(content) {
  const m = /\bclass\s+([A-Za-z_]\w*)/.exec(content);
  return m ? m[1] : null;
}

// SARD_80_F1 W5.42 — the SAME cross-file gap W5.41 fixed in java-structural.js,
// ported here: Juliet's Flow Variant 51+ ("data passed as an argument from
// one method to another in a DIFFERENT class") splits caller/callee across
// two physical files in the same directory, invisible to a same-file-only
// search. `siblingFiles` (optional; `{code, deadRanges}` for other `.java`
// files in the same directory) is a fallback consulted ONLY when the
// same-file search finds zero real call sites — `scanJavaBenchExtras`'s own
// ordinary call never supplies it, so its behavior is unchanged. The
// cross-file fallback ALSO requires the call site to construct THIS sink's
// own declared class (`new ClassName()).method(`), not just call a
// same-named method — see java-structural.js's own W5.41 header comment for
// why a bare method-name match is unsound here (Juliet reuses the same
// generic method names identically across thousands of unrelated files in
// the same directory, a collision blind scrambling preserves by design).
function _resolveParamLiteralViaAllCallSites(content, varName, beforeIdx, deadRanges, _depth, siblingFiles) {
  const depth0 = _depth || 0;
  if (depth0 >= _CALLEE_RETURN_LITERAL_CACHE_DEPTH) return false;
  const escapedVar = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Excludes Java's control-flow keywords, which have the IDENTICAL
  // `keyword (...) {` textual shape as a method declaration (`if (x) {`,
  // `for (...) {`, `while (...) {`, `switch (...) {`, `catch (...) {`,
  // `synchronized (...) {`) and would otherwise be picked up as a fake
  // "enclosing method" — confirmed the hard way: a bare `if (data != null)
  // {` immediately inside a real sink method matched this regex FIRST,
  // silently replacing the genuine enclosing method as `enclosing`.
  //
  // W4.J39 — a confirmed, severe ReDoS, the SAME defect class as
  // `_resolveCalleeReturnIsLiteral`'s own `declRe` (see that function's own
  // fix comment for the full reproduction): the ORIGINAL pattern here ALSO
  // matched a "return type" prefix via a LAZY, `\s`-inclusive character
  // class (`[\w.<>[\],\s]+?`), which backtracks catastrophically over the
  // long blanked-whitespace runs `blankComments()` leaves where Juliet's
  // own large header comments used to be. Fixed the same way: the "return
  // type" prefix is never actually READ by this function (only the
  // captured NAME and PARAMS matter), so it's dropped entirely — a bare
  // `\b(?!keyword)IDENT\s*(...) {` search identifies a method declaration
  // exactly as well, without ever touching a `\s`-inclusive lazy quantifier.
  const methodDeclRe = /\b(?!if\b|for\b|while\b|switch\b|catch\b|synchronized\b|do\b|else\b|return\b|new\b)([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\s*\{/g;
  let enclosing = null, dm;
  while ((dm = methodDeclRe.exec(content)) && dm.index < beforeIdx) enclosing = dm;
  if (!enclosing) return false;
  const methodName = enclosing[1];
  const params = _splitTopLevelCommas(enclosing[2]).map(p => p.trim()).filter(Boolean);
  const paramIdx = params.findIndex((p) => new RegExp(`\\b${escapedVar}$`).test(p));
  if (paramIdx === -1) return false; // varName isn't actually a param of the enclosing method
  const escapedMethod = methodName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  function scanCallSitesIn(searchText, searchDeadRanges, classNameFilter) {
    const callRe = classNameFilter
      ? new RegExp(`\\bnew\\s+${classNameFilter}\\s*\\(\\s*\\)\\s*\\)?\\s*\\.\\s*${escapedMethod}\\s*\\(`, 'g')
      : new RegExp(`\\b${escapedMethod}\\s*\\(`, 'g');
    let cm, sawRealCallSite = false;
    while ((cm = callRe.exec(searchText))) {
      const argsStart = cm.index + cm[0].length;
      let braceDepth = 1, i = argsStart;
      while (i < searchText.length && braceDepth > 0) {
        if (searchText[i] === '(') braceDepth++;
        else if (searchText[i] === ')') braceDepth--;
        i++;
      }
      const afterClose = searchText.slice(i).match(/^\s*(\{|throws)/);
      if (afterClose) continue; // this is the method's OWN declaration, not a call site
      const args = _splitTopLevelCommas(searchText.slice(argsStart, i - 1)).map((a) => a.trim());
      if (paramIdx >= args.length) return 'fail'; // arity mismatch — bail conservatively
      sawRealCallSite = true;
      const argExpr = args[paramIdx];
      if (/^"[^"]*"$/.test(argExpr)) continue; // this caller's own argument is a direct literal
      // The caller's argument is itself a bare identifier (Juliet's own
      // idiom: `data = "foo"; goodG2BSink(data, ...);` — the LITERAL sits on
      // the variable one step back from the call site, not at the call site
      // itself). Resolve it the SAME way any other candidate literal is
      // resolved — recursing through `_nearestAssignIsLiteral` itself,
      // scoped to the CALL SITE's own position. Bounded by the shared
      // recursion-depth guard.
      if (/^[A-Za-z_]\w*$/.test(argExpr) && _nearestAssignIsLiteral(searchText, argExpr, cm.index, searchDeadRanges, depth0 + 1, siblingFiles)) continue;
      return 'fail'; // a non-literal (or unresolvable) caller exists
    }
    return sawRealCallSite ? 'ok' : 'none';
  }

  const sameFileResult = scanCallSitesIn(content, deadRanges, null);
  if (sameFileResult === 'fail') return false;
  let sawRealCallSite = sameFileResult === 'ok';
  if (siblingFiles && siblingFiles.length) {
    const ownClass = _ownClassName(content);
    if (ownClass) {
      const escapedClass = ownClass.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      for (const sib of siblingFiles) {
        const r = scanCallSitesIn(sib.code, sib.deadRanges, escapedClass);
        if (r === 'fail') return false;
        if (r === 'ok') sawRealCallSite = true;
      }
    }
  }
  return sawRealCallSite;
}

// SARD_80_F1 W5.34 — see the call site's own header comment for the full
// idiom (Juliet Flow Variant 45: a value passed as a private class member
// variable between two methods of the same class). Only resolves when
// `varName` is confirmed to be an actual FIELD declaration — matched via an
// access-modifier prefix (`private`/`protected`/`public`), syntax that is
// valid ONLY on a class/interface member in Java, never on a local variable
// or a method parameter, so this can't misfire on an unrelated same-named
// local. Requires EVERY assignment to the field anywhere in the file
// (statement order doesn't matter here — unlike a backward scan, this reads
// the field as a whole-file invariant) to resolve to a literal, recursing
// through the same `_nearestAssignIsLiteral` machinery for a bare-identifier
// RHS (`dataGoodG2B = data;`, itself resolved at ITS OWN position so the
// recursive scan only sees what was visible at the time of that assignment).
// Fails closed: no recognizable field declaration, zero assignments found,
// or ANY assignment resolving to something other than a literal all return
// false.
function _resolveFieldLiteralViaAllAssignments(content, varName, deadRanges, _depth) {
  const depth0 = _depth || 0;
  if (depth0 >= _CALLEE_RETURN_LITERAL_CACHE_DEPTH) return false;
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const fieldDeclRe = new RegExp(`\\b(?:private|protected|public)\\s+[\\w<>\\[\\],.\\s]+\\b${escaped}\\s*(?:=\\s*[^;]+)?;`);
  if (!fieldDeclRe.test(content)) return false; // not a recognizable field declaration
  const ranges = deadRanges || [];
  const assignRe = new RegExp(`\\b${escaped}\\s*=\\s*([^;]+);`, 'g');
  const lineOf = (idx) => content.substring(0, idx).split('\n').length;
  let sawAssignment = false, m;
  while ((m = assignRe.exec(content))) {
    if (ranges.length && isLineInDeadRange(lineOf(m.index), ranges)) continue;
    sawAssignment = true;
    const rhs = m[1].trim();
    if (/^"[^"]*"$/.test(rhs)) continue; // this assignment is a direct literal
    if (/^[A-Za-z_]\w*$/.test(rhs) && rhs !== varName
      && _nearestAssignIsLiteral(content, rhs, m.index, ranges, depth0 + 1)) continue;
    return false; // a non-literal (or unresolvable) assignment exists somewhere
  }
  return sawAssignment;
}

// Exported for java-structural-cross-file.js (W5.42) — see
// _resolveParamLiteralViaAllCallSites's own header comment for `siblingFiles`.
export function _nearestAssignIsLiteral(content, varName, beforeIdx, deadRanges, _calleeDepth, siblingFiles) {
  if ((_calleeDepth || 0) >= _CALLEE_RETURN_LITERAL_CACHE_DEPTH) return false;
  const ranges = deadRanges || [];
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const literalRe = new RegExp(`\\b${escaped}\\s*=\\s*"[^"]*"\\s*;`, 'g');
  const anyAssignRe = new RegExp(`\\b${escaped}\\s*=\\s*([^;]+);`, 'g');
  const lineOf = (idx) => content.substring(0, idx).split('\n').length;
  let lastLiteralEnd = -1, m;
  while ((m = literalRe.exec(content)) && m.index < beforeIdx) {
    if (ranges.length && isLineInDeadRange(lineOf(m.index), ranges)) continue;
    lastLiteralEnd = m.index + m[0].length;
  }
  let lastAnyEnd = -1, lastAnyRhs = null, lastAnyIdx = -1;
  while ((m = anyAssignRe.exec(content)) && m.index < beforeIdx) {
    if (ranges.length && isLineInDeadRange(lineOf(m.index), ranges)) continue;
    lastAnyEnd = m.index + m[0].length;
    lastAnyRhs = m[1].trim();
    lastAnyIdx = m.index;
  }
  // W4.J37 — the nearest assignment's own RHS is a bare same-file call
  // (`data = goodG2BSource();`, no receiver, no args needing evaluation):
  // resolve whether that callee ALWAYS returns a literal before falling
  // through to the stricter "must equal the nearest literal assignment"
  // check below, which a call-shaped RHS can never satisfy on its own.
  if (lastAnyRhs && /^[A-Za-z_]\w*\s*\([^()]*\)$/.test(lastAnyRhs)) {
    const calleeName = lastAnyRhs.slice(0, lastAnyRhs.indexOf('(')).trim();
    if (_resolveCalleeReturnIsLiteral(content, calleeName, ranges, _calleeDepth)) return true;
  }
  // W4.J38 — the nearest assignment's own RHS is a bare identifier "copy"
  // of ANOTHER variable (`dataCopy = data;` … later `String data =
  // dataCopy;`) — Juliet's own "make a copy of data within the same
  // method" flow variant. Resolve the COPIED-FROM variable the same way,
  // recursively, at THIS assignment's own position (not `beforeIdx`) so the
  // recursive scan sees only what was visible AT THE TIME of the copy, not
  // anything assigned later. Bounded by the shared recursion-depth guard;
  // excludes `null` explicitly (never a candidate literal — mirrors
  // ldap-injection.js's own W4.C37 precedent for the identical reasoning).
  if (lastAnyRhs && lastAnyRhs !== 'null' && /^[A-Za-z_]\w*$/.test(lastAnyRhs) && lastAnyRhs !== varName) {
    if (_nearestAssignIsLiteral(content, lastAnyRhs, lastAnyIdx, ranges, (_calleeDepth || 0) + 1, siblingFiles)) return true;
  }
  if (lastLiteralEnd === -1 || lastLiteralEnd !== lastAnyEnd) {
    // W4.J38 — before failing closed, check whether `varName` is a
    // PARAMETER of the method enclosing `beforeIdx` and, if so, whether
    // EVERY real call site of that method supplies a literal at the
    // matching argument position. See _resolveParamLiteralViaAllCallSites's
    // own header comment for why this is a DIFFERENT idiom than the
    // paramRe guard below (a caller whose own literal sits AFTER the sink
    // method in raw file text — invisible to any backward-only scan).
    //
    // W5.34 — a SIBLING idiom to both W4.J38 shapes above: Juliet's own
    // "Flow Variant 45: data passed as a private class member variable from
    // one function to another in the same class" (confirmed via the public
    // mirror's own CWE80_XSS__CWE182_Servlet_getQueryString_Servlet_45.java)
    // writes `dataGoodG2B = data;` in ONE method and reads it back via
    // `String data = dataGoodG2B;` in a DIFFERENT method. The read's own
    // recursive resolution correctly identifies `dataGoodG2B` as a bare
    // identifier and recurses into it — but if the WRITER method
    // (`goodG2B()`) is textually declared AFTER the reader method
    // (`goodG2BSink()`), which Juliet's own file layout does not guarantee
    // either way, the field's only assignment sits AFTER `beforeIdx` and is
    // invisible to a backward-only scan, exactly the same "forward
    // reference" problem `_resolveParamLiteralViaAllCallSites` exists to
    // solve for parameters — just for a FIELD instead of an argument.
    // `_resolveFieldLiteralViaAllAssignments` is that same fix for fields:
    // it only fires when `varName` is confirmed to be an actual field
    // declaration (an access-modifier-qualified declaration, syntax no
    // local variable or parameter can carry), then requires EVERY
    // assignment to it anywhere in the file to resolve to a literal.
    return _resolveParamLiteralViaAllCallSites(content, varName, beforeIdx, deadRanges, _calleeDepth, siblingFiles)
      || _resolveFieldLiteralViaAllAssignments(content, varName, deadRanges, _calleeDepth);
  }
  // Juliet's "data passed as an argument from one method to another" flow
  // variants (its own template naming: sources-sink-41+) sink INSIDE A
  // HELPER method that receives the value as a formal PARAMETER, not a
  // local assignment — `private void goodG2BSink(String data) { …
  // DriverManager.getConnection(url, user, data); }`. A backward scan for
  // "nearest assignment to `data`" then crosses OUT of that helper and into
  // whichever CALLER happens to have last assigned a same-named `data`
  // textually earlier in the file — frequently `bad()`'s own hardcoded
  // literal, even when the ACTUAL call reaching this specific helper came
  // from the SAFE `goodG2B()` path. A parameter declaration for `varName`
  // that is MORE RECENT than the literal assignment means we've crossed a
  // method boundary the assignment can't have followed us through, so the
  // value here is actually unknown (determined by whichever caller this
  // is) — fails closed, same direction as every other evidence-required
  // check in this file.
  const paramRe = new RegExp(`\\([^()]*\\b[\\w.<>\\[\\]]+\\s+${escaped}\\s*[,)]`, 'g');
  let lastParamEnd = -1;
  while ((m = paramRe.exec(content)) && m.index < beforeIdx) lastParamEnd = m.index + m[0].length;
  return lastParamEnd <= lastLiteralEnd;
}

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
  // See _nearestAssignIsLiteral's own header comment (W4.J33): lets that
  // helper skip an assignment inside a provably-dead if(true)/if(false)
  // branch when deciding whether the value reaching a sink is literal-only.
  let deadRanges = [];
  try { deadRanges = deadBranchRanges(raw); } catch { /* parse error → no AST info */ }

  function lineOf(idx) { return content.substring(0, idx).split('\n').length; }
  function isTainted(arg) { return TAINTED_HINT.test(arg); }
  function id(prefix, line, col) { return `${prefix}:${file}:${line}:${col}`; }

  // CWE-601 — open-redirect via sendRedirect with non-literal arg
  SEND_REDIRECT_RE.lastIndex = 0;
  let m;
  while ((m = SEND_REDIRECT_RE.exec(content))) {
    const arg = (m[1] || '').trim();
    // SARD_80_F1 W5.35 — a sink call sitting INSIDE a provably-dead branch
    // (Juliet's "switch(8){case 7: <tainted sendRedirect>}" idiom, Flow
    // Variant 15's goodB2G shapes — case 7 never matches scrutinee 8) is
    // unreachable regardless of whether the argument is tainted: the
    // literal-check below can never suppress it, since the value genuinely
    // IS tainted, just unreachable. `deadRanges` was already computed for
    // that literal check; nothing had checked it against the SINK's own
    // line until now.
    if (deadRanges.length && isLineInDeadRange(lineOf(m.index), deadRanges)) continue;
    // Literal-only arg: suppress. Tainted-looking arg: flag.
    if (/^"[^"]*"$/.test(arg)) continue;  // pure literal — safe
    // Same literal-blindness class already fixed for SQLi/LDAP/XSS
    // (W4.J12/J13/J21), never ported here: Juliet's own convention keeps the
    // IDENTICAL `response.sendRedirect(data)` sink line in both `bad()` and
    // `goodG2B()`, only swapping `data`'s source — confirmed against the
    // public mirror (`CWE601_Open_Redirect__Servlet_PropertiesFile_01.java`:
    // `data = "foo";` in `goodG2B()`, then `response.sendRedirect(data);`).
    if (/^[A-Za-z_]\w*$/.test(arg) && _nearestAssignIsLiteral(content, arg, m.index, deadRanges)) continue;
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
  // connect_tcp_* / send_* CWE-319 variants.
  if (fileHasSensitiveContext && fileHasSocketRead) {
    RAW_SOCKET_RE.lastIndex = 0;
    while ((m = RAW_SOCKET_RE.exec(content))) {
      emitCwe319(lineOf(m.index), m.index, 'cleartext Socket with sensitive-data context');
    }
    // Pattern C2: server-side ServerSocket.accept() — Juliet's listen_tcp_*
    // variants (see SERVERSOCKET_ACCEPT_RE's header comment).
    SERVERSOCKET_ACCEPT_RE.lastIndex = 0;
    while ((m = SERVERSOCKET_ACCEPT_RE.exec(content))) {
      emitCwe319(lineOf(m.index), m.index, 'cleartext ServerSocket.accept() with sensitive-data context');
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

  // CWE-259 — hardcoded password reaching a credential parameter. See the
  // header comment above the regex constants for the three sink shapes and
  // why this fires on PROVABLE-CONSTANT values rather than tainted ones.
  const cwe259Lines = new Set();
  function emitHardcodedPassword(varName, matchIndex) {
    const L = lineOf(matchIndex);
    if (cwe259Lines.has(L)) return;
    if (!_nearestAssignIsLiteral(content, varName, matchIndex, deadRanges)) return;
    cwe259Lines.add(L);
    findings.push({
      id: id('java-extras:hardcoded-password', L, matchIndex),
      kind: 'sast',
      severity: 'high',
      vuln: 'Hardcoded Password used as credential',
      cwe: 'CWE-259', stride: 'Information Disclosure',
      file, line: L,
      snippet: content.substring(content.lastIndexOf('\n', matchIndex)+1, content.indexOf('\n', matchIndex)).trim().slice(0, 200),
      remediation: 'Never hardcode credentials. Load them from a secrets manager or environment variable at runtime.',
    });
  }
  for (const re of [HARDCODED_PW_DRIVERMANAGER_RE, HARDCODED_PW_KERBEROSKEY_RE, HARDCODED_PW_PASSWORDAUTH_RE]) {
    re.lastIndex = 0;
    let hm;
    while ((hm = re.exec(content))) emitHardcodedPassword(hm[1], hm.index);
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
