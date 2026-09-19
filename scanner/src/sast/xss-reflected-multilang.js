// Cross-language reflected-XSS structural detector — PRD Tier 1 (recall).
//
// JS/Python reflected XSS is handled by the flow engine + framework structural
// detectors; the second-tier languages had no XSS coverage. This module adds a
// taint-independent structural rule per language: user input written into an
// HTML response via concatenation / interpolation, without an output encoder.
//
// Precision: each language carries its own escaper exclusion (htmlspecialchars,
// HtmlEncode, html_escape, template.HTMLEscapeString, …). When an escaper is
// applied on the sink line the finding is suppressed — the parameterized/encoded
// form must NOT match. HTML context is required (an HTML tag literal, an HTML
// content-type, or a raw-superglobal echo) so plain-text responses don't fire.

import { blankComments } from './_comment-strip.js';
import { deadBranchRanges, isLineInDeadRange } from './java-ast-folding.js';

const lineOf = (raw, idx) => raw.substring(0, idx).split('\n').length;

const REMEDIATION =
  'HTML-encode user input before writing it into a response: htmlspecialchars (PHP), ' +
  'template/html.EscapeString (Go), ERB::Util.html_escape / avoid .html_safe (Ruby), ' +
  'HttpUtility.HtmlEncode (C#), or an auto-escaping template engine. Never concatenate ' +
  'request data straight into an HTML response.';

// Per-language: { ext, sinks:[RegExp], escaper:RegExp }. A line matches when a
// sink RegExp matches and the escaper RegExp does NOT.
const LANGS = {
  go: {
    ext: /\.go$/i,
    // fmt.Fprint*/io.WriteString to the ResponseWriter, or w.Write([]byte(...)),
    // building an HTML string ("<…") by concatenation.
    sinks: [
      /\b(?:fmt\.Fprintf?|fmt\.Fprintln|io\.WriteString)\s*\(\s*w\b[^)\n]*"<[^"\n]*"\s*\+/,
      /\bw\.Write\s*\(\s*\[\]byte\s*\(\s*"<[^"\n]*"\s*\+/,
    ],
    escaper: /\b(?:template\.HTMLEscapeString|html\.EscapeString|template\.HTMLEscaper)\s*\(/,
  },
  php: {
    ext: /\.(?:php|phtml)$/i,
    // echo/print of a request superglobal (directly or concatenated).
    sinks: [
      /\b(?:echo|print)\b[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
      /\bprintf\s*\([^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    ],
    escaper: /\b(?:htmlspecialchars|htmlentities|strip_tags|filter_var|urlencode|rawurlencode|json_encode|intval|floatval|htmlspecialchars_decode)\s*\(/,
  },
  ruby: {
    ext: /\.rb$/i,
    // render inline:/html: with #{} interpolation, raw(params…), params….html_safe
    sinks: [
      /\brender\s+(?:inline|html):\s*["'][^"'\n]*#\{/,
      /\braw\s*\(\s*(?:params|request|@\w+\.params)\b/,
      /\b(?:params|request)\b[^\n]*\.\s*html_safe\b/,
    ],
    escaper: /\b(?:ERB::Util\.html_escape|CGI\.escapeHTML|h\s*\(|sanitize\s*\()/,
  },
  csharp: {
    ext: /\.cs$/i,
    // Response.Write of Request data, or an HTML string concatenation.
    sinks: [
      /\bResponse\.Write\s*\([^)\n]*\bRequest\b/,
      /\bResponse\.Write\s*\(\s*"<[^"\n]*"\s*\+/,
    ],
    escaper: /\b(?:HttpUtility\.HtmlEncode|HtmlEncoder\.|Server\.HtmlEncode|WebUtility\.HtmlEncode|AntiXss\.)/,
  },
  kotlin: {
    ext: /\.kt$/i,
    // Ktor respondText building HTML by interpolation/concat.
    sinks: [
      /\brespondText\s*\(\s*"<[^"\n]*\$/,
      /\brespondText\s*\(\s*"<[^"\n]*"\s*\+/,
      /\brespondText\s*\(\s*"[^"\n]*\$[^"\n]*"\s*,\s*ContentType\.Text\.Html/,
    ],
    escaper: /\b(?:htmlEscape|escapeHtml|HtmlUtils\.htmlEscape|encodeHTML)\s*\(/,
  },
  java: {
    ext: /\.java$/i,
    // Servlet: response.getWriter().write/print/println(...) or a PrintWriter
    // `out`, building an HTML string ("<…") by concatenation. The concat (`"<…"
    // +`) is the reflected-XSS shape — a static literal has no `+`.
    // Each pattern additionally captures a trailing `+ identifier)`/`+
    // identifier;` tail — the SINGLE, LAST concatenated term, when the
    // concatenation ends right there — mirroring java-structural.js's own
    // SQL/cmd-injection capture shape, so `_nearestAssignIsLiteral` (below)
    // can tell a real tainted variable from a hardcoded one. The capture
    // also tolerates ONE simple method call chained directly onto that
    // identifier (`data.replaceAll(...)`) — Juliet's own real corpus shape
    // (confirmed via the public Java mirror,
    // CWE80_XSS__CWE182_Servlet_File_01.java) is exactly this: `data =
    // readerBuffered.readLine()` (tainted) vs `data = "foo"` (literal) in
    // bad()/goodG2B() respectively, both then passed through the IDENTICAL
    // `data.replaceAll("(<script>)", "")` before the sink — a call on a
    // provably-literal receiver is still provably literal. The inner
    // `(?:"[^"]*"|[^()])*` is quote-aware specifically so a literal paren
    // INSIDE a string argument (like `"(<script>)"` above) doesn't
    // terminate the match early — this taint-independent detector, having
    // no taint model of its own, previously fired on both bad() and
    // goodG2B() identically.
    sinks: [
      /\.\s*(?:getWriter\s*\(\s*\)\s*\.\s*)?(?:write|print|println|append|format|printf)\s*\(\s*"<[^"\n]*"\s*\+(?:\s*([A-Za-z_]\w*)(?:\s*\.\s*[A-Za-z_]\w*\s*\((?:"[^"]*"|[^()])*\))?\s*(?=(?:\s*\+\s*"[^"\n]*"\s*)?[);]))?/,
      /\b(?:out|writer|pw|w)\s*\.\s*(?:write|print|println|append)\s*\(\s*"<[^"\n]*"\s*\+(?:\s*([A-Za-z_]\w*)(?:\s*\.\s*[A-Za-z_]\w*\s*\((?:"[^"]*"|[^()])*\))?\s*(?=(?:\s*\+\s*"[^"\n]*"\s*)?[);]))?/,
    ],
    escaper: /\b(?:encodeForHTML|forHtml|forHtmlContent|htmlEscape|escapeHtml4?|StringEscapeUtils|HtmlUtils\.htmlEscape|Encode\.forHtml|ESAPI|OWASP)\b/,
  },
};

// SARD_80_F1 W4.J28 — Juliet's own "Control flow: if(true) and if(false)"
// flow variant (its own file header names this explicitly) writes
// `if (true) { data = "foo"; } else { /* CWE 561 Dead Code */ data = null; }`
// (or the mirror image for `if (false)`) — the ELSE branch is PROVABLY
// unreachable (a constant-condition, not a genuine runtime-dependent
// branch), but a plain backward-scan just finds
// "the textually nearest assignment", which is the DEAD branch's `data =
// null;` here (textually last), so it never recognizes `data` as the
// literal it always actually is.
//
// SARD_80_F1 W5.32 — originally patched with this file's OWN narrow regex
// (matching only `if(true)`/`if(false)`, then widened to also match
// `if(5==5)`/`if(5!=5)`) — found investigating a NEW fp this exact gap
// exposed once an unrelated fix (a Java parser bug, W5.32's own
// StringTokenizer fix) let the deep taint engine correctly detect `bad()`'s
// real vulnerability for the first time: the resulting dedup/clustering
// reshuffle stopped accidentally folding this ALREADY-PRESENT, independent
// XSS-ML false positive into the genuine finding, exposing a real,
// pre-existing gap rather than introducing one. That narrow regex approach
// only ever covered 2 of the many dead-code idioms this real corpus uses
// (checked directly: 04-14/21/22a/31/41/42/45/51b/52c/54e/61a/66b-74b all
// remained as fps) — rather than keep extending a second, independent
// regex-based dead-branch detector, this now consumes `java-ast-folding.js`'s
// existing `deadBranchRanges`/`isLineInDeadRange` — the SAME shared,
// AST-based (not regex-based) mechanism `java-bench-extras.js` and
// `java-structural.js` already use, which ALREADY resolves literal
// true/false, private-static-final fields, effectively-final fields,
// literal-vs-literal int comparisons, and zero-arg/single-return same-class
// helper calls (W4.J33-36/W5.27's own incrementally-built capability) — one
// shared mechanism, extended once, every consumer benefits, matching this
// whole session's established pattern. The backward-scan now simply SKIPS any assignment whose line falls in a dead
// range, rather than relying on a pre-blanked copy of the source text.
// Cross-file variants (the lettered-suffix families) remain correctly
// out of scope — `deadBranchRanges` is single-file, same boundary as
// every other interprocedural mechanism in this codebase.

// SARD_80_F1 W5.33 — this file's OWN backward-only "nearest assignment"
// check (formerly `_trailingIdentIsLiteral`) had none of the interprocedural
// resolution `java-bench-extras.js` already built for the identical Juliet
// idioms (W4.J37-39): a value returned from a same-file helper
// (`data = goodG2BSource();`), a same-method copy chain (`dataCopy = data;`
// … `data = dataCopy;`), or an argument passed to a helper that receives it
// as a PARAMETER rather than a local assignment. Confirmed via a real-corpus
// sweep of this file's own remaining CWE-80 fp list (Flow Variants 31/41/42/
// 45 — no lettered suffix, genuinely same-file) that these are exactly the
// gap. Rather than re-derive a THIRD independent copy of this logic (a
// second copy, in java-structural.js, was already ported once at W5.23),
// this ports the same three functions verbatim in their already-ReDoS-fixed
// form (W4.J39 — the "return type prefix" lazy `\s`-inclusive character
// class that caused a confirmed hang was dropped entirely in the source
// this was copied from; reintroducing it here would reintroduce the exact
// same hang against Juliet's own large blanked-comment header blocks).
// `_nearestAssignIsLiteral` is the direct, same-signature replacement for
// this file's own former `_trailingIdentIsLiteral` at the one call site
// below. Same-file only, matching every other interprocedural mechanism in
// this codebase — the lettered-suffix (cross-file) variants remain
// correctly out of scope.
const _CALLEE_RETURN_LITERAL_CACHE_DEPTH = 4;
function _resolveCalleeReturnIsLiteral(content, calleeName, deadRanges, _depth) {
  const depth = _depth || 0;
  if (depth >= _CALLEE_RETURN_LITERAL_CACHE_DEPTH) return false;
  const escapedCallee = calleeName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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

// Balanced top-level comma split (paren/bracket/brace-aware, quote-aware).
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

function _resolveParamLiteralViaAllCallSites(content, varName, beforeIdx, deadRanges, _depth) {
  const depth0 = _depth || 0;
  if (depth0 >= _CALLEE_RETURN_LITERAL_CACHE_DEPTH) return false;
  const escapedVar = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const methodDeclRe = /\b(?!if\b|for\b|while\b|switch\b|catch\b|synchronized\b|do\b|else\b|return\b|new\b)([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\s*\{/g;
  let enclosing = null, dm;
  while ((dm = methodDeclRe.exec(content)) && dm.index < beforeIdx) enclosing = dm;
  if (!enclosing) return false;
  const methodName = enclosing[1];
  const params = _splitTopLevelCommas(enclosing[2]).map(p => p.trim()).filter(Boolean);
  const paramIdx = params.findIndex((p) => new RegExp(`\\b${escapedVar}$`).test(p));
  if (paramIdx === -1) return false; // varName isn't actually a param of the enclosing method
  const escapedMethod = methodName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const callRe = new RegExp(`\\b${escapedMethod}\\s*\\(`, 'g');
  let cm, sawRealCallSite = false;
  while ((cm = callRe.exec(content))) {
    const argsStart = cm.index + cm[0].length;
    let braceDepth = 1, i = argsStart;
    while (i < content.length && braceDepth > 0) {
      if (content[i] === '(') braceDepth++;
      else if (content[i] === ')') braceDepth--;
      i++;
    }
    const afterClose = content.slice(i).match(/^\s*(\{|throws)/);
    if (afterClose) continue; // this is the method's OWN declaration, not a call site
    const args = _splitTopLevelCommas(content.slice(argsStart, i - 1)).map((a) => a.trim());
    if (paramIdx >= args.length) return false; // arity mismatch — bail conservatively
    sawRealCallSite = true;
    const argExpr = args[paramIdx];
    if (/^"[^"]*"$/.test(argExpr)) continue; // this caller's own argument is a direct literal
    if (/^[A-Za-z_]\w*$/.test(argExpr) && _nearestAssignIsLiteral(content, argExpr, cm.index, deadRanges, depth0 + 1)) continue;
    return false; // a non-literal (or unresolvable) caller exists
  }
  return sawRealCallSite;
}

// SARD_80_F1 W5.34 — Juliet Flow Variant 45: a value passed as a private
// class member variable between two methods of the same class. See
// java-bench-extras.js's own header comment on the identical, canonical
// copy of this function for the full idiom and precision reasoning. Only
// resolves when `varName` is confirmed to be an actual field declaration
// (access-modifier-qualified — never valid on a local variable or
// parameter).
function _resolveFieldLiteralViaAllAssignments(content, varName, deadRanges, _depth) {
  const depth0 = _depth || 0;
  if (depth0 >= _CALLEE_RETURN_LITERAL_CACHE_DEPTH) return false;
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const fieldDeclRe = new RegExp(`\\b(?:private|protected|public)\\s+[\\w<>\\[\\],.\\s]+\\b${escaped}\\s*(?:=\\s*[^;]+)?;`);
  if (!fieldDeclRe.test(content)) return false;
  const ranges = deadRanges || [];
  const assignRe = new RegExp(`\\b${escaped}\\s*=\\s*([^;]+);`, 'g');
  const lineOf_ = (idx) => content.substring(0, idx).split('\n').length;
  let sawAssignment = false, m;
  while ((m = assignRe.exec(content))) {
    if (ranges.length && isLineInDeadRange(lineOf_(m.index), ranges)) continue;
    sawAssignment = true;
    const rhs = m[1].trim();
    if (/^"[^"]*"$/.test(rhs)) continue;
    if (/^[A-Za-z_]\w*$/.test(rhs) && rhs !== varName
      && _nearestAssignIsLiteral(content, rhs, m.index, ranges, depth0 + 1)) continue;
    return false;
  }
  return sawAssignment;
}

function _nearestAssignIsLiteral(content, varName, beforeIdx, deadRanges, _calleeDepth) {
  if (!varName) return false;
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
  if (lastAnyRhs && /^[A-Za-z_]\w*\s*\([^()]*\)$/.test(lastAnyRhs)) {
    const calleeName = lastAnyRhs.slice(0, lastAnyRhs.indexOf('(')).trim();
    if (_resolveCalleeReturnIsLiteral(content, calleeName, ranges, _calleeDepth)) return true;
  }
  if (lastAnyRhs && lastAnyRhs !== 'null' && /^[A-Za-z_]\w*$/.test(lastAnyRhs) && lastAnyRhs !== varName) {
    if (_nearestAssignIsLiteral(content, lastAnyRhs, lastAnyIdx, ranges, (_calleeDepth || 0) + 1)) return true;
  }
  if (lastLiteralEnd === -1 || lastLiteralEnd !== lastAnyEnd) {
    return _resolveParamLiteralViaAllCallSites(content, varName, beforeIdx, deadRanges, _calleeDepth)
      || _resolveFieldLiteralViaAllAssignments(content, varName, deadRanges, _calleeDepth);
  }
  const paramRe = new RegExp(`\\([^()]*\\b[\\w.<>\\[\\]]+\\s+${escaped}\\s*[,)]`, 'g');
  let lastParamEnd = -1;
  while ((m = paramRe.exec(content)) && m.index < beforeIdx) lastParamEnd = m.index + m[0].length;
  return lastParamEnd <= lastLiteralEnd;
}

export function scanXssReflectedMultilang(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  let lang = null;
  for (const v of Object.values(LANGS)) { if (v.ext.test(fp)) { lang = v; break; } }
  if (!lang) return [];

  const code = blankComments(raw, /\.rb$/i.test(fp) ? 'py' : (/\.(?:php|phtml)$/i.test(fp) ? 'php' : undefined));
  const lines = code.split('\n');
  let deadRanges = [];
  if (lang === LANGS.java) { try { deadRanges = deadBranchRanges(code); } catch { deadRanges = []; } }
  const findings = [];
  const seen = new Set();

  let lineStartOffset = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const thisLineStart = lineStartOffset;
    lineStartOffset += line.length + 1; // +1 for the '\n' _splitStatements-style join consumed
    if (lang.escaper.test(line)) continue;
    let sinkMatch = null;
    for (const re of lang.sinks) {
      const m = line.match(re);
      if (m) { sinkMatch = m; break; }
    }
    if (!sinkMatch) continue;
    // SARD_80_F1 W5.35 — a sink call sitting INSIDE a provably-dead branch
    // (Juliet's "switch(8){case 7: <tainted sink>}" idiom) is unreachable
    // regardless of whether the value reaching it is tainted — the
    // literal-check below can never suppress this shape, since the value
    // genuinely IS tainted, just unreachable.
    if (lang === LANGS.java && deadRanges.length && isLineInDeadRange(i + 1, deadRanges)) continue;
    // SARD_80_F1 W3.x — a captured trailing identifier (Java's sink patterns
    // only) that's provably a hardcoded literal at this point is not a real
    // XSS flow; see `_nearestAssignIsLiteral`'s header comment.
    if (lang === LANGS.java && sinkMatch[1] && _nearestAssignIsLiteral(code, sinkMatch[1], thisLineStart + sinkMatch.index, deadRanges)) continue;
    const ln = i + 1;
    const id = `xss-reflected:${fp}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id, file: fp, line: ln,
      vuln: 'Reflected XSS — user input written into an HTML response without output encoding',
      severity: 'high', cwe: 'CWE-79', family: 'xss', parser: 'XSS-ML', confidence: 0.62,
      snippet: (raw.split('\n')[ln - 1] || '').trim().slice(0, 200),
      remediation: REMEDIATION,
    });
  }
  return findings;
}
