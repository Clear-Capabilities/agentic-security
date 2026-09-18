// Java structural (taint-independent) injection detectors — PRD Tier 1.
//
// The flow-based Java modules miss standalone DAO/handler methods whose
// tainted-by-convention parameter has no in-file source. Java has no string
// templates, so the injection shape is string CONCATENATION (`"…" +`) into a
// dangerous sink — which is itself the vulnerability regardless of the
// variable's name. Parameterized statements / canonicalized paths / host-
// guarded URLs do not match, keeping this high-precision.

import { blankComments } from './_comment-strip.js';
import { deadBranchRanges, isLineInDeadRange } from './java-ast-folding.js';

// Concat-into-sink families with no guard needed (parameterized form has no
// string-concat argument, so it auto-clears). Each pattern additionally
// captures a trailing `+ identifier)` / `+ identifier;` tail — the SINGLE,
// LAST concatenated term, when the concatenation ends right there — so the
// caller can check whether that one identifier is PROVABLY a hardcoded
// literal (see `_trailingIdentIsLiteral` below). Juliet's own convention
// (confirmed against the public Java mirror's CWE-89 execute()/executeQuery()
// variants) keeps the IDENTICAL sink code in both bad() and goodG2B(), only
// swapping the source of one bare local variable (`data = System.getenv(…)`
// vs. `data = "foo"`) — this taint-independent detector, having no taint
// model of its own, previously could not tell the two apart and fired on
// both, a large fraction of this family's real corpus false positives.
const RE = {
  sqlInjection: /\b(?:executeQuery|executeUpdate|execute|createQuery|createNativeQuery|prepareStatement|prepareCall)\s*\(\s*"[^"\n]*"\s*\+(?:\s*([A-Za-z_]\w*)\s*(?=(?:\s*\+\s*"[^"\n]*"\s*)?[);]))?/g,
  cmdInjection: /\b(?:Runtime\.getRuntime\(\)\s*\.\s*exec|ProcessBuilder)\s*\(\s*(?:new\s+String\s*\[\s*\]\s*\{\s*)?"[^"\n]*"\s*\+(?:\s*([A-Za-z_]\w*)\s*(?=(?:\s*\+\s*"[^"\n]*"\s*)?[);]))?/g,
};

// True when `varName`'s NEAREST assignment before `beforeIdx` (source order)
// is a plain string-literal RHS — same "backward nearest-assignment" shape
// as java-bench-extras.js's `_nearestAssignIsLiteral` (CWE-259), reused here
// for the opposite purpose: SUPPRESSING a structural finding instead of
// creating one. Deliberately narrow: only fires when the regex above
// captured a SINGLE trailing identifier immediately before the sink call's
// closing `)`/`;` — a concatenation with more terms after it
// (`"…" + a + b`) is left alone, since a safe `a` says nothing about `b`.
//
// SARD_80_F1 W4.J35 — the SAME dead-code-blindness bug already fixed twice
// this session in sibling files (W4.J33's `java-bench-extras.js`
// `_nearestAssignIsLiteral`; W4.J34's own `deadBranchRanges` extension),
// found here independently while sweeping Java's largest CWE-89 fp bucket
// (300+ files, all `_02`..`_51b`-numbered `connect_tcp_executeUpdate_XX`
// variants sharing this ONE detector). Confirmed via the public Java Juliet
// mirror's own `CWE89_SQL_Injection__connect_tcp_executeUpdate_02.java`:
// `goodG2B2()` does `if (true) { data = "foo"; } else { data = null; }`
// immediately before the identical `executeUpdate("…"+data+"'")` sink line
// `bad()` also uses — the textually-LATER dead `data = null;` in the else
// branch made `lastAnyEnd` land there instead of on the live literal
// assignment, so `lastLiteralEnd === lastAnyEnd` failed and this entire
// flow-variant family (Juliet's own Flow Variant 02, used across dozens of
// CWEs per W4.C28's original C#-side discovery of the same idiom) was never
// recognized as literal-only. Fixed by reusing the ALREADY-EXISTING,
// AST-based `deadBranchRanges`/`isLineInDeadRange` (the SAME mechanism
// W4.J33 already wired into `java-bench-extras.js`, and which W4.J34
// separately extended to also resolve `private static final` field
// constants — this fix inherits BOTH capabilities for free) to skip an
// assignment whose line falls inside a provably-dead branch when computing
// `lastAnyEnd`.
// SARD_80_F1 W5.23 — ports java-bench-extras.js's W4.J37/W4.J38 cross-method
// literal resolution (same-file callee-return, same-method copy-chain,
// argument-passing via all call sites) into this file's OWN independent copy
// of the "nearest assignment" heuristic. Confirmed via a real-corpus sweep
// that CWE-89's own remaining fp bucket includes an even ~11-file share for
// EACH of Juliet's Flow Variant 31 (copy)/41 (argument)/42 (return) suffixes,
// the exact three idioms java-bench-extras.js's CWE-259/601 detectors already
// needed this same fix for — this file never received the port. Kept as a
// SEPARATE copy rather than a shared import, matching this file's own
// established convention (see `_trailingIdentIsLiteral`'s header comment)
// of independently-tuned duplicates rather than a cross-file dependency.
// Regexes below are copied VERBATIM in their already-ReDoS-fixed form (see
// java-bench-extras.js's own W4.J39 fix comments) — never reintroduce a
// lazy, `\s`-inclusive "return type" prefix match; neither function below
// ever reads that prefix, so it was never needed for correctness.
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
  if (returns.length !== 1) return false;
  const { expr, idx } = returns[0];
  if (/^"[^"]*"$/.test(expr)) return true;
  if (/^[A-Za-z_]\w*$/.test(expr)) {
    return _trailingIdentIsLiteral(content, expr, idx, deadRanges, depth + 1);
  }
  return false;
}

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
  if (paramIdx === -1) return false;
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
    if (afterClose) continue;
    const args = _splitTopLevelCommas(content.slice(argsStart, i - 1)).map((a) => a.trim());
    if (paramIdx >= args.length) return false;
    sawRealCallSite = true;
    const argExpr = args[paramIdx];
    if (/^"[^"]*"$/.test(argExpr)) continue;
    if (/^[A-Za-z_]\w*$/.test(argExpr) && _trailingIdentIsLiteral(content, argExpr, cm.index, deadRanges, depth0 + 1)) continue;
    return false;
  }
  return sawRealCallSite;
}

function _trailingIdentIsLiteral(code, varName, beforeIdx, deadRanges, _calleeDepth) {
  if (!varName) return false;
  if ((_calleeDepth || 0) >= _CALLEE_RETURN_LITERAL_CACHE_DEPTH) return false;
  const ranges = deadRanges || [];
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const literalRe = new RegExp(`\\b${escaped}\\s*=\\s*"[^"]*"\\s*;`, 'g');
  const anyAssignRe = new RegExp(`\\b${escaped}\\s*=\\s*([^;]+);`, 'g');
  const lineOfIdx = (idx) => code.substring(0, idx).split('\n').length;
  let lastLiteralEnd = -1, m;
  while ((m = literalRe.exec(code)) && m.index < beforeIdx) {
    if (ranges.length && isLineInDeadRange(lineOfIdx(m.index), ranges)) continue;
    lastLiteralEnd = m.index + m[0].length;
  }
  let lastAnyEnd = -1, lastAnyRhs = null, lastAnyIdx = -1;
  while ((m = anyAssignRe.exec(code)) && m.index < beforeIdx) {
    if (ranges.length && isLineInDeadRange(lineOfIdx(m.index), ranges)) continue;
    lastAnyEnd = m.index + m[0].length;
    lastAnyRhs = m[1].trim();
    lastAnyIdx = m.index;
  }
  // Same-file callee-return resolution (Flow Variant 42).
  if (lastAnyRhs && /^[A-Za-z_]\w*\s*\([^()]*\)$/.test(lastAnyRhs)) {
    const calleeName = lastAnyRhs.slice(0, lastAnyRhs.indexOf('(')).trim();
    if (_resolveCalleeReturnIsLiteral(code, calleeName, ranges, _calleeDepth)) return true;
  }
  // Same-method copy-chain resolution (Flow Variant 31).
  if (lastAnyRhs && lastAnyRhs !== 'null' && /^[A-Za-z_]\w*$/.test(lastAnyRhs) && lastAnyRhs !== varName) {
    if (_trailingIdentIsLiteral(code, lastAnyRhs, lastAnyIdx, ranges, (_calleeDepth || 0) + 1)) return true;
  }
  if (lastLiteralEnd === -1 || lastLiteralEnd !== lastAnyEnd) {
    // Argument-passing resolution via all call sites (Flow Variant 41).
    return _resolveParamLiteralViaAllCallSites(code, varName, beforeIdx, deadRanges, _calleeDepth);
  }
  return true;
}

const META = {
  sqlInjection: {
    vuln: 'SQL Injection — query built with string concatenation (Java)',
    severity: 'critical', cwe: 'CWE-89',
    remediation: 'Use a PreparedStatement with bind parameters: prepareStatement("… WHERE name = ?") then setString(1, name). Never concatenate values into SQL.',
  },
  cmdInjection: {
    vuln: 'Command Injection — exec built with string concatenation (Java)',
    severity: 'critical', cwe: 'CWE-78',
    remediation: 'Use ProcessBuilder with an argument array (no shell): new ProcessBuilder("cmd", arg1, arg2). Never concatenate input into a command string.',
  },
};

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanJavaStructural(fp, raw) {
  if (!/\.java$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };
  const emit = (key, line, meta) => push({
    id: `java-struct-${key}:${fp}:${line}`, file: fp, line,
    vuln: meta.vuln, severity: meta.severity, cwe: meta.cwe, family: meta.family,
    snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
    remediation: meta.remediation, parser: 'JAVA', confidence: 0.78,
  });
  // See _trailingIdentIsLiteral's own header comment (W4.J35).
  let deadRanges = [];
  try { deadRanges = deadBranchRanges(raw); } catch { /* parse error → no AST info */ }

  for (const [key, re] of Object.entries(RE)) {
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(code))) {
      if (_trailingIdentIsLiteral(code, m[1], m.index, deadRanges)) continue;
      emit(key, lineOf(code, m.index), META[key]);
    }
  }

  // Path traversal (CWE-22): a file path built by concatenation, unless the
  // file canonicalizes / normalizes / range-checks the path.
  const PATH_SINK = /\bnew\s+(?:File|FileInputStream|FileReader|FileOutputStream|RandomAccessFile)\s*\(\s*"[^"\n]*"\s*\+|\bPaths\.get\s*\(\s*"[^"\n]*"\s*\+/;
  const PATH_GUARD = /getCanonicalPath|toRealPath|\.normalize\s*\(\s*\)|\bstartsWith\s*\(|FilenameUtils|\.isAbsolute\s*\(/;
  if (PATH_SINK.test(code) && !PATH_GUARD.test(code)) {
    const line = lineOf(code, code.search(PATH_SINK));
    emit('path', line, {
      vuln: 'Path Traversal — file path built with string concatenation (Java)',
      severity: 'high', cwe: 'CWE-22',
      remediation: 'Resolve against an allow-listed base and verify containment: Path want = base.resolve(name).normalize().toRealPath(); if (!want.startsWith(base)) throw …',
    });
  }

  // SSRF (CWE-918): new URL/URI opened from a non-literal/templated value,
  // unless a host allow/deny guard is present.
  //
  // SARD_80_F1 W4.J22/W4.J24 — SSRF_SINK previously matched the mere
  // CONSTRUCTION of a URL/URI object, with no check that it's ever actually
  // used to open an outbound connection. `new URI(data)` is a completely
  // ordinary way to VALIDATE a string's syntax (catch URISyntaxException)
  // before doing something else entirely with it — e.g. Juliet's own
  // CWE-601 (Open Redirect) test cases build a `URI` purely to reject a
  // malformed redirect target, then call `response.sendRedirect(data)`,
  // never opening any connection — confirmed directly against the public
  // mirror (UnitTestBot/juliet-java-test-suite,
  // CWE601_Open_Redirect__Servlet_File_53d.java). That construction-only
  // shape was scoring as unrelated-CWE noise on every Juliet CWE-601 file
  // that validates a URI this way. Now requires evidence of an outbound
  // connection call somewhere in the file — file-scoped (like SSRF_GUARD
  // already is) rather than proximity-scoped, since a real SSRF sink and
  // its `new URL(...)` construction are frequently on the very same line
  // anyway (`new URL(url).openStream()...`, this detector's own positive
  // test fixture).
  const SSRF_SINK = /\bnew\s+(?:URL|URI)\s*\(\s*(?:[A-Za-z_]\w*\s*\)|"[^"\n]*"\s*\+)/;
  const SSRF_CONNECT = /\.\s*openConnection\s*\(|\.\s*openStream\s*\(|\.\s*getContent\s*\(|\.\s*connect\s*\(\s*\)|\bHttpURLConnection\b|\bHttpClient\b/;
  const SSRF_GUARD = /169\.254\.169\.254|getHost\s*\(\s*\)|allow(?:ed)?Hosts?|isLoopback|isSiteLocal|isLinkLocal|InetAddress|\bDENY\b|deny(?:list)?|block(?:list|ed)/i;
  if (SSRF_SINK.test(code) && SSRF_CONNECT.test(code) && !SSRF_GUARD.test(code)) {
    const line = lineOf(code, code.search(SSRF_SINK));
    emit('ssrf', line, {
      vuln: 'SSRF — URL/URI opened from a non-literal value (Java)',
      severity: 'high', cwe: 'CWE-918',
      remediation: 'Resolve the host and reject RFC1918 / link-local / metadata (169.254.169.254) addresses, or use an allow-list, before opening the connection.',
    });
  }

  return findings;
}
