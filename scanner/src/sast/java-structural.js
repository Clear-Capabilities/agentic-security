// Java structural (taint-independent) injection detectors — PRD Tier 1.
//
// The flow-based Java modules miss standalone DAO/handler methods whose
// tainted-by-convention parameter has no in-file source. Java has no string
// templates, so the injection shape is string CONCATENATION (`"…" +`) into a
// dangerous sink — which is itself the vulnerability regardless of the
// variable's name. Parameterized statements / canonicalized paths / host-
// guarded URLs do not match, keeping this high-precision.

import { blankComments } from './_comment-strip.js';

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
function _trailingIdentIsLiteral(code, varName, beforeIdx) {
  if (!varName) return false;
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const literalRe = new RegExp(`\\b${escaped}\\s*=\\s*"[^"]*"\\s*;`, 'g');
  const anyAssignRe = new RegExp(`\\b${escaped}\\s*=\\s*[^;]+;`, 'g');
  let lastLiteralEnd = -1, m;
  while ((m = literalRe.exec(code)) && m.index < beforeIdx) lastLiteralEnd = m.index + m[0].length;
  if (lastLiteralEnd === -1) return false;
  let lastAnyEnd = -1;
  while ((m = anyAssignRe.exec(code)) && m.index < beforeIdx) lastAnyEnd = m.index + m[0].length;
  return lastLiteralEnd === lastAnyEnd;
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

  for (const [key, re] of Object.entries(RE)) {
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(code))) {
      if (_trailingIdentIsLiteral(code, m[1], m.index)) continue;
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
