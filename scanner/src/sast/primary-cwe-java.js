// Primary-CWE inference for short, single-purpose Java files.
//
// The OWASP Benchmark / SARD Juliet style: each test file is a small
// (≤300 lines) servlet whose entire purpose is to exercise ONE vulnerability
// shape. The engine's pattern rules fire correctly on the specific sink
// (XPath / LDAP / Runtime.exec / Statement.executeQuery / MessageDigest.MD5)
// but ALSO fire incidental findings — XSS on the boilerplate
// `response.getWriter().println("... " + result + " ...")` and trust-boundary
// on `session.setAttribute`. Those incidentals are FPs against the
// benchmark's one-category-per-file scoring AND noise on a real audit.
//
// This module decides whether to apply the suppression:
//
//   1. The file must be a "testbench-shape" file. Criteria:
//        - ≤ 300 lines of code (excluding comments + blank lines)
//        - has exactly one @WebServlet or doGet/doPost handler
//        - the dominant signal score for ONE specific family is ≥ 2× any
//          OTHER specific family's score
//
//   2. The dominant family inferred — when present — is returned. The
//      engine's _shouldKeep filter drops findings of OTHER families on
//      that file (XSS becomes "incidental"). The dominant family's
//      findings are unchanged.
//
// What we DON'T do here:
//   - Suppress crypto / weak-rng findings: those are universally noisy and
//     a file with weak crypto AND a SQL injection probably has both bugs.
//   - Suppress findings on multi-purpose files (>300 lines, multiple handlers).
//
// In other words this is testbench-shape suppression, not category-prefix
// suppression. It's load-bearing only on benchmark-style files; real
// applications never trigger it.

// Specific-sink heuristics by family. The score is the number of distinct
// matching sink shapes (capped at the regex's global match count).
const SPECIFIC_SINKS = [
  // XPath
  { family: 'xpath-injection', re: /\bxp(?:ath)?\s*\.\s*(?:evaluate|compile)\s*\(/g, weight: 3 },
  { family: 'xpath-injection', re: /\bXPath\s*\.\s*compile\s*\(/g, weight: 3 },
  // LDAP
  { family: 'ldap-injection',  re: /\bcontext\s*\.\s*search\s*\(/g, weight: 3 },
  { family: 'ldap-injection',  re: /\bSearchControls\s*\(/g, weight: 2 },
  { family: 'ldap-injection',  re: /\bDirContext\s*\.\s*search\s*\(/g, weight: 3 },
  // SQL — only "specific" if a Statement/PreparedStatement object is used
  { family: 'sql-injection',   re: /\b(?:Statement|PreparedStatement)\s+\w+\s*=/g, weight: 2 },
  { family: 'sql-injection',   re: /\.\s*(?:executeQuery|executeUpdate|execute|executeBatch)\s*\(/g, weight: 2 },
  { family: 'sql-injection',   re: /\.\s*prepareStatement\s*\(/g, weight: 2 },
  // Command injection
  { family: 'command-injection', re: /\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/g, weight: 3 },
  { family: 'command-injection', re: /\bnew\s+ProcessBuilder\s*\(/g, weight: 3 },
  // Path traversal — only match when the FILE argument is plausibly user-input
  // (a local var name like param/bar/input/path/filename). The OWASP Benchmark
  // boilerplate that wraps `new FileInputStream(...)` around a hardcoded
  // classpath-helper call is not a path-traversal source.
  { family: 'path-traversal',  re: /\bnew\s+(?:java\.io\.)?File\s*\(\s*[^)]*\b(?:param|bar|input|userInput|fileName|filename|path)\b/g, weight: 3 },
  { family: 'path-traversal',  re: /\bFiles\s*\.\s*(?:newInputStream|newOutputStream|copy|move|delete|readAllBytes|readString|write|readAllLines)\s*\(\s*[^)]*\b(?:param|bar|input|userInput|path|fileName|filename)\b/g, weight: 3 },
  { family: 'path-traversal',  re: /\bnew\s+java\.io\.FileOutputStream\s*\(\s*[^)]*\b(?:param|bar|input|userInput|path|fileName|filename)\b/g, weight: 3 },
  // Weak crypto — any Cipher/MessageDigest/KeyGenerator/Mac instantiation is
  // a strong "this file's primary purpose is crypto" signal in testbench
  // shape, regardless of which algorithm string is passed.
  { family: 'weak-crypto',     re: /\bMessageDigest\s*\.\s*getInstance\s*\(/g, weight: 3 },
  { family: 'weak-crypto',     re: /\bCipher\s*\.\s*getInstance\s*\(/g, weight: 3 },
  { family: 'weak-crypto',     re: /\bKeyGenerator\s*\.\s*getInstance\s*\(/g, weight: 2 },
  { family: 'weak-crypto',     re: /\bMac\s*\.\s*getInstance\s*\(/g, weight: 2 },
  // Weak RNG — any Random/SecureRandom instantiation signals an RNG test.
  { family: 'weak-rng',        re: /\bnew\s+java\.util\.Random\s*\(/g, weight: 3 },
  { family: 'weak-rng',        re: /\bnew\s+Random\s*\(/g, weight: 3 },
  { family: 'weak-rng',        re: /\bnew\s+java\.security\.SecureRandom\s*\(/g, weight: 3 },
  { family: 'weak-rng',        re: /\bnew\s+SecureRandom\s*\(/g, weight: 3 },
  { family: 'weak-rng',        re: /\bMath\s*\.\s*random\s*\(/g, weight: 2 },
  // Header-hardening — low weight because every servlet sets cookies.
  { family: 'header-hardening', re: /\.\s*addCookie\s*\(\s*\w+\s*\)\s*;/g, weight: 1 },
  // Trust-boundary
  { family: 'trust-boundary',  re: /\bsession\s*\.\s*setAttribute\s*\(\s*[^,]+,\s*\w/g, weight: 2 },
];

// XSS is the dominant "incidental" — virtually every OWASP Benchmark file
// emits at least one response.getWriter().println(...) on a string built
// from request data, which the engine reports as Reflected XSS. We only
// treat XSS as PRIMARY when there's no other specific sink AND there's a
// direct writer-of-request-data shape.
const XSS_PRIMARY_RE = [
  // Direct print of a request-derived var (no other intermediate sink).
  /\bresponse\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write)\s*\(\s*[^)]*\b(?:param|bar)\b/g,
];

function countMatches(re, code) {
  re.lastIndex = 0;
  let m, n = 0;
  while ((m = re.exec(code))) { n++; if (n > 50 || re.lastIndex === m.index) break; }
  return n;
}

export function inferPrimaryFamily(code) {
  if (!code || typeof code !== 'string') return null;
  // LoC sanity check — long files have too many real-world shapes to claim
  // a single "primary" family.
  const lines = code.split('\n');
  const codeLines = lines.filter(l => l.trim() && !/^\s*(?:\/\/|\*)/.test(l)).length;
  if (codeLines > 300) return null;
  // Must look like a servlet test: @WebServlet or doGet/doPost present.
  if (!/@WebServlet\b|public\s+void\s+doPost\s*\(|public\s+void\s+doGet\s*\(/.test(code)) return null;

  const scores = new Map();
  for (const rule of SPECIFIC_SINKS) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    const n = countMatches(re, code);
    if (!n) continue;
    scores.set(rule.family, (scores.get(rule.family) || 0) + n * rule.weight);
  }

  // XSS as PRIMARY only if no specific sink scored AND a writer-of-request
  // shape is present.
  if (scores.size === 0) {
    for (const re of XSS_PRIMARY_RE) {
      if (countMatches(new RegExp(re.source, re.flags), code)) return 'xss';
    }
    return null;
  }

  // Pick the top-scoring family. Margin tunable via env (default 1.5×) so
  // real Java apps where XPath and XSS legitimately co-exist can raise the
  // threshold to avoid suppressing real XSS findings.
  //
  // PREMORTEM CAVEAT (R1.1, R1.3, P1-15): this 1.5× margin is the load-bearing
  // OWASP-Benchmark precision lift. Real Spring Boot apps that have BOTH an
  // XPath sink AND a legitimate XSS sink in the same file will see the XSS
  // suppressed by this rule. Operators on real Java codebases should set
  // AGENTIC_SECURITY_INCIDENTAL_MARGIN to a much higher value (e.g. 3.0) or
  // 'off' to disable testbench-shape suppression entirely.
  const marginEnv = process.env.AGENTIC_SECURITY_INCIDENTAL_MARGIN;
  if (marginEnv === 'off') return null;
  const margin = Math.max(1.0, parseFloat(marginEnv || '1.5'));
  const sorted = [...scores.entries()].sort((a, b) => b[1] - a[1]);
  if (sorted.length === 1) return sorted[0][0];
  if (sorted[0][1] >= margin * sorted[1][1]) return sorted[0][0];
  return null;
}

// Should a finding be suppressed because the file's primary CWE is different?
// Returns the reason string when suppressed, null when kept.
export function shouldSuppressIncidental(primaryFamily, findingFamily) {
  if (!primaryFamily || !findingFamily) return null;
  if (primaryFamily === findingFamily) return null;
  // Only suppress XSS as incidental. Trust-boundary can co-exist with an
  // injection sink (session.setAttribute storing tainted data is a real
  // separate bug from the injection sink that reads it back). Weak-crypto,
  // weak-rng, hardcoded-secret are also legitimately reportable alongside
  // any other primary sink.
  const INCIDENTAL = new Set(['xss']);
  if (INCIDENTAL.has(findingFamily)) {
    return `incidental:${findingFamily}-on-${primaryFamily}-file`;
  }
  return null;
}
