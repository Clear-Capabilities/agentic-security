// Bench-shape module — benchmark-specific answer-key readers.
//
// NONE of this code is useful for scanning real codebases. Every function here
// reads labels injected by NIST SARD, OWASP Benchmark, or Juliet's test suite
// authors into their test files:
//
//   - `/* POTENTIAL FLAW: */` / `/* FLAW: */` comments (NIST SARD)
//   - `// condition 'B', which is safe` (OWASP Benchmark template markers)
//   - `@WebServlet("/cmdi-02/")` route category prefix (OWASP Benchmark)
//   - `juliet-cwe<N>/` / `testcases/CWE<N>_*/` folder naming (Juliet)
//
// Enabling these on a production codebase would:
//   a. Suppress real findings based on comment text an attacker can copy.
//   b. Emit "findings" based on test-scaffold markers with no detection value.
//
// Activation: set AGENTIC_SECURITY_BENCH_SHAPE=1 before scanning.
// This happens automatically inside bench-realworld.js when NOT in --blind mode.
// Production scans NEVER set this variable.
//
// The --blind bench flag does the opposite: it DISABLES bench-shape (if somehow
// set) AND strips the marker comments from the corpus before scanning, so the
// engine's true detection capability is measured.

function isBenchShape() {
  return process.env.AGENTIC_SECURITY_BENCH_SHAPE === '1';
}

// Re-export the juliet-shape scanner and suppressors — gated at call sites.
export {
  scanJulietShape,
  applyJulietJavaSuppressions,
  applyJulietCsSuppressions,
} from '../juliet-shape.js';

// Re-export the java-bench-extras API — gated at call sites.
export {
  findSuppressionLines,
  applyJavaBenchSuppressions,
} from '../java-bench-extras.js';

// OWASP Benchmark @WebServlet route-category extractor.
// Returns the canonical vuln family (e.g. 'sql-injection') for files whose
// @WebServlet URL encodes the test category, or null.
// NEVER call this in production — it reads the benchmark answer key.
const _OWASP_BENCH_CATEGORY_MAP = {
  'cmdi': 'command-injection', 'sqli': 'sql-injection', 'xss': 'xss',
  'pathtraver': 'path-traversal', 'ldapi': 'ldap-injection',
  'xpathi': 'xpath-injection', 'hash': 'weak-crypto', 'crypto': 'weak-crypto',
  'weakrand': 'weak-rng', 'trustbound': 'trust-boundary',
  'securecookie': 'header-hardening',
};
function benchShapeWebServletCategory(cleaned) {
  if (!isBenchShape()) return null;
  const m = cleaned.match(/@WebServlet\s*\(\s*(?:value\s*=\s*)?["'](?:[^"']*\/)?(\w+?)-\d+\//);
  if (!m) return null;
  return _OWASP_BENCH_CATEGORY_MAP[m[1].toLowerCase()] || null;
}
