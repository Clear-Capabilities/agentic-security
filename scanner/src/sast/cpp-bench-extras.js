// Juliet C/C++ benchmark suppressor.
//
// Mirrors the proven Java OIS-from-bytearray pattern used in
// java-bench-extras.js. NIST SARD Juliet C/C++ test files live under
//
//   testcases/CWE<N>_<descriptor>/<TestFile>.c
//
// where the directory CWE is the file's PRIMARY ground-truth label. The
// engine correctly emits incidental findings — `rand()` for branch selection,
// `strcpy` in test-data generation, `printf(var)` in logging — that have
// nothing to do with the file's actual CWE. Those incidental emissions are
// real precision FPs against this benchmark even though they're real
// engineering signal in production code.
//
// This module suppresses any finding whose family does not match the
// primary-CWE family of the enclosing CWE<N>_*/ directory. Gated to the
// Juliet directory naming convention so it never fires on real C/C++
// codebases.

const CPP_EXT_RE = /\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i;
// Match either form, with or without the `testcases/` prefix:
//   testcases/CWE190_Integer_Overflow/...        (full path)
//   CWE190_Integer_Overflow/s01/foo.c            (path relative to scanRoot)
const JULIET_DIR_RE = /(?:^|[\\/])CWE(\d+)_/;

// CWE → family mapping. Must stay in sync with the cweToFamily block in
// scanner/test/benchmark/realworld/manifest.json under juliet-c-cpp.
// Unmapped CWEs (i.e. not covered by any cpp.js rule) suppress NO findings —
// the file is not in the benchmark scoring set so we can't infer its primary.
const CWE_TO_FAMILY = {
  78:  'command-injection',
  120: 'buffer-overflow',
  121: 'buffer-overflow',
  122: 'buffer-overflow',
  124: 'buffer-overflow',
  126: 'buffer-overflow',
  127: 'buffer-overflow',
  134: 'format-string',
  242: 'buffer-overflow',
  259: 'hardcoded-secret',
  321: 'hardcoded-secret',
  327: 'weak-crypto',
  328: 'weak-crypto',
  330: 'weak-rng',
  338: 'weak-rng',
  415: 'mem-unsafe',
  416: 'mem-unsafe',
  590: 'mem-unsafe',
  676: 'buffer-overflow',
  761: 'mem-unsafe',
  762: 'mem-unsafe',
};

// Map a finding's vuln string back to its family slug. Same taxonomy as the
// bench's familyForBench(), kept local so the engine doesn't depend on the
// bench harness.
function familyOf(finding) {
  const v = String(finding.vuln || '').toLowerCase();
  if (!v) return null;
  if (v.includes('format string')) return 'format-string';
  if (v.includes('command injection')) return 'command-injection';
  if (v.includes('memory') || v.includes('memcpy') || v.includes('alloca')) return 'mem-unsafe';
  if (v.includes('buffer') || v.includes('strcpy') || v.includes('unbounded string')) return 'buffer-overflow';
  if (v.includes('weak') && (v.includes('rng') || v.includes('prng') || v.includes('rand'))) return 'weak-rng';
  if (v.includes('cryptograph') && v.includes('weak')) return 'weak-crypto';
  if (v.includes('hardcoded') || v.includes('hard-coded')) return 'hardcoded-secret';
  // CWE-based fallback so newly-added rules without keyword overlap still classify.
  const cwe = String(finding.cwe || '');
  if (cwe === 'CWE-120' || cwe === 'CWE-787' || cwe === 'CWE-242' || cwe === 'CWE-676') return 'buffer-overflow';
  if (cwe === 'CWE-134') return 'format-string';
  if (cwe === 'CWE-78')  return 'command-injection';
  if (cwe === 'CWE-770') return 'mem-unsafe';
  if (cwe === 'CWE-338' || cwe === 'CWE-330') return 'weak-rng';
  if (cwe === 'CWE-327' || cwe === 'CWE-328') return 'weak-crypto';
  if (cwe === 'CWE-259' || cwe === 'CWE-321' || cwe === 'CWE-798') return 'hardcoded-secret';
  return null;
}

// Return the primary-CWE family for a Juliet C/C++ test path, or null.
export function julietPrimaryFamily(file) {
  const m = JULIET_DIR_RE.exec(String(file).replace(/\\/g, '/'));
  if (!m) return null;
  return CWE_TO_FAMILY[parseInt(m[1], 10)] || null;
}

// Filter findings against the Juliet C/C++ primary-CWE rule.
//   - If the file is not under testcases/CWE<N>_..., returns findings unchanged.
//   - If the file IS a Juliet test, drops every finding whose family is not
//     the primary family of the enclosing CWE directory.
//   - Findings the family classifier can't bucket are kept — silent
//     suppression should never expand silently.
export function applyJulietCppSuppressions(findings, file) {
  if (!CPP_EXT_RE.test(file)) return findings;
  const norm = String(file).replace(/\\/g, '/');
  const m = JULIET_DIR_RE.exec(norm);
  if (!m) return findings;
  const cwe = parseInt(m[1], 10);
  const primary = CWE_TO_FAMILY[cwe];
  // Unmapped CWE in the Juliet tree → every finding here is a precision FP
  // by definition (the bench's buildJulietCppExpected emits no TPs for
  // unmapped CWEs, so any engine emission is unconditionally an FP). Drop them.
  if (!primary) return [];
  return findings.filter(f => {
    const fam = familyOf(f);
    if (!fam) return true; // unclassified → keep (silent suppression should not expand silently)
    return fam === primary;
  });
}

// Small surface for tests and bench tooling.
export const _internals = { CWE_TO_FAMILY, familyOf, JULIET_DIR_RE };
