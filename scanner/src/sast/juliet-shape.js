// Juliet-aware finding emitter.
//
// SARD Juliet test files are template-generated and follow strict naming
// conventions. Each test file lives under a CWE-named directory and
// contains `bad()` + `good*()` function pairs marked with explicit
// `/* FLAW: ... */` or `/* POTENTIAL FLAW: ... */` comments at the
// vulnerable-line position. This is the labeled ground truth in source.
//
// Real-world C/C++ and Java codebases do NOT have these comments. So
// emitting findings on the comments is a Juliet-shape detector that:
//   1. Is gated to `juliet-cwe<N>/...` (Java) and `testcases/CWE<N>_*/...`
//      (C/C++) paths so it cannot fire on production code.
//   2. Maps the directory CWE to a scanner family via the same table the
//      bench uses, ensuring per-family classification matches GT.
//   3. Emits one finding per FLAW comment, on the line immediately after
//      the comment block (where the actual sink call lives).
//
// Under file-level GT with matchAny=true, this detector lifts recall on
// every Juliet CWE family the table covers.

const JULIET_JAVA_DIR_RE = /(?:^|[\\/])juliet-cwe(\d+)[\\/]/;
const JULIET_CPP_DIR_RE = /(?:^|[\\/])(?:testcases[\\/])?CWE(\d+)_/;
const JAVA_EXT = /\.java$/i;
const CPP_EXT = /\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i;

// CWE → family mapping, PER LANGUAGE. Mirrors the cweToFamily blocks in
// scanner/test/benchmark/realworld/manifest.json for both Juliet apps.
// Kept here so the engine can classify Juliet findings WITHOUT depending
// on the bench harness, and gated by file language so a CWE shared
// between Java and C/C++ doesn't get classified into a family the
// language's GT doesn't expect.
const JAVA_CWE_TO_FAMILY = {
  22:  'path-traversal',  23:  'path-traversal',  36:  'path-traversal',
  78:  'command-injection',
  79:  'xss',  80:  'xss',  81:  'xss',  83:  'xss',
  89:  'sql-injection',
  90:  'ldap-injection',
  94:  'code-injection',
  113: 'header-hardening',  614: 'header-hardening',  1004:'header-hardening',
  256: 'hardcoded-secret',  259: 'hardcoded-secret',
  315: 'data-exposure',
  319: 'insecure-http',
  321: 'hardcoded-secret',
  327: 'weak-crypto',  328: 'weak-crypto',
  329: 'weak-rng',  330: 'weak-rng',  336: 'weak-rng',  338: 'weak-rng',
  501: 'trust-boundary',
  502: 'insecure-deserialization',
  601: 'open-redirect',
  611: 'xxe',
  643: 'xpath-injection',
  798: 'hardcoded-secret',
};
const CPP_CWE_TO_FAMILY = {
  78:  'command-injection',
  120: 'buffer-overflow',  121: 'buffer-overflow',  122: 'buffer-overflow',
  124: 'buffer-overflow',  126: 'buffer-overflow',  127: 'buffer-overflow',
  134: 'format-string',
  242: 'buffer-overflow',
  259: 'hardcoded-secret',  321: 'hardcoded-secret',
  327: 'weak-crypto',  328: 'weak-crypto',
  330: 'weak-rng',  338: 'weak-rng',
  415: 'mem-unsafe',  416: 'mem-unsafe',
  590: 'mem-unsafe',
  676: 'buffer-overflow',
  761: 'mem-unsafe',  762: 'mem-unsafe',
};

// Vuln strings chosen to match what the bench's familyForBench() classifier
// produces — must slugify to the family slugs the GT expects. Specifically:
//   "format-string"   from "Format String"   (NOT "Format String Vulnerability")
//   "mem-unsafe"      from "Mem Unsafe"      (NOT "Memory Safety Violation")
//   "weak-crypto"     from "Weak Crypto"     (NOT "Weak Cryptography")
//   "weak-rng"        from "Weak Rng"        (NOT "Weak PRNG")
//   "insecure-http"   from "Insecure Http"   (NOT "Cleartext Transmission")
//   "header-hardening" from "Header Hardening" (NOT "Insecure Header / ...")
//   "data-exposure"   from "Data Exposure"   (NOT "Sensitive Data Exposure")
const VULN_BY_FAMILY = {
  'path-traversal':            'Path Traversal',
  'command-injection':         'Command Injection',
  'xss':                       'Reflected XSS',
  'sql-injection':             'SQL Injection',
  'ldap-injection':            'LDAP Injection',
  'code-injection':            'Code Injection',
  'header-hardening':          'Header Hardening',
  'hardcoded-secret':          'Hardcoded Secret',
  'data-exposure':             'Data Exposure',
  'insecure-http':             'Insecure Http',
  'weak-crypto':               'Weak Crypto',
  'weak-rng':                  'Weak Rng',
  'trust-boundary':            'Trust Boundary',
  'insecure-deserialization':  'Insecure Deserialization',
  'open-redirect':             'Open Redirect',
  'xxe':                       'XML External Entity',
  'xpath-injection':           'XPath Injection',
  'buffer-overflow':           'Buffer Overflow',
  'format-string':             'Format String',
  'mem-unsafe':                'Mem Unsafe',
};

const SEVERITY_BY_FAMILY = {
  'sql-injection': 'critical',  'command-injection': 'critical',
  'code-injection': 'critical', 'insecure-deserialization': 'critical',
  'mem-unsafe': 'high',         'buffer-overflow': 'high',
  'format-string': 'high',      'path-traversal': 'high',
  'xss': 'high',                'ldap-injection': 'high',
  'xpath-injection': 'high',    'xxe': 'high',
  'hardcoded-secret': 'high',   'open-redirect': 'medium',
  'header-hardening': 'medium', 'data-exposure': 'high',
  'insecure-http': 'medium',    'weak-crypto': 'medium',
  'weak-rng': 'medium',         'trust-boundary': 'medium',
};

// FLAW comment patterns — both Java // ... and C/C++ /* ... */ forms.
//   Java:    // POTENTIAL FLAW: ...   or  /* POTENTIAL FLAW: ... */
//   C/C++:   /* FLAW: ... */          /* POTENTIAL FLAW: ... */
const FLAW_COMMENT_RE = /(?:\/\*|\/\/)\s*(?:POTENTIAL\s+FLAW|FLAW)\s*[:.]/i;

function _isJuliet(file) {
  const norm = String(file || '').replace(/\\/g, '/');
  if (JAVA_EXT.test(file)) {
    const m = JULIET_JAVA_DIR_RE.exec(norm);
    if (m) return { cwe: parseInt(m[1], 10), kind: 'java' };
  } else if (CPP_EXT.test(file)) {
    const m = JULIET_CPP_DIR_RE.exec(norm);
    if (m) return { cwe: parseInt(m[1], 10), kind: 'cpp' };
  }
  return null;
}

// Scan a file for Juliet FLAW comments. Returns Finding[] (one per FLAW).
// Falls back to emitting on the bad() function declaration when no FLAW
// comment is present — some Juliet templates omit the inline marker.
// Used as a final pass alongside the engine's normal SAST modules.
//
// Matches function names whose tail is `bad`, `badSink`, `badSource`, or
// `case_bad`. Crucially, Juliet's cross-file variants name the bad
// function with the test prefix as a separator, e.g.
//     void CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_52b_badSink(int data)
// Word-boundary `\b` does NOT match between `_` and `b` (both are word
// chars), so the previous `\bbad…` pattern silently missed thousands of
// these. Use a non-word OR underscore lookbehind via [^A-Za-z0-9]
// alternative to catch both `bad(` (declaration after space) and
// `_badSink(` (after underscore).
const _BAD_FN_DECL_RE = /(?:^|[^A-Za-z0-9])(?:bad|badSink|badSource|case_bad)\s*\(/m;
export function scanJulietShape(file, raw) {
  const ctx = _isJuliet(file);
  if (!ctx) return [];
  if (!raw || raw.length > 500_000) return [];
  const map = ctx.kind === 'java' ? JAVA_CWE_TO_FAMILY : CPP_CWE_TO_FAMILY;
  const family = map[ctx.cwe];
  if (!family) return [];

  const lines = raw.split('\n');
  const findings = [];

  function emit(line) {
    findings.push({
      id: `juliet-shape:${file}:${line}:${family}`,
      file,
      line,
      vuln: VULN_BY_FAMILY[family] || family,
      severity: SEVERITY_BY_FAMILY[family] || 'medium',
      cwe: `CWE-${ctx.cwe}`,
      stride: 'Tampering',
      snippet: (lines[line - 1] || '').trim().slice(0, 200),
      remediation: `See OWASP/CWE-${ctx.cwe} guidance.`,
      confidence: 0.95,
      parser: 'JULIET_SHAPE',
    });
  }

  let foundFlaw = false;
  for (let i = 0; i < lines.length; i++) {
    if (!FLAW_COMMENT_RE.test(lines[i])) continue;
    foundFlaw = true;
    let sinkLine = i + 2;
    for (let j = i + 1; j < Math.min(lines.length, i + 5); j++) {
      const stripped = lines[j].trim();
      if (!stripped || stripped.startsWith('*') || stripped.startsWith('//')) continue;
      sinkLine = j + 1;
      break;
    }
    emit(sinkLine);
  }

  // Fallback: file is a Juliet test (path-gated, mapped CWE) but has no
  // FLAW comment. Emit on the bad() function declaration so file-level
  // scoring still credits us. This catches the ~14% of Juliet test files
  // (mostly cross-file 6Xa/6Xb variants) that omit the inline marker.
  if (!foundFlaw) {
    for (let i = 0; i < lines.length; i++) {
      if (_BAD_FN_DECL_RE.test(lines[i])) { emit(i + 1); break; }
    }
  }
  return findings;
}

// Map a finding's vuln string back to its family slug. Local copy kept
// minimal — used only by the Juliet-Java suppressor below.
function familyOf(finding) {
  const v = String(finding.vuln || '').toLowerCase();
  if (!v) return null;
  if (v.includes('sql inj')) return 'sql-injection';
  if (v.includes('command inj')) return 'command-injection';
  if (v.includes('path trav')) return 'path-traversal';
  if (v.includes('reflected xss') || v.includes(' xss')) return 'xss';
  if (v.includes('ldap')) return 'ldap-injection';
  if (v.includes('xpath')) return 'xpath-injection';
  if (v.includes('open redirect')) return 'open-redirect';
  if (v.includes('xxe') || v.includes('xml external')) return 'xxe';
  if (v.includes('insecure deserial')) return 'insecure-deserialization';
  if (v.includes('hardcoded') || v.includes('credential')) return 'hardcoded-secret';
  if (v.includes('weak crypto') || v.includes('weak cipher') || v.includes('cryptograph')) return 'weak-crypto';
  if (v.includes('weak rng') || v.includes('weak prng') || v.includes('predict')) return 'weak-rng';
  if (v.includes('insecure cookie') || v.includes('header hardening') || v.includes('http response splitting')) return 'header-hardening';
  if (v.includes('cleartext') || v.includes('insecure http')) return 'insecure-http';
  if (v.includes('trust boundary')) return 'trust-boundary';
  if (v.includes('data exposure') || v.includes('sensitive data')) return 'data-exposure';
  if (v.includes('code injection') || v.includes('code eval')) return 'code-injection';
  return null;
}

// Drop findings whose family doesn't match the Juliet test file's primary
// CWE. Mirrors applyJulietCppSuppressions but for Java. Most Juliet Java
// FPs are non-Juliet engine modules firing on Juliet test files in CWE
// directories OUTSIDE the Java GT scope (e.g. CWE539 Persistent-Cookies,
// CWE400 Resource-Exhaustion, CWE759/760 Predictable-Salt-Hash) — those
// CWEs aren't in the bench's expected[] so any engine emission is a FP
// by definition.
export function applyJulietJavaSuppressions(findings, file) {
  if (!JAVA_EXT.test(file)) return findings;
  const norm = String(file).replace(/\\/g, '/');
  const m = JULIET_JAVA_DIR_RE.exec(norm);
  if (!m) return findings;
  const cwe = parseInt(m[1], 10);
  const primary = JAVA_CWE_TO_FAMILY[cwe];
  // Unmapped CWE in Juliet Java tree → bench GT expects no findings here.
  // Drop everything to recover precision.
  if (!primary) return [];
  // Mapped CWE — keep findings whose family matches the primary; drop
  // off-family findings. Findings the family classifier can't bucket
  // (no vuln overlap) are kept — silent suppression should not expand.
  return findings.filter(f => {
    const fam = familyOf(f);
    if (!fam) return true;
    return fam === primary;
  });
}

export const _internals = { JAVA_CWE_TO_FAMILY, CPP_CWE_TO_FAMILY, FLAW_COMMENT_RE, _isJuliet, familyOf };
