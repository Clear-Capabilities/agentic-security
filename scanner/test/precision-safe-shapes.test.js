// Precision: safe code shapes that several detectors reported as vulnerable.
//
// Each case is a fixture pair under test/fixtures/<case>/: `vulnerable/` holds
// the unsafe shape (the finding must still fire) and `clean/` the safe shape
// the detector used to misread (it must stay silent). Both sides go through a
// real deep scan and the report layer's normalizeFindings, the same view every
// consumer reads.
//
//   java-sql-literal-concat      a query concatenated from string literals only is one constant
//   wrong-context-fixed-scheme   an HTML-encoded value after a literal prefix that fixes the URL scheme
//   spec-drift-escaper-replace   an escaper whose body escapes with `.replace(/&/g, ...)`
//   xss-innerhtml-static         `el.innerHTML = ''` writes no value
//   xxe-identity-transform       an identity transform of an already-parsed DOMSource parses nothing
//   ssrf-metadata-guard-constant a metadata host in a blocklist or a comparison constant is the guard
//   ssrf-local-url-guard         a project URL validator in a try whose every handler raises
//   idor-keyword-arg-name        `pk=` in a call is the callee's parameter, not a variable read
//   redos-python-no-literal      Python has no `/.../` regex literal

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { normalizeFindings } from '../src/report/index.js';
import { withStateWritesDisabled } from '../src/posture/state-dir.js';
import { guardDominatesSink } from '../src/dataflow/guard-dominance.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (...p) => path.join(__dirname, 'fixtures', ...p);

async function findingsOf(dir, cwe) {
  const prevDeep = process.env.AGENTIC_SECURITY_DEEP;
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await withStateWritesDisabled(() => runScan(dir));
    return normalizeFindings(scan).filter((f) => f.cwe === cwe);
  } finally {
    if (prevDeep === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = prevDeep;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI; else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
  }
}

const CASES = [
  ['java-sql-literal-concat', 'CWE-89', /SQL Injection/],
  ['wrong-context-fixed-scheme', 'CWE-79', /Wrong-context output encoding/],
  ['spec-drift-escaper-replace', 'CWE-79', /Spec drift/],
  ['xss-innerhtml-static', 'CWE-79', /^XSS$/],
  ['xxe-identity-transform', 'CWE-611', /TransformerFactory/],
  ['ssrf-metadata-guard-constant', 'CWE-918', /instance-metadata/],
  ['ssrf-local-url-guard', 'CWE-918', /SSRF/],
  ['idor-keyword-arg-name', 'CWE-639', /IDOR/],
  ['redos-python-no-literal', 'CWE-1333', /ReDoS/],
];

for (const [name, cwe, vulnRe] of CASES) {
  test(`${name}: the unsafe shape still fires`, async () => {
    const hits = (await findingsOf(FIX(name, 'vulnerable'), cwe)).filter((f) => vulnRe.test(f.vuln));
    assert.ok(hits.length > 0, `expected a ${cwe} finding matching ${vulnRe} on ${name}/vulnerable`);
  });
  test(`${name}: the safe shape is silent`, async () => {
    const hits = await findingsOf(FIX(name, 'clean'), cwe);
    assert.deepEqual(hits.map((f) => `${f.file}:${f.line} ${f.vuln}`), [], `expected no ${cwe} finding on ${name}/clean`);
  });
}

// The try/except dominance rule, judged directly on the near misses that must keep the finding.
const py = (s) => s.split('\n');
test('guard dominance: a validator in a try whose every handler raises dominates a later sink', () => {
  const lines = py('def f(u):\n    try:\n        check_url(u)\n    except PolicyError as e:\n        raise ValueError(e)\n    fetch(u)');
  assert.equal(guardDominatesSink({ lines, guardIdx: 2, sinkIdx: 5, file: 'a.py' }).dominates, true);
});
test('guard dominance: a handler that swallows the error does not dominate', () => {
  const lines = py('def f(u):\n    try:\n        check_url(u)\n    except PolicyError:\n        log(u)\n    fetch(u)');
  assert.equal(guardDominatesSink({ lines, guardIdx: 2, sinkIdx: 5, file: 'a.py' }).dominates, false);
});
test('guard dominance: one swallowing handler among raising ones does not dominate', () => {
  const lines = py('def f(u):\n    try:\n        check_url(u)\n    except PolicyError as e:\n        raise ValueError(e)\n    except Exception:\n        pass\n    fetch(u)');
  assert.equal(guardDominatesSink({ lines, guardIdx: 2, sinkIdx: 7, file: 'a.py' }).dominates, false);
});
test('guard dominance: a try with an else clause does not dominate', () => {
  const lines = py('def f(u):\n    try:\n        check_url(u)\n    except PolicyError as e:\n        raise ValueError(e)\n    else:\n        fetch(u)\n    fetch(u)');
  assert.equal(guardDominatesSink({ lines, guardIdx: 2, sinkIdx: 7, file: 'a.py' }).dominates, false);
});
test('guard dominance: a sink in a different function after the try does not inherit it', () => {
  const lines = py('def f(u):\n    try:\n        check_url(u)\n    except PolicyError as e:\n        raise ValueError(e)\n\ndef g(u):\n    fetch(u)');
  assert.equal(guardDominatesSink({ lines, guardIdx: 2, sinkIdx: 7, file: 'a.py' }).dominates, false);
});
