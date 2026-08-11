// Typed sanitizer lattice — the taint engine must observe sanitizers ON THE
// FLOW and label a finding only when the sanitizer's family covers the
// finding's threat class.
//
// Before this, `dataflow/catalog.js`'s 65 sanitizer entries had no effect on
// taint at all: `dataflow/engine.js` kept only `kind === 'sink'` hits, so
// `applySanitizerGate` was handed an always-empty `sanitizersOnPath` and was
// inert. Every correctly-sanitized flow was reported at full confidence.
//
// The wrong-family case is the reason this is a LATTICE and not a boolean. A
// blanket "any sanitizer kills the taint" rule scores well on benchmarks and
// silently drops real SQL injection when the code applied an HTML escaper. The
// three fixtures here are identical except for the sanitizer, so the only thing
// that can move the verdict is the family match.
//
// Recall-preserving, same precedent as falsification.js / proof-gate.js: the
// gate LABELS, it never deletes a finding and never touches severity.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.join(__dirname, 'fixtures', name);

async function deepScan(dir) {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const _prevInCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    if (_prevInCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = _prevInCi;
  }
}

const sqlTaintFindings = (fs) =>
  fs.filter(f => f.parser === 'IR-TAINT' && /sql/i.test(`${f.vuln} ${f.cwe}`));

const xssTaintFindings = (fs) =>
  fs.filter(f => f.parser === 'IR-TAINT' && /CWE-79/.test(`${f.cwe}`));

test('a matching-family sanitizer on the flow labels the finding as sanitized', async () => {
  const found = xssTaintFindings(await deepScan(FIX('sanitizer-typed/right-family')));
  assert.ok(found.length, 'precondition: the XSS taint finding must fire at all');
  const labelled = found.filter(f => f.sanitized === true);
  assert.ok(labelled.length,
    `expected sanitized:true from escapeHtml (appliesTo 'xss') on an XSS sink, got: ` +
    found.map(f => `${f.vuln}(sanitized=${f.sanitized})`).join(', '));
  assert.equal(labelled[0].sanitizerProof.family, 'xss');
  assert.ok(labelled[0].sanitizerProof.sanitizers.includes('escapeHtml'));
});

test('a wrong-family sanitizer does NOT label a SQL finding as sanitized', async () => {
  const found = sqlTaintFindings(await deepScan(FIX('sanitizer-typed/wrong-family')));
  assert.ok(found.length, 'precondition: the SQL taint finding must fire at all');
  for (const f of found) {
    assert.notEqual(f.sanitized, true,
      `escapeHtml neutralizes XSS, not SQL — labelling this sanitized would hide a real SQLi`);
  }
});

test('no sanitizer on the flow leaves the finding unlabelled', async () => {
  const found = sqlTaintFindings(await deepScan(FIX('sanitizer-typed/no-sanitizer')));
  assert.ok(found.length, 'precondition: the SQL taint finding must fire at all');
  for (const f of found) assert.notEqual(f.sanitized, true);
});

test('the gate is recall-preserving: a sanitized finding is still reported', async () => {
  const sanitized = xssTaintFindings(await deepScan(FIX('sanitizer-typed/right-family')));
  assert.ok(sanitized.length > 0,
    'labelling must not delete findings — demotion is the proof gate\'s job, not deletion');
  for (const f of sanitized) {
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(f.severity));
  }
});
