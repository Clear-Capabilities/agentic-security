// R7 — adversarial verification with ENFORCED SEPARATION.
//
// The property under test: a verifier must be structurally unable to
// rubber-stamp a finding it produced itself. Plus: recording a verdict is
// recall-preserving — a `refuted` verdict never deletes the finding and never
// touches severity (same precedent as falsification.js / dataflow/proof-gate.js).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  recordProducer,
  assertSeparation,
  recordVerdict,
  consensusOf,
  producerIdOf,
  VERIFICATION_VERDICTS,
  VERIFIER_FALSIFICATION,
} from '../src/posture/verification-separation.js';
import { annotateFalsification } from '../src/posture/falsification.js';

function mkFinding(over = {}) {
  return {
    id: 'SQLI-1',
    severity: 'high',
    file: 'app.js',
    line: 12,
    vuln: 'SQL Injection',
    cwe: 'CWE-89',
    parser: 'IR-TAINT',
    family: 'injection',
    ...over,
  };
}

// ── separation, both directions ─────────────────────────────────────────────

test('assertSeparation refuses when the verifier is the producer', () => {
  const f = mkFinding();
  recordProducer(f, 'detector:IR-TAINT');
  const res = assertSeparation(f, 'detector:IR-TAINT');
  assert.equal(res.ok, false);
  assert.equal(res.refused, true);
  assert.match(res.reason, /producer/i);
});

test('assertSeparation permits when the verifier differs from the producer', () => {
  const f = mkFinding();
  recordProducer(f, 'detector:IR-TAINT');
  const res = assertSeparation(f, 'verifier:falsification');
  assert.equal(res.ok, true);
  assert.equal(res.producer, 'detector:IR-TAINT');
});

test('assertSeparation fails closed when no producer was recorded', () => {
  const res = assertSeparation(mkFinding(), 'verifier:falsification');
  assert.equal(res.ok, false);
  assert.match(res.reason, /no producer/i);
});

test('the producer stamp is write-once — it cannot be re-stamped to fake separation', () => {
  const f = mkFinding();
  recordProducer(f, 'detector:IR-TAINT');
  const again = recordProducer(f, 'verifier:falsification');
  assert.equal(again.ok, false);
  assert.equal(f.verification.producer, 'detector:IR-TAINT');
  assert.equal(assertSeparation(f, 'detector:IR-TAINT').ok, false);
});

test('recordVerdict refuses a self-verdict and records nothing', () => {
  const f = mkFinding();
  recordProducer(f, 'detector:IR-TAINT');
  const res = recordVerdict(f, {
    verifierId: 'detector:IR-TAINT', lens: 'control-flow', verdict: 'upheld', reason: 'mine',
  });
  assert.equal(res.ok, false);
  assert.equal(f.verification.verdicts.length, 0);
  assert.equal(consensusOf(f).verdict, 'undecided');
});

test('recordVerdict accepts an independent verifier', () => {
  const f = mkFinding();
  recordProducer(f, 'detector:IR-TAINT');
  const res = recordVerdict(f, {
    verifierId: 'verifier:falsification', lens: 'control-flow', verdict: 'refuted', reason: 'control on path',
  });
  assert.equal(res.ok, true);
  assert.equal(f.verification.verdicts.length, 1);
  assert.equal(f.verification.verdicts[0].lens, 'control-flow');
});

test('an unknown verdict value is refused', () => {
  const f = mkFinding();
  recordProducer(f, 'detector:IR-TAINT');
  const res = recordVerdict(f, { verifierId: 'v:x', lens: 'reachability', verdict: 'maybe' });
  assert.equal(res.ok, false);
  assert.equal(f.verification.verdicts.length, 0);
  assert.deepEqual(VERIFICATION_VERDICTS, ['upheld', 'refuted', 'undecided']);
});

test('one verifier gets one vote per lens — a re-vote replaces, never stuffs', () => {
  const f = mkFinding();
  recordProducer(f, 'detector:IR-TAINT');
  recordVerdict(f, { verifierId: 'v:a', lens: 'reachability', verdict: 'upheld' });
  recordVerdict(f, { verifierId: 'v:a', lens: 'reachability', verdict: 'refuted' });
  assert.equal(f.verification.verdicts.length, 1);
  assert.equal(f.verification.verdicts[0].verdict, 'refuted');
});

// ── recall preservation ─────────────────────────────────────────────────────

test('a refuted verdict neither deletes the finding nor changes its severity', () => {
  const f = mkFinding();
  const before = JSON.stringify({ ...f });
  recordProducer(f, 'detector:IR-TAINT');
  recordVerdict(f, { verifierId: 'v:a', lens: 'control-flow', verdict: 'refuted' });
  recordVerdict(f, { verifierId: 'v:b', lens: 'data-shape', verdict: 'refuted' });
  assert.equal(f.severity, 'high');
  assert.equal(consensusOf(f).verdict, 'refuted');
  // every original field survives untouched
  const after = { ...f };
  delete after.verification;
  assert.equal(JSON.stringify(after), before);
});

// ── consensus ───────────────────────────────────────────────────────────────

test('consensusOf takes the majority across lenses', () => {
  const f = mkFinding();
  recordProducer(f, 'detector:IR-TAINT');
  recordVerdict(f, { verifierId: 'v:a', lens: 'reachability', verdict: 'upheld' });
  recordVerdict(f, { verifierId: 'v:b', lens: 'control-flow', verdict: 'upheld' });
  recordVerdict(f, { verifierId: 'v:c', lens: 'data-shape', verdict: 'refuted' });
  const c = consensusOf(f);
  assert.equal(c.verdict, 'upheld');
  assert.equal(c.upheld, 2);
  assert.equal(c.refuted, 1);
  assert.equal(c.undecided, 0);
  assert.deepEqual(c.lenses, ['control-flow', 'data-shape', 'reachability']);
});

test('consensusOf returns undecided on a tie and on no verdicts', () => {
  const f = mkFinding();
  recordProducer(f, 'detector:IR-TAINT');
  assert.equal(consensusOf(f).verdict, 'undecided');
  assert.deepEqual(consensusOf(f).lenses, []);
  recordVerdict(f, { verifierId: 'v:a', lens: 'reachability', verdict: 'upheld' });
  recordVerdict(f, { verifierId: 'v:b', lens: 'control-flow', verdict: 'refuted' });
  assert.equal(consensusOf(f).verdict, 'undecided');
  assert.equal(consensusOf({}).verdict, 'undecided');
});

test('producerIdOf namespaces the detector so it can never collide with a verifier id', () => {
  assert.equal(producerIdOf(mkFinding()), 'detector:IR-TAINT');
  assert.equal(producerIdOf({}), 'detector:unknown');
  assert.ok(VERIFIER_FALSIFICATION.startsWith('verifier:'));
});

// ── wiring: the falsification pass verifies as a party separate from the detector

test('annotateFalsification records itself as an independent verifier', () => {
  const findings = [mkFinding({
    source: { line: 1, snippet: "const q = req.query.id" },
    sink: { line: 2, snippet: "db.query('SELECT ' + q)" },
  })];
  annotateFalsification(findings, { 'app.js': "const q = req.query.id\ndb.query('SELECT ' + q)\n" });
  const f = findings[0];
  assert.equal(f.verification.producer, 'detector:IR-TAINT');
  const v = f.verification.verdicts.find(x => x.verifierId === VERIFIER_FALSIFICATION);
  assert.ok(v, 'falsification pass must record a verdict');
  assert.notEqual(v.verifierId, f.verification.producer);
  assert.equal(v.lens, 'control-flow');
  assert.equal(v.verdict, 'upheld'); // survived falsification
  assert.equal(f.verification.consensus.verdict, 'upheld');
  assert.equal(f.severity, 'high');  // never severity-touched
});

test('a falsified (blocked) finding is refuted but kept, unremoved and unchanged in severity', () => {
  const src = "const q = parseInt(req.query.id, 10)\ndb.query('SELECT ' + q)\n";
  const findings = [mkFinding({
    source: { line: 1, snippet: 'const q = parseInt(req.query.id, 10)' },
    sink: { line: 2, snippet: "db.query('SELECT ' + q)" },
  })];
  annotateFalsification(findings, { 'app.js': src });
  const f = findings[0];
  assert.equal(findings.length, 1);
  assert.equal(f.severity, 'high');
  if (f.falsification.verdict === 'blocked') {
    assert.equal(f.verification.consensus.verdict, 'refuted');
    assert.equal(f.quarantined, true);
  }
});

test('a second, differently-lensed verifier makes a contested finding visible', () => {
  const findings = [mkFinding({
    source: { line: 1, snippet: 'const q = req.query.id' },
    sink: { line: 2, snippet: "db.query('SELECT ' + q)" },
  })];
  annotateFalsification(findings, { 'app.js': "const q = req.query.id\ndb.query('SELECT ' + q)\n" }, {
    llmReview: () => ({ verdict: 'refuted', reason: 'argued the opposing case' }),
  });
  const f = findings[0];
  assert.equal(f.verification.verdicts.length, 2);
  assert.equal(f.verification.consensus.verdict, 'undecided'); // 1 upheld vs 1 refuted
  assert.equal(f.verification.consensus.lenses.length, 2);
});

test('annotateFalsification never throws on malformed input', () => {
  assert.doesNotThrow(() => annotateFalsification(null));
  assert.doesNotThrow(() => annotateFalsification([null, {}, mkFinding()], null));
});
