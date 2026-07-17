// Addition #3 — Root-cause sweep with total-count accounting.
//
// Given CONFIRMED findings, sweep the whole codebase for sibling instances of
// the same root cause that no detector fired on, with honest accounting:
// found === candidates + mitigated (never silently drop a match).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sweepRootCauses, formatSweepLedger, _internals } from '../src/posture/root-cause-sweep.js';

test('sweepRootCauses: total-count accounting (found === candidates + mitigated)', () => {
  const findings = [
    { id: 'F1', file: 'origin.js', line: 5, confirmed: true, vuln: 'SQL Injection', cwe: 'CWE-89',
      source: { snippet: 'req.query.id' }, sink: { snippet: 'db.query(userInput)' } },
    // A second finding sitting at a sibling site — NOT confirmed, so it does
    // not generate its own sweep, but its location IS known → 'mitigated'.
    { id: 'F2', file: 'c.js', line: 9, confirmed: false, vuln: 'SQL Injection', cwe: 'CWE-89',
      sink: { snippet: 'db.query(z)' } },
  ];
  const fileContents = {
    'origin.js': 'a\nb\nc\nd\ndb.query(userInput)\n',   // db.query at line 5 — the origin
    'a.js': 'db.query(a)\n',                             // line 1 — candidate
    'b.js': 'foo();\ndb.query(b)\n',                     // line 2 — candidate
    'c.js': '1\n2\n3\n4\n5\n6\n7\n8\ndb.query(z)\n',     // line 9 — mitigated (F2 lives here)
  };

  const result = sweepRootCauses(findings, fileContents);
  assert.equal(result.sweeps.length, 1, 'only the confirmed finding sweeps');

  const s = result.sweeps[0];
  assert.equal(s.fromFindingId, 'F1');
  assert.equal(s.found, 3);
  assert.equal(s.candidates, 2);
  assert.equal(s.mitigated, 1);
  assert.equal(s.remaining, 2);
  assert.equal(s.remaining, s.candidates, 'remaining is exactly the unaccounted candidates');
  assert.equal(s.found, s.candidates + s.mitigated, 'accounting invariant');

  // origin site excluded from the sweep
  const originHit = s.instances.find(i => i.file === 'origin.js' && i.line === 5);
  assert.equal(originHit, undefined, 'origin site is excluded from found');

  // per-instance classification
  const byFile = Object.fromEntries(s.instances.map(i => [i.file, i.status]));
  assert.equal(byFile['a.js'], 'candidate');
  assert.equal(byFile['b.js'], 'candidate');
  assert.equal(byFile['c.js'], 'mitigated-or-known');

  // patterns reported
  assert.match(s.sinkPattern, /db\.query/);
  assert.ok(typeof s.sourcePattern === 'string' && s.sourcePattern.length > 0);

  // repo-wide totals
  assert.deepEqual(result.totals, { found: 3, candidates: 2, mitigated: 1 });
});

test('sweepRootCauses: accepts a Map for fileContents (as well as an object)', () => {
  const findings = [{ id: 'F1', file: 'origin.js', line: 1, confidenceTier: 'high',
    sink: { snippet: 'db.query(userInput)' } }];
  const fileContents = new Map([
    ['origin.js', 'db.query(userInput)\n'],  // origin — excluded
    ['x.js', 'db.query(y)\n'],               // candidate
  ]);
  const result = sweepRootCauses(findings, fileContents);
  assert.equal(result.sweeps.length, 1);
  assert.equal(result.sweeps[0].found, 1);
  assert.equal(result.sweeps[0].candidates, 1);
  assert.equal(result.sweeps[0].mitigated, 0);
  assert.equal(result.sweeps[0].found, result.sweeps[0].candidates + result.sweeps[0].mitigated);
});

test('structural matching treats db.query(a) and db.query(b) as the same shape', () => {
  const sa = _internals.sinkShapeOf('db.query(a)');
  const sb = _internals.sinkShapeOf('db.query(b)');
  assert.ok(sa && sb, 'both snippets produce a shape hash');
  assert.equal(sa, sb, 'db.query(a) and db.query(b) share a structural shape');

  // …but the literal callee anchor stops it matching an unrelated same-shape call.
  const pat = _internals.deriveSinkPattern({ sink: { snippet: 'db.query(userInput)' } });
  assert.equal(_internals.matchLine(pat, '  const r = db.query(anything);'), true, 'matches embedded call');
  assert.equal(_internals.matchLine(pat, 'console.log(x)'), false, 'db.query anchor rejects console.log');
});

test('formatSweepLedger renders a per-sweep line', () => {
  const result = { sweeps: [{ found: 20, candidates: 3, mitigated: 17 }], totals: {} };
  assert.equal(formatSweepLedger(result), 'root-cause sweep: 20 found, 3 candidate, 17 mitigated');

  const two = { sweeps: [
    { found: 3, candidates: 2, mitigated: 1 },
    { found: 1, candidates: 0, mitigated: 1 },
  ], totals: {} };
  assert.equal(
    formatSweepLedger(two),
    'root-cause sweep: 3 found, 2 candidate, 1 mitigated\nroot-cause sweep: 1 found, 0 candidate, 1 mitigated',
  );
});

test('confirmedOnly gate: unconfirmed does not sweep by default; confirmedOnly:false sweeps all', () => {
  const findings = [{ id: 'U', file: 'o.js', line: 1, sink: { snippet: 'db.query(userInput)' } }]; // no confirm fields
  const fc = { 'o.js': 'db.query(userInput)\n', 'p.js': 'db.query(p)\n' };
  assert.equal(sweepRootCauses(findings, fc).sweeps.length, 0, 'default: not confirmed → no sweep');
  const all = sweepRootCauses(findings, fc, { confirmedOnly: false });
  assert.equal(all.sweeps.length, 1, 'confirmedOnly:false → sweep all');
  assert.equal(all.sweeps[0].found, 1);
});

test('sweepRootCauses does not throw on garbage input', () => {
  assert.doesNotThrow(() => sweepRootCauses(null, null));
  assert.doesNotThrow(() => sweepRootCauses([null, {}, undefined], {}));
  assert.doesNotThrow(() => sweepRootCauses([{ id: 'x', confirmed: true }], { 'a.js': null }));
  assert.equal(formatSweepLedger(null), '');
  assert.equal(formatSweepLedger({}), '');
});
