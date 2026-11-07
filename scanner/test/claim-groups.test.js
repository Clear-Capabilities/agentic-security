// PRD FR 05 / FR 07: equivalent detector claims are grouped under one primary without merging independent sinks, every grouped
// claim stays discoverable, and the candidate counts reconcile without double counting.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { groupEquivalentClaims, reconcileCounts } from '../src/llm-validator/claim-groups.js';
import { driftBetween } from '../src/posture/drift.js';

const f = (o) => ({ file: 'app.py', line: 10, cwe: 'CWE-502', severity: 'critical', vuln: 'x', ...o });

test('two detectors on one line and CWE become one result naming both', () => {
  const a = f({ id: 'a', stableId: 'sa', parser: 'REGEX', vuln: 'Model Load: pickle.load()' });
  const b = f({ id: 'b', stableId: 'sb', parser: 'PY-SAST', vuln: 'Insecure Deserialization' });
  const { kept, grouped, groups } = groupEquivalentClaims([a, b]);
  assert.equal(groups, 1);
  assert.equal(kept.length, 1);
  assert.equal(grouped.length, 1);
  assert.deepEqual(kept[0].claims.map((c) => c.parser).sort(), ['PY-SAST', 'REGEX']);
  assert.equal(grouped[0].groupedInto, kept[0].stableId);
});

test('the primary is the claim with a traced path, then the higher severity; severity is never changed', () => {
  const lo = f({ id: 'lo', parser: 'REGEX', severity: 'high' });
  const hi = f({ id: 'hi', parser: 'PHP', severity: 'critical' });
  const { kept } = groupEquivalentClaims([lo, hi]);
  assert.equal(kept[0].id, 'hi');
  assert.equal(lo.severity, 'high');
  const plain = f({ id: 'p', parser: 'REGEX' });
  const traced = f({ id: 't', parser: 'IR-TAINT', severity: 'medium', source: { line: 3 }, sink: { line: 10 } });
  assert.equal(groupEquivalentClaims([plain, traced]).kept[0].id, 't');
  // an IR-traced path outranks a lexically traced one at equal severity, whatever the ids
  const lexical = f({ id: 'a-regex', parser: 'REGEX', source: { line: 3 }, sink: { line: 10 } });
  const ir = f({ id: 'z-ir', parser: 'IR-TAINT', source: { line: 3 }, sink: { line: 10 } });
  assert.equal(groupEquivalentClaims([lexical, ir]).kept[0].id, 'z-ir');
  // a claim that locates the sink outranks a higher-severity claim that locates nothing
  const sinkOnly = f({ id: 's', parser: 'IR-TAINT', severity: 'high', sink: { line: 10 } });
  const bare = f({ id: 'b', parser: 'REGEX', severity: 'critical' });
  assert.equal(groupEquivalentClaims([bare, sinkOnly]).kept[0].id, 's');
});

test('claims that are not equivalent stay apart', () => {
  const cases = [
    [f({ id: 'a', parser: 'REGEX' }), f({ id: 'b', parser: 'REGEX' })],                                   // one detector, two claims
    [f({ id: 'a', parser: 'REGEX' }), f({ id: 'b', parser: 'PY-SAST', line: 11 })],                       // different line
    [f({ id: 'a', parser: 'REGEX' }), f({ id: 'b', parser: 'PY-SAST', cwe: 'CWE-94' })],                   // different weakness
    [f({ id: 'a', parser: 'REGEX' }), f({ id: 'b', parser: 'PY-SAST', file: 'b.py' })],                    // different file
    [f({ id: 'a', parser: 'IR-TAINT', sink: { line: 10 } }), f({ id: 'b', parser: 'MULTI-SINK', sink: { line: 12 } })], // independent sinks
    [f({ id: 'a', parser: 'REGEX', line: undefined }), f({ id: 'b', parser: 'PY-SAST', line: undefined })], // no line to anchor on
    [f({ id: 'a', parser: 'SCA', kind: 'sca' }), f({ id: 'b', parser: 'OSV', kind: 'sca' })],             // dependency findings
    [f({ id: 'a', parser: 'REGEX', kind: 'iac' }), f({ id: 'b', parser: 'CONTAINER-RUNTIME', kind: 'sast' })], // different report category
    [f({ id: 'a', parser: 'IR-TAINT' }), f({ id: 'b', parser: 'HS-RULES', family: 'llm-agent-chain', chain: [] })], // a chain is not its hop
  ];
  for (const pair of cases) {
    const r = groupEquivalentClaims(pair);
    assert.equal(r.kept.length, 2, JSON.stringify(pair.map((x) => x.id + ':' + x.parser)));
    assert.equal(r.grouped.length, 0);
  }
});

test('counts reconcile: raw equals grouped plus refuted plus every active disposition', () => {
  const r = reconcileCounts({ raw: 10, grouped: 2, refuted: 1, dispositionCounts: { 'needs-review': 4, unvalidated: 2, hardening: 1, refuted: 1 }, suppressed: 3 });
  assert.equal(r.deduplicated, 8);
  assert.equal(r.balanced, true);
  assert.equal(r.suppressedBeforeValidation, 3);
  assert.equal(reconcileCounts({ raw: 10, grouped: 2, refuted: 1, dispositionCounts: { 'needs-review': 4 } }).balanced, false);
});

test('drift: grouping or ungrouping a claim never reports it as fixed or new', () => {
  const a = f({ stableId: 'sa', parser: 'REGEX' });
  const b = f({ stableId: 'sb', parser: 'PY-SAST' });
  const before = { findings: [a, b] };
  const after = { findings: [a], groupedClaims: [b] };
  assert.equal(driftBetween(before, after).findings.removed.length, 0);
  assert.equal(driftBetween(after, before).findings.added.length, 0);
});
