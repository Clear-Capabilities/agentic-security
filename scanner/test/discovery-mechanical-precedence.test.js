// GA-06 §4 (0.195.31): a model opinion stays separate from mechanical evidence. Pinned in both directions:
//   - the refutation panel never removes a taint-confirmed candidate (the votes are kept, the refutation is marked overridden,
//     the severity is untouched, and memory does not remember it as refuted), while an unconfirmed one is still removed;
//   - a hunt candidate needs a real citation: a file the hunter was shown and a line inside it; anything else is discarded and
//     counted, never scored;
//   - the validator's strong set covers every dataflow engine and an oracle-confirmed record, and a refused reject keeps the
//     model's own verdict in its own field.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { disprovePanel } from '../src/discovery/disprove.js';
import { rememberRun, previouslyRefuted } from '../src/discovery/memory.js';
import { parseCandidates, runHunter } from '../src/discovery/hunter.js';
import { applyValidatorVerdicts, _stronglyProvenanced } from '../src/llm-validator/index.js';

const refuteAll = async () => JSON.stringify({ refuted: true, reason: 'the panel says no' });
const candidate = (tier, extra = {}) => ({ id: `c-${tier}`, file: 'a.js', line: 3, title: 't', family: 'command-injection', cwe: 'CWE-78', severity: tier === 'taint-confirmed' ? 'high' : 'low', confirmation: { tier }, ...extra });

test('the panel removes an unconfirmed candidate on a refuting majority, and keeps a taint-confirmed one as contested with the votes and severity intact', async () => {
  const { survivors, refuted } = await disprovePanel([candidate('taint-confirmed'), candidate('unconfirmed'), candidate('sink-adjacent')], { llmInvoke: refuteAll });
  assert.deepEqual(refuted.map((c) => c.confirmation.tier).sort(), ['sink-adjacent', 'unconfirmed']);
  assert.equal(survivors.length, 1);
  const kept = survivors[0];
  assert.equal(kept.confirmation.tier, 'taint-confirmed');
  assert.equal(kept.severity, 'high', 'severity comes from the tier and is untouched');
  assert.equal(kept.refutation.refuted, true, 'the model majority is recorded as it was');
  assert.equal(kept.refutation.refuteCount, 3);
  assert.equal(kept.refutation.overridden, true);
  assert.equal(kept.refutation.overriddenBy, 'taint-confirmed');
  assert.equal(refuted.some((c) => c.refutation.overridden), false);
});

test('a contested confirmed candidate is not remembered as refuted, so the next run examines it again', async () => {
  // memory is keyed by location and family, so the two candidates sit on different lines here
  const { survivors, refuted } = await disprovePanel([candidate('taint-confirmed'), candidate('unconfirmed', { line: 7 })], { llmInvoke: refuteAll });
  const memory = rememberRun(null, { fresh: survivors, refutedCandidates: refuted, areas: [] });
  assert.equal(previouslyRefuted(memory, candidate('unconfirmed', { line: 7 })), true);
  assert.equal(previouslyRefuted(memory, candidate('taint-confirmed')), false);
});

test('a silent panel still never refutes, and never marks anything overridden', async () => {
  const { survivors, refuted } = await disprovePanel([candidate('taint-confirmed'), candidate('unconfirmed')], { llmInvoke: async () => 'no json here' });
  assert.equal(refuted.length, 0);
  assert.equal(survivors.length, 2);
  assert.ok(survivors.every((c) => c.refutation.undecided === true && !c.refutation.overridden));
});

const area = { id: 'area-1', label: 'a', files: ['src/a.js', 'src/b.js'] };
const lens = { key: 'injection', title: 'Injection', family: 'command-injection', cwe: 'CWE-78' };
const contents = { 'src/a.js': 'l1\nl2\nl3\n', 'src/b.js': 'x\n' };

test('a hunt candidate must cite a file the hunter was shown and a line inside it; the rest is discarded and counted', async () => {
  const reply = JSON.stringify({ candidates: [
    { file: 'src/a.js', line: 3, title: 'real' },
    { file: './src/b.js', line: 1, title: 'real with ./' },
    { file: 'src/a.js', line: 9, title: 'line past end' },
    { file: 'src/zzz.js', line: 1, title: 'file outside the area' },
    { file: '/etc/passwd', line: 1, title: 'absolute path outside the area' },
    { line: 2, title: 'no file' },
  ] });
  const parsed = parseCandidates(reply, area, lens, { fileContents: contents });
  assert.deepEqual(parsed.map((c) => [c.file, c.line]), [['src/a.js', 3], ['src/b.js', 1]]);
  const run = await runHunter(area, lens, { fileContents: contents, callGraph: { nodes: [], edges: [] } }, { llmInvoke: async () => reply });
  assert.equal(run.degraded, false);
  assert.equal(run.candidates.length, 2);
  assert.equal(run.discarded, 4, 'four proposals were discarded');
  assert.equal(run.citationsDiscarded, 3, 'three of them had a location that did not resolve; the one with no location is counted apart');
  const result = run.transcript.find((e) => e.phase === 'result');
  assert.equal(result.citationsDiscarded, 3);
});

test('a file in the area whose contents the run does not hold is accepted on the file alone (the line cannot be checked), never invented', () => {
  const parsed = parseCandidates(JSON.stringify({ candidates: [{ file: 'src/a.js', line: 400 }, { file: 'src/c.js', line: 1 }] }), area, lens, { fileContents: {} });
  assert.deepEqual(parsed.map((c) => [c.file, c.line]), [['src/a.js', 400]]);
});

test('validator: a reject on any dataflow engine or an oracle-confirmed record is refused with the model verdict kept, and an ordinary reject is retained for review', () => {
  const strong = [
    { id: 'a', parser: 'IR-TAINT', severity: 'high' },
    { id: 'b', parser: 'MULTI-SINK', severity: 'high' },
    { id: 'c', parser: 'CPP_DATAFLOW', severity: 'high' },
    { id: 'd', parser: 'REGEX', severity: 'high', proofTier: 'execution-proven' },
    { id: 'e', parser: 'REGEX', severity: 'medium', verificationRecord: { outcome: 'confirmed' } },
    { id: 'f', parser: 'REGEX', severity: 'medium', verificationView: { state: 'confirmed' } },
  ];
  for (const f of strong) assert.equal(_stronglyProvenanced(f), true, f.id);
  assert.equal(_stronglyProvenanced({ parser: 'REGEX', verificationRecord: { outcome: 'refuted' } }), false);
  const findings = [...strong.map((f) => ({ ...f, validator_verdict: 'reject' })), { id: 'g', parser: 'REGEX', severity: 'low', validator_verdict: 'reject' }];
  const { kept, dropped } = applyValidatorVerdicts(findings.map((f) => ({ ...f })), { legacyRejectSuppress: false });
  assert.deepEqual(kept.map((f) => f.id), ['a', 'b', 'c', 'd', 'e', 'f', 'g']);
  assert.deepEqual(dropped, []);
  const ordinary = kept.find((f) => f.id === 'g');
  assert.equal(ordinary.validator_reject_retained, true, 'a model opinion alone does not remove a finding');
  assert.equal(ordinary.validator_model_verdict, undefined);
  for (const f of kept.filter((k) => k.id !== 'g')) {
    assert.equal(f.validator_verdict, 'escalate');
    assert.equal(f.validator_model_verdict, 'reject', 'the opinion is kept in its own field');
    assert.match(f.validator_reject_refused, /strong provenance/);
    assert.equal(f.severity, strong.find((s) => s.id === f.id).severity, 'severity untouched');
  }
  const legacy = applyValidatorVerdicts(findings.map((f) => ({ ...f })), { legacyRejectSuppress: true });
  assert.deepEqual(legacy.dropped.map((f) => f.id), ['g'], 'the opt-in legacy mode still suppresses an ordinary reject');
  assert.equal(legacy.dropped[0].validator_model_verdict, undefined);
});
