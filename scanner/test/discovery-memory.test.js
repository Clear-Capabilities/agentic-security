// Cross-run discovery memory and multi-model consensus (PRD Phase 3, C4 + C2).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  memoryKey, loadMemory, saveMemory, rememberRun, previouslyRefuted,
  nextWavePlan, forgetRefuted, MEMORY_FILE,
} from '../src/discovery/memory.js';
import { parseEndpoints, consensusOf } from '../src/discovery/llm-invoke.js';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dmem-'));
const cand = (o = {}) => ({ file: 'a.js', line: 3, family: 'injection', ...o });

// ------------------------------------------------------------------ C4 keys
test('the memory key is location+family, not the location-fuzzy stableId', () => {
  // stableId deliberately ignores the line so an id survives code movement.
  // That is right for one scan's dedupe and corrosive as a permanent record:
  // distinct findings in one file would collapse into a single memory entry and
  // one refutation would silence all of them forever.
  assert.notEqual(memoryKey(cand({ line: 3 })), memoryKey(cand({ line: 99 })));
  assert.notEqual(memoryKey(cand({ family: 'injection' })), memoryKey(cand({ family: 'crypto' })));
  assert.equal(memoryKey(cand()), memoryKey(cand()));
});

// -------------------------------------------------------------- C4 verdicts
test('only a REFUTED verdict suppresses a later run', () => {
  // Same asymmetry judge.js applies to triage: a previously-fresh finding is
  // re-reported because it was never fixed.
  const m = rememberRun(null, { fresh: [cand({ line: 1 })], refutedCandidates: [cand({ line: 2 })] });
  assert.equal(previouslyRefuted(m, cand({ line: 2 })), true);
  assert.equal(previouslyRefuted(m, cand({ line: 1 })), false, 'a fresh finding must be re-reported');
  assert.equal(previouslyRefuted(m, cand({ line: 3 })), false);
});

test('rememberRun does not mutate the memory it was given', () => {
  const first = rememberRun(null, { fresh: [cand()] });
  const second = rememberRun(first, { refutedCandidates: [cand({ line: 9 })] });
  assert.equal(first.runs, 1);
  assert.equal(second.runs, 2);
  assert.equal(Object.keys(first.candidates).length, 1, 'the original must be untouched');
});

test('refuted verdicts can be forgotten, because a refutation is an opinion', () => {
  // Three prompts on one day is not a proof. A memory you cannot clear
  // eventually lies — after a model upgrade, or once a sanitiser is removed.
  const m = rememberRun(null, { fresh: [cand({ line: 1 })], refutedCandidates: [cand({ line: 2 })] });
  const cleared = forgetRefuted(m);
  assert.equal(previouslyRefuted(cleared, cand({ line: 2 })), false);
  assert.ok(cleared.candidates[memoryKey(cand({ line: 1 }))], 'non-refuted history survives');
});

// ------------------------------------------------------------ C4 durability
test('memory round-trips through disk', () => {
  const root = tmp();
  const m = rememberRun(null, { refutedCandidates: [cand()] });
  assert.equal(saveMemory(root, m), true);
  assert.equal(previouslyRefuted(loadMemory(root), cand()), true);
});

test('a corrupt memory degrades to remembering nothing, never to a crash', () => {
  const root = tmp();
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(root, MEMORY_FILE), '{ not json');
  const m = loadMemory(root);
  assert.equal(m.runs, 0);
  assert.equal(previouslyRefuted(m, cand()), false, 'a half-read ledger must never suppress anything');
});

test('a memory from an unrecognised schema is discarded whole', () => {
  const root = tmp();
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(root, MEMORY_FILE), JSON.stringify({ schema: 'something-else', candidates: { x: { verdict: 'refuted' } } }));
  assert.equal(loadMemory(root).runs, 0);
});

// ----------------------------------------------------------------- C4 plan
test('the next-wave plan names areas never successfully hunted', () => {
  const m = rememberRun(null, { areas: [{ id: 'a1', label: 'auth/', hunted: true }, { id: 'a2', label: 'billing/', hunted: false }] });
  const plan = nextWavePlan(m, [{ id: 'a1', label: 'auth/' }, { id: 'a2', label: 'billing/' }]);
  assert.deepEqual(plan.unhunted, ['billing/']);
  assert.match(plan.summary, /billing\//);
});

test('with everything hunted the plan says so rather than listing nothing', () => {
  const m = rememberRun(null, { areas: [{ id: 'a1', label: 'auth/', hunted: true }] });
  const plan = nextWavePlan(m, [{ id: 'a1', label: 'auth/' }]);
  assert.deepEqual(plan.unhunted, []);
  assert.match(plan.summary, /every focus area has been hunted/);
});

// ------------------------------------------------------------- C2 consensus
test('endpoint lists are split and de-duplicated', () => {
  // A repeated endpoint would vote twice and manufacture agreement.
  assert.deepEqual(parseEndpoints('http://a, http://b ,http://a'), ['http://a', 'http://b']);
  assert.deepEqual(parseEndpoints(''), []);
  assert.deepEqual(parseEndpoints(null), []);
});

test('consensus keeps the majority answer', () => {
  const r = consensusOf(['yes', 'yes', 'no']);
  assert.equal(r.value, 'yes');
  assert.equal(r.voters, 3);
  assert.ok(Math.abs(r.agreement - 2 / 3) < 1e-9);
});

test('a provider that failed is EXCLUDED from the vote, not counted as dissent', () => {
  // Identical rule to disprove.js's panel: an outage must never look like
  // disagreement.
  const r = consensusOf(['yes', null, undefined, '']);
  assert.equal(r.value, 'yes');
  assert.equal(r.voters, 1, 'only real answers count towards the denominator');
});

test('a tie resolves towards the first endpoint, deterministically', () => {
  // Arbitrary tie-breaking would make the whole pipeline non-reproducible, and
  // a caller who ordered their endpoints by trust should get that ordering.
  assert.equal(consensusOf(['a', 'b']).value, 'a');
  assert.equal(consensusOf(['b', 'a']).value, 'b');
});

test('no answers at all yields null rather than an invented one', () => {
  const r = consensusOf([null, null]);
  assert.equal(r.value, null);
  assert.equal(r.voters, 0);
});
