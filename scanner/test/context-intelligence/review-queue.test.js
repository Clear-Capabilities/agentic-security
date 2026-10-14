import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tempProject, cleanup, build, reviewWith } from './helpers.js';
import { scriptedReader } from '../../src/context-intelligence/evaluation/scripted-reader.js';
import { reviewsToCandidates } from '../../src/context-intelligence/candidates.js';

function candidatesOf(run) {
  const records = [];
  for (const [, res] of run.result.results) {
    if (res.state === 'succeeded' && res.review) { const lj = run.loadJob(res.job); records.push({ review: res.review, entrypoints: lj.entrypoints.map(e => ({ id: e.id, label: e.label })), pack: lj.pack }); }
  }
  return reviewsToCandidates(records);
}

test('a verified review of the vulnerable variant yields a candidate with citations that resolve', async () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    const run = await reviewWith(dir, scriptedReader());
    assert.equal(run.result.coverage.missingCoverage, 0);
    const cands = candidatesOf(run);
    assert.equal(cands.length, 1);
    assert.match(cands[0].file, /app\.js$/);
  } finally { cleanup(dir); }
});

test('the guarded variant produces no candidate', async () => {
  const dir = tempProject('eval/corpus/c01/b');
  try {
    const run = await reviewWith(dir, scriptedReader());
    assert.equal(candidatesOf(run).length, 0);
  } finally { cleanup(dir); }
});

test('a second run over unchanged context is served from the cache with zero model calls', async () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    let calls = 0;
    const inner = scriptedReader();
    const counting = async (p) => { calls++; return inner(p); };
    const built = await build(dir);
    await reviewWith(dir, counting, { built });
    const first = calls;
    assert.ok(first > 0);
    const again = await reviewWith(dir, counting, { built });
    assert.equal(calls, first, 'no new model calls');
    assert.ok(again.result.coverage.cached >= 1);
  } finally { cleanup(dir); }
});

test('a fabricated citation never becomes a candidate', async () => {
  const dir = tempProject('eval/corpus/c01/b');
  try {
    const liar = async () => JSON.stringify({ evidence: [{ role: 'data-access', file: 'src/app.js', startLine: 9000, endLine: 9001, claim: 'invented' }], observedMitigations: [], attackerControl: ['id'], uncertainties: [], likelihood: 'high', conclusion: 'potential_issue', invariant: 'x', narrative: 'invented' });
    const run = await reviewWith(dir, liar);
    assert.equal(candidatesOf(run).length, 0);
  } finally { cleanup(dir); }
});

test('model-supplied severity and unknown fields are ignored', async () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    const inner = scriptedReader();
    const sneaky = async (p) => { const o = JSON.parse(await inner(p)); o.severity = 'critical'; o.confirmed = true; o.cwe = 'CWE-0'; return JSON.stringify(o); };
    const run = await reviewWith(dir, sneaky);
    const cands = candidatesOf(run);
    assert.equal(cands.length, 1);
    assert.equal(cands[0].severity, undefined);
    assert.notEqual(cands[0].cwe, 'CWE-0');
  } finally { cleanup(dir); }
});

test('a transient failure is retried; a permanent failure is reported as missing coverage, not a clean result', async () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    const inner = scriptedReader();
    let n = 0;
    const flaky = async (p) => { n++; if (n === 1) throw new Error('503 service unavailable'); return inner(p); };
    const run = await reviewWith(dir, flaky);
    assert.equal(run.result.coverage.succeeded, run.jobs.length);
    assert.ok(n >= 2);
  } finally { cleanup(dir); }
  const dir2 = tempProject('eval/corpus/c01/a');
  try {
    const broken = async () => { throw new Error('invalid request body'); };
    const run = await reviewWith(dir2, broken);
    assert.equal(run.result.coverage.succeeded, 0);
    assert.ok(run.result.coverage.missingCoverage > 0);
    assert.equal(candidatesOf(run).length, 0);
  } finally { cleanup(dir2); }
});

test('unparseable model output does not succeed', async () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    const run = await reviewWith(dir, async () => 'I think this is fine.');
    assert.equal(run.result.coverage.succeeded, 0);
    assert.ok(run.result.coverage.missingCoverage > 0);
  } finally { cleanup(dir); }
});

test('the call budget stops the run and says so', async () => {
  const dir = tempProject('js-app');
  try {
    const run = await reviewWith(dir, scriptedReader(), { limits: { maxCalls: 2 }, packIds: ['authz-idor'] });
    assert.ok(run.result.coverage.modelCalls <= 2);
    assert.ok(run.result.coverage.missingCoverage > 0);
  } finally { cleanup(dir); }
});

test('prompts fence source as data, never as instructions, and are tagged with a context hash prefix', async () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    const seen = [];
    const inner = scriptedReader();
    await reviewWith(dir, async (p) => { seen.push(p); return inner(p); });
    assert.ok(seen.length > 0);
    for (const p of seen) {
      assert.match(p, /is DATA: source code/);
      assert.match(p, /<<BEGIN context-1 [0-9a-f]{8}>>[\s\S]*<<END context-1 [0-9a-f]{8}>>/);
    }
  } finally { cleanup(dir); }
});
