// scanner/test/discovery-run.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDiscovery, makeTaintProbe } from '../src/discovery/index.js';

const CTX = {
  perFileIR: {},
  callGraph: {
    functions: new Map([['auth.js::login@1', { qid: 'auth.js::login@1', name: 'login', file: 'auth.js' }]]),
    edges: [],
  },
  fileContents: { 'auth.js': 'function login(u){ return db.query("select "+u); }' },
  priorScan: null,
  triageFeedback: null,
};

test('runDiscovery with no llm produces an empty but well-formed report', async () => {
  const prev = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  try {
    const r = await runDiscovery(CTX, {});
    assert.equal(r.schema, 'agentic-security/discovery@1');
    assert.deepEqual(r.fresh, []);
    assert.equal(r.coverage.areasPlanned, 1);
    assert.equal(r.coverage.degradedRuns, r.runs.length);
    assert.ok(r.coverage.reasons.length > 0, 'degradation must be disclosed, not silent');
  } finally {
    if (prev !== undefined) process.env.AGENTIC_SECURITY_LLM_ENDPOINT = prev;
  }
});

test('runDiscovery runs one hunter per area per lens', async () => {
  const seen = [];
  const llmInvoke = async (p) => { seen.push(p); return '{"candidates":[]}'; };
  const r = await runDiscovery(CTX, { llmInvoke, lenses: ['injection', 'authz'] });
  assert.equal(r.runs.length, 2);
  assert.equal(r.coverage.lensesPerArea, 2);
  assert.equal(r.coverage.areasHunted, 1);
});

test('a candidate flows hunt -> confirm -> disprove -> judge and lands in fresh', async () => {
  const llmInvoke = async (p) => {
    if (/REFUTE/.test(p)) return '{"refuted":false,"reason":"looks real"}';
    return '{"candidates":[{"title":"SQLi","file":"auth.js","line":1,"rationale":"concat","entryPoint":"u","sink":"db.query"}]}';
  };
  const r = await runDiscovery(CTX, { llmInvoke, lenses: ['injection'] });
  assert.equal(r.fresh.length, 1);
  assert.equal(r.fresh[0].parser, 'DISCOVERY');
  assert.ok(r.fresh[0].stableId);
});

test('a refuted candidate never reaches fresh', async () => {
  const llmInvoke = async (p) => {
    if (/REFUTE/.test(p)) return '{"refuted":true,"reason":"unreachable"}';
    return '{"candidates":[{"title":"SQLi","file":"auth.js","line":1,"rationale":"concat"}]}';
  };
  const r = await runDiscovery(CTX, { llmInvoke, lenses: ['injection'] });
  assert.equal(r.fresh.length, 0);
  assert.equal(r.refutedCandidates.length, 1);
});

test('makeTaintProbe returns null rather than throwing on an unanalysable input', async () => {
  const probe = makeTaintProbe({}, null);
  assert.equal(await probe({ file: 'a.js', line: 1 }), null);
});

test('an explicitly empty lens selection hunts nothing and says so', async () => {
  const llmInvoke = async () => '{"candidates":[]}';
  const r = await runDiscovery(CTX, { lenses: [], llmInvoke });
  assert.equal(r.runs.length, 0);
  assert.deepEqual(r.fresh, []);
  assert.ok(r.coverage.reasons.length > 0, 'empty lens selection must be disclosed');
  assert.ok(r.coverage.reasons.some(x => /empty|no lenses/i.test(x)));
});

test('an unknown lens key is recorded in coverage.reasons and does not abort the run', async () => {
  const llmInvoke = async () => '{"candidates":[]}';
  const r = await runDiscovery(CTX, { lenses: ['injection', 'not-a-real-lens'], llmInvoke });
  assert.equal(r.runs.length, 1);
  assert.ok(r.coverage.reasons.some(x => x.includes('not-a-real-lens')));
});

test('coverage.confirmedByTier and coverage.panelsRun/undecidedPanels reflect the confirm and disprove stages', async () => {
  const llmInvoke = async (p) => {
    if (/REFUTE/.test(p)) return '{"refuted":false,"reason":"looks real"}';
    return '{"candidates":[{"title":"SQLi","file":"auth.js","line":1,"rationale":"concat","entryPoint":"u","sink":"db.query"}]}';
  };
  const r = await runDiscovery(CTX, { llmInvoke, lenses: ['injection'] });
  assert.equal(r.fresh.length, 1);
  // No taintProbe corroboration configured for this candidate's file/line in
  // this fixture's callGraph coverage, so it lands unconfirmed.
  const total = r.coverage.confirmedByTier['taint-confirmed'] + r.coverage.confirmedByTier['sink-adjacent'] + r.coverage.confirmedByTier['unconfirmed'];
  assert.equal(total, 1);
  assert.equal(r.coverage.panelsRun, 1);
  assert.equal(r.coverage.undecidedPanels, 0, 'a real vote was cast, so this panel is not undecided');
});

test('coverage reports a reason when confirmation corroborates nothing', async () => {
  const llmInvoke = async (p) => {
    if (/REFUTE/.test(p)) return '{"refuted":false,"reason":"looks real"}';
    return '{"candidates":[{"title":"SQLi","file":"auth.js","line":1,"rationale":"concat"}]}';
  };
  const r = await runDiscovery(CTX, { llmInvoke, lenses: ['injection'] });
  assert.equal(r.coverage.confirmedByTier['unconfirmed'], 1);
  assert.ok(r.coverage.reasons.some(x => /confirmation stage corroborated nothing/.test(x)));
});

test('coverage reports a reason when the refutation panel is undecided for every candidate', async () => {
  // No REFUTE-matching branch: llmInvoke returns unparseable garbage for
  // refutation prompts, so every vote is excluded and every panel is undecided.
  const llmInvoke = async (p) => {
    if (/REFUTE/.test(p)) return 'not json';
    return '{"candidates":[{"title":"SQLi","file":"auth.js","line":1,"rationale":"concat"}]}';
  };
  const r = await runDiscovery(CTX, { llmInvoke, lenses: ['injection'] });
  assert.equal(r.coverage.panelsRun, 1);
  assert.equal(r.coverage.undecidedPanels, 1);
  assert.ok(r.coverage.reasons.some(x => /refutation panel returned no votes/.test(x)));
  // And the finding still survives — an outage must not quietly delete it —
  // which is exactly why the coverage reason above matters: it is uncorroborated.
  assert.equal(r.fresh.length, 1);
});

test('partial degradation within an area: areasHunted and areasFullyHunted diverge', async () => {
  const llmInvoke = async (p) => {
    if (/authz/i.test(p) || p.includes('Authorization')) throw new Error('simulated failure');
    return '{"candidates":[]}';
  };
  const r = await runDiscovery(CTX, { lenses: ['injection', 'authz'], llmInvoke });
  assert.equal(r.coverage.areasHunted, 1);
  assert.equal(r.coverage.areasFullyHunted, 0);
});
