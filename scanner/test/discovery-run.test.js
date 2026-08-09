// scanner/test/discovery-run.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDiscovery, makeTaintProbe, makeBudget } from '../src/discovery/index.js';

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

// --- PRD Phase 0 / C3: the run budget ---------------------------------------
//
// This pipeline is multiplicative and shipped unbounded. Measured on a SIX-file
// fixture: 6 areas × 7 lenses = 42 hunter calls, then 42 candidates × 3
// refutation votes = 126 more. 168 LLM calls from six files, with nothing
// capping any of it. The cost of a run was a function of repository size, which
// is not a property anyone should discover from an invoice.

const manyFiles = (n) => {
  const fns = new Map();
  const fileContents = {};
  for (let i = 0; i < n; i++) {
    fns.set(`f${i}.js::x@1`, { qid: `f${i}.js::x@1`, name: 'x', file: `f${i}.js` });
    fileContents[`f${i}.js`] = 'function x(){ return 1; }';
  }
  return { perFileIR: {}, callGraph: { functions: fns, edges: [] }, fileContents };
};
const alwaysProposes = async (p) => (/REFUTE/.test(p)
  ? '{"refuted":false}'
  : '{"candidates":[{"title":"X","file":"f0.js","line":1,"sink":"eval"}]}');

test('the LLM call budget is a hard ceiling, not a suggestion', async () => {
  let actual = 0;
  const counted = async (p) => { actual += 1; return alwaysProposes(p); };
  const r = await runDiscovery(manyFiles(6), { llmInvoke: counted, maxLlmCalls: 5 });
  assert.equal(r.coverage.llmCalls, 5);
  assert.ok(actual <= 5, `the callback must never be invoked past the ceiling, got ${actual}`);
  assert.equal(r.coverage.budgetExhausted, true);
});

test('an exhausted budget is reported as an INCOMPLETE run, not a clean one', async () => {
  // The whole point: a run that stopped early must not read as "nothing found".
  const r = await runDiscovery(manyFiles(6), { llmInvoke: alwaysProposes, maxLlmCalls: 3 });
  const text = r.coverage.reasons.join('\n');
  assert.match(text, /RUN INCOMPLETE/);
  assert.match(text, /absence of a finding below is not evidence of absence/);
});

test('a run inside its budget is not marked exhausted', async () => {
  const r = await runDiscovery(manyFiles(1), { llmInvoke: alwaysProposes, maxLlmCalls: 1000 });
  assert.equal(r.coverage.budgetExhausted, false);
  assert.ok(!r.coverage.reasons.join('\n').includes('RUN INCOMPLETE'));
});

test('the candidate cap bounds panel cost and is disclosed, never silent', async () => {
  const r = await runDiscovery(manyFiles(6), { llmInvoke: alwaysProposes, maxLlmCalls: 1000, maxCandidates: 10 });
  assert.ok(r.coverage.candidatesCapped > 0, 'the cap must have bitten for this to test anything');
  assert.ok(r.coverage.panelsRun <= 10);
  assert.match(r.coverage.reasons.join('\n'), /candidate cap/);
  // "Neither findings nor cleared" is the load-bearing phrase: a capped
  // candidate was not examined, which is different from being dismissed.
  assert.match(r.coverage.reasons.join('\n'), /neither findings nor cleared/);
});

test('a dollar ceiling converts to calls only when a per-call cost is supplied', async () => {
  // Without costPerCallUsd there is no honest conversion, so maxCostUsd alone
  // must not silently become an unbounded run OR an arbitrary limit.
  const b1 = makeBudget({ maxCostUsd: 1, costPerCallUsd: 0.1, maxLlmCalls: 1000 });
  assert.equal(b1.maxCalls, 10);
  const b2 = makeBudget({ maxCostUsd: 1, maxLlmCalls: 77 });
  assert.equal(b2.maxCalls, 77, 'a dollar ceiling with no per-call cost must not change the call ceiling');
});

test('the wall-clock budget stops a run that is taking too long', async () => {
  let t = 0;
  const clock = () => t;
  const budget = makeBudget({ maxWallMs: 100, maxLlmCalls: 1000 }, clock);
  const wrapped = budget.wrap(async () => 'ok');
  await wrapped('first');            // inside the window
  t = 500;                            // time passes
  await assert.rejects(() => wrapped('second'), /wall-clock budget spent/);
});

test('makeBudget leaves a missing llmInvoke alone', async () => {
  // The degradation path depends on `null` staying null; wrapping it would turn
  // "no endpoint configured" into a thrown error.
  const budget = makeBudget({});
  assert.equal(budget.wrap(null), null);
  assert.equal(budget.wrap(undefined), undefined);
});

// --- PRD D3: the hybrid-loop uplift switch ----------------------------------
//
// `confirm: false` disables the deterministic gate so a population can be run
// both ways and the difference attributed to the taint engine. It exists to be
// measured against, never as a performance option: a run with it off is
// strictly weaker, because the confirmation tier is what sets severity.

test('confirmation is ON by default', async () => {
  const r = await runDiscovery(manyFiles(1), { llmInvoke: alwaysProposes, maxLlmCalls: 100 });
  assert.ok(!r.coverage.reasons.join('\n').includes('confirmation was DISABLED'));
});

test('confirm:false disables the deterministic gate and SAYS SO', async () => {
  // Silently weakening the pipeline would make the uplift measurement itself
  // dishonest — a reader must be able to tell which mode produced a report.
  const r = await runDiscovery(manyFiles(1), { llmInvoke: alwaysProposes, maxLlmCalls: 100, confirm: false });
  assert.match(r.coverage.reasons.join('\n'), /confirmation was DISABLED/);
  const tiers = r.coverage.confirmedByTier;
  assert.equal(tiers['taint-confirmed'], 0, 'nothing can be taint-confirmed with the probe off');
  assert.equal(tiers['sink-adjacent'], 0);
});

test('with confirmation off, every surviving finding is unconfirmed and therefore low', async () => {
  const r = await runDiscovery(manyFiles(1), { llmInvoke: alwaysProposes, maxLlmCalls: 100, confirm: false });
  for (const f of r.fresh) {
    assert.equal(f.discovery.confirmation.tier, 'unconfirmed');
    assert.equal(f.severity, 'low', 'severity comes from the confirmation tier, so it must collapse');
  }
});

// --- PRD N4: the standing cost metric ---------------------------------------
test('callsPerFinding is reported, with null rather than Infinity on no findings', async () => {
  // Cost drifts across workstreams — C3 bounded the worst case, C4 moved the
  // typical case 4x — so it is reported every run rather than measured when
  // somebody remembers to look.
  const none = await runDiscovery(manyFiles(1), { llmInvoke: async () => '{"candidates":[]}', maxLlmCalls: 50 });
  assert.equal(none.fresh.length, 0);
  assert.equal(none.coverage.callsPerFinding, null, 'no findings must not divide by zero');

  const some = await runDiscovery(manyFiles(1), { llmInvoke: alwaysProposes, maxLlmCalls: 50 });
  if (some.fresh.length > 0) {
    assert.equal(typeof some.coverage.callsPerFinding, 'number');
    assert.ok(some.coverage.callsPerFinding > 0);
  }
});
