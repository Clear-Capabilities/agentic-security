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
  assert.equal(r.refuted.length, 1);
});

test('makeTaintProbe returns null rather than throwing on an unanalysable input', async () => {
  const probe = makeTaintProbe({}, null);
  assert.equal(await probe({ file: 'a.js', line: 1 }), null);
});
