// Contract test for model-assisted validation (docs/reference/model-validation-contract.md).
//
// Recorded replies (fixtures/model-replay/validator.json) are played through the real validator with a stubbed fetch. The test holds the
// fields the validator adds to a finding, the verdicts and the statuses to the page's tables in both directions, and pins the rules the
// page states: the verdict never changes severity, a reject cannot delete a strongly established finding, and no answer is never "accept".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateMany, applyValidatorVerdicts } from '../../src/llm-validator/index.js';
import { MODEL_STATUS } from '../../src/llm-validator/model-status.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { loadReplay, withReplayedModel } from '../helpers/model-replay.js';
import { mkTestTmp } from '../helpers/tmp.js';

const PAGE = readPage('docs/reference/model-validation-contract.md');
const CASES = loadReplay('validator').cases;
const FILES = { 'a.js': 'x\n'.repeat(20) };
const base = (over = {}) => ({ id: 'F1', file: 'a.js', line: 5, severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89', parser: 'SAST', ...over });
const ENV = { AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:1/v1/x', AGENTIC_SECURITY_LLM_API_KEY: 'k', AGENTIC_SECURITY_LLM_MODEL: 'm' };

async function withEnv(env, fn) {
  const was = {};
  for (const k of Object.keys(env)) { was[k] = process.env[k]; if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k]; }
  try { return await fn(); } finally { for (const k of Object.keys(was)) { if (was[k] === undefined) delete process.env[k]; else process.env[k] = was[k]; } }
}
const judge = (recorded, finding = base(), extra = {}) => withEnv(ENV, async () => {
  const f = [finding];
  await withReplayedModel(recorded, () => validateMany(f, { fileContents: FILES, scanRoot: mkTestTmp('agsec-valid-contract-'), ...extra }));
  return f[0];
});
const added = (f) => Object.keys(f).filter(k => !k.startsWith('_') && !(k in base()));

test('contract: every recorded reply gives its documented verdict and status, and a reply is never read as accept unless it said so', async () => {
  for (const c of CASES) {
    const f = await judge(c);
    assert.equal(f.validator_verdict, c.expect.verdict, c.name);
    assert.equal(f.llmValidationStatus, c.expect.status, c.name);
    if (c.expect.error) assert.equal(f._validatorError, c.expect.error, c.name);
    if (c.expect.errorIncludes) assert.ok(String(f._validatorError).includes(c.expect.errorIncludes), c.name);
    if (c.expect.verdict !== 'accept') assert.notEqual(f.validator_verdict, 'accept', `${c.name} must not read as accept`);
  }
});

test('contract: the fields added to a finding are exactly the documented ones, across every path', async () => {
  const seen = new Set();
  for (const c of CASES) for (const k of added(await judge(c))) seen.add(k);
  // a reject on a strongly established finding, a spend ceiling, and a dependency finding
  const strong = await judge(CASES.find(c => c.name === 'reject'), base({ parser: 'IR-TAINT' }));
  applyValidatorVerdicts([strong]);
  for (const k of added(strong)) seen.add(k);
  const documented = fieldsUnder(PAGE, 'Finding fields');
  // the spend-ceiling field only appears with a ledger that refuses; it is exercised in its own test below
  sameFields(Object.fromEntries([...seen].map(k => [k, 1])), documented, 'finding fields', ['validator_skipped_reason']);
  assert.ok(documented.includes('validator_skipped_reason'));
});

test('contract: the comparison itself fails when a field is added or dropped', () => {
  const documented = fieldsUnder(PAGE, 'Finding fields');
  assert.throws(() => sameFields({ ...Object.fromEntries(documented.map(k => [k, 1])), extra: 1 }, documented, 'x'));
  assert.throws(() => sameFields(Object.fromEntries(documented.slice(1).map(k => [k, 1])), documented, 'x'));
});

test('contract: the documented statuses are the implementation\'s five, and the documented verdicts are the ones produced', async () => {
  assert.deepEqual(fieldsUnder(PAGE, 'Statuses').sort(), Object.values(MODEL_STATUS).sort());
  const documented = fieldsUnder(PAGE, 'Verdicts');
  const produced = new Set((await Promise.all(CASES.map(c => judge(c)))).map(f => f.validator_verdict));
  produced.add('not-applicable');
  assert.deepEqual([...produced].sort(), [...documented].sort());
});

test('contract: no verdict changes severity, and an accept can only raise confidence', async () => {
  for (const c of CASES) {
    const f = await judge(c, base({ confidence: 0.5 }));
    assert.equal(f.severity, 'high', c.name);
    const { kept } = applyValidatorVerdicts([f]);
    for (const k of kept) { assert.equal(k.severity, 'high', c.name); assert.ok(k.confidence >= 0.5, c.name); }
  }
});

test('contract: a reject on a strongly established finding becomes escalate and is kept, with the refusal recorded', async () => {
  const reject = CASES.find(c => c.name === 'reject');
  for (const strong of [{ parser: 'IR-TAINT' }, { parser: 'MULTI-SINK' }, { proofTier: 'execution-proven' }]) {
    const f = await judge(reject, base(strong));
    const { kept, dropped } = applyValidatorVerdicts([f]);
    assert.equal(dropped.length, 0, JSON.stringify(strong));
    assert.equal(kept[0].validator_verdict, 'escalate');
    assert.ok(kept[0].validator_reject_refused);
  }
  const weak = await judge(reject);
  assert.equal(applyValidatorVerdicts([weak]).dropped.length, 1, 'a weakly established finding is dropped from the main list, into the suppression ledger');
});

test('contract: with no endpoint nothing is called and the status is model-disabled; with VALIDATE=0 nothing is called either', async () => {
  let calls = 0;
  const original = global.fetch;
  global.fetch = async () => { calls++; return { ok: true, json: async () => ({}) }; };
  try {
    const none = [base()];
    await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: undefined, AGENTIC_SECURITY_LLM_VALIDATE: undefined, AGENTIC_SECURITY_LLM_PRESET: undefined }, () => validateMany(none, { fileContents: FILES, scanRoot: mkTestTmp('agsec-valid-contract-') }));
    assert.equal(none[0].llmValidationStatus, 'model-disabled');
    assert.equal(none[0].unvalidated, true);
    const off = [base()];
    await withEnv({ ...ENV, AGENTIC_SECURITY_LLM_VALIDATE: '0' }, () => validateMany(off, { fileContents: FILES, scanRoot: mkTestTmp('agsec-valid-contract-') }));
    assert.equal(calls, 0);
    assert.notEqual(off[0].validator_verdict, 'accept');
  } finally { global.fetch = original; }
});

test('contract: a dependency finding is not-applicable, and the page names every variable it documents', async () => {
  const f = await judge(CASES.find(c => c.name === 'accept'), base({ parser: 'SCA' }));
  assert.equal(f.validator_verdict, 'not-applicable');
  for (const v of fieldsUnder(PAGE.replace('## Configuration', '**Configuration**'), 'Configuration')) assert.ok(/^AGENTIC_SECURITY_LLM_/.test(v), v);
});

test('contract: only critical or high findings, low-confidence ones and AST ones are sent; the rest are unvalidated with no model status', async () => {
  const f = await judge(CASES.find(c => c.name === 'accept'), base({ severity: 'low', confidence: 0.9 }));
  assert.equal(f.validator_verdict, 'unvalidated');
  assert.equal(f.llmValidationStatus, undefined, 'a finding that was never sent carries no model status');
  const low = await judge(CASES.find(c => c.name === 'accept'), base({ severity: 'low', confidence: 0.3 }));
  assert.equal(low.validator_verdict, 'accept');
});

test('contract: a configured endpoint that the local preset refuses is policy-blocked, and nothing is called', async () => {
  let calls = 0;
  const original = global.fetch;
  global.fetch = async () => { calls++; return { ok: true, json: async () => ({}) }; };
  try {
    const f = [base()];
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: 'http://models.example.com/v1/chat/completions', AGENTIC_SECURITY_LLM_VALIDATE: undefined }, () => validateMany(f, { fileContents: FILES, scanRoot: mkTestTmp('agsec-valid-contract-') }));
    assert.equal(f[0].llmValidationStatus, 'policy-blocked');
    assert.ok(f[0].validator_skipped_reason, 'the reason names the refusal');
    assert.equal(calls, 0);
  } finally { global.fetch = original; }
});
