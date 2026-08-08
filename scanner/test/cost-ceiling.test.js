// R12 — the hard cost ceiling.
//
// The whole point of this module is that it REFUSES rather than warns, so the
// tests are mostly about refusal: that the cap binds before the call, that an
// unpriceable model cannot spend, that a malformed cap is not read as "no
// cap", and that a finding skipped at the ceiling is reported as unvalidated
// rather than quietly passing.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createCostLedger, parseCapUsd, priceFor, costOf, renderCostCeiling, CapExceeded, _internals,
} from '../src/llm-validator/cost-ceiling.js';

const MODEL = 'claude-haiku-4-5';

test('no cap configured means the feature is off', () => {
  assert.equal(parseCapUsd({}), null);
  assert.equal(parseCapUsd({ AGENTIC_SECURITY_LLM_MAX_USD: '' }), null);
  const l = createCostLedger({ capUsd: null, model: MODEL });
  assert.equal(l.enforcing, false);
  assert.equal(l.canAfford({ inputTokens: 1e9, outputTokens: 1e9 }).ok, true);
  assert.equal(l.remainingUsd(), Infinity);
  assert.equal(renderCostCeiling(l.state()), null);
});

test('a malformed cap is refused, never read as "no cap"', () => {
  // The failure this prevents: a typo silently becoming unlimited spend.
  for (const bad of ['abc', '-1', 'NaN', 'Infinity']) {
    assert.throws(() => parseCapUsd({ AGENTIC_SECURITY_LLM_MAX_USD: bad }), CapExceeded, `accepted ${bad}`);
  }
  assert.equal(parseCapUsd({ AGENTIC_SECURITY_LLM_MAX_USD: '0' }), 0);
  assert.equal(parseCapUsd({ AGENTIC_SECURITY_LLM_MAX_USD: '2.50' }), 2.5);
});

test('the cap binds BEFORE the call, on the worst-case estimate', () => {
  const price = priceFor(MODEL, {});
  // One call's worst case, priced exactly.
  const call = { inputTokens: 1_000_000, outputTokens: 0 };
  const one = costOf(call, price);
  const l = createCostLedger({ capUsd: one * 1.5, model: MODEL });

  assert.equal(l.canAfford(call).ok, true, 'the first call fits');
  l.record(call);
  const second = l.canAfford(call);
  assert.equal(second.ok, false, 'the second call must be refused before it is made');
  assert.match(second.reason, /cost ceiling reached/);
  assert.equal(l.refusals(), 1);
});

test('a per-batch ledger cannot be defeated by many small calls', () => {
  const price = priceFor(MODEL, {});
  const small = { inputTokens: 100_000, outputTokens: 0 };
  const cost = costOf(small, price);
  const l = createCostLedger({ capUsd: cost * 3.5, model: MODEL });
  let made = 0;
  for (let i = 0; i < 100; i++) {
    if (!l.canAfford(small).ok) break;
    l.record(small);
    made++;
  }
  assert.equal(made, 3, 'spend must accumulate across calls, not reset per call');
  assert.ok(l.spentUsd() <= l.capUsd);
});

test('an unpriceable model refuses every call rather than spending unmetered', () => {
  const l = createCostLedger({ capUsd: 100, model: 'some-unknown-model', env: {} });
  const r = l.canAfford({ inputTokens: 10, outputTokens: 10 });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no price is known/);
  assert.equal(l.state().priceable, false);
  assert.match(renderCostCeiling(l.state()), /unpriceable/);
});

test('an unpriceable model is fine when no ceiling is configured', () => {
  // Nothing to enforce, so refusing would break existing behaviour for no gain.
  const l = createCostLedger({ capUsd: null, model: 'some-unknown-model', env: {} });
  assert.equal(l.canAfford({ inputTokens: 10 }).ok, true);
});

test('a malformed price override is unpriceable, not silently ignored', () => {
  for (const bad of ['1.0', 'a,b', '1,2,3', '-1,2']) {
    assert.equal(priceFor(MODEL, { AGENTIC_SECURITY_LLM_PRICE_USD_PER_MTOK: bad }), null, `accepted ${bad}`);
  }
  const ok = priceFor('anything', { AGENTIC_SECURITY_LLM_PRICE_USD_PER_MTOK: '3, 15' });
  assert.deepEqual({ input: ok.input, output: ok.output, source: ok.source }, { input: 3, output: 15, source: 'override' });
});

test('the override prices a model the built-in table does not know', () => {
  const l = createCostLedger({
    capUsd: 1, model: 'byo-model',
    env: { AGENTIC_SECURITY_LLM_PRICE_USD_PER_MTOK: '1,1' },
  });
  assert.equal(l.canAfford({ inputTokens: 1000, outputTokens: 1000 }).ok, true);
  assert.equal(l.state().priceSource, 'override');
});

test('a zero cap permits nothing', () => {
  const l = createCostLedger({ capUsd: 0, model: MODEL });
  assert.equal(l.canAfford({ inputTokens: 1, outputTokens: 0 }).ok, false);
  // A genuinely free call is not blocked by a zero cap — the check is on spend.
  assert.equal(l.canAfford({ inputTokens: 0, outputTokens: 0 }).ok, true);
});

test('reported state always carries the cap alongside the spend', () => {
  const l = createCostLedger({ capUsd: 5, model: MODEL });
  l.record({ inputTokens: 1_000_000, outputTokens: 0 });
  const s = l.state();
  for (const k of ['enforcing', 'capUsd', 'spentUsd', 'remainingUsd', 'calls', 'refusals', 'priceable']) {
    assert.ok(k in s, `state is missing ${k}`);
  }
  assert.equal(s.capUsd, 5);
  assert.ok(s.spentUsd > 0);
  assert.equal(s.remainingUsd, Number((5 - s.spentUsd).toFixed(6)));
  assert.match(renderCostCeiling(s), /of \$5\.0000 cap/);
});

test('the summary says findings were left unvalidated, not validated', () => {
  const l = createCostLedger({ capUsd: 0, model: MODEL });
  l.canAfford({ inputTokens: 1000, outputTokens: 0 });
  assert.match(renderCostCeiling(l.state()), /REFUSED at the ceiling/);
  assert.match(renderCostCeiling(l.state()), /unvalidated, not validated/);
});

test('the built-in price table is small and dated on purpose', () => {
  // A large or undated table is how stale prices silently mis-enforce every
  // ceiling built on them. If this fails, confirm the prices were re-checked
  // and update the date stamp in the module header.
  assert.ok(Object.keys(_internals.PRICES).length <= 3,
    'the built-in table grew — price data belongs with the operator, not the engine');
});

// --- measured vs estimated ------------------------------------------------
//
// The defect these close, found by adversarial review: `callEndpoint` returned
// only {ok, text}, discarding the provider's usage report, so the ledger ALWAYS
// booked the pre-call worst case — full max_tokens of output, which most
// replies never reach — while `renderCostCeiling` printed it as "LLM spend $X".
// An upper bound presented as a measurement.

test('an estimated call is disclosed as an upper bound, not as spend', () => {
  const l = createCostLedger({ capUsd: 10, model: MODEL });
  l.record({ inputTokens: 1000, outputTokens: 512 }, { measured: false });
  const s = l.state();
  assert.equal(s.fullyMeasured, false);
  assert.equal(s.estimatedCalls, 1);
  assert.ok(s.estimatedUsd > 0);
  const line = renderCostCeiling(s);
  assert.match(line, /at most/, 'an estimated figure must not read as a measurement');
  assert.match(line, /ESTIMATED at the full permitted output length/);
  assert.match(line, /true spend is lower/);
});

test('a fully measured ledger says so and drops the qualifier', () => {
  const l = createCostLedger({ capUsd: 10, model: MODEL });
  l.record({ inputTokens: 1000, outputTokens: 40 }, { measured: true });
  const s = l.state();
  assert.equal(s.fullyMeasured, true);
  assert.equal(s.estimatedCalls, 0);
  assert.equal(s.estimatedUsd, 0);
  const line = renderCostCeiling(s);
  assert.doesNotMatch(line, /at most/);
  assert.doesNotMatch(line, /ESTIMATED/);
});

test('one estimated call taints the whole figure', () => {
  // Mixing measured and estimated yields a number that is still an upper
  // bound, so the qualifier must survive the majority being measured.
  const l = createCostLedger({ capUsd: 10, model: MODEL });
  for (let i = 0; i < 9; i++) l.record({ inputTokens: 100, outputTokens: 10 }, { measured: true });
  l.record({ inputTokens: 100, outputTokens: 512 }, { measured: false });
  const s = l.state();
  assert.equal(s.fullyMeasured, false);
  assert.equal(s.estimatedCalls, 1);
  assert.match(renderCostCeiling(s), /at most/);
});

test('record() defaults to estimated when the caller does not say', () => {
  // The conservative default: forgetting the flag must not silently upgrade an
  // estimate into a measurement.
  const l = createCostLedger({ capUsd: 10, model: MODEL });
  l.record({ inputTokens: 100, outputTokens: 10 });
  assert.equal(l.state().fullyMeasured, false);
});

test('measured usage still enforces the cap', () => {
  // Disclosure must not weaken enforcement.
  const price = priceFor(MODEL, {});
  const call = { inputTokens: 1_000_000, outputTokens: 0 };
  const l = createCostLedger({ capUsd: costOf(call, price) * 1.5, model: MODEL });
  l.record(call, { measured: true });
  assert.equal(l.canAfford(call).ok, false);
});
