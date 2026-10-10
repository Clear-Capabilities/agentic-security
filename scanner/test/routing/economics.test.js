// X-602.AC01 and AC02: auditable provider economics. Prices come from the provider catalog's dated snapshot; no model is called.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { priceBookFromCatalog, validatePriceBook, costOf, cacheEligibility, medianKnown, BILLING_BASES } from '../../src/posture/routing/economics.js';
import { SOURCED_AT, PROVIDERS } from '../../src/posture/provider-catalog.js';

const book = priceBookFromCatalog();
const MODEL = 'claude-sonnet-4-6'; // catalog: in 3, out 15, cached 0.30 per million tokens
const measured = (o) => ({ inputTokens: 10_000, outputTokens: 1_000, cachedInputTokens: 4_000, source: 'measured', ...o });
const near = (a, b) => assert.ok(Math.abs(a - b) < 1e-12, `${a} != ${b}`);

describe('[X-602.AC01] costs separate input, output, cached input, retries and tool execution, with price version, currency and billing basis', () => {
  test('each component is priced on its own and the total is their sum', () => {
    const c = costOf({ usage: measured(), model: MODEL, priceBook: book, retries: [{ usage: measured({ inputTokens: 2000, outputTokens: 0, cachedInputTokens: 0 }) }], toolExecutionUsd: 0.002 });
    near(c.measured.input.usd, (6000 * 3) / 1e6);
    near(c.measured.cachedInput.usd, (4000 * 0.3) / 1e6);
    near(c.measured.output.usd, (1000 * 15) / 1e6);
    near(c.measured.retries.usd, (2000 * 3) / 1e6);
    near(c.measured.toolExecution.usd, 0.002);
    near(c.totalUsd, 0.018 + 0.0012 + 0.015 + 0.006 + 0.002);
    assert.equal(c.totalStatus, 'measured');
    for (const k of ['input', 'cachedInput', 'output', 'retries', 'toolExecution', 'total']) assert.ok(k in c.measured, k);
  });

  test('the result names the price version, currency, billing basis and book digest it was computed against', () => {
    const c = costOf({ usage: measured(), model: MODEL, priceBook: book, toolExecutionUsd: 0 });
    assert.equal(c.priceVersion, `provider-catalog@${SOURCED_AT}`);
    assert.equal(c.currency, 'USD');
    assert.equal(c.billingBasis, 'list-price');
    assert.match(c.priceBookDigest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(c.model, MODEL);
  });

  test('a different price version or currency yields a different, comparable-by-metadata record', () => {
    const other = { ...book, version: 'provider-catalog@2099-01-01', currency: 'EUR' };
    const c = costOf({ usage: measured(), model: MODEL, priceBook: other, toolExecutionUsd: 0 });
    assert.equal(c.priceVersion, 'provider-catalog@2099-01-01');
    assert.equal(c.currency, 'EUR');
  });

  test('every model in the catalog is in the price book with the catalog rates', () => {
    for (const p of Object.values(PROVIDERS)) for (const m of p.models) {
      assert.equal(book.entries[m.id].in, m.in); assert.equal(book.entries[m.id].out, m.out); assert.equal(book.entries[m.id].cached, m.cached);
    }
  });

  test('a price book without a version, currency or valid basis is rejected', () => {
    assert.equal(validatePriceBook(book).ok, true);
    for (const bad of [{ version: '' }, { currency: 'dollars' }, { billingBasis: 'vibes' }, { entries: { x: { in: -1 } } }, { entries: { x: { out: NaN } } }, { schema: 'other' }]) {
      assert.equal(validatePriceBook({ ...book, ...bad }).ok, false, JSON.stringify(bad));
    }
    assert.ok(BILLING_BASES.includes('subscription'));
  });

  test('cache read tokens are cheaper than uncached ones, so the cached component is not folded into input', () => {
    const cached = costOf({ usage: measured({ cachedInputTokens: 10_000 }), model: MODEL, priceBook: book, toolExecutionUsd: 0 });
    const cold = costOf({ usage: measured({ cachedInputTokens: 0 }), model: MODEL, priceBook: book, toolExecutionUsd: 0 });
    assert.ok(cached.totalUsd < cold.totalUsd);
    assert.equal(cached.measured.input.usd, 0);
    near(cold.measured.cachedInput.usd, 0);
  });
});

describe('[X-602.AC02] unknown pricing or cache eligibility is unknown or a bounded estimate, never zero, and a prediction never replaces measured usage', () => {
  test('an unpriced model is unknown at every level, not zero', () => {
    const c = costOf({ usage: measured(), model: 'model-without-a-price', priceBook: book, toolExecutionUsd: 0 });
    for (const k of ['input', 'cachedInput', 'output', 'total']) { assert.equal(c.measured[k].status, 'unknown', k); assert.equal(c.measured[k].usd, null, k); }
    assert.equal(c.totalUsd, null); assert.equal(c.totalLowerUsd, null); assert.equal(c.totalUpperUsd, null);
    assert.equal(c.totalStatus, 'unknown');
  });

  test('a null rate in the book is unknown, and so is a missing price book', () => {
    const holed = { ...book, entries: { ...book.entries, [MODEL]: { ...book.entries[MODEL], out: null } } };
    const c = costOf({ usage: measured(), model: MODEL, priceBook: holed, toolExecutionUsd: 0 });
    assert.equal(c.measured.output.usd, null);
    assert.equal(c.totalUsd, null);
    assert.equal(costOf({ usage: measured(), model: MODEL, priceBook: null, toolExecutionUsd: 0 }).totalStatus, 'unknown');
  });

  test('a subscription basis has no metered per-token cost, so it is unknown rather than free', () => {
    const c = costOf({ usage: measured(), model: MODEL, priceBook: { ...book, billingBasis: 'subscription' }, toolExecutionUsd: 0 });
    assert.equal(c.totalStatus, 'unknown'); assert.equal(c.totalUsd, null);
    assert.equal(c.billingBasis, 'subscription');
  });

  test('an unknown cache split is a bounded estimate between all-cached and all-uncached, never a single made-up number', () => {
    const c = costOf({ usage: measured({ cachedInputTokens: null }), model: MODEL, priceBook: book, toolExecutionUsd: 0 });
    assert.equal(c.measured.input.status, 'bounded-estimate');
    assert.equal(c.measured.input.usd, null);
    near(c.measured.input.lowerUsd, (10_000 * 0.3) / 1e6);
    near(c.measured.input.upperUsd, (10_000 * 3) / 1e6);
    assert.equal(c.totalStatus, 'bounded-estimate');
    assert.ok(c.totalLowerUsd > 0 && c.totalUpperUsd > c.totalLowerUsd);
    assert.equal(c.totalUsd, null);
  });

  test('a prompt below the provider minimum cacheable prefix is known to be uncached', () => {
    const entry = book.entries[MODEL];
    assert.equal(cacheEligibility(entry, 500), 'ineligible');
    assert.equal(cacheEligibility(entry, 50_000), 'unknown', 'eligible is not the same as a hit');
    assert.equal(cacheEligibility({ cacheKind: null }, 50_000), 'unknown');
    const c = costOf({ usage: measured({ inputTokens: 500, cachedInputTokens: null }), model: MODEL, priceBook: book, toolExecutionUsd: 0 });
    assert.equal(c.measured.input.status, 'measured');
    near(c.measured.input.usd, (500 * 3) / 1e6);
    near(c.measured.cachedInput.usd, 0);
  });

  test('unreported token counts are unknown; they are not priced as zero tokens', () => {
    const c = costOf({ usage: measured({ outputTokens: null }), model: MODEL, priceBook: book, toolExecutionUsd: 0 });
    assert.equal(c.measured.output.status, 'unknown');
    assert.equal(c.totalUsd, null);
    const noTokens = costOf({ usage: { inputTokens: null, outputTokens: null, cachedInputTokens: null, source: 'measured' }, model: MODEL, priceBook: book, toolExecutionUsd: 0 });
    assert.equal(noTokens.totalStatus, 'unknown');
  });

  test('a prediction never fills in for a measurement: estimated usage leaves the measured section unknown', () => {
    for (const source of ['estimated', 'unknown']) {
      const c = costOf({ usage: measured({ source }), model: MODEL, priceBook: book, toolExecutionUsd: 0, predictedTokens: 10_000 });
      assert.equal(c.totalUsd, null, source);
      assert.equal(c.totalStatus, 'unknown');
      assert.equal(c.measured.input.usd, null);
      assert.equal(c.predicted.basis, 'prediction');
      near(c.predicted.upperUsd, (10_000 * 3) / 1e6);
    }
    const real = costOf({ usage: measured(), model: MODEL, priceBook: book, toolExecutionUsd: 0, predictedTokens: 999_999_999 });
    near(real.totalUsd, 0.018 + 0.0012 + 0.015);
  });

  test('tool execution that was not measured is unknown, not free; a measured zero is a known zero', () => {
    assert.equal(costOf({ usage: measured(), model: MODEL, priceBook: book }).measured.toolExecution.status, 'unknown');
    assert.equal(costOf({ usage: measured(), model: MODEL, priceBook: book }).totalUsd, null);
    assert.equal(costOf({ usage: measured(), model: MODEL, priceBook: book, toolExecutionUsd: null }).measured.toolExecution.usd, null);
    const zero = costOf({ usage: measured(), model: MODEL, priceBook: book, toolExecutionUsd: 0 });
    assert.equal(zero.measured.toolExecution.status, 'measured');
    assert.equal(zero.measured.toolExecution.usd, 0);
  });

  test('a retry that reported no usage is bounded by the request size, never priced at zero; with no size estimate it is unknown', () => {
    const bounded = costOf({ usage: measured(), model: MODEL, priceBook: book, retries: [{}], estimatedRequestTokens: 8000, toolExecutionUsd: 0 });
    assert.equal(bounded.measured.retries.status, 'bounded-estimate');
    near(bounded.measured.retries.lowerUsd, 0);
    near(bounded.measured.retries.upperUsd, (8000 * 3) / 1e6);
    assert.equal(bounded.totalStatus, 'bounded-estimate');
    const unknown = costOf({ usage: measured(), model: MODEL, priceBook: book, retries: [{}], toolExecutionUsd: 0 });
    assert.equal(unknown.measured.retries.status, 'unknown');
    assert.equal(unknown.totalUsd, null);
    const none = costOf({ usage: measured(), model: MODEL, priceBook: book, retries: [], toolExecutionUsd: 0 });
    assert.equal(none.measured.retries.usd, 0, 'no retries is a known zero');
  });

  test('a median over costs ignores unknowns and returns null, never 0, when none are known', () => {
    assert.equal(medianKnown([null, null]), null);
    assert.equal(medianKnown([]), null);
    assert.equal(medianKnown([null, 3, 1, 2]), 2);
    assert.equal(medianKnown([4, 2]), 3);
  });
});
