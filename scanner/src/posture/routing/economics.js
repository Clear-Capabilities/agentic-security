// Auditable provider economics (X-602).
//
// Turns token usage into a cost that says how it was obtained. Extends the provider catalog (posture/provider-catalog.js, which
// already carries the dated $/1M-token rates and each provider's cache model) rather than keeping a second price table, and sits
// beside cache-economics.js, which prices Claude Code's own transcript. That module and the interactive cost advisor are unchanged.
//
// What "auditable" means here:
//
//   - A cost is split into input (uncached prompt tokens), cached input, output, retries and tool execution, and the result names the
//     price book version, currency and billing basis it was computed against, so two costs are comparable only when those match.
//   - UNKNOWN IS NOT ZERO. A missing price, a missing token count, an unknown cache split, a subscription whose marginal cost is not
//     metered: each yields `unknown` (null) or a BOUNDED estimate with a lower and an upper value, never 0. A total with an unknown
//     component is unknown; it does not quietly sum the parts that happened to be known.
//   - MEASURED AND PREDICTED NEVER MIX. `measured` is computed only from usage the provider reported. A prediction (from a context
//     size, say) goes in `predicted`, and the measured fields stay null when no measurement exists. A prediction never fills in for a
//     measurement, and the budget path in decide.js uses the bounded upper estimate, labelled as such, not a "measured" number.
//
// Pure: no fs, no clock, no network. Money is a plain number of the book's currency; sums use the same order every time so a result
// is reproducible.

import { PROVIDERS, SOURCED_AT } from '../provider-catalog.js';
import { digestOf } from '../assurance/identity.js';

export const PRICE_BOOK_SCHEMA = 'agentic-security/routing-price-book';
export const BILLING_BASES = Object.freeze(['list-price', 'contract', 'subscription', 'unknown']);
/** A basis whose per-token price is not the whole story: a flat subscription has no metered marginal cost. */
const UNMETERED_BASES = Object.freeze(['subscription', 'unknown']);
export const COST_STATUS = Object.freeze({ measured: 'measured', bounded: 'bounded-estimate', unknown: 'unknown' });
const PER = 1_000_000;

/**
 * The price book derived from the provider catalog. `version` pins the catalog snapshot date, so a price change is a new version, and
 * the catalog's own warning stands: those rates are a dated snapshot, not live truth.
 */
export function priceBookFromCatalog({ providers = PROVIDERS, sourcedAt = SOURCED_AT, billingBasis = 'list-price', currency = 'USD' } = {}) {
  const entries = {};
  for (const [provider, p] of Object.entries(providers)) {
    for (const m of p.models) {
      entries[m.id] = {
        provider, in: m.in ?? null, out: m.out ?? null, cached: m.cached ?? null,
        cacheKind: p.cache?.kind ?? null, cacheMinPrefixTokens: p.cache?.minPrefixTokens ?? null,
      };
    }
  }
  const book = { schema: PRICE_BOOK_SCHEMA, version: `provider-catalog@${sourcedAt}`, currency, billingBasis, unit: 'per-1M-tokens', sourcedAt, entries };
  book.digest = digestOf({ ...book, digest: undefined });
  return book;
}

export function validatePriceBook(b) {
  const errors = [];
  const bad = (path, message) => errors.push({ code: 'BAD_PRICE_BOOK', path, message });
  if (!b || typeof b !== 'object') return { ok: false, errors: [{ code: 'BAD_PRICE_BOOK', path: '', message: 'not an object' }] };
  if (b.schema !== PRICE_BOOK_SCHEMA) bad('schema', `expected ${PRICE_BOOK_SCHEMA}`);
  if (typeof b.version !== 'string' || !b.version) bad('version', 'a price book has a version');
  if (typeof b.currency !== 'string' || !/^[A-Z]{3}$/.test(b.currency)) bad('currency', 'must be a three-letter code');
  if (!BILLING_BASES.includes(b.billingBasis)) bad('billingBasis', `must be one of ${BILLING_BASES.join(', ')}`);
  if (!b.entries || typeof b.entries !== 'object') bad('entries', 'missing');
  else {
    for (const [id, e] of Object.entries(b.entries)) {
      for (const f of ['in', 'out', 'cached']) {
        if (e[f] !== null && e[f] !== undefined && !(typeof e[f] === 'number' && Number.isFinite(e[f]) && e[f] >= 0)) bad(`entries.${id}.${f}`, 'a rate is a non-negative number, or null when unknown (never 0 for unknown)');
      }
    }
  }
  return { ok: errors.length === 0, errors };
}

const pick = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const UNKNOWN = Object.freeze({ usd: null, lowerUsd: null, upperUsd: null, status: COST_STATUS.unknown });
const unknown = (reason) => ({ ...UNKNOWN, reason });
const exact = (usd) => ({ usd, lowerUsd: usd, upperUsd: usd, status: COST_STATUS.measured });
const bounded = (lowerUsd, upperUsd, reason) => ({ usd: null, lowerUsd, upperUsd, status: COST_STATUS.bounded, reason });

/**
 * Can the prompt prefix be cached at all? `ineligible` is a fact (the provider's own minimum prefix is not met, or it has no cache);
 * `unknown` is everything else, because eligible is not the same as hit.
 */
export function cacheEligibility(entry, inputTokens) {
  if (!entry || entry.cacheKind === null || entry.cacheKind === undefined) return 'unknown';
  if (Number.isInteger(inputTokens) && Number.isInteger(entry.cacheMinPrefixTokens) && inputTokens < entry.cacheMinPrefixTokens) return 'ineligible';
  return 'unknown';
}

/** Cost of the token components of ONE attempt from MEASURED usage. */
function attemptCost(usage, entry) {
  const inTok = usage.inputTokens;
  const outTok = usage.outputTokens;
  const out = outTok === null || pick(entry?.out) === null ? unknown(outTok === null ? 'output tokens not reported' : 'no output price') : exact((outTok * entry.out) / PER);
  let input; let cachedInput;
  if (inTok === null || pick(entry?.in) === null) {
    const why = inTok === null ? 'input tokens not reported' : 'no input price';
    input = unknown(why); cachedInput = unknown(why);
  } else if (usage.cachedInputTokens !== null && usage.cachedInputTokens !== undefined) {
    const cached = usage.cachedInputTokens;
    input = exact(((inTok - cached) * entry.in) / PER);
    cachedInput = cached === 0 ? exact(0) : (pick(entry.cached) === null ? unknown('cached input tokens reported but no cached-input price') : exact((cached * entry.cached) / PER));
  } else if (cacheEligibility(entry, inTok) === 'ineligible') {
    // Below the provider's minimum cacheable prefix, so no token can have been served from cache: a fact, not a guess.
    input = exact((inTok * entry.in) / PER); cachedInput = exact(0);
  } else if (pick(entry.cached) === null) {
    input = unknown('cache split not reported and no cached-input price to bound it'); cachedInput = unknown('cache split not reported');
  } else {
    // Cache split unknown: the cached share is somewhere in [0, inTok]. Bound the COMBINED prompt cost, and say so on both parts.
    const lo = (inTok * Math.min(entry.in, entry.cached)) / PER;
    const hi = (inTok * Math.max(entry.in, entry.cached)) / PER;
    input = bounded(lo, hi, 'cache split not reported: the prompt cost lies between all-cached and all-uncached; the bound covers input and cached input together');
    cachedInput = { ...input, combinedWithInput: true };
  }
  return { input, cachedInput, output: out };
}

const sumParts = (parts) => {
  if (parts.some((p) => p.status === COST_STATUS.unknown)) return { ...UNKNOWN, reason: 'a component is unknown, so the total is unknown' };
  const lowerUsd = parts.reduce((a, p) => a + p.lowerUsd, 0);
  const upperUsd = parts.reduce((a, p) => a + p.upperUsd, 0);
  if (parts.every((p) => p.status === COST_STATUS.measured)) return exact(lowerUsd);
  return { usd: null, lowerUsd, upperUsd, status: COST_STATUS.bounded };
};

/**
 * Price one task run.
 *
 * @param {object} o
 * @param {{inputTokens:number|null, outputTokens:number|null, cachedInputTokens:number|null, source:string}} o.usage  the FINAL attempt's usage
 * @param {string} o.model
 * @param {object} o.priceBook
 * @param {Array<{usage?:object, billable?:boolean}>} [o.retries]  earlier attempts. An attempt with no reported usage is bounded by
 *        `estimatedRequestTokens` (a failed request may have been billed for its input), never priced at 0.
 * @param {number|null} [o.estimatedRequestTokens]  request size estimate used ONLY to bound unreported retries
 * @param {number|null} [o.toolExecutionUsd]  null/undefined means not measured (unknown), not free
 * @param {number|null} [o.predictedTokens]   a prediction; reported under `predicted`, never under `measured`
 * @returns the cost with `priceVersion`, `currency`, `billingBasis`, and separate `measured` / `predicted` sections
 */
export function costOf({ usage, model, priceBook, retries = [], estimatedRequestTokens = null, toolExecutionUsd = undefined, predictedTokens = null } = {}) {
  const meta = {
    priceVersion: priceBook?.version ?? null, currency: priceBook?.currency ?? null, billingBasis: priceBook?.billingBasis ?? 'unknown',
    priceBookDigest: priceBook?.digest ?? null, model,
  };
  const entry = priceBook?.entries?.[model] ?? null;
  const metered = priceBook && !UNMETERED_BASES.includes(priceBook.billingBasis);
  const reason = !priceBook ? 'no price book' : !entry ? `no price for model '${model}'` : !metered ? `billing basis '${priceBook.billingBasis}' has no metered per-token cost` : null;
  const usable = reason === null ? entry : null;

  const u = usage || {};
  const measuredUsage = u.source === 'measured';
  const tokens = { inputTokens: pick(u.inputTokens) === null ? null : u.inputTokens, outputTokens: pick(u.outputTokens) === null ? null : u.outputTokens, cachedInputTokens: pick(u.cachedInputTokens) === null ? null : u.cachedInputTokens };
  const unpriced = (why) => ({ input: unknown(why), cachedInput: unknown(why), output: unknown(why) });
  let parts;
  if (!usable) parts = unpriced(reason);
  else if (!measuredUsage) parts = unpriced(`usage is '${u.source ?? 'unknown'}', not measured: a prediction is not substituted for a measurement`);
  else parts = attemptCost(tokens, usable);

  // retries: each earlier attempt, priced on its own reported usage, or bounded when it reported none
  let retryParts;
  if (!retries.length) retryParts = exact(0);
  else {
    const each = retries.map((r) => {
      if (!usable) return unknown(reason);
      if (r?.usage?.source === 'measured') { const c = attemptCost({ inputTokens: pick(r.usage.inputTokens) === null ? null : r.usage.inputTokens, outputTokens: pick(r.usage.outputTokens) === null ? null : r.usage.outputTokens, cachedInputTokens: pick(r.usage.cachedInputTokens) === null ? null : r.usage.cachedInputTokens }, usable); return sumParts([c.input, c.cachedInput.combinedWithInput ? exact(0) : c.cachedInput, c.output]); }
      if (Number.isInteger(estimatedRequestTokens) && pick(usable.in) !== null) return bounded(0, (estimatedRequestTokens * usable.in) / PER, 'attempt reported no usage: bounded by its estimated input, never assumed free');
      return unknown('attempt reported no usage and no request size estimate is available');
    });
    retryParts = sumParts(each);
  }
  const tool = toolExecutionUsd === undefined || toolExecutionUsd === null ? unknown('tool execution cost not measured') : (pick(toolExecutionUsd) !== null && toolExecutionUsd >= 0 ? exact(toolExecutionUsd) : unknown('invalid tool execution cost'));

  const distinct = [parts.input, parts.cachedInput.combinedWithInput ? exact(0) : parts.cachedInput, parts.output, retryParts, tool];
  const total = sumParts(distinct);
  const measured = { ...parts, retries: retryParts, toolExecution: tool, total };
  let predicted = null;
  if (Number.isInteger(predictedTokens) && usable && pick(usable.in) !== null) {
    predicted = { basis: 'prediction', upperUsd: (predictedTokens * usable.in) / PER, note: 'a prediction from a request-size estimate; it never replaces measured usage' };
  }
  // A cost on a metered basis from measured usage is "measured"; everything else is reported as it is.
  return Object.freeze({ ...meta, measured, predicted, totalUsd: total.status === COST_STATUS.measured ? total.usd : null, totalStatus: total.status, totalLowerUsd: total.lowerUsd, totalUpperUsd: total.upperUsd });
}

/** Median of the known values; null (never 0) when there are none. */
export function medianKnown(values) {
  const v = values.filter((x) => typeof x === 'number' && Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return null;
  const m = v.length >> 1;
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
}
