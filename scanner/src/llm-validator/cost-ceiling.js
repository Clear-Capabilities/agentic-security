// R12 — a hard cost ceiling for the LLM validator tier.
//
// A cost *advisor* already exists (`hooks/model-cost-advisor.js`): it biases a
// quality/cost dial and warns as spend approaches a soft budget. What did not
// exist is a CAP — something that refuses to spend rather than advising about
// it. A soft budget you can sail past is not a ceiling, and "it warned you" is
// no comfort on an invoice.
//
// THE DISTINCTION THAT MATTERS: this never degrades quality to fit a budget.
// It stops. Silently switching to a cheaper model or a shorter prompt to stay
// under a cap would change what the scan MEANS while reporting the same shape,
// and a finding validated by a model the operator did not choose is a
// different claim than the one they asked for. When the cap binds, remaining
// findings are left explicitly `unvalidated` with a reason naming the cap.
//
// FAIL CLOSED ON UNKNOWN PRICING. A ceiling that cannot price a call cannot
// enforce anything. Rather than spending unmetered and reporting a $0.00
// ledger, an unpriceable model refuses every call. Operators override with
// `AGENTIC_SECURITY_LLM_PRICE_USD_PER_MTOK="<in>,<out>"`.
//
// PRICES ARE OPERATOR-SUPPLIED FACTS, NOT ENGINE FACTS. The built-in table is a
// convenience for the shipped preset, and list prices change. It is deliberately
// small, it is stamped with the date it was last checked, and anything not in it
// must be priced explicitly. Do not grow this table casually — a stale price
// here silently mis-enforces every ceiling built on it.

// USD per 1,000,000 tokens, {input, output}. Last checked: 2026-08-07.
const PRICES = Object.freeze({
  'claude-haiku-4-5': { input: 1.00, output: 5.00 },
});

export class CapExceeded extends Error {
  constructor(msg) { super(msg); this.name = 'CapExceeded'; }
}

/** Parse the configured cap. Returns null when no cap is set (feature off). */
export function parseCapUsd(env = process.env) {
  const raw = env.AGENTIC_SECURITY_LLM_MAX_USD;
  if (raw == null || raw === '') return null;
  const n = Number(raw);
  // A malformed cap is refused rather than ignored: treating "abc" or a
  // negative as "no cap" turns a typo into unlimited spend.
  if (!Number.isFinite(n) || n < 0) {
    throw new CapExceeded(`AGENTIC_SECURITY_LLM_MAX_USD is not a non-negative number: ${JSON.stringify(raw)}`);
  }
  return n;
}

/** Resolve {input, output} USD per 1M tokens for a model, or null if unknown. */
export function priceFor(model, env = process.env) {
  const override = env.AGENTIC_SECURITY_LLM_PRICE_USD_PER_MTOK;
  if (override) {
    const parts = String(override).split(',').map(s => Number(s.trim()));
    if (parts.length === 2 && parts.every(n => Number.isFinite(n) && n >= 0)) {
      return { input: parts[0], output: parts[1], source: 'override' };
    }
    return null; // malformed override -> unpriceable, so fail closed
  }
  const p = PRICES[model];
  return p ? { ...p, source: 'built-in' } : null;
}

export function costOf({ inputTokens = 0, outputTokens = 0 }, price) {
  if (!price) return null;
  return (inputTokens / 1e6) * price.input + (outputTokens / 1e6) * price.output;
}

/**
 * A ledger enforcing a hard ceiling.
 *
 * `capUsd === null` means no ceiling was configured: `canAfford` always allows
 * and nothing is enforced. That is the default, and it is the ONLY state in
 * which unpriceable models are permitted — without a cap there is nothing to
 * enforce, so refusing would break existing behaviour for no benefit.
 */
export function createCostLedger({ capUsd = null, model = 'unknown', env = process.env } = {}) {
  const price = priceFor(model, env);
  let spentUsd = 0, calls = 0, refusals = 0;
  // How much of `spentUsd` came from ESTIMATES rather than reported usage.
  // Tracked separately because the two are not the same kind of number: the
  // estimate charges the full permitted output length, which most replies
  // never reach, so a ledger fed only estimates reports an upper bound. That
  // is fine for ENFORCEMENT (it can only stop early, never late) and wrong for
  // REPORTING. Callers get told which they are looking at.
  let estimatedUsd = 0, estimatedCalls = 0;

  const enforcing = capUsd != null;

  return {
    enforcing,
    capUsd,
    model,
    price,
    spentUsd: () => spentUsd,
    calls: () => calls,
    refusals: () => refusals,
    remainingUsd: () => (enforcing ? Math.max(0, capUsd - spentUsd) : Infinity),

    /**
     * May a call costing at most `estimate` tokens proceed?
     * @returns {{ok:boolean, reason?:string}}
     */
    canAfford({ inputTokens = 0, outputTokens = 0 } = {}) {
      if (!enforcing) return { ok: true };
      if (!price) {
        refusals++;
        return {
          ok: false,
          reason: `no price is known for model '${model}', so a spend ceiling cannot be enforced. `
            + 'Set AGENTIC_SECURITY_LLM_PRICE_USD_PER_MTOK="<input>,<output>" (USD per 1M tokens) '
            + 'or remove AGENTIC_SECURITY_LLM_MAX_USD. Refusing rather than spending unmetered.',
        };
      }
      // Charge the ESTIMATE before the call, not the actual after it. Checking
      // afterwards would let a single call blow through the cap and report the
      // overrun as a fait accompli.
      const projected = spentUsd + (costOf({ inputTokens, outputTokens }, price) || 0);
      if (projected > capUsd) {
        refusals++;
        return {
          ok: false,
          reason: `cost ceiling reached: this call would bring spend to $${projected.toFixed(4)}, `
            + `over the $${capUsd.toFixed(4)} cap (AGENTIC_SECURITY_LLM_MAX_USD). `
            + 'Remaining findings are left unvalidated rather than validated by a cheaper substitute.',
        };
      }
      return { ok: true };
    },

    /**
     * Record usage after a call.
     * @param {object} usage {inputTokens, outputTokens}
     * @param {object} [opts]
     * @param {boolean} [opts.measured] true when the figures came from the
     *   provider's own usage report; false when they are our pre-call
     *   estimate. Defaults to false — the conservative reading, so a caller
     *   that forgets to say cannot accidentally upgrade an estimate into a
     *   measurement.
     */
    record({ inputTokens = 0, outputTokens = 0 } = {}, { measured = false } = {}) {
      calls++;
      const c = costOf({ inputTokens, outputTokens }, price);
      // Unpriceable usage is not free. With no cap it is simply not tracked;
      // with a cap, `canAfford` already refused, so this branch cannot spend.
      if (c != null) spentUsd += c;
      if (!measured) {
        estimatedCalls++;
        if (c != null) estimatedUsd += c;
      }
      return spentUsd;
    },

    /** Reportable state. Always carries the cap so a figure cannot be read alone. */
    state() {
      return {
        enforcing,
        capUsd,
        model,
        priceSource: price?.source || null,
        priceable: !!price,
        spentUsd: Number(spentUsd.toFixed(6)),
        remainingUsd: enforcing ? Number(Math.max(0, capUsd - spentUsd).toFixed(6)) : null,
        calls,
        refusals,
        // Disclosure, not decoration. `spentUsd` is an UPPER BOUND to the
        // extent these are non-zero, and a reader has no way to know that
        // without being told.
        estimatedCalls,
        estimatedUsd: Number(estimatedUsd.toFixed(6)),
        fullyMeasured: estimatedCalls === 0,
      };
    },
  };
}

/** One-line summary; null when no ceiling is configured. */
export function renderCostCeiling(s) {
  if (!s || !s.enforcing) return null;
  if (!s.priceable) {
    return `LLM cost ceiling: ENFORCED but model '${s.model}' is unpriceable — ${s.refusals} call(s) refused, nothing spent.`;
  }
  // Say "at most" whenever any part of the figure is an estimate. The word is
  // the whole point: without it an upper bound reads as a measurement.
  const qualifier = s.fullyMeasured ? '' : 'at most ';
  const base = `LLM spend ${qualifier}$${s.spentUsd.toFixed(4)} of $${s.capUsd.toFixed(4)} cap across ${s.calls} call(s)`;
  const parts = [base];
  if (!s.fullyMeasured) {
    parts.push(
      `${s.estimatedCalls} of those call(s) reported no token usage, so their cost is ESTIMATED at the `
      + 'full permitted output length — the true spend is lower',
    );
  }
  if (s.refusals) {
    parts.push(`${s.refusals} call(s) REFUSED at the ceiling — those findings are unvalidated, not validated`);
  }
  return parts.join('; ') + '.';
}

export const _internals = { PRICES };
