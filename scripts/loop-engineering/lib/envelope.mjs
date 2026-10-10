// Spend accounting beyond the model worker (LOOP-002): the separate provider/infrastructure envelope, and the upper-bound reserve that
// stands in for a charge nobody reported. Pure functions over the budgets object the controller persists in state.json.
//
//   * The ENVELOPE is a second, separately metered budget. It is off unless the profile enables it AND carries a preauthorization
//     (validateBoundsConfig refuses an enabled envelope without one). A controller-run step that declares a cost (`costUsd`, or
//     `costUnknown: true`) is a paid step: it is charged to the envelope BEFORE it runs, and is not run at all when the envelope is off or
//     the charge would pass the cap. The model spend cap (claudeBudgetUsd) is a different budget and is never used to pay for these.
//   * An UNKNOWN charge is never zero. A paid step that declares `costUnknown`, or a model attempt whose stream reported no cost, is charged
//     the profile's defined upper-bound reserve. Once billing is unknown, a further paid step needs the reserve to fit under the cap.

export const emptyProvider = () => ({ usedUsd: 0, charges: [], stops: [] });

/** The envelope as the controller enforces it (a profile with no block, or a disabled one, has enabled:false). */
export function envelopeConfig(profile) {
  const E = profile?.providerEnvelope;
  if (!E) return { present: false, enabled: false, capUsd: 0, unknownBillingReserveUsd: 0 };
  return { present: true, enabled: E.enabled === true && !!E.preauthorization, capUsd: E.capUsd, unknownBillingReserveUsd: E.unknownBillingReserveUsd, preauthorizedBy: E.preauthorization?.by || null };
}

/** The declared cost of a step: { paid:false } for a free step, else { paid:true, usd, unknown }. */
export function stepCost(step, cfg) {
  if (step.costUnknown === true) return { paid: true, usd: cfg.unknownBillingReserveUsd, unknown: true };
  if (typeof step.costUsd === 'number' && step.costUsd > 0) return { paid: true, usd: step.costUsd, unknown: false };
  return { paid: false, usd: 0, unknown: false };
}

/**
 * Decide and record the charge for one step. Mutates `provider` (the budgets.provider object).
 * -> { ok:true, charged } | { ok:false, reason, kind: 'not-enabled' | 'exhausted' }. A refused step is recorded in provider.stops.
 */
export function chargeEnvelope(provider, cfg, step, { at = new Date().toISOString() } = {}) {
  const c = stepCost(step, cfg);
  if (!c.paid) return { ok: true, charged: 0, paid: false };
  const refuse = (kind, reason) => { provider.stops.push({ at, step: step.id, kind, usd: c.usd, reason }); return { ok: false, kind, reason, paid: true, usd: c.usd }; };
  if (!cfg.enabled) return refuse('not-enabled', `step ${step.id} declares a cost of $${c.usd}${c.unknown ? ' (unknown billing, reserve charged)' : ''}, but the provider/infrastructure envelope is not enabled and preauthorized in the profile, so the paid step was not run`);
  // once the envelope has refused a step for want of room it is exhausted: later, smaller steps do not get to slip in behind it
  if (provider.stops.some((x) => x.kind === 'exhausted') || provider.usedUsd + c.usd > cfg.capUsd + 1e-9) return refuse('exhausted', `step ${step.id} would charge $${c.usd}${c.unknown ? ' (unknown billing, reserve charged)' : ''} against an envelope of $${cfg.capUsd} with $${provider.usedUsd.toFixed(2)} already used, so the paid step was not run`);
  provider.usedUsd = Number((provider.usedUsd + c.usd).toFixed(6));
  provider.charges.push({ at, step: step.id, usd: c.usd, unknown: c.unknown });
  return { ok: true, charged: c.usd, paid: true, unknown: c.unknown };
}

/**
 * The charge for one model attempt.
 *   reportedUsd  the figure the stream reported at the end (number) or null
 *   runningUsd   the largest running figure seen before a kill (0 if none)
 *   tokenUsd     a pessimistic token-derived figure (0 when no usage was seen either)
 *   reserveUsd   limits.unknownBillingReserveUsd, or null for a profile that predates it
 * -> { usd, estimated, reserve }. Without a reserve the legacy rules apply; with one, an unreported figure is charged at least the
 * reserve, so an attempt with no cost and no usage is never zero.
 */
export function modelCharge({ reportedUsd, runningUsd = 0, tokenUsd = 0, reserveUsd = null }) {
  if (typeof reportedUsd === 'number') return { usd: reportedUsd, estimated: false, reserve: false };
  const base = runningUsd > 0 ? runningUsd : tokenUsd;
  if (reserveUsd == null) return { usd: base, estimated: true, reserve: false };
  return { usd: Math.max(base, reserveUsd), estimated: true, reserve: true };
}
