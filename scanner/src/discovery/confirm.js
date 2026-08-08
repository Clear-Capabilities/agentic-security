//
// Route every model-proposed candidate back through the deterministic layer.
//
// WHY THIS EXISTS. A hunter's output is a hypothesis. The engine underneath it
// can already decide, for a given file and line, whether tainted data reaches a
// modelled sink there. Asking it turns "the model thinks so" into "the model
// thinks so AND the taint engine agrees", which is a materially stronger claim
// than either layer makes alone.
//
// THE ASYMMETRY IS DELIBERATE. Confirmation raises standing; the absence of
// confirmation NEVER lowers it below `unconfirmed` and is never recorded as a
// refutation. The taint engine models a subset of the program — an
// unconfirmed candidate may be a real bug in a construct the engine does not
// model, and calling that a false positive would launder a coverage gap into a
// verdict. Refutation is `disprove.js`'s job, and it must be argued, not
// inferred from silence.
export const CONFIRMATION_TIERS = Object.freeze(['taint-confirmed', 'sink-adjacent', 'unconfirmed']);

function unconfirmed(probedBy, reason) {
  return { tier: 'unconfirmed', evidence: null, probedBy, reason: reason || null };
}

export async function confirmCandidate(candidate, opts = {}) {
  const probe = typeof opts.taintProbe === 'function' ? opts.taintProbe : null;
  if (!probe) return { ...candidate, confirmation: unconfirmed(null, 'no taintProbe supplied') };

  let res;
  try {
    res = await probe(candidate);
  } catch (err) {
    return { ...candidate, confirmation: unconfirmed('taintProbe', `probe failed: ${err?.message || String(err)}`) };
  }
  if (!res) return { ...candidate, confirmation: unconfirmed('taintProbe', null) };
  if (!CONFIRMATION_TIERS.includes(res.tier)) {
    return { ...candidate, confirmation: unconfirmed('taintProbe', `unknown tier: ${res.tier}`) };
  }
  return {
    ...candidate,
    confirmation: { tier: res.tier, evidence: res.evidence ?? null, probedBy: 'taintProbe', reason: null },
  };
}

export async function confirmAll(candidates, opts = {}) {
  const out = [];
  for (const c of candidates || []) out.push(await confirmCandidate(c, opts));
  return out;
}
