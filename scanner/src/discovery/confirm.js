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

// WHEN A TAINT FINDING CORROBORATES A CANDIDATE. A taint finding near the cited line proves that tainted data reaches SOME
// modelled sink there; it corroborates the candidate only when that sink is the kind of weakness the candidate claims. The
// classes below group the CWEs the taint engine reports with the CWE each lens claims; a pair corroborates when both fall in
// the same class. A lens whose claim is not a data-flow-to-sink weakness (business logic, feature abuse, chained, wildcard:
// CWE-840, 799, 1173, 710) is in no class and is never corroborated by a taint hit, because a flow to an unrelated sink says
// nothing about it. Measured reason for the rule: a refutation panel voted 3-0 against "Potential Vulnerability in Anthropic
// API" (wildcard lens) and the candidate survived as confirmed because a SQL-injection taint finding sat on the same line.
const CORROBORATION_CLASSES = Object.freeze({
  // injection: the lens brief names SQL, shell, template, XPath, LDAP and deserialization
  injection: ['CWE-74', 'CWE-77', 'CWE-78', 'CWE-79', 'CWE-80', 'CWE-88', 'CWE-89', 'CWE-90', 'CWE-91', 'CWE-93', 'CWE-94', 'CWE-95', 'CWE-96', 'CWE-97', 'CWE-113', 'CWE-117', 'CWE-502', 'CWE-564', 'CWE-643', 'CWE-652', 'CWE-917', 'CWE-943', 'CWE-1236', 'CWE-1336'],
  'access-control': ['CWE-284', 'CWE-285', 'CWE-639', 'CWE-862', 'CWE-863', 'CWE-915'],
  crypto: ['CWE-295', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-329', 'CWE-330', 'CWE-331', 'CWE-338', 'CWE-347', 'CWE-759', 'CWE-760', 'CWE-916'],
});
const CLASS_OF = new Map(Object.entries(CORROBORATION_CLASSES).flatMap(([cls, cwes]) => cwes.map((c) => [c, cls])));

/** The corroboration class of a CWE, or null when a taint finding cannot corroborate a claim of that CWE. */
function corroborationClass(cwe) {
  return CLASS_OF.get(String(cwe || '').toUpperCase().trim()) || null;
}

/** Does a taint finding with CWE `findingCwe` corroborate a candidate claiming `candidateCwe`? */
export function taintCorroborates(candidateCwe, findingCwe) {
  const a = corroborationClass(candidateCwe);
  return a !== null && a === corroborationClass(findingCwe);
}

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
