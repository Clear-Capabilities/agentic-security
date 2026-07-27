// R7 — adversarial verification with ENFORCED SEPARATION.
//
// The falsification pass (`falsification.js`) already tries to DISPROVE a
// finding. What it could not previously do is *prove* that whoever checked the
// finding was not whoever produced it. That guarantee is what this module adds,
// plus a recorded multi-perspective verdict for contested findings.
//
// The property that matters: a verifier is structurally unable to rubber-stamp
// its own finding.
//   - `recordProducer` stamps who produced the finding, WRITE-ONCE. A later
//     party cannot re-stamp itself as the producer to manufacture separation.
//   - `assertSeparation` refuses when the verifier id equals the recorded
//     producer id, and FAILS CLOSED when no producer was recorded at all
//     (separation that cannot be established is not separation).
//   - `recordVerdict` runs that check itself, so there is no code path that
//     records a verdict without it. One verifier gets one vote per lens: a
//     re-vote replaces the previous one rather than stuffing the ballot.
//
// RECALL-PRESERVING, same precedent as `falsification.js` and
// `dataflow/proof-gate.js`: nothing here ever removes a finding and nothing
// here ever touches `severity`. A `refuted` consensus is a triage signal, not
// a deletion — absence of proof is not proof of absence.
//
// NO THROWING (posture/CLAUDE.md convention): every entry point returns a
// refusal object `{ ok:false, refused:true, reason }` instead of throwing, so
// an annotator can call it inside the engine's pipeline without a guard.

export const VERIFICATION_VERDICTS = ['upheld', 'refuted', 'undecided'];

// Verifier ids are namespaced so they can never collide with a producer id.
export const VERIFIER_FALSIFICATION = 'verifier:falsification';
export const VERIFIER_LLM_REVIEW = 'verifier:llm-review';

function _refuse(reason) { return { ok: false, refused: true, reason }; }

/** Namespaced id for whoever produced a finding — derived from its detector. */
export function producerIdOf(finding) {
  const p = finding && finding.parser ? String(finding.parser) : 'unknown';
  return `detector:${p}`;
}

/**
 * Stamp who produced this finding. Write-once: a second call with a different
 * id is REFUSED (this is what stops a verifier reassigning provenance to
 * itself). A repeat call with the same id is a no-op success.
 */
export function recordProducer(finding, producerId) {
  if (!finding || typeof finding !== 'object') return _refuse('no finding');
  const id = producerId ? String(producerId) : '';
  if (!id) return _refuse('no producer id');
  if (!finding.verification || typeof finding.verification !== 'object') {
    finding.verification = { producer: id, verdicts: [] };
    return { ok: true, producer: id };
  }
  if (!finding.verification.producer) {
    finding.verification.producer = id;
    if (!Array.isArray(finding.verification.verdicts)) finding.verification.verdicts = [];
    return { ok: true, producer: id };
  }
  if (finding.verification.producer === id) return { ok: true, producer: id };
  return _refuse(`producer already recorded as "${finding.verification.producer}" — write-once`);
}

/**
 * The separation check. `{ ok:true, producer }` when the verifier is a party
 * other than the producer; a refusal otherwise. Fails closed when no producer
 * has been recorded.
 */
export function assertSeparation(finding, verifierId) {
  if (!finding || typeof finding !== 'object') return _refuse('no finding');
  const vid = verifierId ? String(verifierId) : '';
  if (!vid) return _refuse('no verifier id');
  const producer = finding.verification && finding.verification.producer;
  if (!producer) {
    return _refuse('no producer recorded — separation cannot be established');
  }
  if (producer === vid) {
    return _refuse(`verifier "${vid}" is the producer of this finding — separation violated`);
  }
  return { ok: true, producer };
}

/**
 * Record one verifier's verdict from one perspective (`lens`, e.g.
 * 'reachability' | 'control-flow' | 'data-shape'). Refuses — recording
 * nothing — when separation fails or the verdict is not one of
 * VERIFICATION_VERDICTS. Never touches severity, never removes anything.
 */
export function recordVerdict(finding, { verifierId, lens, verdict, reason } = {}) {
  if (!finding || typeof finding !== 'object') return _refuse('no finding');
  if (!lens) return _refuse('no lens');
  if (!VERIFICATION_VERDICTS.includes(verdict)) {
    return _refuse(`unknown verdict "${verdict}" — expected one of ${VERIFICATION_VERDICTS.join('|')}`);
  }
  const sep = assertSeparation(finding, verifierId);
  if (!sep.ok) return sep;

  const entry = {
    verifierId: String(verifierId),
    lens: String(lens),
    verdict,
    ...(reason ? { reason: String(reason) } : {}),
  };
  const list = finding.verification.verdicts;
  const i = list.findIndex(v => v.verifierId === entry.verifierId && v.lens === entry.lens);
  if (i >= 0) list[i] = entry; else list.push(entry);
  return { ok: true, recorded: entry };
}

/**
 * Majority across every recorded verdict. Ties — including "no verdicts at
 * all" — are 'undecided'. `lenses` is the sorted set of perspectives that
 * actually voted, so a caller can see whether a verdict is one-eyed or a panel.
 */
export function consensusOf(finding) {
  const list = (finding && finding.verification && Array.isArray(finding.verification.verdicts))
    ? finding.verification.verdicts : [];
  let upheld = 0, refuted = 0, undecided = 0;
  const lenses = new Set();
  for (const v of list) {
    if (!v) continue;
    if (v.lens) lenses.add(String(v.lens));
    if (v.verdict === 'upheld') upheld++;
    else if (v.verdict === 'refuted') refuted++;
    else if (v.verdict === 'undecided') undecided++;
  }
  let verdict = 'undecided';
  if (upheld > refuted) verdict = 'upheld';
  else if (refuted > upheld) verdict = 'refuted';
  return { verdict, upheld, refuted, undecided, lenses: [...lenses].sort() };
}
