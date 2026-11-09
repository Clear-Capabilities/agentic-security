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
export function recordVerdict(finding, { verifierId, lens, verdict, reason, evidence } = {}) {
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
    ...(evidence && typeof evidence === 'object' ? { evidence: _evidence(evidence) } : {}),
  };
  const list = finding.verification.verdicts;
  const i = list.findIndex(v => v.verifierId === entry.verifierId && v.lens === entry.lens);
  if (i >= 0) list[i] = entry; else list.push(entry);
  return { ok: true, recorded: entry };
}

// Threat-model PRD FR-04.3 (TM-06): what a verdict rests on. Votes that share an observation, a generator or a lineage are ONE piece of
// evidence however many lenses they come through; a verdict with none declared counts as its verifier's own. `kind` says what sort of
// evidence it is: 'effect' (an observed effect), 'deterministic' (a check of the code itself) or 'reasoning' (an argument, a model).
const EVIDENCE_KINDS = new Set(['effect', 'deterministic', 'reasoning']);
function _evidence(e) {
  const out = {};
  for (const k of ['observationId', 'generator', 'lineage']) if (e[k]) out[k] = String(e[k]).slice(0, 120);
  if (EVIDENCE_KINDS.has(e.kind)) out.kind = e.kind;
  return out;
}
function _groupKey(v) {
  const e = v.evidence || {};
  return e.observationId ? `observation:${e.observationId}` : e.lineage ? `lineage:${e.lineage}` : e.generator ? `generator:${e.generator}` : `verifier:${v.verifierId}`;
}

/**
 * Majority across INDEPENDENT evidence groups (threat-model FR-04.3). Each group (a shared observation, generator or lineage, else one
 * verifier) has one vote, the majority of its own verdicts; two lenses from one verifier are one vote. Ties, including "no verdicts at
 * all", are 'undecided'. The per-lens counts (`upheld`, `refuted`, `undecided`) and `lenses` are kept for compatibility and for the
 * reviewer. `conflict` is true when independent groups disagree. `refutationAuthority` says whether the refutation could remove a
 * critical finding from the actionable queue: 'sufficient' only with no conflict and at least one refuting group backed by effect or
 * deterministic evidence; a correlated majority or reasoning alone is 'advisory'. A generator that produced the finding cannot
 * corroborate it.
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
  const producer = finding && finding.verification && finding.verification.producer;
  const groups = new Map();
  let selfAuthored = 0;
  for (const v of list) {
    if (!v || !VERIFICATION_VERDICTS.includes(v.verdict)) continue;
    if (producer && v.evidence && v.evidence.generator && `detector:${v.evidence.generator}` === producer) { selfAuthored++; continue; }
    const k = _groupKey(v);
    const g = groups.get(k) || { key: k, upheld: 0, refuted: 0, undecided: 0, kinds: new Set(), lenses: new Set() };
    g[v.verdict]++; if (v.evidence && v.evidence.kind) g.kinds.add(v.evidence.kind); g.lenses.add(String(v.lens));
    groups.set(k, g);
  }
  const vote = (g) => (g.upheld > g.refuted ? 'upheld' : g.refuted > g.upheld ? 'refuted' : 'undecided');
  const independent = { upheld: 0, refuted: 0, undecided: 0, groups: groups.size };
  for (const g of groups.values()) independent[vote(g)]++;
  let verdict = 'undecided';
  if (independent.upheld > independent.refuted) verdict = 'upheld';
  else if (independent.refuted > independent.upheld) verdict = 'refuted';
  const conflict = independent.upheld > 0 && independent.refuted > 0;
  const strongRefuter = [...groups.values()].some((g) => vote(g) === 'refuted' && (g.kinds.has('effect') || g.kinds.has('deterministic')));
  const refutationAuthority = verdict !== 'refuted' ? 'none' : (!conflict && strongRefuter ? 'sufficient' : 'advisory');
  return {
    verdict, upheld, refuted, undecided, lenses: [...lenses].sort(),
    independent, conflict, refutationAuthority, ...(selfAuthored ? { selfAuthoredExcluded: selfAuthored } : {}),
    groups: [...groups.values()].map((g) => ({ key: g.key, vote: vote(g), lenses: [...g.lenses].sort(), kinds: [...g.kinds].sort() })).sort((a, b) => a.key.localeCompare(b.key)),
  };
}

/** Whether a refuted consensus may take a finding of this severity out of the actionable queue. Critical needs sufficient authority. */
export function refutationRemoves(finding, consensus = consensusOf(finding)) {
  if (!consensus || consensus.verdict !== 'refuted') return false;
  if (finding && finding.severity === 'critical') return consensus.refutationAuthority === 'sufficient';
  return true;
}
