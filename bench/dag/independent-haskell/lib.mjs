import crypto from 'node:crypto';
import { wilson } from '../../_lib/wilson.mjs';
import { cohen } from '../../_lib/agreement.mjs';

// ── the single-labeler record (UNCHANGED) ────────────────────────────────────
// labels.json holds 8 fields per label and one verdict, and its digest is computed over exactly those 8 fields. Nothing below may change
// `canonicalLabels` or `digestOf`: the second-labeler capability is added BESIDE this record (labels-panel.json), so extending the schema cannot
// invalidate the sealed set. scanner/test/bench-independent-haskell-panel.test.js pins the digest of a fixed label list to an independent
// re-implementation of this canonical form.
export const canonicalLabels = (labels) => [...labels].sort((a, b) => a.id.localeCompare(b.id)).map(l => ({
  id: l.id, project: l.project, language: l.language, file: l.file, line: l.line, vuln: l.vuln, verdict: l.verdict, evidence: l.evidence }));
export const digestOf = (labels) => crypto.createHash('sha256').update(JSON.stringify(canonicalLabels(labels))).digest('hex');
// One Wilson for the benches (bench/_lib/wilson.mjs). Same signature as before: [lower, upper] or null for n = 0.
export { wilson };

// ── the two-labeler panel (optional, additive) ───────────────────────────────
// One LLM labeler reading source cannot say how far its verdicts depend on the labeler. A panel adds a second, blind labeler of a DIFFERENT model,
// reports their agreement (percent and Cohen's kappa), tells "the labelers disagreed" apart from "one labeler was unsure" (the single record collapses
// both into `ambiguous`), and settles the rest in a recorded third pass by an adjudicator who is neither labeler. The rules are borrowed from
// scanner/src/posture/evaluation/labels.js (a proposer cannot be its own reviewer; independence is asserted, not assumed), not its schema.
//
// labels-panel.json:
//   { panelVersion: 2, baseLabelsDigest, labelers: [{labelerId, model, blind: true}], adjudicator: {labelerId, model} | null, panelDigest,
//     sites: [{ id, project, language, file, line, vuln, votes: [{labelerId, verdict: 'tp'|'fp'|'unsure', evidence}], status, adjudication: {verdict, evidence} | null, final }] }
//   status: agreed | disagreed | one-unsure | all-unsure     (derived from the votes; stored for readers, re-derived by `validatePanel`)
//   final:  tp | fp | ambiguous                              (agreed: the shared verdict; otherwise the adjudication, else ambiguous)
export const PANEL_VERSION = 2;
export const VOTE_VERDICTS = Object.freeze(['tp', 'fp', 'unsure']);
export const FINAL_VERDICTS = Object.freeze(['tp', 'fp', 'ambiguous']);

/** The single record's verdict as a panel vote: its `ambiguous` could mean "unsure" or "disagreed", and the single record cannot say which, so it is `unsure`. */
export const voteOfBaseVerdict = (v) => (v === 'tp' || v === 'fp' ? v : 'unsure');

export function statusOfVotes(votes) {
  const decided = votes.filter((v) => v.verdict !== 'unsure').map((v) => v.verdict);
  const unsure = votes.length - decided.length;
  if (unsure === votes.length) return 'all-unsure';
  if (new Set(decided).size > 1) return 'disagreed';
  return unsure ? 'one-unsure' : 'agreed';
}
export const finalOf = (status, votes, adjudication) => {
  if (status === 'agreed') return votes[0].verdict;
  return adjudication && (adjudication.verdict === 'tp' || adjudication.verdict === 'fp') ? adjudication.verdict : 'ambiguous';
};

export function canonicalPanel(panel) {
  return {
    panelVersion: panel.panelVersion, baseLabelsDigest: panel.baseLabelsDigest,
    labelers: panel.labelers.map((l) => ({ labelerId: l.labelerId, model: l.model, blind: l.blind === true })),
    adjudicator: panel.adjudicator ? { labelerId: panel.adjudicator.labelerId, model: panel.adjudicator.model } : null,
    sites: [...panel.sites].sort((a, b) => a.id.localeCompare(b.id)).map((s) => ({
      id: s.id, project: s.project, language: s.language, file: s.file, line: s.line, vuln: s.vuln,
      votes: [...s.votes].sort((a, b) => a.labelerId.localeCompare(b.labelerId)).map((v) => ({ labelerId: v.labelerId, verdict: v.verdict, evidence: v.evidence })),
      adjudication: s.adjudication ? { verdict: s.adjudication.verdict, evidence: s.adjudication.evidence } : null,
    })),
  };
}
export const panelDigestOf = (panel) => crypto.createHash('sha256').update(JSON.stringify(canonicalPanel(panel))).digest('hex');

const nonEmpty = (s) => typeof s === 'string' && s.trim().length > 0;

/**
 * Structural and independence checks. `base` (the single record's labels) is optional: when given, every panel site must be a base site with the
 * same identity fields, and the base labeler's vote, if the panel carries it, must be the one the base verdict maps to.
 * @returns {{ok: boolean, errors: string[]}}
 */
export function validatePanel(panel, base = null) {
  const errors = [];
  const err = (m) => errors.push(m);
  if (!panel || panel.panelVersion !== PANEL_VERSION) return { ok: false, errors: [`panelVersion must be ${PANEL_VERSION}`] };
  const labelers = Array.isArray(panel.labelers) ? panel.labelers : [];
  if (labelers.length < 2) err('a panel needs at least two labelers');
  const ids = new Set(); const models = new Set();
  for (const l of labelers) {
    if (!nonEmpty(l.labelerId) || !nonEmpty(l.model)) { err('every labeler needs a labelerId and a model'); continue; }
    if (ids.has(l.labelerId)) err(`duplicate labelerId ${l.labelerId}`);
    if (models.has(l.model)) err(`labelers ${l.labelerId} and another use the same model (${l.model}): the panel is not independent`);
    if (l.blind !== true) err(`labeler ${l.labelerId} is not declared blind (it must not see another labeler's verdicts before voting)`);
    ids.add(l.labelerId); models.add(l.model);
  }
  const adj = panel.adjudicator || null;
  if (adj) {
    if (!nonEmpty(adj.labelerId) || !nonEmpty(adj.model)) err('the adjudicator needs a labelerId and a model');
    else if (ids.has(adj.labelerId)) err(`the adjudicator ${adj.labelerId} is also a labeler: a proposer cannot settle its own disagreement`);
    else if (models.has(adj.model)) err(`the adjudicator uses the same model (${adj.model}) as a labeler`);
  }
  const baseById = base ? new Map(base.map((b) => [b.id, b])) : null;
  const seen = new Set();
  for (const s of Array.isArray(panel.sites) ? panel.sites : []) {
    const where = `site ${s && s.id}`;
    if (!s || !nonEmpty(s.id)) { err('a site without an id'); continue; }
    if (seen.has(s.id)) err(`${where}: duplicated`);
    seen.add(s.id);
    const votes = Array.isArray(s.votes) ? s.votes : [];
    const voters = votes.map((v) => v.labelerId);
    if (new Set(voters).size !== voters.length) err(`${where}: a labeler voted twice`);
    for (const id of ids) if (!voters.includes(id)) err(`${where}: no vote from ${id}`);
    for (const v of votes) {
      if (!ids.has(v.labelerId)) err(`${where}: a vote from ${v.labelerId}, who is not on the panel`);
      if (!VOTE_VERDICTS.includes(v.verdict)) err(`${where}: bad vote verdict ${v.verdict}`);
      if (!nonEmpty(v.evidence)) err(`${where}: the vote of ${v.labelerId} carries no evidence`);
    }
    if (votes.length && votes.every((v) => VOTE_VERDICTS.includes(v.verdict))) {
      const status = statusOfVotes(votes);
      if (s.status !== status) err(`${where}: status ${s.status} does not follow from the votes (${status})`);
      if (s.adjudication) {
        if (!adj) err(`${where}: an adjudication with no adjudicator on the panel`);
        if (status === 'agreed') err(`${where}: the labelers agreed; an adjudication cannot override agreement`);
        if (!['tp', 'fp', 'ambiguous'].includes(s.adjudication.verdict)) err(`${where}: bad adjudication verdict`);
        if (!nonEmpty(s.adjudication.evidence)) err(`${where}: the adjudication carries no evidence`);
      }
      const final = finalOf(status, votes, s.adjudication || null);
      if (s.final !== final) err(`${where}: final ${s.final} does not follow from the votes and the adjudication (${final})`);
    }
    if (baseById) {
      const b = baseById.get(s.id);
      if (!b) err(`${where}: not a site of the single-labeler record`);
      else {
        for (const f of ['project', 'language', 'file', 'line', 'vuln']) if (b[f] !== s[f]) err(`${where}: ${f} differs from the single-labeler record`);
      }
    }
  }
  if (baseById) for (const id of baseById.keys()) if (!seen.has(id)) err(`site ${id} of the single-labeler record is missing from the panel`);
  if (panel.panelDigest !== undefined && panel.panelDigest !== panelDigestOf(panel)) err('panelDigest does not match the panel (edited without re-digest)');
  return { ok: errors.length === 0, errors };
}

/** Assemble a panel from its parts. Does not read or write files. `drafts`: {labelerId: [{i, v, e}]} indexed into `sample`; `base`: the single record's labels (optional, becomes labeler `baseLabelerId`). */
export function buildPanel({ sample, labelers, drafts, base = null, baseLabelerId = null, adjudicator = null, adjudication = null, baseLabelsDigest = null }) {
  const sites = new Map();
  const identity = (s) => ({ project: s.project, language: s.language || 'haskell', file: s.file, line: s.line, vuln: s.vuln });
  const idOf = (s) => crypto.createHash('sha256').update([s.project, s.file, s.line, s.vuln].join('|')).digest('hex').slice(0, 12);
  for (const s of sample) sites.set(idOf(s), { id: idOf(s), ...identity(s), votes: [], adjudication: null });
  for (const [labelerId, rows] of Object.entries(drafts || {})) {
    if (rows.length !== sample.length) throw new Error(`${rows.length} verdicts from ${labelerId} for ${sample.length} sampled sites`);
    for (const r of rows) {
      const s = sample[r.i];
      if (!s) throw new Error(`${labelerId}: verdict for an index outside the sample (${r.i})`);
      if (!VOTE_VERDICTS.includes(r.v)) throw new Error(`${labelerId}: bad verdict ${r.v} at ${r.i}`);
      sites.get(idOf(s)).votes.push({ labelerId, verdict: r.v, evidence: r.e });
    }
  }
  if (base && baseLabelerId) for (const b of base) { const s = sites.get(b.id); if (s) s.votes.push({ labelerId: baseLabelerId, verdict: voteOfBaseVerdict(b.verdict), evidence: b.evidence }); }
  for (const r of adjudication || []) {
    const s = sample[r.i];
    if (!s) throw new Error(`adjudication for an index outside the sample (${r.i})`);
    if (!FINAL_VERDICTS.includes(r.v)) throw new Error(`bad adjudication verdict ${r.v} at ${r.i}`);
    sites.get(idOf(s)).adjudication = { verdict: r.v, evidence: r.e };
  }
  const out = [...sites.values()].map((s) => {
    const status = statusOfVotes(s.votes);
    return { ...s, status, final: finalOf(status, s.votes, s.adjudication) };
  });
  const panel = { panelVersion: PANEL_VERSION, baseLabelsDigest, labelers, adjudicator, sites: out };
  panel.panelDigest = panelDigestOf(panel);
  return panel;
}

/**
 * Agreement between every pair of labelers: percent agreement and Cohen's kappa over {tp, fp, unsure}, the same over the sites BOTH decided
 * (tp / fp), and the four-way status counts that keep "disagreed" apart from "one was unsure". Plus the final tallies after adjudication.
 */
export function agreementReport(panel) {
  const ids = panel.labelers.map((l) => l.labelerId).sort();
  const vote = (s, id) => (s.votes.find((v) => v.labelerId === id) || {}).verdict;
  const pairs = [];
  for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) {
    const all = panel.sites.map((s) => [vote(s, ids[i]), vote(s, ids[j])]);
    const decided = all.filter(([a, b]) => a !== 'unsure' && b !== 'unsure');
    pairs.push({
      labelers: [ids[i], ids[j]],
      threeWay: cohen(all, ['tp', 'fp', 'unsure']),
      decidedOnly: { ...cohen(decided, ['tp', 'fp']), sites: decided.length, excludedBecauseUnsure: all.length - decided.length },
    });
  }
  const statusCounts = { agreed: 0, disagreed: 0, 'one-unsure': 0, 'all-unsure': 0 };
  const finalCounts = { tp: 0, fp: 0, ambiguous: 0 };
  let adjudicated = 0; let unsettled = 0;
  for (const s of panel.sites) {
    statusCounts[s.status]++;
    finalCounts[s.final]++;
    if (s.status !== 'agreed') { if (s.adjudication) adjudicated++; if (s.final === 'ambiguous') unsettled++; }
  }
  const nonAgreed = panel.sites.length - statusCounts.agreed;
  return {
    sites: panel.sites.length, labelers: panel.labelers.map((l) => ({ labelerId: l.labelerId, model: l.model })), adjudicator: panel.adjudicator ? { labelerId: panel.adjudicator.labelerId, model: panel.adjudicator.model } : null,
    pairs, statusCounts, nonAgreed, adjudicated, unsettledAfterAdjudication: unsettled, finalCounts,
    note: 'kappa corrects raw agreement for chance, and is undefined or unstable when one category dominates (percent agreement and the matrix are reported beside it). "disagreed" means two labelers decided differently; "one-unsure"/"all-unsure" mean a labeler declined to decide: they are different findings about the label, and the single-labeler record cannot tell them apart.',
  };
}
