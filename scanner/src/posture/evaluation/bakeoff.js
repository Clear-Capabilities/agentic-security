// Bake-off recipe: the manifest, the adapter contract and the claim guard (QA-008.AC02, QA-008.AC03).
//
// A bake-off compares this engine with other tools on one workload. The failure modes that make such a comparison worthless are
// all about what is silently different between the runs, so the recipe pins them in a manifest, and this module refuses to
// produce a comparative claim when any of them is not identical:
//
//   workload             the same target set, by digest, for every participant
//   scope                the same languages and families
//   provider and model   named per participant (an engine with no model says so)
//   verification         one standard for what counts as a confirmed defect
//   limits               the same time and spend ceilings
//   failures             a timeout or crash is a recorded failure, scored as a miss, never dropped
//
// Comparators are GENERIC SLOTS (`comparator-a`, `comparator-b`, ...). This repository names no other tool: the operator maps a
// slot to whatever they run. An adapter can declare itself `unavailable` (not installed, no licence, no provider access), and that
// participant is `not-evaluated`: it is not a zero, not a loss and not excluded quietly. It appears in the report with its
// reason. A comparative accuracy or cost claim exists only between participants that were actually evaluated on the identical
// workload under the identical standard, and only for a quantity both measured; otherwise the claim is withheld with the reasons.
//
// Scoring is delegated to comparison.js (CWE-only matching, intersection of completed entries), unchanged.
//
// Pure: no fs, no clock, no process execution. An adapter's `run` is supplied by the caller.

import { digestOf } from '../assurance/identity.js';
import { compareParticipants, scoreParticipant } from '../comparison.js';

const BAKEOFF_SCHEMA = 'agentic-security/bakeoff-manifest';
const ENGINE_SLOT = 'this-engine';
const SLOT_RE = /^(?:this-engine|comparator-[a-z])$/;
export const UNAVAILABLE_REASONS = Object.freeze(['not-installed', 'no-licence', 'no-provider-access', 'not-configured', 'platform-unsupported', 'operator-declined']);

const isObj = (x) => x && typeof x === 'object' && !Array.isArray(x);
const err = (path, message) => ({ code: 'BAD_MANIFEST', path, message });

/** @returns {{ok: boolean, errors: object[]}} */
export function validateBakeoffManifest(m) {
  const errors = [];
  if (!isObj(m)) return { ok: false, errors: [err('', 'manifest must be an object')] };
  if (m.schema !== BAKEOFF_SCHEMA) errors.push(err('schema', `schema must be ${BAKEOFF_SCHEMA}`));
  const w = m.workload;
  if (!isObj(w) || !Array.isArray(w.targetIds) || !w.targetIds.length) errors.push(err('workload.targetIds', 'name the target ids the workload consists of'));
  else {
    if (!/^sha256:[0-9a-f]{64}$/.test(w.workloadDigest || '')) errors.push(err('workload.workloadDigest', 'the workload is pinned by digest'));
    else if (w.workloadDigest !== workloadDigestOf(w)) errors.push(err('workload.workloadDigest', 'the digest does not match the targets and tree digests listed'));
  }
  if (!isObj(m.scope) || !Array.isArray(m.scope.languages) || !Array.isArray(m.scope.families)) errors.push(err('scope', 'declare the languages and families in scope'));
  if (!isObj(m.verification) || !m.verification.standard) errors.push(err('verification.standard', 'one verification standard must be named (what counts as a confirmed defect)'));
  const lim = m.limits;
  if (!isObj(lim) || !(lim.perTargetTimeoutMs > 0) || !(lim.wallClockMs > 0) || typeof lim.spendCeilingUsd !== 'number') errors.push(err('limits', 'perTargetTimeoutMs, wallClockMs and spendCeilingUsd are all required'));
  if (m.failurePolicy !== 'count-as-misses') errors.push(err('failurePolicy', 'failures are scored as misses; the only accepted policy is count-as-misses'));
  const ps = m.participants;
  if (!Array.isArray(ps) || ps.length < 2) errors.push(err('participants', 'a bake-off needs this engine and at least one comparator slot'));
  else {
    const seen = new Set();
    ps.forEach((p, i) => {
      if (!isObj(p) || !SLOT_RE.test(p.slot || '')) { errors.push(err(`participants[${i}].slot`, 'a slot is "this-engine" or "comparator-a".."comparator-z"; no product name belongs in a recipe')); return; }
      if (seen.has(p.slot)) errors.push(err(`participants[${i}].slot`, `duplicate slot ${p.slot}`));
      seen.add(p.slot);
      if (!isObj(p.provider) || !('model' in p.provider)) errors.push(err(`participants[${i}].provider`, 'name the provider and model, or {"model": null} for a tool that uses none'));
    });
    if (!seen.has(ENGINE_SLOT)) errors.push(err('participants', 'this-engine must be one of the participants'));
  }
  return { ok: errors.length === 0, errors };
}

/** The digest a workload is pinned by: its targets and their tree digests, nothing else. */
export function workloadDigestOf(workload) {
  const targets = Object.fromEntries((workload.targetIds || []).slice().sort().map((id) => [id, workload.treeDigests?.[id] ?? null]));
  return digestOf({ kind: 'bakeoff-workload', targets });
}

/**
 * Decide, per participant, whether it can be evaluated. `adapters` maps a slot to `{ available: boolean, reason?, run? }`.
 * A slot with no adapter, or an adapter that says it is unavailable, is `not-evaluated` with a typed reason.
 */
export function resolveParticipants(manifest, adapters = {}) {
  return manifest.participants.map((p) => {
    const a = adapters[p.slot];
    if (!a) return { slot: p.slot, provider: p.provider, state: 'not-evaluated', reason: 'not-configured', detail: 'no adapter was supplied for this slot' };
    if (a.available === false) {
      const reason = UNAVAILABLE_REASONS.includes(a.reason) ? a.reason : 'not-configured';
      return { slot: p.slot, provider: p.provider, state: 'not-evaluated', reason, detail: a.detail || null };
    }
    return { slot: p.slot, provider: p.provider, state: 'evaluated', reason: null, detail: null };
  });
}

/**
 * Judge a finished bake-off.
 * @param {object} o
 * @param {object} o.manifest   a valid manifest
 * @param {object[]} o.entries  [{id, cwe}] the workload's answer key
 * @param {Object<string, {workloadDigest: string, verificationStandard: string, results: object, costUsd?: number|null, completed?: number}>} o.runs  by slot, for evaluated participants
 * @param {Object<string, object>} [o.adapters]
 */
export function judgeBakeoff({ manifest, entries, runs = {}, adapters = {} }) {
  const v = validateBakeoffManifest(manifest);
  if (!v.ok) return { ok: false, errors: v.errors };
  const resolved = resolveParticipants(manifest, adapters);
  const participants = resolved.map((r) => {
    if (r.state !== 'evaluated') return r;
    const run = runs[r.slot];
    if (!run) return { ...r, state: 'not-evaluated', reason: 'no-run-recorded', detail: 'the adapter was available but no result was recorded' };
    return { ...r, run: { workloadDigest: run.workloadDigest, verificationStandard: run.verificationStandard, costUsd: run.costUsd ?? null } };
  });
  const evaluated = participants.filter((p) => p.state === 'evaluated');
  const withheld = [];
  for (const p of participants.filter((x) => x.state === 'not-evaluated')) withheld.push({ slot: p.slot, reason: `${p.slot} was not evaluated (${p.reason}); no comparison with it is made` });

  // Comparability: every evaluated participant must have run the manifest's workload under the manifest's standard.
  const mismatched = evaluated.filter((p) => p.run.workloadDigest !== manifest.workload.workloadDigest || p.run.verificationStandard !== manifest.verification.standard);
  for (const p of mismatched) withheld.push({ slot: p.slot, reason: `${p.slot} ran a different workload or verification standard than the manifest pins; its figures are not comparable` });
  const comparable = evaluated.filter((p) => !mismatched.includes(p));

  let comparison = null;
  const claims = [];
  if (comparable.length >= 2) {
    const parts = comparable.map((p) => ({ id: p.slot, results: runs[p.slot].results }));
    comparison = compareParticipants(entries, parts);
    if (!comparison.ok) { withheld.push({ slot: null, reason: `scoring refused: ${comparison.reason}` }); comparison = null; }
  } else {
    withheld.push({ slot: null, reason: 'fewer than two participants were evaluated on the identical workload; there is nothing to compare' });
  }
  // End-to-end view per participant: an entry it could not complete is a MISS here (the comparison above is over the shared
  // intersection and is labelled as such). Both views are published; neither replaces the other.
  const endToEnd = {};
  for (const p of comparable) {
    const sc = scoreParticipant(entries, runs[p.slot].results);
    let detected = 0; for (const v of sc.per.values()) if (v.detected) detected++;
    endToEnd[p.slot] = { entries: entries.length, completed: sc.completed, failedOrMissing: entries.length - sc.completed, detected, recallEndToEnd: entries.length ? detected / entries.length : null, rule: 'failures and missing results count as misses' };
  }
  if (comparison) {
    // An accuracy claim is a statement of the measured figures over the shared intersection; it never says "better" for a tie or an
    // interval overlap, and it needs every participant to have completed the shared entries.
    claims.push({ kind: 'accuracy', basis: 'shared-intersection', participants: comparable.map((p) => p.slot), statement: 'figures over the entries every compared participant completed; see the comparison table' });
    const costs = comparable.map((p) => ({ slot: p.slot, usd: runs[p.slot].costUsd ?? null }));
    if (costs.every((c) => typeof c.usd === 'number')) claims.push({ kind: 'cost', participants: costs.map((c) => c.slot), costsUsd: Object.fromEntries(costs.map((c) => [c.slot, c.usd])), statement: 'measured spend per participant under the same limits' });
    else withheld.push({ slot: null, reason: `no cost claim: ${costs.filter((c) => typeof c.usd !== 'number').map((c) => c.slot).join(', ')} did not report a measured cost` });
  }
  const report = {
    schema: 'agentic-security/bakeoff-report', ok: true, errors: [], manifestDigest: digestOf(manifest),
    workloadDigest: manifest.workload.workloadDigest, participants, comparison, endToEnd, claims, withheld,
    superiority: 'none claimed',
    note: 'a participant that was not evaluated is reported as such; it is never a zero, a loss or a silent omission',
  };
  report.reportDigest = digestOf({ ...report, reportDigest: undefined });
  return report;
}
