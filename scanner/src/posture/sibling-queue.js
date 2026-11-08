// Sibling review queue for a confirmed root cause (threat-model PRD FR-05.3, AC-05C).
//
// The root-cause sweep (`root-cause-sweep.js`) finds structural siblings of a confirmed finding and counts them exactly. Its
// `mitigated` count means only that a DETECTOR already reports a finding at that location: detector coverage, not a repair. This
// queue turns one sweep into reviewable items, each with the predicate that discovered it and a binding to its source line, and keeps
// six states apart:
//
//   detector-reported         a detector reports this location (the sweep's legacy `mitigated`)
//   candidate                 a structural sibling nobody has looked at
//   independently-confirmed   a reviewer or verifier other than the producer confirmed it
//   repair-proposed           a fix has been proposed for it
//   repaired                  a fix has been applied to it
//   verified                  a replay-verified repair record for THIS sibling (its own hypothesis id) exists
//
// A state is raised only by evidence that names the sibling by its id. A verification record for one corrected sibling never closes
// another, however similar. Totals come from the sweep's exact counts; the per-state counts cover the sampled items, and `unsampled`
// is what the sample left out, so the numbers reconcile when the sweep capped its list.
import crypto from 'node:crypto';
import { validateVerificationRecord } from './assurance/verification-record.js';

const SIBLING_STATES = Object.freeze(['detector-reported', 'candidate', 'independently-confirmed', 'repair-proposed', 'repaired', 'verified']);
const RANK = Object.fromEntries(SIBLING_STATES.map((s, i) => [s, i]));
const MAX_QUEUE = 100;

/** The stable id of one sibling: its file, line and the exact text of the matched line. */
export const siblingId = (file, line, snippet) => `sibling:${crypto.createHash('sha256').update(`${file}\u0000${line}\u0000${snippet}`).digest('hex').slice(0, 24)}`;

function raise(item, state, basis) { if (RANK[state] > RANK[item.state]) { item.state = state; item.basis = basis; } }

/**
 * @param {object} sweep    one entry of `sweepRootCauses(...).sweeps`
 * @param {{evidence?: {siblingId:string, kind:'confirmation'|'repair-proposal'|'repair'|'verification', by?:string, record?:object}[], producer?:string}} o
 */
export function buildSiblingQueue(sweep, { evidence = [], producer = null } = {}) {
  if (!sweep || typeof sweep !== 'object') return { ok: false, reason: 'no sweep' };
  const items = (sweep.instances || []).slice(0, MAX_QUEUE).map((m) => ({
    id: siblingId(m.file, m.line, m.snippet), file: m.file, line: m.line,
    discovery: { fromFindingId: sweep.fromFindingId ?? null, sinkPattern: sweep.sinkPattern ?? null, sourcePattern: sweep.sourcePattern ?? null },
    state: m.status === 'mitigated-or-known' ? 'detector-reported' : 'candidate',
    basis: m.status === 'mitigated-or-known' ? 'a detector reports a finding at this location (detector coverage, not a repair)' : 'structural sibling of the confirmed root cause',
    rejected: [],
  }));
  const byId = new Map(items.map((it) => [it.id, it]));
  for (const e of evidence) {
    const it = e && byId.get(e.siblingId);
    if (!it) continue; // evidence for a sibling not in this queue changes nothing here
    if (e.kind === 'confirmation') {
      if (!e.by || (producer && e.by === producer)) { it.rejected.push({ kind: e.kind, reason: 'a confirmation must come from a party other than the producer' }); continue; }
      raise(it, 'independently-confirmed', `confirmed by ${String(e.by).slice(0, 60)}`);
    } else if (e.kind === 'repair-proposal') raise(it, 'repair-proposed', 'a repair was proposed');
    else if (e.kind === 'repair') raise(it, 'repaired', 'a repair was applied');
    else if (e.kind === 'verification') {
      const r = e.record;
      const v = r ? validateVerificationRecord(r) : { ok: false };
      if (!v.ok) { it.rejected.push({ kind: e.kind, reason: 'the verification record failed validation' }); continue; }
      if (r.hypothesisId !== it.id) { it.rejected.push({ kind: e.kind, reason: 'the record verifies another sibling' }); continue; }
      if (!r.repair || r.repair.status !== 'replay-verified') { it.rejected.push({ kind: e.kind, reason: 'the record is not a replay-verified repair' }); continue; }
      raise(it, 'verified', `replay-verified repair record ${String(r.id).slice(0, 24)}`);
    }
  }
  const counts = Object.fromEntries(SIBLING_STATES.map((s) => [s, 0]));
  for (const it of items) counts[it.state]++;
  const found = Number(sweep.found ?? items.length);
  return {
    ok: true, fromFindingId: sweep.fromFindingId ?? null, items,
    totals: { found, detectorReported: Number(sweep.mitigated ?? 0), candidatesAtDiscovery: Number(sweep.candidates ?? 0), sampled: items.length, unsampled: Math.max(0, found - items.length), byState: counts },
    note: 'detector-reported means a detector covers the location; only a verified item has a replay-verified repair of its own',
  };
}
