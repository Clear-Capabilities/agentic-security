//
// Review results -> existing discovery candidates -> existing adjudication.
//
// A DCI review is a hypothesis. This module normalises an accepted `potential_issue` into the SAME candidate schema the
// `hunt` pipeline uses, so the existing machinery decides what happens next and nothing about it is reimplemented here:
//
//   confirm.js   routes the candidate back through the taint engine. A novel authorization or business-logic
//                hypothesis the taint engine cannot prove stays `unconfirmed`; it is neither rejected nor promoted.
//   disprove.js  the only stage that may remove a candidate, and only by an argued majority.
//   judge.js     shapes the finding. Severity comes from the CONFIRMATION TIER (taint-confirmed high, sink-adjacent
//                medium, unconfirmed low). A model's confidence, likelihood or adjectives are never an input, and
//                nothing here can produce `critical`.
//
// One shared defect reached through many routes is ONE candidate with many witnesses, not many top-level findings.
import { sha256 } from './canonical.js';
import { confirmAll } from '../discovery/confirm.js';
import { disprovePanel } from '../discovery/disprove.js';
import { judgeCandidates } from '../discovery/judge.js';

const SINK_ROLES = ['data-access', 'database-read', 'database-write', 'state-change', 'sink', 'side-effect'];

function normalizeInvariant(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim(); }

function primaryEvidence(evidence) {
  for (const role of SINK_ROLES) {
    const hit = evidence.find(e => e.role === role);
    if (hit) return hit;
  }
  return evidence[0];
}

/**
 * Build candidates from verified reviews.
 *   records   [{ review, entrypoints: [{id,label}], pack }]  (only status 'completed' + 'potential_issue' qualifies)
 */
export function reviewsToCandidates(records) {
  const groups = new Map();
  for (const r of records) {
    const rv = r.review;
    if (!rv || rv.status !== 'completed' || rv.conclusion !== 'potential_issue' || !rv.evidence.length) continue;
    const ev = primaryEvidence(rv.evidence);
    const key = sha256(`${r.pack.id}|${ev.file}|${ev.startLine}|${normalizeInvariant(rv.invariant)}`).slice(0, 12);
    if (!groups.has(key)) {
      groups.set(key, {
        id: key,
        focusAreaId: String(rv.contextHash).slice(0, 12),
        lens: r.pack.lens,
        title: `${r.pack.title}: ${r.entrypoints[0].label}`,
        file: ev.file,
        line: ev.startLine,
        family: r.pack.family,
        cwe: r.pack.cwe,
        rationale: rv.narrative || rv.invariant,
        entryPoint: r.entrypoints.map(e => e.label).join('; '),
        sink: ev.claim || ev.role,
        origin: 'context-intelligence',
        questionPack: rv.questionPack,
        advisoryOnly: rv.advisoryOnly === true,
        witnesses: [],
        sourceSpanEvidence: rv.evidence.map(e => ({ role: e.role, file: e.file, startLine: e.startLine, endLine: e.endLine })),
        scopeIntegrity: { contextIntegrity: rv.contextIntegrity, standalone: rv.standalone, deterministicAgreement: rv.deterministicAgreement, deterministicProtection: rv.deterministicProtection || null },
        reviewStatus: rv.status,
        uncertainties: rv.uncertainties,
        recommendedValidation: rv.recommendedValidation,
      });
    }
    const g = groups.get(key);
    for (const e of r.entrypoints) {
      if (!g.witnesses.some(w => w.entrypointId === e.id)) g.witnesses.push({ entrypointId: e.id, label: e.label, contextHash: rv.contextHash, questionPack: rv.questionPack });
    }
  }
  return [...groups.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
}

/**
 * Run the existing adjudication. All stages are optional and injected:
 *   taintProbe   -> confirm.js     refute -> disprove.js (needs a governed invoker: `{ llmInvoke | endpoint policy }`)
 * Returns { findings, duplicates, suppressed, refuted, advisory }. `findings` carry a `contextIntelligence` block and
 * `parser: 'DISCOVERY'`, so the report layer keeps them advisory exactly as it does for `hunt`.
 */
export async function adjudicate(candidates, opts = {}) {
  const advisory = candidates.filter(c => c.advisoryOnly);
  const real = candidates.filter(c => !c.advisoryOnly);
  const confirmed = await confirmAll(real, { taintProbe: opts.taintProbe });
  let survivors = confirmed;
  let refuted = [];
  if (opts.refute) {
    const panel = await disprovePanel(confirmed, { ...opts.refute, scanRoot: opts.scanRoot });
    survivors = panel.survivors;
    refuted = panel.refuted;
  }
  const byId = new Map(candidates.map(c => [c.id, c]));
  const judged = judgeCandidates(survivors, opts.priorScan, opts.triageFeedback);
  const decorate = (f) => {
    const id = String(f.id).split('-').pop();
    const c = byId.get(id) || survivors.find(s => f.id.endsWith(s.id)) || null;
    if (!c) return f;
    return {
      ...f,
      contextIntelligence: {
        origin: 'context-intelligence', questionPack: c.questionPack, witnesses: c.witnesses, witnessCount: c.witnesses.length,
        sourceSpanEvidence: c.sourceSpanEvidence, scopeIntegrity: c.scopeIntegrity, reviewStatus: c.reviewStatus,
        uncertainties: c.uncertainties, recommendedValidation: c.recommendedValidation,
        note: 'A model hypothesis checked for citations, not a proof. Severity comes from the confirmation tier only.',
      },
    };
  };
  return {
    findings: judged.fresh.map(decorate),
    duplicates: judged.duplicates.map(decorate),
    suppressed: judged.suppressed.map(decorate),
    refuted: refuted.map(c => ({ id: c.id, title: c.title, file: c.file, line: c.line, refutation: c.refutation })),
    advisory: advisory.map(c => ({ id: c.id, title: c.title, file: c.file, line: c.line, questionPack: c.questionPack, witnesses: c.witnesses, rationale: c.rationale })),
  };
}
