//
// Turn surviving candidates into findings, then decide which are actually new.
//
// SEVERITY IS DRIVEN BY EVIDENCE, NOT BY THE MODEL'S ADJECTIVES. A hunter has
// no calibrated view of impact and will call everything critical. What we can
// defend is how well-evidenced the candidate is, so the confirmation tier sets
// the ceiling: taint-confirmed → high, sink-adjacent → medium, unconfirmed →
// low. A human or the existing triage path can raise it; the discovery layer
// never claims critical on its own.
//
// A PRIOR TRUE POSITIVE IS NOT A DUPLICATE. Triage feedback suppresses only
// `fp` verdicts. A `tp` verdict means the finding was real, and re-reporting it
// while it is still in the code is correct behaviour.
//
// STABLE IDS ARE LOCATION-FUZZY BY DESIGN, AND THAT MATTERS HERE. `stable-id.js`
// hashes ruleId, snippet, path shape, and BASENAME — deliberately not the line,
// so an id survives code moving down a file. The consequence for this layer:
// two different candidates of the same lens in the same file collide on one
// stableId. That is why file+line+family is the PRIMARY duplicate key and the
// stableId check is only a secondary net. It also means an `fp` verdict
// suppresses the whole (lens, file) pair rather than one line — the same
// breadth the rest of the engine already has, kept rather than silently
// diverged from. `ruleId` is set explicitly so ids partition by lens rather
// than falling back to the CWE.
import { computeStableId } from '../posture/stable-id.js';

const SEVERITY_BY_TIER = { 'taint-confirmed': 'high', 'sink-adjacent': 'medium', 'unconfirmed': 'low' };

export function toFindingShape(candidate) {
  const tier = candidate?.confirmation?.tier || 'unconfirmed';
  const base = {
    id: `discovery-${candidate.lens}-${candidate.id}`,
    severity: SEVERITY_BY_TIER[tier] || 'low',
    file: candidate.file,
    line: candidate.line,
    vuln: candidate.title,
    cwe: candidate.cwe || 'CWE-710',
    description: candidate.rationale
      ? `${candidate.rationale} (entry point: ${candidate.entryPoint || 'unstated'}; sink: ${candidate.sink || 'unstated'})`
      : `Proposed by the ${candidate.lens} lens; no rationale supplied.`,
    remediation: `Review ${candidate.file}:${candidate.line}. Confirm whether ${candidate.entryPoint || 'attacker-controlled input'} can reach ${candidate.sink || 'this operation'}, and constrain it at the boundary if so.`,
    parser: 'DISCOVERY',
    family: candidate.family || 'other',
    ruleId: `discovery:${candidate.lens}`,
  };
  return {
    ...base,
    stableId: computeStableId(base),
    discovery: {
      lens: candidate.lens,
      focusAreaId: candidate.focusAreaId,
      confirmation: candidate.confirmation || null,
      refutation: candidate.refutation || null,
    },
  };
}

export function judgeCandidates(candidates, priorScan, triageFeedback) {
  const prior = Array.isArray(priorScan?.findings) ? priorScan.findings : [];
  const priorByLoc = new Map();
  const priorIds = new Set();
  for (const p of prior) {
    if (p?.stableId) priorIds.add(p.stableId);
    priorByLoc.set(`${p?.file}|${p?.line}|${p?.family}`, p?.stableId || null);
  }
  const feedback = triageFeedback && typeof triageFeedback === 'object' ? triageFeedback : {};

  const fresh = [], duplicates = [], suppressed = [];
  for (const c of candidates || []) {
    const f = toFindingShape(c);
    if (feedback[f.stableId] === 'fp') { suppressed.push({ ...f, suppressedBy: 'triage-fp' }); continue; }
    const locKey = `${f.file}|${f.line}|${f.family}`;
    if (priorIds.has(f.stableId)) { duplicates.push({ ...f, duplicateOf: f.stableId }); continue; }
    if (priorByLoc.has(locKey)) { duplicates.push({ ...f, duplicateOf: priorByLoc.get(locKey) }); continue; }
    fresh.push(f);
  }
  return { fresh, duplicates, suppressed };
}
