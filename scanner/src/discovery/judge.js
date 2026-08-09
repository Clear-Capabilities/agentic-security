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

// Guards against a malformed candidate producing a schema-invalid finding
// (root CLAUDE.md requires { id, severity, file, line, vuln, cwe, ... } on
// every finding). `hunter.js` already filters out candidates with no usable
// file/line before they reach here, so this should never trigger in the
// normal pipeline — but toFindingShape is exported and callable directly, and
// degrading with `null` (rather than throwing) matches this subsystem's
// degrade-don't-throw style everywhere else. Callers must skip a `null`.
export function toFindingShape(candidate) {
  const file = typeof candidate?.file === 'string' && candidate.file ? candidate.file : null;
  const line = Number.isInteger(candidate?.line) ? candidate.line : null;
  if (!file || line === null) return null;

  const tier = candidate?.confirmation?.tier || 'unconfirmed';
  const lensTitle = candidate?.lens ? `${candidate.lens} candidate` : 'discovery candidate';
  const title = typeof candidate?.title === 'string' && candidate.title ? candidate.title : lensTitle;
  const base = {
    id: `discovery-${candidate.lens}-${candidate.id}`,
    severity: SEVERITY_BY_TIER[tier] || 'low',
    file,
    line,
    vuln: title,
    cwe: candidate.cwe || 'CWE-710',
    description: candidate.rationale
      ? `${candidate.rationale} (entry point: ${candidate.entryPoint || 'unstated'}; sink: ${candidate.sink || 'unstated'})`
      : `Proposed by the ${candidate.lens} lens; no rationale supplied.`,
    remediation: `Review ${candidate.file}:${candidate.line}. Confirm whether ${candidate.entryPoint || 'attacker-controlled input'} can reach ${candidate.sink || 'this operation'}, and constrain it at the boundary if so.`,
    parser: 'DISCOVERY',
    family: candidate.family || 'other',
    ruleId: `discovery:${candidate.lens}`,
    // snippet discriminates findings so computeStableId has material to hash. An empty
    // snippet collapses distinct findings of the same lens in the same file onto one id.
    snippet: candidate.sink || candidate.entryPoint || candidate.title || '',
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
    if (!f) continue; // malformed candidate (no usable file/line) — degrade by skipping, never throw
    if (feedback[f.stableId] === 'fp') { suppressed.push({ ...f, suppressedBy: 'triage-fp' }); continue; }
    const locKey = `${f.file}|${f.line}|${f.family}`;
    // Location key is PRIMARY: same file, line, and family match existing findings.
    if (priorByLoc.has(locKey)) { duplicates.push({ ...f, duplicateOf: priorByLoc.get(locKey) }); continue; }
    // stableId is SECONDARY: same lens, file, and sink at a moved line is likely the same bug.
    if (priorIds.has(f.stableId)) { duplicates.push({ ...f, duplicateOf: f.stableId }); continue; }
    fresh.push(f);
  }
  return { fresh, duplicates, suppressed };
}
