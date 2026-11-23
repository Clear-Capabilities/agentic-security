// Structured qualification of a hunt candidate against a service contract (Epic B-02, B-04).
//
// Qualification answers one question: is there a supported hypothesis worth testing? It does not establish an exploit, and it does
// not authorise a repair to be called verified. The record is additive on the candidate (`candidate.qualification`) and carries, for
// a reviewer, the contract and invariant the candidate is about (or `contract-gap`), the attacker assumptions the hunter proposed
// (marked as proposed), the root cause and entry point, the citations with their validation status against the bundle the model
// was shown, the controls the context layer observed on the reaching entry points with their evidence and protection state, what
// is unresolved, and a decision with independent reason codes.
//
// Decisions: `qualified` (an invariant is matched, the citation resolves, the context for it is complete), `needs-context` (the
// context is partial, stale or unavailable, or the citation does not resolve: nobody may call this safe or disqualified),
// `contract-gap` (a resolving candidate the contract does not cover: kept with its existing evidence, never suppressed),
// `disqualified` (only `refutation.js` sets this, with an evidence-backed blocker). The decision never comes from a model's confidence.
import { contractRef, invariantRef, parseContractRef } from './schema.js';

export const QUALIFICATION_DECISIONS = Object.freeze(['qualified', 'needs-context', 'contract-gap', 'disqualified']);
export const QUALIFICATION_SCHEMA = 'agentic-security/candidate-qualification';

const ROUTE_RE = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY)\s+(\S+)$/i;
function routeGlobMatches(glob, label) {
  const g = ROUTE_RE.exec(glob); const l = ROUTE_RE.exec(label);
  if (!g || !l) return glob === label;
  if (g[1].toUpperCase() !== 'ANY' && g[1].toUpperCase() !== l[1].toUpperCase()) return false;
  const re = new RegExp('^' + g[2].replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '.*').replace(/(?<!\.)\*/g, '[^/]*') + '$');
  return re.test(l[2]);
}

/**
 * Which contract invariant a candidate is about. The hunter may name one (`candidate.invariantId`); it is accepted only when the
 * contract declares it. Otherwise the entry points that reach the cited line are matched against each invariant's scope routes
 * and attacker entry points. No match is `contract-gap`.
 */
export function matchInvariant(candidate, contract, entrypoints = []) {
  const declared = new Map((contract?.invariants || []).map((i) => [i.id, i]));
  if (typeof candidate?.invariantId === 'string') {
    if (declared.has(candidate.invariantId)) return { invariant: declared.get(candidate.invariantId), basis: 'named-by-hunter' };
    // The hunter claimed a property the contract does not state. Route overlap would not make it a contract invariant: the
    // candidate is a contract gap, kept with its evidence, and the gap is the reviewer's to close.
    return { invariant: null, basis: 'named-invariant-not-declared' };
  }
  const labels = entrypoints.map((e) => e.label).filter(Boolean);
  for (const inv of declared.values()) {
    const routes = [...(inv.scope?.routes || []), ...(inv.attacker?.entryPoints || [])];
    if (routes.some((r) => labels.some((l) => routeGlobMatches(r, l)))) return { invariant: inv, basis: 'entry-point-in-scope' };
  }
  return { invariant: null, basis: 'no-invariant-covers-the-entry-point' };
}

/**
 * Build the qualification record for one candidate.
 * @param {object} candidate   a hunt candidate (file, line, title, rationale, cwe, confirmation?, and optionally the model's
 *                             proposed `invariantId`, `attacker` {principal, role, tenant}, `prerequisites`, `boundaryCrossing`)
 * @param {object} o           { contract, supplier (context-supplier), approval (approvalState result) }
 */
export function qualifyCandidate(candidate, { contract = null, supplier = null, approval = null } = {}) {
  const ctx = supplier && supplier.available ? supplier.forCandidate(candidate.file, candidate.line) : { state: 'unavailable', reason: supplier?.reason || 'no context supplier', segments: [], entrypoints: [], controls: [] };
  const citation = { file: candidate.file, startLine: candidate.line, endLine: candidate.line, claim: candidate.title || '' };
  const citationStatus = supplier && supplier.available ? supplier.verifyCitation({ ...citation, claim: `${candidate.title || ''} ${candidate.rationale || ''}` }) : 'context-unavailable';
  const match = contract ? matchInvariant(candidate, contract, ctx.entrypoints) : { invariant: null, basis: 'no-contract' };
  const reasons = [];
  let decision;
  if (!contract) { decision = 'contract-gap'; reasons.push('no-contract-supplied'); }
  else if (!match.invariant) { decision = 'contract-gap'; reasons.push(match.basis); }
  if (citationStatus !== null && citationStatus !== undefined) reasons.push(`citation:${citationStatus}`);
  if (ctx.state !== 'complete') reasons.push(`context:${ctx.state}${ctx.reason ? ':' + ctx.reason : ''}`);
  if (!decision) decision = (citationStatus === null && ctx.state === 'complete') ? 'qualified' : 'needs-context';
  if (approval && approval.state !== 'approved') reasons.push(`approval:${approval.state}`);
  const controls = (ctx.controls || []).map((c) => ({ kind: c.kind, file: c.file, line: c.line, evidence: c.evidence, basis: c.basis, authority: 'context-intelligence', effectiveness: effectivenessFor(c, ctx.entrypoints) }));
  const unresolved = [];
  for (const e of ctx.entrypoints || []) for (const [dim, p] of Object.entries(e.protection || {})) if (p && ['not_resolved', 'omitted_due_to_budget'].includes(p.state)) unresolved.push({ entrypoint: e.label, dimension: dim, state: p.state, why: p.why });
  return {
    schema: QUALIFICATION_SCHEMA,
    contractRef: contract ? contractRef(contract) : null,
    invariantId: match.invariant ? match.invariant.id : null,
    invariantRef: match.invariant ? invariantRef(contract, match.invariant.id) : null,
    invariantBasis: match.basis,
    contractGap: !match.invariant,
    approval: approval ? { state: approval.state, current: approval.current, transitionId: approval.transitionId } : null,
    entryPoint: candidate.entryPoint || (ctx.entrypoints[0]?.label ?? null),
    reachingEntryPoints: ctx.entrypoints.map((e) => ({ label: e.label, contextHash: e.contextHash, integrity: e.integrity })),
    attacker: { principal: candidate.attacker?.principal ?? null, role: candidate.attacker?.role ?? null, tenant: candidate.attacker?.tenant ?? null, source: 'model-proposed', established: false },
    prerequisites: Array.isArray(candidate.prerequisites) ? candidate.prerequisites.slice(0, 8).map(String) : [],
    boundaryCrossing: typeof candidate.boundaryCrossing === 'string' ? candidate.boundaryCrossing.slice(0, 200) : null,
    rootCause: { file: candidate.file, line: candidate.line, sink: candidate.sink || null },
    citations: [{ ...citation, status: citationStatus === null ? 'resolved' : citationStatus, spanHashes: (ctx.segments || []).map((s) => s.spanHash).filter(Boolean) }],
    context: { state: ctx.state, reason: ctx.reason ?? null },
    controls,
    unresolved,
    recommendedValidation: match.invariant ? recommendedFor(match.invariant) : ['review: no contract invariant covers this entry point; the candidate keeps its independent deterministic evidence'],
    decision,
    reasons,
  };
}

function effectivenessFor(control, entrypoints) {
  // The context layer judges a control per entry point; a control that runs after the sensitive operation is ineffective there.
  for (const e of entrypoints || []) {
    const dim = e.protection?.[control.kind === 'tenant-scope' ? 'ownership' : control.kind];
    if (dim && Array.isArray(dim.evidence) && dim.evidence.some((ev) => ev.file === control.file && ev.line === control.line)) return dim.state === 'present' ? 'effective-on-path' : dim.state === 'evaluated_and_ineffective' ? 'ineffective-after-operation' : 'unresolved';
  }
  return 'not-judged';
}

function recommendedFor(inv) {
  const out = [];
  if (Array.isArray(inv.scenarioInvariantRefs) && inv.scenarioInvariantRefs.length) out.push(`scenario: run the executable invariant(s) ${inv.scenarioInvariantRefs.join(', ')} against the fixture`);
  if (Array.isArray(inv.dciInvariantRefs) && inv.dciInvariantRefs.length) out.push(`static: the context-intelligence rule(s) ${inv.dciInvariantRefs.join(', ')} on the reaching entry points`);
  for (const ev of inv.requiredEvidence || []) out.push(`evidence: ${ev}`);
  return out;
}

/** Summarise qualification decisions for a report. */
export function qualificationSummary(candidates) {
  const by = Object.fromEntries(QUALIFICATION_DECISIONS.map((d) => [d, 0]));
  for (const c of candidates || []) if (c?.qualification?.decision) by[c.qualification.decision] = (by[c.qualification.decision] || 0) + 1;
  return by;
}

export { parseContractRef };
