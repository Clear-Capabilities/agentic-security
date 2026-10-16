// DCI findings through the EXISTING reporting path (E4-07).
//
// An invariant violation or a cross-route inconsistency is not reported in a format of its own. It becomes a candidate in the schema the `hunt`
// pipeline already uses, goes through the same confirmation and judging (`adjudicate`: confirm.js -> judge.js), and comes out as a normal finding with
// a stableId, a severity, a CWE and a `contextIntelligence` block. From there triage, SARIF (`toSARIF`), CI gates, the verified-fix policy and the
// privacy controls apply with no DCI-specific code.
//
// WHAT THE EXISTING TIERS MEAN HERE. Severity comes from the confirmation tier alone (taint-confirmed high, sink-adjacent medium, unconfirmed low).
// A deterministic counterexample maps onto those tiers like this, and only like this:
//   proven      -> taint-confirmed   an executed local request showed the exposure
//   plausible   -> sink-adjacent     a resolved path reaches the operation with no such control before it
//   unresolved  -> unconfirmed       the analysis could not say
//   refuted     -> no finding        the claim was contradicted; it is counted, not reported
//
// WHAT A DCI FINDING CARRIES (all under `contextIntelligence`, never as new top-level fields): the invariant violated (or the sibling-route rule),
// the affected authorization scope (resource, control, routes, files), the code that shows it, the counterexample state and trace, a fix
// recommendation, and a verification slot that `verifyDciFix` fills after a patch.
import { createHash } from 'node:crypto';
import { adjudicate } from './candidates.js';
import { assessCandidate, executeAttempt } from './counterexample.js';
import { findCrossRouteInconsistencies } from './cross-route.js';
import { evaluateInvariants } from './invariants.js';
import { buildContext } from './build.js';
import { normalizeConfig } from './config.js';
import { buildFixVerificationRecord, evidenceItem, leg } from '../fix/verification-record.js';
import { patchHashOf } from '../fix/verification-adapters.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const CWE = { ownership: 'CWE-639', 'tenant-scope': 'CWE-639', authentication: 'CWE-306', 'authorization-role': 'CWE-862' };
const TIER_OF = { proven: 'taint-confirmed', plausible: 'sink-adjacent', unresolved: 'unconfirmed' };
const FIX = {
  ownership: 'Scope the data operation to the authenticated principal: add the owner to the query filter (for example `{ id, ownerId: req.user.id }`) or compare the loaded object\'s owner with the principal and reject on mismatch, the way the enforcing sibling route does.',
  'tenant-scope': 'Scope the data operation to the principal\'s tenant: add the tenant to the query filter or reject when the object\'s tenant differs from the principal\'s, the way the enforcing sibling route does.',
  authentication: 'Require an authenticated principal before the sensitive operation, using the same guard the sibling routes use.',
  'authorization-role': 'Require the role the sibling routes require before the sensitive operation.',
};
const sha = (v) => createHash('sha256').update(JSON.stringify(v)).digest('hex');
const siteOf = (ep) => ({ file: ep?.registrationSite?.file || ep?.rootSpan?.file || '', line: ep?.registrationSite?.line || ep?.rootSpan?.startLine || 1 });

/**
 * @param {{crossRoute?:object, invariantResults?:object[], bundles:object[], invariants?:object}} src
 * @returns {object[]} candidates in the shared discovery schema, each with `deterministic` evidence
 */
export function candidatesFromEvidence({ crossRoute, invariantResults = [], bundles }) {
  const byLabel = new Map(bundles.filter((b) => b.manifest).map((b) => [b.entrypoint.label, b]));
  const out = [];
  for (const f of crossRoute?.findings || []) {
    const b = byLabel.get(f.route); if (!b) continue;
    const site = siteOf(b.entrypoint);
    const id = sha(['xroute', f.resource, f.dimension, f.route, site.file]).slice(0, 12);
    out.push({
      id, focusAreaId: sha(['ctx', b.manifest.contextHash]).slice(0, 12), lens: 'dci-authz',
      title: `Inconsistent ${f.dimension} enforcement on ${f.resource}: ${f.route}`, file: site.file, line: site.line, family: 'authorization', cwe: CWE[f.dimension] || 'CWE-285',
      rationale: f.explanation, entryPoint: f.route, sink: `${f.operations.join('/')} of ${f.resource}`, origin: 'context-intelligence', questionPack: null, advisoryOnly: false,
      witnesses: [{ entrypointId: b.entrypoint.id, label: f.route, contextHash: b.manifest.contextHash, questionPack: null }],
      sourceSpanEvidence: f.enforcedAt.flatMap((e) => (e.evidence || []).map((x) => ({ role: 'guard', file: x.file, startLine: x.line, endLine: x.line }))),
      scopeIntegrity: { contextIntegrity: b.manifest.context.integrity, standalone: true, deterministicAgreement: 'agrees', deterministicProtection: null },
      reviewStatus: 'deterministic', uncertainties: [], recommendedValidation: `Run the same request as a principal who does not own the ${f.resource} against ${f.route} and against ${f.enforcedAt[0]?.route}; the sibling should refuse and this route should not.`,
      remediation: FIX[f.dimension] || 'Enforce the same control as the sibling routes.',
      deterministic: {
        rule: { kind: 'cross-route-consistency', description: `Every route that touches a resource enforces what its sibling routes enforce` },
        invariant: null,
        scope: { resource: f.resource, control: f.dimension, operations: f.operations, route: f.route, enforcedAt: f.enforcedAt.map((e) => e.route), files: [...new Set([site.file, ...f.enforcedAt.flatMap((e) => (e.evidence || []).map((x) => x.file))])] },
        counterexample: null, fix: { recommendation: FIX[f.dimension] || null }, verification: { status: 'pending' },
      },
      _bundle: b, _crossRoute: f,
    });
  }
  for (const r of invariantResults) {
    if (r.verdict !== 'violated') continue;
    const b = byLabel.get(r.label); if (!b) continue;
    const site = siteOf(b.entrypoint);
    const dims = r.controls.filter((c) => c.state === 'absent').map((c) => c.dim);
    const id = sha(['inv', r.invariantId, r.entrypointId]).slice(0, 12);
    out.push({
      id, focusAreaId: sha(['ctx', b.manifest.contextHash]).slice(0, 12), lens: 'dci-authz',
      title: `Invariant ${r.invariantId} violated: ${r.label}`, file: site.file, line: site.line, family: 'authorization', cwe: CWE[dims[0]] || 'CWE-285',
      rationale: `${r.title}. ${r.reasons.join('; ')}`, entryPoint: r.label, sink: dims.join(', ') + ' missing', origin: 'context-intelligence', questionPack: null, advisoryOnly: false,
      witnesses: [{ entrypointId: r.entrypointId, label: r.label, contextHash: b.manifest.contextHash, questionPack: null }], sourceSpanEvidence: [],
      scopeIntegrity: { contextIntegrity: b.manifest.context.integrity, standalone: true, deterministicAgreement: 'agrees', deterministicProtection: null },
      reviewStatus: 'deterministic', uncertainties: [], recommendedValidation: `Request ${r.label} as a principal lacking: ${dims.join(', ')}.`,
      remediation: dims.map((d) => FIX[d]).filter(Boolean).join(' ') || 'Enforce the controls the invariant requires.',
      deterministic: { rule: { kind: 'invariant', id: r.invariantId, title: r.title, declaredSeverity: r.severity || null }, invariant: { id: r.invariantId, title: r.title, requires: dims }, scope: { resource: null, control: dims, route: r.label, files: [r.file] }, counterexample: null, fix: { recommendation: dims.map((d) => FIX[d]).filter(Boolean) }, verification: { status: 'pending' } },
      _bundle: b, _invariant: r,
    });
  }
  return out.sort((a, b) => (a.id < b.id ? -1 : 1));
}

/**
 * Attempt a counterexample for every candidate that has a cross-route basis, set each candidate's confirmation tier from it, and run the shared
 * adjudication. Refuted candidates are returned separately and produce no finding.
 */
export async function dciFindings({ candidates, bundles, fixtures = {}, scanRoot = null }) {
  const states = new Map(); const refuted = [];
  const live = [];
  for (const c of candidates) {
    let a;
    if (c._crossRoute) a = assessCandidate(c._crossRoute, { bundles, fixture: fixtures[c._crossRoute.route] || fixtures[c.id] });
    else a = { state: 'plausible', trace: [{ kind: 'static', what: 'invariant evaluation', detail: 'the protection verdict for the required control is absent' }], reasons: ['no sibling route to attempt a counterexample against'] };
    states.set(c.id, a);
    const pub = { state: a.state, trace: a.trace, reasons: a.reasons };
    if (a.state === 'refuted') { refuted.push({ id: c.id, title: c.title, file: c.file, line: c.line, refutation: pub }); continue; }
    live.push({ ...c, deterministic: { ...c.deterministic, counterexample: pub } });
  }
  const clean = live.map(({ _bundle, _crossRoute, _invariant, ...rest }) => rest);
  const taintProbe = async (cand) => ({ tier: TIER_OF[states.get(cand.id).state] || 'unconfirmed', evidence: { counterexample: states.get(cand.id).state } });
  const adj = await adjudicate(clean, { taintProbe, scanRoot });
  return { ...adj, counterexampleRefuted: refuted, assessments: Object.fromEntries([...states].map(([k, v]) => [k, v.state])) };
}

// ---- final verification of a fix ------------------------------------------------------------------------------------------------

async function analyse(files, invariants, now) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dci-verify-'));
  try {
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}');
    for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true }); fs.writeFileSync(path.join(root, f), t); }
    const built = await buildContext(root, { config: normalizeConfig({}).config });
    if (!built.ok) return { ok: false, reason: built.reason };
    const crossRoute = findCrossRouteInconsistencies(built.bundles, { now, invariants });
    const inv = invariants ? evaluateInvariants(invariants, built.bundles, { now }) : { results: [], problems: [] };
    return { ok: true, bundles: built.bundles, crossRoute, invariantResults: inv.results };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

/**
 * Settle a DCI finding after a patch: is the cross-route inconsistency (or the invariant violation) gone in the patched tree, and does the same
 * executed attempt now fail? Returns a verdict and a patch-level verification record in the shared fix-verification schema, so the verified-fix policy
 * (completeness tiers, residual risk) applies unchanged.
 * @param {{finding:object, candidate:object, before:Record<string,string>, after:Record<string,string>, fixture?:object, invariants?:object, now?:Date}} o
 */
export async function verifyDciFix({ finding, candidate, before, after, fixture = null, invariants = null, now = new Date() }) {
  const post = await analyse(after, invariants, now);
  const route = candidate._crossRoute?.route || candidate._invariant?.label;
  const dim = candidate._crossRoute?.dimension;
  const stillInconsistent = post.ok && post.crossRoute.findings.some((f) => f.route === route && (!dim || f.dimension === dim));
  const stillViolated = post.ok && post.invariantResults.some((r) => r.verdict === 'violated' && r.label === route && (!candidate._invariant || r.invariantId === candidate._invariant.invariantId));
  let after1 = null;
  // the attempt is EXECUTED on the patched files even though a static look may already see the control: a fix is verified by the attack failing, not by the code looking right
  if (candidate._crossRoute && fixture) after1 = executeAttempt(candidate._crossRoute, { ...fixture, files: after });
  const execDenied = after1 && after1.state === 'refuted' && after1.trace.some((t) => t.kind === 'executed');
  const execStillWorks = after1 && after1.state === 'proven';
  const ev = []; const add = (kind, v) => { const e = evidenceItem({ kind, mediaType: 'application/json', sha256: sha(v) }); if (!ev.some((x) => x.id === e.id)) ev.push(e); return e.id; };
  const before1 = finding?.contextIntelligence?.deterministic?.counterexample;
  const securityAfter = !post.ok ? leg('blocked', { reason: `the patched tree could not be analysed (${post.reason})` })
    : (stillInconsistent || stillViolated) ? leg('failed', { evidenceIds: [add('dci-reanalysis', { stillInconsistent, stillViolated })], reason: 'the same inconsistency or invariant violation is still reported on the patched tree' })
    : leg('passed', { evidenceIds: [add('dci-reanalysis', { stillInconsistent, stillViolated })] });
  const files = Object.keys(after).filter((f) => after[f] !== before[f]);
  const record = buildFixVerificationRecord({
    findingId: finding?.id || candidate.id, findingStableId: finding?.stableId, mode: 'verify', route: 'dci-reverify', patchHash: patchHashOf(Object.fromEntries(files.map((f) => [f, after[f]]))), postPatchHash: patchHashOf(after), affectedFiles: files.length ? files : ['(none)'],
    securityBefore: leg('passed', { evidenceIds: [add('dci-finding', { id: finding?.id, scope: finding?.contextIntelligence?.deterministic?.scope })] }),
    securityAfter,
    exploitProofBefore: before1 && before1.state === 'proven' ? leg('passed', { evidenceIds: [add('dci-counterexample', before1)] }) : leg('not_run', { reason: 'the finding had no executed counterexample' }),
    exploitProofAfter: execDenied ? leg('passed', { evidenceIds: [add('dci-counterexample-after', after1)] }) : execStillWorks ? leg('failed', { evidenceIds: [add('dci-counterexample-after', after1)], reason: 'the same executed attempt still succeeds on the patched tree' }) : leg('not_run', { reason: fixture ? 'the executed attempt could not be made on the patched tree' : 'no fixture was supplied' }),
    newFindingDelta: post.ok ? (post.crossRoute.findings.filter((f) => !before1 || f.route !== route).length > 0 ? leg('not_run', { reason: 'other inconsistencies remain; not compared with the pre-patch set here' }) : leg('passed', { evidenceIds: [add('dci-reanalysis', { remaining: post.crossRoute.findings.length })] })) : leg('not_run', { reason: 'the patched tree could not be analysed' }),
    behaviorPreservation: leg('not_run', { reason: 'run the project tests through the fix verifier (verifyPatch) to cover behaviour' }),
    behaviorTests: leg('not_run', { reason: 'not run by this check' }),
    // behaviour is required like everywhere else: a re-analysis and an attack that fails say the weakness is gone, not that the feature survived
    requiredLegs: ['securityAfter', 'behaviorPreservation', 'behaviorTests', ...(fixture ? ['exploitProofAfter'] : [])], evidence: ev, tools: { engineVersion: null, verifier: 'dci-reverify' },
  });
  const status = (stillInconsistent || stillViolated || execStillWorks) ? 'failed' : (!post.ok ? 'inconclusive' : 'verified');
  return { status, stillInconsistent, stillViolated, executedAfter: after1 ? { state: after1.state, trace: after1.trace } : null, record };
}
