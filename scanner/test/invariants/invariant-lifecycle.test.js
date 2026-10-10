// X-402: inferred versus approved invariants. The ledger is signed under the per-install key, so the tests pin a key for this
// process (and restore the environment afterwards). The classification tests that need a real, runner-issued receipt execute a
// scenario through the trust boundary; where the boundary cannot run they say SKIPPED, NOT PASSED.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { _resetKeyCacheForTests } from '../../src/posture/integrity.js';
import { createInvariant } from '../../src/posture/invariants/schema.js';
import { semanticId } from '../../src/posture/assurance/identity.js';
import {
  emptyLedger, recordTransition, verifyLedger, isAuthoritative, authorizeReviewer, classifyViolation, violationReport, inferredInvariant, LEDGER_SCHEMA,
} from '../../src/posture/invariants/lifecycle.js';
import { verifyInvariant } from '../../src/posture/invariants/run.js';
import { mineInvariantProposals } from '../../src/posture/specification-mining.js';
import { mineWorkflowInvariants } from '../../src/posture/business-logic.js';
import { invariantFromLogicClaim } from '../../src/posture/logic-claims.js';
import { invariantProposalFor } from '../../src/discovery/lenses.js';
import { runDiscovery } from '../../src/discovery/index.js';
import { contract, APPS, fixtureOf, configWith, boundaryProbe, COMMIT } from '../helpers/invariant-fixtures.js';

const KEY_VAR = 'AGENTIC_SECURITY_HMAC_KEY';
let savedKey;
let boundary = { ready: false, why: '' };
before(async () => {
  savedKey = process.env[KEY_VAR];
  process.env[KEY_VAR] = 'ab'.repeat(32);
  _resetKeyCacheForTests();
  boundary = await boundaryProbe();
});
after(() => {
  if (savedKey === undefined) delete process.env[KEY_VAR]; else process.env[KEY_VAR] = savedKey;
  _resetKeyCacheForTests();
});
const needsBoundary = (fn) => (t) => (boundary.ready ? fn(t) : t.skip(boundary.why));

const clone = (o) => JSON.parse(JSON.stringify(o));
const POLICY = { id: 'local-1', reviewers: ['dana', 'erin'] };
const human = (id) => ({ id, kind: 'human' });
const mined = () => mineInvariantProposals({
  'src/orders.js': 'function validateOwnership(req, order) {\n  return order.owner === req.params.id;\n}\n',
  'src/admin.js': 'function requireAdmin(req) {\n  return req.user.role === "admin";\n}\n',
});
const proposed = (inv, by = { id: 'miner', kind: 'code' }) => recordTransition(emptyLedger(), { action: 'propose', invariant: inv, actor: by, reason: 'mined from the source' });

describe('[X-402.AC01] model- or code-derived invariants enter proposed state with source evidence and uncertainty, and cannot become authoritative automatically', () => {
  test('[X-402.AC01] specification mining proposes contracts: inferred, proposed, with source evidence and an uncertainty', () => {
    const found = mined();
    assert.equal(found.length, 2);
    assert.deepEqual(found.map((i) => i.class).sort(), ['privilege-constraint', 'tenant-isolation']);
    for (const inv of found) {
      assert.equal(inv.review.state, 'proposed');
      assert.equal(inv.review.origin, 'inferred');
      assert.ok(inv.review.sources.length >= 1 && inv.review.sources[0].file && inv.review.sources[0].line, 'the source file and line are recorded');
      assert.ok(inv.review.uncertainty > 0 && inv.review.uncertainty <= 1);
      assert.notEqual(inv.author.kind, 'human');
    }
    // a function with no state-contract name proposes nothing
    assert.deepEqual(mineInvariantProposals({ 'a.js': 'function add(a, b) {\n  return a + b;\n}\n' }), []);
  });

  test('[X-402.AC01] state machines, reviewer claims and discovery lenses propose contracts through the same path', () => {
    const wf = mineWorkflowInvariants({ 'src/order.js': "const ORDER_STATUSES = ['new', 'paid', 'shipped'];\n" });
    assert.equal(wf.length, 1);
    assert.equal(wf[0].class, 'workflow-order');
    assert.deepEqual(wf[0].forbidden[0].allowed, [{ from: 'new', to: 'paid' }, { from: 'paid', to: 'shipped' }]);
    assert.equal(wf[0].review.state, 'proposed');
    assert.deepEqual(mineWorkflowInvariants({ 'a.js': 'const x = 1;\n' }), []);

    const claim = invariantFromLogicClaim({ kind: 'missing-ownership-check', file: 'routes/orders.js', line: 12 });
    assert.equal(claim.class, 'tenant-isolation');
    assert.equal(claim.author.kind, 'model');
    assert.equal(claim.review.state, 'proposed');
    assert.equal(invariantFromLogicClaim({ kind: 'race-condition', file: 'a.js' }), null, 'no skeleton for a bare race: nothing is invented');
    assert.equal(invariantFromLogicClaim({ kind: 'missing-ownership-check' }), null, 'a claim with no file has no source evidence');

    const lens = invariantProposalFor({ lens: 'authz', title: 'IDOR: orders readable across tenants', file: 'routes/orders.js', line: 4 });
    assert.equal(lens.class, 'tenant-isolation');
    assert.equal(lens.author.kind, 'model');
    assert.ok(lens.review.uncertainty >= 0.8, 'a model-raised candidate is the least certain source');
    assert.equal(invariantProposalFor({ lens: 'injection', title: 'sql', file: 'a.js' }), null);
    assert.equal(invariantProposalFor({ lens: 'authz', title: 'IDOR', file: undefined }), null);
  });

  test('[X-402.AC01] discovery reports proposals only when the feature is enabled, and they stay proposals', async () => {
    const ctx = {
      perFileIR: {},
      callGraph: { functions: new Map([['routes/orders.js::handler@1', { qid: 'routes/orders.js::handler@1', name: 'handler', file: 'routes/orders.js' }]]), edges: [] },
      fileContents: { 'routes/orders.js': 'function handler(req, res) { return db.find(req.params.id); }' },
      priorScan: null, triageFeedback: null,
    };
    const llmInvoke = async (p) => (/REFUTE/.test(p) ? '{"refuted":false,"reason":"looks real"}'
      : '{"candidates":[{"title":"IDOR: orders readable across tenants","file":"routes/orders.js","line":1,"rationale":"no tenant scope on the lookup","entryPoint":"id","sink":"db.find"}]}');
    const run = (opts) => runDiscovery(ctx, { llmInvoke, lenses: ['authz'], ...opts });
    const off = await run({});
    assert.equal(off.fresh.length, 1, 'the hunt produced a candidate, so the assertions below are about real input');
    assert.equal('invariantProposals' in off, false, 'additive and absent by default');
    const disabled = await run({ invariantProposals: { config: await configWith() } });
    assert.equal('invariantProposals' in disabled, false, 'the feature flag, not the option, decides');
    const on = await run({ invariantProposals: { config: await configWith('invariant-scenarios') } });
    assert.equal(on.invariantProposals.length, 1);
    assert.equal(on.invariantProposals[0].invariant.class, 'tenant-isolation');
    assert.equal(on.invariantProposals[0].invariant.review.state, 'proposed');
    assert.equal(on.invariantProposals[0].invariant.author.kind, 'model');
    assert.equal(on.invariantProposals[0].hypothesisId, on.fresh[0].stableId);
    assert.deepEqual(on.fresh, off.fresh, 'proposing changes no finding');
  });

  test('[X-402.AC01] a proposal cannot enter the ledger as approved, and an inferred contract with no evidence is not a valid contract', () => {
    const inv = mined()[0];
    const forged = createInvariant({ ...clone(inv), review: { ...inv.review, state: 'approved' } });
    const r = recordTransition(emptyLedger(), { action: 'propose', invariant: forged, actor: { id: 'miner', kind: 'code' }, reason: 'x' });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, 'proposal-must-be-proposed');
    const noEvidence = createInvariant({ ...clone(inv), review: { state: 'proposed', origin: 'inferred', sources: [], uncertainty: 0.5 } });
    const r2 = recordTransition(emptyLedger(), { action: 'propose', invariant: noEvidence, actor: { id: 'miner', kind: 'code' }, reason: 'x' });
    assert.equal(r2.ok, false);
    assert.equal(r2.errors[0].code, 'invalid-invariant');
    assert.equal(inferredInvariant({ class: 'tenant-isolation', source: 'specification-mining', evidence: {}, uncertainty: 0.5 }), null, 'a proposal needs a source file');
  });

  test('[X-402.AC01] a model, code or the proposer cannot approve; with no reviewer policy nobody can; a proposed contract is not authoritative', () => {
    const inv = mined()[0];
    const { ledger } = proposed(inv);
    assert.equal(isAuthoritative(ledger, inv.id), false, 'proposed is not authoritative');
    const approve = (actor, o) => recordTransition(ledger, { action: 'approve', invariantId: inv.id, actor, reason: 'looks right' }, o);
    assert.equal(approve({ id: 'miner', kind: 'code' }, { policy: { ...POLICY, reviewers: ['miner'] } }).errors[0].code, 'not-a-human-reviewer');
    assert.equal(approve({ id: 'gpt', kind: 'model' }, { policy: { ...POLICY, reviewers: ['gpt'] } }).errors[0].code, 'not-a-human-reviewer');
    assert.equal(approve(human('dana')).errors[0].code, 'no-authorized-policy', 'no policy and no registry: the default is closed');
    assert.equal(approve(human('dana'), { policy: { id: 'p', reviewers: [] } }).errors[0].code, 'no-authorized-policy');
    assert.equal(approve(human('mallory'), { policy: POLICY }).errors[0].code, 'unauthorized-reviewer');
    assert.equal(approve({ id: '', kind: 'human' }, { policy: POLICY }).ok, false, 'an anonymous approval is refused');
    assert.equal(authorizeReviewer({ id: ' ', kind: 'human' }, { policy: POLICY }).code, 'anonymous-reviewer');
    assert.equal(approve(human('dana'), { policy: POLICY }).ok, true, 'an authorized human reviewer can');
    // none of the refused attempts changed the ledger
    assert.equal(ledger.records.length, 1);
  });
});

describe('[X-402.AC02] approval, rejection and supersession produce auditable versioned transitions tied to an authorized policy or reviewer action', () => {
  const approvedLedger = (inv) => {
    const p = proposed(inv);
    return recordTransition(p.ledger, { action: 'approve', invariantId: inv.id, actor: human('dana'), reason: 'matches the product requirement' }, { policy: POLICY });
  };

  test('[X-402.AC02] approve is a recorded, chained, signed transition naming who, why, from and to, and it makes the contract authoritative', () => {
    const inv = mined()[0];
    const r = approvedLedger(inv);
    assert.equal(r.ok, true);
    const [first, second] = r.ledger.records;
    assert.equal(first.action, 'propose'); assert.equal(first.to, 'proposed'); assert.equal(first.prev, null); assert.equal(first.origin, 'inferred');
    assert.equal(second.action, 'approve'); assert.equal(second.from, 'proposed'); assert.equal(second.to, 'approved');
    assert.equal(second.actor.id, 'dana'); assert.equal(second.reason, 'matches the product requirement');
    assert.equal(second.prev, first.id, 'hash chain');
    assert.equal(second.seq, 2);
    assert.equal(second.policyId, 'policy:local-1', 'the authority the approval rests on is recorded');
    assert.match(second.signature, /^[0-9a-f]{64}$/);
    assert.deepEqual(verifyLedger(r.ledger).errors, []);
    assert.equal(isAuthoritative(r.ledger, inv.id), true);
    assert.equal(r.ledger.schema, LEDGER_SCHEMA);
  });

  test('[X-402.AC02] a reviewer verified by the operator\'s approver registry is accepted, one outside it is not, and roles are honoured', () => {
    const inv = mined()[0];
    const { ledger } = proposed(inv);
    const registry = { approvers: [{ identity: 'dana', roles: ['security'] }, { identity: 'frank', roles: ['intern'] }] };
    const ok = recordTransition(ledger, { action: 'approve', invariantId: inv.id, actor: human('dana'), reason: 'ok' }, { registry });
    assert.equal(ok.ok, true);
    assert.equal(ok.record.policyId, 'approver-registry');
    assert.equal(recordTransition(ledger, { action: 'approve', invariantId: inv.id, actor: human('zed'), reason: 'ok' }, { registry }).ok, false);
    const roled = { policy: { id: 'p', requiredRoles: ['security'] }, registry };
    assert.equal(recordTransition(ledger, { action: 'approve', invariantId: inv.id, actor: human('frank'), reason: 'ok' }, roled).ok, false);
    assert.equal(recordTransition(ledger, { action: 'approve', invariantId: inv.id, actor: human('dana'), reason: 'ok' }, roled).ok, true);
    assert.equal(authorizeReviewer(human('dana'), { policy: POLICY }).ok, true);
  });

  test('[X-402.AC02] rejection and supersession are transitions too, and illegal ones are refused', () => {
    const v1 = contract('tenant');
    const v2 = createInvariant({ ...clone(v1), revision: 2, name: 'revised' });
    let r = proposed(v1, human('ross'));
    r = recordTransition(r.ledger, { action: 'approve', invariantId: v1.id, actor: human('dana'), reason: 'ok' }, { policy: POLICY });
    // a later revision of the same key is proposed, then the old one superseded by it
    r = recordTransition(r.ledger, { action: 'propose', invariant: v2, actor: human('ross'), reason: 'tightened' }, { policy: POLICY });
    assert.equal(r.ok, true, JSON.stringify(r.errors));
    const sup = recordTransition(r.ledger, { action: 'supersede', invariantId: v1.id, supersededBy: v2.id, actor: human('dana'), reason: 'v2 replaces v1' }, { policy: POLICY });
    assert.equal(sup.ok, true, JSON.stringify(sup.errors));
    assert.equal(sup.record.to, 'superseded');
    assert.equal(sup.record.supersededBy, v2.id);
    assert.equal(isAuthoritative(sup.ledger, v1.id), false, 'a superseded contract no longer gates');
    // superseding by an earlier or unrelated revision is refused; so is superseding twice
    assert.equal(recordTransition(r.ledger, { action: 'supersede', invariantId: v1.id, supersededBy: v1.id, actor: human('dana'), reason: 'x' }, { policy: POLICY }).errors[0].code, 'bad-supersession');
    assert.equal(recordTransition(sup.ledger, { action: 'supersede', invariantId: v1.id, supersededBy: v2.id, actor: human('dana'), reason: 'again' }, { policy: POLICY }).errors[0].code, 'illegal-transition');
    // reject
    const rej = recordTransition(r.ledger, { action: 'reject', invariantId: v2.id, actor: human('dana'), reason: 'not a requirement' }, { policy: POLICY });
    assert.equal(rej.record.to, 'rejected');
    assert.equal(recordTransition(rej.ledger, { action: 'approve', invariantId: v2.id, actor: human('dana'), reason: 'changed my mind' }, { policy: POLICY }).errors[0].code, 'illegal-transition', 'a rejected contract is not approved by a later click');
    // a reason is mandatory
    assert.equal(recordTransition(r.ledger, { action: 'reject', invariantId: v2.id, actor: human('dana'), reason: '  ' }, { policy: POLICY }).errors[0].code, 'reason-required');
    // an ambiguous revision (same key and revision, different content) is refused
    const clash = createInvariant({ ...clone(v1), name: 'same revision, different words', forbidden: [{ ...v1.forbidden[0], prefix: 'invoices/' }] });
    assert.equal(recordTransition(r.ledger, { action: 'propose', invariant: clash, actor: human('ross'), reason: 'x' }).errors[0].code, 'ambiguous-revision');
  });

  test('[X-402.AC02] editing, forging, reordering or dropping a record is detected', () => {
    const inv = mined()[0];
    const good = approvedLedger(inv).ledger;
    assert.equal(verifyLedger(good).ok, true);
    const edit = (fn) => { const l = clone(good); fn(l); return verifyLedger(l); };
    // flip a reviewer decision
    assert.ok(edit((l) => { l.records[1].to = 'rejected'; }).errors.some((e) => e.code === 'id-mismatch' || e.code === 'bad-signature'));
    // rewrite the reviewer
    assert.ok(edit((l) => { l.records[1].actor.id = 'mallory'; }).errors.some((e) => e.code === 'bad-signature'));
    // forge an approval with a made-up signature and a consistent id
    const forged = clone(good);
    forged.records[1].actor = { id: 'bot', kind: 'model' };
    assert.equal(verifyLedger(forged).ok, false);
    // a signature from another key
    const prev = process.env[KEY_VAR];
    process.env[KEY_VAR] = 'cd'.repeat(32); _resetKeyCacheForTests();
    const otherKey = verifyLedger(good);
    process.env[KEY_VAR] = prev; _resetKeyCacheForTests();
    assert.ok(otherKey.errors.some((e) => e.code === 'bad-signature'), 'a ledger signed under another install key does not verify');
    // drop the proposal, reorder, duplicate
    assert.equal(edit((l) => { l.records.shift(); }).ok, false);
    assert.equal(edit((l) => { l.records.reverse(); }).ok, false);
    assert.equal(edit((l) => { l.records.push({ ...l.records[1] }); }).ok, false);
    // approval by a model recorded directly in the data
    const modelApproved = clone(good); modelApproved.records[1].actor.kind = 'model';
    assert.ok(verifyLedger(modelApproved).errors.some((e) => e.code === 'not-a-human-reviewer'));
    assert.equal(isAuthoritative(modelApproved, inv.id), false, 'a ledger that does not verify authorizes nothing');
    assert.equal(verifyLedger(null).ok, false);
  });

  test('[X-402.AC02] the hash chain is checked on its own: a record that re-computes a valid id and signature but points at the wrong predecessor is rejected', () => {
    // a permissive signer isolates the chain check from the signature check, and the id is recomputed so only `prev` is wrong
    const lax = { sign: () => 'ff', verify: () => true };
    const inv = mined()[0];
    const p = recordTransition(emptyLedger(), { action: 'propose', invariant: inv, actor: { id: 'miner', kind: 'code' }, reason: 'mined' }, { signer: lax });
    const a = recordTransition(p.ledger, { action: 'approve', invariantId: inv.id, actor: human('dana'), reason: 'ok' }, { policy: POLICY, signer: lax });
    assert.equal(verifyLedger(a.ledger, { signer: lax }).ok, true);
    const bad = clone(a.ledger);
    bad.records[1].prev = 'itrn:0000000000000000';
    bad.records[1].id = semanticId('itrn', bad.records[1], ['seq', 'invariantId', 'key', 'revision', 'action', 'from', 'to', 'actor', 'reason', 'supersededBy', 'prev']);
    const v = verifyLedger(bad, { signer: lax });
    assert.deepEqual(v.errors.map((e) => e.code), ['chain-broken']);
    assert.equal(verifyLedger({ schema: 'other', records: [] }).ok, false);
  });
});

describe('[X-402.AC03] reports distinguish candidate violations from violations of approved invariants and prevent model-generated contracts from establishing their own ground truth', () => {
  test('[X-402.AC03] a result without a runner-issued receipt classifies as unverified, however it is dressed up', () => {
    const inv = contract('tenant');
    const dressed = { outcome: 'confirmed', receipt: { issuedBy: 'verifier', settled: { outcome: 'confirmed' } }, record: { outcome: 'confirmed' } };
    assert.equal(classifyViolation({ invariant: inv, ledger: emptyLedger(), run: dressed }).kind, 'unverified');
    assert.equal(classifyViolation({ invariant: inv, ledger: emptyLedger(), run: { outcome: 'inconclusive' } }).kind, 'unverified');
    assert.equal(classifyViolation({ invariant: inv, ledger: emptyLedger(), run: null }).kind, 'unverified');
    assert.equal(classifyViolation({ invariant: inv, ledger: emptyLedger(), run: { outcome: 'confirmed', receipt: null } }).gating, false);
  });

  test('[X-402.AC03] the report keeps approved and candidate violations apart and only the approved group gates', () => {
    const entries = [
      { classification: { kind: 'candidate-violation', gating: false } }, { classification: { kind: 'candidate-violation', gating: false } },
      { classification: { kind: 'no-violation-observed', gating: false } }, { classification: { kind: 'unverified', gating: false } },
    ];
    const r = violationReport(entries);
    assert.equal(r.approvedViolations.length, 0);
    assert.equal(r.candidateViolations.length, 2);
    assert.equal(r.gating, false, 'candidates alone never gate');
    const withApproved = violationReport([...entries, { classification: { kind: 'approved-violation', gating: true } }]);
    assert.equal(withApproved.gating, true);
    assert.equal(withApproved.approvedViolations.length, 1);
    assert.equal(withApproved.candidateViolations.length, 2, 'the candidates stay in their own group');
    assert.match(r.note, /model-generated contract is never its own ground truth/);
    assert.equal(violationReport(undefined).gating, false);
  });

  test('[X-402.AC03] the same executed violation is a CANDIDATE for a proposed contract and an APPROVED violation after a reviewer approves it; a forged document or ledger changes nothing', needsBoundary(async () => {
    const config = await configWith('verification-oracles', 'invariant-scenarios');
    const fixture = fixtureOf(APPS.tenantVulnerable);
    const inv = contract('tenant', {
      author: { id: 'miner', kind: 'code' },
      review: { state: 'proposed', origin: 'inferred', sources: [{ source: 'specification-mining', file: 'app.mjs', line: 1 }], uncertainty: 0.6 },
    });
    const p = recordTransition(emptyLedger(), { action: 'propose', invariant: inv, actor: { id: 'miner', kind: 'code' }, reason: 'mined' });
    const run = (ledger, invariant = inv) => verifyInvariant({ invariant, fixture, commit: COMMIT, config, ledger });

    // proposed: the violation is real (executed, receipted) but it is a candidate and does not gate
    const asProposed = await run(p.ledger);
    assert.equal(asProposed.results[0].outcome, 'confirmed');
    assert.equal(asProposed.results[0].classification.kind, 'candidate-violation');
    assert.equal(asProposed.report.gating, false);
    assert.equal(asProposed.report.approvedViolations.length, 0);
    assert.equal(asProposed.report.candidateViolations.length, 1);

    // a document that CLAIMS approval, with no ledger entry, is still a candidate (and says why)
    const claimsApproved = createInvariant({ ...clone(inv), review: { ...inv.review, state: 'approved' } });
    const claimed = await run(p.ledger, claimsApproved);
    assert.equal(claimed.results[0].classification.kind, 'candidate-violation');
    assert.equal(claimed.results[0].classification.gating, false);
    assert.match(claimed.results[0].classification.reason, /document claims approval|not in the ledger/);

    // a forged approval written straight into the ledger data does not verify, so it does not gate
    const forgedLedger = clone(p.ledger);
    forgedLedger.records.push({ ...clone(p.ledger.records[0]), seq: 2, action: 'approve', from: 'proposed', to: 'approved', actor: { id: 'dana', kind: 'human' }, prev: p.ledger.records[0].id });
    const forged = await run(forgedLedger);
    assert.equal(forged.results[0].classification.kind, 'candidate-violation');
    assert.match(forged.results[0].classification.reason, /ledger does not verify/);

    // a reviewer approves it: the identical run is now a violation of an approved invariant and gates
    const a = recordTransition(p.ledger, { action: 'approve', invariantId: inv.id, actor: human('dana'), reason: 'this is a real requirement' }, { policy: POLICY });
    const asApproved = await run(a.ledger);
    assert.equal(asApproved.results[0].outcome, 'confirmed');
    assert.equal(asApproved.results[0].classification.kind, 'approved-violation');
    assert.equal(asApproved.report.gating, true);
    assert.equal(asApproved.report.approvedViolations.length, 1);
    assert.equal(asApproved.report.candidateViolations.length, 0);
    // the fixed application under the approved contract is not a violation
    const clean = await verifyInvariant({ invariant: inv, fixture: fixtureOf(APPS.tenantFixed), commit: COMMIT, config, ledger: a.ledger });
    assert.equal(clean.results[0].classification.kind, 'no-violation-observed');
    assert.equal(clean.report.gating, false);
  }));
});
