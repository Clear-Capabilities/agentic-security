#!/usr/bin/env node
// The contract-driven verification vertical slice, end to end, on the two-tenant invoice fixture (Phase 1 of the programme).
//
//   node scripts/contract-slice-example.mjs [--json]
//
// Stages, each carrying the same contract and invariant identity: validate the contract and its threat pack; propose and approve it
// in a local ledger (a fixture reviewer: NOT a real review); build the hash-bound context for the fixture; evaluate the deterministic
// context-intelligence invariants; hunt in contract-aware mode with a SCRIPTED model (a fixed function of the prompt: it proves the
// plumbing and says nothing about any model's effectiveness); qualify and challenge the candidates with evidence; run the executable
// tenant-isolation invariant through the business-state oracle on the vulnerable and the patched service; verify the repair with the
// four legs and the preservation of the authorized workflow; validate the regression artifact. Every leg that this host or this
// build cannot execute is printed as unsupported, never as a pass.
//
// Exit: 0 when every executed stage settled as the fixture predicts; 1 otherwise; 3 when the trust boundary cannot run on this host.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..', 'scanner');
const FIXTURE = path.join(SCANNER, 'test', 'fixtures', 'contract-slice');
const PATCH = path.join(SCANNER, 'test', 'fixtures', 'contract-slice-patch', 'service.mjs');
const json = process.argv.includes('--json');
const out = { schema: 'agentic-security/contract-slice-run', synthetic: true, host: { platform: process.platform, node: process.version }, stages: [] };
const stage = (name, status, detail) => { out.stages.push({ name, status, ...detail }); if (!json) console.log(`${status.padEnd(12)} ${name}${detail && detail.note ? `  ${detail.note}` : ''}`); };

const { validateContract, contractRef, invariantRef, bindingView } = await import(path.join(SCANNER, 'src/contracts/schema.js'));
const { reconcilePack } = await import(path.join(SCANNER, 'src/contracts/pack.js'));
const { proposeContract, approveContract, approvalState } = await import(path.join(SCANNER, 'src/contracts/approval.js'));
const { buildContext } = await import(path.join(SCANNER, 'src/context-intelligence/build.js'));
const { persistBuild } = await import(path.join(SCANNER, 'src/context-intelligence/persist.js'));
const { normalizeConfig } = await import(path.join(SCANNER, 'src/context-intelligence/config.js'));
const { evaluateInvariants } = await import(path.join(SCANNER, 'src/context-intelligence/invariants.js'));
const { setStateWritesEnabled } = await import(path.join(SCANNER, 'src/posture/state-dir.js'));
const { buildProjectIRAsync } = await import(path.join(SCANNER, 'src/ir/index.js'));
const { runDiscovery } = await import(path.join(SCANNER, 'src/discovery/index.js'));
const { VOTE_SCHEMA_V2 } = await import(path.join(SCANNER, 'src/discovery/disprove.js'));
const { createInvariant } = await import(path.join(SCANNER, 'src/posture/invariants/schema.js'));
const { verifyInvariant } = await import(path.join(SCANNER, 'src/posture/invariants/run.js'));
const { generateScenarios } = await import(path.join(SCANNER, 'src/posture/invariants/scenarios.js'));
const { verifyInvariantRepair, validateRegressionArtifact } = await import(path.join(SCANNER, 'src/posture/invariants/repair.js'));
const { emptyLedger, recordTransition } = await import(path.join(SCANNER, 'src/posture/invariants/lifecycle.js'));
const { resolveAssuranceConfig } = await import(path.join(SCANNER, 'src/posture/assurance/config.js'));

let failures = 0; const expect = (cond, what) => { if (!cond) failures += 1; return cond; };
const REVIEWER = { id: 'slice-fixture-reviewer', kind: 'human' }; const POLICY = { id: 'slice-fixture-policy', reviewers: [REVIEWER.id] };
const now = new Date().toISOString().slice(0, 10);

// 1. the contract and its pack
const contract = JSON.parse(fs.readFileSync(path.join(FIXTURE, 'security/contracts/invoices-service/contract.json'), 'utf8'));
const v = validateContract(contract);
const pack = reconcilePack(contract, fs.readFileSync(path.join(FIXTURE, 'security/contracts/invoices-service/threat-pack.md'), 'utf8'));
stage('contract validate', v.ok && pack.ok ? 'ok' : 'failed', { ref: contractRef(contract), errors: v.errors, packIssues: pack.issues, bindings: bindingView(contract), note: contractRef(contract) });
expect(v.ok && pack.ok);

// 2. approval in a local ledger (the fixture's reviewer; not a real review)
let ledger = proposeContract(null, contract, { actor: { id: 'slice-script', kind: 'code' }, reason: 'the slice proposes its own fixture contract' }).ledger;
ledger = approveContract(ledger, contract, { actor: REVIEWER, reason: 'fixture reviewer; synthetic', policy: POLICY }).ledger;
const approval = approvalState(contract, ledger, { policy: POLICY, now });
stage('contract approval', approval.state === 'approved' ? 'ok' : 'failed', { state: approval.state, transitionId: approval.transitionId, note: `${approval.state} by ${approval.reviewer} (fixture reviewer, synthetic)` });
expect(approval.state === 'approved');

// 3. context build on a disposable copy of the fixture
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-slice-'));
for (const f of ['service.mjs', 'server.js', 'context-intelligence-invariants.json']) fs.copyFileSync(path.join(FIXTURE, f), path.join(dir, f));
fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"contract-slice","private":true,"type":"module"}\n');
setStateWritesEnabled(true);
const { config } = normalizeConfig({});
const built = await buildContext(dir, { config });
const persisted = built.ok ? persistBuild(dir, built, config) : { ok: false, failures: [built.reason] };
stage('context build', built.ok && persisted.ok ? 'ok' : 'failed', { summary: built.summary, note: built.ok ? `${built.summary.bundlesBuilt} bundles, ${built.summary.complete} complete` : built.reason });
expect(built.ok && persisted.ok && built.summary.complete === 3);

// 4. deterministic context-intelligence invariants (the static binding of TENANT-ISOLATION-001)
const dci = evaluateInvariants(JSON.parse(fs.readFileSync(path.join(dir, 'context-intelligence-invariants.json'), 'utf8')), built.bundles);
const tenantVerdicts = Object.fromEntries(dci.results.filter((r) => r.invariantId === 'INVOICES-TENANT-SCOPE').map((r) => [r.label, r.verdict]));
stage('static invariants', tenantVerdicts['PUT /invoices/:id/memo'] === 'violated' && tenantVerdicts['GET /invoices/:id'] === 'satisfied' ? 'ok' : 'failed', { invariantRef: invariantRef(contract, 'TENANT-ISOLATION-001'), dciInvariant: 'INVOICES-TENANT-SCOPE', verdicts: tenantVerdicts, note: Object.entries(tenantVerdicts).map(([k, v2]) => `${k}=${v2}`).join(', ') });
expect(tenantVerdicts['PUT /invoices/:id/memo'] === 'violated');

// 5. the hunt in contract-aware mode with a scripted model
const fileContents = Object.fromEntries(['service.mjs', 'server.js'].map((f) => [f, fs.readFileSync(path.join(dir, f), 'utf8')]));
const ir = await buildProjectIRAsync(fileContents);
const scripted = async (prompt) => {
  if (/You are hunting/.test(prompt)) {
    const upd = prompt.split('\n').find((l) => /\|\s+db\.updateOne\(key, \{ \.\.\.rec, memo/.test(l));
    return JSON.stringify({ candidates: upd ? [{ title: 'Cross-tenant memo update', file: 'service.mjs', line: Number(upd.trim().split('|')[0]), code: upd.split('| ')[1], cwe: 'CWE-639', rationale: 'the update is not scoped by the principal\'s tenant', entryPoint: 'PUT /invoices/:id/memo', sink: 'db.updateOne', invariantId: 'TENANT-ISOLATION-001', attacker: { principal: 'tenant-member', tenant: 'globex' }, prerequisites: ['a valid session for any tenant'] }] : [] });
  }
  return JSON.stringify({ schema: VOTE_SCHEMA_V2, refuted: false, blocker: { kind: 'none', explanation: 'no control scopes this write', citations: [] } });
};
const hunt = await runDiscovery({ fileContents, perFileIR: ir.perFile, callGraph: ir.callGraph }, { scanRoot: dir, memory: false, lenses: ['authz'], maxAreas: 2, llmInvoke: scripted, contractMode: { contract, approval } });
const memo = (hunt.candidatesAll || []).find((c) => c.title === 'Cross-tenant memo update');
stage('hunt (scripted model)', memo && memo.qualification?.decision === 'qualified' ? 'ok' : 'failed', { synthetic: true, contract: hunt.contract, candidate: memo ? { qualification: memo.qualification.decision, invariantRef: memo.qualification.invariantRef, citation: memo.qualification.citations[0].status, history: memo.history } : null, attrition: hunt.attrition, note: memo ? `${memo.qualification.decision}; ${memo.qualification.invariantRef}; history ${memo.history.map((h) => h.stage + ':' + h.decision).join(' > ')}` : 'no candidate' });
expect(memo && memo.qualification?.decision === 'qualified');

// 6. the executable scenario on the vulnerable and the patched service
const inv = createInvariant(JSON.parse(fs.readFileSync(path.join(FIXTURE, 'invariants/invoices-tenant-isolation.json'), 'utf8')));
const aconfig = resolveAssuranceConfig({ env: {}, overrides: { features: { 'invariant-scenarios': true, 'verification-oracles': true, 'patch-negative-verification': true, 'invariant-repair': true } } });
const commit = contract.scope.repositories[0].revision;
let invLedger = recordTransition(emptyLedger(), { action: 'propose', invariant: inv, actor: { id: 'slice-script', kind: 'code' }, reason: 'slice' }).ledger;
invLedger = recordTransition(invLedger, { action: 'approve', invariantId: inv.id, actor: REVIEWER, reason: 'fixture reviewer; synthetic' }, { policy: POLICY }).ledger;
const fixture = { files: { 'service.mjs': fileContents['service.mjs'] } };
const patch = { files: { 'service.mjs': fs.readFileSync(PATCH, 'utf8') } };
const vul = await verifyInvariant({ invariant: inv, fixture, commit, config: aconfig, ledger: invLedger });
const fixed = await verifyInvariant({ invariant: inv, fixture: patch, commit, config: aconfig, ledger: invLedger });
const outcome = (r) => (r.results || []).map((x) => `${x.kind}:${x.status}/${x.outcome}/${x.classification?.kind}`).join(' ');
const boundaryRefused = vul.status !== 'ok' || (vul.results || []).some((r) => r.status !== 'completed');
if (boundaryRefused) stage('scenario (business-state oracle)', 'unsupported', { reason: vul.reason || (vul.results || [])[0]?.reason || 'the trust boundary did not run on this host', note: 'this host cannot run the trust boundary; not a pass' });
else stage('scenario (business-state oracle)', outcome(vul).includes('confirmed/approved-violation') && outcome(fixed).includes('refuted/no-violation-observed') ? 'ok' : 'failed', { invariantRef: invariantRef(contract, 'TENANT-ISOLATION-001'), scenarioInvariant: `${inv.key}@${inv.revision} ${inv.id}`, vulnerable: outcome(vul), patched: outcome(fixed), note: `vulnerable ${outcome(vul)}; patched ${outcome(fixed)}` });

// 7. the repair verified with preservation; the artifact carries the contract identity
let rep = null;
if (!boundaryRefused) {
  const scenario = generateScenarios(inv, { fixture, config: aconfig }).scenarios[0];
  rep = await verifyInvariantRepair({ invariant: inv, ledger: invLedger, scenario, fixture, patch, commit, contract: { ref: contractRef(contract), invariantId: 'TENANT-ISOLATION-001', approvalTransitionId: approval.transitionId } }, { config: aconfig });
  const valid = rep.artifact ? validateRegressionArtifact(rep.artifact) : { ok: false };
  stage('repair verification', rep.status === 'verified-fix' && valid.ok && rep.artifact.contract?.ref === contractRef(contract) ? 'ok' : 'failed', { status: rep.status, blockers: rep.blockers, artifact: rep.artifact ? { id: rep.artifact.id, contract: rep.artifact.contract, legs: rep.artifact.legs.map((l) => l.role) } : null, note: `${rep.status}; artifact ${rep.artifact ? rep.artifact.id + ' contract ' + rep.artifact.contract.ref : 'none'}` });
  expect(rep.status === 'verified-fix' && valid.ok);
  const denyAll = { files: { 'service.mjs': patch.files['service.mjs'].replace('export function setInvoiceMemo(db, principal, key, payload) {', 'export function setInvoiceMemo(db, principal, key, payload) {\n  return { status: 403 };') } };
  const rep2 = await verifyInvariantRepair({ invariant: inv, ledger: invLedger, scenario, fixture, patch: denyAll, commit }, { config: aconfig });
  stage('repair that blocks everyone', rep2.status === 'not-verified-fix' && rep2.blockers.some((b) => b.code === 'authorized-workflow-broken') ? 'ok' : 'failed', { status: rep2.status, blockers: rep2.blockers.map((b) => b.code), note: `${rep2.status} (${rep2.blockers.map((b) => b.code).join(', ')})` });
  expect(rep2.status === 'not-verified-fix');
} else stage('repair verification', 'unsupported', { note: 'depends on the scenario leg' });

// what this run does not establish
out.unsupported = [
  'runtime predicate and preservation bindings of the contract: no producer in this build (bindingView gaps)',
  'Linux trust boundary for the business-state oracle: not advertised; this run executed only where the host boundary runs',
  'a real framework or database: the fixture is plain Node over an in-memory store',
  'model effectiveness: the model here is a scripted function of the prompt',
];
if (!json) { console.log(''); for (const u of out.unsupported) console.log(`unsupported  ${u}`); }
fs.rmSync(dir, { recursive: true, force: true });
setStateWritesEnabled(false);
if (json) console.log(JSON.stringify(out, null, 2));
process.exit(boundaryRefused ? 3 : failures ? 1 : 0);
