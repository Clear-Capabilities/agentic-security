// E4-07: a DCI finding goes through the existing reporting path and traces to rule, code, counterexample, fix recommendation and final verification.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildContext } from '../../src/context-intelligence/build.js';
import { normalizeConfig } from '../../src/context-intelligence/config.js';
import { findCrossRouteInconsistencies } from '../../src/context-intelligence/cross-route.js';
import { evaluateInvariants } from '../../src/context-intelligence/invariants.js';
import { candidatesFromEvidence, dciFindings, verifyDciFix } from '../../src/context-intelligence/findings.js';
import { describeFindingCompleteness } from '../../src/pipeline/finding-schema.js';
import { toSARIF } from '../../src/report/index.js';
import { validateFixVerificationRecord } from '../../src/fix/verification-record.js';

const NOW = new Date('2026-10-16T00:00:00Z');
const HEAD = "const app = require('express')();\nfunction requireUser(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }\n";
const GET = "app.get('/notes/:id', requireUser, async (req, res) => { const n = await db.notes.findOne({ id: req.params.id, ownerId: req.user.id }); if (!n) return res.sendStatus(404); res.json(n); });\n";
const PUT_BAD = "app.put('/notes/:id', requireUser, async (req, res) => { await db.notes.updateOne({ id: req.params.id }, { $set: req.body }); res.sendStatus(204); });\n";
const PUT_GOOD = "app.put('/notes/:id', requireUser, async (req, res) => { await db.notes.updateOne({ id: req.params.id, ownerId: req.user.id }, { $set: req.body }); res.sendStatus(204); });\n";
const BAD = HEAD + GET + PUT_BAD; const GOOD = HEAD + GET + PUT_GOOD;
const POLICY = { schema: 'agentic-security/dci-invariants', schemaVersion: '1.0.0', invariants: [{ id: 'NOTES-001', title: 'Notes are owner scoped', rule: 'requires', appliesTo: { routes: ['/notes/*'] }, requires: ['ownership'], severity: 'critical' }] };
const FIXTURE = { files: { 'app.js': BAD }, entry: 'app.js', victim: { user: { id: 'A' }, ownsId: 'n1', collection: 'notes', marker: 'S-A' }, attacker: { user: { id: 'B' } }, store: { notes: [{ id: 'n1', ownerId: 'A', secret: 'S-A' }] }, path: '/notes/n1', method: 'PUT', body: { secret: 'owned' }, siblingPath: '/notes/n1', siblingMethod: 'GET' };

async function analyse(files, opts = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e4g-'));
  try {
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}');
    for (const [f, t] of Object.entries(files)) fs.writeFileSync(path.join(root, f), t);
    const built = await buildContext(root, { config: normalizeConfig({}).config });
    const crossRoute = findCrossRouteInconsistencies(built.bundles, { now: NOW });
    const inv = evaluateInvariants(opts.policy || POLICY, built.bundles, { now: NOW });
    return { bundles: built.bundles, crossRoute, invariantResults: inv.results };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test('a proven cross-route finding comes out of the shared adjudication as an ordinary finding, with every link in the chain under contextIntelligence', async () => {
  const a = await analyse({ 'app.js': BAD });
  const candidates = candidatesFromEvidence({ crossRoute: a.crossRoute, bundles: a.bundles });
  assert.equal(candidates.length, 1);
  const r = await dciFindings({ candidates, bundles: a.bundles, fixtures: { 'PUT /notes/:id': FIXTURE } });
  assert.equal(r.findings.length, 1);
  const f = r.findings[0];
  assert.equal(f.parser, 'DISCOVERY'); assert.equal(f.family, 'authorization'); assert.equal(f.cwe, 'CWE-639'); assert.equal(f.severity, 'high');
  assert.ok(f.stableId && f.id && f.file === 'app.js' && Number.isInteger(f.line));
  assert.match(f.remediation, /Scope the data operation to the authenticated principal/);
  assert.equal(describeFindingCompleteness(f) !== undefined, true);
  const d = f.contextIntelligence.deterministic;
  assert.equal(d.rule.kind, 'cross-route-consistency');
  assert.deepEqual(d.scope.enforcedAt, ['GET /notes/:id']); assert.equal(d.scope.resource, 'note'); assert.equal(d.scope.control, 'ownership'); assert.equal(d.scope.route, 'PUT /notes/:id');
  assert.equal(d.counterexample.state, 'proven'); assert.ok(d.counterexample.trace.some((t) => t.kind === 'executed'));
  assert.ok(d.fix.recommendation.length > 40); assert.equal(d.verification.status, 'pending');
  assert.match(f.contextIntelligence.note, /no model produced this/);
  assert.equal(r.assessments[candidates[0].id], 'proven');
});

test('severity comes from the confirmation tier alone: proven is high, plausible is medium, unresolved is low, and a declared invariant severity is recorded, not used', async () => {
  const a = await analyse({ 'app.js': BAD });
  const cands = candidatesFromEvidence({ crossRoute: a.crossRoute, invariantResults: a.invariantResults, bundles: a.bundles });
  assert.ok(cands.some((c) => c.deterministic.rule.kind === 'invariant') && cands.some((c) => c.deterministic.rule.kind === 'cross-route-consistency'));
  const proven = await dciFindings({ candidates: cands, bundles: a.bundles, fixtures: { 'PUT /notes/:id': FIXTURE } });
  const bySev = Object.fromEntries(proven.findings.map((f) => [f.contextIntelligence.deterministic.rule.kind, f.severity]));
  assert.equal(bySev['cross-route-consistency'], 'high');
  assert.equal(bySev.invariant, 'medium', 'an invariant with no sibling to attempt is plausible: sink-adjacent, medium');
  const inv = proven.findings.find((f) => f.contextIntelligence.deterministic.rule.kind === 'invariant');
  assert.equal(inv.contextIntelligence.deterministic.rule.declaredSeverity, 'critical');
  assert.notEqual(inv.severity, 'critical', 'the policy\'s declared severity does not set the finding\'s severity');
  const noFixture = await dciFindings({ candidates: cands, bundles: a.bundles });
  assert.ok(noFixture.findings.every((f) => f.severity === 'medium'), noFixture.findings.map((f) => f.severity).join());
  assert.ok(!noFixture.findings.some((f) => f.severity === 'critical'));
});

test('a refuted candidate produces no finding and is reported separately; the safe route is never reported', async () => {
  const a = await analyse({ 'app.js': GOOD });
  assert.deepEqual(a.crossRoute.findings, []);
  const bad = await analyse({ 'app.js': BAD });
  const cands = candidatesFromEvidence({ crossRoute: bad.crossRoute, bundles: bad.bundles });
  const r = await dciFindings({ candidates: cands, bundles: bad.bundles, fixtures: { 'PUT /notes/:id': { ...FIXTURE, files: { 'app.js': GOOD } } } });
  assert.equal(r.findings.length, 0); assert.equal(r.counterexampleRefuted.length, 1); assert.equal(r.counterexampleRefuted[0].refutation.state, 'refuted');
});

test('the finding flows through the existing outputs: SARIF, duplicate detection against a prior scan, and triage suppression', async () => {
  const a = await analyse({ 'app.js': BAD });
  const cands = candidatesFromEvidence({ crossRoute: a.crossRoute, bundles: a.bundles });
  const first = await dciFindings({ candidates: cands, bundles: a.bundles, fixtures: { 'PUT /notes/:id': FIXTURE } });
  const f = first.findings[0];
  // the existing boundary (X-207): a hypothesis from the discovery pipeline is advisory. It is excluded from gating output and the exclusion is listed, never silent.
  const scan = { findings: [f], scanRoot: '.', supplyChain: [] };
  const sarif = toSARIF(scan, {});
  assert.equal(sarif.runs[0].results.length, 0, 'not a gating result until promoted');
  assert.equal(scan.advisoryExcluded.length, 1); assert.equal(scan.advisoryExcluded[0].stableId, f.stableId);
  assert.match(scan.advisoryExcluded[0].reason, /not a finding until promoted/);
  const { isAdvisoryHypothesis } = await import('../../src/posture/verification/advisory-state.js');
  assert.equal(isAdvisoryHypothesis(f), true);
  // once promoted the same finding is an ordinary SARIF result: nothing DCI-specific is needed
  const promoted = { ...f, parser: 'IR-TAINT' }; delete promoted.discovery;
  const sarif2 = toSARIF({ findings: [promoted], scanRoot: '.', supplyChain: [] }, {});
  assert.equal(sarif2.runs[0].results.length, 1);
  assert.match(JSON.stringify(sarif2.runs[0].results[0]), /app\.js/); assert.match(sarif2.runs[0].results[0].message.text, /enforce ownership on note; PUT \/notes\/:id \(update\) does not/);
  const again = await dciFindings({ candidates: cands, bundles: a.bundles, fixtures: { 'PUT /notes/:id': FIXTURE } });
  const withPrior = await (await import('../../src/context-intelligence/candidates.js')).adjudicate(cands.map(({ _bundle, _crossRoute, _invariant, ...c }) => ({ ...c, deterministic: again.findings[0].contextIntelligence.deterministic })), { taintProbe: async () => ({ tier: 'taint-confirmed' }), priorScan: { findings: [f] } });
  assert.equal(withPrior.findings.length, 0); assert.equal(withPrior.duplicates.length, 1);
  const fp = await (await import('../../src/context-intelligence/candidates.js')).adjudicate(cands.map(({ _bundle, _crossRoute, _invariant, ...c }) => c), { taintProbe: async () => ({ tier: 'taint-confirmed' }), triageFeedback: { [f.stableId]: 'fp' } });
  assert.equal(fp.suppressed.length, 1); assert.equal(fp.findings.length, 0);
});

test('no parallel reporting system: the finding has the shared shape, and DCI added nothing to the top level', async () => {
  const a = await analyse({ 'app.js': BAD });
  const r = await dciFindings({ candidates: candidatesFromEvidence({ crossRoute: a.crossRoute, bundles: a.bundles }), bundles: a.bundles, fixtures: { 'PUT /notes/:id': FIXTURE } });
  const keys = Object.keys(r.findings[0]).sort();
  const shared = ['cwe', 'description', 'discovery', 'family', 'file', 'id', 'line', 'parser', 'remediation', 'ruleId', 'severity', 'snippet', 'stableId', 'vuln', 'contextIntelligence'].sort();
  assert.deepEqual(keys, shared);
  const src = fs.readFileSync(new URL('../../src/context-intelligence/findings.js', import.meta.url), 'utf8');
  assert.match(src, /from '\.\/candidates\.js'/); assert.equal(/writeFile|JSON\.stringify\(.*report/.test(src.replace(/mkdtemp|writeFileSync\(path\.join\(root/g, '')), false, 'it writes no report of its own');
});

test('final verification: the patched tree no longer reports the inconsistency, the same attack is denied, and the record is a valid fix-verification record', async () => {
  const a = await analyse({ 'app.js': BAD });
  const cands = candidatesFromEvidence({ crossRoute: a.crossRoute, bundles: a.bundles });
  const r = await dciFindings({ candidates: cands, bundles: a.bundles, fixtures: { 'PUT /notes/:id': FIXTURE } });
  const finding = r.findings[0];
  const cand = cands[0];
  const ok = await verifyDciFix({ finding, candidate: cand, before: { 'app.js': BAD }, after: { 'app.js': GOOD }, fixture: FIXTURE, now: NOW });
  assert.equal(ok.status, 'verified');
  assert.equal(ok.stillInconsistent, false); assert.equal(ok.executedAfter.state, 'refuted');
  const v = validateFixVerificationRecord(ok.record); assert.equal(v.ok, true, JSON.stringify(v.errors));
  assert.equal(ok.record.securityBefore.status, 'passed'); assert.equal(ok.record.securityAfter.status, 'passed');
  assert.equal(ok.record.exploitProofBefore.status, 'passed'); assert.equal(ok.record.exploitProofAfter.status, 'passed');
  assert.equal(ok.record.behaviorTests.status, 'not_run', 'behaviour is covered by the fix verifier, not claimed here');
  assert.equal(ok.record.verifiedFull, false, 'behaviour was not run, so this is not a full verification');
  assert.equal(ok.record.fixCompleteness, 'MITIGATION');
  assert.ok(ok.record.degradedLegs.some((d) => d.startsWith('behaviorTests')));
  // an ineffective fix is caught by both the re-analysis and the executed attempt
  const cosmetic = HEAD + GET + PUT_BAD.replace('res.sendStatus(204);', 'res.sendStatus(204); /* ownerId: req.user.id */');
  const bad = await verifyDciFix({ finding, candidate: cand, before: { 'app.js': BAD }, after: { 'app.js': cosmetic }, fixture: FIXTURE, now: NOW });
  assert.equal(bad.status, 'failed'); assert.equal(bad.stillInconsistent, true); assert.equal(bad.record.securityAfter.status, 'failed');
});
