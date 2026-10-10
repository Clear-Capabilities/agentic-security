// REL-003: the protected final closure, decision half. Every guard is exercised in both directions: a fully passing synthetic
// fact set closes, and each single deliberate defect (a failed, skipped, stale, waived or blocked criterion, a missing receipt for
// another requirement, a DAG inconsistency, a changed evidence hash, a dirty tree, an unmeasured gate...) prevents closure with the
// reason named. The controller half (a real run in a disposable repository) is in final-closure-controller.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO } from '../helpers/closure-fixtures.js';
import {
  evaluateClosure, checkDag, checkReceipts, checkEvidenceHashes, checkRequiredGates, checkMeasured, checkLimits, checkScope, checkDeliverables,
  rehashReceipts, gitFacts, parseMeasured, fileSetDeliverable, implementationDiff, prdLedger, unmetByRequirement, DELIVERABLE_KINDS,
} from '../../../scripts/loop-engineering/lib/closure.mjs';
import { validateClosureConfig } from '../../../scripts/loop-engineering/lib/closure-config.mjs';
import { buildAssuranceBundle } from '../../../scripts/loop-engineering/lib/closure-bundle.mjs';
import { verifyBundle } from '../../../scanner/src/posture/portfolio/bundle.js';
import { loadProfile, validateProfile } from '../../../scripts/loop-engineering/lib/profile.mjs';
import { createManifest } from '../../../scripts/loop-engineering/lib/manifest.mjs';
import { assessFinal, writeFinalEvidence } from '../../../scripts/loop-engineering/lib/final.mjs';

const PROFILE_PATH = path.join(REPO, 'scripts', 'loop-engineering', 'profiles', 'assurance-differentiation.json');
const PRD_FIXTURE = path.join(REPO, 'scripts', 'loop-engineering', 'test', 'fixtures', 'assurance-prd-section8.md');
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

// ------------------------------------------------------------------ a small closing world

const req = (id, deps = [], n = 2) => ({ id, weight: 2, dependencies: deps, criteria: Array.from({ length: n }, (_, i) => ({ id: `${id}.AC${String(i + 1).padStart(2, '0')}`, text: 't' })), category: 'x', verification: { kind: 'node-test' }, watch: [] });
const MANIFEST = () => {
  const requirements = [req('A-1'), req('A-2', ['A-1']), req('B-1'), req('REL-3', ['A-2', 'B-1'])];
  return { requirements, totals: { requirements: 4, criteria: 8, weight: 8 }, prd: { path: 'PRD.md', sha256: 'p'.repeat(64) }, acceptanceHash: 'h'.repeat(64) };
};
const CONFIG = () => ({
  releaseRequirement: 'REL-3', expect: { requirements: 4, criteria: 8, weight: 8 }, requireCleanTree: true,
  requiredGates: { quality: ['q'], routing: ['r'], release: ['rel'] },
  limits: { max: { runWallSeconds: 600, runMaxAttempts: 40, claudeBudgetUsd: 50, resource: { maxRssMiB: 2048 } }, min: { resource: { minFreeDiskGiB: 1 } } },
});
const T0 = '2026-01-01T00:00:00.000Z';
const ORDER = () => ({ phaseStartedAt: T0, validatedAt: '2026-01-01T00:00:11.000Z', closureStartedAt: '2026-01-01T00:00:12.000Z', issuedAt: '2026-01-01T00:00:30.000Z' });
const receiptFor = (r) => ({
  id: r.id, found: true, file: `/e/${r.id}.json`, fileSha256: 'a'.repeat(64), fileSha256AtIssue: 'a'.repeat(64), evidenceId: `${r.id}-000001`,
  valid: true, invalidReasons: [], fresh: true, staleReasons: [], invoker: 'controller', phase: 'final', result: 'pass', createdAt: '2026-01-01T00:00:10.000Z',
  counts: { tests: 2, pass: 2, fail: 0, skipped: 0 }, criteria: r.criteria.map((c) => ({ id: c.id, state: 'pass' })), blockerType: null, logProblems: [],
});
const PASSING_DELIVERABLES = () => DELIVERABLE_KINDS.map((kind) => ({ kind, status: 'complete' }));
const facts = (over = {}) => {
  const manifest = MANIFEST();
  return {
    config: CONFIG(), manifest, receipts: new Map(manifest.requirements.map((r) => [r.id, receiptFor(r)])), order: ORDER(),
    gates: ['q', 'r', 'rel'].map((id) => ({ id, ok: true, exitCode: 0 })), expectedGates: ['q', 'r', 'rel'],
    measured: [{ id: 'm', group: 'quality', ran: true, status: 'pass', synthetic: false }],
    treeDigests: { before: 'd', afterEach: ['d', 'd'], after: 'd' }, git: { head: 'c'.repeat(40), dirty: false, dirtyCount: 0 },
    limits: { profile: { runWallSeconds: 600, runMaxAttempts: 40, claudeBudgetUsd: 50, resource: { maxRssMiB: 2048, minFreeDiskGiB: 1 } }, frozen: { runWallSeconds: 600, runMaxAttempts: 40, claudeBudgetUsd: 50, resource: { maxRssMiB: 2048, minFreeDiskGiB: 1 } }, used: { attemptsUsed: 3, usdUsed: 0, wallUsedMs: 1000 }, runBlockers: [] },
    scope: { platform: 'darwin', supported: ['darwin', 'linux'], unsupported: ['win32'], files: [{ path: 'docs/scope.md', present: true }] },
    deliverables: PASSING_DELIVERABLES(), ...over,
  };
};
const kinds = (d) => d.unmet.map((u) => u.kind);
const mutate = (fn) => { const f = facts(); fn(f); return evaluateClosure(f); };
const has = (d, kind, id) => d.unmet.some((u) => u.kind === kind && (id === undefined || u.id === id));

// ------------------------------------------------------------------ REL-003.AC01

test('[REL-003.AC01] a fully passing world closes at the expected requirement and criterion counts', () => {
  const d = evaluateClosure(facts());
  assert.equal(d.closed, true, JSON.stringify(d.unmet));
  assert.equal(d.verdict, 'all-required-criteria-verified');
  assert.deepEqual(d.counts, { requirements: { verified: 4, expected: 4 }, criteria: { verified: 8, expected: 8 } });
  assert.deepEqual(d.open, []);
});

test('[REL-003.AC01] a failed, skipped, stale, waived or blocked criterion prevents closure, each with its own reason', () => {
  const cases = [
    ['failed', (f) => { f.receipts.get('A-1').criteria[0].state = 'fail'; f.receipts.get('A-1').result = 'fail'; }, 'criterion-failed', 'A-1.AC01'],
    ['skipped', (f) => { f.receipts.get('B-1').counts.skipped = 1; }, 'criterion-skipped', 'B-1'],
    ['stale', (f) => { Object.assign(f.receipts.get('A-2'), { fresh: false, staleReasons: ['relevant source/test files changed'] }); }, 'receipt-stale', 'A-2'],
    ['waived', (f) => { f.receipts.get('A-1').criteria[1].state = 'waived'; }, 'criterion-waived', 'A-1.AC02'],
    ['blocked', (f) => { Object.assign(f.receipts.get('B-1'), { result: 'blocked', blockerType: 'missing-tool' }); }, 'criterion-blocked', 'B-1'],
  ];
  for (const [name, fn, kind, id] of cases) {
    const d = mutate(fn);
    assert.equal(d.closed, false, `${name} must prevent closure`);
    assert.equal(d.verdict, 'incomplete');
    assert.ok(has(d, kind, id), `${name}: expected ${kind} ${id}, got ${JSON.stringify(d.unmet)}`);
    assert.ok(d.counts.criteria.verified < 8 || d.counts.requirements.verified < 4, `${name}: counts must fall short of the expected totals`);
  }
});

test('[REL-003.AC01] a passing criterion inside a failed or skipped receipt is not counted toward the criteria total, and is not reported as invalid', () => {
  const f = facts();
  const a1 = f.manifest.requirements.find((r) => r.id === 'A-1');
  f.receipts.get('A-1').result = 'fail'; f.receipts.get('A-1').criteria[0].state = 'fail';
  const failed = checkReceipts({ requirements: [a1], receipts: f.receipts, phaseStartedAt: T0 });
  assert.equal(failed.passedCriteria, 0, 'AC02 reads pass, but the receipt it sits in failed');
  assert.deepEqual(failed.unmet.map((u) => u.kind).sort(), ['criterion-failed', 'criterion-failed'], 'the receipt and the failing criterion; the passing one adds nothing');
  const g = facts();
  g.receipts.get('A-1').counts.skipped = 2;
  const skipped = checkReceipts({ requirements: [a1], receipts: g.receipts, phaseStartedAt: T0 });
  assert.equal(skipped.passedCriteria, 0);
  assert.deepEqual(skipped.unmet.map((u) => u.kind), ['criterion-skipped']);
  assert.equal(checkReceipts({ requirements: [a1], receipts: facts().receipts, phaseStartedAt: T0 }).passedCriteria, 2, 'direction two: a clean receipt counts both');
});

test('[REL-003.AC01] a missing, invalid, non-independent or pre-phase receipt for any OTHER requirement prevents closure', () => {
  for (const id of ['A-1', 'A-2', 'B-1']) {
    const d = mutate((f) => { f.receipts.set(id, { id, found: false }); });
    assert.equal(d.closed, false);
    assert.ok(has(d, 'receipt-missing', id), `${id}: ${JSON.stringify(d.unmet)}`);
  }
  assert.ok(has(mutate((f) => { Object.assign(f.receipts.get('A-1'), { valid: false, invalidReasons: ['bad signature (forged or edited evidence)'] }); }), 'receipt-invalid', 'A-1'));
  assert.ok(has(mutate((f) => { f.receipts.get('A-1').invoker = 'worker-invoked'; }), 'receipt-not-independent', 'A-1'));
  assert.ok(has(mutate((f) => { f.receipts.get('A-1').invoker = 'cli'; }), 'receipt-not-independent', 'A-1'));
  assert.ok(has(mutate((f) => { f.receipts.get('B-1').createdAt = '2025-12-31T23:59:00.000Z'; }), 'receipt-not-fresh', 'B-1'), 'a receipt that predates the final phase is not fresh');
  assert.ok(has(mutate((f) => { f.receipts.get('B-1').phase = 'post-attempt'; }), 'receipt-not-fresh', 'B-1'));
});

test('[REL-003.AC01] the closure requirement itself must pass all of its criteria on this tree', () => {
  assert.ok(has(mutate((f) => { f.receipts.get('REL-3').criteria[2 - 1].state = 'fail'; f.receipts.get('REL-3').result = 'fail'; }), 'criterion-failed', 'REL-3.AC02'));
  assert.ok(has(mutate((f) => { f.receipts.set('REL-3', { id: 'REL-3', found: false }); }), 'receipt-missing', 'REL-3'));
  assert.ok(has(mutate((f) => { f.receipts.get('REL-3').criteria.pop(); }), 'criterion-missing', 'REL-3.AC02'));
});

test('[REL-003.AC01] receipts are validated BEFORE the closure criteria run, and the record is issued LAST', () => {
  assert.equal(evaluateClosure(facts()).closed, true);
  const wrong = [
    ['closure criteria ran before the other receipts were validated', (o) => { o.closureStartedAt = '2026-01-01T00:00:05.000Z'; }],
    ['issued before the closure criteria finished starting', (o) => { o.issuedAt = '2026-01-01T00:00:11.500Z'; }],
    ['validation timestamp missing', (o) => { delete o.validatedAt; }],
  ];
  for (const [name, fn] of wrong) {
    const d = mutate((f) => fn(f.order));
    assert.equal(d.closed, false, name);
    assert.ok(has(d, 'order', 'finalization'), name);
  }
});

test('[REL-003.AC01] closure needs the EXPECTED counts: a shorter world that passes everything it has does not close', () => {
  const f = facts();
  f.manifest.requirements = f.manifest.requirements.filter((r) => r.id !== 'B-1');
  f.manifest.requirements.find((r) => r.id === 'REL-3').dependencies = ['A-2'];
  f.manifest.totals = { requirements: 3, criteria: 6, weight: 6 };
  const d = evaluateClosure(f);
  assert.equal(d.closed, false);
  assert.ok(has(d, 'count', 'requirements') && has(d, 'count', 'criteria'), JSON.stringify(d.unmet));
  assert.ok(has(d, 'dag', 'totals'), 'the manifest itself no longer has the expected totals');
});

test('[REL-003.AC01] a dirty tree, an unreadable tree state and an unstable digest each prevent closure', () => {
  const dirty = mutate((f) => { f.git = { head: 'c'.repeat(40), dirty: true, dirtyCount: 3 }; });
  assert.ok(has(dirty, 'dirty-tree') && !dirty.closed);
  assert.ok(has(mutate((f) => { f.git = null; }), 'dirty-tree'));
  assert.ok(has(mutate((f) => { f.treeDigests.afterEach = ['d', 'e']; }), 'tree-unstable'));
  assert.ok(has(mutate((f) => { f.treeDigests.after = 'x'; }), 'tree-unstable'));
  assert.ok(has(mutate((f) => { f.treeDigests.before = null; }), 'tree-unstable'));
  // direction two: the same dirty state is tolerated only by a profile that explicitly says so, and that is visible in the config
  const lenient = facts(); lenient.config.requireCleanTree = false; lenient.git = { head: 'c'.repeat(40), dirty: true, dirtyCount: 3 };
  assert.equal(evaluateClosure(lenient).closed, true);
});

// ------------------------------------------------------------------ REL-003.AC02

test('[REL-003.AC02] DAG consistency: a cycle, an unknown or self dependency, a malformed criterion id and wrong totals are named', () => {
  assert.deepEqual(checkDag(MANIFEST(), { requirements: 4, criteria: 8, weight: 8 }), []);
  const cyc = MANIFEST(); cyc.requirements[0].dependencies = ['A-2'];
  assert.ok(checkDag(cyc).some((u) => u.id === 'graph' && /cycle/.test(u.reason)));
  const unk = MANIFEST(); unk.requirements[1].dependencies = ['NOPE-9'];
  assert.ok(checkDag(unk).some((u) => u.id === 'A-2' && /unknown|not a requirement/.test(u.reason)));
  const self = MANIFEST(); self.requirements[2].dependencies = ['B-1'];
  assert.ok(checkDag(self).some((u) => u.id === 'B-1' && /itself/.test(u.reason)));
  const badId = MANIFEST(); badId.requirements[0].criteria[1].id = 'A-1.AC07';
  assert.ok(checkDag(badId).some((u) => u.id === 'A-1' && /sequential/.test(u.reason)));
  const dup = MANIFEST(); dup.requirements[1].id = 'A-1';
  assert.ok(checkDag(dup).some((u) => /twice/.test(u.reason)));
  const tot = MANIFEST(); tot.totals.criteria = 9;
  assert.ok(checkDag(tot).some((u) => u.id === 'totals'));
  assert.ok(checkDag(MANIFEST(), { requirements: 70, criteria: 210, weight: 269 }).some((u) => u.id === 'totals'));
  // through the whole decision
  const d = mutate((f) => { f.manifest.requirements[0].dependencies = ['A-2']; });
  assert.ok(!d.closed && has(d, 'dag', 'graph'));
});

test('[REL-003.AC02] a requirement that passes while its dependency does not is a DAG inconsistency, not a success', () => {
  const d = mutate((f) => { Object.assign(f.receipts.get('A-1'), { result: 'fail', criteria: f.receipts.get('A-1').criteria.map((c) => ({ ...c, state: 'fail' })) }); });
  assert.equal(d.closed, false);
  assert.ok(has(d, 'dag', 'A-2') && /dependency A-1/.test(d.unmet.find((u) => u.kind === 'dag' && u.id === 'A-2').reason), JSON.stringify(d.unmet));
});

test('[REL-003.AC02] evidence hashes: a file changed between validation and issuance, an unhashable file and a log mismatch all prevent closure', () => {
  assert.deepEqual(checkEvidenceHashes(facts().receipts), []);
  assert.ok(has(mutate((f) => { f.receipts.get('A-1').fileSha256AtIssue = 'f'.repeat(64); }), 'evidence-hash', 'A-1'));
  assert.ok(has(mutate((f) => { f.receipts.get('B-1').fileSha256 = null; }), 'evidence-hash', 'B-1'));
  assert.ok(has(mutate((f) => { f.receipts.get('B-1').logProblems = ['log hash mismatch: /x.log']; }), 'evidence-hash', 'B-1'));
  // a real file: hash taken, file edited, hash retaken -> the pair no longer agrees
  const dir = mkTestTmp('closure-hash-');
  const file = path.join(dir, 'e.json'); fs.writeFileSync(file, '{"a":1}');
  const rc = new Map([['X', { id: 'X', found: true, file, fileSha256: sha(fs.readFileSync(file)) }]]);
  fs.writeFileSync(file, '{"a":2}');
  rehashReceipts(rc);
  assert.ok(checkEvidenceHashes(rc).some((u) => u.kind === 'evidence-hash' && /changed between validation and issuance/.test(u.reason)));
  fs.writeFileSync(file, '{"a":1}');
  const same = new Map([['X', { id: 'X', found: true, file, fileSha256: sha(fs.readFileSync(file)) }]]);
  rehashReceipts(same);
  assert.deepEqual(checkEvidenceHashes(same), []);
});

test('[REL-003.AC02] quality, routing and release gates are required by name: a missing or failing one prevents closure', () => {
  const cfg = CONFIG().requiredGates;
  assert.deepEqual(checkRequiredGates({ gates: [{ id: 'q', ok: true }, { id: 'r', ok: true }, { id: 'rel', ok: true }], requiredGates: cfg }), []);
  for (const id of ['q', 'r', 'rel']) {
    const missing = mutate((f) => { f.gates = f.gates.filter((g) => g.id !== id); });
    assert.ok(has(missing, 'gate-missing', id) && !missing.closed, id);
    const failed = mutate((f) => { f.gates.find((g) => g.id === id).ok = false; f.gates.find((g) => g.id === id).exitCode = 1; });
    assert.ok(has(failed, 'gate-failed', id) && !failed.closed, id);
  }
  // the named-gate check on its own, not only through the whole decision
  const direct = checkRequiredGates({ gates: [{ id: 'q', ok: false, exitCode: 2 }, { id: 'rel', ok: true }], requiredGates: cfg });
  assert.deepEqual(direct.map((u) => [u.kind, u.id]), [['gate-failed', 'q'], ['gate-missing', 'r']]);
  // a gate the profile runs but the closure does not name is still an expected gate
  const extra = mutate((f) => { f.expectedGates = [...f.expectedGates, 'other']; });
  assert.ok(has(extra, 'gate-missing', 'other'));
});

test('[REL-003.AC02] measured gates: only a non-synthetic pass counts; synthetic, insufficient-population and unmeasured stay OPEN', () => {
  assert.deepEqual(checkMeasured([{ id: 'm', group: 'quality', ran: true, status: 'pass', synthetic: false }]), { unmet: [], open: [] });
  for (const [status, synthetic] of [['pass', true], ['insufficient-population', false], ['unmeasured', true], ['fail', false]]) {
    const d = mutate((f) => { f.measured = [{ id: 'm', group: 'quality', ran: true, status, synthetic }]; });
    assert.equal(d.closed, false, `${status}/${synthetic}`);
    assert.equal(d.open.length, 1, `${status}/${synthetic}`);
    assert.equal(d.open[0].kind, 'open-gate');
    assert.equal(d.verdict, 'incomplete');
  }
  const didNotRun = mutate((f) => { f.measured = [{ id: 'm', group: 'routing', ran: false, reason: 'exit 1' }]; });
  assert.ok(has(didNotRun, 'gate-missing', 'm') && !didNotRun.closed);
  assert.deepEqual(parseMeasured('status-json', '{"status":"unmeasured","synthetic":true}'), { status: 'unmeasured', synthetic: true });
  assert.equal(parseMeasured('status-json', 'not json at all').status, 'unmeasured');
  const ev = parseMeasured('evaluation-gates', JSON.stringify({ synthetic: true, results: [{ gatesOverall: 'pass' }, { gatesOverall: 'insufficient-population' }] }));
  assert.deepEqual(ev, { status: 'insufficient-population', synthetic: true });
  assert.equal(parseMeasured('evaluation-gates', '{"results":[{"gatesOverall":"pass"}]}').status, 'pass');
});

test('[REL-003.AC02] controller limits: a changed, over-ceiling or exhausted budget, or a run-level blocker, prevents closure', () => {
  const ok = facts().limits;
  assert.deepEqual(checkLimits({ profileLimits: ok.profile, frozenLimits: ok.frozen, config: CONFIG().limits, used: ok.used, runBlockers: [] }), []);
  assert.ok(has(mutate((f) => { f.limits.profile = { ...f.limits.profile, claudeBudgetUsd: 51 }; f.limits.frozen = f.limits.profile; }), 'limits'), 'above the ceiling');
  assert.ok(has(mutate((f) => { f.limits.profile = { ...f.limits.profile, runWallSeconds: 601 }; }), 'limits'), 'profile no longer equals the frozen limits');
  assert.ok(has(mutate((f) => { f.limits.profile = { ...f.limits.profile, resource: { maxRssMiB: 2048, minFreeDiskGiB: 0.5 } }; f.limits.frozen = f.limits.profile; }), 'limits'), 'below the floor');
  assert.ok(has(mutate((f) => { f.limits.used.attemptsUsed = 41; }), 'limits'));
  assert.ok(has(mutate((f) => { f.limits.used.usdUsed = 51; }), 'limits'));
  assert.ok(has(mutate((f) => { f.limits.used.wallUsedMs = 601000; }), 'limits'));
  assert.ok(has(mutate((f) => { f.limits.runBlockers = [{ type: 'auth-missing' }]; }), 'limits'));
  assert.ok(has(mutate((f) => { delete f.limits.profile.runMaxAttempts; delete f.limits.frozen.runMaxAttempts; }), 'limits'), 'a limit that is not set is not within its ceiling');
});

test('[REL-003.AC02] supported scope: an unsupported platform and a missing scope document prevent closure', () => {
  assert.deepEqual(checkScope(facts().scope), []);
  const win = mutate((f) => { f.scope.platform = 'win32'; });
  assert.ok(has(win, 'scope', 'platform') && /listed as unsupported/.test(win.unmet.find((u) => u.id === 'platform').reason));
  assert.ok(has(mutate((f) => { f.scope.files = [{ path: 'docs/scope.md', present: false }]; }), 'scope', 'docs/scope.md'));
  assert.ok(has(mutate((f) => { f.scope.platform = 'plan9'; }), 'scope', 'platform'));
});

test('[REL-003.AC02] the real profile declares the protected checks beyond per-requirement tests, and every required gate actually runs', () => {
  const { profile } = loadProfile(PROFILE_PATH);
  validateProfile(profile, REPO);
  const c = profile.finalVerification.closure;
  assert.equal(c.releaseRequirement, 'REL-003');
  assert.deepEqual(c.expect, { requirements: 70, criteria: 210, weight: 269 });
  const gateIds = profile.finalGates.map((g) => g.id);
  for (const group of ['quality', 'routing', 'release']) assert.ok(c.requiredGates[group].length > 0, `${group} gates are required`);
  for (const id of [...c.requiredGates.quality, ...c.requiredGates.routing, ...c.requiredGates.release]) assert.ok(gateIds.includes(id), `${id} is a final gate`);
  assert.ok(c.requiredGates.release.includes('release-closure-check'), 'the release closure check is a required release gate');
  assert.ok(c.requiredGates.routing.includes('bench-router-replay'));
  assert.ok(c.measuredGates.some((m) => m.group === 'quality') && c.measuredGates.some((m) => m.group === 'routing'), 'a measured quality and a measured routing gate');
  assert.equal(c.requireCleanTree, true);
  // the PRD section 7 ceilings are what the closure holds the profile to
  assert.equal(c.limits.max.runWallSeconds, 43200); assert.equal(c.limits.max.runMaxAttempts, 150); assert.equal(c.limits.max.claudeBudgetUsd, 50);
  assert.equal(c.limits.max.perAttemptBudgetUsd, 6); assert.equal(c.limits.min.resource.minFreeDiskGiB, 5);
  assert.deepEqual(checkLimits({ profileLimits: profile.limits, frozenLimits: profile.limits, config: c.limits, used: { attemptsUsed: 0, usdUsed: 0, wallUsedMs: 0 }, runBlockers: [] }), [], 'the real profile limits sit inside its own ceilings');
});

test('[REL-003.AC02] the frozen manifest of the real profile gets the expected 70 requirements, 210 criteria and weight 269, and a clean DAG', () => {
  const { profile, sha256: psha } = loadProfile(PROFILE_PATH);
  const dir = mkTestTmp('closure-manifest-');
  fs.copyFileSync(PRD_FIXTURE, path.join(dir, 'PRD.md'));
  const { manifest } = createManifest({ repoRoot: dir, prdPath: 'PRD.md', profile, profileSha: psha });
  assert.deepEqual(manifest.totals, { requirements: 70, criteria: 210, weight: 269 });
  assert.deepEqual(checkDag(manifest, profile.finalVerification.closure.expect), []);
  assert.equal(manifest.finalVerification.closure.releaseRequirement, 'REL-003');
  assert.ok(manifest.requirements.find((r) => r.id === 'REL-003'));
  // direction two: the same manifest against a wrong expectation is not clean
  assert.ok(checkDag(manifest, { requirements: 69, criteria: 210, weight: 269 }).length > 0);
});

test('[REL-003.AC02] a closure block that names a gate the profile does not run, or omits its ceilings, is rejected at profile validation', () => {
  const gates = ['q', 'r', 'rel'];
  const good = { releaseRequirement: 'REL-3', expect: { requirements: 4, criteria: 8, weight: 8 }, requiredGates: { quality: ['q'], routing: ['r'], release: ['rel'] }, limits: { max: { runWallSeconds: 1 } }, deliverables: { scorecards: ['a'], policyCards: ['b'], replayableFixtures: ['c'], artifacts: ['d'] } };
  assert.deepEqual(validateClosureConfig(good, gates), []);
  assert.ok(validateClosureConfig({ ...good, requiredGates: { ...good.requiredGates, quality: ['ghost'] } }, gates).some((p) => /ghost/.test(p) && /must actually run/.test(p)));
  assert.ok(validateClosureConfig({ ...good, limits: {} }, gates).some((p) => /limits\.max/.test(p)));
  assert.ok(validateClosureConfig({ ...good, expect: { requirements: 0 } }, gates).length >= 3);
  assert.ok(validateClosureConfig({ ...good, deliverables: { ...good.deliverables, artifacts: [] } }, gates).some((p) => /artifacts/.test(p)));
  assert.ok(validateClosureConfig({ ...good, measuredGates: [{ id: 'x', group: 'quality', executable: 'node', args: [], timeoutSeconds: 5, parse: 'free-text' }] }, gates).some((p) => /parse/.test(p)));
  assert.ok(validateClosureConfig(null, gates).length > 0);
});

// ------------------------------------------------------------------ REL-003.AC03

test('[REL-003.AC03] a missing deliverable of any of the six kinds prevents closure and is named', () => {
  for (const kind of DELIVERABLE_KINDS) {
    const d = mutate((f) => { f.deliverables = f.deliverables.filter((x) => x.kind !== kind); });
    assert.equal(d.closed, false, kind);
    assert.ok(has(d, 'deliverable-missing', kind), kind);
    const d2 = mutate((f) => { f.deliverables.find((x) => x.kind === kind).status = 'missing'; f.deliverables.find((x) => x.kind === kind).reason = 'because'; });
    assert.ok(has(d2, 'deliverable-missing', kind) && !d2.closed, kind);
  }
  assert.deepEqual(DELIVERABLE_KINDS, ['implementation-diff', 'prd-ledger', 'scorecards', 'policy-cards', 'replayable-fixtures', 'release-assurance-bundle']);
});

test('[REL-003.AC03] a deliverable that describes unfinished work is OPEN: listed, never counted as completion', () => {
  const d = mutate((f) => { f.deliverables.find((x) => x.kind === 'release-assurance-bundle').status = 'open'; f.deliverables.find((x) => x.kind === 'release-assurance-bundle').reason = '2 checks unsupported'; });
  assert.equal(d.closed, false);
  assert.equal(d.verdict, 'incomplete');
  assert.deepEqual(d.open.map((o) => [o.kind, o.id]), [['deliverable-open', 'release-assurance-bundle']]);
  assert.equal(d.unmet.length, 0, 'open is not a failure to produce the deliverable, and it is not a pass either');
  assert.deepEqual(checkDeliverables(PASSING_DELIVERABLES()), { unmet: [], open: [] });
});

test('[REL-003.AC03] an unsupported measured gate is left OPEN even when every requirement and every other gate passes', () => {
  const d = mutate((f) => { f.measured = [{ id: 'real-code-evaluation', group: 'quality', ran: true, status: 'insufficient-population', synthetic: true }]; });
  assert.equal(d.unmet.length, 0, 'nothing failed: this is purely an open gate');
  assert.equal(d.counts.requirements.verified, 4);
  assert.equal(d.counts.criteria.verified, 8);
  assert.equal(d.closed, false, 'all counts at the expected totals still does not close with an open gate');
  assert.equal(d.verdict, 'incomplete');
  assert.match(d.open[0].reason, /synthetic population.*stays open/);
});

test('[REL-003.AC03] fileSetDeliverable: present files are hashed; a missing or empty file makes the deliverable missing', () => {
  const dir = mkTestTmp('closure-files-');
  fs.writeFileSync(path.join(dir, 'a.json'), '{"x":1}'); fs.writeFileSync(path.join(dir, 'empty.md'), '');
  const ok = fileSetDeliverable('scorecards', dir, ['a.json']);
  assert.equal(ok.status, 'complete'); assert.equal(ok.files[0].sha256, sha('{"x":1}'));
  const bad = fileSetDeliverable('scorecards', dir, ['a.json', 'nope.json', 'empty.md']);
  assert.equal(bad.status, 'missing'); assert.match(bad.reason, /nope\.json.*empty\.md/);
  assert.equal(fileSetDeliverable('scorecards', dir, ['../outside']).status, 'missing', 'a path outside the repository is never a deliverable');
});

function tmpRepo() {
  const dir = mkTestTmp('closure-git-');
  const git = (...a) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', ...a], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git('init', '-q'); fs.writeFileSync(path.join(dir, 'base.txt'), 'base\n'); git('add', '-A'); git('commit', '-q', '-m', 'base');
  return { dir, git, base: git('rev-parse', 'HEAD') };
}

test('[REL-003.AC03] the implementation diff is the committed change since the base revision; an empty diff or no base is not an implementation', () => {
  const r = tmpRepo();
  const out = path.join(r.dir, '.out', 'implementation.diff');
  assert.equal(implementationDiff({ repoRoot: r.dir, baseHead: r.base, outFile: out }).status, 'missing', 'no change since base');
  assert.equal(implementationDiff({ repoRoot: r.dir, baseHead: null, outFile: out }).status, 'missing', 'no base revision');
  fs.writeFileSync(path.join(r.dir, 'feature.js'), 'export const x = 1;\n'); r.git('add', '-A'); r.git('commit', '-q', '-m', 'feature');
  const d = implementationDiff({ repoRoot: r.dir, baseHead: r.base, outFile: out });
  assert.equal(d.status, 'complete');
  assert.match(fs.readFileSync(out, 'utf8'), /feature\.js/);
  assert.equal(d.sha256, sha(fs.readFileSync(out)));
  assert.equal(implementationDiff({ repoRoot: r.dir, baseHead: 'f'.repeat(40), outFile: out }).status, 'missing', 'an unknown base revision fails, it does not produce an empty pass');
});

test('[REL-003.AC03] the updated PRD ledger lists every requirement and is OPEN while any requirement is unmet', () => {
  const dir = mkTestTmp('closure-ledger-');
  const f = facts();
  const none = prdLedger({ manifest: f.manifest, receipts: f.receipts, unmetByRequirement: new Map(), outFile: path.join(dir, 'l.json') });
  assert.equal(none.status, 'complete');
  const ledger = JSON.parse(fs.readFileSync(path.join(dir, 'l.json'), 'utf8'));
  assert.equal(ledger.requirements.length, 4); assert.ok(ledger.requirements.every((r) => r.state === 'verified' && r.criteria.every((c) => c.state === 'pass')));
  const d = mutate((x) => { x.receipts.get('A-1').criteria[0].state = 'fail'; x.receipts.get('A-1').result = 'fail'; });
  const byReq = unmetByRequirement(d.unmet, f.manifest);
  assert.ok(byReq.has('A-1') && byReq.has('A-2'), 'the failing requirement and the dependent that rests on it');
  const open = prdLedger({ manifest: f.manifest, receipts: f.receipts, unmetByRequirement: byReq, outFile: path.join(dir, 'l2.json') });
  assert.equal(open.status, 'open'); assert.match(open.reason, /A-1/);
});

function bundleWorld(failOne) {
  const r = tmpRepo();
  fs.writeFileSync(path.join(r.dir, 'dist.bin'), 'artifact-bytes');
  const manifest = MANIFEST();
  const receipts = new Map();
  for (const rq of manifest.requirements) {
    const file = path.join(r.dir, `${rq.id}.json`);
    fs.writeFileSync(file, JSON.stringify({ requirement: rq.id, result: 'pass', criteria: rq.criteria.map((c) => ({ id: c.id, state: 'pass' })) }));
    receipts.set(rq.id, { id: rq.id, found: true, file, evidenceId: `${rq.id}-000001` });
  }
  const unmetByReq = new Map(failOne ? [['A-1', ['criterion-failed: A-1.AC01 is fail']]] : []);
  return { r, manifest, receipts, unmetByReq };
}
const bundleOf = (w, over = {}) => buildAssuranceBundle({
  repoRoot: w.r.dir, config: CONFIG(), manifest: w.manifest, receipts: w.receipts, unmetByReq: w.unmetByReq,
  gates: [{ id: 'rel', argv: ['x'], cwd: '.', exitCode: 0, outcome: 'exited', ok: true, durationMs: 1 }],
  measured: [{ id: 'm', group: 'quality', ran: true, status: 'pass', synthetic: false }],
  git: { head: w.r.base, dirty: false, dirtyCount: 0 }, artifactPaths: ['dist.bin'], outDir: path.join(w.r.dir, '.out', 'bundle'), ...over,
});

test('[REL-003.AC03] the release assurance bundle verifies offline and is complete only when every mandatory check is completed', () => {
  const ok = bundleOf(bundleWorld(false));
  assert.equal(ok.status, 'complete', ok.reason);
  const v = verifyBundle(ok.path);
  assert.equal(v.ok, true, JSON.stringify(v.errors));
  assert.equal(v.manifest.complete, true);
  assert.equal(v.manifest.checks.completed.length, 4 + 2, 'four requirements, one gate and one measured gate');
  assert.ok(v.manifest.verificationReceipts.some((x) => x.id === 'A-1-000001'));
});

test('[REL-003.AC03] an incomplete requirement or an unmeasured gate makes the bundle OPEN, listed, and still verifiable; it never claims completion', () => {
  const bad = bundleOf(bundleWorld(true));
  assert.equal(bad.status, 'open');
  const v = verifyBundle(bad.path);
  assert.equal(v.ok, true, JSON.stringify(v.errors));
  assert.equal(v.manifest.complete, false);
  assert.deepEqual(v.manifest.checks.incomplete.map((c) => c.id), ['A-1']);
  const unmeasured = bundleOf(bundleWorld(false), { measured: [{ id: 'm', group: 'quality', ran: true, status: 'insufficient-population', synthetic: true }], outDir: path.join(bundleWorld(false).r.dir, '.out', 'b2') });
  assert.equal(unmeasured.status, 'open');
  assert.deepEqual(verifyBundle(unmeasured.path).manifest.checks.unsupported.map((c) => c.id), ['measured:m'], 'the unsupported gate is carried as unsupported, with its gap');
});

test('[REL-003.AC03] the bundle is refused (missing) when it cannot bind a commit or a build artifact', () => {
  const w = bundleWorld(false);
  assert.equal(bundleOf(w, { git: { head: null } }).status, 'missing');
  assert.equal(bundleOf(w, { artifactPaths: ['not-built.bin'] }).status, 'missing');
  assert.match(bundleOf(w, { artifactPaths: ['not-built.bin'] }).reason, /not-built\.bin/);
});

// ------------------------------------------------------------------ the issued record

test('[REL-003.AC01] a final record only counts as closure when it says it closed at the expected counts and its cited evidence files are unchanged', () => {
  const dir = mkTestTmp('closure-assess-');
  const key = 'k'.repeat(32);
  const evFile = path.join(dir, 'ev.json'); fs.writeFileSync(evFile, '{"r":1}');
  const manifest = { finalVerification: { required: true, closure: { releaseRequirement: 'REL-3', expect: { requirements: 4, criteria: 8, weight: 8 } } }, acceptanceHash: 'h', prd: { sha256: 'p' }, profile: { sha256: 's' } };
  const tree = { wholeTree: () => ({ digest: 'd' }) };
  const base = { runId: 'r', acceptanceHash: 'h', prdSha256: 'p', profileSha256: 's', verdict: 'all-required-criteria-verified', stable: true, treeDigest: 'd' };
  const closed = { schema: 1, closed: true, counts: { requirements: { verified: 4, expected: 4 }, criteria: { verified: 8, expected: 8 } }, open: [], receipts: [{ id: 'A-1', file: evFile, sha256: sha(fs.readFileSync(evFile)) }] };
  const file = path.join(dir, 'final-evidence.json');
  const assess = (closure) => { writeFinalEvidence(file, { ...base, ...(closure === undefined ? {} : { closure }) }, key); return assessFinal({ file, manifest, tree, key }); };
  assert.equal(assess(closed).ok, true, JSON.stringify(assess(closed).reasons));
  assert.match(assess(undefined).reasons.join(), /not a closure record/, 'a generic final record does not satisfy a closure profile');
  assert.match(assess({ ...closed, closed: false }).reasons.join(), /not a closure record/, 'a record that says it did not close, however its verdict reads');
  assert.match(assess({ ...closed, counts: { requirements: { verified: 3, expected: 4 }, criteria: { verified: 8, expected: 8 } } }).reasons.join(), /3\/4 requirements/);
  assert.match(assess({ ...closed, open: [{ kind: 'open-gate', id: 'm' }] }).reasons.join(), /remain open/);
  fs.writeFileSync(evFile, '{"r":2}');
  assert.match(assess(closed).reasons.join(), /evidence file for A-1 changed/);
  fs.writeFileSync(evFile, '{"r":1}');
  assert.equal(assess(closed).ok, true);
  const forged = JSON.parse(fs.readFileSync(file, 'utf8')); forged.closure.closed = true; forged.closure.counts.criteria.verified = 8; forged.stable = false; fs.writeFileSync(file, JSON.stringify(forged));
  assert.equal(assessFinal({ file, manifest, tree, key }).ok, false, 'an edited record fails its signature');
});

test('[REL-003.AC01] the untracked requirements document does not make the tree dirty; any other untracked or modified file does', () => {
  const r = tmpRepo();
  const prd = 'PRD.md';
  fs.writeFileSync(path.join(r.dir, prd), '# draft\n');
  assert.equal(gitFacts(r.dir).dirty, true, 'without the exemption an untracked draft is a dirty tree');
  const clean = gitFacts(r.dir, { ignore: [prd] });
  assert.equal(clean.dirty, false); assert.equal(clean.head, r.base);
  fs.writeFileSync(path.join(r.dir, 'stray.txt'), 'x');
  assert.equal(gitFacts(r.dir, { ignore: [prd] }).dirty, true, 'a different untracked file counts');
  fs.rmSync(path.join(r.dir, 'stray.txt'));
  fs.appendFileSync(path.join(r.dir, 'base.txt'), 'edited\n');
  assert.equal(gitFacts(r.dir, { ignore: [prd] }).dirty, true, 'a modified tracked file counts');
  assert.equal(gitFacts(path.join(r.dir, 'nonexistent'), { ignore: [prd] }), null, 'an unreadable repository is unknown, not clean');
});
