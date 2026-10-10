// REL-003: the protected final closure, controller half. The REAL controller (run.mjs, guardian, verifier, evidence, final phase) is driven
// against small DISPOSABLE repositories with a scripted worker. Nothing here touches the real PRD, calls a model or spends anything.
//
//   pass       a committed, fully passing repository closes: status completed, 100 percent, a closure record, all six deliverables
//   dirty      the same repository with its implementation left uncommitted does NOT close
//   failed     a required criterion that passes first and fails in the final phase blocks closure, naming the criterion
//   skipped    a required test that is skipped in the final phase blocks closure
//   open       a measured gate that reads unmeasured on a synthetic population keeps closure OPEN although everything else passes
//
// The decision logic itself is covered, defect by defect, in final-closure.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { MiniRepo, sleep, alive } from '../../../scripts/loop-engineering/test/helpers.js';
import { verifyBundle } from '../../../scanner/src/posture/portfolio/bundle.js';

const R = (id, weight = 1, deps = []) => ({ id, weight, deps, criteria: ['the criterion'] });
const REQS = () => [R('CORE-001', 2), R('LOOP-001', 1, ['CORE-001']), R('X-201', 3, ['CORE-001']), R('REL-003', 2, ['LOOP-001', 'X-201'])];
const gate = (id, code = 0) => ({ id, cwd: '.', executable: 'node', args: ['-e', `process.exit(${code})`], timeoutSeconds: 30 });
const GATES = () => [gate('gate-q'), gate('gate-r'), gate('gate-ok')];
const TERMINAL = ['completed', 'blocked', 'crashed', 'failed', 'paused-budget', 'stopped'];

const CLOSURE = (extra = {}) => ({
  releaseRequirement: 'REL-003', expect: { requirements: 4, criteria: 4, weight: 8 }, requireCleanTree: true,
  requiredGates: { quality: ['gate-q'], routing: ['gate-r'], release: ['gate-ok'] },
  measuredGates: [{ id: 'measured-eval', group: 'quality', cwd: '.', executable: 'node', args: ['measured.mjs'], timeoutSeconds: 30, parse: 'status-json' }],
  limits: { max: { attemptsPerRequirement: 3, runWallSeconds: 600, runMaxAttempts: 40, claudeBudgetUsd: 50 }, min: {} },
  deliverables: { scorecards: ['docs/score.json'], policyCards: ['docs/card.md'], replayableFixtures: ['replay/a.json'], artifacts: ['dist.bin'], scopeFiles: ['docs/scope.md'] },
  ...extra,
});

// A suite that passes on its first run (the controller's pre-check) and misbehaves on every later one (the final phase). The counter
// file is ignored by git, so it never perturbs the source digest.
const flaky = (id, mode) => `import test from 'node:test';
import fs from 'node:fs';
let n = 0; try { n = Number(fs.readFileSync('counter-${id}.txt', 'utf8')); } catch { /* first run */ }
fs.writeFileSync('counter-${id}.txt', String(n + 1));
const late = n >= 1;
test('[${id}.AC01] flaky in the final phase', ${mode === 'skip' ? '{ skip: late ? "skipped in the final phase" : false }' : '{}'}, () => { ${mode === 'fail' ? "if (late) throw new Error('fails in the final phase');" : ''} });
`;

const git = (cwd, ...a) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', ...a], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

async function scenario({ commit = true, flakyMode = null, measured = { status: 'pass', synthetic: false }, tamper = false } = {}) {
  const suiteSources = flakyMode ? { 'suite-X-201': flaky('X-201', flakyMode) } : undefined;
  const repo = new MiniRepo(REQS(), {
    profile: { limits: { workerIdleSeconds: 60, noProgressSeconds: 120, claudeAttemptSeconds: 90, attemptsPerRequirement: 1 }, finalGates: GATES(), extra: { finalVerification: { required: true, closure: CLOSURE() } } },
    suiteSources, workerMode: { default: 'noop' },
  });
  try {
    const root = repo.root;
    fs.appendFileSync(path.join(root, '.gitignore'), 'counter-*.txt\n');
    fs.writeFileSync(path.join(root, 'measured.mjs'), `console.log(JSON.stringify(${JSON.stringify(measured)}));\n`);
    git(root, 'add', '-A'); git(root, 'commit', '-q', '-m', 'base');
    // the requirements document is untracked by convention; it is bound by its hash, so it must not make the tree dirty
    git(root, 'rm', '-q', '--cached', 'PRD.md'); git(root, 'commit', '-q', '-m', 'untrack the requirements document');
    // the "implementation": flag files the suites look for, plus the deliverable inputs
    for (const r of REQS()) fs.writeFileSync(path.join(root, `flag-${r.id}`), 'ok');
    fs.mkdirSync(path.join(root, 'docs'), { recursive: true }); fs.mkdirSync(path.join(root, 'replay'), { recursive: true });
    fs.writeFileSync(path.join(root, 'docs', 'score.json'), '{"scorecard":true}\n'); fs.writeFileSync(path.join(root, 'docs', 'card.md'), '# card\n');
    fs.writeFileSync(path.join(root, 'docs', 'scope.md'), '# scope\n'); fs.writeFileSync(path.join(root, 'replay', 'a.json'), '{"replay":true}\n');
    fs.writeFileSync(path.join(root, 'dist.bin'), 'artifact');
    const init = await repo.init();
    assert.equal(init.code, 0, init.stdout + init.stderr);
    if (commit) { git(root, 'add', '-A', '--', '.', ':!PRD.md'); git(root, 'commit', '-q', '-m', 'implementation'); }
    const start = await repo.cli(['start', '--background', '--serve', '127.0.0.1:0']);
    assert.equal(start.code, 0, start.stdout + start.stderr);
    const st = await repo.waitFor(async () => { const s = await repo.status(); return TERMINAL.includes(s.status) ? s : null; }, { timeoutMs: 120000, label: 'terminal status' });
    if (st.controller?.pid) await repo.waitFor(async () => !alive(st.controller.pid), { timeoutMs: 30000, label: 'controller exit' });
    const status = await repo.status();
    const readJson = (p) => { try { return JSON.parse(repo.read(p)); } catch { return null; } };
    const rel = path.relative(root, repo.runPath('final-report.json'));
    const report = readJson(rel);
    const finalEvidence = readJson(path.relative(root, repo.runPath('final-evidence.json')));
    const finalDir = repo.runPath('final');
    const bundleDir = path.join(finalDir, 'assurance-bundle');
    const snap = {
      status, report, finalEvidence,
      diff: fs.existsSync(path.join(finalDir, 'implementation.diff')) ? fs.readFileSync(path.join(finalDir, 'implementation.diff'), 'utf8') : null,
      ledger: readJson(path.relative(root, path.join(finalDir, 'prd-ledger.json'))),
      bundle: fs.existsSync(bundleDir) ? verifyBundle(bundleDir) : null,
    };
    if (tamper) {
      // change an evidence file the closure cites, keeping it valid JSON
      const ev = repo.runPath('evidence', 'X-201');
      const file = fs.readdirSync(ev).filter((f) => /\.json$/.test(f)).sort().pop();
      const p = path.join(ev, file); const j = JSON.parse(fs.readFileSync(p, 'utf8')); j.reason = 'edited after closure'; fs.writeFileSync(p, JSON.stringify(j, null, 2));
      snap.tampered = await repo.status();
    }
    return snap;
  } finally { await repo.cleanup(); await sleep(50); }
}

// start every scenario now; each test unwraps its own, so an error is reported by the test that owns it
const settle = (p) => p.then((v) => ({ v }), (e) => ({ e }));
const RUNS = {
  pass: settle(scenario({ tamper: true })),
  dirty: settle(scenario({ commit: false })),
  failed: settle(scenario({ flakyMode: 'fail' })),
  skipped: settle(scenario({ flakyMode: 'skip' })),
  open: settle(scenario({ measured: { status: 'unmeasured', synthetic: true } })),
};
const get = async (k) => { const r = await RUNS[k]; if (r.e) throw r.e; return r.v; };
const kindsOf = (snap) => (snap.report?.unmet || []).map((u) => `${u.kind}:${u.id}`);

test('[REL-003.AC01] a committed, fully passing disposable repository closes at 4/4 requirements and 4/4 criteria with one closure record', async () => {
  const s = await get('pass');
  assert.equal(s.status.status, 'completed', s.status.statusReason);
  assert.equal(s.status.verifiedPercent, 100);
  assert.equal(s.report.verdict, 'all-required-criteria-verified');
  assert.deepEqual(s.report.unmet, []); assert.deepEqual(s.report.open, []);
  assert.deepEqual(s.finalEvidence.closure.counts, { requirements: { verified: 4, expected: 4 }, criteria: { verified: 4, expected: 4 } });
  assert.equal(s.finalEvidence.closure.closed, true);
  assert.equal(s.status.final.ok, true);
  // the order contract is recorded in the issued record: validated, then the closure criteria, then issuance
  const o = s.finalEvidence.closure.order;
  assert.ok(o.phaseStartedAt <= o.validatedAt && o.validatedAt <= o.closureStartedAt && o.closureStartedAt <= o.issuedAt, JSON.stringify(o));
  // every cited receipt was issued in the final phase by the controller
  assert.equal(s.finalEvidence.closure.receipts.length, 4);
});

test('[REL-003.AC01] a changed evidence file after closure un-completes it', async () => {
  const s = await get('pass');
  assert.notEqual(s.tampered.status, 'completed', 'status after tampering with an evidence file cited by the closure record');
  assert.ok(s.tampered.verifiedPercent < 100, `verified ${s.tampered.verifiedPercent}`);
});

test('[REL-003.AC01] an uncommitted implementation (a dirty tree) is not closed, and the reason says to commit', async () => {
  const s = await get('dirty');
  assert.notEqual(s.status.status, 'completed');
  assert.ok(s.status.verifiedPercent < 100);
  assert.ok(kindsOf(s).includes('dirty-tree:tree'), kindsOf(s).join(', '));
  assert.equal(s.finalEvidence.closure.closed, false);
  assert.ok(kindsOf(s).includes('deliverable-missing:implementation-diff'), 'with nothing committed there is no implementation diff either');
});

test('[REL-003.AC01] a required criterion that fails in the final phase blocks closure and is named', async () => {
  const s = await get('failed');
  assert.notEqual(s.status.status, 'completed');
  assert.ok(s.status.verifiedPercent < 100);
  const k = kindsOf(s);
  assert.ok(k.includes('criterion-failed:X-201.AC01'), k.join(', '));
  assert.equal(s.report.verdict, 'incomplete');
  assert.ok(s.finalEvidence.closure.counts.criteria.verified < 4);
});

test('[REL-003.AC01] a required test that is skipped in the final phase blocks closure (a skip counts as failed)', async () => {
  const s = await get('skipped');
  assert.notEqual(s.status.status, 'completed');
  const k = kindsOf(s);
  assert.ok(k.includes('criterion-skipped:X-201'), k.join(', '));
  assert.equal(s.finalEvidence.closure.closed, false);
});

test('[REL-003.AC02] the controller ran the protected checks: required gates, measured gate, limits and scope all appear in the final record', async () => {
  const s = await get('pass');
  assert.deepEqual(s.report.gates.map((g) => g.id).sort(), ['gate-ok', 'gate-q', 'gate-r']);
  assert.ok(s.report.gates.every((g) => g.ok));
  assert.deepEqual(s.finalEvidence.closure.measured.map((m) => [m.id, m.status, m.synthetic]), [['measured-eval', 'pass', false]]);
  assert.equal(s.finalEvidence.closure.git.dirty, false);
  assert.match(s.finalEvidence.closure.git.head, /^[0-9a-f]{40}$/);
});

test('[REL-003.AC03] a closed run delivers the implementation diff, the updated ledger, scorecards, policy cards, replay fixtures and a verifying assurance bundle', async () => {
  const s = await get('pass');
  const d = Object.fromEntries(s.finalEvidence.closure.deliverables.map((x) => [x.kind, x]));
  for (const kind of ['implementation-diff', 'prd-ledger', 'scorecards', 'policy-cards', 'replayable-fixtures', 'release-assurance-bundle']) assert.equal(d[kind]?.status, 'complete', `${kind}: ${JSON.stringify(d[kind])}`);
  assert.match(s.diff, /flag-CORE-001/, 'the diff carries the committed implementation');
  assert.equal(s.ledger.requirements.length, 4); assert.ok(s.ledger.requirements.every((r) => r.state === 'verified'));
  assert.equal(s.bundle.ok, true, JSON.stringify(s.bundle.errors));
  assert.equal(s.bundle.manifest.complete, true);
});

test('[REL-003.AC03] a measured gate that reads unmeasured on a synthetic population stays OPEN: everything else passes, and closure is still refused', async () => {
  const s = await get('open');
  assert.notEqual(s.status.status, 'completed', 'an open gate is never completion');
  assert.ok(s.status.verifiedPercent < 100);
  assert.deepEqual(s.report.unmet, [], 'nothing failed; the gate is simply not measured');
  const open = s.report.open.map((o) => `${o.kind}:${o.id}`);
  assert.ok(open.includes('open-gate:measured-eval'), open.join(', '));
  assert.ok(open.includes('deliverable-open:scorecards') && open.includes('deliverable-open:release-assurance-bundle'), open.join(', '));
  assert.equal(s.report.verdict, 'incomplete');
  assert.equal(s.finalEvidence.closure.counts.requirements.verified, 4, 'the requirements really did all pass; the refusal is about the open gate');
  assert.equal(s.bundle.manifest.complete, false, 'the bundle says so itself');
  assert.deepEqual(s.bundle.manifest.checks.unsupported.map((c) => c.id), ['measured:measured-eval']);
});
