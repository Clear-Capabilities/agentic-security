// X-208: the verification conformance suite. It runs one contract over every registered oracle adapter, shows the release gate
// rejects an adapter that lacks class scope, resource budgets, negative controls or authoritative evidence receipts (with
// deliberately bad fake adapters, in both directions), and checks the documentation's replay example actually runs.
//
// Execution conformance needs the trust boundary. Where this host cannot run it, those tests say "SKIPPED, NOT PASSED" and the
// static half still runs; nothing here reports an unrun check as passed.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { listOracles, getOracle, oracleManifest } from '../../src/posture/oracles/registry.js';
import { defineOracle, runOracle, HARNESS_FILE, ORACLE_CLASSES } from '../../src/posture/oracles/oracle.js';
import {
  checkAdapterContract, checkFixturePins, checkConformance, runAdapterConformance, computePins, loadPins, BUDGET_CEILINGS, PINS_FILE,
} from '../../src/posture/oracles/conformance.js';
import { SCENARIO_CLASSES } from '../../src/posture/oracles/scenario-classes.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';
import { CHECKS, RELEASE_GROUPS, resolveGroups, plannedCheckIds } from '../../../scripts/release-check.mjs';
import { CHECKS as PREPUSH_CHECKS } from '../../../scripts/pre-push-gate.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const REPO = path.resolve(SCANNER, '..');
const GATE = path.join(REPO, 'scripts', 'verification-conformance-check.mjs');
const EXAMPLE = path.join(REPO, 'scripts', 'verification-replay-example.mjs');
const GUIDE = path.join(REPO, 'docs', 'guides', 'verification-oracle-conformance.md');
const REGISTRY_URL = pathToFileURL(path.join(SCANNER, 'src', 'posture', 'oracles', 'registry.js')).href;

let boundaryReady = false;
let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const report = await probeControls({});
  const unmet = unmetControls(report, [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  boundaryReady = backend === 'userspace' && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); execution conformance is UNVERIFIED here`;
});
const needsBoundary = (fn) => (t) => (boundaryReady ? fn(t) : t.skip(whyNot));

const harnessProcesses = () => String(spawnSync('ps', ['-A', '-o', 'ppid=,command='], { encoding: 'utf8' }).stdout).split('\n')
  .filter((l) => l.includes(HARNESS_FILE) && [1, process.pid].includes(Number(l.trim().split(/\s+/)[0]))).length;

const real = () => listOracles();
const failing = (result) => result.checks.filter((c) => !c.ok).map((c) => c.check);
const withoutDigest = (a) => { const s = { ...a }; delete s.logicDigest; return s; };

// ---------------------------------------------------------------- AC01

describe('[X-208.AC01] one suite tests all registered adapters, state mappings, tamper attempts, cancellation and replay against pinned fixtures', () => {
  test('[X-208.AC01] every registered adapter satisfies the static contract and its pinned fixtures', () => {
    const adapters = real();
    assert.equal(adapters.length, 8);
    assert.deepEqual(adapters.map((a) => a.class).sort(), [...ORACLE_CLASSES].sort(), 'every advertised class is served');
    for (const a of adapters) {
      const r = checkAdapterContract(a, { scannerRoot: SCANNER });
      assert.deepEqual(failing(r), [], `${a.id}`);
      assert.deepEqual(r.checks.map((c) => c.check), ['spec', 'class-scope', 'resource-budgets', 'negative-controls', 'evidence-receipts']);
      const pin = checkFixturePins(a, SCANNER);
      assert.equal(pin.ok, true, `${a.id}: ${pin.detail}`);
    }
    // the manifest the gate reads agrees with the registry
    assert.deepEqual(oracleManifest().problems, []);
    for (const a of adapters) for (const k of Object.keys(BUDGET_CEILINGS)) assert.ok(a.budgets[k] <= BUDGET_CEILINGS[k], `${a.id}.${k}`);
  });

  test('[X-208.AC01] the pin file covers exactly the registered adapters and every fixture', () => {
    const pins = loadPins(SCANNER);
    assert.equal(pins.schema, 'agentic-security/oracle-conformance-pins');
    assert.deepEqual(Object.keys(pins.adapters).sort(), real().map((a) => a.id).sort(), 'no unpinned adapter and no stale pin');
    for (const a of real()) {
      assert.deepEqual(Object.keys(pins.adapters[a.id].fixtures).sort(), ['inconclusive', 'negative', 'positive']);
      assert.deepEqual(pins.adapters[a.id], computePins(a, SCANNER));
    }
    assert.ok(fs.existsSync(path.join(SCANNER, PINS_FILE)));
  });

  test('[X-208.AC01] a moved fixture, a moved scenario or moved adapter logic fails the pin check; an unpinned adapter fails too', () => {
    const root = mkTestTmp('x208-pins-');
    fs.cpSync(path.join(SCANNER, 'test', 'fixtures', 'oracles'), path.join(root, 'test', 'fixtures', 'oracles'), { recursive: true });
    const a = getOracle('injection-execution');
    const pins = loadPins(SCANNER);
    assert.equal(checkFixturePins(a, root, pins).ok, true, 'a faithful copy passes');
    const dir = path.join(root, 'test', 'fixtures', 'oracles', 'injection-execution');
    for (const [rel, label] of [['positive/target.mjs', 'positive fixture'], ['negative/target.mjs', 'negative fixture'], ['inconclusive/target.mjs', 'inconclusive fixture'], ['scenario.json', 'scenario']]) {
      const original = fs.readFileSync(path.join(dir, rel), 'utf8');
      fs.writeFileSync(path.join(dir, rel), `${original}\n// edited\n`);
      const r = checkFixturePins(a, root, pins);
      assert.equal(r.ok, false, label);
      assert.match(r.detail, new RegExp(label));
      fs.writeFileSync(path.join(dir, rel), original);
      assert.equal(checkFixturePins(a, root, pins).ok, true, `${label} restored`);
    }
    const moved = { ...a, logicDigest: `sha256:${'0'.repeat(64)}` };
    assert.match(checkFixturePins(moved, root, pins).detail, /adapter logic digest/);
    assert.match(checkFixturePins(a, root, { schema: 'x', adapters: {} }).detail, /no pinned fixtures/);
    assert.match(checkFixturePins(a, root, null).detail, /no pinned fixtures/);
  });

  test('[X-208.AC01] the whole-registry suite includes the pin check for every adapter and fails when a pinned fixture moved', async () => {
    const report = await checkConformance(real(), { scannerRoot: SCANNER, execute: false });
    for (const r of report.adapters) assert.ok(r.checks.some((c) => c.check === 'pinned-fixtures' && c.ok), `${r.id} was pin-checked`);
    assert.equal(report.ok, true);
    const root = mkTestTmp('x208-suite-pins-');
    fs.cpSync(path.join(SCANNER, 'test', 'fixtures', 'oracles'), path.join(root, 'test', 'fixtures', 'oracles'), { recursive: true });
    const f = path.join(root, 'test', 'fixtures', 'oracles', 'state-transition', 'negative', 'target.mjs');
    fs.writeFileSync(f, `${fs.readFileSync(f, 'utf8')}\n// edited after pinning\n`);
    const moved = await checkConformance(real(), { scannerRoot: root, pins: loadPins(SCANNER), execute: false });
    assert.equal(moved.ok, false);
    const bad = moved.adapters.find((r) => r.id === 'state-transition');
    assert.ok(failing(bad).includes('pinned-fixtures'));
    assert.ok(moved.adapters.filter((r) => r.id !== 'state-transition').every((r) => r.ok), 'only the adapter whose fixture moved fails');
  });

  test('[X-208.AC01] the state mappings for a run that never executes are fixed: disabled is not-run, an unmet prerequisite and a refusing boundary are unsupported, none issues a receipt', async () => {
    const base = (id) => ({ oracleId: id, hypothesisId: 'h', commit: 'a'.repeat(40), entry: 'target.mjs', ...(() => { const d = path.join(SCANNER, 'test', 'fixtures', 'oracles', id); return { files: { 'target.mjs': fs.readFileSync(path.join(d, 'positive', 'target.mjs'), 'utf8') }, inputs: JSON.parse(fs.readFileSync(path.join(d, 'scenario.json'), 'utf8')) }; })() });
    const { resolveAssuranceConfig } = await import('../../src/posture/assurance/config.js');
    const enabled = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true, 'invariant-scenarios': true } } });
    const spy = { runInBoundary: async () => { throw new Error('must not run'); } };
    let ran = 0;
    const refusing = { runInBoundary: async () => { ran++; return { blocked: true, executed: false, reasons: ['control unproved'], backend: 'namespace' }; } };
    const healthy = { platform: process.platform, nodeMajor: 24, backend: 'userspace', hasPosixShell: true };
    for (const a of real()) {
      const off = await runOracle(base(a.id), { deps: spy });
      assert.deepEqual([off.status, off.outcome, off.executed, off.receipt], ['disabled', 'not-run', false, null], `${a.id}: feature off`);
      const unmet = await runOracle(base(a.id), { config: enabled, probeEnv: { ...healthy, nodeMajor: 18 }, deps: spy });
      assert.deepEqual([unmet.status, unmet.outcome, unmet.executed, unmet.receipt], ['unsupported', 'unsupported', false, null], `${a.id}: unmet prerequisite`);
      const blocked = await runOracle(base(a.id), { config: enabled, probeEnv: healthy, deps: refusing });
      assert.deepEqual([blocked.status, blocked.outcome, blocked.receipt], ['blocked', 'unsupported', null], `${a.id}: refusing boundary`);
      assert.equal(blocked.record.outcome, 'unsupported');
      assert.equal(blocked.record.attempt, 0);
    }
    assert.ok(ran >= 0);
  });

  test('[X-208.AC01] the full suite passes for every registered adapter: state mappings, receipts, tamper attempts, cancellation and replay', needsBoundary(async () => {
    const report = await checkConformance(real(), { scannerRoot: SCANNER, execute: true, requireExecution: true, harnessProcesses });
    for (const r of report.adapters) assert.deepEqual(r.checks.filter((c) => !c.ok), [], `${r.id}`);
    assert.equal(report.ok, true);
    assert.equal(report.executionRan, true);
    assert.deepEqual(report.registryProblems, []);
    const expected = ['state-positive', 'state-negative', 'state-inconclusive', 'records-valid', 'authoritative-receipt', 'tamper-harness-rewrite', 'tamper-verdict-text', 'tamper-caller-verdict', 'unavailable-prerequisite', 'cancellation', 'replay'];
    for (const r of report.adapters) {
      assert.equal(r.execution, 'passed', r.id);
      for (const c of expected) assert.ok(r.checks.some((x) => x.check === c && x.ok), `${r.id} ran ${c}`);
    }
  }));

  test('[X-208.AC01] the suite detects a runner that hands out receipts it did not issue, and an adapter that confirms everything', needsBoundary(async () => {
    // a stand-in runner returning a COPY of the issued receipt: a copy is not an issued receipt
    const copying = async (req, o) => { const r = await runOracle(req, o); return r.receipt ? { ...r, receipt: { ...r.receipt } } : r; };
    const a = real().find((x) => x.id === 'state-transition');
    const bad = await runAdapterConformance(a, { scannerRoot: SCANNER, run: copying, harnessProcesses });
    assert.equal(bad.ok, false);
    assert.ok(failing(bad).includes('authoritative-receipt'), failing(bad).join());
    const good = await runAdapterConformance(a, { scannerRoot: SCANNER, harnessProcesses });
    assert.equal(good.ok, true, JSON.stringify(failing(good)));

    // an adapter whose verifier-side interpretation always says "the effect was observed" cannot refute its own negative control
    const always = defineOracle({ ...withoutDigest(a), interpret: () => ({ satisfied: true, preconditionsHeld: true, observed: { always: true }, reason: 'always satisfied' }) });
    const r = await runAdapterConformance(always, { scannerRoot: SCANNER, harnessProcesses });
    assert.equal(r.ok, false);
    assert.ok(failing(r).includes('state-negative'));
    assert.ok(failing(r).includes('state-inconclusive'));
  }));

  test('[X-208.AC01] a host that cannot run the boundary reports execution as not-run, and that is a failure only when execution is required', async () => {
    const cannot = { probeEnv: { platform: process.platform, nodeMajor: 18, backend: 'userspace', hasPosixShell: true }, deps: { runInBoundary: async () => { throw new Error('must not run'); } } };
    const soft = await checkConformance(real(), { scannerRoot: SCANNER, execute: true, runOptions: cannot });
    assert.equal(soft.ok, true, 'static contract and pins held');
    assert.equal(soft.executionRan, false);
    for (const r of soft.adapters) { assert.equal(r.execution, 'not-run'); assert.match(r.executionReason, /could not run|unmet|prerequisite/); }
    const hard = await checkConformance(real(), { scannerRoot: SCANNER, execute: true, requireExecution: true, runOptions: cannot });
    assert.equal(hard.ok, false, 'required execution that did not run is a failure, never a pass');
  });
});

// ---------------------------------------------------------------- AC02

function fakeFrom(id, mutate) {
  const a = withoutDigest(getOracle(id));
  return mutate(a);
}

describe('[X-208.AC02] release gating rejects an adapter that lacks class scope, resource budgets, negative controls or authoritative evidence receipts', () => {
  const cases = {
    'no class scope: an unknown class': [(a) => ({ ...a, class: 'made-up-class' }), 'class-scope'],
    'no class scope: platforms not stated': [(a) => ({ ...a, platforms: undefined }), 'class-scope'],
    'no class scope: Linux claimed supported': [(a) => ({ ...a, platforms: { ...a.platforms, linux: { status: 'supported', note: 'works' } } }), 'class-scope'],
    'no class scope: no limitations': [(a) => ({ ...a, limitations: [] }), 'class-scope'],
    'no class scope: no fixture directory': [(a) => ({ ...a, fixtures: { ...a.fixtures, dir: 'test/fixtures/oracles/does-not-exist' } }), 'class-scope'],
    'no resource budgets': [(a) => ({ ...a, budgets: undefined }), 'resource-budgets'],
    'a missing budget': [(a) => ({ ...a, budgets: { ...a.budgets, maxOutputBytes: undefined } }), 'resource-budgets'],
    'a budget over its ceiling (timeout)': [(a) => ({ ...a, budgets: { ...a.budgets, timeoutMs: BUDGET_CEILINGS.timeoutMs + 1 } }), 'resource-budgets'],
    'a budget over its ceiling (files)': [(a) => ({ ...a, budgets: { ...a.budgets, maxFiles: BUDGET_CEILINGS.maxFiles * 10 } }), 'resource-budgets'],
    'no negative controls': [(a) => ({ ...a, negativeControls: [] }), 'negative-controls'],
    'a negative control that expects confirmation': [(a) => ({ ...a, negativeControls: [{ id: 'x', description: 'x', expectedOutcome: 'confirmed' }] }), 'negative-controls'],
    'a negative fixture that is not on disk': [(a) => ({ ...a, fixtures: { ...a.fixtures, negative: 'nope' } }), 'negative-controls'],
    'no verifier-side interpretation': [(a) => ({ ...a, interpret: undefined }), 'evidence-receipts'],
    'no verifier-authored harness': [(a) => ({ ...a, harnessSource: '// nothing' }), 'evidence-receipts'],
    'no preparation of the harness input': [(a) => ({ ...a, prepare: undefined }), 'evidence-receipts'],
  };
  for (const [name, [mutate, expectedCheck]] of Object.entries(cases)) {
    test(`[X-208.AC02] ${name} fails the ${expectedCheck} check`, () => {
      const fake = fakeFrom('injection-execution', mutate);
      // keep the digest the real adapter had, as a forged-in-place adapter would
      const withDigest = { ...fake, logicDigest: getOracle('injection-execution').logicDigest };
      const r = checkAdapterContract(withDigest, { scannerRoot: SCANNER });
      assert.equal(r.ok, false);
      assert.ok(failing(r).includes(expectedCheck), `${name}: failed [${failing(r).join(', ')}]`);
    });
  }

  test('[X-208.AC02] an adapter whose logic changed under an unchanged digest is rejected (evidence receipts bind to the logic)', () => {
    const real_ = getOracle('state-transition');
    const edited = { ...withoutDigest(real_), harnessSource: `${real_.harnessSource}\n// quietly edited`, logicDigest: real_.logicDigest };
    assert.ok(failing(checkAdapterContract(edited, { scannerRoot: SCANNER })).includes('evidence-receipts'));
    assert.ok(failing(checkAdapterContract({ ...withoutDigest(real_) }, { scannerRoot: SCANNER })).includes('evidence-receipts'), 'no digest at all');
    assert.deepEqual(failing(checkAdapterContract(real_, { scannerRoot: SCANNER })), [], 'and the genuine adapter passes');
  });

  test('[X-208.AC02] the whole-registry gate fails for a bad adapter, a duplicate id, an unserved class and an unregistered non-taint class adapter', async () => {
    const good = real();
    const bad = { ...withoutDigest(good[0]), negativeControls: [], logicDigest: good[0].logicDigest };
    const r1 = await checkConformance([bad, ...good.slice(1)], { scannerRoot: SCANNER, execute: false });
    assert.equal(r1.ok, false);
    assert.equal(r1.adapters[0].ok, false);
    assert.ok(r1.adapters.slice(1).every((a) => a.ok), 'the other adapters still conform: the failure is attributed to the bad one');

    const r2 = await checkConformance([...good, good[0]], { scannerRoot: SCANNER, execute: false });
    assert.equal(r2.ok, false);
    assert.ok(failing(r2.adapters.at(-1)).includes('unique-id'));

    const r3 = await checkConformance(good.filter((a) => a.class !== 'parser-resource'), { scannerRoot: SCANNER, execute: false });
    assert.equal(r3.ok, false);
    assert.ok(r3.registryProblems.some((p) => /parser-resource/.test(p)));

    const missingNonTaint = good.filter((a) => a.id !== 'replay-idempotency');
    const r4 = await checkConformance(missingNonTaint, { scannerRoot: SCANNER, execute: false });
    assert.ok(r4.registryProblems.some((p) => /replay-idempotency/.test(p) || /replay/.test(p)));
    assert.ok(SCENARIO_CLASSES.some((c) => c.adapterId === 'replay-idempotency'));

    const r5 = await checkConformance(good, { scannerRoot: SCANNER, execute: false });
    assert.equal(r5.ok, true, 'the genuine registry passes the same gate');
  });

  test('[X-208.AC02] the gate command exits 0 for the registry and 1 for a bad adapter, naming the check', () => {
    const run = (args) => spawnSync(process.execPath, [GATE, ...args], { encoding: 'utf8' });
    const ok = run(['--static']);
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    assert.match(ok.stdout, /8 adapter\(s\) conform/);

    const dir = mkTestTmp('x208-gate-');
    const variants = {
      'negative-controls': 'negativeControls: []',
      'resource-budgets': 'budgets: undefined',
      'class-scope': "class: 'made-up'",
      'evidence-receipts': 'interpret: undefined',
    };
    for (const [check, override] of Object.entries(variants)) {
      const file = path.join(dir, `bad-${check}.mjs`);
      fs.writeFileSync(file, `import { listOracles } from ${JSON.stringify(REGISTRY_URL)};\nconst g = listOracles();\nexport const adapters = [{ ...g[0], ${override} }, ...g.slice(1)];\n`);
      const bad = run(['--static', '--adapters', file]);
      assert.equal(bad.status, 1, `${check}: ${bad.stdout}`);
      assert.match(bad.stdout, new RegExp(`FAIL ${getOracle(listOracles()[0].id).id}`));
      assert.match(bad.stdout, new RegExp(`${check}:`), `${check} is named`);
      assert.match(bad.stdout, /verification conformance: FAILED/);
      // the same module with the genuine adapters passes: the variant, not the harness, is what failed
    }
    const genuine = path.join(dir, 'genuine.mjs');
    fs.writeFileSync(genuine, `import { listOracles } from ${JSON.stringify(REGISTRY_URL)};\nexport const adapters = listOracles();\n`);
    assert.equal(run(['--static', '--adapters', genuine]).status, 0);
    assert.equal(run(['--bogus']).status, 2);
    assert.equal(run(['--adapters']).status, 2);
    const notArray = path.join(dir, 'not-array.mjs');
    fs.writeFileSync(notArray, 'export const adapters = 5;\n');
    assert.equal(run(['--static', '--adapters', notArray]).status, 2);
  });

  test('[X-208.AC02] the gate is wired into the release gate (and its group, so the parallel workflow cannot drop it) and the pre-push gate', () => {
    const check = CHECKS.find((c) => c.id === 'verification-conformance-gate');
    assert.ok(check, 'registered as a release check');
    assert.equal(check.slow, true);
    assert.ok(plannedCheckIds({ fast: false }).includes('verification-conformance-gate'));
    assert.ok(RELEASE_GROUPS['benches-b'].includes('verification-conformance-gate'), 'named in a release group');
    const groups = resolveGroups();
    const homes = Object.entries(groups).filter(([, ids]) => ids.includes('verification-conformance-gate')).map(([name]) => name);
    assert.deepEqual(homes, ['benches-b'], 'in exactly one group');
    // every planned check lands in some group, so adding this one dropped none
    const grouped = new Set(Object.values(groups).flat());
    for (const id of plannedCheckIds({ fast: false })) assert.ok(grouped.has(id), `${id} is in a group`);
    const src = fs.readFileSync(path.join(REPO, 'scripts', 'release-check.mjs'), 'utf8');
    assert.match(src, /evaluate\('verification-conformance-gate', \(\) => runNpmGate\('verification:conformance:check'\)\)/);
    const pkg = JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));
    assert.equal(pkg.scripts['verification:conformance:check'], 'node ../scripts/verification-conformance-check.mjs');
    assert.equal(pkg.scripts['verification:conformance:static'], 'node ../scripts/verification-conformance-check.mjs --static');
    const pre = PREPUSH_CHECKS.find((c) => c.id === 'verification-conformance-static');
    assert.ok(pre, 'the cheap static half is in the pre-push gate');
    assert.equal(pre.npmScript, 'verification:conformance:static');
    assert.ok(pkg.scripts[pre.npmScript], 'the npm script it names exists');
    // the suites that make up this requirement are part of the verification test script
    for (const f of ['interface-equivalence', 'advisory-gating', 'oracle-conformance']) assert.ok(pkg.scripts['test:verification'].includes(`test/verification/${f}.test.js`), f);
  });
});

// ---------------------------------------------------------------- AC03

describe('[X-208.AC03] documentation: a bounded local replay example and how to add an oracle without expanding default execution permissions', () => {
  const doc = fs.readFileSync(GUIDE, 'utf8');

  test('[X-208.AC03] the guide names the replay example, the gate commands and the add-an-oracle steps, and every command and path it names exists', () => {
    assert.match(doc, /## A bounded local replay/);
    assert.match(doc, /## Adding an oracle without expanding default execution permissions/);
    const pkg = JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));
    const npmRuns = [...doc.matchAll(/npm run ([a-z:-]+)/g)].map((m) => m[1]);
    assert.ok(npmRuns.length >= 3);
    for (const s of new Set(npmRuns)) assert.ok(pkg.scripts[s], `npm run ${s} exists`);
    const paths = new Set([...doc.matchAll(/`((?:scripts|scanner|docs)\/[A-Za-z0-9_./<>-]+)`/g)].map((m) => m[1]).filter((p) => !p.includes('<')));
    assert.ok(paths.size >= 6);
    for (const p of paths) assert.ok(fs.existsSync(path.join(REPO, p)), `${p} exists`);
    for (const p of ['scripts/verification-replay-example.mjs', 'scripts/verification-conformance-check.mjs', PINS_FILE ? `scanner/${PINS_FILE}` : '']) assert.ok(paths.has(p), `${p} is named`);
    for (const f of ['scripts/release-check.mjs', 'scanner/test/verification/oracle-conformance.test.js']) assert.ok(doc.includes(f));
  });

  test('[X-208.AC03] the guide states the permission limits: default-off, operator-only, boundary-only, no runtime registration, no scope widening, no Linux claim', () => {
    for (const phrase of [/off\s+by default/i, /only an operator can enable it/i, /through\s+`runInBoundary`/, /no runtime registration/i, /never `supported` on Linux/i, /widen the replay scope/i, /ceilings/i, /not a pass/i, /Known limits/]) {
      assert.match(doc, phrase, String(phrase));
    }
    assert.equal(/—/.test(doc), false, 'no em-dashes in prose');
  });

  test('[X-208.AC03] the documented replay example runs: the verdict and the record id reproduce, and it is bounded to a repository fixture', needsBoundary(() => {
    const r = spawnSync(process.execPath, [EXAMPLE], { encoding: 'utf8', timeout: 120_000 });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /first run:  outcome confirmed, reproduced expected: true, record vrec:[0-9a-f]{16}/);
    assert.match(r.stdout, /replay reproduced the verdict and the record id/);
    const ids = [...r.stdout.matchAll(/record (vrec:[0-9a-f]{16})/g)].map((m) => m[1]);
    assert.equal(ids.length, 2);
    assert.equal(ids[0], ids[1], 'the second run reproduces the same record id');
    // the example runs only the named oracle's pinned fixture; an unknown oracle is refused without running anything
    const bad = spawnSync(process.execPath, [EXAMPLE, '../../etc'], { encoding: 'utf8', timeout: 30_000 });
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /no pinned fixture/);
  }));

  // This test must never skip: the controller counts a skipped test anywhere in the suite as a failure, and a pair of tests where each host
  // skips one of them can never be verified on any host. The kill switch makes the boundary not run on EVERY host, so the not-executed path is
  // exercised here whether or not the host could have run it; on a host that cannot, it is exercised without the switch as well.
  test('[X-208.AC03] when the boundary does not run, because a kill switch is set or the host cannot run it, the example says so and exits 3 rather than reporting a pass', () => {
    const run = (env) => spawnSync(process.execPath, [EXAMPLE], { encoding: 'utf8', timeout: 60_000, env: { ...process.env, ...env } });
    const killed = run({ AGENTIC_SECURITY_NO_VERIFICATION_ORACLES: '1' });
    assert.equal(killed.status, 3, killed.stdout + killed.stderr);
    assert.match(killed.stdout, /not executed/);
    assert.match(killed.stdout, /not a pass/);
    assert.doesNotMatch(killed.stdout, /replay reproduced the verdict/);
    const globalKill = run({ AGENTIC_SECURITY_NO_ASSURANCE: '1' });
    assert.equal(globalKill.status, 3, 'the global kill switch stops it too');
    if (!boundaryReady) {
      const r = run({});
      assert.equal(r.status, 3);
      assert.match(r.stdout, /not a pass/);
    }
  });
});
