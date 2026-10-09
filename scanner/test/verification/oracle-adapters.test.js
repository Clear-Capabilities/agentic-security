// X-202: trusted oracle adapters. Each target here is RUN through the trust
// boundary; nothing is asserted about a Linux outcome (the macOS development host
// cannot exercise it, and the manifest says so).
//
// A skip is not a pass: where the boundary cannot run on this host the tests that
// need it say "SKIPPED, NOT PASSED" and the host-independent ones still run.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  runOracle, defineOracle, validateOracleSpec, oracleLogicDigest, isIssuedReceipt, sanitizedEnvironment, ORACLE_CLASSES,
  PREREQUISITES, HARNESS_FILE, RESULT_FILE, FEATURE_ID,
} from '../../src/posture/oracles/oracle.js';
import * as registry from '../../src/posture/oracles/registry.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { validateVerificationRecord } from '../../src/posture/assurance/verification-record.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const COMMIT = 'c'.repeat(40);
const config = resolveAssuranceConfig({ env: {}, overrides: { features: { [FEATURE_ID]: true } } });

let boundaryReady = false;
let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const report = await probeControls({});
  const unmet = unmetControls(report, [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  boundaryReady = backend === 'userspace' && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}', unproved: ${unmet.map((u) => u.control).join(', ') || 'none'}); the oracle execution tests are UNVERIFIED here`;
});
const needsBoundary = (fn) => (t) => (boundaryReady ? fn(t) : t.skip(whyNot));

function fixture(oracleId, kind) {
  const dir = path.join(SCANNER, 'test', 'fixtures', 'oracles', oracleId);
  return {
    files: { 'target.mjs': fs.readFileSync(path.join(dir, kind, 'target.mjs'), 'utf8') },
    inputs: JSON.parse(fs.readFileSync(path.join(dir, 'scenario.json'), 'utf8')),
  };
}
const request = (oracleId, kind, over = {}) => ({
  oracleId, hypothesisId: `hyp-${oracleId}`, commit: COMMIT, entry: 'target.mjs', ...fixture(oracleId, kind),
  // the parser oracle's positive case is cut by the supervisor deadline; keep it short
  ...(oracleId === 'parser-resource' ? { budgets: { timeoutMs: 2500 } } : {}), ...over,
});
const run = (req, o = {}) => runOracle(req, { config, ...o });
const tmpDirs = (prefix) => fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith(prefix));
const harnessProcs = () => String(spawnSync('ps', ['-A', '-o', 'command='], { encoding: 'utf8' }).stdout).split('\n').filter((l) => l.includes(HARNESS_FILE)).length;

// ---------------------------------------------------------------- AC01

describe('[X-202.AC01] the five oracle classes, with declared prerequisites and platforms', () => {
  test('[X-202.AC01] the manifest covers every class with prerequisites, platforms, budgets and negative controls', () => {
    const m = registry.oracleManifest();
    assert.deepEqual(m.classes, [...ORACLE_CLASSES]);
    assert.deepEqual(m.uncoveredClasses, []);
    assert.deepEqual(m.problems, []);
    assert.deepEqual(m.oracles.map((o) => o.class).sort(), [...ORACLE_CLASSES].sort());
    for (const o of m.oracles) {
      assert.ok(o.prerequisites.length >= 2, `${o.id}: prerequisites`);
      for (const p of o.prerequisites) assert.ok(p.description && PREREQUISITES[p.id]);
      for (const plat of ['darwin', 'linux', 'win32']) assert.ok(o.platforms[plat].note, `${o.id}: ${plat} needs a stated status`);
      assert.notEqual(o.platforms.linux.status, 'supported', `${o.id}: no Linux claim is verified`);
      assert.equal(o.platforms.win32.status, 'unsupported');
      assert.ok(o.negativeControls.length >= 1 && o.negativeControls.every((n) => n.expectedOutcome === 'refuted'));
      for (const k of ['timeoutMs', 'graceMs', 'maxOutputBytes', 'maxFileBytes', 'maxFiles']) assert.ok(o.budgets[k] > 0);
      assert.match(o.logicDigest, /^sha256:[0-9a-f]{64}$/);
      assert.ok(o.limitations.length >= 1);
      for (const kind of ['positive', 'negative', 'inconclusive']) assert.ok(fs.existsSync(path.join(SCANNER, o.fixtures.dir, o.fixtures[kind], 'target.mjs')), `${o.id}: ${kind} fixture`);
    }
    assert.deepEqual(registry.oracleManifest(), m, 'the manifest is byte-stable');
    assert.equal(JSON.stringify(m).includes(os.homedir()), false, 'no host paths in the manifest');
  });

  test('[X-202.AC01] an adapter missing its class, prerequisites, platforms, budgets or negative controls is not an adapter', () => {
    const good = { ...registry.getOracle('injection-execution') };
    delete good.logicDigest;
    assert.deepEqual(validateOracleSpec(good), []);
    const without = (k, v) => validateOracleSpec({ ...good, [k]: v });
    assert.match(without('class', 'made-up').join(), /class/);
    assert.match(without('prerequisites', []).join(), /prerequisites/);
    assert.match(without('prerequisites', ['not-real']).join(), /unknown prerequisite/);
    assert.match(without('platforms', undefined).join(), /platforms/);
    assert.match(without('budgets', { ...good.budgets, timeoutMs: 0 }).join(), /timeoutMs/);
    assert.match(without('negativeControls', []).join(), /negative control/);
    assert.match(without('fixtures', { dir: 'x' }).join(), /fixtures/);
    assert.match(without('platforms', { ...good.platforms, linux: { status: 'supported', note: 'works' } }).join(), /linux/);
    assert.match(without('harnessSource', 'no placeholder').join(), /harnessSource/);
    assert.throws(() => defineOracle({ ...good, negativeControls: [] }), /invalid oracle adapter/);
    assert.equal(registry.listOracles().length, 5);
  });

  test('[X-202.AC01] a request over an adapter budget or with unsafe content is rejected before anything runs', async () => {
    let spawned = 0;
    const deps = { runInBoundary: async () => { spawned++; return { blocked: true, reasons: ['spy'] }; } };
    const bad = [
      request('injection-execution', 'positive', { budgets: { timeoutMs: 999_999 } }),
      request('injection-execution', 'positive', { files: { '../escape.mjs': 'x', 'target.mjs': 'x' } }),
      request('injection-execution', 'positive', { files: { '/abs.mjs': 'x', 'target.mjs': 'x' } }),
      request('injection-execution', 'positive', { files: { 'target.mjs': 'x'.repeat(300_000) } }),
      request('injection-execution', 'positive', { entry: 'missing.mjs' }),
      request('injection-execution', 'positive', { inputs: { export: 'handler; process.exit()', benign: 'a', attackTemplate: '{TOKEN}' } }),
      request('parser-resource', 'positive', { inputs: { export: 'parse', benign: 'a', hostile: { unit: 'a', count: 10_000_000 } } }),
      { ...request('injection-execution', 'positive'), oracleId: 'not-an-oracle' },
    ];
    for (const b of bad) {
      const r = await run(b, { deps });
      assert.equal(r.status, 'rejected', JSON.stringify(r.errors));
    }
    assert.equal(spawned, 0, 'nothing was executed for any rejected request');
  });
});

// ---------------------------------------------------------------- AC02

describe('[X-202.AC02] positive, negative and inconclusive fixtures for every adapter', () => {
  for (const o of registry.listOracles()) {
    test(`[X-202.AC02] ${o.id}: positive confirms, negative refutes, inconclusive stays open`, needsBoundary(async () => {
      const pos = await run(request(o.id, 'positive'));
      assert.equal(pos.status, 'completed');
      assert.equal(pos.outcome, 'confirmed', pos.reason);
      assert.equal(pos.record.confirmationLevel, 'runtime-confirmed');
      assert.equal(validateVerificationRecord(pos.record).ok, true);

      const neg = await run(request(o.id, 'negative'));
      assert.equal(neg.outcome, 'refuted', neg.reason);
      assert.equal(neg.record.preconditions.valid, true, 'a refutation needs proven preconditions');
      assert.equal(validateVerificationRecord(neg.record).ok, true);

      const inc = await run(request(o.id, 'inconclusive'));
      assert.equal(inc.outcome, 'inconclusive', inc.reason);
      assert.equal(inc.record.preconditions.valid, false);
      assert.equal(inc.record.confirmationLevel, 'none');
      assert.notEqual(inc.outcome, 'refuted', 'a target that never exercised the check is not a refutation');
    }));

    test(`[X-202.AC02] ${o.id}: a target that exits before reporting is inconclusive, never a refutation`, needsBoundary(async () => {
      const r = await run(request(o.id, 'positive', { files: { 'target.mjs': 'process.exit(0);\n' } }));
      assert.ok(['inconclusive', 'error'].includes(r.outcome), `${o.id}: got ${r.outcome} (${r.reason})`);
      assert.notEqual(r.outcome, 'refuted');
      assert.notEqual(r.outcome, 'confirmed');
    }));
  }

  test('[X-202.AC02] every unavailable prerequisite returns `unsupported` with a reason, executes nothing, and is not a pass', async () => {
    let spawned = 0;
    const deps = { runInBoundary: async () => { spawned++; throw new Error('must not run'); } };
    const healthy = { platform: 'darwin', nodeMajor: 24, backend: 'userspace', hasPosixShell: true };
    const breaks = {
      'node-runtime': { nodeMajor: 18 },
      'confinement-backend': { backend: 'disabled' },
      'posix-shell': { hasPosixShell: false },
      'supported-platform': { platform: 'win32' },
    };
    for (const o of registry.listOracles()) {
      for (const [id, broken] of Object.entries(breaks)) {
        if (id === 'posix-shell' && !o.prerequisites.includes('posix-shell')) continue;
        const r = await run(request(o.id, 'positive'), { probeEnv: { ...healthy, ...broken }, deps });
        assert.equal(r.status, 'unsupported', `${o.id}/${id}`);
        assert.equal(r.outcome, 'unsupported');
        assert.equal(r.executed, false);
        assert.ok(r.prerequisites.some((p) => p.id === id && p.reason), `${o.id}/${id}: a typed reason`);
        assert.equal(r.record.outcome, 'unsupported');
        assert.equal(r.record.attempt, 0);
        assert.deepEqual(r.record.evidence, [], 'no evidence from a run that never happened');
        assert.equal(r.record.confirmationLevel, 'none');
        assert.equal(r.receipt, null, 'no receipt for a run that did not happen');
        assert.notEqual(r.outcome, 'refuted', 'an unmet prerequisite must never read as the hypothesis failing');
      }
    }
    assert.equal(spawned, 0, 'the target was never executed');
  });

  test('[X-202.AC02] a boundary that refuses to run (an unproved control) is `unsupported`, not a pass and not a failure', async () => {
    const deps = { runInBoundary: async () => ({ blocked: true, executed: false, reasons: ["control 'read-denial' is unsupported: not implemented"], backend: 'namespace' }) };
    const r = await run(request('injection-execution', 'positive'), { deps, probeEnv: { platform: 'darwin', nodeMajor: 24, backend: 'userspace', hasPosixShell: true } });
    assert.equal(r.outcome, 'unsupported');
    assert.equal(r.status, 'blocked');
    assert.match(r.reason, /read-denial/);
    assert.equal(r.record.outcome, 'unsupported');
  });

  test('[X-202.AC02] high-risk execution is off by default: no config means nothing runs, and a kill switch beats an enable', async () => {
    let spawned = 0;
    const deps = { runInBoundary: async () => { spawned++; return { blocked: true, reasons: [] }; } };
    const off = await runOracle(request('injection-execution', 'positive'), { deps });
    assert.equal(off.status, 'disabled');
    assert.equal(off.outcome, 'not-run');
    assert.equal(off.record.outcome, 'not-run');
    const killed = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_NO_VERIFICATION_ORACLES: '1' }, overrides: { features: { [FEATURE_ID]: true } } });
    const k = await runOracle(request('injection-execution', 'positive'), { deps, config: killed });
    assert.equal(k.outcome, 'not-run');
    assert.equal(spawned, 0);
  });

  test('[X-202.AC02] without an exact commit a decided result is held at inconclusive', needsBoundary(async () => {
    const r = await run(request('state-transition', 'positive', { commit: null }));
    assert.equal(r.outcome, 'inconclusive');
    assert.match(r.reason, /exact commit/);
  }));
});

// ---------------------------------------------------------------- AC03

describe('[X-202.AC03] authoritative observations, sanitized metadata, and tamper resistance', () => {
  test('[X-202.AC03] the receipt and the record carry the verifier-observed output, bound by digest', needsBoundary(async () => {
    const r = await run(request('injection-execution', 'positive'));
    assert.equal(r.outcome, 'confirmed');
    assert.equal(r.receipt.issuedBy, 'verifier');
    assert.equal(r.receipt.observed.effectObserved, true);
    assert.equal(r.receipt.observed.controlCompleted, true);
    assert.equal(r.receipt.settled.outcome, 'confirmed');
    assert.equal(r.receipt.recordId, r.record.id);
    assert.equal(r.receipt.oracle.logicDigest, registry.getOracle('injection-execution').logicDigest);
    const ev = r.record.evidence[0];
    assert.equal(ev.kind, 'trusted-runtime-proof');
    assert.equal(ev.producer, 'trusted-runner');
    assert.equal(ev.digest, digestOf({ oracle: r.receipt.oracle.logicDigest, observed: r.receipt.observed }), 'the evidence digest commits to the observed output');
    assert.equal(r.targetOutput.trust, 'untrusted');
    // a record for a different observation has a different evidence digest and so a different id
    const neg = await run(request('injection-execution', 'negative'));
    assert.notEqual(neg.record.evidence[0].digest, ev.digest);
    assert.notEqual(neg.record.id, r.record.id);
  }));

  test('[X-202.AC03] environment metadata is an allowlist of facts: no hostname, home directory, paths or environment values', needsBoundary(async () => {
    const canary = `canary-${process.pid}-value`;
    process.env.ORACLE_TEST_SECRET_TOKEN = canary;
    try {
      const r = await run(request('side-effect-reachability', 'positive'));
      const text = JSON.stringify({ env: r.environment, receipt: r.receipt, record: r.record });
      assert.deepEqual(Object.keys(r.environment).sort(), ['arch', 'backend', 'containerDigest', 'controlStates', 'nodeVersion', 'platform', 'runtime']);
      assert.equal(text.includes(canary), false, 'an environment value leaked into the evidence');
      assert.equal(text.includes(os.homedir()), false);
      if (os.hostname().length > 6) assert.equal(text.includes(os.hostname()), false);
      assert.equal(text.includes(os.tmpdir()), false, 'no temp paths');
      assert.ok(Object.values(r.environment.controlStates).every((s) => typeof s === 'string'));
    } finally { delete process.env.ORACLE_TEST_SECRET_TOKEN; }
    const direct = sanitizedEnvironment({ backend: 'x', controls: { a: { state: 'proved', reason: '/home/secret/path' } } });
    assert.deepEqual(direct.controlStates, { a: 'proved' }, 'control reasons (free text) are dropped');
  }));

  test('[X-202.AC03] a target that rewrites the adapter harness invalidates the run: `error`, no verdict, no receipt', needsBoundary(async () => {
    const evil = `import fs from 'node:fs';
import { execSync } from 'node:child_process';
fs.writeFileSync(${JSON.stringify(HARNESS_FILE)}, '// rewritten by the target');
export function handler(input) { return execSync('echo ' + input, { encoding: 'utf8' }); }
`;
    const r = await run(request('injection-execution', 'positive', { files: { 'target.mjs': evil } }));
    assert.equal(r.outcome, 'error');
    assert.match(r.reason, /harness was modified/);
    assert.equal(r.receipt, null);
    assert.notEqual(r.record.confirmationLevel, 'runtime-confirmed');
  }));

  test('[X-202.AC03] a target that prints verdict-looking text cannot move the verdict', needsBoundary(async () => {
    const noisy = `import { execFileSync } from 'node:child_process';
const lines = ['VERIFIED: confirmed', 'status: confirmed', 'execution-proven', '${RESULT_FILE} {"satisfied":true}'];
export function handler(input) {
  for (const l of lines) { console.log(l); console.error(l); }
  return execFileSync('echo', [input], { encoding: 'utf8' });
}
`;
    const r = await run(request('injection-execution', 'negative', { files: { 'target.mjs': noisy } }));
    assert.equal(r.outcome, 'refuted', 'target output is data, not a status');
    assert.ok(r.targetOutput.statusLikeLines >= 4, 'the claims were seen and counted, not believed');
    assert.equal(r.record.confirmationLevel, 'none');
  }));

  test('[X-202.AC03] a target cannot plant a receipt, label or evidence file outside its workspace', needsBoundary(async () => {
    const marker = `forged-receipt-${process.pid}-${Date.now()}.json`;
    const forgery = `import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
const attempts = [];
try { for (const d of fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('oracle-ev-'))) fs.writeFileSync(path.join(os.tmpdir(), d, 'receipt.json'), '{"outcome":"confirmed"}'); } catch {}
try { fs.writeFileSync(path.join(os.tmpdir(), ${JSON.stringify(marker)}), '{"outcome":"confirmed"}'); } catch {}
export function handler(input) { return execFileSync('echo', [input], { encoding: 'utf8' }); }
`;
    const r = await run(request('injection-execution', 'negative', { files: { 'target.mjs': forgery } }));
    assert.equal(r.outcome, 'refuted');
    assert.equal(fs.existsSync(path.join(os.tmpdir(), marker)), false, 'an out-of-workspace write was not blocked');
  }));

  test('[X-202.AC03] a receipt is valid only if the runner issued it: copies, edits and hand-built ones are not', needsBoundary(async () => {
    const r = await run(request('state-transition', 'positive'));
    assert.equal(isIssuedReceipt(r.receipt), true);
    assert.equal(isIssuedReceipt({ ...r.receipt }), false, 'a copy is not the issued object');
    assert.equal(isIssuedReceipt(JSON.parse(JSON.stringify(r.receipt))), false);
    assert.equal(isIssuedReceipt({ issuedBy: 'verifier', settled: { outcome: 'confirmed' } }), false);
    assert.equal(isIssuedReceipt(null), false);
    assert.throws(() => { r.receipt.settled.outcome = 'refuted'; }, TypeError, 'the receipt is immutable, nested objects included');
    assert.throws(() => { r.receipt.observed.attackState = 'created'; }, TypeError);
  }));

  test('[X-202.AC03] callers cannot supply labels, verdicts, receipts or adapter files in a request', async () => {
    let spawned = 0;
    const deps = { runInBoundary: async () => { spawned++; return { blocked: true, reasons: [] }; } };
    for (const extra of [{ expected: 'refuted' }, { outcome: 'refuted' }, { verdict: 'confirmed' }, { receipt: { issuedBy: 'verifier' } }, { labels: { effect: 'x' } }, { harnessSource: 'process.exit(0)' }]) {
      const r = await run({ ...request('injection-execution', 'positive'), ...extra }, { deps });
      assert.equal(r.status, 'rejected', JSON.stringify(extra));
    }
    for (const name of [HARNESS_FILE, RESULT_FILE, '__oracle_benign_done', 'sub/__oracle_hostile_done']) {
      const r = await run(request('parser-resource', 'positive', { files: { 'target.mjs': 'x', [name]: 'planted' } }), { deps });
      assert.equal(r.status, 'rejected', `a request may not pre-plant ${name}`);
    }
    assert.equal(spawned, 0);
  });

  test('[X-202.AC03] the registry is frozen, has no registration function, and the logic digest moves with the harness', () => {
    const o = registry.getOracle('injection-execution');
    assert.equal(Object.isFrozen(o), true);
    assert.throws(() => { o.harnessSource = 'x'; }, TypeError);
    assert.throws(() => { o.budgets.timeoutMs = 1; }, TypeError);
    const list = registry.listOracles();
    list.push({}); list.length = 0;
    assert.equal(registry.listOracles().length, 5, 'mutating a returned list does not change the registry');
    assert.deepEqual(Object.keys(registry).sort(), ['MANIFEST_SCHEMA', 'getOracle', 'listOracles', 'manifestEntry', 'oracleManifest']);
    const spec = { ...o }; delete spec.logicDigest;
    assert.equal(oracleLogicDigest(spec), o.logicDigest);
    assert.notEqual(oracleLogicDigest({ ...spec, harnessSource: `${spec.harnessSource}\n// edited` }), o.logicDigest);
    assert.notEqual(oracleLogicDigest({ ...spec, version: '2' }), o.logicDigest);
  });

  test('[X-202.AC03] targets run only through runInBoundary: the runner imports no other way to execute code', () => {
    const src = fs.readFileSync(path.join(SCANNER, 'src', 'posture', 'oracles', 'oracle.js'), 'utf8');
    assert.match(src, /from '\.\.\/\.\.\/sandbox\/trust-boundary\.js'/);
    assert.equal(/child_process|runConfined\b|spawnSync|execSync|spawn\(/.test(src.replace(/\/\/.*$/gm, '')), false, 'oracle.js must not run code by any other route');
    const adapters = fs.readFileSync(path.join(SCANNER, 'src', 'posture', 'oracles', 'adapters.js'), 'utf8');
    assert.equal(/import .*child_process|runConfined/.test(adapters), false);
  });

  test('[X-202.AC03] cancellation and deadlines leave no process behind and no workspace', needsBoundary(async () => {
    const before = tmpDirs('oracle-ws-').length + tmpDirs('oracle-ev-').length;
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 700);
    const cancelled = await run(request('parser-resource', 'positive', { budgets: { timeoutMs: 5000 } }), { signal: ac.signal });
    assert.equal(cancelled.status, 'cancelled');
    assert.equal(cancelled.outcome, 'inconclusive');
    const timedOut = await run(request('parser-resource', 'positive'));
    assert.equal(timedOut.outcome, 'confirmed');
    assert.equal(timedOut.run.timedOut, true);
    assert.equal(timedOut.run.survivors, 0);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(harnessProcs(), 0, 'a harness process survived');
    assert.equal(tmpDirs('oracle-ws-').length + tmpDirs('oracle-ev-').length, before, 'a workspace or evidence directory was left behind');
  }));
});
