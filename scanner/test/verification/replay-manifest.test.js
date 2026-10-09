// X-203: replay manifests and environment identity. Replays run oracles through
// the trust boundary; the criteria are tested in both directions (a good manifest
// reproduces, a hostile or incomplete one is rejected or parked, and nothing
// executes unless it is valid).
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createReplayManifest, validateReplayManifest, replayManifest, environmentIdentity, manifestId, unmetPrerequisites,
  allowedScope, MAX_ATTEMPTS, ATTEMPT_SCHEMA, REPLAY_SCHEMA,
} from '../../src/posture/replay/replay.js';
import * as registry from '../../src/posture/oracles/registry.js';
import { FEATURE_ID } from '../../src/posture/oracles/oracle.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { validateVerificationRecord } from '../../src/posture/assurance/verification-record.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const COMMIT = 'd'.repeat(40);
const config = resolveAssuranceConfig({ env: {}, overrides: { features: { [FEATURE_ID]: true } } });

let boundaryReady = false;
let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const report = await probeControls({});
  const unmet = unmetControls(report, [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  boundaryReady = backend === 'userspace' && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); replay execution is UNVERIFIED here`;
});
const needsBoundary = (fn) => (t) => (boundaryReady ? fn(t) : t.skip(whyNot));

function fixture(oracleId, kind) {
  const dir = path.join(SCANNER, 'test', 'fixtures', 'oracles', oracleId);
  return {
    files: { 'target.mjs': fs.readFileSync(path.join(dir, kind, 'target.mjs'), 'utf8') },
    inputs: JSON.parse(fs.readFileSync(path.join(dir, 'scenario.json'), 'utf8')),
  };
}
function bundle(oracleId = 'injection-execution', kind = 'positive', over = {}) {
  const { files, inputs } = fixture(oracleId, kind);
  const manifest = createReplayManifest({
    hypothesisId: 'hyp-replay', commit: COMMIT, fixtureFiles: files, oracleId, entry: 'target.mjs', inputs, ...over.manifest,
  });
  return { manifest, fixtureFiles: files, patchFiles: null, ...over.bundle };
}
const withId = (m) => ({ ...m, id: manifestId(m) });
const spy = () => { const s = { calls: 0 }; s.deps = { runInBoundary: async () => { s.calls++; throw new Error('must not run'); } }; return s; };
const tmpDirs = (prefix) => fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith(prefix));
const psLines = (needle) => String(spawnSync('ps', ['-A', '-o', 'command='], { encoding: 'utf8' }).stdout).split('\n').filter((l) => l.includes(needle) && !l.includes('ps -A')).length;

// ---------------------------------------------------------------- AC01

describe('[X-203.AC01] a manifest pins the environment, and replay reproduces the verdict', () => {
  test('[X-203.AC01] the manifest pins commit, patch hash, fixture hash, toolchain, oracle version, inputs and budgets', () => {
    const { manifest: m, fixtureFiles } = bundle();
    assert.equal(m.schema, REPLAY_SCHEMA);
    assert.equal(m.repository.commit, COMMIT);
    assert.equal(m.patch, null);
    assert.equal(m.fixture.digest, digestOf(fixtureFiles));
    assert.deepEqual(m.toolchain, { runtime: 'node', version: process.versions.node, platform: process.platform, arch: process.arch, containerDigest: null });
    const oracle = registry.getOracle('injection-execution');
    assert.deepEqual(m.oracle, { id: oracle.id, version: oracle.version, logicDigest: oracle.logicDigest });
    assert.equal(m.inputsDigest, digestOf(m.inputs));
    assert.deepEqual(Object.keys(m.budgets).sort(), ['graceMs', 'maxOutputBytes', 'timeoutMs']);
    assert.deepEqual(m.scope, allowedScope('injection-execution'));
    assert.equal(validateReplayManifest(m, { fixtureFiles }).ok, true);
    assert.equal(bundle().manifest.id, m.id, 'the manifest identity is deterministic');
    const env = environmentIdentity();
    assert.match(env.toolchainDigest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(JSON.stringify(env).includes(os.homedir()), false, 'environment identity carries no host paths');
    assert.deepEqual(unmetPrerequisites(m), [], 'the same environment meets every prerequisite');
  });

  test('[X-203.AC01] a patch is pinned by its own hash and changes the manifest identity', () => {
    const base = bundle();
    const patch = fixture('injection-execution', 'negative').files;
    const patched = bundle('injection-execution', 'positive', { manifest: { patchFiles: patch } });
    assert.match(patched.manifest.patch.digest, /^sha256:[0-9a-f]{64}$/);
    assert.notEqual(patched.manifest.id, base.manifest.id);
    assert.equal(validateReplayManifest(patched.manifest, { fixtureFiles: patched.fixtureFiles, patchFiles: patch }).ok, true);
    assert.equal(validateReplayManifest(patched.manifest, { fixtureFiles: patched.fixtureFiles, patchFiles: null }).ok, false, 'a pinned patch must be supplied');
  });

  test('[X-203.AC01] replay on the same supported environment reproduces the verdict and the identical record id', needsBoundary(async () => {
    const b = bundle('injection-execution', 'positive', { manifest: { expected: { outcome: 'confirmed' } } });
    const first = await replayManifest(b, { config });
    const second = await replayManifest(b, { config });
    assert.equal(first.status, 'completed');
    assert.equal(first.outcome, 'confirmed');
    assert.equal(first.reproduced, true);
    assert.equal(second.outcome, first.outcome);
    assert.equal(second.record.id, first.record.id, 'a replay yields the same verification record');
    assert.equal(first.record.commit, COMMIT);
    assert.equal(validateVerificationRecord(first.record).ok, true);
    assert.equal(first.attempt.attempt, 1);

    const neg = await replayManifest(bundle('state-transition', 'negative', { manifest: { expected: { outcome: 'refuted' } } }), { config });
    assert.equal(neg.outcome, 'refuted');
    assert.equal(neg.reproduced, true);
  }));

  test('[X-203.AC01] a patch that closes the hole replays as refuted, and a wrong expectation is reported as not reproduced', needsBoundary(async () => {
    const patch = fixture('injection-execution', 'negative').files;
    const b = bundle('injection-execution', 'positive', { manifest: { patchFiles: patch, expected: { outcome: 'confirmed' } }, bundle: { patchFiles: patch } });
    const r = await replayManifest(b, { config });
    assert.equal(r.outcome, 'refuted', 'the patched revision no longer reproduces the exploit');
    assert.equal(r.reproduced, false, 'the recorded verdict did not reproduce, and that is stated rather than hidden');
  }));
});

// ---------------------------------------------------------------- AC02

describe('[X-203.AC02] missing toolchains, images, network or features are typed prerequisites with resumable attempts', () => {
  test('[X-203.AC02] a missing toolchain parks the attempt: typed prerequisite, nothing executed, no evidence, `not-run`', async () => {
    const s = spy();
    const b = bundle('injection-execution', 'positive', { manifest: { expected: { outcome: 'confirmed' } } });
    const elsewhere = environmentIdentity({ version: '99.9.9' });
    const r = await replayManifest(b, { config, hostEnvironment: elsewhere, runOptions: { deps: s.deps } });
    assert.equal(r.status, 'awaiting-prerequisites');
    assert.equal(r.executed, false);
    assert.equal(r.outcome, 'not-run');
    assert.equal(r.reproduced, null, 'an unrun check reproduces nothing');
    assert.ok(r.prerequisites.some((p) => p.kind === 'toolchain' && p.state === 'missing' && p.resumable === true));
    assert.ok(r.prerequisites.some((p) => p.kind === 'network' && p.state === 'denied'), 'acquisition would need the network, which is not granted');
    assert.deepEqual(r.record.evidence, []);
    assert.equal(r.record.confirmationLevel, 'none');
    assert.equal(r.record.attempt, 0);
    assert.equal(r.attempt.status, 'awaiting-prerequisites');
    assert.equal(s.calls, 0);
  });

  test('[X-203.AC02] the parked attempt is resumable: it runs once the prerequisite is met, and counts both attempts', needsBoundary(async () => {
    const b = bundle('injection-execution', 'positive', { manifest: { expected: { outcome: 'confirmed' } } });
    const parked = await replayManifest(b, { config, hostEnvironment: environmentIdentity({ arch: 'riscv64' }), runOptions: { deps: spy().deps } });
    assert.equal(parked.status, 'awaiting-prerequisites');
    const resumed = await replayManifest(b, { config, resume: parked.attempt });
    assert.equal(resumed.status, 'completed');
    assert.equal(resumed.outcome, 'confirmed');
    assert.equal(resumed.attempt.attempt, 2);
    assert.equal(resumed.record.attempt, 2);
    assert.deepEqual(resumed.attempt.history.map((h) => h.attempt), [1, 2]);
    assert.equal(resumed.attempt.history[0].outcome, 'not-run');
  }));

  test('[X-203.AC02] a pinned container digest is `unsupported` here: never run outside the container it names', async () => {
    const s = spy();
    const env = environmentIdentity({ containerDigest: `sha256:${'9'.repeat(64)}` });
    const b = bundle('injection-execution', 'positive', { manifest: { environment: env } });
    const r = await replayManifest(b, { config, runOptions: { deps: s.deps } });
    assert.equal(r.status, 'awaiting-prerequisites');
    assert.equal(r.outcome, 'unsupported');
    for (const kind of ['container-runtime', 'container-image', 'network']) assert.ok(r.prerequisites.some((p) => p.kind === kind && p.resumable === false), kind);
    assert.equal(r.record.outcome, 'unsupported');
    assert.equal(s.calls, 0);
  });

  test('[X-203.AC02] a disabled feature is a typed, resumable prerequisite; enabling it lets the attempt run', needsBoundary(async () => {
    const b = bundle('state-transition', 'positive');
    const off = await replayManifest(b, { config: resolveAssuranceConfig({ env: {} }) });
    assert.equal(off.status, 'awaiting-prerequisites');
    assert.equal(off.outcome, 'not-run');
    assert.ok(off.prerequisites.some((p) => p.kind === 'feature' && p.id === FEATURE_ID && p.resumable));
    const on = await replayManifest(b, { config, resume: off.attempt });
    assert.equal(on.outcome, 'confirmed');
  }));

  test('[X-203.AC02] a boundary that cannot run is a typed prerequisite, not a verdict', async () => {
    const deps = { runInBoundary: async () => ({ blocked: true, executed: false, reasons: ["control 'tree-termination' is unsupported"], backend: 'namespace' }) };
    const r = await replayManifest(bundle(), { config, runOptions: { deps, probeEnv: { platform: 'darwin', nodeMajor: 24, backend: 'userspace', hasPosixShell: true } } });
    assert.equal(r.status, 'awaiting-prerequisites');
    assert.equal(r.outcome, 'unsupported');
    assert.ok(r.prerequisites.some((p) => p.kind === 'trust-boundary' && /tree-termination/.test(p.reason)));
  });

  test('[X-203.AC02] no model opinion can stand in for a skipped execution: verdict fields are rejected, and an expectation is only ever compared', async () => {
    const s = spy();
    const b = bundle();
    for (const forged of [{ modelVerdict: 'confirmed' }, { verdict: 'confirmed' }, { outcome: 'confirmed' }, { confirmed: true }]) {
      const r = await replayManifest({ ...b, manifest: { ...b.manifest, ...forged } }, { config, runOptions: { deps: s.deps } });
      assert.equal(r.status, 'rejected', JSON.stringify(forged));
      assert.ok(r.errors.some((e) => e.code === 'UNKNOWN_FIELD'));
    }
    const parked = await replayManifest(bundle('injection-execution', 'positive', { manifest: { expected: { outcome: 'confirmed' } } }), { config, hostEnvironment: environmentIdentity({ version: '0.0.1' }), runOptions: { deps: s.deps } });
    assert.equal(parked.outcome, 'not-run', 'an expectation of "confirmed" does not make a skipped run confirmed');
    assert.equal(parked.reproduced, null);
    assert.equal(s.calls, 0);
  });

  test('[X-203.AC02] a forged or foreign attempt cannot skip prerequisites or exceed the attempt limit', async () => {
    const s = spy();
    const b = bundle();
    const other = bundle('state-transition', 'positive');
    const env = environmentIdentity({ version: '1.2.3' });
    const parked = await replayManifest(b, { config, hostEnvironment: env, runOptions: { deps: s.deps } });
    const forgedDone = { ...parked.attempt, status: 'completed', outcome: 'confirmed' };
    assert.equal((await replayManifest(b, { config, resume: forgedDone, runOptions: { deps: s.deps } })).status, 'rejected');
    assert.equal((await replayManifest(other, { config, resume: parked.attempt, runOptions: { deps: s.deps } })).status, 'rejected', 'an attempt belongs to one manifest');
    assert.equal((await replayManifest(b, { config, resume: { ...parked.attempt, attempt: MAX_ATTEMPTS }, runOptions: { deps: s.deps } })).status, 'rejected');
    assert.equal((await replayManifest(b, { config, resume: { schema: ATTEMPT_SCHEMA, manifestId: b.manifest.id, status: 'awaiting-prerequisites', attempt: 'x', history: [] }, runOptions: { deps: s.deps } })).status, 'rejected');
    // claiming the prerequisite is satisfied does nothing: it is re-evaluated against the real host
    const claim = await replayManifest(b, { config, resume: { ...parked.attempt, satisfied: true }, hostEnvironment: env, runOptions: { deps: s.deps } });
    assert.equal(claim.status, 'awaiting-prerequisites');
    assert.equal(s.calls, 0);
  });
});

// ---------------------------------------------------------------- AC03

describe('[X-203.AC03] deadlines, output caps and cleanup are enforced, and bad manifests are rejected', () => {
  test('[X-203.AC03] a process-tree deadline ends a hanging target and everything it started', needsBoundary(async () => {
    const hang = `import { execSync } from 'node:child_process';
export function handler() { execSync('sleep 31337'); }
`;
    const { inputs } = fixture('injection-execution', 'positive');
    const b = bundle('injection-execution', 'positive', { manifest: { budgets: { timeoutMs: 1500 }, fixtureFiles: { 'target.mjs': hang }, inputs }, bundle: { fixtureFiles: { 'target.mjs': hang } } });
    const before = tmpDirs('oracle-ws-').length;
    const t0 = Date.now();
    const r = await replayManifest(b, { config });
    assert.equal(r.status, 'completed');
    assert.equal(r.run.timedOut, true, 'the deadline fired');
    assert.ok(Date.now() - t0 < 12_000, `took ${Date.now() - t0} ms`);
    assert.equal(r.run.survivors, 0);
    assert.equal(r.outcome, 'inconclusive', 'a run cut by its deadline decides nothing');
    await new Promise((res) => setTimeout(res, 300));
    assert.equal(psLines('sleep 31337'), 0, 'the backgrounded descendant survived the replay');
    assert.equal(tmpDirs('oracle-ws-').length, before, 'the workspace was not cleaned up');
  }));

  test('[X-203.AC03] an output flood is capped, the tree is terminated, and the result is `error`', needsBoundary(async () => {
    const flood = `export function handler() { const line = 'x'.repeat(1000); for (;;) console.log(line); }
`;
    const { inputs } = fixture('injection-execution', 'positive');
    const b = bundle('injection-execution', 'positive', { manifest: { budgets: { maxOutputBytes: 4000, timeoutMs: 5000 }, fixtureFiles: { 'target.mjs': flood }, inputs }, bundle: { fixtureFiles: { 'target.mjs': flood } } });
    const r = await replayManifest(b, { config });
    assert.equal(r.status, 'completed');
    assert.equal(r.run.outputCapped, true);
    assert.equal(r.outcome, 'error');
    assert.equal(r.run.survivors, 0);
    assert.ok(r.record.confirmationLevel === 'none');
  }));

  test('[X-203.AC03] a manifest whose content hashes do not match is rejected, and nothing executes', async () => {
    const s = spy();
    const good = bundle();
    const run = (b) => replayManifest(b, { config, runOptions: { deps: s.deps } });
    const tampered = { ...good, fixtureFiles: { 'target.mjs': `${good.fixtureFiles['target.mjs']}\n// edited after pinning` } };
    const r1 = await run(tampered);
    assert.equal(r1.status, 'rejected');
    assert.ok(r1.errors.some((e) => e.code === 'HASH_MISMATCH' && e.path === 'fixture.digest'));
    const patch = fixture('injection-execution', 'negative').files;
    const withPatch = bundle('injection-execution', 'positive', { manifest: { patchFiles: patch }, bundle: { patchFiles: patch } });
    const r2 = await run({ ...withPatch, patchFiles: { 'target.mjs': 'export function handler() {}' } });
    assert.ok(r2.errors.some((e) => e.code === 'HASH_MISMATCH' && e.path === 'patch.digest'));
    const r3 = await run({ ...good, patchFiles: patch });
    assert.ok(r3.errors.some((e) => e.code === 'HASH_MISMATCH' && e.path === 'patch'), 'an unpinned patch cannot be smuggled in');
    const r4 = await run({ ...good, manifest: { ...good.manifest, inputs: { ...good.manifest.inputs, benign: 'changed' } } });
    assert.ok(r4.errors.some((e) => e.code === 'HASH_MISMATCH' && e.path === 'inputsDigest'));
    const r5 = await run({ ...good, manifest: { ...good.manifest, budgets: { ...good.manifest.budgets, timeoutMs: 100 } } });
    assert.ok(r5.errors.some((e) => e.code === 'ID_MISMATCH'), 'editing any pinned field breaks the manifest identity');
    assert.equal(s.calls, 0);
  });

  test('[X-203.AC03] a manifest whose allowed execution scope fails validation is rejected, and nothing executes', async () => {
    const s = spy();
    const good = bundle();
    const reject = async (mutate, code, label) => {
      const r = await replayManifest({ ...good, manifest: withId(mutate(structuredClone(good.manifest))) }, { config, runOptions: { deps: s.deps } });
      assert.equal(r.status, 'rejected', label);
      assert.ok(r.errors.some((e) => e.code === code), `${label}: expected ${code}, got ${JSON.stringify(r.errors.map((e) => e.code))}`);
    };
    await reject((m) => { m.scope.network = true; return m; }, 'SCOPE_VIOLATION', 'network access');
    await reject((m) => { m.scope.executes = ['injection-execution', 'parser-resource']; return m; }, 'SCOPE_VIOLATION', 'a second oracle');
    await reject((m) => { m.scope.writes = 'anywhere'; return m; }, 'SCOPE_VIOLATION', 'writes outside the workspace');
    await reject((m) => { m.scope.extra = true; return m; }, 'SCOPE_VIOLATION', 'unknown scope key');
    await reject((m) => { m.budgets.timeoutMs = 10 * 60 * 1000; return m; }, 'BUDGET_EXCEEDED', 'a budget above the oracle ceiling');
    await reject((m) => { m.budgets.timeoutMs = 0; return m; }, 'BAD_TYPE', 'a zero budget');
    await reject((m) => { m.oracle.logicDigest = `sha256:${'0'.repeat(64)}`; return m; }, 'ORACLE_MISMATCH', 'a different oracle logic');
    await reject((m) => { m.oracle.version = '99'; return m; }, 'ORACLE_MISMATCH', 'a different oracle version');
    await reject((m) => { m.oracle.id = 'no-such-oracle'; return m; }, 'UNKNOWN_ORACLE', 'an unknown oracle');
    await reject((m) => { m.repository.commit = 'main'; return m; }, 'BAD_COMMIT', 'an unpinned revision');
    await reject((m) => { m.entry = 'other.mjs'; return m; }, 'SCOPE_VIOLATION', 'an entry outside the pinned files');
    await reject((m) => { m.expected = { outcome: 'guess' }; return m; }, 'BAD_TYPE', 'an invalid expectation');
    // a path escape is rejected even when its hash is pinned correctly
    const escape = { 'target.mjs': good.fixtureFiles['target.mjs'], '../outside.mjs': 'x' };
    const escaped = bundle('injection-execution', 'positive', { manifest: { fixtureFiles: escape }, bundle: { fixtureFiles: escape } });
    const r = await replayManifest(escaped, { config, runOptions: { deps: s.deps } });
    assert.equal(r.status, 'rejected');
    assert.ok(r.errors.some((e) => e.code === 'SCOPE_VIOLATION' && /safe relative path/.test(e.message)));
    assert.equal((await replayManifest({ manifest: { ...good.manifest, schemaVersion: '2.0.0' }, fixtureFiles: good.fixtureFiles }, { config })).status, 'rejected');
    assert.equal((await replayManifest({ manifest: null, fixtureFiles: {} }, { config })).status, 'rejected');
    assert.equal((await replayManifest(undefined, { config })).status, 'rejected');
    assert.equal(s.calls, 0);
  });
});
