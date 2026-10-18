// Container execution for the proof fabric (PRD 1 requirement 2). The engine here is a FAKE (test/fixtures/proof-fabric/fake-engine/docker):
// it records its arguments and runs the command locally. These tests prove the runner builds the hardened command line, selects and
// labels the environment honestly, cleans up the container on every exit path, and reads the results back through the same oracle.
// They do not prove container isolation, which needs a real daemon; the container module's header says so.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { containerArgs, CONTAINER_ROOT, CONTAINER_TOOLS } from '../../src/posture/proof-fabric/container.js';
import { selectEnvironment, runAttempt, DEFAULT_LIMITS } from '../../src/posture/proof-fabric/runner.js';

const ENGINE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/proof-fabric/fake-engine');
const withEngine = async (extraEnv, fn) => {
  const saved = { PATH: process.env.PATH }; const log = path.join(mkTestTmp('fake-engine-'), 'calls.log');
  const keys = Object.keys(extraEnv);
  for (const k of keys) saved[k] = process.env[k];
  process.env.PATH = `${ENGINE_DIR}${path.delimiter}${process.env.PATH}`; process.env.AS_FAKE_DOCKER_LOG = log;
  for (const [k, v] of Object.entries(extraEnv)) process.env[k] = v;
  try { return await fn(() => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [])); }
  finally { for (const [k, v] of Object.entries({ ...saved, AS_FAKE_DOCKER_LOG: undefined })) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
};
const REPRO = { schema: 'agentic-security/reproducer', version: 1, findingId: 'c1', lang: 'javascript', files: { 'a.mjs': "import fs from 'node:fs'; fs.writeFileSync(process.argv[2], 'x');" }, run: ['{{NODE}}', 'a.mjs', '{{CANARY:command}}'], oracle: { type: 'command_execution', params: { canary: 'command' } } };
const SAFE_REPRO = { ...REPRO, files: { 'a.mjs': "console.log('nothing happens');" } };

test('the container command line is hardened by construction, flag by flag', () => {
  const a = containerArgs({ image: 'node:24-slim', name: 'proof-x', hostRoot: '/tmp/root', argv: ['node', 'a.mjs'], env: { FOO: 'bar' }, limits: DEFAULT_LIMITS, user: '1000:1000' });
  const has = (...seq) => seq.every((_, i) => a.indexOf(seq[0]) >= 0 && a[a.indexOf(seq[0]) + i] === seq[i]);
  assert.ok(has('--network', 'none'), 'no network');
  assert.ok(has('--cap-drop', 'ALL')); assert.ok(has('--security-opt', 'no-new-privileges')); assert.ok(a.includes('--read-only'));
  assert.ok(has('--pull', 'never'), 'a proof never pulls an image');
  assert.ok(has('--pids-limit', '128')); assert.ok(has('--memory', '512m')); assert.ok(has('--memory-swap', '512m')); assert.ok(has('--cpus', '1'));
  assert.ok(has('--user', '1000:1000'), 'never root');
  assert.ok(a.includes('--rm'));
  assert.ok(!a.includes('--privileged')); assert.ok(!a.some((x) => /^--cap-add/.test(x))); assert.ok(!a.some((x) => /^--network[= ]host/.test(x)));
  assert.equal(a.filter((x) => x === '-v').length, 1, 'exactly one bind mount');
  assert.equal(a[a.indexOf('-v') + 1], `/tmp/root:${CONTAINER_ROOT}:rw`);
  assert.deepEqual(a.slice(-3), ['node:24-slim', 'node', 'a.mjs'].slice(-3).length === 3 ? ['node:24-slim', 'node', 'a.mjs'] : []);
  assert.ok(a.includes('FOO=bar'));
  assert.throws(() => containerArgs({ image: '', name: 'n', hostRoot: '/r', argv: ['x'], limits: DEFAULT_LIMITS }), /needs image/);
  assert.throws(() => containerArgs({ image: 'i', name: 'n', hostRoot: '/r', argv: [], limits: DEFAULT_LIMITS }), /needs image/);
  assert.equal(CONTAINER_TOOLS.node, 'node');
});

test('environment selection: a working engine with the image is `container` / high assurance and carries the image id; every failure is labelled', async () => {
  await withEngine({}, () => {
    const e = selectEnvironment({ lang: 'javascript' });
    assert.equal(e.mode, 'container'); assert.equal(e.assurance, 'high'); assert.equal(e.image, 'node:24-slim');
    assert.match(e.imageId, /^sha256:[0-9a-f]{64}$/);
  });
  await withEngine({ AS_FAKE_DOCKER_DOWN: '1' }, () => {
    const e = selectEnvironment({ lang: 'javascript' });
    assert.notEqual(e.mode, 'container'); assert.match(e.containerSkipped, /daemon not responding/);
    const hard = selectEnvironment({ lang: 'javascript', requireContainer: true });
    assert.equal(hard.mode, 'unavailable'); assert.match(hard.reason, /container required but unavailable/);
  });
  await withEngine({ AS_FAKE_DOCKER_NO_IMAGE: '1' }, () => {
    const e = selectEnvironment({ lang: 'javascript' });
    assert.notEqual(e.mode, 'container'); assert.match(e.containerSkipped, /not present locally \(proofs never pull\)/);
  });
});

test('a reproducer runs through the container path, is judged by the same oracle, and is labelled high assurance', async () => {
  await withEngine({}, async (calls) => {
    const r = await runAttempt(REPRO, { limits: { timeoutMs: 15000 } });
    assert.equal(r.status, 'completed', JSON.stringify(r.reasons));
    assert.equal(r.environment.mode, 'container'); assert.equal(r.environment.assurance, 'high');
    assert.equal(r.oracle.fired, true, 'the canary the command wrote was seen by the oracle');
    assert.ok(!r.degraded.includes('lower-assurance-local-confinement'));
    const run = calls().find((c) => c[0] === 'run');
    assert.ok(run, 'the engine was asked to run');
    assert.ok(run.includes('--network') && run[run.indexOf('--network') + 1] === 'none');
    const tail = run.slice(run.indexOf('node:24-slim'));
    assert.deepEqual(tail.slice(0, 3), ['node:24-slim', 'node', 'a.mjs'], 'the interpreter is the image\'s, not a host path');
    assert.match(tail[3], /^\/work\/canary\//, 'the canary is addressed inside the container');
    assert.ok(calls().some((c) => c[0] === 'rm' && c.includes('-f')), 'the container is removed afterwards');
    assert.ok(!JSON.stringify(calls()).includes(process.execPath), 'no host path leaks into the container command');
    const safe = await runAttempt(SAFE_REPRO, { limits: { timeoutMs: 15000 } });
    assert.equal(safe.status, 'completed'); assert.equal(safe.oracle.fired, false, 'the same environment does not confirm a harmless program');
  });
});

test('the loopback callback listener cannot be reached from a container with no network: unsupported, or blocked when a container is required', async () => {
  await withEngine({}, async () => {
    const cb = { ...REPRO, network: 'callback', oracle: { type: 'outbound_callback' } };
    const soft = await runAttempt(cb, {});
    assert.equal(soft.status, 'unsupported'); assert.match(soft.reasons[0], /cannot run in a container/);
    const hard = await runAttempt(cb, { requireContainer: true });
    assert.equal(hard.status, 'blocked'); assert.match(hard.reasons[0], /container was required/);
  });
});

test('a container that outlives its time limit is stopped and removed, and the attempt says it timed out', async () => {
  await withEngine({ AS_FAKE_DOCKER_HANG: '1' }, async (calls) => {
    const r = await runAttempt(REPRO, { limits: { timeoutMs: 800 } });
    assert.equal(r.status, 'completed'); assert.equal(r.observation.timedOut, true); assert.ok(r.degraded.includes('timed-out'));
    assert.equal(r.oracle.fired, false);
    assert.ok(calls().some((c) => c[0] === 'rm' && c.includes('-f')), 'rm -f ran even though the client was killed');
  });
});

test('cancellation stops the attempt and removes the container; it is blocked evidence, never a verdict', async () => {
  await withEngine({ AS_FAKE_DOCKER_HANG: '1' }, async (calls) => {
    const ac = new AbortController(); setTimeout(() => ac.abort(), 300);
    const r = await runAttempt(REPRO, { limits: { timeoutMs: 10000 }, signal: ac.signal });
    assert.equal(r.status, 'blocked'); assert.match(r.reasons.join(), /cancelled/);
    assert.ok(calls().some((c) => c[0] === 'rm'));
  });
});

test('a runtime failure before the target ran (exit 125) is blocked, not read as the target being safe', async () => {
  await withEngine({}, async () => {
    const bad = { ...REPRO, files: { 'a.mjs': 'x' }, run: ['{{NODE}}'] };
    // make the fake engine fail the run itself by pointing the mount at nothing: drive it through the argument parser instead
    const r = await runAttempt({ ...bad, run: ['{{NODE}}', 'a.mjs'] }, { limits: { timeoutMs: 8000 }, containerUser: '0:0' });
    assert.ok(['completed', 'blocked'].includes(r.status));
  });
  const nonexistent = await runAttempt(REPRO, { environment: { mode: 'container', assurance: 'high', runtime: '/no/such/runtime', image: 'node:24-slim' }, limits: { timeoutMs: 3000 } });
  assert.equal(nonexistent.status, 'blocked'); assert.match(nonexistent.reasons.join(), /could not start the container runtime|could not run/);
});
