// Epic F-02/F-03: real application profiles are probed, never installed; an unavailable framework, database, container runtime or
// fetch authorisation is a typed setup blocker; an available host still does not run target code unconfined. F-AC03, F-AC06.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probeProfile, runProfileLeg, environmentManifest, PROFILES, PLATFORM_STATUS } from '../../src/posture/oracles/profiles.js';

const probes = (o) => ({ which: (b) => (o.bins || []).includes(b), nodeModule: (n) => (o.node || []).includes(n), pythonModule: (n) => (o.py || []).includes(n), dockerInfo: () => !!o.dockerUp });

test('each missing piece is its own typed blocker; nothing is installed or pulled', () => {
  const none = probeProfile('express-postgres', { probes: probes({ bins: ['node'] }) });
  assert.equal(none.status, 'setup-blocked');
  assert.deepEqual(none.blockers.map((b) => b.code), ['framework-unavailable', 'database-unavailable']);
  const dockerNoPolicy = probeProfile('express-postgres', { probes: probes({ bins: ['node', 'docker'], node: ['express'] }) });
  assert.deepEqual(dockerNoPolicy.blockers.map((b) => b.code), ['dependency-fetch-not-authorized']);
  const dockerDown = probeProfile('express-postgres', { fetchPolicy: { allowImages: true }, probes: probes({ bins: ['node', 'docker'], node: ['express'] }) });
  assert.deepEqual(dockerDown.blockers.map((b) => b.code), ['container-runtime-unavailable']);
  const fastapi = probeProfile('fastapi-postgres', { probes: probes({ bins: ['python3'] }) });
  assert.deepEqual(fastapi.blockers.map((b) => b.code), ['framework-unavailable', 'framework-unavailable', 'database-unavailable']);
  assert.equal(probeProfile('nope').status, 'unknown-profile');
});

test('F-AC03/F-AC06: an available host still returns unsupported (no confined runner), never a host fallback; Linux stays unverified', () => {
  const ok = probes({ bins: ['node', 'postgres', 'initdb', 'pg_ctl'], node: ['express'] });
  assert.equal(probeProfile('express-postgres', { probes: ok }).status, 'available');
  const leg = runProfileLeg('express-postgres', { probes: ok });
  assert.deepEqual([leg.status, leg.reason], ['unsupported', 'confined-runner-not-implemented']);
  assert.deepEqual([runProfileLeg('express-postgres', { probes: probes({}) }).reason], ['setup-blocked']);
  assert.equal(PLATFORM_STATUS.linux, 'unverified');
  assert.equal(probeProfile('express-postgres', { platform: 'win32', probes: ok }).blockers.at(-1).code, 'platform-unverified');
  assert.deepEqual(Object.keys(PROFILES).sort(), ['express-postgres', 'fastapi-postgres']);
});

test('the environment manifest pins what it can and says why it cannot pin the rest', () => {
  const m = environmentManifest('express-postgres', { appRoot: process.cwd(), lockfile: 'package-lock.json', migrations: ['does-not-exist.sql'] });
  assert.match(m.lockfile.digest, /^sha256:/);
  assert.equal(m.imageDigest, null); assert.match(m.imageReason, /no image/);
  assert.equal(m.migrations[0].digest, null);
  assert.match(m.digest, /^sha256:/);
});
