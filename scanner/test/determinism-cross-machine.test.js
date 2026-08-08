// R4 — the cross-machine determinism gate.
//
// The gate's whole value is that a green result means something, so every way
// it could go green WITHOUT having compared two machines is asserted to fail.
// These run the real scripts as subprocesses and check exit codes, because a
// gate is its exit code — a comparator that printed a complaint and exited 0
// would be worse than no comparator at all.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const COMPARE = path.join(REPO, 'scripts', 'determinism-compare.mjs');
const ATTEST = path.join(REPO, 'scripts', 'attest-fixture.mjs');

function compare(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'det-'));
  try {
    for (const [name, obj] of Object.entries(files)) {
      fs.writeFileSync(path.join(dir, name), typeof obj === 'string' ? obj : JSON.stringify(obj));
    }
    const r = spawnSync(process.execPath, [COMPARE, dir], { encoding: 'utf8' });
    return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

// Per-fixture shape. The gate attests TWO fixtures — the regex/structural one
// and a deep one that must reach the taint engine — so agreement is checked
// per fixture and a divergence names the layer.
const att = (over = {}) => ({
  digest: 'a'.repeat(64), findingCount: 11, engineVersion: '0.131.0',
  digests: { basic: 'a'.repeat(64), deep: 'b'.repeat(64) },
  findingCounts: { basic: 11, deep: 3 },
  parsers: { basic: ['REGEX'], deep: ['IR-TAINT', 'PY-SAST'] },
  canonicalisation: 'agentic-security/run-attestation-canon-v1',
  platform: 'linux-x64', nodeVersion: 'v24.0.0', ...over,
});

test('two platforms agreeing on a non-empty digest passes', () => {
  const r = compare({ 'a.json': att(), 'b.json': att({ platform: 'darwin-arm64' }) });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /VERIFIED/);
});

test('a disagreement on the basic fixture fails and names it', () => {
  const r = compare({
    'a.json': att(),
    'b.json': att({ platform: 'darwin-arm64', digests: { basic: 'c'.repeat(64), deep: 'b'.repeat(64) } }),
  });
  assert.equal(r.code, 1);
  assert.match(r.out, /fixture 'basic': machines disagree/);
});

test('a disagreement on the DEEP fixture fails and names it', () => {
  // The case the single-fixture gate could never have caught: the taint engine
  // and the Python parser diverging while the regex detectors agree.
  const r = compare({
    'a.json': att(),
    'b.json': att({ platform: 'darwin-arm64', digests: { basic: 'a'.repeat(64), deep: 'd'.repeat(64) } }),
  });
  assert.equal(r.code, 1);
  assert.match(r.out, /fixture 'deep': machines disagree/);
});

test('a deep fixture that degraded to the syntactic layer fails', () => {
  // Agreement reached because the taint engine did not run is agreement for
  // the wrong reason, and it would silently hollow out the whole gate.
  const r = compare({
    'a.json': att(),
    'b.json': att({ platform: 'darwin-arm64', parsers: { basic: ['REGEX'], deep: ['JS-FW'] } }),
  });
  assert.equal(r.code, 1);
  assert.match(r.out, /degraded to the syntactic layer/);
});

test('a fixture missing from one machine is not silently skipped', () => {
  const r = compare({
    'a.json': att(),
    'b.json': att({ platform: 'darwin-arm64', digests: { basic: 'a'.repeat(64) } }),
  });
  assert.equal(r.code, 1);
  assert.match(r.out, /fixture 'deep' is missing/);
});

test('attestations predating the multi-fixture gate are refused, not compared', () => {
  const legacy = att();
  delete legacy.digests;
  const other = att({ platform: 'darwin-arm64' });
  delete other.digests;
  const r = compare({ 'a.json': legacy, 'b.json': other });
  assert.equal(r.code, 1);
  assert.match(r.out, /predate the multi-fixture gate/);
});

test('one attestation is not a cross-machine comparison', () => {
  // The failure mode this guards: an upload step silently failing, leaving one
  // artifact that trivially "agrees" with itself.
  const r = compare({ 'a.json': att() });
  assert.equal(r.code, 1);
  assert.match(r.out, /at least two/);
});

test('two runs on the SAME platform is repeatability, not cross-machine', () => {
  const r = compare({ 'a.json': att(), 'b.json': att() });
  assert.equal(r.code, 1);
  assert.match(r.out, /same platform/);
});

test('agreement on an empty finding set is not evidence', () => {
  const r = compare({
    'a.json': att({ findingCount: 0 }),
    'b.json': att({ platform: 'darwin-arm64', findingCount: 0 }),
  });
  assert.equal(r.code, 1);
  assert.match(r.out, /proves nothing/);
});

test('an empty DEEP fixture is not evidence either', () => {
  const r = compare({
    'a.json': att({ findingCounts: { basic: 11, deep: 0 } }),
    'b.json': att({ platform: 'darwin-arm64', findingCounts: { basic: 11, deep: 0 } }),
  });
  assert.equal(r.code, 1);
  assert.match(r.out, /proves nothing/);
});

test('mismatched canonicalisations are not comparable', () => {
  const r = compare({
    'a.json': att(),
    'b.json': att({ platform: 'darwin-arm64', canonicalisation: 'something-else' }),
  });
  assert.equal(r.code, 1);
  assert.match(r.out, /not comparable/);
});

test('a malformed or unparseable attestation fails rather than being skipped', () => {
  assert.equal(compare({ 'a.json': att(), 'b.json': '{not json' }).code, 1);
  assert.equal(compare({ 'a.json': att(), 'b.json': { platform: 'darwin-arm64' } }).code, 1);
});

test('an empty directory fails', () => {
  assert.equal(compare({}).code, 1);
});

test('the attest script is repeatable on this machine and reports a non-empty set', () => {
  // The cross-machine half needs CI. Same-machine repeatability is checkable
  // here, and a break in it would break the CI job for a reason that has
  // nothing to do with machines differing.
  const run = () => {
    const r = spawnSync(process.execPath, [ATTEST, '--json'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout);
  };
  const a = run();
  const b = run();
  assert.equal(a.digest, b.digest, 'two runs on one machine must agree before two machines can');
  assert.ok(a.findingCount > 0, 'the fixture must produce findings or the gate is vacuous');
});
