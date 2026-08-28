import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { readLifecycle, updateLifecycle, latestOpenIntroduction } from '../../src/posture/provenance/lifecycle.js';

test('Scenario E: introduce, remediate, reintroduce produces three ordered events', async () => {
  const fx = createGitFixture();
  try {
    const finding = { stableId: 'sid-e', findingProvenance: { status: 'complete', findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z' } } };

    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    let store = readLifecycle(fx.root);
    assert.equal(store['sid-e'].length, 1);
    assert.equal(store['sid-e'][0].type, 'introduced');

    await updateLifecycle(fx.root, [], { scanId: 'scan2', observedAt: '2026-02-01T00:00:00Z' });
    store = readLifecycle(fx.root);
    assert.equal(store['sid-e'].length, 2);
    assert.equal(store['sid-e'][1].type, 'remediated');
    assert.equal(latestOpenIntroduction(store, 'sid-e'), null);

    await updateLifecycle(fx.root, [finding], { scanId: 'scan3', observedAt: '2026-03-01T00:00:00Z' });
    store = readLifecycle(fx.root);
    assert.equal(store['sid-e'].length, 3);
    assert.equal(store['sid-e'][2].type, 'reintroduced');
    const latest = latestOpenIntroduction(store, 'sid-e');
    assert.ok(latest);
    assert.equal(latest.type, 'reintroduced');
  } finally {
    fx.cleanup();
  }
});

test('a finding present across two consecutive scans does not double-introduce', async () => {
  const fx = createGitFixture();
  try {
    const finding = { stableId: 'sid-stable', findingProvenance: { status: 'not_available' } };
    await updateLifecycle(fx.root, [finding], { scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
    await updateLifecycle(fx.root, [finding], { scanId: 's2', observedAt: '2026-01-02T00:00:00Z' });
    const store = readLifecycle(fx.root);
    assert.equal(store['sid-stable'].length, 1);
  } finally {
    fx.cleanup();
  }
});

test('a read-only scan (--no-state) persists nothing but still returns this scan\'s view', async () => {
  // Two halves, and the second is the one that is easy to get wrong: a
  // read-only scan must not write, AND must not lie. Returning the on-disk
  // store unchanged would report a finding first seen in this scan as having
  // no introduction event at all — a false answer, not a missing one.
  const fx = createGitFixture();
  const prior = process.env.AGENTIC_SECURITY_NO_STATE;
  try {
    process.env.AGENTIC_SECURITY_NO_STATE = '1';
    const finding = { stableId: 'sid-ro', findingProvenance: { status: 'not_available' } };
    const view = await updateLifecycle(fx.root, [finding], { scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });

    assert.equal(view['sid-ro'].length, 1);
    assert.equal(view['sid-ro'][0].type, 'introduced');
    assert.ok(!fs.existsSync(path.join(fx.root, '.agentic-security')),
      'a read-only scan must not create the state directory');
    assert.deepEqual(readLifecycle(fx.root), {}, 'and must persist nothing');
  } finally {
    if (prior === undefined) delete process.env.AGENTIC_SECURITY_NO_STATE;
    else process.env.AGENTIC_SECURITY_NO_STATE = prior;
    fx.cleanup();
  }
});

test('refuses to create state in a directory that is not a recognised project root', async () => {
  // statePath() decides WHERE state belongs; it applies no safety check of its
  // own. That check (isSafeStateDir) lives inside safeWriteState()/
  // ensureStateDir(), which this module deliberately bypasses so a failed write
  // can throw inside the locked section. So it must apply the check itself —
  // otherwise it litters `.agentic-security/` into any directory it is pointed
  // at, which is precisely the defect state-dir.js exists to prevent (its
  // header records a user who uninstalled the plugin over it).
  //
  // A bare tmp dir with no .git/package.json/etc. is not a project root.
  const orphan = fs.mkdtempSync(path.join(os.tmpdir(), 'as-noproject-'));
  try {
    const view = await updateLifecycle(orphan, [{ stableId: 'sid-orphan' }], { scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });

    assert.ok(!fs.existsSync(path.join(orphan, '.agentic-security')),
      'must not create a state directory outside a project root');
    // The check runs BEFORE the lock is taken — withLock's first act is an
    // mkdir of the same directory, so guarding only the store write would have
    // created the litter and then declined to fill it.
    assert.deepEqual(fs.readdirSync(orphan), [], 'the directory must be left byte-identical');
    // Still a view, not a lie: the caller gets what this scan would have
    // recorded, same contract as the read-only path.
    assert.equal(view['sid-orphan'][0].type, 'introduced');
  } finally {
    fs.rmSync(orphan, { recursive: true, force: true });
  }
});

test('lock is released even if the update callback throws', async () => {
  const fx = createGitFixture();
  try {
    // Force the write inside updateLifecycle's locked critical section to
    // fail deterministically: put a directory where lifecycle.json needs
    // to be written, so fs.writeFileSync throws EISDIR. (A monkeypatch of
    // fs.writeFileSync doesn't work here — `import * as fs from 'node:fs'`
    // in real strict-mode ESM yields a frozen namespace object, so
    // reassigning a property throws "Cannot assign to read only
    // property" instead of installing the patch.)
    const provenanceDir = path.join(fx.root, '.agentic-security', 'provenance');
    const storeFile = path.join(provenanceDir, 'lifecycle.json');
    fs.mkdirSync(provenanceDir, { recursive: true });
    fs.mkdirSync(storeFile);

    await assert.rejects(
      updateLifecycle(fx.root, [{ stableId: 'x' }], { scanId: 's1', observedAt: '2026-01-01T00:00:00Z' })
    );

    // Clear the obstruction so the next call's assertion is about the
    // LOCK being released, not about the write failing again.
    fs.rmdirSync(storeFile);

    // The real proof: if the lock file from the failed call above were
    // still on disk, this next call would spin for the internal 5s
    // timeout and reject. Racing it against a much shorter deadline turns
    // "lock leaked" into an observable failure instead of a slow hang.
    const result = await Promise.race([
      updateLifecycle(fx.root, [{ stableId: 'x' }], { scanId: 's2', observedAt: '2026-01-02T00:00:00Z' }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('TIMEOUT: lock was not released after the callback threw')), 2000)),
    ]);
    assert.ok(result);
    const store = readLifecycle(fx.root);
    assert.equal(store['x'].length, 1);
    assert.equal(store['x'][0].type, 'introduced');
  } finally {
    fx.cleanup();
  }
});

test('a stale lock (dead PID, old mtime) is reaped instead of wedging updates', async () => {
  const fx = createGitFixture();
  try {
    const provenanceDir = path.join(fx.root, '.agentic-security', 'provenance');
    fs.mkdirSync(provenanceDir, { recursive: true });
    const lockFile = path.join(provenanceDir, 'lifecycle.lock');

    // spawnSync only returns after the child has already exited, so its
    // pid is guaranteed dead by the time we write it into the lock file.
    const dead = spawnSync(process.execPath, ['-e', '0']);
    assert.ok(Number.isFinite(dead.pid), 'expected a real pid from the dead child process');

    fs.writeFileSync(lockFile, String(dead.pid));
    // Also backdate well past the 30s staleness window, so the test does
    // not rely solely on PID-liveness detection working on this platform.
    const old = new Date(Date.now() - 60000);
    fs.utimesSync(lockFile, old, old);

    const result = await Promise.race([
      updateLifecycle(fx.root, [{ stableId: 'y' }], { scanId: 's1', observedAt: '2026-01-01T00:00:00Z' }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('TIMEOUT: stale lock was not reaped')), 4000)),
    ]);
    assert.ok(result);
    const store = readLifecycle(fx.root);
    assert.equal(store['y'].length, 1);
    assert.equal(store['y'][0].type, 'introduced');
  } finally {
    fx.cleanup();
  }
});

test('applyScan: a finding whose findingOrigin.revertOf is set is classified "reverted", not "reintroduced"', async () => {
  const fx = createGitFixture();
  try {
    const finding = {
      stableId: 'sid-revert',
      findingProvenance: {
        status: 'complete',
        findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z', revertOf: null, cherryPickOf: null },
      },
    };
    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    await updateLifecycle(fx.root, [], { scanId: 'scan2', observedAt: '2026-02-01T00:00:00Z' });

    const reintroduced = {
      stableId: 'sid-revert',
      findingProvenance: {
        status: 'complete',
        findingOrigin: { commit: 'c2', authorDate: '2026-03-01T00:00:00Z', revertOf: 'c-fix', cherryPickOf: null },
      },
    };
    await updateLifecycle(fx.root, [reintroduced], { scanId: 'scan3', observedAt: '2026-03-01T00:00:00Z' });
    const store = readLifecycle(fx.root);
    assert.equal(store['sid-revert'].length, 3);
    assert.equal(store['sid-revert'][2].type, 'reverted');
  } finally { fx.cleanup(); }
});

test('applyScan: a finding whose findingOrigin.cherryPickOf is set is classified "cherry-picked"', async () => {
  const fx = createGitFixture();
  try {
    const finding = {
      stableId: 'sid-cherry',
      findingProvenance: {
        status: 'complete',
        findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z', revertOf: null, cherryPickOf: 'c-orig' },
      },
    };
    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    const store = readLifecycle(fx.root);
    assert.equal(store['sid-cherry'][0].type, 'cherry-picked');
  } finally { fx.cleanup(); }
});

test('applyScan: neither revertOf nor cherryPickOf set — unchanged introduced/reintroduced behavior', async () => {
  const fx = createGitFixture();
  try {
    const finding = { stableId: 'sid-plain', findingProvenance: { status: 'complete', findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z' } } };
    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    const store = readLifecycle(fx.root);
    assert.equal(store['sid-plain'][0].type, 'introduced');
  } finally { fx.cleanup(); }
});

test('isOpenEvent: a "reverted" or "cherry-picked" last event is still open — remediation can close it', async () => {
  const fx = createGitFixture();
  try {
    const finding = {
      stableId: 'sid-open',
      findingProvenance: { status: 'complete', findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z', revertOf: 'c-fix', cherryPickOf: null } },
    };
    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    let store = readLifecycle(fx.root);
    assert.equal(store['sid-open'][0].type, 'reverted');
    assert.ok(latestOpenIntroduction(store, 'sid-open'), 'a "reverted" event must count as open');

    await updateLifecycle(fx.root, [], { scanId: 'scan2', observedAt: '2026-02-01T00:00:00Z' });
    store = readLifecycle(fx.root);
    assert.equal(store['sid-open'][1].type, 'remediated', 'a reverted-open finding must still be remediable when it disappears');
  } finally { fx.cleanup(); }
});
