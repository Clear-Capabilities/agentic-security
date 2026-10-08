// The local twin of hosted CI's "Verify committed bundle matches source": a bundle that agrees with its own sidecar but not with the source is
// stale, and must fail (it passed the gate's bundle-integrity check and failed CI on 0.159.0).
import test from 'node:test';
import assert from 'node:assert/strict';
import { bundleMatchesSource } from '../../scripts/check-bundle-source.mjs';

const runner = (script) => { const calls = []; const run = (cmd, args) => { calls.push([cmd, ...args].join(' ')); return script(cmd, args); }; run.calls = calls; return run; };

test('equal: a fresh build identical to the committed bundle passes, and nothing is restored', () => {
  const run = runner((cmd, args) => ({ status: 0 }));
  assert.deepEqual(bundleMatchesSource({ run }), { ok: true });
  assert.ok(!run.calls.some((c) => c.startsWith('git checkout')));
});

test('stale: a fresh build that differs FAILS, says the bundle is stale, and restores the committed files', () => {
  const run = runner((cmd, args) => (cmd === 'git' && args[0] === 'diff' ? { status: 1 } : { status: 0 }));
  const r = bundleMatchesSource({ run });
  assert.equal(r.ok, false);
  assert.equal(r.restored, true);
  assert.match(r.reason, /STALE/);
  assert.ok(run.calls.some((c) => c === 'git checkout -- dist/agentic-security.mjs dist/agentic-security.mjs.sha256'), 'a failing run leaves the working tree as it found it');
});

test('a failed build is a failure, never a pass, and nothing is compared', () => {
  const run = runner((cmd, args) => (cmd === 'npm' ? { status: 2 } : { status: 0 }));
  const r = bundleMatchesSource({ run });
  assert.equal(r.ok, false);
  assert.match(r.reason, /build failed/);
  assert.ok(!run.calls.some((c) => c.startsWith('git diff')));
});

test('git unable to compare (exit other than 0 or 1) is not "equal"', () => {
  const run = runner((cmd, args) => (cmd === 'git' && args[0] === 'diff' ? { status: 128 } : { status: 0 }));
  const r = bundleMatchesSource({ run });
  assert.equal(r.ok, false);
  assert.match(r.reason, /could not compare/);
});

test('a restore that fails is reported, not hidden', () => {
  const run = runner((cmd, args) => (cmd === 'git' && args[0] === 'diff' ? { status: 1 } : cmd === 'git' && args[0] === 'checkout' ? { status: 1 } : { status: 0 }));
  const r = bundleMatchesSource({ run });
  assert.equal(r.ok, false);
  assert.equal(r.restored, false);
});
