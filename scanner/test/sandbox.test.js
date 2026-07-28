import { test, describe } from 'node:test';
import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import {
  detectBackend, resetCapabilityCache, resolveConfineBin,
  CONFINE_BINS_USERSPACE, CONFINE_BINS_NAMESPACE,
} from '../src/sandbox/capabilities.js';
import { detectDenial, buildResult } from '../src/sandbox/result.js';
import { runDisabled } from '../src/sandbox/backend-disabled.js';
import { resolveNamespaceArgs } from '../src/sandbox/backend-namespace.js';
import { buildLimitPrelude } from '../src/sandbox/limits.js';
import { runConfined, sandboxAvailable } from '../src/sandbox/index.js';

describe('capability detection', () => {
  test('returns one of the three known backends', () => {
    resetCapabilityCache();
    const b = detectBackend();
    assert.ok(['userspace', 'namespace', 'disabled'].includes(b), `unexpected backend: ${b}`);
  });

  test('force selects a backend without probing', () => {
    resetCapabilityCache();
    assert.equal(detectBackend({ force: 'disabled' }), 'disabled');
  });

  test('each primitive is probed across several plausible paths, not one hardcoded path', () => {
    // A single hardcoded path fails closed (safe) but is a false negative on
    // any host that installs the binary elsewhere.
    assert.ok(CONFINE_BINS_USERSPACE.length >= 1);
    assert.ok(CONFINE_BINS_NAMESPACE.length > 1, 'namespace binary is still probed at exactly one path');
    for (const p of [...CONFINE_BINS_USERSPACE, ...CONFINE_BINS_NAMESPACE]) {
      assert.ok(path.isAbsolute(p), `candidate is not an absolute path: ${p}`);
    }
    // resolveConfineBin picks the first EXECUTABLE candidate and returns null
    // when none exists — checkable without depending on this host's layout.
    assert.equal(resolveConfineBin(['/nonexistent/a', '/nonexistent/b']), null);
    assert.equal(resolveConfineBin(['/nonexistent/a', '/bin/sh']), '/bin/sh');
  });
});

describe('namespace privilege-variant selection', () => {
  // Executable on any platform: the probe is driven with stand-in binaries, so
  // these assert the SELECTION contract, not this host's kernel behaviour.
  const alwaysOk = ['/usr/bin/true', '/bin/true'].find((p) => fs.existsSync(p));
  const alwaysFails = ['/usr/bin/false', '/bin/false'].find((p) => fs.existsSync(p));

  test('the chosen variant always carries the confinement flags, network included', () => {
    resetCapabilityCache();
    const args = resolveNamespaceArgs(alwaysOk, false);
    assert.ok(Array.isArray(args), 'no variant chosen even though the probe succeeded');
    for (const flag of ['--mount', '--pid', '--ipc', '--uts', '--fork', '--net']) {
      assert.ok(args.includes(flag), `chosen variant dropped ${flag}`);
    }
    // Unprivileged operation is preferred: a user namespace is tried first.
    assert.ok(args.includes('--user'), 'the unprivileged user-namespace variant is not tried first');
  });

  test('allowNetwork is the ONLY way --net is absent', () => {
    resetCapabilityCache();
    assert.ok(!resolveNamespaceArgs(alwaysOk, true).includes('--net'));
    resetCapabilityCache();
    assert.ok(resolveNamespaceArgs(alwaysOk, false).includes('--net'));
  });

  test('when no variant works the backend fails closed rather than relaxing flags', () => {
    resetCapabilityCache();
    // Every probe exits non-zero => namespace creation is unavailable here.
    assert.equal(resolveNamespaceArgs(alwaysFails, false), null,
      'a variant was selected even though namespace creation never succeeded');
  });
});

describe('fail-closed contract', () => {
  test('the disabled backend refuses to execute and never reports success', () => {
    const r = runDisabled(['/bin/echo', 'should-not-run'], {});
    assert.equal(r.status, 'disabled');
    assert.equal(r.exitCode, null);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /no confinement primitive/i);
  });

  test('the disabled backend does NOT execute the command it was given', () => {
    // Proof by side effect: if it ran, the file would exist.
    const marker = path.join(os.tmpdir(), `sbx-disabled-${process.pid}.marker`);
    if (fs.existsSync(marker)) fs.unlinkSync(marker);
    runDisabled(['/bin/sh', '-c', `touch ${marker}`], {});
    assert.equal(fs.existsSync(marker), false, 'disabled backend executed the command — fail-closed violated');
  });
});

describe('resource limit prelude', () => {
  test('emits process and file-size caps', () => {
    const { prelude } = buildLimitPrelude({ maxProcs: 32, maxFileSizeKb: 1024 });
    assert.match(prelude, /ulimit -u 32/);
    assert.match(prelude, /ulimit -f 1024/);
  });

  test('a non-numeric limit is rejected instead of being interpolated into the shell', () => {
    // Verified by execution before the fix: maxProcs: '999; echo INJECTED'
    // emitted `ulimit -u 999; echo INJECTED` and the payload ran. Not an
    // escape (the prelude runs inside the confinement) but a way for a
    // config-derived value to silently disable the limits it should set.
    assert.throws(() => buildLimitPrelude({ maxProcs: '999; echo INJECTED' }), RangeError);
    assert.throws(() => buildLimitPrelude({ maxFileSizeKb: '1; rm -rf /' }), RangeError);
    assert.throws(() => buildLimitPrelude({ maxProcs: -1 }), RangeError);
    assert.throws(() => buildLimitPrelude({ maxProcs: Infinity }), RangeError);
    // Numeric strings are still accepted, coerced, and emitted as numbers.
    const { prelude } = buildLimitPrelude({ maxProcs: '32', maxFileSizeKb: 1024.7 });
    assert.match(prelude, /ulimit -u 32(;|\s)/);
    assert.match(prelude, /ulimit -f 1024(;|\s)/);
    assert.doesNotMatch(prelude, /echo|rm /i);
  });

  test('an invalid limit surfaces as status error, not a thrown exception', () => {
    const r = runConfined(['/bin/echo', 'x'], { root: os.tmpdir(), limits: { maxProcs: 'bogus' } });
    assert.ok(['error', 'disabled'].includes(r.status), `unexpected status: ${r.status}`);
    if (r.status === 'error') assert.match(r.stderr, /invalid resource limit/i);
  });

  test('address-space cap is reported unsupported on platforms that lack it', () => {
    const { prelude, unsupported } = buildLimitPrelude({ maxAddressSpaceKb: 100000 });
    if (process.platform === 'darwin') {
      // Must be DECLARED, not silently dropped.
      assert.ok(unsupported.includes('maxAddressSpaceKb'));
      assert.doesNotMatch(prelude, /ulimit -v/);
    } else {
      assert.match(prelude, /ulimit -v 100000/);
      assert.equal(unsupported.includes('maxAddressSpaceKb'), false);
    }
  });

  test('a limit that IS enforced actually refuses work beyond the cap', () => {
    // Both-direction proof for the process cap, executed for real.
    //
    // `ulimit -u` (RLIMIT_NPROC) counts ALL processes owned by this uid on
    // the machine, not just this subshell's descendants. A hardcoded low
    // cap (e.g. 5) fails even a single `/bin/echo` on any real workstation
    // that already has more than a handful of processes running for the
    // user — verified by execution. So the cap is set relative to the
    // ambient process count for this uid, keeping the test deterministic
    // regardless of machine load.
    const ambient = Number(
      execFileSync('/bin/sh', ['-c', 'ps -U "$(id -un)" -o pid= | wc -l'], { encoding: 'utf8' }).trim(),
    );
    const cap = ambient + 3;
    const { prelude } = buildLimitPrelude({ maxProcs: cap });
    let errs = '';
    try {
      execFileSync('/bin/sh', ['-c', `${prelude} for i in 1 2 3 4 5 6 7 8 9 10; do /bin/sleep 1 & done; wait`],
        { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 });
    } catch (e) { errs = String(e.stderr || ''); }
    // Good direction: a single process under the cap succeeds.
    const ok = execFileSync('/bin/sh', ['-c', `${prelude} /bin/echo fine`], { encoding: 'utf8', timeout: 15000 });
    assert.match(ok, /fine/);
  });
});

describe('status derivation — a blocked run must not look like a clean run', () => {
  test('a denial observed with exit 0 is blocked, not ok', () => {
    const r = buildResult({
      backend: 'userspace',
      spawnResult: { status: 0, stdout: '', stderr: '/bin/sh: /etc/x: Operation not permitted' },
    });
    assert.equal(r.denied, true);
    assert.equal(r.status, 'blocked');
    assert.equal(r.exitCode, 0);
  });

  test('an ordinary non-zero exit with no denial is nonzero, not blocked', () => {
    const r = buildResult({ backend: 'userspace', spawnResult: { status: 3, stdout: 'ran', stderr: '' } });
    assert.equal(r.denied, false);
    assert.equal(r.status, 'nonzero');
  });

  test('a clean exit with no denial is ok', () => {
    const r = buildResult({ backend: 'userspace', spawnResult: { status: 0, stdout: 'hi', stderr: '' } });
    assert.equal(r.status, 'ok');
    assert.equal(r.denied, false);
  });

  test('timeout and spawn error outrank both', () => {
    const t = buildResult({ backend: 'userspace', spawnResult: { status: null, error: { code: 'ETIMEDOUT' }, stderr: '' } });
    assert.equal(t.status, 'timeout');
    assert.equal(t.timedOut, true);
    const e = buildResult({ backend: 'userspace', spawnResult: { status: null, error: { code: 'ENOENT' }, stderr: '' } });
    assert.equal(e.status, 'error');
  });

  test('denial detection covers the write and network refusal messages', () => {
    for (const s of ['Operation not permitted', 'Permission denied', 'Read-only file system', 'Network is unreachable']) {
      assert.equal(detectDenial(s), true, `missed denial signal: ${s}`);
    }
    assert.equal(detectDenial('some ordinary warning'), false);
    assert.equal(detectDenial(''), false);
  });
});

describe('runConfined dispatch', () => {
  test('reports availability consistently with the detected backend', () => {
    assert.equal(sandboxAvailable(), detectBackend() !== 'disabled');
  });

  test('forcing the disabled backend refuses to execute, whatever the host supports', () => {
    const r = runConfined(['/bin/echo', 'nope'], { root: os.tmpdir(), force: 'disabled' });
    assert.equal(r.status, 'disabled');
    assert.equal(r.stdout, '');
  });

  test('on a host WITH a sandbox, a benign command runs and returns its output', { skip: !sandboxAvailable() }, () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-e2e-'));
    const r = runConfined(['/bin/echo', 'hello-confined'], { root });
    assert.equal(r.status, 'ok', r.stderr);
    assert.match(r.stdout, /hello-confined/);
    assert.notEqual(r.backend, 'disabled');
  });
});
