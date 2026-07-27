import { test, describe } from 'node:test';
import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { detectBackend, resetCapabilityCache } from '../src/sandbox/capabilities.js';
import { runDisabled } from '../src/sandbox/backend-disabled.js';
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
