// scanner/test/sandbox-escape.test.js
import { test, describe } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectBackend } from '../src/sandbox/capabilities.js';
import { runUserspace } from '../src/sandbox/backend-userspace.js';

const ACTIVE = detectBackend();
const skip = ACTIVE !== 'userspace'
  ? `skipped: active backend is '${ACTIVE}', not 'userspace' — cannot verify on this host`
  : false;

describe('userspace confinement — escape attempts', { skip }, () => {
  let root, outside;
  test('setup', () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-root-'));
    outside = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-out-'));
  });

  test('GOOD: a write inside the sandbox root succeeds', () => {
    const r = runUserspace(['/bin/sh', '-c', 'echo ok > $ROOT/a.txt && cat $ROOT/a.txt'], { root });
    assert.equal(r.status, 'ok', r.stderr);
    assert.match(r.stdout, /ok/);
  });

  test('BAD: a write outside the sandbox root is blocked and creates no file', () => {
    const target = path.join(outside, 'escape.txt');
    const r = runUserspace(['/bin/sh', '-c', `echo bad > ${target}`], { root });
    assert.notEqual(r.exitCode, 0, 'write outside root unexpectedly succeeded');
    assert.equal(fs.existsSync(target), false, 'ESCAPED: file was created outside the sandbox root');
  });

  test('BAD: outbound network is blocked', () => {
    const r = runUserspace(['/usr/bin/nc', '-z', '-w', '3', '1.1.1.1', '443'], { root, timeoutMs: 15000 });
    assert.notEqual(r.exitCode, 0, 'outbound connection unexpectedly succeeded inside the sandbox');
  });

  test('BAD: a wall-clock overrun is terminated', () => {
    const r = runUserspace(['/bin/sh', '-c', 'sleep 30'], { root, timeoutMs: 1500 });
    assert.equal(r.timedOut, true);
    assert.equal(r.status, 'timeout');
  });

  test('BAD (weak): a fork storm is contained only relative to ambient load, not absolutely', () => {
    // `ulimit -u` (RLIMIT_NPROC) is a per-uid, SYSTEM-WIDE cap on this
    // platform, not a per-process-tree cap (verified by execution in
    // Task 2). A hardcoded low cap (e.g. 5) fails deterministically before
    // the storm even starts, because the user's ambient process count on
    // any real workstation already exceeds it — even `/bin/sh` itself
    // cannot fork. That is not "the storm was contained," it's "nothing
    // could run," which would be a contrived pass. So this test sets the
    // cap relative to the ambient count for this uid (the same workaround
    // Task 2 used), the way an honest deployment would have to.
    //
    // The uncomfortable conclusion this proves: because the cap must stay
    // above ambient load to avoid starving the user's own processes,
    // fork-storm containment on this platform is WEAK. It bounds a storm to
    // "ambient + headroom" extra processes, not to some small absolute
    // number — a real fork bomb launched inside the sandbox can still
    // consume a meaningful number of system-wide process slots before the
    // cap bites. This test asserts that weaker, but real, guarantee: the
    // storm is cut off before completing all 60 forks, it does not run
    // away unbounded.
    const ambient = Number(
      execFileSync('/bin/sh', ['-c', 'ps -U "$(id -un)" -o pid= | wc -l'], { encoding: 'utf8' }).trim(),
    );
    const cap = ambient + 3;
    const r = runUserspace(
      ['/bin/sh', '-c', 'n=0; while [ $n -lt 60 ]; do /bin/sleep 1 & n=$((n+1)); done; wait'],
      { root, timeoutMs: 20000, limits: { maxProcs: cap } });
    // Contained relative to ambient load: the shell reported fork failures
    // once the cap (ambient + 3) was hit, or the run was killed on time.
    // It is NOT asserted that the storm failed to start at all — with a
    // cap this close to ambient, a few forks legitimately succeed first.
    assert.ok(r.timedOut || /fork|resource/i.test(r.stderr),
      'fork storm ran to completion uncontained');

    // Good direction, same cap: an ordinary single process still succeeds —
    // proving the cap is a real containment mechanism, not just a broken
    // shell that can no longer fork at all.
    const ok = runUserspace(['/bin/sh', '-c', 'echo fine'], { root, limits: { maxProcs: cap } });
    assert.equal(ok.status, 'ok', ok.stderr);
    assert.match(ok.stdout, /fine/);
  });
});
