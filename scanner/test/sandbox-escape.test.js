// scanner/test/sandbox-escape.test.js
import { test, describe } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectBackend } from '../src/sandbox/capabilities.js';
import { runUserspace } from '../src/sandbox/backend-userspace.js';
import { runNamespace } from '../src/sandbox/backend-namespace.js';
import { runDisabled } from '../src/sandbox/backend-disabled.js';

// A skip here is NOT a pass. Detection is functional (capabilities.js): the
// backend is reported only when it just ran a trivial command under real
// confinement, so `disabled` means confinement is genuinely unavailable on this
// host — not that the check was lenient. Nothing below is verified when these
// skip, and no assertion is relaxed to keep the suite green: the escape
// contract is asserted where confinement works, and declared unverified where
// it does not.
const ACTIVE = detectBackend();
const skip = ACTIVE !== 'userspace'
  ? `SKIPPED, NOT PASSED: userspace confinement is unavailable on this host `
    + `(functional probe selected backend '${ACTIVE}'); the userspace escape contract is UNVERIFIED here`
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
    assert.equal(r.denied, true, 'denial was not observed');
    assert.equal(r.status, 'blocked');
    assert.equal(fs.existsSync(target), false, 'ESCAPED: file was created outside the sandbox root');
  });

  test('BAD: a DENIED write is not reported as a clean run even when the command exits 0', () => {
    // The regression this locks down: status used to come purely from the exit
    // code, so a command whose out-of-root write was refused but which still
    // exited 0 was reported status:'ok', exitCode:0 — indistinguishable from a
    // run where nothing was refused at all. That is exactly the misread a
    // downstream execution-verification tier must not make.
    const target = path.join(outside, 'escape-exit0.txt');
    const r = runUserspace(['/bin/sh', '-c', `echo bad > ${target}; exit 0`], { root });
    assert.equal(r.exitCode, 0, 'precondition: the command must exit 0 for this test to mean anything');
    assert.equal(fs.existsSync(target), false, 'ESCAPED: file was created outside the sandbox root');
    assert.equal(r.denied, true, 'the denial was invisible to the caller');
    assert.notEqual(r.status, 'ok', 'a denied run was reported as a clean run');
    assert.equal(r.status, 'blocked');
  });

  test('GOOD: an ordinary non-zero exit is "nonzero", never "blocked"', () => {
    // Converse of the above: a program that ran fine and chose to exit 3 is a
    // program failure, not a confinement event.
    const r = runUserspace(['/bin/sh', '-c', 'exit 3'], { root });
    assert.equal(r.exitCode, 3);
    assert.equal(r.denied, false);
    assert.equal(r.status, 'nonzero', 'ordinary failure mislabelled as a confinement block');
  });

  test('BAD: the parent environment is not handed to the confined command', () => {
    // Env-borne credentials are a distinct exposure from the accepted
    // "reads are not confined" scope cut — the sandbox would be handing them
    // over, not merely failing to hide them.
    process.env.SBX_PARENT_SECRET = 'leaked-value-should-not-appear';
    try {
      const r = runUserspace(['/bin/sh', '-c', 'echo "[${SBX_PARENT_SECRET}]"'], { root });
      assert.equal(r.status, 'ok', r.stderr);
      assert.doesNotMatch(r.stdout, /leaked-value-should-not-appear/,
        'LEAKED: a parent environment variable reached the confined command');
      // Opt-in still works, one variable at a time.
      const r2 = runUserspace(['/bin/sh', '-c', 'echo "[$EXPLICIT]"'], { root, env: { EXPLICIT: 'passed-in' } });
      assert.match(r2.stdout, /passed-in/);
    } finally {
      delete process.env.SBX_PARENT_SECRET;
    }
  });

  test('BAD: outbound network is blocked', () => {
    const r = runUserspace(['/usr/bin/nc', '-z', '-w', '3', '1.1.1.1', '443'], { root, timeoutMs: 15000 });
    assert.notEqual(r.exitCode, 0, 'outbound connection unexpectedly succeeded inside the sandbox');
  });

  test('BAD: a wall-clock overrun stops the direct child', () => {
    const r = runUserspace(['/bin/sh', '-c', 'sleep 30'], { root, timeoutMs: 1500 });
    assert.equal(r.timedOut, true);
    assert.equal(r.status, 'timeout');
  });

  test('KNOWN GAP: the timeout does not kill the process tree on this platform', () => {
    // This asserts a LIMITATION, on purpose. The wall-clock timeout is
    // spawnSync's, which signals only the direct child, so a backgrounded
    // grandchild outlives the 'timeout' result. The module guide says exactly
    // this; the test exists so the claim stays true by execution rather than
    // by memory. If a future change really does kill the tree, this test will
    // fail — and the guide's "Timeout does not kill the process tree" section
    // must be corrected in the same commit.
    const marker = path.join(root, 'survivor.marker');
    if (fs.existsSync(marker)) fs.unlinkSync(marker);
    const r = runUserspace(
      ['/bin/sh', '-c', '( /bin/sleep 3; /usr/bin/touch "$ROOT/survivor.marker" ) & sleep 30'],
      { root, timeoutMs: 1200 });
    assert.equal(r.status, 'timeout');
    assert.equal(fs.existsSync(marker), false, 'precondition: nothing should have been written yet');
    // Wait past the survivor's own sleep, then look again.
    execFileSync('/bin/sleep', ['4']);
    assert.equal(fs.existsSync(marker), true,
      'the backgrounded child did NOT survive — tree termination now works; update the guide');
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

const nsSkip = detectBackend() !== 'namespace'
  ? 'SKIPPED, NOT PASSED: kernel-namespace confinement is unavailable on this host — either the tool is '
    + 'absent, or it is present but the host refuses the namespaces (functional probe failed, so the '
    + 'backend reports unavailable and execution features are disabled rather than degraded). '
    + 'Implemented but UNVERIFIED here.'
  : false;

// These skip on a non-Linux host — that is expected, and it is also why none
// of the namespace claims may be stated as verified. They exist so that the
// FIRST run on a Linux host asserts the same both-direction contract the
// userspace backend already meets, rather than discovering the gap later.
describe('kernel-namespace confinement — escape attempts', { skip: nsSkip }, () => {
  test('GOOD: a write inside the sandbox root succeeds', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-ns-'));
    const r = runNamespace(['/bin/sh', '-c', 'echo ok > "$ROOT/a.txt" && cat "$ROOT/a.txt"'], { root });
    assert.equal(r.status, 'ok', r.stderr);
    assert.match(r.stdout, /ok/);
  });

  test('KNOWN GAP: a write outside the sandbox root is NOT confined by this backend', () => {
    // Asserts the documented reality, not a wish. This backend has no
    // remount/bind/pivot_root — only a `cd` — so an absolute out-of-root write
    // succeeds. The guide says so; this test makes the claim executable on the
    // first Linux host that runs it. If write confinement is later
    // implemented, this test WILL fail, and the guide's namespace section must
    // be rewritten in the same commit.
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-ns-'));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-ns-out-'));
    const target = path.join(outside, 'escape.txt');
    runNamespace(['/bin/sh', '-c', `echo bad > ${target}`], { root });
    assert.equal(fs.existsSync(target), true,
      'write confinement now appears to work — verify it properly and update the guide');
  });

  test('BAD: outbound network is blocked by the empty network namespace', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-ns-'));
    const r = runNamespace(['/bin/sh', '-c', 'exec 3<>/dev/tcp/1.1.1.1/443'], { root, timeoutMs: 15000 });
    assert.notEqual(r.exitCode, 0, 'outbound connection unexpectedly succeeded inside the sandbox');
  });

  test('BAD: a wall-clock overrun stops the direct child', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-ns-'));
    const r = runNamespace(['/bin/sh', '-c', 'sleep 30'], { root, timeoutMs: 1500 });
    assert.equal(r.timedOut, true);
    assert.equal(r.status, 'timeout');
  });
});

test('the namespace backend returns the same result shape as every other backend', () => {
  // Asserted against a REAL returned object, not just the function's type and
  // arity — the old version passed even if the backend returned nothing. A
  // missing root returns the documented error shape without executing
  // anything, so this is checkable on any host.
  const r = runNamespace(['/bin/echo', 'never-runs'], {});
  const expected = ['status', 'denied', 'stdout', 'stderr', 'exitCode', 'timedOut', 'backend'];
  assert.deepEqual(Object.keys(r).sort(), [...expected].sort());
  assert.equal(r.status, 'error', 'a missing root must not throw — it must return the documented shape');
  assert.equal(r.backend, 'namespace');
  assert.equal(r.exitCode, null);
  assert.equal(r.denied, false);
  // Same key set as the disabled backend, which every host can execute.
  assert.deepEqual(Object.keys(runDisabled(['/bin/echo'], {})).sort(), [...expected].sort());
});

test('a missing sandbox root returns status error rather than throwing', () => {
  // A caller that has to try/catch is a caller that might catch and "fall
  // back" to running the command unconfined.
  for (const [name, fn] of [['userspace', runUserspace], ['namespace', runNamespace]]) {
    const r = fn(['/bin/echo', 'never-runs'], {});
    assert.equal(r.status, 'error', `${name} backend did not return the documented error shape`);
    assert.equal(r.backend, name);
    assert.match(r.stderr, /sandbox root/i);
  }
});
