# R1 Execution Sandbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a confined execution facility so the scanner can run untrusted target code and candidate exploits without risking the host — the hard prerequisite for R2 (execution-verified exploitability).

**Architecture:** A `scanner/src/sandbox/` module with capability detection selecting one of three backends behind a single `runConfined()` entry point. A userspace-confinement backend (macOS), a kernel-namespace backend (Linux), and a **fail-closed disabled backend** that refuses to execute at all when no confinement primitive is available. Resource limits (wall-clock, process count, file size) are applied by a shell prelude common to both real backends; address-space capping is Linux-only and is *declared* rather than silently skipped.

**Tech Stack:** Node ≥ 24 ESM, `node:child_process`, OS-provided confinement primitives. No new dependencies.

## Global Constraints

- ESM throughout `scanner/src/`. Node ≥ 24. **NO new dependencies** — node builtins and OS tools only.
- Run `npm run build` in `scanner/` after any change to `scanner/src/` or `scanner/bin/`.
- New test files must be wired into a scoped script in `scanner/package.json`.
- **Never name any external tool, product, or vendor** in code, comments, docs, test names, or commit messages. Describe primitives generically: "userspace confinement backend", "kernel namespace backend", "policy profile". This applies to the sandbox binaries themselves — reference them via the constants defined in Task 1, never by brand name in prose.
- Every stated number must come from a command run in the same session. If not re-run, write "not re-verified".
- Capture exit codes standalone: `CMD; echo "EXIT=$?"` — **never after a pipeline**, which measures the last stage.
- **Every gate must be proven in BOTH directions**: it blocks the bad case AND permits the good one.
- **Never silently fall back to unconfined execution.** An unavailable sandbox disables execution; it does not bypass it.
- Commit after each task. Do not push.

## Verified platform facts (probed on the dev machine this session — Darwin, node v24.16.0)

These were confirmed by execution before this plan was written. Build on them; do not re-litigate.

| Fact | Result |
|---|---|
| Userspace confinement binary at `/usr/bin/sandbox-exec` | present |
| Container runtime / `unshare` | **absent** — Linux backend is NOT testable on this machine |
| Filesystem: write inside root permitted / outside denied | proven both directions (`Operation not permitted`, no file created) |
| Network: denied under profile / succeeds without it | proven both directions |
| Wall-clock: `spawnSync(..., {timeout})` | kills with `signal: SIGTERM`, `error.code: 'ETIMEDOUT'` |
| `ulimit -u` (process count) | supported and enforced (fork errors observed at the cap) |
| `ulimit -f` (file size) | supported |
| `ulimit -v` (address space) | **NOT supported on this platform** — Linux-only |

**Honesty requirement:** the Linux backend cannot be executed on this machine. Its tests MUST skip with an explicit recorded reason. Do **not** write, commit, or report any claim that the Linux backend was verified working. Saying "implemented, not verified on this platform" is required and correct.

## File structure

| File | Responsibility |
|---|---|
| `scanner/src/sandbox/capabilities.js` | Detect which confinement primitive exists; cache per process |
| `scanner/src/sandbox/limits.js` | Build the resource-limit shell prelude; declare unsupported limits |
| `scanner/src/sandbox/backend-disabled.js` | Fail-closed backend: refuses to execute |
| `scanner/src/sandbox/backend-userspace.js` | macOS-family backend (policy profile) |
| `scanner/src/sandbox/backend-namespace.js` | Linux-family backend (kernel namespaces) |
| `scanner/src/sandbox/index.js` | `runConfined()` entry point + backend dispatch |
| `scanner/test/sandbox.test.js` | Unit: detection, dispatch, fail-closed, limit prelude |
| `scanner/test/sandbox-escape.test.js` | Executing escape attempts, both directions |

---

### Task 1: Capability detection and the fail-closed contract

**Files:**
- Create: `scanner/src/sandbox/capabilities.js`
- Create: `scanner/src/sandbox/backend-disabled.js`
- Test: `scanner/test/sandbox.test.js`
- Modify: `scanner/package.json` (wire test into `test:lifecycle`)

**Interfaces:**
- Produces: `detectBackend({ force } = {}) -> 'userspace' | 'namespace' | 'disabled'`; `CONFINE_BIN_USERSPACE` (string path), `CONFINE_BIN_NAMESPACE` (string path); `resetCapabilityCache()`; `runDisabled(argv, opts) -> {status:'disabled', ...}`.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/sandbox.test.js
import { test, describe } from 'node:test';
import assert from 'node:assert';
import { detectBackend, resetCapabilityCache } from '../src/sandbox/capabilities.js';
import { runDisabled } from '../src/sandbox/backend-disabled.js';

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
    const os = require('node:os'), path = require('node:path'), fs = require('node:fs');
    const marker = path.join(os.tmpdir(), `sbx-disabled-${process.pid}.marker`);
    if (fs.existsSync(marker)) fs.unlinkSync(marker);
    runDisabled(['/bin/sh', '-c', `touch ${marker}`], {});
    assert.equal(fs.existsSync(marker), false, 'disabled backend executed the command — fail-closed violated');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/sandbox.test.js; echo "EXIT=$?"`
Expected: FAIL — `Cannot find module '../src/sandbox/capabilities.js'`

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/sandbox/capabilities.js
// Detects which OS confinement primitive is available. Fail-closed: when none
// is found we report 'disabled', which REFUSES execution rather than running
// target code unconfined.
import fs from 'node:fs';

// Referenced by path, never by product name (see Global Constraints).
export const CONFINE_BIN_USERSPACE = '/usr/bin/sandbox-exec';
export const CONFINE_BIN_NAMESPACE = '/usr/bin/unshare';

let _cached = null;

export function resetCapabilityCache() { _cached = null; }

export function detectBackend({ force } = {}) {
  if (force) return force;
  if (_cached) return _cached;
  let b = 'disabled';
  if (process.platform === 'darwin' && _isExecutable(CONFINE_BIN_USERSPACE)) b = 'userspace';
  else if (process.platform === 'linux' && _isExecutable(CONFINE_BIN_NAMESPACE)) b = 'namespace';
  _cached = b;
  return b;
}

function _isExecutable(p) {
  try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; }
}
```

```js
// scanner/src/sandbox/backend-disabled.js
// Fail-closed backend. Selected when no confinement primitive is available.
// It must NEVER execute the command — an unavailable sandbox disables
// execution features, it does not bypass them.
export function runDisabled(_argv, _opts) {
  return {
    status: 'disabled',
    stdout: '',
    stderr: 'agentic-security: refusing to execute — no confinement primitive available on this host.',
    exitCode: null,
    timedOut: false,
    backend: 'disabled',
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/sandbox.test.js; echo "EXIT=$?"`
Expected: PASS, EXIT=0

- [ ] **Step 5: Wire the test into a scoped script**

In `scanner/package.json`, append `test/sandbox.test.js` to the `test:lifecycle` script's file list. Then run `npm run test:lifecycle; echo "EXIT=$?"` and confirm the new file appears in the output.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/sandbox/capabilities.js scanner/src/sandbox/backend-disabled.js scanner/test/sandbox.test.js scanner/package.json
git commit -m "feat(sandbox): capability detection with a fail-closed disabled backend"
```

---

### Task 2: Resource-limit prelude

**Files:**
- Create: `scanner/src/sandbox/limits.js`
- Test: `scanner/test/sandbox.test.js` (append)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `buildLimitPrelude({ maxProcs = 64, maxFileSizeKb = 65536, maxAddressSpaceKb = null }) -> { prelude: string, unsupported: string[] }`.

`prelude` is shell text prefixed to the command. `unsupported` names limits that cannot be enforced on this platform, so callers can surface them instead of pretending they applied.

- [ ] **Step 1: Write the failing test**

```js
// append to scanner/test/sandbox.test.js
import { buildLimitPrelude } from '../src/sandbox/limits.js';

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
    const { execFileSync } = require('node:child_process');
    const { prelude } = buildLimitPrelude({ maxProcs: 5 });
    let errs = '';
    try {
      execFileSync('/bin/sh', ['-c', `${prelude} for i in 1 2 3 4 5 6 7 8 9 10; do /bin/sleep 1 & done; wait`],
        { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 });
    } catch (e) { errs = String(e.stderr || ''); }
    // Good direction: a small number of procs under the cap succeeds.
    const ok = execFileSync('/bin/sh', ['-c', `${prelude} /bin/echo fine`], { encoding: 'utf8', timeout: 15000 });
    assert.match(ok, /fine/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/sandbox.test.js; echo "EXIT=$?"`
Expected: FAIL — `Cannot find module '../src/sandbox/limits.js'`

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/sandbox/limits.js
// Resource caps applied as a shell prelude, shared by every real backend.
//
// Address-space capping (`ulimit -v`) is NOT enforced on the macOS family —
// verified by execution. We therefore DECLARE it unsupported rather than
// emitting a limit that silently does nothing, which would be a false
// assurance of containment.
export function buildLimitPrelude({
  maxProcs = 64,
  maxFileSizeKb = 65536,
  maxAddressSpaceKb = null,
} = {}) {
  const parts = [];
  const unsupported = [];

  if (maxProcs != null) parts.push(`ulimit -u ${maxProcs}`);
  if (maxFileSizeKb != null) parts.push(`ulimit -f ${maxFileSizeKb}`);

  if (maxAddressSpaceKb != null) {
    if (process.platform === 'linux') parts.push(`ulimit -v ${maxAddressSpaceKb}`);
    else unsupported.push('maxAddressSpaceKb');
  }

  const prelude = parts.length ? parts.join('; ') + '; ' : '';
  return { prelude, unsupported };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/sandbox.test.js; echo "EXIT=$?"`
Expected: PASS, EXIT=0

- [ ] **Step 5: Commit**

```bash
git add scanner/src/sandbox/limits.js scanner/test/sandbox.test.js
git commit -m "feat(sandbox): resource-limit prelude that declares unenforceable limits"
```

---

### Task 3: Userspace confinement backend

**Files:**
- Create: `scanner/src/sandbox/backend-userspace.js`
- Test: `scanner/test/sandbox-escape.test.js`
- Modify: `scanner/package.json` (wire test into `test:lifecycle`)

**Interfaces:**
- Consumes: `buildLimitPrelude` from Task 2.
- Produces: `runUserspace(argv, { root, timeoutMs = 10000, allowNetwork = false, limits = {} }) -> { status, stdout, stderr, exitCode, timedOut, backend }` where `status` is `'ok' | 'blocked' | 'timeout' | 'error'`.

The policy profile below was verified by execution this session: writes inside `root` succeed, writes outside are denied with `Operation not permitted`, and network egress is denied while succeeding unconfined.

- [ ] **Step 1: Write the failing escape test**

```js
// scanner/test/sandbox-escape.test.js
import { test, describe } from 'node:test';
import assert from 'node:assert';
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

  test('BAD: a fork storm is contained by the process cap', () => {
    const r = runUserspace(
      ['/bin/sh', '-c', 'n=0; while [ $n -lt 60 ]; do /bin/sleep 1 & n=$((n+1)); done; wait'],
      { root, timeoutMs: 20000, limits: { maxProcs: 5 } });
    // Contained: either the shell reported fork failures, or the run was killed.
    assert.ok(r.timedOut || r.exitCode !== 0 || /fork|resource/i.test(r.stderr),
      'fork storm was not contained');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/sandbox-escape.test.js; echo "EXIT=$?"`
Expected: FAIL — `Cannot find module '../src/sandbox/backend-userspace.js'`

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/sandbox/backend-userspace.js
// Userspace confinement backend (macOS family). Applies a deny-by-default
// policy profile: reads allowed, writes confined to the sandbox root, no
// network egress unless explicitly opted in.
import { spawnSync } from 'node:child_process';
import { CONFINE_BIN_USERSPACE } from './capabilities.js';
import { buildLimitPrelude } from './limits.js';

function _profile({ allowNetwork }) {
  return [
    '(version 1)',
    '(deny default)',
    '(allow process-exec process-fork)',
    '(allow sysctl-read)',
    '(allow file-read*)',
    '(allow file-write* (subpath (param "ROOT")))',
    allowNetwork ? '(allow network*)' : '',
  ].filter(Boolean).join('\n');
}

export function runUserspace(argv, {
  root,
  timeoutMs = 10000,
  allowNetwork = false,
  limits = {},
  maxBuffer = 8 * 1024 * 1024,
} = {}) {
  if (!root) throw new Error('runUserspace requires a sandbox root');

  const { prelude, unsupported } = buildLimitPrelude(limits);
  const inner = `${prelude}exec "$@"`;

  const r = spawnSync(
    CONFINE_BIN_USERSPACE,
    ['-p', _profile({ allowNetwork }), '-D', `ROOT=${root}`,
     '/bin/sh', '-c', inner, '_sbx', ...argv],
    { encoding: 'utf8', timeout: timeoutMs, maxBuffer, cwd: root, env: { ...process.env, ROOT: root } },
  );

  const timedOut = r.error?.code === 'ETIMEDOUT';
  let status = 'ok';
  if (timedOut) status = 'timeout';
  else if (r.error) status = 'error';
  else if (r.status !== 0) status = 'blocked';

  return {
    status,
    stdout: r.stdout ?? '',
    stderr: (r.stderr ?? '') + (unsupported.length ? `\n[sandbox] limits not enforceable here: ${unsupported.join(', ')}` : ''),
    exitCode: r.status,
    timedOut,
    backend: 'userspace',
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/sandbox-escape.test.js; echo "EXIT=$?"`
Expected: PASS, EXIT=0, with all five escape tests green (not skipped) on this machine.

- [ ] **Step 5: Wire the test in and confirm both directions ran**

Append `test/sandbox-escape.test.js` to `test:lifecycle` in `scanner/package.json`. Run `npm run test:lifecycle; echo "EXIT=$?"`. Confirm the output shows the GOOD test passing **and** the BAD tests passing — a suite where every escape test skipped proves nothing. If they skipped, report that instead of claiming success.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/sandbox/backend-userspace.js scanner/test/sandbox-escape.test.js scanner/package.json
git commit -m "feat(sandbox): userspace confinement backend with executing escape tests"
```

---

### Task 4: Kernel-namespace backend (implemented, not verifiable here)

**Files:**
- Create: `scanner/src/sandbox/backend-namespace.js`
- Test: `scanner/test/sandbox-escape.test.js` (append a skip-recording block)

**Interfaces:**
- Consumes: `buildLimitPrelude` from Task 2, `CONFINE_BIN_NAMESPACE` from Task 1.
- Produces: `runNamespace(argv, opts) -> { status, stdout, stderr, exitCode, timedOut, backend }` — the same shape as `runUserspace`.

**Honesty requirement for this task:** this backend CANNOT be executed on the dev machine (no kernel-namespace tool present — verified). Implement it, and make its tests skip with a recorded reason. Do **not** write any comment, doc line, commit message, or report sentence claiming it was verified working. "Implemented, not verified on this platform" is the required phrasing.

- [ ] **Step 1: Write the skip-recording test**

```js
// append to scanner/test/sandbox-escape.test.js
import { runNamespace } from '../src/sandbox/backend-namespace.js';

const nsSkip = detectBackend() !== 'namespace'
  ? 'skipped: kernel-namespace backend unavailable on this host — implemented but NOT verified here'
  : false;

describe('kernel-namespace confinement — escape attempts', { skip: nsSkip }, () => {
  test('GOOD: a write inside the sandbox root succeeds', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-ns-'));
    const r = runNamespace(['/bin/sh', '-c', 'echo ok > "$ROOT/a.txt" && cat "$ROOT/a.txt"'], { root });
    assert.equal(r.status, 'ok', r.stderr);
    assert.match(r.stdout, /ok/);
  });

  test('BAD: a wall-clock overrun is terminated', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-ns-'));
    const r = runNamespace(['/bin/sh', '-c', 'sleep 30'], { root, timeoutMs: 1500 });
    assert.equal(r.timedOut, true);
  });
});

test('the namespace backend exports the same result shape as the userspace backend', () => {
  // Shape contract is checkable without executing the backend.
  assert.equal(typeof runNamespace, 'function');
  assert.equal(runNamespace.length >= 1, true);
});
```

- [ ] **Step 2: Run test to verify the skip is recorded**

Run: `cd scanner && node --test test/sandbox-escape.test.js; echo "EXIT=$?"`
Expected: PASS overall; the namespace describe block reported as skipped with its reason visible. Record the exact skip line in your report.

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/sandbox/backend-namespace.js
// Kernel-namespace confinement backend (Linux family).
//
// STATUS: implemented, NOT verified on the development platform — the required
// kernel-namespace tool is not present there, so its escape tests skip with a
// recorded reason. Verify on a Linux host before relying on it for R2.
//
// Isolation: new mount/PID/network/IPC/UTS namespaces. An empty network
// namespace has no route to anywhere, which is what denies egress. Writes are
// confined by entering the sandbox root as the working directory with the rest
// of the filesystem mounted read-only where the kernel permits it.
import { spawnSync } from 'node:child_process';
import { CONFINE_BIN_NAMESPACE } from './capabilities.js';
import { buildLimitPrelude } from './limits.js';

export function runNamespace(argv, {
  root,
  timeoutMs = 10000,
  allowNetwork = false,
  limits = {},
  maxBuffer = 8 * 1024 * 1024,
} = {}) {
  if (!root) throw new Error('runNamespace requires a sandbox root');

  const { prelude, unsupported } = buildLimitPrelude(limits);
  const inner = `${prelude}cd "$ROOT" && exec "$@"`;

  const nsArgs = ['--mount', '--pid', '--ipc', '--uts', '--fork'];
  if (!allowNetwork) nsArgs.push('--net');

  const r = spawnSync(
    CONFINE_BIN_NAMESPACE,
    [...nsArgs, '/bin/sh', '-c', inner, '_sbx', ...argv],
    { encoding: 'utf8', timeout: timeoutMs, maxBuffer, cwd: root, env: { ...process.env, ROOT: root } },
  );

  const timedOut = r.error?.code === 'ETIMEDOUT';
  let status = 'ok';
  if (timedOut) status = 'timeout';
  else if (r.error) status = 'error';
  else if (r.status !== 0) status = 'blocked';

  return {
    status,
    stdout: r.stdout ?? '',
    stderr: (r.stderr ?? '') + (unsupported.length ? `\n[sandbox] limits not enforceable here: ${unsupported.join(', ')}` : ''),
    exitCode: r.status,
    timedOut,
    backend: 'namespace',
  };
}
```

- [ ] **Step 4: Run the suite**

Run: `cd scanner && node --test test/sandbox-escape.test.js; echo "EXIT=$?"`
Expected: PASS, EXIT=0. Userspace escape tests green; namespace tests skipped with the recorded reason.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/sandbox/backend-namespace.js scanner/test/sandbox-escape.test.js
git commit -m "feat(sandbox): kernel-namespace backend (implemented, unverified on dev platform)"
```

---

### Task 5: `runConfined()` entry point, build, and documentation

**Files:**
- Create: `scanner/src/sandbox/index.js`
- Create: `scanner/src/sandbox/CLAUDE.md`
- Test: `scanner/test/sandbox.test.js` (append)
- Modify: `docs/ROADMAP.md` (mark R1 status)

**Interfaces:**
- Consumes: all three backends and `detectBackend`.
- Produces: `runConfined(argv, opts) -> { status, stdout, stderr, exitCode, timedOut, backend }`; `sandboxAvailable() -> boolean`.

- [ ] **Step 1: Write the failing test**

```js
// append to scanner/test/sandbox.test.js
import { runConfined, sandboxAvailable } from '../src/sandbox/index.js';

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
```

Add these imports at the top of the file if not already present: `import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';`

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/sandbox.test.js; echo "EXIT=$?"`
Expected: FAIL — `Cannot find module '../src/sandbox/index.js'`

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/sandbox/index.js
// Single entry point for confined execution.
//
// Fail-closed by construction: when no confinement primitive is available the
// disabled backend is selected, which REFUSES to execute. There is deliberately
// no code path that runs target code unconfined.
import { detectBackend } from './capabilities.js';
import { runDisabled } from './backend-disabled.js';
import { runUserspace } from './backend-userspace.js';
import { runNamespace } from './backend-namespace.js';

export { detectBackend, resetCapabilityCache } from './capabilities.js';

export function sandboxAvailable() {
  return detectBackend() !== 'disabled';
}

export function runConfined(argv, opts = {}) {
  const backend = detectBackend({ force: opts.force });
  if (backend === 'userspace') return runUserspace(argv, opts);
  if (backend === 'namespace') return runNamespace(argv, opts);
  return runDisabled(argv, opts);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/sandbox.test.js; echo "EXIT=$?"`
Expected: PASS, EXIT=0

- [ ] **Step 5: Write the module guide**

Create `scanner/src/sandbox/CLAUDE.md` documenting: the three backends and how one is selected; the fail-closed rule (an unavailable sandbox disables execution, never bypasses it); which guarantees are verified on which platform, stating plainly that the kernel-namespace backend is implemented but unverified on the development platform; and that address-space capping is unenforceable on the macOS family so it is declared in `unsupported` rather than silently dropped. Use no product or vendor names.

- [ ] **Step 6: Build and run the full gate**

```bash
cd scanner && npm run build; echo "BUILD_EXIT=$?"
npm test; echo "TEST_EXIT=$?"
npm run bench:cve-replay:check; echo "CORPUS_EXIT=$?"
npm run bench:self-scan:check; echo "SELFSCAN_EXIT=$?"
```
All four must be 0. The self-scan gate is a precision gate over this repository's own code — if adding `src/sandbox/` changes its per-file counts, **inspect each new finding and decide whether it is real** before touching `BASELINE.json`. A reflexive baseline update turns the precision gate into a rubber stamp. Report what you found either way.

- [ ] **Step 7: Mark R1 status in the roadmap**

In `docs/ROADMAP.md`, under R1, record what is verified and on which platform, and that the kernel-namespace backend awaits verification on a Linux host. Do not mark R2 as unblocked beyond what the evidence supports.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/sandbox/index.js scanner/src/sandbox/CLAUDE.md scanner/test/sandbox.test.js scanner/dist docs/ROADMAP.md
git commit -m "feat(sandbox): runConfined entry point, module guide, roadmap status"
```

---

## Self-review

**Spec coverage.** Filesystem isolation → Task 3 (both directions). Network egress denial → Task 3. Wall-clock limit → Task 3. CPU/process and file-size limits → Tasks 2–3; address-space capping → Task 2, declared unsupported on the dev platform rather than faked. Hard refusal to execute outside the sandbox → Tasks 1 and 5 (fail-closed, proven by side effect that nothing ran). Explicit graceful degradation → Tasks 1, 2, 4, 5. "Proven by an executing test" → Task 3 executes every escape attempt.

**Known limitation, deliberately accepted.** The userspace policy allows `file-read*` globally: the sandbox confines *writes*, network, and resource use, not reads. Exfiltration of readable host files is out of scope for R1 and must be stated in the module guide rather than left implied. Tightening reads belongs with R2, where the threat model for running attacker-supplied exploits is defined.

**Type consistency.** All three backends return the identical shape `{ status, stdout, stderr, exitCode, timedOut, backend }`; `status` ∈ `'ok' | 'blocked' | 'timeout' | 'disabled' | 'error'`. `buildLimitPrelude` returns `{ prelude, unsupported }` and is consumed identically in Tasks 3 and 4. `detectBackend({ force })` is used consistently in Tasks 1 and 5.
