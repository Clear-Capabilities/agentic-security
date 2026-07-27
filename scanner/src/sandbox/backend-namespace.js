// Kernel-namespace confinement backend (Linux family).
//
// STATUS: implemented, not verified on this platform — the required
// kernel-namespace tool is not present here, so its escape tests skip with a
// recorded reason. Verify on a Linux host before relying on it for R2.
//
// WHAT THIS BACKEND ACTUALLY CONFINES — do not overstate it. It enters new
// mount/PID/IPC/UTS namespaces and, unless `allowNetwork`, an empty network
// namespace. The empty network namespace has no route anywhere, and that is
// the ONE confinement this backend implements: network egress.
//
// It does NOT confine writes. There is no remount, no bind mount and no
// pivot_root here — only a `cd` into the sandbox root. A `cd` sets the working
// directory; it does not restrict where a process may write. A confined
// command that writes to an absolute path outside the root (a home directory,
// a system config path) will SUCCEED, subject only to ordinary filesystem
// permissions. The new mount namespace isolates mount-table CHANGES made by
// the confined process from the host; it does not make the host filesystem
// read-only. Treat filesystem confinement as ABSENT on this backend until a
// read-only remount is implemented AND verified by execution on a Linux host.
//
// TIMEOUT SCOPE. The wall-clock timeout is `spawnSync`'s, which signals only
// the direct child. On this backend the direct child is the namespace tool
// running as pid 1 of a new PID namespace (`--pid --fork`), so killing it is
// expected to take the whole namespace's processes with it — better than the
// userspace backend, where a backgrounded grandchild demonstrably survives.
// "Expected", not verified: like everything else here it needs a Linux host.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { resolveNamespaceBin } from './capabilities.js';
import { buildLimitPrelude } from './limits.js';
import { buildResult, errorResult, buildConfinedEnv } from './result.js';

export function runNamespace(argv, {
  root,
  timeoutMs = 10000,
  allowNetwork = false,
  limits = {},
  env = {},
  maxBuffer = 8 * 1024 * 1024,
} = {}) {
  // Documented shape, never a throw — see the same note in backend-userspace.
  if (!root) return errorResult('namespace', 'runNamespace requires a sandbox root');

  const bin = resolveNamespaceBin();
  if (!bin) return errorResult('namespace', 'no kernel-namespace binary found on this host');

  let resolvedRoot;
  try {
    // Resolve symlinks so the path the kernel actually sees matches what we
    // hand to the child.
    resolvedRoot = fs.realpathSync(root);
  } catch (e) {
    return errorResult('namespace', `sandbox root is not usable: ${e.message}`);
  }

  let prelude, unsupported;
  try {
    ({ prelude, unsupported } = buildLimitPrelude(limits));
  } catch (e) {
    return errorResult('namespace', `invalid resource limit: ${e.message}`);
  }
  // `cd` only sets the working directory — it is NOT write confinement. See
  // the header note.
  const inner = `${prelude}cd "$ROOT" && exec "$@"`;

  const nsArgs = ['--mount', '--pid', '--ipc', '--uts', '--fork'];
  if (!allowNetwork) nsArgs.push('--net');

  const r = spawnSync(
    bin,
    [...nsArgs, '/bin/sh', '-c', inner, '_sbx', ...argv],
    {
      encoding: 'utf8',
      timeout: timeoutMs,
      maxBuffer,
      cwd: resolvedRoot,
      env: buildConfinedEnv({ root: resolvedRoot, env }),
    },
  );

  return buildResult({ backend: 'namespace', spawnResult: r, unsupported });
}
