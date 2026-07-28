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
//
// PRIVILEGE. Creating mount/PID/IPC/UTS/network namespaces directly requires
// CAP_SYS_ADMIN, which an ordinary CI account does not have — asking for them
// bare fails with a permission error and the backend cannot start at all. The
// unprivileged route is to create a USER namespace first and take the
// requested namespaces inside it, where the invoking user holds the
// capabilities. So the flag set is chosen by PROBE, not assumed: each variant
// below is executed with a trivial command and the first one that actually
// succeeds is used (and cached). Fail-closed: if no variant works the backend
// returns status 'error' and nothing runs. The confinement flags are NEVER
// relaxed to make a run succeed — dropping `--net` would remove the only
// confinement this backend implements, so `--net` is part of every probed
// variant when `allowNetwork` is false.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { resolveNamespaceBin, cachedNamespaceVariant, cacheNamespaceVariant } from './capabilities.js';
import { buildLimitPrelude } from './limits.js';
import { buildResult, errorResult, buildConfinedEnv } from './result.js';

// Ordered most-portable-first. Each entry is only the PRIVILEGE-acquisition
// prefix; the namespace flags themselves are appended identically to all of
// them by `_nsArgs`, so no variant can quietly confine less than another.
//
//   1. user namespace with the invoking user mapped to root inside it — the
//      unprivileged route, and the one a standard CI runner needs.
//   2. user namespace with the invoking user mapped to itself — for hosts
//      whose policy permits a user namespace but not the root mapping.
//   3. no prefix — the direct route, which needs CAP_SYS_ADMIN (i.e. root).
//      Last so an unprivileged host never pays for a doomed attempt first.
const NS_PRIVILEGE_VARIANTS = Object.freeze([
  Object.freeze(['--user', '--map-root-user']),
  Object.freeze(['--user', '--map-current-user']),
  Object.freeze([]),
]);

function _nsArgs(privilegeFlags, allowNetwork) {
  const a = [...privilegeFlags, '--mount', '--pid', '--ipc', '--uts', '--fork'];
  if (!allowNetwork) a.push('--net');
  return a;
}

/**
 * The first privilege variant under which the requested namespaces can
 * actually be created on this host, or null when none can. Probed by running
 * a trivial command — a reasoned expectation about which flags "should" work
 * is exactly what made this backend unusable on an unprivileged runner.
 */
export function resolveNamespaceArgs(bin, allowNetwork, { probeTimeoutMs = 5000 } = {}) {
  const key = `${bin}:${allowNetwork ? 'net' : 'nonet'}`;
  const cached = cachedNamespaceVariant(key);
  if (cached !== undefined) return cached;

  let chosen = null;
  for (const variant of NS_PRIVILEGE_VARIANTS) {
    const args = _nsArgs(variant, allowNetwork);
    const probe = spawnSync(bin, [...args, '/bin/sh', '-c', 'exit 0'], {
      encoding: 'utf8', timeout: probeTimeoutMs, stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (!probe.error && probe.status === 0) { chosen = args; break; }
  }
  cacheNamespaceVariant(key, chosen);
  return chosen;
}

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

  // Fail closed: no usable variant means the confinement cannot be
  // established, so nothing is executed. There is deliberately no path that
  // drops confinement flags and runs anyway.
  const nsArgs = resolveNamespaceArgs(bin, allowNetwork);
  if (!nsArgs) {
    return errorResult('namespace', 'kernel namespaces could not be created on this host (unprivileged user-namespace creation appears to be denied); refusing to execute unconfined');
  }

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
