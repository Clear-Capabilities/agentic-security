// Userspace confinement backend (macOS family). Applies a deny-by-default
// policy profile: reads allowed, writes confined to the sandbox root, no
// network egress unless explicitly opted in.
//
// TIMEOUT SCOPE — read before trusting `status:'timeout'`. The wall-clock
// timeout is `spawnSync`'s, which signals only the DIRECT child. Verified by
// execution on this platform: with `timeoutMs: 1200`, a command that
// backgrounded a 4-second child returned `status:'timeout'` while the
// grandchild survived the timeout and completed its work afterwards. So
// 'timeout' means "we stopped waiting and killed the process we spawned", NOT
// "the process tree was terminated". Anything left running is still inside the
// policy profile (its writes and network stay confined), but it is still
// running. Callers that need a hard tree kill must supply it themselves.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { resolveUserspaceBin } from './capabilities.js';
import { buildLimitPrelude, ambientRelativeMaxProcs } from './limits.js';
import { buildResult, errorResult, buildConfinedEnv } from './result.js';

function _profile({ allowNetwork, denyRead = [] }) {
  return [
    '(version 1)',
    '(deny default)',
    '(allow process-exec process-fork)',
    '(allow sysctl-read)',
    '(allow file-read*)',
    // Read denial (CORE-003). SBPL is last-match-wins, so these deny rules MUST
    // come after the blanket read allow. Each path is a parameter, never
    // spliced into the profile text, so a path cannot inject policy.
    ...denyRead.map((_, i) => `(deny file-read* (subpath (param "DENY${i}")))`),
    '(allow file-write* (subpath (param "ROOT")))',
    allowNetwork ? '(allow network*)' : '',
  ].filter(Boolean).join('\n');
}

/**
 * Build the exact spawn invocation for a userspace-confined command, without
 * running it. Shared by the synchronous runner below and the supervised
 * (process-tree-killing) runner, so both are confined by the SAME profile.
 * Returns `{ error }` in the documented error shape instead of throwing.
 */
export function buildUserspaceInvocation(argv, {
  root,
  allowNetwork = false,
  limits = {},
  env = {},
  denyReadPaths = [],
} = {}) {
  if (!root) return { error: errorResult('userspace', 'runUserspace requires a sandbox root') };

  const bin = resolveUserspaceBin();
  if (!bin) return { error: errorResult('userspace', 'no userspace confinement binary found on this host') };

  let resolvedRoot;
  try {
    resolvedRoot = fs.realpathSync(root);
  } catch (e) {
    return { error: errorResult('userspace', `sandbox root is not usable: ${e.message}`) };
  }

  // Resolve each denied path as far as it exists (a symlink would otherwise
  // let the same file be reached by a path the profile does not name). A path
  // that does not exist yet is denied by its literal text.
  const denyRead = [];
  for (const p of denyReadPaths || []) {
    if (typeof p !== 'string' || !p) continue;
    let real = path.resolve(p);
    try { real = fs.realpathSync(real); } catch { /* not present: deny the literal path */ }
    if (!denyRead.includes(real)) denyRead.push(real);
  }

  const effectiveLimits = {
    ...limits,
    maxProcs: limits.maxProcs ?? ambientRelativeMaxProcs(),
  };
  let prelude, unsupported;
  try {
    ({ prelude, unsupported } = buildLimitPrelude(effectiveLimits));
  } catch (e) {
    return { error: errorResult('userspace', `invalid resource limit: ${e.message}`) };
  }
  const inner = `${prelude}exec "$@"`;

  return {
    bin,
    args: [
      '-p', _profile({ allowNetwork, denyRead }),
      '-D', `ROOT=${resolvedRoot}`,
      ...denyRead.flatMap((p, i) => ['-D', `DENY${i}=${p}`]),
      '/bin/sh', '-c', inner, '_sbx', ...argv,
    ],
    cwd: resolvedRoot,
    env: buildConfinedEnv({ root: resolvedRoot, env }),
    unsupported,
  };
}

export function runUserspace(argv, {
  root,
  timeoutMs = 10000,
  allowNetwork = false,
  limits = {},
  env = {},
  maxBuffer = 8 * 1024 * 1024,
  denyReadPaths = [],
} = {}) {
  // Documented shape, never a throw: a caller that wraps this in try/catch and
  // "falls back" is a classic route to unconfined execution.
  const inv = buildUserspaceInvocation(argv, { root, allowNetwork, limits, env, denyReadPaths });
  if (inv.error) return inv.error;

  const r = spawnSync(inv.bin, inv.args, {
    encoding: 'utf8',
    timeout: timeoutMs,
    // Match the namespace backend: SIGKILL cannot be ignored, SIGTERM can.
    // A payload that installs a SIGTERM handler would otherwise outlive its
    // own budget while the caller is told it timed out.
    killSignal: 'SIGKILL',
    maxBuffer,
    cwd: inv.cwd,
    env: inv.env,
  });

  return buildResult({ backend: 'userspace', spawnResult: r, unsupported: inv.unsupported });
}
