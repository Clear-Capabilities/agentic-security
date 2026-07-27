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
import { resolveUserspaceBin } from './capabilities.js';
import { buildLimitPrelude } from './limits.js';
import { buildResult, errorResult, buildConfinedEnv } from './result.js';

// `ulimit -u` (RLIMIT_NPROC) is a per-uid, system-wide cap on this platform,
// not a per-process-tree cap (verified by execution in Task 2). A fixed
// default like the 64 in buildLimitPrelude() breaks ordinary, non-adversarial
// runs on any host whose user already has more than ~64 ambient processes —
// which is common. So unless the caller passes an explicit maxProcs, we
// compute one relative to the ambient count for this uid, the same
// workaround Task 2 used in its own test, to keep default behavior usable
// without pretending a low fixed cap is real containment.
function _ambientProcCount() {
  try {
    const out = spawnSync('/bin/sh', ['-c', 'ps -U "$(id -un)" -o pid= | wc -l'], { encoding: 'utf8' });
    return Number(String(out.stdout || '').trim()) || 200;
  } catch {
    return 200;
  }
}

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
  env = {},
  maxBuffer = 8 * 1024 * 1024,
} = {}) {
  // Documented shape, never a throw: a caller that wraps this in try/catch and
  // "falls back" is a classic route to unconfined execution.
  if (!root) return errorResult('userspace', 'runUserspace requires a sandbox root');

  const bin = resolveUserspaceBin();
  if (!bin) return errorResult('userspace', 'no userspace confinement binary found on this host');

  let resolvedRoot;
  try {
    // Resolve symlinks (e.g. macOS /var -> /private/var) so the profile's
    // subpath param matches the path the kernel actually sees.
    resolvedRoot = fs.realpathSync(root);
  } catch (e) {
    return errorResult('userspace', `sandbox root is not usable: ${e.message}`);
  }

  const effectiveLimits = {
    ...limits,
    maxProcs: limits.maxProcs ?? (_ambientProcCount() + 64),
  };

  let prelude, unsupported;
  try {
    ({ prelude, unsupported } = buildLimitPrelude(effectiveLimits));
  } catch (e) {
    return errorResult('userspace', `invalid resource limit: ${e.message}`);
  }
  const inner = `${prelude}exec "$@"`;

  const r = spawnSync(
    bin,
    ['-p', _profile({ allowNetwork }), '-D', `ROOT=${resolvedRoot}`,
     '/bin/sh', '-c', inner, '_sbx', ...argv],
    {
      encoding: 'utf8',
      timeout: timeoutMs,
      maxBuffer,
      cwd: resolvedRoot,
      env: buildConfinedEnv({ root: resolvedRoot, env }),
    },
  );

  return buildResult({ backend: 'userspace', spawnResult: r, unsupported });
}
