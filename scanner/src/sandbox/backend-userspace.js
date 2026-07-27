// Userspace confinement backend (macOS family). Applies a deny-by-default
// policy profile: reads allowed, writes confined to the sandbox root, no
// network egress unless explicitly opted in.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { CONFINE_BIN_USERSPACE } from './capabilities.js';
import { buildLimitPrelude } from './limits.js';

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
  maxBuffer = 8 * 1024 * 1024,
} = {}) {
  if (!root) throw new Error('runUserspace requires a sandbox root');

  // Resolve symlinks (e.g. macOS /var -> /private/var) so the profile's
  // subpath param matches the path the kernel actually sees.
  const resolvedRoot = fs.realpathSync(root);

  const effectiveLimits = {
    ...limits,
    maxProcs: limits.maxProcs ?? (_ambientProcCount() + 64),
  };
  const { prelude, unsupported } = buildLimitPrelude(effectiveLimits);
  const inner = `${prelude}exec "$@"`;

  const r = spawnSync(
    CONFINE_BIN_USERSPACE,
    ['-p', _profile({ allowNetwork }), '-D', `ROOT=${resolvedRoot}`,
     '/bin/sh', '-c', inner, '_sbx', ...argv],
    { encoding: 'utf8', timeout: timeoutMs, maxBuffer, cwd: resolvedRoot, env: { ...process.env, ROOT: resolvedRoot } },
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
