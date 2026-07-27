// Kernel-namespace confinement backend (Linux family).
//
// STATUS: implemented, not verified on this platform — the required
// kernel-namespace tool is not present here, so its escape tests skip with a
// recorded reason. Verify on a Linux host before relying on it for R2.
//
// Isolation: new mount/PID/network/IPC/UTS namespaces. An empty network
// namespace has no route to anywhere, which is what denies egress. Writes are
// confined by entering the sandbox root as the working directory with the rest
// of the filesystem mounted read-only where the kernel permits it.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
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

  // Resolve symlinks so the path the kernel actually mounts/binds matches
  // what we hand to the child (same symlinked-tmp exposure Task 3 hit on
  // the userspace backend).
  const resolvedRoot = fs.realpathSync(root);

  const { prelude, unsupported } = buildLimitPrelude(limits);
  const inner = `${prelude}cd "$ROOT" && exec "$@"`;

  const nsArgs = ['--mount', '--pid', '--ipc', '--uts', '--fork'];
  if (!allowNetwork) nsArgs.push('--net');

  const r = spawnSync(
    CONFINE_BIN_NAMESPACE,
    [...nsArgs, '/bin/sh', '-c', inner, '_sbx', ...argv],
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
    backend: 'namespace',
  };
}
