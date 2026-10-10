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

// Host paths every confined process needs just to start (dynamic loader, system
// libraries, locale and timezone data, device nodes). Used ONLY when reads are
// confined; the default profile below still allows reads globally. Metadata
// (stat) is granted on the ancestors of each readable root and nowhere else, so
// a path outside the readable set cannot even be probed for existence.
const BASELINE_READ_SUBPATHS = Object.freeze([
  '/usr', '/bin', '/sbin', '/System', '/Library/Preferences', '/private/etc', '/dev',
  '/private/var/db/dyld', '/private/var/db/timezone', '/private/var/select',
]);
const BASELINE_META_LITERALS = Object.freeze([
  '/', '/private', '/private/var', '/private/var/db', '/var', '/etc', '/tmp', '/Library', '/private/tmp',
]);

function _profile({ allowNetwork, proxyPort = null, denyRead = [], confineReads = false, readRoots = [], writeRoots = [], metaLiterals = [] }) {
  const lines = [
    '(version 1)',
    '(deny default)',
    '(allow process-exec process-fork)',
    '(allow sysctl-read)',
  ];
  if (!confineReads) {
    lines.push('(allow file-read*)');
  } else {
    // Reads are confined to the baseline above, the declared readable roots and
    // the writable roots. Every path is a parameter or a fixed literal, never
    // spliced text, so a path cannot inject policy.
    lines.push(`(allow file-read* (literal "/") ${BASELINE_READ_SUBPATHS.map((p) => `(subpath "${p}")`).join(' ')})`);
    lines.push(`(allow file-read-metadata ${BASELINE_META_LITERALS.map((p) => `(literal "${p}")`).join(' ')})`);
    lines.push('(allow file-read* (subpath (param "ROOT")))');
    readRoots.forEach((_, i) => lines.push(`(allow file-read* (subpath (param "RD${i}")))`));
    writeRoots.forEach((_, i) => lines.push(`(allow file-read* (subpath (param "WR${i}")))`));
    metaLiterals.forEach((_, i) => lines.push(`(allow file-read-metadata (literal (param "META${i}")))`));
    lines.push('(allow file-write* (literal "/dev/null"))');
  }
  // Read denial (CORE-003). SBPL is last-match-wins, so these deny rules MUST
  // come after every read allow.
  denyRead.forEach((_, i) => lines.push(`(deny file-read* (subpath (param "DENY${i}")))`));
  lines.push('(allow file-write* (subpath (param "ROOT")))');
  writeRoots.forEach((_, i) => lines.push(`(allow file-write* (subpath (param "WR${i}")))`));
  if (allowNetwork) lines.push('(allow network*)');
  // Mediated network (X-504): the only reachable endpoint is the runner's own
  // loopback proxy port; everything else, including every other loopback port
  // and DNS, stays denied by the default rule.
  else if (Number.isInteger(proxyPort) && proxyPort > 0 && proxyPort < 65536) {
    lines.push(`(allow network-outbound (remote ip "localhost:${proxyPort}"))`);
  }
  return lines.join('\n');
}

function _realOrResolved(p) {
  let real = path.resolve(p);
  try { real = fs.realpathSync(real); } catch { /* not present: use the literal path */ }
  return real;
}

function _ancestors(p) {
  const out = [];
  let cur = path.dirname(p);
  while (cur && cur !== path.dirname(cur)) { out.push(cur); cur = path.dirname(cur); }
  return out;
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
  readRoots = null,
  writeRoots = [],
  networkProxyPort = null,
  cwd = null,
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

  // Capability mode (X-502/X-504). `readRoots` non-null confines reads to the
  // baseline plus those roots; `writeRoots` adds writable subtrees beyond
  // `root`; `networkProxyPort` opens exactly one loopback port. All of them are
  // absent for every pre-existing caller, whose profile is unchanged.
  const confineReads = Array.isArray(readRoots);
  const rd = confineReads ? [...new Set(readRoots.filter((p) => typeof p === 'string' && p).map(_realOrResolved))] : [];
  const wr = [...new Set((writeRoots || []).filter((p) => typeof p === 'string' && p).map(_realOrResolved))];
  let resolvedCwd = resolvedRoot;
  if (cwd) {
    resolvedCwd = _realOrResolved(cwd);
    try { if (!fs.statSync(resolvedCwd).isDirectory()) throw new Error('not a directory'); } catch (e) {
      return { error: errorResult('userspace', `working directory is not usable: ${e.message}`) };
    }
  }
  const metaSet = new Set();
  if (confineReads) {
    for (const p of [resolvedRoot, resolvedCwd, ...rd, ...wr]) for (const a of _ancestors(p)) metaSet.add(a);
    for (const b of BASELINE_META_LITERALS) metaSet.delete(b);
  }
  const metaLiterals = [...metaSet].sort();

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
      '-p', _profile({ allowNetwork, proxyPort: networkProxyPort, denyRead, confineReads, readRoots: rd, writeRoots: wr, metaLiterals }),
      '-D', `ROOT=${resolvedRoot}`,
      ...denyRead.flatMap((p, i) => ['-D', `DENY${i}=${p}`]),
      ...rd.flatMap((p, i) => ['-D', `RD${i}=${p}`]),
      ...wr.flatMap((p, i) => ['-D', `WR${i}=${p}`]),
      ...metaLiterals.flatMap((p, i) => ['-D', `META${i}=${p}`]),
      '/bin/sh', '-c', inner, '_sbx', ...argv,
    ],
    cwd: resolvedCwd,
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
  readRoots = null,
  writeRoots = [],
  networkProxyPort = null,
  cwd = null,
} = {}) {
  // Documented shape, never a throw: a caller that wraps this in try/catch and
  // "falls back" is a classic route to unconfined execution.
  const inv = buildUserspaceInvocation(argv, { root, allowNetwork, limits, env, denyReadPaths, readRoots, writeRoots, networkProxyPort, cwd });
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
