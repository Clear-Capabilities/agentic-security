// Kernel-namespace confinement backend (Linux family).
//
// STATUS. This backend cannot be exercised on the macOS development host — the
// required kernel-namespace tool is absent, so its escape tests skip with a
// recorded reason there. Whether the confinement described below actually
// holds is a per-host fact that only a Linux host can answer, and only by
// EXECUTING the escape suite. Do not read this comment as a verification
// claim; read `src/sandbox/CLAUDE.md` for what has and has not been executed.
//
// WHAT THIS BACKEND CONFINES.
//
//   1. NETWORK EGRESS — an empty network namespace (`--net`, unless the caller
//      passes `allowNetwork`). It has no route anywhere.
//
//   2. FILESYSTEM WRITES — a private mount namespace in which every mount
//      point present at setup time is rebound READ-ONLY, and only the sandbox
//      root is rebound read-write. An out-of-root write therefore fails with
//      EROFS. That error text is one of `result.js`'s denial patterns, so an
//      escape attempt surfaces as `status:'blocked'` + `denied:true` — the
//      same shape the userspace backend produces, which is the main reason
//      this shape was chosen over `pivot_root` (see below).
//
//   3. RESOURCE CAPS — the shared `ulimit` prelude.
//
// WHY READ-ONLY REBIND RATHER THAN pivot_root. `pivot_root` into the sandbox
// root is the stronger primitive: after detaching the old root, out-of-root
// paths are not merely read-only, they are absent from the mount namespace
// entirely. It was rejected here for three concrete reasons. (a) It requires
// materialising a system tree (the shell, the C library, the utilities a PoC
// invokes) inside the caller's sandbox root, which pollutes a directory the
// caller owns and reads back. (b) It changes path semantics: `$ROOT` becomes
// `/`, so a caller's absolute paths mean something different on this backend
// than on the userspace one, and the two backends stop being interchangeable.
// (c) An out-of-root write would then fail with ENOENT, which is
// indistinguishable from an ordinary missing path and cannot be reported as a
// confinement denial — the caller loses the `denied` signal precisely where it
// matters most. The read-only rebind keeps paths, keeps the denial signal, and
// keeps both backends returning the same thing for the same escape attempt.
//
// HONEST LIMIT OF THE READ-ONLY REBIND. The namespaces are acquired by
// creating a user namespace, and the confined process is therefore (initially)
// privileged inside it — it holds CAP_SYS_ADMIN over the mount namespace it
// runs in, and could rebind the tree read-write again. That would gut the
// confinement, so after the mounts are established and before the caller's
// command is executed, the backend drops the whole capability set (bounding,
// inheritable, and — via the `noroot` secure bits — the implicit privileges of
// uid 0) and only then executes. If the privilege-dropping utility is not
// present on the host the command still runs under the read-only mount tree,
// but the result DECLARES `privilegeDrop` unenforced (in `unsupported`, the
// same mechanism `limits.js` uses) rather than pretending the hardening
// applied. It is never silently skipped.
//
// FAIL-CLOSED, AND VERIFIED PER RUN RATHER THAN ASSUMED. Every step that
// establishes confinement aborts the run on failure: no namespace variant, no
// filesystem-attach utility, a mount tree that cannot be made read-only, a
// sandbox root that turns out not to be writable — each returns
// `status:'error'` with nothing executed. Beyond that, the confinement is PROVEN by execution on
// every single run: the parent creates a canary path OUTSIDE the sandbox root,
// and the confined shell — already in its final, deprivileged state —
// attempts to create it. If that write succeeds, confinement is not in force
// and the shell exits WITHOUT running the caller's command. A reasoned
// expectation that "the remount should have worked" is exactly the class of
// claim this module exists to refuse.
//
// TIMEOUT SCOPE — SETTLED BY TWO CI RUNS, AFTER TWO WRONG CLAIMS.
//
// This comment asserted for a long time that killing the direct child would
// reap the whole namespace, since that child is pid 1 of a new PID namespace
// (`--pid --fork`) — and that this made the backend BETTER than the userspace
// one. A test was written to check rather than assume. What CI actually found,
// in two rounds:
//
//   1. With the default SIGTERM the timeout did nothing at all: a 1200 ms
//      budget against a payload sleeping 30 s returned after `30057 ms`, having
//      run the payload to completion. The kernel does not deliver
//      default-action signals to a PID namespace's pid 1 from outside it, so
//      with no handler installed SIGTERM is simply dropped.
//   2. With `killSignal: 'SIGKILL'` — which cannot be ignored — the call
//      returns in about 1.2 s. The DIRECT CHILD is bounded. But a backgrounded
//      grandchild still outlived it and wrote its marker, so the PID namespace
//      does NOT reap the tree here.
//
// Settled: SIGKILL bounds the direct child promptly; it does not kill the tree.
// That is the SAME limitation the userspace backend carries, not an improvement
// on it. Confinement is unaffected — survivors remain inside the mount and
// network namespaces and can neither write out of root nor reach the network —
// but there is no bound on how long descendants run, and any caller needing one
// must impose it (see `posture/prove-findings.js`, which does). Pinned by
// "KNOWN GAP: the timeout bounds the direct child but does NOT reap the tree"
// in `sandbox-escape.test.js`, which fails in both directions.
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
// relaxed to make a run succeed — dropping `--net` would remove the network
// confinement, so `--net` is part of every probed variant when `allowNetwork`
// is false, and `--mount` is in every variant unconditionally because the
// write confinement is built inside it.
// TWO MODES. The default (legacy) mode above is unchanged: the whole host tree
// stays visible and is rebound read-only. CAPABILITY MODE is entered when the
// caller passes `readRoots` (an array, possibly empty): the process pivots into
// a tmpfs root that holds only the runtime baseline and the declared roots (see
// `linux-rootfs.js`), so a path outside them has no name at all. In both modes
// `denyReadPaths` masks the named host paths (an empty tmpfs over a directory,
// /dev/null over a file; absent in capability mode unless under a declared
// root), and the process runs under a PID namespace created with
// `--kill-child`: when the unshare process dies, the namespace's init gets
// SIGKILL and the kernel kills every member, which no `setsid` or double fork
// can leave. `--kill-child` is used only where `unshare` advertises it; where it
// does not, `treeKill` is false and supervised execution is refused.
//
// Mediated network (a proxy reachable from inside an empty network namespace)
// is NOT implemented. `networkProxyPort` is refused, so a task that needs a
// network destination is blocked on this backend, never quietly allowed.
//
// Nothing above is a verification claim. What has been executed on a Linux
// host is stated by `sandbox/CLAUDE.md` and evidenced only by the
// `sandbox-linux` CI job's probes (`linux-probes.js`).
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  resolveNamespaceBin, resolveMountBin, resolvePrivDropBin, resolvePivotBin, resolveUmountBin,
  cachedNamespaceVariant, cacheNamespaceVariant,
} from './capabilities.js';
import { buildLimitPrelude, ambientRelativeMaxProcs } from './limits.js';
import { buildResult, errorResult, buildConfinedEnv } from './result.js';
import {
  buildRootPlan, serializePlan, PIVOT_SETUP_SCRIPT, FINAL_SCRIPT, MARK_SETUP_FAILED, MARK_NO_PRIVDROP,
} from './linux-rootfs.js';

// Ordered most-portable-first. Each entry is only the PRIVILEGE-acquisition
// prefix; the namespace flags themselves are appended identically to all of
// them by `_nsArgs`, so no variant can quietly confine less than another.
//
//   1. user namespace with the invoking user mapped to root inside it — the
//      unprivileged route, and the one a standard CI runner needs. It is also
//      the only variant under which the write confinement can be built, since
//      rebinding the mount tree needs CAP_SYS_ADMIN in the owning namespace.
//   2. user namespace with the invoking user mapped to itself — for hosts
//      whose policy permits a user namespace but not the root mapping.
//   3. no prefix — the direct route, which needs CAP_SYS_ADMIN (i.e. root).
//      Last so an unprivileged host never pays for a doomed attempt first.
const NS_PRIVILEGE_VARIANTS = Object.freeze([
  Object.freeze(['--user', '--map-root-user']),
  Object.freeze(['--user', '--map-current-user']),
  Object.freeze([]),
]);

function _nsArgs(privilegeFlags, allowNetwork, killChild = false) {
  const a = [...privilegeFlags, '--mount', '--pid', '--ipc', '--uts', '--fork'];
  if (killChild) a.push('--kill-child');
  if (!allowNetwork) a.push('--net');
  return a;
}

/** Whether a resolved argument list carries the PID-namespace tree kill. */
export function namespaceTreeKill(args) {
  return Array.isArray(args) && args.includes('--kill-child');
}

// The markers live in linux-rootfs.js so both modes agree. A payload that
// PRINTS one of these strings can force `status:'error'` (or a false
// `privilegeDrop` unenforced note). That is the safe direction: the worst it
// achieves is making its own run look like it did not happen, which no
// downstream tier reads as evidence of anything. It cannot make an unconfined
// run look confined.

// Default mode: runs inside the namespaces, still privileged, before the
// caller's command. Builds the write confinement, then hands off to $SBX_FINAL
// with the capability set dropped.
//
// Order matters: the sandbox root is bound onto itself while the tree is still
// writable, so the read-only pass and the read-write rebind of the root never
// have to fight each other. Individual sub-mounts are best-effort (some pseudo
// filesystems legitimately refuse a rebind); the canary check in $SBX_FINAL is
// what actually decides whether the result is trustworthy.
export const LEGACY_SETUP_SCRIPT = `
_fail() { echo "${MARK_SETUP_FAILED} $1" >&2; exit 91; }
"$SBX_MOUNT" --make-rprivate / || _fail "mount propagation could not be made private"
"$SBX_MOUNT" -t proc proc /proc 2>/dev/null || true
"$SBX_MOUNT" --bind "$ROOT" "$ROOT" || _fail "the sandbox root could not be bind-mounted"
_mps=$(while read -r _a _b _c _d _mp _rest; do printf '%s\\n' "$_mp"; done < /proc/self/mountinfo)
for _mp in $_mps; do
  [ "$_mp" = "/" ] && continue
  [ "$_mp" = "$ROOT" ] && continue
  case "$_mp" in "$ROOT"/*) continue ;; esac
  "$SBX_MOUNT" -o remount,bind,ro "$_mp" 2>/dev/null || true
done
"$SBX_MOUNT" -o remount,bind,ro / || _fail "the root filesystem could not be rebound read-only"
# Belt and braces: the root was bound before the read-only pass and skipped by
# it, so this is normally a no-op. Its return code is NOT the gate — the
# executed in-root write check in $SBX_FINAL is, and that one fails closed.
"$SBX_MOUNT" -o remount,bind,rw "$ROOT" 2>/dev/null || true
if [ -n "$SBX_MASKS" ]; then
  while IFS= read -r _m; do
    [ -n "$_m" ] || continue
    if [ -d "$_m" ]; then
      "$SBX_MOUNT" -t tmpfs -o size=4k,mode=000 tmpfs "$_m" || _fail "a protected directory could not be masked"
    elif [ -e "$_m" ]; then
      "$SBX_MOUNT" --bind /dev/null "$_m" || _fail "a protected file could not be masked"
    fi
  done <<SBX_MASK_EOF
$SBX_MASKS
SBX_MASK_EOF
fi
if [ -n "$SBX_PRIVDROP" ] && "$SBX_PRIVDROP" --securebits=+noroot,+noroot_locked --bounding-set=-all --inh-caps=-all /bin/sh -c 'exit 0' 2>/dev/null; then
  exec "$SBX_PRIVDROP" --securebits=+noroot,+noroot_locked --bounding-set=-all --inh-caps=-all /bin/sh -c "$SBX_FINAL" _sbx "$@"
fi
echo "${MARK_NO_PRIVDROP}" >&2
exec /bin/sh -c "$SBX_FINAL" _sbx "$@"
`;

/**
 * The first privilege variant under which the requested namespaces can
 * actually be created on this host, or null when none can. Probed by running
 * a trivial command — a reasoned expectation about which flags "should" work
 * is exactly what made this backend unusable on an unprivileged runner.
 *
 * `--kill-child` is added only when the binary advertises it in its help text;
 * it is an addition to the confinement, never a requirement for it, so a host
 * without it still gets the same confinement and simply reports `treeKill`
 * false (see `namespaceTreeKill`).
 */
export function resolveNamespaceArgs(bin, allowNetwork, { probeTimeoutMs = 5000 } = {}) {
  const key = `${bin}:${allowNetwork ? 'net' : 'nonet'}`;
  const cached = cachedNamespaceVariant(key);
  if (cached !== undefined) return cached;

  let killChild = false;
  try {
    const help = spawnSync(bin, ['--help'], { encoding: 'utf8', timeout: probeTimeoutMs });
    killChild = /--kill-child/.test(`${help.stdout || ''}${help.stderr || ''}`);
  } catch { killChild = false; }

  let chosen = null;
  for (const variant of NS_PRIVILEGE_VARIANTS) {
    const args = _nsArgs(variant, allowNetwork, killChild);
    const probe = spawnSync(bin, [...args, '/bin/sh', '-c', 'exit 0'], {
      encoding: 'utf8', timeout: probeTimeoutMs, stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (!probe.error && probe.status === 0) { chosen = args; break; }
  }
  cacheNamespaceVariant(key, chosen);
  return chosen;
}

/** Strip the internal markers from stderr before it reaches the caller. */
function _cleanStderr(s) {
  return String(s || '')
    .split('\n')
    .filter((l) => !l.includes(MARK_SETUP_FAILED) && l.trim() !== MARK_NO_PRIVDROP)
    .join('\n');
}

function _setupFailureReason(stderr) {
  for (const line of String(stderr || '').split('\n')) {
    const i = line.indexOf(MARK_SETUP_FAILED);
    if (i !== -1) return line.slice(i + MARK_SETUP_FAILED.length).trim();
  }
  return null;
}

const _within = (parent, child) => child === parent || child.startsWith(parent.endsWith('/') ? parent : parent + '/');

function _maskPaths(denyReadPaths, resolvedRoot) {
  const out = [];
  for (const p of denyReadPaths || []) {
    if (typeof p !== 'string' || !p) continue;
    let real = path.resolve(p);
    try { real = fs.realpathSync(real); } catch { /* not present: nothing to mask, and nothing to read */ }
    if (/[\0\n]/.test(real)) return { error: `a denied path cannot be carried into the mount setup (${JSON.stringify(p)})` };
    if (_within(real, resolvedRoot)) return { error: `a denied path overlaps the sandbox root (${real})` };
    if (!out.includes(real)) out.push(real);
  }
  return { paths: out };
}

/**
 * Build the exact spawn invocation for a namespace-confined command, without
 * running it. Shared by the synchronous runner and the supervised runner, so
 * both are confined by the SAME setup. Returns `{ error }` in the documented
 * error shape instead of throwing. On success the caller MUST call
 * `inv.finish(rawStderr, {hadError})` exactly once after the process ends: it
 * checks the host-side canary, extracts any setup failure, removes the
 * temporary directories, and returns `{ error }` or `{ stderr, unsupported }`.
 *
 * @param {object} [deps]  test seam: tool resolvers and the argument resolver.
 *   Cannot weaken the setup: it only changes WHERE the tools are found.
 */
export function buildNamespaceInvocation(argv, {
  root,
  allowNetwork = false,
  limits = {},
  env = {},
  denyReadPaths = [],
  readRoots = null,
  writeRoots = [],
  networkProxyPort = null,
  cwd = null,
} = {}, deps = {}) {
  const d = {
    nsBin: resolveNamespaceBin, mountBin: resolveMountBin, privDropBin: resolvePrivDropBin,
    pivotBin: resolvePivotBin, umountBin: resolveUmountBin, nsArgs: resolveNamespaceArgs, ...deps,
  };
  if (!root) return { error: errorResult('namespace', 'runNamespace requires a sandbox root') };
  if (networkProxyPort != null) {
    return { error: errorResult('namespace', 'mediated network access is not implemented on this backend (an empty network namespace has no path to a proxy); refusing to execute') };
  }

  const bin = d.nsBin();
  if (!bin) return { error: errorResult('namespace', 'no kernel-namespace binary found on this host') };

  // Write confinement is built with this utility. No utility, no confinement,
  // no run — there is deliberately no branch that proceeds without it.
  const mountBin = d.mountBin();
  if (!mountBin) {
    return { error: errorResult('namespace',
      'no filesystem-attach binary found on this host, so write confinement cannot be established; refusing to execute unconfined') };
  }

  let resolvedRoot;
  try {
    // Resolve symlinks so the path the kernel actually sees matches what we
    // hand to the child.
    resolvedRoot = fs.realpathSync(root);
  } catch (e) {
    return { error: errorResult('namespace', `sandbox root is not usable: ${e.message}`) };
  }

  const strict = Array.isArray(readRoots);
  const masked = _maskPaths(denyReadPaths, resolvedRoot);
  if (masked.error) return { error: errorResult('namespace', masked.error) };

  let plan = null;
  let pivotBin = null; let umountBin = null;
  if (strict) {
    pivotBin = d.pivotBin();
    umountBin = d.umountBin();
    if (!pivotBin || !umountBin) {
      return { error: errorResult('namespace', 'capability mode needs the root-switching and unmount tools, and this host lacks them; refusing to execute') };
    }
    plan = buildRootPlan({ root: resolvedRoot, readRoots, writeRoots, denyReadPaths: masked.paths, cwd });
    if (!plan.ok) return { error: errorResult('namespace', `the filesystem plan is not acceptable: ${plan.error}`) };
  } else if (cwd) {
    // Default mode keeps its one working directory. Silently ignoring a
    // requested directory would run the command somewhere the caller did not
    // choose.
    let wd = null;
    try { wd = fs.realpathSync(cwd); } catch { /* handled below */ }
    if (wd !== resolvedRoot) return { error: errorResult('namespace', 'a working directory other than the sandbox root needs capability mode (readRoots); refusing to execute') };
  }

  // Same per-uid RLIMIT_NPROC trap as the userspace backend, and worse here:
  // the confined shell has to fork several helpers to BUILD its confinement,
  // so a fixed cap below the ambient count for this uid makes the setup itself
  // fail and the sandbox look broken. See `ambientRelativeMaxProcs`.
  const effectiveLimits = { ...limits, maxProcs: limits.maxProcs ?? ambientRelativeMaxProcs() };

  let prelude, unsupported;
  try {
    ({ prelude, unsupported } = buildLimitPrelude(effectiveLimits));
  } catch (e) {
    return { error: errorResult('namespace', `invalid resource limit: ${e.message}`) };
  }

  // Fail closed: no usable variant means the confinement cannot be
  // established, so nothing is executed. There is deliberately no path that
  // drops confinement flags and runs anyway.
  const nsArgs = d.nsArgs(bin, allowNetwork);
  if (!nsArgs) {
    return { error: errorResult('namespace', 'kernel namespaces could not be created on this host (unprivileged user-namespace creation appears to be denied); refusing to execute unconfined') };
  }

  // The canary lives OUTSIDE the sandbox root, in a directory this process
  // just created and can write. If the confined shell can create it, the
  // confinement is not in force and the command is not run.
  const made = [];
  const dispose = () => { for (const p of made.splice(0)) { try { fs.rmSync(p, { recursive: true, force: true }); } catch { /* best effort */ } } };
  let canaryDir; let newRoot = null;
  try {
    canaryDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-sbx-canary-'));
    made.push(canaryDir);
    if (strict) { newRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-sbx-newroot-')); made.push(newRoot); }
  } catch (e) {
    dispose();
    return { error: errorResult('namespace', `could not create the confinement scratch directories: ${e.message}`) };
  }
  const canary = path.join(canaryDir, 'out-of-root.canary');

  const sbxEnv = {
    SBX_MOUNT: mountBin,
    SBX_PRIVDROP: d.privDropBin() || '',
    SBX_CANARY: canary,
    SBX_FINAL: FINAL_SCRIPT,
  };
  let script;
  if (strict) {
    Object.assign(sbxEnv, {
      SBX_STRICT: '1', SBX_NEWROOT: newRoot, SBX_PLAN: serializePlan(plan), SBX_PIVOT: pivotBin, SBX_UMOUNT: umountBin, SBX_CWD: plan.cwd,
    });
    script = PIVOT_SETUP_SCRIPT;
  } else {
    if (masked.paths.length) sbxEnv.SBX_MASKS = masked.paths.join('\n');
    script = LEGACY_SETUP_SCRIPT;
  }

  return {
    bin,
    args: [...nsArgs, '/bin/sh', '-c', prelude + script, '_sbx', ...argv],
    cwd: resolvedRoot,
    env: { ...buildConfinedEnv({ root: resolvedRoot, env }), ...sbxEnv },
    unsupported,
    mode: strict ? 'capability' : 'default',
    treeKill: namespaceTreeKill(nsArgs),
    plan,
    dispose,
    finish(rawStderr, { hadError = false } = {}) {
      try {
        // Parent-side confirmation of the same fact the canary check asserts
        // from the inside. Cheap, and it does not depend on the confined shell
        // being honest about its own exit code.
        if (fs.existsSync(canary)) {
          return { error: errorResult('namespace',
            'the confined process created a file outside the sandbox root: write confinement is NOT in force on this host') };
        }
      } finally { dispose(); }
      const raw = String(rawStderr || '');
      const setupFailure = _setupFailureReason(raw);
      if (setupFailure && !hadError) {
        // Confinement could not be established (or could not be proven). Nothing
        // ran: the shell exits before `exec`ing the caller's command.
        return { error: errorResult('namespace', `confinement could not be established: ${setupFailure}`) };
      }
      const eff = [...unsupported];
      if (raw.includes(MARK_NO_PRIVDROP)) eff.push('privilegeDrop');
      return { stderr: _cleanStderr(raw), unsupported: eff };
    },
  };
}

export function runNamespace(argv, opts = {}) {
  const { timeoutMs = 10000, maxBuffer = 8 * 1024 * 1024 } = opts;
  // Documented shape, never a throw — see the same note in backend-userspace.
  const inv = buildNamespaceInvocation(argv, opts);
  if (inv.error) return inv.error;

  let r;
  try {
    r = spawnSync(inv.bin, inv.args, {
      encoding: 'utf8',
      timeout: timeoutMs,
      // SIGKILL, not the SIGTERM default: the direct child is pid 1 of a new
      // PID namespace, and the kernel does not deliver default-action signals
      // to a namespace's pid 1 from outside it. SIGKILL cannot be ignored.
      // Found by CI: the first Linux run of the tree-kill test recorded
      // duration_ms 30057 against a 1200 ms budget. With `--kill-child` the
      // same SIGKILL, delivered to the unshare process, also reaps the whole
      // namespace (see the header).
      killSignal: 'SIGKILL',
      maxBuffer,
      cwd: inv.cwd,
      env: inv.env,
    });
  } catch (e) {
    inv.dispose();
    return errorResult('namespace', `the confined process could not be started: ${e.message}`);
  }

  const fin = inv.finish(r.stderr ?? '', { hadError: !!r.error });
  if (fin.error) return fin.error;
  return buildResult({
    backend: 'namespace',
    spawnResult: { ...r, stderr: fin.stderr },
    unsupported: fin.unsupported,
  });
}
