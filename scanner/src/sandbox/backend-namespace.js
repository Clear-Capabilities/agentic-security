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
// filesystem-attach utility, a root that cannot be rebound read-write, a mount
// tree that cannot be made read-only — each returns `status:'error'` with
// nothing executed. Beyond that, the confinement is PROVEN by execution on
// every single run: the parent creates a canary path OUTSIDE the sandbox root,
// and the confined shell — already in its final, deprivileged state —
// attempts to create it. If that write succeeds, confinement is not in force
// and the shell exits WITHOUT running the caller's command. A reasoned
// expectation that "the remount should have worked" is exactly the class of
// claim this module exists to refuse.
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
// relaxed to make a run succeed — dropping `--net` would remove the network
// confinement, so `--net` is part of every probed variant when `allowNetwork`
// is false, and `--mount` is in every variant unconditionally because the
// write confinement is built inside it.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  resolveNamespaceBin, resolveMountBin, resolvePrivDropBin,
  cachedNamespaceVariant, cacheNamespaceVariant,
} from './capabilities.js';
import { buildLimitPrelude } from './limits.js';
import { buildResult, errorResult, buildConfinedEnv } from './result.js';

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

function _nsArgs(privilegeFlags, allowNetwork) {
  const a = [...privilegeFlags, '--mount', '--pid', '--ipc', '--uts', '--fork'];
  if (!allowNetwork) a.push('--net');
  return a;
}

// Markers the confined shell writes to its own stderr so the parent can tell
// a confinement-setup failure from ordinary program output. They are stripped
// from the stderr handed back to the caller.
//
// A payload that PRINTS one of these strings can force `status:'error'` (or a
// false `privilegeDrop` unenforced note). That is the safe direction: the
// worst it achieves is making its own run look like it did not happen, which
// no downstream tier reads as evidence of anything. It cannot make an
// unconfined run look confined.
const MARK_SETUP_FAILED = 'AGSEC_SANDBOX_SETUP_FAILED:';
const MARK_NO_PRIVDROP = 'AGSEC_SANDBOX_PRIVDROP_UNAVAILABLE';

// Runs inside the namespaces, still privileged, before the caller's command.
// Builds the write confinement, then hands off to $SBX_FINAL with the
// capability set dropped.
//
// Order matters: the sandbox root is bound onto itself while the tree is still
// writable, so the read-only pass and the read-write rebind of the root never
// have to fight each other. Individual sub-mounts are best-effort (some pseudo
// filesystems legitimately refuse a rebind); the canary check in $SBX_FINAL is
// what actually decides whether the result is trustworthy.
const SETUP_SCRIPT = `
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
"$SBX_MOUNT" -o remount,bind,rw "$ROOT" || _fail "the sandbox root could not be rebound writable"
if [ -n "$SBX_PRIVDROP" ] && "$SBX_PRIVDROP" --securebits=+noroot,+noroot_locked --bounding-set=-all --inh-caps=-all /bin/sh -c 'exit 0' 2>/dev/null; then
  exec "$SBX_PRIVDROP" --securebits=+noroot,+noroot_locked --bounding-set=-all --inh-caps=-all /bin/sh -c "$SBX_FINAL" _sbx "$@"
fi
echo "${MARK_NO_PRIVDROP}" >&2
exec /bin/sh -c "$SBX_FINAL" _sbx "$@"
`;

// Runs in the FINAL privilege state, immediately before the caller's command.
// Both directions are checked by execution, every run: the out-of-root canary
// must be refused, and an in-root write must succeed. Either check failing
// means the sandbox is not what it claims, so the command is not run.
const FINAL_SCRIPT = `
_fail() { echo "${MARK_SETUP_FAILED} $1" >&2; exit 91; }
if ( : > "$SBX_CANARY" ) 2>/dev/null; then
  _fail "an out-of-root write is still possible; refusing to execute"
fi
if ! ( : > "$ROOT/.agsec-sbx-wcheck" ) 2>/dev/null; then
  _fail "the sandbox root is not writable; refusing to execute"
fi
rm -f "$ROOT/.agsec-sbx-wcheck"
cd "$ROOT" && exec "$@"
`;

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

  // Write confinement is built with this utility. No utility, no confinement,
  // no run — there is deliberately no branch that proceeds without it.
  const mountBin = resolveMountBin();
  if (!mountBin) {
    return errorResult('namespace',
      'no filesystem-attach binary found on this host, so write confinement cannot be established; refusing to execute unconfined');
  }

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

  // Fail closed: no usable variant means the confinement cannot be
  // established, so nothing is executed. There is deliberately no path that
  // drops confinement flags and runs anyway.
  const nsArgs = resolveNamespaceArgs(bin, allowNetwork);
  if (!nsArgs) {
    return errorResult('namespace', 'kernel namespaces could not be created on this host (unprivileged user-namespace creation appears to be denied); refusing to execute unconfined');
  }

  // The canary lives OUTSIDE the sandbox root, in a directory this process
  // just created and can write. If the confined shell can create it, the
  // confinement is not in force and the command is not run.
  let canaryDir = null;
  try {
    canaryDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-sbx-canary-'));
  } catch (e) {
    return errorResult('namespace', `could not create the confinement canary: ${e.message}`);
  }
  const canary = path.join(canaryDir, 'out-of-root.canary');

  let r;
  try {
    r = spawnSync(
      bin,
      [...nsArgs, '/bin/sh', '-c', prelude + SETUP_SCRIPT, '_sbx', ...argv],
      {
        encoding: 'utf8',
        timeout: timeoutMs,
        maxBuffer,
        cwd: resolvedRoot,
        env: {
          ...buildConfinedEnv({ root: resolvedRoot, env }),
          SBX_MOUNT: mountBin,
          SBX_PRIVDROP: resolvePrivDropBin() || '',
          SBX_CANARY: canary,
          SBX_FINAL: FINAL_SCRIPT,
        },
      },
    );

    // Parent-side confirmation of the same fact the canary check asserts from
    // the inside. Cheap, and it does not depend on the confined shell being
    // honest about its own exit code.
    if (fs.existsSync(canary)) {
      return errorResult('namespace',
        'the confined process created a file outside the sandbox root: write confinement is NOT in force on this host');
    }
  } finally {
    try { fs.rmSync(canaryDir, { recursive: true, force: true }); } catch { /* best effort */ }
  }

  const rawStderr = r.stderr ?? '';
  const setupFailure = _setupFailureReason(rawStderr);
  if (setupFailure && !r.error) {
    // Confinement could not be established (or could not be proven). Nothing
    // ran: the shell exits before `exec`ing the caller's command.
    return errorResult('namespace', `confinement could not be established: ${setupFailure}`);
  }

  const effectiveUnsupported = [...unsupported];
  if (rawStderr.includes(MARK_NO_PRIVDROP)) effectiveUnsupported.push('privilegeDrop');

  return buildResult({
    backend: 'namespace',
    spawnResult: { ...r, stderr: _cleanStderr(rawStderr) },
    unsupported: effectiveUnsupported,
  });
}
