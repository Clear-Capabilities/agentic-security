export const id = 259;
export const ids = [259];
export const modules = {

/***/ 8259:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  proveFinding: () => (/* binding */ proveFinding)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(3024);
// EXTERNAL MODULE: external "node:os"
var external_node_os_ = __webpack_require__(8161);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(6760);
// EXTERNAL MODULE: external "node:child_process"
var external_node_child_process_ = __webpack_require__(1421);
;// CONCATENATED MODULE: ./src/sandbox/limits.js
// Resource caps applied as a shell prelude, shared by every real backend.
//
// Address-space capping (`ulimit -v`) is NOT enforced on the macOS family —
// verified by execution. We therefore DECLARE it unsupported rather than
// emitting a limit that silently does nothing, which would be a false
// assurance of containment.


// `ulimit -u` (RLIMIT_NPROC) is charged per *uid*, system-wide, on both
// platforms this module supports — it is not a per-process-tree cap. A fixed
// default like the 64 below therefore breaks ordinary, non-adversarial runs on
// any host whose user already owns more than ~64 processes, which is most of
// them: the confined shell cannot even fork the helpers it needs to set itself
// up, and the failure looks like a broken sandbox rather than a cap doing its
// job. So unless a caller passes an explicit `maxProcs`, both real backends
// derive one from the ambient count for this uid. That keeps default behaviour
// usable without pretending a low fixed cap is real containment — see the
// "fork-storm containment is weak" note in the module guide.
function ambientRelativeMaxProcs(headroom = 64) {
  let ambient = 200;
  try {
    const out = (0,external_node_child_process_.spawnSync)('/bin/sh', ['-c', 'ps -U "$(id -un)" -o pid= | wc -l'], { encoding: 'utf8' });
    ambient = Number(String(out.stdout || '').trim()) || 200;
  } catch { /* fall through to the conservative default */ }
  return ambient + headroom;
}

function buildLimitPrelude({
  maxProcs = 64,
  maxFileSizeKb = 65536,
  maxAddressSpaceKb = null,
} = {}) {
  const parts = [];
  const unsupported = [];

  if (maxProcs != null) parts.push(`ulimit -u ${_num('maxProcs', maxProcs)}`);
  if (maxFileSizeKb != null) parts.push(`ulimit -f ${_num('maxFileSizeKb', maxFileSizeKb)}`);

  if (maxAddressSpaceKb != null) {
    if (process.platform === 'linux') parts.push(`ulimit -v ${_num('maxAddressSpaceKb', maxAddressSpaceKb)}`);
    else unsupported.push('maxAddressSpaceKb');
  }

  const prelude = parts.length ? parts.join('; ') + '; ' : '';
  return { prelude, unsupported };
}

/**
 * Limit values are interpolated into a shell fragment, so a non-numeric value
 * is shell text. Verified by execution: `maxProcs: '999; echo INJECTED'`
 * emitted `ulimit -u 999; echo INJECTED` and the payload ran. That is not a
 * sandbox escape (the prelude runs INSIDE the confinement) but it lets a
 * config-derived value silently DISABLE the very limits it was meant to set —
 * e.g. `'0 2>/dev/null; true'` swallows the failure. Coerce and reject
 * anything that is not a finite, non-negative number.
 */
function _num(name, v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) {
    throw new RangeError(`${name} must be a finite, non-negative number (got ${JSON.stringify(v)})`);
  }
  return Math.floor(n);
}

;// CONCATENATED MODULE: ./src/sandbox/result.js
// Shared result construction for every real backend.
//
// WHY THIS EXISTS (the misread it prevents): status used to be derived purely
// from the exit code — `exitCode !== 0` was reported as `'blocked'`. That
// conflates two entirely different outcomes:
//
//   1. A program that ran fine and chose to exit non-zero (a failing test, a
//      grep with no match) was labelled 'blocked' — a false confinement claim.
//   2. A program whose out-of-root write was DENIED but which still exited 0
//      was labelled 'ok' — the caller saw a clean run and could not tell that
//      the sandbox had refused something. Verified by execution: the denied
//      write returns exit 0 when the command swallows the failure.
//
// So the two signals are now separated:
//
//   - `denied`  — a confinement violation was OBSERVED in the child's error
//                 output. Best effort, see the honesty note below.
//   - `status`  — 'blocked' when a denial was observed, 'nonzero' when the
//                 command merely exited non-zero with no denial signal, 'ok'
//                 only when it exited 0 with no denial signal.
//
// HONESTY NOTE — what `denied:false` does and does not mean. The denial signal
// is read from the confined process's own stderr (the OS primitives here do
// not hand the parent a structured violation channel). A program that writes
// out of root and swallows its own error message produces NO signal, so
// `denied:false` means "no denial was observed", NOT "no denial occurred".
// Never treat `status:'ok'` as proof that nothing was refused. It is proof
// only that the command exited 0 and said nothing about a refusal.

const DENIAL_PATTERNS = [
  /operation not permitted/i,
  /permission denied/i,
  /read-only file system/i,
  /deny file-write/i,
  /deny network/i,
  /network is unreachable/i,
];

/** True iff the confined process's error output shows an observed denial. */
function detectDenial(stderr) {
  const s = String(stderr || '');
  return DENIAL_PATTERNS.some((re) => re.test(s));
}

/**
 * Build the single result shape every backend returns. `status` is one of
 * 'ok' | 'blocked' | 'nonzero' | 'timeout' | 'disabled' | 'error'.
 */
function buildResult({ backend, spawnResult, unsupported = [] }) {
  const r = spawnResult;
  const rawStderr = r.stderr ?? '';
  const timedOut = r.error?.code === 'ETIMEDOUT';
  const denied = detectDenial(rawStderr);

  let status;
  if (timedOut) status = 'timeout';
  else if (r.error) status = 'error';
  else if (denied) status = 'blocked';
  else if (r.status !== 0) status = 'nonzero';
  else status = 'ok';

  return {
    status,
    denied,
    stdout: r.stdout ?? '',
    stderr: rawStderr + (unsupported.length ? `\n[sandbox] not enforceable here: ${unsupported.join(', ')}` : ''),
    exitCode: r.status ?? null,
    timedOut,
    backend,
  };
}

/** Documented-shape error result: runConfined never throws at its callers. */
function errorResult(backend, message) {
  return {
    status: 'error',
    denied: false,
    stdout: '',
    stderr: `agentic-security: ${message}`,
    exitCode: null,
    timedOut: false,
    backend,
  };
}

/**
 * Minimal environment handed to untrusted code. The parent environment is NOT
 * forwarded: it routinely carries credentials (tokens, cloud keys, registry
 * auth) and the confined program can read and exfiltrate them. This is a
 * distinct exposure from the accepted "reads are not confined" scope cut —
 * that one is about files on disk, this one is about secrets the parent hands
 * over for free. Callers that need extra variables pass them explicitly via
 * `opts.env`, which is merged on top of this base.
 */
function buildConfinedEnv({ root, env = {} } = {}) {
  return {
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    ROOT: root,
    HOME: root,
    TMPDIR: root,
    LANG: 'C',
    ...env,
  };
}

;// CONCATENATED MODULE: ./src/sandbox/backend-userspace.js
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

function runUserspace(argv, {
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
    resolvedRoot = external_node_fs_.realpathSync(root);
  } catch (e) {
    return errorResult('userspace', `sandbox root is not usable: ${e.message}`);
  }

  const effectiveLimits = {
    ...limits,
    maxProcs: limits.maxProcs ?? ambientRelativeMaxProcs(),
  };

  let prelude, unsupported;
  try {
    ({ prelude, unsupported } = buildLimitPrelude(effectiveLimits));
  } catch (e) {
    return errorResult('userspace', `invalid resource limit: ${e.message}`);
  }
  const inner = `${prelude}exec "$@"`;

  const r = (0,external_node_child_process_.spawnSync)(
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

;// CONCATENATED MODULE: ./src/sandbox/backend-namespace.js
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
// TIMEOUT SCOPE. The wall-clock timeout is `spawnSync`'s, which signals only
// the direct child. On this backend the direct child is the namespace tool
// running as pid 1 of a new PID namespace (`--pid --fork`), so killing it is
// expected to take the whole namespace's processes with it — better than the
// userspace backend, where a backgrounded grandchild demonstrably survives.
// "Expected", NOT verified, and this one did not clear with the rest: the
// escape suite has now RUN and passed on a Linux runner, but its wall-clock
// case asserts only that the DIRECT CHILD is stopped. No test observes whether
// a backgrounded grandchild dies with the PID namespace, so tree-kill remains
// a reasoned expectation. Do not state it as a guarantee until a test asserts
// the grandchild is gone.
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
# Belt and braces: the root was bound before the read-only pass and skipped by
# it, so this is normally a no-op. Its return code is NOT the gate — the
# executed in-root write check in $SBX_FINAL is, and that one fails closed.
"$SBX_MOUNT" -o remount,bind,rw "$ROOT" 2>/dev/null || true
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
function resolveNamespaceArgs(bin, allowNetwork, { probeTimeoutMs = 5000 } = {}) {
  const key = `${bin}:${allowNetwork ? 'net' : 'nonet'}`;
  const cached = cachedNamespaceVariant(key);
  if (cached !== undefined) return cached;

  let chosen = null;
  for (const variant of NS_PRIVILEGE_VARIANTS) {
    const args = _nsArgs(variant, allowNetwork);
    const probe = (0,external_node_child_process_.spawnSync)(bin, [...args, '/bin/sh', '-c', 'exit 0'], {
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

function runNamespace(argv, {
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
    resolvedRoot = external_node_fs_.realpathSync(root);
  } catch (e) {
    return errorResult('namespace', `sandbox root is not usable: ${e.message}`);
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
    canaryDir = external_node_fs_.mkdtempSync(external_node_path_.join(external_node_os_.tmpdir(), 'agsec-sbx-canary-'));
  } catch (e) {
    return errorResult('namespace', `could not create the confinement canary: ${e.message}`);
  }
  const canary = external_node_path_.join(canaryDir, 'out-of-root.canary');

  let r;
  try {
    r = (0,external_node_child_process_.spawnSync)(
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
    if (external_node_fs_.existsSync(canary)) {
      return errorResult('namespace',
        'the confined process created a file outside the sandbox root: write confinement is NOT in force on this host');
    }
  } finally {
    try { external_node_fs_.rmSync(canaryDir, { recursive: true, force: true }); } catch { /* best effort */ }
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

;// CONCATENATED MODULE: ./src/sandbox/capabilities.js
// Detects which OS confinement primitive is available. Fail-closed: when none
// is found we report 'disabled', which REFUSES execution rather than running
// target code unconfined.
//
// DETECTION IS FUNCTIONAL, NOT PRESENCE-BASED. An earlier version concluded
// "available" from "the confinement binary is executable". That is a different
// question from the one callers are actually asking. Verified on a Linux CI
// runner: the kernel-namespace tool is installed and executable, but the
// distribution restricts unprivileged user-namespace creation, so every
// privilege variant fails and no confined command can start. Presence-based
// detection reported the backend as available anyway, and `sandboxAvailable()`
// — the signal callers use to decide whether it is safe to EXECUTE UNTRUSTED
// CODE — answered true while nothing could actually be confined. False
// assurance about confinement is precisely the failure this module exists to
// prevent, so a backend now counts as available only if it just ran a trivial
// command through its real code path.
//
// The probe result is cached for the process (one spawn, not one per call —
// detection sits on the path of ordinary scans) and cleared by
// `resetCapabilityCache()`.






// Referenced by path, never by product name (see Global Constraints).
//
// Each family lists every plausible install location, probed in order. A
// single hardcoded path is safe (a miss fails closed to 'disabled') but it is
// a FALSE NEGATIVE: a host that does have the primitive somewhere else loses
// the sandbox silently. Probing the candidate set removes that failure mode.
const CONFINE_BINS_USERSPACE = Object.freeze([
  '/usr/bin/sandbox-exec',
  '/usr/local/bin/sandbox-exec',
]);
const CONFINE_BINS_NAMESPACE = Object.freeze([
  '/usr/bin/unshare',
  '/bin/unshare',
  '/usr/local/bin/unshare',
  '/sbin/unshare',
  '/usr/sbin/unshare',
]);

// The filesystem-attach utility used by the namespace backend to establish
// write confinement (read-only rebind of the whole mount tree, read-write
// rebind of the sandbox root). Resolved by path for the same reason as the
// others. Absent => the namespace backend cannot establish write confinement
// and fails closed; it never runs a command with the filesystem open.
const CONFINE_BINS_MOUNT = Object.freeze([
  '/usr/bin/mount',
  '/bin/mount',
  '/sbin/mount',
  '/usr/sbin/mount',
]);

// The privilege-dropping utility used to remove CAP_SYS_ADMIN (and everything
// else) from the confined process *after* the mounts are in place, so the
// payload cannot simply undo the read-only rebinds. Best-effort hardening on
// top of the mount confinement, not the confinement itself: when it is absent
// the run still happens under the read-only mount tree and the result declares
// `privilegeDrop` unenforced rather than staying silent about it.
const CONFINE_BINS_PRIVDROP = Object.freeze([
  '/usr/bin/setpriv',
  '/bin/setpriv',
  '/sbin/setpriv',
  '/usr/sbin/setpriv',
]);

// Back-compat single-path exports: the first (canonical) candidate.
const CONFINE_BIN_USERSPACE = CONFINE_BINS_USERSPACE[0];
const CONFINE_BIN_NAMESPACE = CONFINE_BINS_NAMESPACE[0];

let _cached = null;

// Which namespace-flag variant actually works on this host, keyed by the
// requested confinement shape. Probing costs a process spawn, so it is done
// once; `undefined` means "not probed yet", `null` means "probed and nothing
// worked" (which the backend turns into a fail-closed error, never a run).
const _nsVariant = new Map();

function resetCapabilityCache() { _cached = null; _nsVariant.clear(); }

function cachedNamespaceVariant(key) {
  return _nsVariant.has(key) ? _nsVariant.get(key) : undefined;
}
function cacheNamespaceVariant(key, value) { _nsVariant.set(key, value); }

/** First executable candidate, or null when none of them exists. */
function resolveConfineBin(candidates) {
  for (const p of candidates) if (_isExecutable(p)) return p;
  return null;
}

function resolveUserspaceBin() { return resolveConfineBin(CONFINE_BINS_USERSPACE); }
function resolveNamespaceBin() { return resolveConfineBin(CONFINE_BINS_NAMESPACE); }
function resolveMountBin() { return resolveConfineBin(CONFINE_BINS_MOUNT); }
function resolvePrivDropBin() { return resolveConfineBin(CONFINE_BINS_PRIVDROP); }

// Bounded on purpose: a capability check must never hang a scan. The probe is
// a single `exit 0` under confinement, so anything beyond a couple of seconds
// is a host that is not going to answer.
const PROBE_TIMEOUT_MS = Math.max(
  250,
  Number(process.env.AGENTIC_SECURITY_SANDBOX_PROBE_TIMEOUT_MS) || 4000,
);

/**
 * Run a trivial command through a backend's real code path and report whether
 * confinement actually worked. Anything other than a clean confined run — a
 * missing binary, a refused namespace, a timeout, a throw — is `false`. There
 * is deliberately no branch that relaxes confinement to make a probe pass: a
 * backend that can only succeed with a flag dropped is not available, it is
 * `'disabled'`.
 */
function _probeThroughBackend(runner) {
  let root = null;
  try {
    root = external_node_fs_.mkdtempSync(external_node_path_.join(external_node_os_.tmpdir(), 'agsec-sbx-probe-'));
    const r = runner(['/bin/sh', '-c', 'exit 0'], { root, timeoutMs: PROBE_TIMEOUT_MS });
    return r?.status === 'ok';
  } catch {
    return false;
  } finally {
    if (root) { try { external_node_fs_.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ } }
  }
}

/**
 * The real probes, one per backend. The binary check stays only as a cheap
 * pre-filter that avoids a pointless temp dir on a host that plainly lacks the
 * primitive — it is no longer the answer, just the fast negative.
 */
function defaultProbes() {
  return {
    userspace: () => (resolveUserspaceBin() ? _probeThroughBackend(runUserspace) : false),
    namespace: () => (resolveNamespaceBin() ? _probeThroughBackend(runNamespace) : false),
  };
}

/** Backends worth probing on a platform, most-appropriate first. */
function backendCandidates(platform = process.platform) {
  if (platform === 'darwin') return ['userspace'];
  if (platform === 'linux') return ['namespace'];
  return [];
}

/**
 * @param {object}   [o]
 * @param {string}   [o.force]      Bypass detection entirely (tests, and callers
 *                                  that want the disabled path deliberately).
 * @param {object}   [o.probes]     Probe map override — a seam for tests to drive
 *                                  the selection contract with stand-ins on any
 *                                  platform. Cannot cause unconfined execution:
 *                                  dispatch still goes to the real backend.
 * @param {string[]} [o.candidates] Candidate order override (same seam).
 */
function detectBackend({ force, probes, candidates } = {}) {
  if (force) return force;
  if (_cached) return _cached;

  const probeMap = probes || defaultProbes();
  const order = candidates || backendCandidates();

  let b = 'disabled';
  for (const name of order) {
    const probe = probeMap[name];
    if (typeof probe !== 'function') continue;
    let works = false;
    try { works = probe() === true; } catch { works = false; }
    if (works) { b = name; break; }
    // Otherwise fall through to the next candidate, and ultimately to
    // 'disabled' — never to "run it anyway".
  }
  _cached = b;
  return b;
}

function _isExecutable(p) {
  try { external_node_fs_.accessSync(p, external_node_fs_.constants.X_OK); return true; } catch { return false; }
}

;// CONCATENATED MODULE: ./src/sandbox/backend-disabled.js
// Fail-closed backend. Selected when no confinement primitive is available.
// It must NEVER execute the command — an unavailable sandbox disables
// execution features, it does not bypass them.
function runDisabled(_argv, _opts) {
  return {
    status: 'disabled',
    denied: false,
    stdout: '',
    stderr: 'agentic-security: refusing to execute — no confinement primitive available on this host.',
    exitCode: null,
    timedOut: false,
    backend: 'disabled',
  };
}

;// CONCATENATED MODULE: ./src/sandbox/index.js
// Single entry point for confined execution.
//
// Fail-closed by construction: when no confinement primitive is available the
// disabled backend is selected, which REFUSES to execute. There is deliberately
// no code path that runs target code unconfined.
//
// Result shape (identical for every backend):
//   { status, denied, stdout, stderr, exitCode, timedOut, backend }
// status: 'ok' | 'blocked' | 'nonzero' | 'timeout' | 'disabled' | 'error'.
// See result.js for what 'blocked' vs 'nonzero' mean and, importantly, what
// `denied:false` does NOT prove. runConfined never throws — a bad root or an
// invalid limit returns status 'error', because a caller that catches and
// falls back is a route to unconfined execution.







function sandboxAvailable() {
  return detectBackend() !== 'disabled';
}

function runConfined(argv, opts = {}) {
  const backend = detectBackend({ force: opts.force });
  if (backend === 'userspace') return runUserspace(argv, opts);
  if (backend === 'namespace') return runNamespace(argv, opts);
  return runDisabled(argv, opts);
}

;// CONCATENATED MODULE: ./src/posture/proof-tier.js
// How strongly a finding is backed by evidence.
//
//   execution-proven — a proof-of-concept RAN inside the sandbox and produced
//                      the predicted observable effect. The strongest claim.
//   proof-failed     — a proof-of-concept ran and did NOT demonstrate the bug.
//                      A triage signal, NOT an automatic false-positive verdict:
//                      absence of proof is not proof of absence.
//   taint-proven     — the analyser's static reasoning found it; nothing executed.
//   unproven         — no analyser backing recorded.
const PROOF_TIERS = Object.freeze([
  'execution-proven', 'proof-failed', 'taint-proven', 'unproven',
]);

// Parsers that represent real analysis rather than a plain pattern match.
const _ANALYSED = new Set(['IR-TAINT', 'MULTI-SINK']);

function proofTierOf(finding) {
  if (finding?.proofTier) return finding.proofTier;
  return _ANALYSED.has(finding?.parser) ? 'taint-proven' : 'unproven';
}

function attachProofTier(finding, evidence) {
  if (!PROOF_TIERS.includes(evidence?.tier)) {
    throw new Error(`unknown proof tier: ${evidence?.tier}`);
  }
  let tier = evidence.tier;
  // Guard the central honesty rule: nothing that did not RUN may be called
  // execution-proven or proof-failed. Fall back to the finding's static standing.
  if (!evidence.ran && (tier === 'execution-proven' || tier === 'proof-failed')) {
    tier = proofTierOf({ ...finding, proofTier: undefined });
  }
  return { ...finding, proofTier: tier, proofEvidence: { ...evidence, tier } };
}

;// CONCATENATED MODULE: ./src/posture/execution-proof.js
// Promote a finding to execution-proven by running its proof-of-concept inside
// the confined execution sandbox and observing a real effect.
//
// Proof is a file the PoC writes, NOT an exit code: the sandbox cannot reliably
// distinguish "denied" from "ran and exited 0", so exit status is not evidence.






const PROOF_MARKER = 'PROVEN';

function _evidence(over = {}) {
  return {
    tier: 'taint-proven', backend: detectBackend(), ran: false, observed: null,
    reason: null, exitCode: null, timedOut: false, at: new Date().toISOString(), ...over,
  };
}

// A run that never got as far as executing the PoC. `ran:false` for these is
// the whole point: 'proof-failed' asserts "the PoC ran and the predicted effect
// did not appear", which is a triage signal about the FINDING. A sandbox that
// could not start says nothing about the finding at all, and must leave it at
// its static tier rather than manufacturing a failed exploit attempt.
const _DID_NOT_EXECUTE = new Set(['disabled', 'error']);

// Materialise caller-supplied files into the sandbox root so a PoC can import
// the code it is supposed to exploit. Paths are confined to the root: an
// absolute path or one that climbs out is refused rather than clamped, because
// silently rewriting a path would put a file somewhere the caller did not ask
// for and the PoC would then exercise the wrong code.
function _materialise(root, files) {
  for (const [rel, content] of Object.entries(files || {})) {
    if (typeof content !== 'string') continue;
    const abs = external_node_path_.resolve(root, rel);
    if (abs !== root && !abs.startsWith(root + external_node_path_.sep)) {
      return `refusing to write '${rel}': it resolves outside the sandbox root`;
    }
    external_node_fs_.mkdirSync(external_node_path_.dirname(abs), { recursive: true });
    external_node_fs_.writeFileSync(abs, content, 'utf8');
  }
  return null;
}

/**
 * @param {object} finding    carries `poc: {lang, code}`
 * @param {object} [opts]
 * @param {object} [opts.files]  rel→content written into the sandbox root before
 *   the PoC runs. This is what lets the SAME PoC be run against a candidate
 *   patch: pass the patched contents and a still-`execution-proven` verdict
 *   means the fix did not close the hole.
 */
async function proveFinding(finding, { timeoutMs = 10000, force, files } = {}) {
  const poc = finding?.poc;
  if (!poc?.code) {
    return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: 'no proof-of-concept attached' }));
  }
  if (poc.lang !== 'js') {
    return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: `unsupported poc language: ${poc.lang}` }));
  }
  if (!sandboxAvailable()) {
    return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: 'no confinement primitive available; refusing to execute' }));
  }

  const root = external_node_fs_.realpathSync(external_node_fs_.mkdtempSync(external_node_path_.join(external_node_os_.tmpdir(), 'proof-')));
  try {
    const badPath = _materialise(root, files);
    if (badPath) {
      return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: badPath }));
    }
    external_node_fs_.writeFileSync(external_node_path_.join(root, 'poc.mjs'), poc.code, 'utf8');
    const r = runConfined([process.execPath, 'poc.mjs'], { root, timeoutMs, force });
    const proven = external_node_fs_.existsSync(external_node_path_.join(root, PROOF_MARKER));
    const ran = !r.timedOut && !_DID_NOT_EXECUTE.has(r.status);

    return attachProofTier(finding, _evidence({
      tier: proven ? 'execution-proven' : ran ? 'proof-failed' : proofTierOf(finding),
      backend: r.backend,
      ran,
      observed: proven ? `proof marker '${PROOF_MARKER}' written by the proof-of-concept` : null,
      reason: proven ? null
        : r.status === 'error' ? `the confinement sandbox could not start, so the proof-of-concept never executed (${r.backend} backend): ${String(r.stderr || '').trim() || 'no detail reported'}`
        : r.status === 'disabled' ? 'confined execution is disabled; the proof-of-concept was refused and never executed'
        : r.timedOut ? 'proof-of-concept exceeded its time budget'
        : 'proof-of-concept ran but did not demonstrate the predicted effect',
      exitCode: r.exitCode, timedOut: r.timedOut,
    }));
  } finally {
    external_node_fs_.rmSync(root, { recursive: true, force: true });
  }
}


/***/ })

};
