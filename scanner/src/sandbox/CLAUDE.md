# src/sandbox/

Confined execution facility for running untrusted target code and candidate
exploits (R1 of `docs/ROADMAP.md`). This is a hard prerequisite for anything
that executes code the scanner did not write — no other module in this
repository runs target code, confined or otherwise.

## Entry point

Everything goes through `index.js`:

- `sandboxAvailable() -> boolean` — true iff a real confinement primitive was
  detected on this host.
- `runConfined(argv, opts) -> { status, denied, stdout, stderr, exitCode, timedOut, backend }`
  — dispatches to whichever backend `detectBackend()` selected. `opts.force`
  overrides detection (used by tests, and by any caller that wants to force
  the disabled path deliberately).

`status` is one of `'ok' | 'blocked' | 'nonzero' | 'timeout' | 'disabled' |
'error'`. All three backends return the identical shape, so callers never
branch on which backend ran. **`runConfined` never throws** — a missing
`root`, an unresolvable root, a missing confinement binary, or an invalid
resource limit all return `status: 'error'` in the normal shape. (A caller
that wraps it in `try`/`catch` and "falls back" is a classic route to
unconfined execution, so there is nothing to catch.)

## `blocked` vs `nonzero` vs `ok` — and the limit of what is observable

An earlier version derived `status` purely from the exit code, which conflated
two unrelated outcomes: a program that ran fine and exited 3 was reported
`'blocked'`, while a program whose out-of-root write was **denied** but which
exited 0 was reported `'ok'` — a clean run, as far as the caller could tell.
Both are now separated:

| Field | Meaning |
|---|---|
| `denied: true` | A confinement violation was **observed** in the confined process's error output. |
| `status: 'blocked'` | `denied` was true — something was refused. |
| `status: 'nonzero'` | The command exited non-zero with **no** denial observed. Ordinary program failure, not a confinement event. |
| `status: 'ok'` | Exited 0 with no denial observed. |

**What `denied: false` does not mean.** The signal is read from the confined
process's own stderr — these OS primitives give the parent no structured
violation channel. A program that writes outside the root and swallows its own
error message produces no signal at all, so `denied: false` means "no denial
was observed", **not** "no denial occurred". `status: 'ok'` is proof that the
command exited 0 and said nothing about a refusal; it is **not** proof that
the sandbox refused nothing. Downstream consumers (e.g. an R2 execution
verification tier) must not read `'ok'` as "ran unimpeded". The reliable
negative evidence remains the one the escape tests use: check for the side
effect (the out-of-root file does not exist), not the status.

## Backend selection (`capabilities.js`) — functional, not presence-based

`detectBackend({ force })` selects a backend by **executing a trivial command
(`exit 0`) through that backend's real code path** and reporting the backend
only if that run succeeds. Availability means "confinement demonstrably works
here", never "the confinement binary is installed".

| Platform | Candidate backend | Selected when |
|---|---|---|
| macOS family | `'userspace'` | a trivial command ran confined and returned `status:'ok'` |
| Linux family | `'namespace'` | a trivial command ran confined and returned `status:'ok'` |
| any | `'disabled'` | no candidate's probe succeeded |

A candidate whose probe fails is **skipped**, detection falls through to the
next candidate, and with nothing left the answer is `'disabled'`. The probe is
never allowed to pass by weakening confinement: there is no branch that drops a
flag to get a green run, because a backend that can only succeed unconfined is
not an available backend.

**Why presence was the wrong question.** Verified on a Linux CI runner: the
kernel-namespace tool is installed and executable, but the distribution
restricts unprivileged user-namespace creation, so every privilege variant in
`backend-namespace.js` fails and no confined command can start. Presence-based
detection reported `'namespace'` and `sandboxAvailable()` answered `true` while
every actual run failed. `sandboxAvailable()` is the signal callers use to
decide whether it is safe to **execute untrusted code**; answering "the tool is
installed" when the honest answer is "confinement does not work here" is false
assurance of exactly the kind this module exists to prevent.

**On a host that restricts unprivileged namespace creation, the backend
therefore reports unavailable and the execution features that depend on it are
DISABLED — not degraded.** `detectBackend()` returns `'disabled'`,
`sandboxAvailable()` returns `false`, `runConfined` refuses to execute, and
`execution-proof.js` leaves findings at their static tier with a reason naming
the sandbox. Nothing runs unconfined and no weaker confinement is substituted.
The sandbox-dependent tests in `sandbox-escape.test.js` and
`execution-proof.test.js` skip there, each with an explicit
"SKIPPED, NOT PASSED … UNVERIFIED here" reason — a skip is a declared gap in
verification, never a pass.

**Cost and bounds.** The probe costs one spawn and its result (positive *and*
negative) is cached for the process, so ordinary scans pay it at most once;
`resetCapabilityCache()` clears it. The probe runs with a short timeout
(4 s default, `AGENTIC_SECURITY_SANDBOX_PROBE_TIMEOUT_MS` to override) and a
throw is treated as a failure, so a capability check can never hang a scan.
`force` bypasses probing entirely.

`detectBackend` also accepts `{ probes, candidates }` — a test seam that drives
the selection contract with stand-ins on any platform. It cannot produce
unconfined execution: dispatch in `index.js` still goes to the real backend.

Each primitive's binary is resolved across a **candidate list** of plausible
install paths (`CONFINE_BINS_USERSPACE` / `CONFINE_BINS_NAMESPACE`), not a
single hardcoded path, and that lookup now serves only as a cheap fast-negative
before the real probe. A miss still fails closed to `'disabled'`, which is safe
— but a single path would be a false negative on any distribution that installs
the binary elsewhere, silently costing that host its sandbox. The backends run
the resolved path, not the canonical one.

## Fail-closed rule

If no candidate backend's functional probe succeeds, `detectBackend` returns `'disabled'` and
`runConfined` dispatches to `backend-disabled.js`, which **refuses to execute
the command at all** — it returns `status: 'disabled'` without ever spawning
a process. There is no code path in this module that runs target code
unconfined. An unavailable sandbox disables the execution feature; it never
silently degrades to running the command directly. This is proven by an
executing test (`sandbox.test.js`): the disabled backend is invoked with a
command that would create a marker file, and the test asserts the file does
not exist afterward.

## What is verified on which platform

This module was developed and its tests run on a macOS host. Guarantees below
are stated per platform — do not extrapolate one platform's result to the
other.

**Userspace backend (macOS family) — verified by execution on this platform:**
- A write outside the sandbox root is blocked; the target file is never
  created.
- Outbound network connections are blocked.
- A wall-clock overrun stops the **direct child** (`status: 'timeout'`,
  `timedOut: true`) — but see "Timeout does not kill the process tree" below.
  This is not full termination and must not be described as such.
- Benign in-root work (writes inside the root, ordinary commands) still
  succeeds — the gate holds in both directions, not just the blocking one.
- Fork-storm containment is **weak, not strong, on this platform**. The
  process-count limit (`ulimit -u` / `RLIMIT_NPROC`) is a per-uid, **system-wide**
  cap here, not a per-process-tree cap — it counts every process the user
  owns on the whole machine, not just the sandboxed subtree. Ambient process
  count for a normal user on this host is on the order of several hundred, so
  any usable cap has to sit at "ambient + margin" or it starves the user's own
  unrelated processes before the sandboxed command even starts. That means a
  fork storm inside the sandbox can still spawn a meaningful number of
  processes — bounded to ambient-plus-margin, not to some small absolute
  number — before the cap bites. Treat this as a soft brake, not a hard wall.
- Address-space capping (`ulimit -v`) is **not enforceable** on this platform.
  `limits.js` (`buildLimitPrelude`) detects this and reports the limit in its
  `unsupported` array instead of emitting a `ulimit -v` line that would
  silently do nothing — an unenforced limit must never look like an enforced
  one.

**Kernel-namespace backend (Linux family) — implemented, NOT verified.** The
required namespace tool is absent on the macOS development host, so
`backend-namespace.js`'s escape tests skip there with a recorded reason rather
than being asserted against. Nothing in this guide should be read as a claim
that the namespace backend's isolation has been demonstrated by execution
anywhere. It must be verified on a Linux host — with the same both-direction
escape-attempt tests used for the userspace backend — before anything
downstream (e.g. an R2 execution-verification tier) relies on it.

**How it gets verified: the `sandbox-linux` CI job.** Hosted runners restrict
unprivileged user-namespace creation at the kernel's access-control layer, so
the functional probe fails there and the escape suite skips — which is why
this backend went unverified for so long. The `sandbox-linux` job in
`.github/workflows/ci.yml` relaxes that **host policy** for itself (it has
passwordless root) and then runs the existing suite unchanged. It relaxes a
restriction on creating namespaces; it does not relax a single assertion or
confinement flag. `scripts/sandbox-linux-verify.mjs` then prints the selected
backend and `RAN`/`SKIPPED` for every test and **exits non-zero unless the
kernel-namespace suite actually ran**, so a skip cannot be mistaken for a pass
in a green job. Whether the relaxation works on the current runner image is
itself a fact only a CI log can settle — until that log exists, everything in
the next section is "implemented, unverified".

**Privilege: the namespaces are acquired unprivileged, and the flag set is
probed rather than assumed.** Creating mount/PID/IPC/UTS/network namespaces
directly requires `CAP_SYS_ADMIN`; an ordinary CI account does not have it, so
asking for them bare fails with a permission error and the backend cannot start
at all. `resolveNamespaceArgs()` therefore tries an ordered list of
privilege-acquisition prefixes — user namespace with the invoking user mapped
to root inside it, then user namespace with the user mapped to itself, then no
prefix (which needs root) — and **executes a trivial command under each**,
selecting the first that actually succeeds. The result is cached per
binary/network shape and cleared by `resetCapabilityCache()`.

The confinement flags are identical across every variant and are **never
relaxed to make a run succeed**: `--net` is present in every probed variant
whenever `allowNetwork` is false, and `--mount` unconditionally, because the
write confinement is built inside that mount namespace — dropping either to
get a green run would remove a confinement. If no variant succeeds the backend returns
`status: 'error'` and **nothing is executed**, the same fail-closed rule as the
disabled backend. The selection contract (flags always present, `allowNetwork`
the only way `--net` is absent, `null` when every probe fails) is asserted by
executing tests in `sandbox.test.js` driven with stand-in binaries, so it holds
on any platform; whether a given kernel actually grants the namespaces is a
per-host fact only that host can answer.

**Write confinement: implemented, unverified.** This backend used to confine
network egress and nothing else — no remount, no bind mount, no `pivot_root`,
just a `cd` — so an absolute out-of-root write succeeded. That gap is now
closed in code:

1. A **private mount namespace** in which every mount point present at setup
   time is rebound **read-only**, and only the sandbox root is rebound
   read-write. An out-of-root write therefore fails with `EROFS`, whose error
   text is one of `result.js`'s denial patterns — so an escape attempt
   surfaces as `status:'blocked'` + `denied:true`, the same shape the
   userspace backend produces for the same attempt.
2. A **capability drop** (whole bounding + inheritable set, plus the `noroot`
   secure bits so uid 0 stops implying privilege) applied *after* the mounts
   and *before* the caller's command. Without it the payload would hold
   `CAP_SYS_ADMIN` over its own mount namespace — the namespaces are acquired
   via a user namespace — and could simply rebind the tree writable again.
3. A **per-run proof by execution**, not a reasoned expectation. The parent
   seeds a canary path *outside* the sandbox root; the confined shell, already
   in its final deprivileged state, attempts to create it and refuses to
   `exec` the caller's command if that write succeeds. The parent then
   re-checks the canary from outside, so the verdict does not depend on the
   confined shell being honest about its own exit code.

**Why read-only rebind and not `pivot_root`.** `pivot_root` is the stronger
primitive — after detaching the old root, out-of-root paths are absent from
the mount namespace rather than merely read-only. It was rejected for three
concrete reasons. (a) It requires materialising a system tree (shell, C
library, whatever a PoC invokes) inside the *caller's* sandbox root, polluting
a directory the caller owns and reads back. (b) It changes path semantics —
`$ROOT` becomes `/` — so the two backends stop being interchangeable for the
same caller input. (c) An out-of-root write would then fail with `ENOENT`,
indistinguishable from an ordinary missing path, which destroys the `denied`
signal exactly where it matters most. The read-only rebind keeps paths, keeps
the denial signal, and keeps both backends answering the same way.

**Fail-closed throughout.** No namespace variant, no filesystem-attach
utility, a mount tree that cannot be rebound read-only, a sandbox root that
cannot be rebound writable, or a canary that turns out writable — each returns
`status:'error'` with **nothing executed**. There is no branch that proceeds
with the filesystem open.

**The one hardening that can be absent, and it is declared.** If the
privilege-dropping utility is not on the host, the command still runs under
the read-only mount tree but the result carries `privilegeDrop` in the
`unsupported` list (surfaced on stderr as `[sandbox] not enforceable here:
privilegeDrop`), the same mechanism `limits.js` uses for an unenforceable
limit. It is never silently skipped, and the escape test that covers the
rebind attack fails if it is missing rather than quietly passing.

**None of the above has been executed anywhere yet.** It is asserted by
`sandbox-escape.test.js`'s kernel-namespace suite, which skips on macOS. Until
a CI log shows that suite `RAN`, this section describes code, not evidence.

## Timeout does not kill the process tree

`timeoutMs` is enforced with `spawnSync`'s timeout, which signals **only the
process this module spawned**. Verified by execution on the macOS family: with
`timeoutMs: 1200`, a command that backgrounded a 4-second child returned
`status: 'timeout'` and the grandchild survived, completing its work *after*
the result was returned. So `'timeout'` means "we stopped waiting and killed
the process we spawned", not "the process tree was terminated". Survivors stay
inside the policy profile — their writes and egress remain confined — but they
are still running and still consuming resources. A caller that needs a hard
tree kill must implement it.

The namespace backend is structurally better here: it runs the confined
command under `--pid --fork`, so the direct child is pid 1 of a new PID
namespace and killing it should take the namespace's processes with it. That
is a reasoned expectation from the flags, **not** an executed result — it
needs the same Linux-host verification as everything else on that backend.

## Known limitation, deliberately accepted: reads are not confined

The userspace policy allows `(allow file-read*)` globally — that backend
confines **writes**, network egress, and resource use, but **not reads**. (The
kernel-namespace backend has the same cut: per the section above its mount
tree is rebound read-only, not detached, so everything on it stays readable.)
A confined command can read any file on the host the OS-level
permissions allow, including outside the sandbox root. Exfiltration of
readable host files (writing what was read to network or to a location the
attacker later reads through some other channel) is **out of scope for this
module**. This is a deliberate R1 scope cut, not an oversight: tightening
reads requires a threat model for what a confined process may legitimately
need to read, which belongs with the execution-verification work that
consumes this sandbox, not with the sandbox primitive itself.

### The parent environment is NOT one of the things a confined process may read

Secrets carried in the parent process's environment (API tokens, cloud keys,
registry auth) are a *distinct* exposure from unconfined file reads — the
sandbox would be handing them over rather than merely failing to hide them —
so they are not covered by the scope cut above. Every real backend therefore
runs the command with a **minimal constructed environment**
(`buildConfinedEnv` in `result.js`): `PATH`, `ROOT`, `HOME`, `TMPDIR`, `LANG`,
with `HOME`/`TMPDIR` pointed at the sandbox root. `process.env` is not
forwarded. A caller that genuinely needs a variable inside passes it
explicitly as `opts.env`, which is merged on top of the base — an opt-in, one
variable at a time, not a blanket export.

## Resource limits (`limits.js`)

`buildLimitPrelude({ maxProcs, maxFileSizeKb, maxAddressSpaceKb })` returns
`{ prelude, unsupported }`. `prelude` is a shell fragment of `ulimit` calls to
prefix before the confined command; `unsupported` lists any requested limit
that the current platform cannot enforce, so a caller can log or surface that
degradation rather than assume the limit applied silently.

Limit values are interpolated into a shell fragment, so they are **coerced
with `Number()` and rejected unless finite and non-negative** (`RangeError`,
which the backends turn into `status: 'error'`). Before that, a
config-supplied string such as `'999; echo INJECTED'` was emitted verbatim and
its payload ran — not an escape (the prelude runs inside the confinement) but
a way for a config-derived value to silently *disable* the limits it was
supposed to set.

## Extending this module

- Both real backends (`backend-userspace.js`, `backend-namespace.js`) must
  keep returning the exact same result shape as each other and as
  `backend-disabled.js` — callers dispatch on `status`/`backend`, not on
  which module ran.
- Any new backend must add its own both-direction escape test
  (`sandbox-escape.test.js`) before being wired into `index.js`: a `GOOD` case
  showing legitimate in-root work still succeeds, and one `BAD` case per
  escape vector the backend claims to block.
- Do not add a code path that runs a command when `detectBackend()` returns
  `'disabled'`. If a future backend needs a new capability check, add it to
  `detectBackend`, not around it.
