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

## Backend selection (`capabilities.js`)

`detectBackend({ force })` probes for one confinement primitive, cached after
the first call (`resetCapabilityCache()` clears it, used between tests):

| Platform | Primitive checked | Backend selected |
|---|---|---|
| macOS family | userspace confinement binary present and executable | `'userspace'` |
| Linux family | kernel-namespace tool present and executable | `'namespace'` |
| neither found | — | `'disabled'` |

Each primitive is probed across a **candidate list** of plausible install
paths (`CONFINE_BINS_USERSPACE` / `CONFINE_BINS_NAMESPACE`), not a single
hardcoded path. A miss still fails closed to `'disabled'`, which is safe — but
a single path would be a false negative on any distribution that installs the
binary elsewhere, silently costing that host its sandbox. The backends run the
resolved path, not the canonical one.

## Fail-closed rule

If no primitive is found, `detectBackend` returns `'disabled'` and
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

**Kernel-namespace backend (Linux family) — implemented, NOT verified on this
platform.** The required namespace tool is absent on the macOS development
host, so `backend-namespace.js`'s escape tests skip with a recorded reason
rather than being asserted against. Nothing in this guide should be read as a
claim that the namespace backend's isolation has been demonstrated by
execution anywhere. It must be verified on a Linux host — with the same
both-direction escape-attempt tests used for the userspace backend — before
anything downstream (e.g. an R2 execution-verification tier) relies on it.

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
whenever `allowNetwork` is false, because network egress is the only
confinement this backend implements — dropping it to get a green run would
leave nothing confined. If no variant succeeds the backend returns
`status: 'error'` and **nothing is executed**, the same fail-closed rule as the
disabled backend. The selection contract (flags always present, `allowNetwork`
the only way `--net` is absent, `null` when every probe fails) is asserted by
executing tests in `sandbox.test.js` driven with stand-in binaries, so it holds
on any platform; whether a given kernel actually grants the namespaces is a
per-host fact only that host can answer.

**And it confines less than "unverified" suggests. Writes are NOT confined on
this backend — that is false by inspection, not merely undemonstrated.** The
backend enters new mount/PID/IPC/UTS namespaces and, by default, an empty
network namespace. The empty network namespace is the *only* confinement it
implements: it has no route anywhere, which denies egress. For the
filesystem there is **no remount, no bind mount and no `pivot_root`** — only a
`cd` into the sandbox root. `cd` sets the working directory; it does not
restrict where a process may write. A confined command writing to an absolute
path outside the root (a home directory, a system config path) will
**succeed**, subject only to ordinary filesystem permissions. The new mount
namespace isolates mount-table *changes* made by the confined process; it does
not make the host filesystem read-only.

On a Linux host `detectBackend()` selects this backend automatically, so a
caller there gets network isolation and resource limits and **no write
confinement at all**. Do not run anything on that path that must not touch the
host filesystem. Closing the gap means implementing a read-only remount (or
equivalent) *and* verifying it by execution on a Linux host with both-direction
escape tests — the guide must not claim write confinement here before both
have happened.

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
kernel-namespace backend confines *less* than that: per the section above, it
implements network isolation only and does **not** confine writes at all.)
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
