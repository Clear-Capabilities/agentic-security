# src/sandbox/

Confined execution facility for running untrusted target code and candidate
exploits (R1 of `docs/ROADMAP.md`). This is a hard prerequisite for anything
that executes code the scanner did not write — no other module in this
repository runs target code, confined or otherwise.

## Entry point

Everything goes through `index.js`:

- `sandboxAvailable() -> boolean` — true iff a real confinement primitive was
  detected on this host.
- `runConfined(argv, opts) -> { status, stdout, stderr, exitCode, timedOut, backend }`
  — dispatches to whichever backend `detectBackend()` selected. `opts.force`
  overrides detection (used by tests, and by any caller that wants to force
  the disabled path deliberately).

`status` is one of `'ok' | 'blocked' | 'timeout' | 'disabled' | 'error'`. All
three backends return the identical shape, so callers never branch on which
backend ran.

## Backend selection (`capabilities.js`)

`detectBackend({ force })` probes for one confinement primitive, cached after
the first call (`resetCapabilityCache()` clears it, used between tests):

| Platform | Primitive checked | Backend selected |
|---|---|---|
| macOS family | userspace confinement binary present and executable | `'userspace'` |
| Linux family | kernel-namespace tool present and executable | `'namespace'` |
| neither found | — | `'disabled'` |

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
- A wall-clock overrun is terminated (`status: 'timeout'`, `timedOut: true`).
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

## Known limitation, deliberately accepted: reads are not confined

The userspace policy allows `(allow file-read*)` globally — every backend in
this module confines **writes**, network egress, and resource use, but **not
reads**. A confined command can read any file on the host the OS-level
permissions allow, including outside the sandbox root. Exfiltration of
readable host files (writing what was read to network or to a location the
attacker later reads through some other channel) is **out of scope for this
module**. This is a deliberate R1 scope cut, not an oversight: tightening
reads requires a threat model for what a confined process may legitimately
need to read, which belongs with the execution-verification work that
consumes this sandbox, not with the sandbox primitive itself.

## Resource limits (`limits.js`)

`buildLimitPrelude({ maxProcs, maxFileSizeKb, maxAddressSpaceKb })` returns
`{ prelude, unsupported }`. `prelude` is a shell fragment of `ulimit` calls to
prefix before the confined command; `unsupported` lists any requested limit
that the current platform cannot enforce, so a caller can log or surface that
degradation rather than assume the limit applied silently.

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
