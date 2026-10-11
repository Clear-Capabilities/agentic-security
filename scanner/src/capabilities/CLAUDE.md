# src/capabilities/

Task capability manifests and runner-level enforcement of filesystem, structured
command and outbound network access (X-501 to X-504 of the differentiation PRD).
A hook explains a decision; the runner is what stops the task. Nothing here is
wired into `engine.js` or the scan/report path: a default scan is unchanged, and
the `capability-enforcement` feature (`posture/assurance/config.js`) is off by
default, operator-only (a project file can never turn it on) and advertised for
Linux only.

Suite: `npm run test:capabilities` (`test/capabilities/`, in `npm test` through
`scripts/run-unit-tests.mjs` SCOPES). Every criterion has a test named
`[X-50n.ACnn]`, both directions.

## Modules

| Module | Role |
|---|---|
| `manifest.js` | X-501. `validateManifest`, `bindManifest`, `deriveChild`, `manifestDigest`. Deny-by-default, closed-world, frozen. A bound manifest carries `binding = {taskId, revision, policyVersion, digest}`. `deriveChild` builds a child only from a subset of the parent (lexical AND symlink-resolved path containment, command argument modes, host/port/scheme/pin containment, limits, delegation depth); any widening is `SCOPE_EXPANSION` and yields NO manifest. |
| `decide.js` | X-501.AC02/AC03. `decide(bound, action, ctx)`: one deterministic, frozen, sanitized decision per action (`filesystem-read/write`, `command`, `network`, `tool`, `delegation`). The claimed binding must match. Unknown kinds, malformed actions and any exception are `deny`. Also owns the interpreter table and the shebang check. |
| `reasons.js` | The closed table of reason codes. `reason` is always the fixed sentence for the code; only `subject` is request-derived and it is redacted and length-capped. |
| `paths.js`, `address.js` | Path canonicalization (symlinks, `..`) and host/address classification (strict dotted quads, no numeric tail labels, mapped IPv6, metadata addresses). Pure helpers. |
| `secrets.js` | One scrubber: provider-shaped credentials (`mcp/redact.js` `redactSecretShapes`) plus assignment/entropy shapes (`llm-validator/redact.js`). `detectSecretShapes` (no entropy pass) is what argument checking uses. |
| `outbound.js` | X-504.AC02/AC03. `redactOutbound` (URL userinfo, secret query params, secret header names, JSON/form/text bodies, canary values in raw, URL-encoded and base64 forms), `sanitizeLogText`, `denialRecord` (class, host digest, port, scheme, code; never the host or any payload), `recordNetworkDenial` (appends to the existing `egress/audit.js` chain). |
| `proxy.js` | X-504.AC01. The one network door: a loopback HTTP proxy. Checks the declared destination, resolves the name once, checks the resolved addresses and connects to THAT address, filters plaintext HTTP, tunnels declared https opaquely, never follows a redirect. |
| `probes.js` | Active probes for `fs-read-confinement`, `fs-multi-root-write` and `network-mediation` (attack plus positive control), layered on `sandbox/control-probes.js`; `requiredControlsFor(manifest)`; `isAdvertisedBackend`; `platformStatements`. Results are cached per process and per backend. |
| `runner.js` | X-502/X-503. `runCapabilityTask(bound, {executable, args, env?, cwd?}, opts)`. Gate order: feature, platform, binding and secret-free environment, command policy, protected paths, backend, active probes. Then one supervised run. |
| `records.js` | Decisions as CORE-002 `capability-decision` records, and `advise` (the hook view: `hook-advisory`, never enforced). |
| `report.js` | `buildCapabilityReport`: per capability `requested` / `checked` (probe states) / `enforced`, plus resource enforcement and the standing limitations. |

## What is enforced, and by what

- **Filesystem.** `sandbox/backend-userspace.js` gained opt-in capability mode:
  `readRoots` (reads confined to a baseline of system paths plus the declared
  roots; metadata only for the ancestors of those roots, so other paths cannot be
  probed for existence), `writeRoots`, `cwd`, `networkProxyPort`. Absent, the
  profile is byte-for-byte what it was. Protected paths (key directory, home
  credential directories, label and evidence directories) are read-denied after
  every allow, and a manifest root that overlaps one is blocked before anything
  runs. The kernel stops symlink and `..` escapes; `decide` agrees and names why.
- **Commands.** Executable plus argument array, never a shell string. The array
  reaches `exec` as an array, so command substitution is text. Executables must
  be absolute, listed, not inside a writable root, and not an interpreter (known
  shells/runtimes/launchers by name, anything starting `#!`) unless declared
  `interpreter: 'scoped'` with exact pinned arguments. A secret-shaped argument
  or registered canary blocks the run. The environment is the sandbox's minimal
  one plus explicit non-secret variables.
- **Descendants.** They inherit the file and network confinement (it is the
  kernel's) and are tracked and terminated by `sandbox/supervise.js` on deadline,
  cancellation, output flood or exit. The result carries `cleanup`
  (`signalled`, `killedPids`, `survivors`, `complete`). NOT claimed: allowlisting
  the exec calls a descendant makes.
- **Network.** No network at all unless the manifest declares destinations; then
  exactly the proxy's loopback port is open in the profile, and the proxy URL is
  in the environment of the whole tree. A direct socket, a datagram, a name lookup
  or a local service socket is refused by the kernel. HTTPS is an opaque tunnel
  (payload not inspected; the report says `payloadFiltering: plaintext-http-only`).

## Enforcement status, stated plainly

`level` is `enforced` only when the backend is an advertised one (the kernel
namespace backend on Linux) AND every control the manifest depends on is
`proved`. On macOS the probes can prove the userspace controls on the host, and a
task can run there only when the caller passes `allowUnadvertisedBackend`; the
result is `level: 'host-proved'`, `enforced: false`, and every capability in the
report says so. Without the opt-in an isolation-required task is `unsupported`
(`platform-unsupported`). A control that is not proved BLOCKS the run (typed
`blocked`, `missing-execution-backend`, the target never executes).

**Linux is `partially-verified`**, and only by the hosted `sandbox-linux` job. Its
active probes proved write confinement, read denial, environment scrubbing, the
no-network default, tree termination, the file-size limit, read confinement to
declared roots and multi-root writes on the namespace backend (a pivoted tmpfs
root; protected paths absent or masked; a PID namespace the kernel tears down).
NOT verified: **mediated network** is not implemented on Linux (an empty network
namespace has no path to a proxy), so a task that declares a destination is
`blocked` there with `network-mediation is unsupported`, never allowed. The
**process-count cap** IS proved on Linux (the `sandbox-linux` job's `process-cap`
probe): the resource prelude runs under dash, whose `ulimit` has no `-u`, so the
namespace backend applies the cap with `prlimit --nproc` to the task's command
after the confinement is built, and `maxProcesses` in a manifest is passed through
and reported `enforced` when the run is at the `enforced` level (on macOS it stays
`unverified`: the cap is per-user and system-wide there). Memory caps are
`not-enforced`. The capability, trust-boundary and corpus suites RUN on the Linux
backend and assert Linux semantics (an undeclared path has no name, so a refusal
is ENOENT or EROFS rather than `denied`; liveness is judged by heartbeat, not host
pid; a declared network destination blocks the task); `sandbox-linux` fails if any
of them skips.

## Known limits (also in `REPORT_LIMITATIONS`)

Descendant exec is not allowlisted; ancestors of declared roots expose metadata;
the proxy accepts connections from any local process (it only forwards to the
declared set); a double-fork plus `setsid` between supervisor sweeps can outlive
a task; the policy layer is advisory wherever the runner is not the caller.

## Tool use, delegation, recovery, receipts, adversarial corpus (X-505 to X-508)

| Module | Role |
|---|---|
| `tool-registry.js` | X-505.AC01. The classification of every MCP tool (`read` / `mutating` / `external`) and the checks it requires before the handler runs. `test/capabilities/tools.test.js` compares it with `mcp/tools.js` `ALL_TOOLS` in both directions, so a new tool without a classification fails. |
| `tool-gate.js` | X-505. `createToolGate`: the check `mcp/server.js` makes before a handler, for the task identity bound to the server. Active when an operator-supplied `capabilityPolicy` is bound OR the operator enabled the feature in the environment (a project file never can). Feature on and no policy: read tools pass, mutating/external tools are `identity-missing`. A request-metadata task id that differs from the bound one is `identity-spoofed`. Unclassified tools are `tool-unclassified`. Decisions are `in-process-policy`, never `enforced`. |
| `delegate.js` | X-505.AC02. `delegate(parent, request, {binding, registry, guard})`: the one door for handing capabilities to another agent. Depth comes from the manifest chain (each hop needs a strictly lower `maxDepth`), the child is derived once by `deriveChild` (frozen, no partial grant), tool names compare exactly (no aliases), and a child task id is issued once (`registry`). |
| `hook-advice.js`, `hooks/lib/capability-advice.js` | X-505. What a hook says: the same `decide`, labelled `hook-advisory`, never blocking. Inert unless the operator set `AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT=1` AND `AGENTIC_SECURITY_CAPABILITY_MANIFEST=<file>`; wired into `dispatch-pre-tool.js` (edits), `pre-bash-guard.js` (a shell string is reported `unsupported`) and `capability-dispatch.js` (`Task`, `Agent`, `mcp__*`). Hook tool names are the HOST spelling (`mcp__srv__apply_fix`); the server gate sees the short name; there is no aliasing between the two. |
| `recovery.js` | X-506. `proposeChange` (missing capability plus the narrowest reviewable `{add}`; nothing proposed for key/label/link/secret/metadata refusals), `mediate` (one decision, `ok` or `blocked`, never a fallback), `createDenialGuard` (finite per-action retries and a per-task denial budget, reset only by a new policy version), `signPolicyGrant` (signer domain only) and `applyPolicyChange` (Ed25519 grant bound to the exact from/to manifest digests, short window, single use, finite changes per task; creates policy version N+1, appends to a hash-chained `createPolicyLedger`, reruns preflight). The worker has no signing key, so it cannot grant itself an exception. |
| `receipts.js` | X-507. Hash-chained receipts (`start` with the runner's observed backend, level and control states, `decision`, `outcome`, `end` seal naming every decision id), signed in the signer domain with the self-issued trust label from `posture/evidence-bundle.js`. `createReceiptRecorder` needs a domain that may write authoritative evidence (verifier), `signReceiptChain` a domain that may read the signing key (signer). `verifyReceiptEnvelope` needs only the public key and returns `label`: `fully-enforced` only for a complete, intact, current chain whose runner reached `enforced` with every control proved; otherwise `incomplete-audit-trail`, `superseded-policy`, `host-proved-not-enforced`, `not-run`, `tampered`. `receiptReport` reads requested / checked / enforced from the SIGNED start receipt. |
| `attack-coverage.js` | X-508. `buildAttackCoverage` and `enforcedModeReleaseGate` over the corpus results. A mandatory leak, error or uncovered class blocks; a skipped mandatory case or a non-`enforced` level makes enforced mode unreleasable without being a failure; a reproduced documented limit is reported in the notes. |

`test/capabilities/adversarial/corpus.js` is the disposable malicious-repository corpus (injection text, build
scripts, canaries outside the repository, recording servers). Execution cases skip loudly where no userspace
backend is probed; policy cases run everywhere. Mandatory cases must be blocked with no canary leak. One
non-mandatory case (`DE-03`) records a documented limit honestly: a detached grandchild whose parent exits
before the next supervisor sweep can outlive the task, with confinement still holding (it reads no secret
and reaches no destination). That outcome is `known-limit`, not `blocked`. Passing the corpus shows these
attempts were stopped on this backend in this run; it does not show the sandbox is secure against all attempts.

### What is still not claimed

Tool and delegation checks are policy at the tool boundary (the tool then runs in the server process): the
runner remains the only enforcement layer. Linux is `partially-verified` in the platform statement (the controls listed there, on the hosted job only) and the attack-coverage record keeps `platforms.linux: 'unverified'` as a standing statement even though the corpus now runs on the hosted Linux runner inside the capabilities suite: turning that into a verified claim is a decision for the owners, not a side effect of the suite passing. The enforced-mode release gate (`enforcedModeReleaseGate`) is a library
function used by the suite; it is not yet called from `scripts/release-check.mjs`.
