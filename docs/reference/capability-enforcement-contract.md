# Runner-level capability enforcement: contract

The frozen shape and behaviour of runner-level capability enforcement (`scanner/src/capabilities/`): the task capability manifest (schema `agentic-security/capability-manifest`, version `1.0.0`) and its validation refusals, the binding a manifest is valid for, the policy decision and its closed reason codes, the capability decision record (schema `agentic-security/capability-decision`, version `1.0.0`), the operator-only feature switch, the per-platform status statements, the runner's refusal results and the capability report (version 1). The test `scanner/test/contracts/capability-enforcement.contract.test.js` holds the implementation to every table and every rule on this page, in both directions: a field or code that disappears from the code fails, and so does one this page does not list. It exercises the rules without a sandbox backend, so it runs the same on macOS and on a plain Linux runner.

This capability is Labs. Freezing the contract does not promote it: the feature is off by default and operator-only, enforced mode is advertised for Linux only, Linux is `partially-verified` (only the controls the hosted `sandbox-linux` job proves), mediated network is unsupported on Linux, and a macOS run is `host-proved`, never `enforced`.

## The feature switch

Nothing in `scanner/src/capabilities/` is wired into the scan or report path. The runner (`runCapabilityTask`) passes the feature gate of the assurance configuration (`scanner/src/posture/assurance/config.js`) first, before it reads the request. The feature `capability-enforcement` has risk class `high-risk-execution` and supported platforms `linux` only.

**Feature switches**

| Variable | Effect |
|---|---|
| `AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT` | `1` or `true` turns the feature on, `0` or `false` turns it off. Any other value is invalid configuration and leaves the feature off |
| `AGENTIC_SECURITY_NO_CAPABILITY_ENFORCEMENT` | `1` is a kill switch for this feature; it wins over every other source |
| `AGENTIC_SECURITY_NO_ASSURANCE` | `1` is a kill switch for every assurance feature, this one included |

Rules the code enforces:

- **Off by default.** With no switch set, the feature is disabled with source `default`.
- **Operator-only.** A project file (`.agentic-security/assurance.yml`) that sets `enabled: true` for this feature is refused: the feature stays off, the source is `project-file-refused` and the refusal is recorded in the notes. Only the environment or an explicit caller override can turn it on. A project file can still turn it off.
- **Invalid configuration fails closed.** A non-boolean value leaves the feature off and is reported in `errors`.
- **Linux only.** Turned on anywhere other than Linux, the gate answers `unsupported` with `platform-unsupported`. The runner proceeds past that answer only when the caller passes `allowUnadvertisedBackend` (a development opt-in), and the run is then labelled `host-proved`, never `enforced`.

**Feature gate results**

| Code | Status | When |
|---|---|---|
| `disabled` | `disabled` | The feature is off (the default) |
| `kill-switch` | `blocked` | A kill switch is set |
| `invalid-config` | `blocked` | The configuration for this feature is invalid |
| `platform-unsupported` | `unsupported` | The feature is on and the platform is not Linux |

## The task capability manifest

A manifest is the complete statement of what one task may do. It is deny-by-default (an absent section grants nothing, and no wildcard means "everything") and closed-world (an unknown field, a wrong type or a malformed value invalidates the whole manifest; nothing is carried through or defaulted open). `validateManifest` never throws and returns `{ok, errors, manifest}`; `manifest` is present only when `ok`, and it is deeply frozen.

**Manifest input**

| Field | Required | Meaning |
|---|---|---|
| `schema` | Yes | `agentic-security/capability-manifest` |
| `schemaVersion` | Yes | A semantic version with major version 1 |
| `taskId` | Yes | A non-empty string |
| `parentTaskId` | No | The parent task, for a derived child |
| `repository` | Yes | `{revision}`: a 40 or 64 character lowercase hex commit id |
| `policyVersion` | Yes | A positive integer |
| `filesystem` | No | `{read, write}`: lists of absolute roots |
| `commands` | No | Structured command entries |
| `network` | No | Declared destinations |
| `tools` | No | Tool names, matching `[A-Za-z0-9_.:-]{1,80}` |
| `resources` | No | Resource limits |
| `delegation` | No | `{allow, maxDepth}` |
| `createdAt` | No | Informational; must be a string; dropped from the normalized manifest |

**Normalized manifest**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/capability-manifest` |
| `schemaVersion` | As submitted |
| `taskId` | As submitted |
| `parentTaskId` | As submitted, or `null` |
| `repository` | `{revision}` |
| `policyVersion` | As submitted |
| `filesystem` | `{read, write}`, each de-duplicated and sorted; empty lists when absent |
| `commands` | Normalized command entries, de-duplicated and sorted; empty when absent |
| `network` | Normalized destinations, de-duplicated and sorted; empty when absent |
| `tools` | De-duplicated and sorted; empty when absent |
| `resources` | Only the limits the manifest set; `{}` when absent |
| `delegation` | `{allow, maxDepth}`; `{allow: false, maxDepth: 0}` when absent |

**Filesystem grant**

| Field | Meaning |
|---|---|
| `read` | Absolute roots the task may read. Writable roots are readable too |
| `write` | Absolute roots the task may write |

A root must be absolute, free of NUL bytes and of parent-directory segments, and may not be the filesystem root. At most 256 entries per list.

**Command entry**

| Field | Meaning |
|---|---|
| `executable` | An absolute path without parent-directory segments. Never a name resolved through a search path |
| `args` | `{mode, values}`; when absent, `{mode: 'exact', values: []}` (no arguments) |
| `interpreter` | `scoped` or absent (normalized to `null`). Only a scoped interpreter may run a shell, a language runtime or a launcher, and only with `mode: 'exact'` |

**Command arguments**

| Field | Meaning |
|---|---|
| `mode` | One of the argument modes below |
| `values` | Plain strings, at most 256, each at most 8192 characters and free of NUL bytes |

**Argument modes**

| Mode | Meaning |
|---|---|
| `exact` | The argument array must equal `values` |
| `prefix` | The argument array must start with `values` |
| `any` | Any arguments; `values` must be empty |

**Network destination**

| Field | Meaning |
|---|---|
| `host` | A host name, an IP address, or `*.domain` with at least two labels behind the wildcard. A bare suffix or an address behind a wildcard is refused |
| `port` | An integer from 1 to 65535. There is no wildcard port |
| `schemes` | A non-empty subset of the network schemes below; `https` only when absent |
| `allowPrivateResolution` | Whether a host name may resolve to a loopback, private, link-local or metadata address; `false` when absent |
| `addresses` | A pinned set of 1 to 32 IP addresses, or `null` |

**Network schemes**

| Scheme | Meaning |
|---|---|
| `http` | Plaintext HTTP, filtered for secrets before it is forwarded |
| `https` | An opaque tunnel; the payload is not inspected |

**Delegation**

| Field | Meaning |
|---|---|
| `allow` | A boolean; required when `delegation` is present |
| `maxDepth` | An integer from 0 to 8; 0 when `allow` is false, at least 1 when it is true (1 when omitted) |

**Resource limits**

| Limit | Minimum | Maximum |
|---|---|---|
| `timeoutMs` | 1 | 120000 |
| `maxOutputBytes` | 1 | 16777216 |
| `maxFileSizeKb` | 1 | 1048576 |
| `maxProcesses` | 1 | 4096 |
| `maxMemoryMiB` | 64 | 65536 |

Every limit is an integer within its range. `maxMemoryMiB` is carried and never claimed enforced.

### Validation refusals

Every error is `{code, path, message}`. All errors in the manifest are returned together, and an invalid manifest produces no normalized manifest at all.

**Validation error codes**

| Code | Raised when |
|---|---|
| `NOT_AN_OBJECT` | The manifest (or a child request) is not a plain object |
| `SCHEMA_MISMATCH` | `schema` is not `agentic-security/capability-manifest` |
| `BAD_VERSION` | `schemaVersion` is not a semantic version |
| `UNSUPPORTED_MAJOR` | `schemaVersion` has a major version other than 1 |
| `MISSING_FIELD` | A required field is absent |
| `UNKNOWN_FIELD` | A field, nested field or resource limit is not part of the schema |
| `BAD_TYPE` | A value has the wrong type or is out of range (a non-hex revision, a port of 0, a limit outside its range) |
| `BAD_PATH` | A root or executable is relative, contains a parent-directory segment or a NUL byte, or is the filesystem root |
| `UNKNOWN_ENUM` | An argument mode, a scheme or an `interpreter` value is not one of the allowed values |
| `RULE_VIOLATION` | A rule across fields is broken: `any` with values, a scoped interpreter without `exact`, a wildcard without a registrable domain, a delegation depth that contradicts `allow` |
| `SCOPE_EXPANSION` | `deriveChild` was asked for a child wider than its parent |

### Binding and derivation

`bindManifest` validates and returns `{ok, errors, bound}`, where `bound` is the frozen `{manifest, binding}` every decision and the runner consume. A decision whose claimed identity does not match the binding is denied with `binding-mismatch`, so a grant made for one task, revision or policy version cannot be replayed for another.

**Binding**

| Field | Meaning |
|---|---|
| `taskId` | The manifest's task id |
| `revision` | The manifest's repository revision |
| `policyVersion` | The manifest's policy version |
| `digest` | `sha256:` digest of the normalized manifest |

`deriveChild(parent, request)` builds a child only from a subset of the parent: roots inside the parent's (lexically and after resolving symbolic links), commands covered by the parent's argument modes, destinations covered by host, port, scheme, private-resolution and pinned addresses, tools the parent has, limits no higher than the parent's, and a delegation depth strictly lower. The child names its real parent and keeps the parent's revision and policy version. Any widening is `SCOPE_EXPANSION` and yields no manifest, so there is no partial grant.

## Policy decisions

`decide(bound, action, ctx)` answers one question per action and never throws. It is deny-by-default: the answer is `allow` only when a declared grant covers the action; an unknown kind, a binding mismatch, a malformed action and any internal error are `deny`. The result is frozen.

**Policy decision**

| Field | Meaning |
|---|---|
| `decision` | `allow` or `deny` |
| `code` | A reason code from the closed table below |
| `reason` | The fixed sentence for the code, never text built from the request |
| `kind` | The action kind, sanitized |
| `subject` | The one request-derived field: control characters removed, secret-shaped material redacted, length capped |
| `taskId` | The bound task id, or `null` |
| `manifestDigest` | The binding digest, or `null` |

**Capability kinds**

| Kind | Action |
|---|---|
| `filesystem-read` | Read a path |
| `filesystem-write` | Write a path |
| `command` | Run an absolute executable with an argument array |
| `network` | Reach a host, port and scheme |
| `tool` | Use a named tool |
| `delegation` | Hand capabilities to another task |

**Reason codes**

| Code | Sentence |
|---|---|
| `allowed` | the action is inside the declared capability scope |
| `no-grant` | no capability of this kind is declared for the task |
| `binding-mismatch` | the request is not bound to this task, repository revision and policy version |
| `unknown-action` | the action kind is not recognized |
| `invalid-manifest` | the capability manifest is invalid |
| `scope-expansion` | the request would widen the capability scope granted by the parent task |
| `path-invalid` | the path is not an absolute, well-formed path |
| `path-traversal` | the path escapes the declared roots through parent-directory segments |
| `symlink-escape` | the path resolves outside the declared roots through a symbolic link |
| `outside-roots` | the path is outside every declared root |
| `protected-path` | the path is protected from tasks (keys, sealed labels, evidence, credentials) |
| `executable-not-absolute` | the executable must be an absolute path; names are not resolved through a search path |
| `executable-unresolvable` | the executable does not exist or is not a regular executable file |
| `executable-in-writable-root` | the executable lives in a writable root, so the task could replace it |
| `command-not-listed` | the executable is not a declared command |
| `args-invalid` | the argument list is not an array of plain strings within the size limits |
| `args-not-permitted` | the arguments are not permitted for this declared command |
| `secret-in-argument` | an argument contains secret material; arguments are visible to every process |
| `interpreter-blocked` | the executable is a shell or language interpreter and is not declared as a scoped interpreter |
| `interpreter-args-unpinned` | a scoped interpreter must be declared with its exact argument list |
| `host-invalid` | the destination host is not a well-formed host name or address |
| `port-invalid` | the destination port is not valid |
| `destination-not-declared` | the destination is not a declared network destination |
| `port-not-declared` | the destination host is declared but not on this port |
| `scheme-not-declared` | the destination is declared but not for this scheme |
| `dns-private-address` | the host name resolves to a loopback, private, link-local or metadata address that was not declared |
| `dns-changed` | the host name resolves to addresses outside the pinned set |
| `payload-too-large` | the outbound payload exceeds the mediated size limit |
| `payload-uninspectable` | the outbound payload is binary and cannot be filtered for secrets |
| `tool-not-declared` | the tool is not a declared tool action |
| `delegation-not-allowed` | the task is not allowed to delegate |
| `delegation-depth` | the delegation depth limit is reached |
| `resource-limit-exceeded` | the request exceeds a declared resource limit |
| `tool-unclassified` | the tool has no declared capability classification, so it cannot be checked and is refused |
| `identity-missing` | no current task identity is bound to this server, so a mutating or externally communicating tool is refused |
| `identity-spoofed` | the request names a task identity other than the one this server is bound to |
| `retry-limit` | the same action was denied the permitted number of times in this policy version and stays blocked |
| `task-halted` | the task reached its denial budget and is halted until an operator changes the policy |

## The capability decision record

`toCapabilityDecisionRecord(decision, {mediation, enforced, backend, probeDigest})` turns a policy decision into an `agentic-security/capability-decision` record and validates it. It returns `{ok, record, errors}`; an invalid record is never returned.

**Decision record**

| Field | Required | Meaning |
|---|---|---|
| `schema` | Yes | `agentic-security/capability-decision` |
| `schemaVersion` | Yes | `1.0.0` |
| `id` | Yes | Semantic id over the identifying fields; a record whose id does not match is refused |
| `taskId` | Yes | The task, or `unbound` |
| `capability` | Yes | A capability kind |
| `subject` | Yes | The sanitized subject, capped at 200 characters |
| `decision` | Yes | A decision value below |
| `mediation` | Yes | A mediation value below |
| `enforced` | Yes | A boolean |
| `backend` | Yes | The backend that mediated, or `null` |
| `probeDigest` | No | The digest of the active probe evidence |
| `reason` | Yes | `<code>: <sentence>` |
| `migration` | No | Accepted by the schema; the runner never writes it |
| `createdAt` | No | Informational; accepted by the schema; the runner never writes it |

**Decision values**

| Value | Meaning |
|---|---|
| `allow` | The policy permits the action |
| `deny` | The policy refuses the action |
| `blocked` | The action could not be mediated |
| `unsupported` | The action is not one the policy can mediate |

**Mediation values**

| Value | May claim enforced |
|---|---|
| `runner` | Yes, with a named backend and a probe digest |
| `proxy` | Yes, with a named backend and a probe digest |
| `in-process-policy` | No |
| `hook-advisory` | No |
| `none` | No |

A record with `enforced: true` is refused unless its mediation is `runner` or `proxy`, it names a backend, it carries a probe digest, and its decision is `allow` or `deny`. What a hook says (`advise`) is always `hook-advisory` with `enforced: false`, and a shell command string is answered `unsupported` with no record, because it cannot be mediated.

## Platform status

`platformStatements()` is a standing statement, not a measurement. `isAdvertisedBackend(backend, platform)` is true only for the `namespace` backend on a platform the feature supports, which is Linux alone.

**Platform statements**

| Platform | Backend | Status |
|---|---|---|
| `linux` | `namespace` | `partially-verified` |
| `darwin` | `userspace` | `host-proved-not-advertised` |
| `win32` | none | `unsupported` |

**Linux verified controls** (proved by active probes on the hosted `sandbox-linux` job only, not on every Linux host)

| Control | Meaning |
|---|---|
| `write-confinement` | Writes outside the declared write roots fail |
| `read-denial` | Protected host paths cannot be read |
| `env-scrub` | The task gets a minimal environment |
| `network` | No network unless destinations are declared |
| `tree-termination` | Descendants are terminated with the task |
| `file-size-limit` | The file-size cap stops a large write |
| `fs-read-confinement` | Reads are confined to declared roots |
| `fs-multi-root-write` | Several declared write roots work, undeclared ones do not |
| `process-cap` | The process-count cap holds |

**Linux unsupported controls**

| Control | Meaning |
|---|---|
| `network-mediation` | Not implemented on the namespace backend. A manifest that declares a destination requires this control, so the task is blocked on Linux, never allowed |

**Run levels**

| Level | Meaning |
|---|---|
| `enforced` | An advertised backend, and every control the manifest depends on was proved |
| `host-proved` | A backend that is not advertised (macOS) with every required control proved on this host, after the caller opted in. Nothing is claimed enforced |
| `none` | The run did not reach a level; reported on a blocked run |

A control that is not `proved` blocks the run before the target executes; it is never a warning and never a quiet fallback.

## Runner results

`runCapabilityTask(bound, {executable, args, env, cwd}, opts)` checks, in order: the feature gate, the request and binding, a secret-free environment, the command policy, protected paths against the manifest's roots, the backend, then the active probes. Every refusal is a typed result with `executed: false` and `outcome: 'not-run'`; the target never runs.

**Runner refusal**

| Field | Meaning |
|---|---|
| `status` | A result status below |
| `code` | Why |
| `reason` | A sentence |
| `executed` | `false` |
| `outcome` | `not-run` |

**Policy denial** (the extra fields of a refusal with code `capability-denied` from the command or working-directory policy)

| Field | Meaning |
|---|---|
| `policyCode` | The reason code |
| `decisions` | The policy decisions |
| `missing` | The missing capability |
| `proposal` | The narrowest reviewable manifest change, data for an operator; nothing applies it |
| `attemptsRemaining` | Retries left for this action under the denial guard |
| `exhausted` | Whether the denial budget is spent |

A `capability-denied` refusal for the environment (a secret-looking variable, a non-string value, a registered canary) or for a manifest root that overlaps a protected path carries `policyCode` (and, for the root, an empty `decisions`) but not the other fields: those refusals are made before any policy decision exists.

**Result statuses**

| Status | Meaning |
|---|---|
| `ok` | The task ran and every process was cleaned up |
| `disabled` | The feature is off |
| `blocked` | Refused: kill switch, invalid configuration, policy denial, no backend, or a control not proved |
| `unsupported` | The platform or backend is not advertised and the caller did not opt in |
| `degraded` | The task ran and processes survived termination |

## The capability report

`buildCapabilityReport` states, for every capability, what was requested, what the probes checked, and whether it was enforced, as three separate fields.

**Capability report**

| Field | Meaning |
|---|---|
| `version` | `1` |
| `platform` | The platform the probes ran on |
| `backend` | The backend |
| `level` | A run level |
| `probeDigest` | The digest of the probe states, or `null` |
| `platforms` | The standing platform statements |
| `controls` | Each probed control's state and reason |
| `capabilities` | One entry per capability kind |
| `resources` | One entry per resource limit |
| `limitations` | The standing limitations |

**Report capability entry**

| Field | Meaning |
|---|---|
| `kind` | The capability kind |
| `requested` | What the manifest asked for, as counts |
| `checked` | The state of each control that would enforce it |
| `enforcedBy` | `runner`, `proxy` or `in-process-policy` |
| `enforced` | True only at level `enforced` with every required control proved. Always false for `tool` and `delegation` |
| `descendantExec` | On `command` only: `not-allowlisted` |
| `payloadFiltering` | On `network` only: `plaintext-http-only` |

**Report resources**

| Limit | Meaning |
|---|---|
| `timeoutMs` | Enforced at level `enforced` |
| `maxOutputBytes` | Enforced at level `enforced` |
| `maxFileSizeKb` | Enforced at level `enforced` when the file-size control was proved |
| `maxProcesses` | Enforced at level `enforced` when set and the process-cap control was proved; otherwise `unverified` |
| `maxMemoryMiB` | Never enforced: `not-enforced` |

## What this does not do

<!-- limits-verified: 2026-11-13 -->

- **It is not on unless an operator turns it on.** The default scan never uses it, a project file cannot enable it, and a host without the switch gets a `disabled` result.
- **macOS is never `enforced`.** The userspace backend can prove its controls on a host, and a run there is `host-proved` with `enforced: false` for every capability. Windows has no backend.
- **Linux is only partially verified.** The listed controls are proved by the hosted `sandbox-linux` job on its runner image and kernel, not on every Linux host. The attack-coverage record keeps `platforms.linux: 'unverified'`.
- **Mediated network does not exist on Linux.** A task that declares any network destination is blocked there. The mediation proxy runs only on the macOS development path.
- **Descendant exec calls are not allowlisted.** Only the top-level executable and arguments are mediated; a descendant inherits the file and network confinement and is terminated with the task.
- **Ancestors of a declared root expose metadata.** The existence and size of other paths are not visible.
- **HTTPS payloads are not inspected.** An HTTPS destination is an opaque tunnel; only plaintext HTTP is filtered for secrets.
- **The mediation proxy accepts connections from any local process.** It forwards only to declared destinations, so the exposure is the declared set.
- **A double fork between supervisor sweeps can outlive the task.** A detached grandchild whose parent exits before the next sweep can survive; confinement still holds on it.
- **Memory caps are not enforced anywhere,** and the process-count cap is enforced only on the Linux namespace backend.
- **Tool and delegation checks are policy, not enforcement.** They run in the server process and are reported `in-process-policy`; hook answers are `hook-advisory` and never block.
- **The validator accepts any 1.x schema version.** `schemaVersion` `1.5.0` validates and is carried through unchanged; only the major version is checked.
- **Some runner codes are outside the shared closed list.** The runner's `capability-denied` code is not one of the assurance configuration's `RESULT_CODES`, so a consumer that validates against that list alone would reject it.
- **The enforced-mode release gate is not wired into the release check.** `enforcedModeReleaseGate` is a library function the suite uses.
