# Detection and response: record contract

<!-- seo: title="Detection and response contract: the detection, hunt and exposure window records" description="The frozen fields of the detection record, the hunt result and the exposure window, the hunt verdicts and exit codes, and what a hunt can and cannot conclude." -->

**Maturity:** Preview

This page freezes the records the detection and response loop writes: the detection, the hunt result and the exposure window. A compatibility test (`scanner/test/contracts/dnr.contract.test.js`) builds each record and holds it to the tables below in both directions, so a field cannot be added or removed without changing this page and the record's `version` in the same commit. How to use the loop is in the [detection and response guide](../guides/detection-and-response.md). Everything here runs locally and reads files; nothing connects to a SIEM or a network.

## Commands and exit codes

```bash
agentic-security dnr generate <finding-id> [--format <name>|all] [--out <dir>] [--allow-unproven] [--json]
agentic-security dnr validate <finding-id>
agentic-security dnr hunt <finding-id> --logs <file-or-dir> [--since <iso>] [--until <iso>]
agentic-security dnr window <finding-id> --deployments <file> [--artifact-graph <file>[,<file>]] [--fix-commit <sha>] [--environment <name>]
agentic-security dnr show <finding-id>
agentic-security dnr status <finding-id>
```

`dnr hunt` returns a distinct code per verdict so automation cannot read an unanswered question as a clean one.

| Code | Meaning |
|---|---|
| `0` | `NOT_OBSERVED` for `hunt`; completed for every other command |
| `1` | A stored or produced result failed its own check (validation), or a window is not `complete` |
| `4` | A usage problem or a precondition that is not met (for example no confirmed exploit and no `--allow-unproven`) |
| `10` | `OBSERVED` |
| `11` | `INCONCLUSIVE` |
| `12` | `TELEMETRY_UNAVAILABLE` |

**Output formats:** `sigma`, `http`, `waf`, `log-query`, `yara`, `spl`, `kql`, `cloudwatch`, `elastic`, `yaral`, `datadog`. A format that cannot express a finding exactly prints `not applicable` with the reason. It does not approximate.

Records live under `.agentic-security/dnr/<finding>/` as `<kind>-<digest>.json`, each with its own `recordDigest`. A record that no longer matches its digest is returned flagged and never trusted.

## The detection

`agentic-security/detection-ir`, version 1. The id is `det-` plus 12 hex characters derived from the content.

**Detection**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/detection-ir` |
| `version` | `1` |
| `id` | `det-` plus 12 hex characters |
| `findingId` | The finding |
| `cwe` | The finding's CWE |
| `family` | The vulnerability family |
| `attackBehavior` | The attack in words |
| `endpoint` | `method` and `path` |
| `parameter` | `name` and `location` |
| `payloadClass` | One of the nine payload classes |
| `affectedOperation` | `sink`, `file` and `line` |
| `processEffect` | The process effect of the attack |
| `networkEffect` | The network effect |
| `dbEffect` | The database effect |
| `confidence` | A number from 0 to 1 |
| `grounding` | `exploit-confirmed` (the proof ran and confirmed), `reproduced` (the proof ran and reproduced the behaviour without confirming the exploit) or `static-only` (no proof; `--allow-unproven`) |
| `evidence` | Where each claim came from: the finding, the proof and the reproducer |
| `facts` | For each of `payloadClass`, `endpoint`, `parameter` and `sink`, its `source` and `ref` |
| `limitations` | What the detection cannot say, such as that the exploit was not executed |
| `digest` | Digest of the content |

**Validation** (stored with the detection)

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/detection-validation` |
| `version` | `1` |
| `detectionId` | The detection |
| `status` | `VALIDATED` when every positive fired and no look-alike did |
| `cases` | Every positive and look-alike tried, with whether it was expected to fire and did |
| `render` | Whether the payload class's JavaScript regular expression compiles. The rendered text of each format is held to its own grammar separately (`syntax.js` `checkRendered`, the format assurance table below), not here |
| `counts` | `positives`, `negatives`, `passed` and `failed` |
| `failures` | The cases that disagreed with the rule |

## The hunt

**Hunt result**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/hunt-result` |
| `version` | `1` |
| `findingId` | The finding |
| `detectionId` | The detection that was searched for |
| `detectionDigest` | Its digest |
| `notExploitedClaim` | Always `false`: a hunt never claims a vulnerability was not exploited |
| `egress` | `none` |
| `verdict` | `OBSERVED`, `NOT_OBSERVED`, `INCONCLUSIVE` or `TELEMETRY_UNAVAILABLE` |
| `logs` | What was read (below) |
| `window` | The dated span the logs cover (below) |
| `coverage` | What the logs could and could not show (below) |
| `effect` | Always `corroborated: false`: a matched line is a signal that the response indicated success, not evidence that data was delivered |
| `matches` | The matching events (below) |
| `caveats` | Plain-language reasons the verdict is limited |
| `statement` | The verdict in one sentence |

**Logs**

| Field | Meaning |
|---|---|
| `source` | The path searched |
| `files` | Files read |
| `filesSkipped` | Files not read, such as compressed ones |
| `lines` | Lines seen |
| `parsed` | Lines understood |
| `failed` | Lines not understood |
| `truncated` | Whether a size or time budget stopped the read |

**Window**

| Field | Meaning |
|---|---|
| `start` | The earliest dated event |
| `end` | The latest |
| `datedEvents` | How many events carried a usable time |

**Coverage**

| Field | Meaning |
|---|---|
| `requestedWindow` | The `--since` and `--until` asked for |
| `outOfWindow` | Events outside it |
| `gaps` | `{count, limitMs, listed}`: holes between dated events longer than the limit (six hours unless `--max-gap` says otherwise), the first twenty listed. With the default limit a gap is reported as informational, because the logs alone cannot tell a quiet period from lost retention; a limit the operator sets makes a gap block a negative (since 0.195.31) |
| `truncatedEvents` | Events whose query or body parameters were cut at the parser's limits, so a payload past the limit would not have been seen; a non-zero count blocks a negative (since 0.195.31) |
| `ambiguousTime` | Events whose timestamp carries no zone and so could not be placed in time; they were searched but not dated, and a non-zero count blocks a negative (since 0.195.31) |
| `undated` | Events with no usable time |
| `endpointEvents` | Judged events for the detection's endpoint: the same method AND route template the matcher uses (earlier releases counted an event of the same method on any route) |
| `target` | For the endpoint: `relevant` events, `adjudicable` ones, `missingRequired` ones (a required field absent), `deniedAttempts`, `authorizedDelegations`, and whether the match samples were capped |
| `windowGaps` | Edges of the requested window the logs do not reach (`start` or `end`); each one blocks a negative answer |
| `requiredFields` | The log fields the detection needs |
| `fieldAvailability` | Which of them the logs actually had, including `authOutcome` and `tenant` |

**Matches**

| Field | Meaning |
|---|---|
| `count` | Matching events |
| `firstSeen` | The earliest |
| `lastSeen` | The latest |
| `samples` | A bounded list of events with values redacted and a fingerprint in place of the value |

`NOT_OBSERVED` means the searched window, in the logs that could be read, held no matching event. It does not mean the vulnerability was not exploited elsewhere or outside the window.

**Effect.** `effect.corroborated` is always `false` on a hunt result: a matched line shows that the response indicated success (`samples[].signal: response-indication`). Delivery or mutation of data is a separate claim that needs a separately bound observer.

### Authentication and object authorization

A normalized event carries the credential's presence and the authentication outcome as separate facts: `credentialPresent` and `authOutcome` (`authenticated`, `unauthenticated`, `unknown`, `conflict`). The outcome comes from mapped fields (`authenticated`, `is_authenticated`, `auth.outcome`, `auth.result`, `authn.outcome`, `authn.result`). An explicit rejection survives a credential header, even a redacted one. A header with no outcome only shows that a credential was sent, so an `auth-bypass` detection cannot judge that event. The legacy `authPresent` field is unchanged.

| Class | Fires when | Cannot judge when |
|---|---|---|
| `auth-bypass` | a 2xx response to a request that is not authenticated: no credential, or one the outcome says was rejected | the status is missing, or a credential was sent with no recorded outcome, or the outcome fields conflict |
| `object-authz` (CWE-639) | a 2xx response to an authenticated actor whose tenant differs from the object's, with no cross-tenant grant | the status, the outcome, the actor tenant or the object tenant is missing |

For `object-authz`, a 401 or 403, or a recorded `authz.decision: deny`, is a denied attempt and never a delivery. A recorded `authz.cross_tenant_grant: true` is an authorized delegation. The actor tenant (`identity.tenant`, `actor.tenant`, `auth.tenant`, `principal.tenant`), the object tenant (`object.tenant`, `resource.tenant`, `record.tenant`), the grant and the decision are read only from those mapped fields. A value the client sends in a header, the query or the body is never treated as identity.

Rendering: `object-authz` is published only to the `http` and `log-query` outputs, which name the fields it needs. Every other destination reports it as unavailable with the reason. An `auth-bypass` rule rendered to a rule language tests for a missing Authorization header, and it says in `coverage.notCovered` that a credential sent and rejected is not covered. Validation adds independent controls for both classes: a rejected credential, an accepted one, a header with no outcome (which must be undecidable), the rightful tenant, a delegation and a denial.

## The exposure window

`agentic-security/exposure-window`, version 1. Every date is sourced; a date with no source is reported unknown and listed.

**Exposure window**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/exposure-window` |
| `version` | `1` |
| `findingId` | The finding |
| `status` | `complete`, `partial` or `unavailable` |
| `vulnerabilityIntroduced` | `at`, `commit` and `source`, or `null` |
| `firstVulnerableDeployment` | `at`, `commit`, `commitSource`, `environment` and `artifactDigest`, or `null` |
| `fixCommitted` | `at` and `commit`, or `null` |
| `fixDeployed` | `at`, `commit`, `commitSource`, `environment` and `artifactDigest`, or `null` |
| `stillExposed` | `true` only when the newest recorded deployment contains the flaw |
| `telemetryWindow` | The span the telemetry covers, or `null` |
| `observableWindow` | The part of the exposure the telemetry covers, or `null` |
| `unobservableBefore` | Exposure that predates the telemetry, or `null` |
| `unobservableAfter` | Exposure after the telemetry ends (the fix not deployed, or deployed after the last log line), open-ended when there is no fix deployment, or `null` (since 0.195.31) |
| `exposureStart` | `{at, evidence}`: the first vulnerable deployment, or `at: null` with `evidence: none` (since 0.195.31) |
| `exposureEnd` | `{at, evidence}`: the fix deployment, `fix-not-deployed` when the history has none, or `none` (since 0.195.31) |
| `unresolvedDeployments` | Deployments whose contents could not be resolved against the commits |
| `deploymentProblems` | Entries of the history that were refused, with the reason |
| `unknowns` | Every date or fact that could not be sourced |
| `statement` | What the window does and does not say |

**Where a deployment's commit comes from.** A deployment record names a commit. A record that names only an image digest is placed at the commit the image declares in its `org.opencontainers.image.revision` build label, read from the [artifact provenance graph](../guides/artifact-provenance.md) passed with `--artifact-graph`, and `commitSource` says `artifact-provenance-graph`. A record whose commit and image disagree is refused and listed; an image that declares no commit, or two graphs that disagree about one image, place nothing. Without `--artifact-graph`, a digest-only record is refused.

## What each format's output has been held to

Four levels, stated per format and never merged (GA-10 §4, since 0.195.31): the renderer **generates** it; its **syntax** is checked by a vendored schema (a JSON shape this repository owns or vendors) or by a subset grammar written from the target's public documentation for exactly the constructs the renderer emits (`scanner/src/posture/dnr/syntax.js`, with the document and version each was read from); it is tested against **samples** when an interpreter in this repository executes the rendered rule over the labelled log corpus and must agree with the hunt evaluator on every line; and it is tested against a real **product** only in a disposable qualification environment, which none has been. No vendor tool runs here: `official` is not a level any row claims. A generic suggestion is never presented as a deployed control.

**Format assurance**

| Format | Generated | Syntax | Samples | Product |
|---|---|---|---|---|
| `sigma` | yes | subset-grammar (Sigma specification 2.0.0; the `webserver` log source fields) | no | no |
| `http` | yes | vendored-schema (this repository's `http-detection` v1) | yes | no |
| `waf` | yes | subset-grammar (ModSecurity SecRule, 2.9 and 3.0: a chain whose metadata sits on the starter and whose only disruptive action is `pass`) | no | no |
| `log-query` | yes | vendored-schema (this repository's `structured-log-query` v1) | yes | no |
| `yara` | yes | subset-grammar (YARA 4.5: text, hex and regex strings, the string escapes YARA accepts) | no | no |
| `spl` | yes | subset-grammar (Splunk SPL 9.x: search terms, `regex` and `where`) | no | no |
| `kql` | yes | subset-grammar (Kusto over the `W3CIISLog` table and its columns) | no | no |
| `cloudwatch` | yes | subset-grammar (Logs Insights: `fields`, `filter ... like /re/`, `sort`) | no | no |
| `elastic` | yes | vendored-schema (Query DSL `bool` with `term`, `regexp`, `range`, `exists`; no Lucene-less classes) | no | no |
| `yaral` | yes | subset-grammar (YARA-L 2.0: `meta`, `events` with `re.regex`, `condition`) | no | no |
| `datadog` | yes | vendored-schema (`log_detection` rule fields; `isEnabled` must be `false`) | no | no |

`scanner/test/dnr/renderer-syntax.test.js` renders every payload class at every parameter location on a literal and a templated path and holds each applicable output to its checker, and each checker to a known-bad sample; the `FORMAT_ASSURANCE` constant in `outputs.js` must match this table.

## Guarantees

- **A renderer declines what its target cannot see** (since 0.195.31). The Sigma `webserver` log source records no request body and no arbitrary header, the `W3CIISLog` table and an access log line carry no `Authorization` header: a rule that would need one is reported `applicable: false` with the reason, never written against an invented field or widened to every 2xx.
- **A hunt never says "not exploited".** `notExploitedClaim` is `false`, and an unanswered question has its own verdict and exit code.
- **Nothing leaves the machine.** No command here contacts a network or a model.
- **Secrets are redacted before anything is stored or printed.** A fingerprint stands in for the value.
- **A date with no source is unknown.** The window is `partial` or `unavailable` rather than filled with an assumption.
- **A detection is checked with the evaluator the hunt uses.** A rule that misses a positive or fires on a look-alike fails validation.

## What this does not do

<!-- limits-verified: 2026-11-06 -->

- **No SIEM connection, no vendor parser.** Every renderer produces text; none connects anywhere, and no output has been run against a live product. The syntax checks are subset grammars and vendored schemas written here from the targets' public documentation, not the vendors' own parsers; a construct outside the subset the renderers emit is not judged, and an official check (Sigma's own validator, a YARA compiler, a ModSecurity rule check) belongs to a hosted qualification job that is not provisioned.
- **Local, text-only logs.** Common and combined access logs and JSON lines are read; compressed logs are skipped and make the verdict `INCONCLUSIVE`.
- **Nine payload classes.** A finding of another class gets no detection rather than a guessed one.
- **The artifact join relies on a build label.** An image built without the revision label cannot be placed in history, and the join does not infer one.
- **A hunt covers only the logs it was given.** Exposure outside the telemetry is reported as unobserved.
