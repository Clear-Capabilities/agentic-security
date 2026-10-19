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
| `payloadClass` | One of the eight payload classes |
| `affectedOperation` | `sink`, `file` and `line` |
| `processEffect` | The process effect of the attack |
| `networkEffect` | The network effect |
| `dbEffect` | The database effect |
| `confidence` | A number from 0 to 1 |
| `grounding` | `exploit-confirmed` or `static-only` |
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
| `render` | Whether the generated expression compiles |
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
| `undated` | Events with no usable time |
| `endpointEvents` | Events for the detection's endpoint |
| `requiredFields` | The log fields the detection needs |
| `fieldAvailability` | Which of them the logs actually had |

**Matches**

| Field | Meaning |
|---|---|
| `count` | Matching events |
| `firstSeen` | The earliest |
| `lastSeen` | The latest |
| `samples` | A bounded list of events with values redacted and a fingerprint in place of the value |

`NOT_OBSERVED` means the searched window, in the logs that could be read, held no matching event. It does not mean the vulnerability was not exploited elsewhere or outside the window.

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
| `unresolvedDeployments` | Deployments whose contents could not be resolved against the commits |
| `deploymentProblems` | Entries of the history that were refused, with the reason |
| `unknowns` | Every date or fact that could not be sourced |
| `statement` | What the window does and does not say |

**Where a deployment's commit comes from.** A deployment record names a commit. A record that names only an image digest is placed at the commit the image declares in its `org.opencontainers.image.revision` build label, read from the [artifact provenance graph](../guides/artifact-provenance.md) passed with `--artifact-graph`, and `commitSource` says `artifact-provenance-graph`. A record whose commit and image disagree is refused and listed; an image that declares no commit, or two graphs that disagree about one image, place nothing. Without `--artifact-graph`, a digest-only record is refused.

## Guarantees

- **A hunt never says "not exploited".** `notExploitedClaim` is `false`, and an unanswered question has its own verdict and exit code.
- **Nothing leaves the machine.** No command here contacts a network or a model.
- **Secrets are redacted before anything is stored or printed.** A fingerprint stands in for the value.
- **A date with no source is unknown.** The window is `partial` or `unavailable` rather than filled with an assumption.
- **A detection is checked with the evaluator the hunt uses.** A rule that misses a positive or fires on a look-alike fails validation.

## What this does not do

<!-- limits-verified: 2026-10-19 -->

- **No SIEM connection.** Every renderer produces text; none connects anywhere, and the Elastic, YARA-L and Datadog output was not run against a live product.
- **Local, text-only logs.** Common and combined access logs and JSON lines are read; compressed logs are skipped and make the verdict `INCONCLUSIVE`.
- **Eight payload classes.** A finding of another class gets no detection rather than a guessed one.
- **The artifact join relies on a build label.** An image built without the revision label cannot be placed in history, and the join does not infer one.
- **A hunt covers only the logs it was given.** Exposure outside the telemetry is reported as unobserved.
