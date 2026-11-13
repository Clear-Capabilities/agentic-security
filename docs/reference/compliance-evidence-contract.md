# Compliance control evidence: contract

<!-- seo: title="Compliance evidence contract: control status vocabularies, report fields and the OSCAL refusal rule" description="The frozen per-control status vocabularies of the compliance report, the fields each output carries, the rule that unassessed and manual controls never count as satisfied, and the OSCAL rule that an unassessed control gets no finding." -->

**Maturity:** Preview

This page freezes, at contract version 1 (the code carries no version of its own), what `agentic-security compliance` promises and what it refuses: the per-control status vocabulary of each assessment path, the fields each output carries, the rule that an unassessed or manual control is never counted as satisfied, and the OSCAL rule that a control the engine did not decide carries no finding. A compatibility test (`scanner/test/contracts/compliance-evidence.contract.test.js`) runs the real evaluators, the real OSCAL exporter and the real CLI over small inline inputs and holds each shape to the tables below in both directions, so a field cannot be added or removed without changing this page. How to use the command is in the [Compliance guide](../guides/compliance.md); why the OSCAL output looks the way it does is in [OSCAL output](../OSCAL.md).

Every output on this page is automated technical-control evidence mapped to a framework's controls. None of them is a certification, a management attestation or an assessor's opinion.

## The command

`compliance` reads `.agentic-security/last-scan.json`; it never re-scans. Three assessment paths share one command:

| Invocation | Path | Status vocabulary |
|---|---|---|
| `compliance --report <id>` (or `--walkthrough <id>`) | The framework evaluator | Evaluator status |
| `compliance --report <id> --truth --format json\|oscal` | The truth model over the evaluator's rows | Truth state |
| `compliance` (no framework; NIST Privacy Framework 1.1) | The privacy assessment | Privacy bucket |

Exit codes: `0` when a report is produced, `2` when there is no scan to read or the framework id is unknown, `1` only when `--fail-on gap` is given on the privacy path and at least one control is in the `gap` bucket.

**Framework list entry** (`compliance --list --format json`, one per framework)

| Field | Meaning |
|---|---|
| `id` | The framework id passed to `--report` |
| `name` | The framework's name |
| `source` | `bundled`, or `project` for a framework at `.agentic-security/compliance/<id>/controls.json` |
| `license` | The framework file's license, or `user-provided` for a project framework without one |

A project framework with the same id as a bundled one replaces it.

## The framework evaluator

`compliance --report <id> --format json` prints one row per control of the framework.

**Evaluator status**

| Field | Meaning |
|---|---|
| `present` | Every mapped signal cleared on a scan that examined something |
| `partial` | Some signals cleared and some did not, or a mapping is unverifiable (a `rule:` mapping, a family no detector produces, incomplete Haskell or Nix analysis, a scan that examined no files, a control rated not code-testable, or a partly code-testable control backed only by artifact-existence checks) |
| `absent` | Signals exist and none cleared |
| `manual` | The control has no automated mapping |

**Evaluation row**

| Field | Meaning |
|---|---|
| `control` | The control as loaded from the framework file |
| `status` | One evaluator status (above) |
| `observations` | One sentence per mapping, stating what was checked and what it found |
| `controlRefs` | Ids of the open findings attributed to this control; empty for `present` and `manual` |
| `derivedProvenance` | The earliest Git origin among the contributing findings, with its confidence and limitations |
| `obligationMappings` | Obligation records minted by `graph:` mappings; empty without one |
| `evidence` | The measured strength of the detectors behind the control's `family:` mappings |
| `partiallyEvidenced` | `true` when that strength is `weak` or `unmeasured` |

Rules:

- **A control with no mapping is `manual`.** It is never `present`.
- **A control rated not code-testable is never `present`**, whatever its mappings found.
- **A scan that examined nothing is not evidence.** When every recorded file count is 0 and the scan holds no results, a mapped control is capped at `partial`, never `present`. A scan object with no file count at all is treated as assessable.

## The truth model

`--truth` restates every evaluator row in six states, with the denominators beside them. Only the first two are verdicts.

**Truth state**

| Field | Meaning |
|---|---|
| `assessed_satisfied` | Every automated signal the control needs ran and cleared, on a complete scan, and the control is rated code-testable |
| `assessed_not_satisfied` | At least one signal found an open problem attributed to this control |
| `not_assessed` | Nothing looked: the control is rated code-testable but has no check, or the evaluator reported an unrecognised status |
| `not_applicable` | Declared so by a named person with a reason in `.agentic-security/compliance-applicability.json`; never inferred |
| `requires_human_review` | The control needs a person: it is not code-testable, only partly so, or one signal stands for a wider obligation |
| `insufficient_evidence` | Signals exist but cannot carry a verdict: an incomplete scan, a scan that examined nothing, an unverifiable mapping or weak evidence |

**Truth assessment**

| Field | Meaning |
|---|---|
| `frameworkId` | The framework |
| `controls` | One truth control per evaluator row |
| `denominators` | The counts a reader needs to judge the coverage |
| `frameworkClaim` | What the assessment does and does not establish about the framework as a whole |

**Truth control**

| Field | Meaning |
|---|---|
| `id` | The control id |
| `title` | The control's summary |
| `state` | One truth state (above) |
| `reasons` | Why this state |
| `codeTestable` | The publisher's (or for NIST SP 800-171, our) code-testability rating, or `null` |
| `evaluatorStatus` | The evaluator status it was derived from |
| `observations` | The evaluator's observations |

**Denominators**

| Field | Meaning |
|---|---|
| `declaredControls` | The framework's declared control count, or `null` |
| `evaluatedControls` | Controls with a row |
| `unevaluatedControls` | Declared but not evaluated, or `null` |
| `applicable` | Evaluated controls not declared not applicable |
| `byState` | A count per truth state |
| `assessed` | `assessed_satisfied` plus `assessed_not_satisfied` |
| `assessedOfApplicable` | `assessed` over `applicable`, or `null` |
| `satisfied` | `assessed_satisfied` only |
| `satisfiedOfApplicable` | `satisfied` over `applicable`, or `null` |
| `needAPersonOrMoreEvidence` | `requires_human_review` plus `insufficient_evidence` plus `not_assessed` |

**Framework claim**

| Field | Meaning |
|---|---|
| `established` | Always `false` |
| `statement` | One sentence stating what was assessed, and that it is not a statement that the system meets the framework |
| `reasons` | Why the claim is not established |

Rules:

- **Only `assessed_satisfied` counts as satisfied.** `not_assessed`, `requires_human_review` and `insufficient_evidence` are counted in `needAPersonOrMoreEvidence`, never in `satisfied`.
- **A not-applicable declaration needs a reason and a person.** One without either is `insufficient_evidence`, not `not_applicable`.
- **`frameworkClaim.established` is never `true`**, even when every applicable control is `assessed_satisfied`.

## The privacy assessment

`compliance --format json` prints the NIST Privacy Framework 1.1 assessment. The scan writes the same assessment to `.agentic-security/privacy-framework.json` unless `AGENTIC_SECURITY_NO_PRIVACY_FRAMEWORK=1` is set; the command recomputes it from the last scan.

**Privacy bucket**

| Field | Meaning |
|---|---|
| `gap` | Mapped to an engine signal, and the signal did not clear. The only bucket that produces a finding |
| `engine-gap` | Rated code-testable, but this engine has no signal for it, or its signal could not count this scan (the scan examined nothing, or a privacy-taint-only control without an IR-backed run). Shown as "Not assessed" |
| `manual` | Rated not code-testable: governance, policy or process |
| `satisfied` | Mapped, and the signal cleared |

**Privacy assessment**

| Field | Meaning |
|---|---|
| `frameworkId` | `nist-privacy-1-1` |
| `frameworkName` | The framework's name |
| `controls` | One privacy control per framework control |
| `summary` | A count per bucket |
| `findings` | One gap finding per `gap` control |
| `assessable` | Whether the scan examined anything |
| `interpretation` | One paragraph stating the satisfied count over the assessed controls and naming what was not assessed |

**Privacy summary**

| Field | Meaning |
|---|---|
| `gap` | Controls in `gap` |
| `engine-gap` | Controls in `engine-gap` |
| `manual` | Controls in `manual` |
| `satisfied` | Controls in `satisfied` |
| `total` | All controls |

**Privacy control**

| Field | Meaning |
|---|---|
| `id` | The control id |
| `function` | The framework function, or `null` |
| `category` | The framework category, or `null` |
| `summary` | The control text summary |
| `codeTestable` | `yes`, `partial` or `no` |
| `bucket` | One privacy bucket (above) |
| `observations` | The evaluator's observations |
| `disclosure` | Why the control was not assessed; present on `engine-gap` and `manual` only |

**Privacy gap finding**

| Field | Meaning |
|---|---|
| `id` | `privacy-framework:<control id>` |
| `severity` | `high`, `medium` or `low`, by what the gap exposes |
| `file` | `.agentic-security/compliance/nist-privacy-1-1` |
| `line` | `0`: a gap is a property of the project, not of one line |
| `vuln` | The control, named as not satisfied |
| `cwe` | `CWE-359` |
| `description` | The control and the evaluator's observations |
| `remediation` | An action, or a pointer to the observations |
| `parser` | `COMPLIANCE` |
| `family` | `privacy-compliance` |
| `complianceControl` | The framework, control id and code-testability rating |
| `controlRefs` | The open findings attributed to the control |
| `derivedProvenance` | The earliest Git origin of those findings with its disclaimer, or `null` |

Rules:

- **`engine-gap` and `manual` are never counted as satisfied.** The satisfied rate in `interpretation` is `satisfied` over `satisfied` plus `gap`, never over `total`.
- **A scan that examined no files assesses nothing.** Every mapped control is `engine-gap`, `satisfied` and `gap` are both 0, and `interpretation` says so first.
- **Gap findings join `scan.findings` only on request** (`AGENTIC_SECURITY_PRIVACY_FRAMEWORK=1`); the assessment is written either way.

## OSCAL output

`--format oscal` on any of the three paths prints an OSCAL 1.1.2 `assessment-results` document. Each path's statuses are reduced to one OSCAL decision per control:

**OSCAL decision**

| Field | Meaning |
|---|---|
| `satisfied` | A finding with target state `satisfied`, and a `TEST` observation |
| `not-satisfied` | A finding with target state `not-satisfied`, an open risk, and a `TEST` observation |
| `unassessed` | No finding and no risk. An observation with method `EXAMINE` and a remark saying why |

The reduction, per path:

| Status | Decision |
|---|---|
| Evaluator `present` | `satisfied` |
| Evaluator `partial`, `absent` | `not-satisfied` |
| Evaluator `manual` | `unassessed` |
| Truth `assessed_satisfied` | `satisfied` |
| Truth `assessed_not_satisfied` | `not-satisfied` |
| Truth `not_assessed`, `not_applicable`, `requires_human_review`, `insufficient_evidence` | `unassessed` |
| Privacy `satisfied` | `satisfied` |
| Privacy `gap` | `not-satisfied` |
| Privacy `manual`, `engine-gap` | `unassessed` |
| Any status not listed here | `unassessed`, with a remark naming it an exporter defect |

**OSCAL document**

| Field | Meaning |
|---|---|
| `uuid` | The document |
| `metadata` | Title, last-modified time, document version (the engine version) and OSCAL version |
| `import-ap` | A self-reference: no assessment plan governs this assessment, and the remark says so |
| `results` | Exactly one result |
| `back-matter` | The framework resource and the tool caveats |

**OSCAL result**

| Field | Meaning |
|---|---|
| `uuid` | The result |
| `local-definitions` | The tool as the assessment asset |
| `title` | The framework's assessment |
| `description` | The counts, and the statement that unassessed controls carry no finding |
| `start` | The scan's start time, or the emit time when the scan recorded none |
| `props` | `controls-reviewed`, `count-satisfied`, `count-not-satisfied`, `count-unassessed` and `framework-id` |
| `links` | The framework and caveat resources |
| `reviewed-controls` | Every control of the framework as loaded |
| `observations` | One per control, whatever its decision |
| `findings` | One per decided control; absent when no control was decided |
| `risks` | One per `not-satisfied` control; absent when none |
| `remarks` | The evidence-grade disclaimer and the statement that no licensed assessor reviewed the document |

**OSCAL observation**

| Field | Meaning |
|---|---|
| `uuid` | The observation |
| `title` | Control id and title |
| `description` | The observations, or a sentence saying how the control was or was not assessed |
| `methods` | `TEST` for a decided control, `EXAMINE` for an unassessed one |
| `types` | `control-objective` |
| `origins` | The tool |
| `collected` | The same time as `start` |
| `props` | `source-control-id` (the publisher's original id) and `assessment-status` (the path's own status), plus path-specific props |
| `remarks` | Present on an unassessed control only: why it was not assessed |

**OSCAL finding**

| Field | Meaning |
|---|---|
| `uuid` | The finding |
| `title` | Control id and title |
| `description` | The observations |
| `props` | `source-control-id` and `assessment-status` |
| `origins` | The tool |
| `target` | `objective-id`, the control id as an OSCAL token, and the binary state with reason `pass` or `fail` |
| `related-observations` | The control's observation |
| `related-risks` | The open risk; present on `not-satisfied` only |
| `remarks` | For `satisfied`: that the mapped signals cleared, which is scanner evidence toward the control and not an attestation that it is implemented and operating |

Rules:

- **An unassessed control gets no finding.** OSCAL's finding state is binary, and asserting either state for a control nobody decided would be false. It appears as an `EXAMINE` observation carrying its upstream status in `assessment-status`.
- **Counts add up.** `count-satisfied` plus `count-not-satisfied` plus `count-unassessed` equals `controls-reviewed`, and equals the number of observations; the number of findings equals the first two.
- **Original ids are kept.** A control id that is not a legal OSCAL token is rewritten, and the original travels as `source-control-id` on every observation and finding.

## What this does not do

<!-- limits-verified: 2026-11-13 -->

- **It is not a certification**, not an audit opinion and not a management attestation. Only a certifying assessor issues one, and only the organization's own leadership can assert that its controls are in place and operating. NIST SP 800-171 evidence is not a CMMC assessment and produces no SPRS score.
- **The control mappings are ours, not the framework body's.** Which detector family, artifact or rule stands for a control was chosen by this project. For NIST SP 800-171 Rev. 3 the code-testability rating is ours too: the published export rates nothing.
- **Manual controls need a human.** Governance, policy, process, personnel and physical controls are outside any scanner's reach and are reported as such, not assessed.
- **`satisfied` means the mapped signals cleared.** A detector that finds nothing is not proof that nothing is there, and a module artifact that exists is evidence a file exists, not that the activity it records happened.
- **The default OSCAL path is coarser than `--truth`.** Without `--truth`, an evaluator `partial` becomes a `not-satisfied` finding even when the reason is an unverifiable mapping or a scan that examined nothing, so a control nobody could decide can appear as a failure. `--truth` keeps those as `insufficient_evidence` observations with no finding.
- **`--fail-on gap` and `--gap` act on the privacy path only.** With `--report <id>` the command exits 0 whatever the controls read, and `--gap` does not filter.
- **The truth model trusts the recorded scan status.** A last scan without a recorded `scanHealth.status` of `complete` gives no `assessed_satisfied` control at all.
- **The deep-attestation scanners under `scripts/nist-compliance` and `scripts/nist-800-171` are outside this contract.** They score term, path, import and manifest evidence with fixed weights, use their own status labels (one of which is the literal string `Compliant`, meaning a weighted evidence threshold was met), and skip controls rated not code-testable.
- **The OSCAL document is structurally checked, not validated against the published schema**, and no assessment plan governs it.
