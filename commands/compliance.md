---
description: Compliance + auditor flows. Framework attestation, walkthrough, buyer-facing badge, stack audits, PR augmentation.
argument-hint: "[--report <fw>|--walkthrough <fw>|--attestation|--audit <target>|--pr]"
---

# /compliance

Compliance + auditor flows dispatcher.

## Modes

| Flag | Behaviour |
|---|---|
| `--report <framework>` | Generate auditor-ready compliance attestation. Frameworks: `nist`, `asvs`, `llm`, `eu-ai-act` |
| `--walkthrough <framework>` | Step-by-step auditor narrative with evidence mapping per control. Frameworks: `nist-csf-2`, `nist-ai-600-1`, `nist-privacy-1-1`, `owasp-asvs-5`, `owasp-llm-top-10`, `eu-ai-act`, `gdpr`, `hipaa-security-rule`, `ccpa` (or BYO at `.agentic-security/compliance/<id>/controls.json`) |
| `--attestation` | Render buyer-facing security posture artifact. `--format badge|onepager|page` |
| `--audit <target>` | Stack-specific security audits. Targets: `db`, `auth`, `rate-limit`, `webhook`, `env`, `csp-cors`, `deploy`, `launch`, `llm-cost`, `prompt` |
| `--pr` | Generate PR-description block (security delta vs base + ATT&CK + reviewers + artifacts) |
| `--gap` | Show only the **Not-Compliant** controls, each with the exact command that closes it |
| `--privacy` | NIST Privacy Framework 1.1 assessment with remediation per gap. Artifacts: `.agentic-security/privacy-framework.{json,md}` |

Bare `/compliance` (no flag) prints this mode menu. `--report` and `--gap` accept `--format cli|json|oscal`.

## `--gap` (close the deltas)

`--gap` runs the attestation for `<framework>` but filters to controls scored **Not-Compliant** / **Partial**, and for each one prints the single command that closes it — e.g. a missing-rate-limit control maps to `/compliance --audit rate-limit`, a secrets control to `/fix --rotate-secret`, a coverage gap to `/fix --compliance`. The output is an actionable worklist, not a full report. `/fix --compliance` consumes the same mapping to batch-close them.

## `--privacy` (NIST Privacy Framework 1.1)

Runs on every scan and writes `.agentic-security/privacy-framework.{json,md}`.
All 104 PF 1.1 controls are carried, and each lands in exactly one bucket:

| Bucket | Meaning |
|---|---|
| **gap** | Mapped to an engine signal, and that signal is failing — **this is the only bucket that emits a finding** |
| **not assessed** | NIST rates the control code-testable, but this engine has no signal for it. Disclosed by name. **Not a pass.** |
| **manual** | NIST rates the control not code-testable — governance, policy, process. Outside any scanner's reach. |
| **satisfied** | Mapped, and the signal is clean |

The split matters: of the 104 controls NIST rates **23 yes, 33 partial and 48 no**
for code-testability. A tool that reports the 48 governance controls as "passed"
because no rule fired against them is manufacturing assurance, so they are never
counted as satisfied — and neither are controls this engine simply does not check.

**Remediation.** Each gap carries an actionable remediation and is emitted as a
normal finding (`family: privacy-compliance`, `CWE-359`), so it flows through
triage and `/fix` like any other. Findings are **opt-in** via
`AGENTIC_SECURITY_PRIVACY_FRAMEWORK=1`: a compliance opinion should not silently
become a build failure for a project that never asked for one. The assessment
artifact is written either way.

A scan that examined **no files** reports every control as *not assessed* rather
than satisfied — a clean signal from a run that read nothing is not evidence.

Backed by a real subcommand — `/compliance --privacy` runs it, and you can call
it directly:

```bash
agentic-security compliance                        # assessment + per-gap remediation
agentic-security compliance --gap                  # only the failing controls
agentic-security compliance --format json          # machine-readable
agentic-security compliance --fail-on gap          # exit 1 when a control fails (CI)
agentic-security compliance --list                 # bundled + BYO frameworks
agentic-security compliance --walkthrough <id>     # auditor narrative, any framework
AGENTIC_SECURITY_PRIVACY_FRAMEWORK=1 agentic-security scan .   # gaps as fixable findings
```

It reads `.agentic-security/last-scan.json` rather than re-scanning: a compliance
answer is a statement about a scan that happened. With no scan to read it exits
**2** and says so, rather than assessing an empty project — which would report
every control as unassessed and sits one careless flag away from looking clean.

Exit codes: **0** report produced · **1** only with `--fail-on gap` and a failing
control · **2** nothing to assess, or an unknown framework.

## `--format oscal` (machine-readable export)

`--report <fw> --format oscal` emits the attestation as an **OSCAL-aligned** JSON document (NIST's machine-readable assessment format): an `assessment-results`-shaped object with one `finding`/`observation` per control, each carrying the control id, status (`satisfied` / `not-satisfied`), and the evidence paths the scanner matched. `--format json` emits the same data in the plugin's native finding schema. Both are what GRC tooling and auditors ingest; `--format cli` (default) stays human-readable.

## Examples

```bash
/compliance --report nist                       # NIST AI 600-1 attestation
/compliance --walkthrough owasp-asvs-5          # OWASP ASVS auditor walkthrough
/compliance --attestation --format onepager     # buyer-facing one-pager
/compliance --audit db                          # database posture audit
/compliance --pr                                # PR-description block
```

## Implementation

Routes to the posture modules (`compliance-policy.js`, `auditor-walkthrough.js`, `pr-augment.js`) and the scanner CLI.
