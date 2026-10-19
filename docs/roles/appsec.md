# AppSec

<!-- seo: title="AppSec guide: trust, tune and govern the analysis" description="How an application security team reads the evidence, tunes rules and suppressions, sets assurance gates and checks what the analysis did not cover." -->

**Primary question:** How do I trust, tune, and govern the analysis?

**Core workflow:** [CI gating](../workflows/ci-gating.md)

## Trust it

- Start with [the evidence model](../how-it-works/evidence-model.md): severity, confidence, reachability, exploit evidence and remediation completeness are separate facts.
- Read [scan health](../trust/scan-health.md) before you read a count of findings. A `partial` scan changes what a zero means.
- Know the limits: [trust and limitations](../trust/trust-and-limitations.md) and [benchmarking methodology](../trust/benchmarking-methodology.md).

## Tune it

| Lever | Where |
|---|---|
| Suppress one line | `// agentic-security-ignore: <rule-id>`. Line-scoped, and every suppression is written to a ledger that `--include-suppressed` shows |
| Severity overrides, custom rules, ignore paths | `.agentic-security/rules.yml` |
| Disable a rule | `disable:` in `rules.yml`; takes effect only with a verifying signature or an explicit opt-out |
| Experimental rules | `shadow: true` custom rules write to a shadow file and are excluded from gates |
| Decisions on findings | `triage` (pro profile): true positive, false positive, won't fix, feeding the next scan |
| Personas | `agentic-security profile set vibecoder` or `pro` changes defaults, not capability |

## Govern it

- Gate on severity and on assurance: [assurance modes](../trust/assurance-modes.md), [CI gating](../workflows/ci-gating.md).
- Constrain what leaves the machine: [model egress](../trust/model-egress.md).
- Retention, encryption, export and legal hold: [State and retention](../governance/state-and-retention.md).
- Understand what the tool does against hostile repositories: [agent threat model](../trust/agent-threat-model.md).

## Escalate with proof

Where a finding must be settled, supply a reproducer and run `agentic-security triage exploit <id> --prove` (Preview). See [exploit proof](../guides/exploit-proof-fabric.md). A `not-reproduced` result is not a safety proof.

## Read more

- [Architecture: the finding lifecycle](../architecture/finding-lifecycle.md)
- [Configuration and environment variables](../reference/configuration.md)
- [Runtime corroboration](../guides/runtime-twin.md) (Preview)
- [Source-to-artifact provenance](../guides/artifact-provenance.md) (Preview)
