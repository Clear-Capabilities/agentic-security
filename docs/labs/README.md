# Labs

<!-- seo: title="Labs: experimental Agentic Security capabilities" description="Experimental capabilities whose interface may change materially: the finding-to-rule compiler, detector spec synthesis, fleet scanning and runner-level capability enforcement." -->

**Labs** means experimental: the code is real, but the interface may change materially. Do not build a process on the exact output shape of a Labs capability.

These are the Labs entries in [the registry](../capabilities.yaml):

| Capability | Lifecycle stage | What it does | Read |
|---|---|---|---|
| Finding-to-rule compiler | Learn | Promotes one proven finding to a reviewed deterministic rule that passes its own corpus and can propose the rule with `rules synthesize --auto` | [Rule compiler](../guides/rule-compiler.md) |
| Detector spec synthesis | Learn | Drafts a detector spec for human review, never incorporated automatically | [`/labs --synthesize-rule`](../../commands/labs.md) |
| Fleet scanning and dependency blast radius | Scale | Runs leased scan jobs for a declared set of repositories and answers which depend on a given one | [Fleet](../guides/fleet.md) |
| Detection and response (`dnr`) | Detect | Generates a validated detection from a proven vulnerability, hunts local logs and scopes the exposure window; local and text-only | [Detection and response](../guides/detection-and-response.md) |
| Eval Lab and model router | Cross-cutting | Measures a baseline and models on detection, proof, remediation, cost and repeatability, and routes tasks | [Eval Lab](../guides/eval-lab.md) |
| Release assurance | Verify | A signed release package, an offline verifier and a deterministic deployability verdict; not part of the default scan | [Release assurance](../guides/release-assurance.md) |
| Runner-level capability enforcement | Verify | Filesystem, command and network limits enforced by the task runner; off by default and operator-only | [Agent threat model](../trust/agent-threat-model.md) |

## The `/labs` command

`/agentic-security:labs` is the dispatcher for experimental and AI-driven analyses. Its modes have their own graduation status, recorded in [`commands/labs.md`](../../commands/labs.md): some (`--llm`, `--risk-dollars`, `--time-to-fix`) are marked Stable there as candidates to graduate to a first-class surface, others (`--claude-audit`, `--cross-repo`, `--model-rescan`) Beta, and `--synthesize-rule` Experimental. That table is a per-mode graduation note for the command. It does not override the registry label of a capability.

## Promotion

A Labs capability graduates by changing the registry with implementation evidence. It does not graduate because a page reads better with it.
