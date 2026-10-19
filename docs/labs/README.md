# Labs

<!-- seo: title="Labs: experimental Agentic Security capabilities" description="Experimental capabilities whose interface may change materially: detector spec synthesis and runner-level capability enforcement." -->

**Labs** means experimental: the code is real, but the interface may change materially. Do not build a process on the exact output shape of a Labs capability.

These are the Labs entries in [the registry](../capabilities.yaml):

| Capability | Lifecycle stage | What it does | Read |
|---|---|---|---|
| Detector spec synthesis | Learn | Drafts a detector spec for human review, never incorporated automatically | [`/labs --synthesize-rule`](../../commands/labs.md) |
| Runner-level capability enforcement | Verify | Filesystem, command and network limits enforced by the task runner; off by default and operator-only | [Agent threat model](../trust/agent-threat-model.md) |

**Why these two stay Labs.** Detector spec synthesis is a drafting aid for a human reviewer with no measurable output; promoting it would claim a precision it cannot have. Runner-level enforcement is `partially-verified` on Linux (only the controls the hosted `sandbox-linux` job proves), mediated network is unsupported, and macOS runs are `host-proved`, never `enforced`. Its exit criteria are that every control is proven by `sandbox-linux`, and that mediated network is either supported or removed from the advertised set.

## Graduated to Preview

Five capabilities left Labs in 0.182.0, each with a reference page that freezes its output shapes and a compatibility test that fails on an undocumented field. Preview is not GA: each page says what is still being hardened.

| Capability | Lifecycle stage | Contract |
|---|---|---|
| Finding-to-rule compiler | Learn | [Rule compiler contract](../reference/rule-compiler-contract.md) |
| Fleet scanning and dependency blast radius | Scale | [Fleet contract](../reference/fleet-contract.md) |
| Detection and response (`dnr`) | Detect | [Detection and response contract](../reference/dnr-contract.md) |
| Eval Lab and model router | Cross-cutting | [Eval Lab report](../reference/eval-lab-report.md) |
| Release assurance | Verify | [Release assurance contract](../reference/release-assurance-contract.md) |

## The `/labs` command

`/agentic-security:labs` is the dispatcher for experimental and AI-driven analyses. Its modes have their own graduation status, recorded in [`commands/labs.md`](../../commands/labs.md): some (`--llm`, `--risk-dollars`, `--time-to-fix`) are marked Stable there as candidates to graduate to a first-class surface, others (`--claude-audit`, `--cross-repo`, `--model-rescan`) Beta, and `--synthesize-rule` Experimental. That table is a per-mode graduation note for the command. It does not override the registry label of a capability.

## Promotion

A Labs capability graduates by changing the registry with implementation evidence. It does not graduate because a page reads better with it.
