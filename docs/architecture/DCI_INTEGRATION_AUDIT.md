# Context Intelligence integration audit

Recorded before implementation: what already existed, what was reused, and what is new.

| Need | Existing piece | Decision |
|---|---|---|
| Project IR and call graph | `ir/` (`buildProjectIR`) | reused as the graph source; a typed `symbol-graph/1` is built on top |
| HTTP route discovery | `engine.js` route scan, Haskell web model | reused; handler resolution added |
| Other entry-point kinds | entry-point inventory | reused |
| Model invocation, egress, redaction | `discovery/llm-invoke.js`, egress policy, payload redaction, untrusted-text fencing | reused unchanged |
| Confirm, refute, judge | `discovery/{confirm,disprove,judge}.js` | reused unchanged |
| Taint corroboration | `makeTaintProbe` | reused |
| State directory, link safety, legal holds | `posture/state-dir.js`, legal-hold helpers | reused |
| Grouped intervals | `posture/evaluation/interval.js` | reused for evaluation |
| Scan health and coverage vocabulary | existing | wording matched |
| Typed symbol graph with stable ids and span hashes | none | new |
| Per-entry-point bundle, manifest, completeness | none | new |
| Compiler metadata | none | new, read-only import only |
| Bounded review queue with checkpoints | none | new |

Not built, with reasons: running a compiler to produce metadata (no sandbox proof for untrusted source), and a provider batch API client (no verified provider contract on this checkout; offline batch files are provided instead).
