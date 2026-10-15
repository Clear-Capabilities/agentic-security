# Context Intelligence architecture

Source: `scanner/src/context-intelligence/`. Guide: [Deterministic Context Intelligence](../guides/context-intelligence.md).

## Pipeline

```
source snapshot -> symbol graph -> entry points -> bounded reachability -> packer
   -> context-manifest/1 + numbered bundles -> content-addressed store
   -> governed single-call review -> citation verification -> candidates
   -> existing confirm / disprove / judge
```

Everything left of the review is deterministic: the same snapshot, configuration and tool version give byte-identical manifests. The review stage is the only model call, and its output is accepted only through verification.

## Modules

| Module | Role |
|---|---|
| `canonical.js` | hashing, canonical JSON, repository-relative path safety, safe file reads |
| `files.js`, `repo-info.js` | snapshot of the working tree or a git ref, with symlink and size limits |
| `graph-schema.js`, `imports.js`, `spans.js` | `symbol-graph/1`: stable symbol ids, span hashes, call edges with conditionality, import resolution, material and boundary classification of unresolved edges |
| `adapters/existing-ir.js` | builds the graph from the existing project IR and call graph |
| `adapters/haskell-hie.js` | read-only `hie-export/1` importer and merge |
| `controls.js` | authentication, role, ownership and tenant-scope detection with principal-versus-untrusted discrimination |
| `entrypoints.js` | entry-point resolution and dispositions, reusing the engine route scan, the Haskell web model and the entry-point inventory |
| `reachability.js` | bounded breadth-first reachability, middleware ordering, protection states |
| `packer.js` | security-preserving packing, telemetry pruning with proof, linked packages |
| `manifest.js`, `store.js`, `persist.js` | `context-manifest/1`, atomic link-safe artifact store, verification, export, cleanup |
| `prompts/packs.js`, `review.js` | question packs, prompt construction, redaction, citation verification |
| `queue.js` | bounded concurrent review queue, durable checkpoints, offline batch export and import |
| `candidates.js` | verified reviews to candidates, then the existing confirmation, refutation and judge stages |
| `diff.js` | route diffs between refs, reverse dependencies, cache accounting |
| `evaluation/` | synthetic suite runner, scripted reader, scorecards, leakage audit, holdout ledger |
| `cli.js`, `config.js`, `capabilities.js` | command surface, configuration, honest capability matrix |

## Reuse, not replacement

Entry-point discovery reuses `scanRoutes`, the Haskell web model and the entry-point inventory. The model call goes through the same resolver and egress policy as `hunt`, with the same redaction. Confirmation, refutation and judging are the existing stages. State goes under the existing state directory with the existing safety checks and legal-hold handling. Nothing in the default scan imports this subsystem.

## Invariants

- Unresolved is never silently dropped: material unresolved edges block `complete`.
- A control after the sensitive operation is `evaluated_and_ineffective`, never protection.
- Model output cannot set severity, and an invalid citation invalidates the review.
- Store writes are atomic, refuse links and unsafe paths, and every stored package is re-checked against its hash on use.
- A missing result is missing coverage, never a clean result.

## Known limits

Router mounts across files and middleware factories are reported unresolved. Token counts are estimates. Review quality has no real-world measurement. Automatic compiler builds and provider batch APIs are blocked, with reasons recorded in the capability matrix.
