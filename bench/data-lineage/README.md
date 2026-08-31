# bench/data-lineage/ — Data-Flow Explorer accuracy corpus

Successor to `bench/privacy-recall/` (PRD section 3: "Baseline contains
only four fixtures and is not adequate proof of broad, cross-language
lineage accuracy"). This corpus measures the Milestone 1/2 lineage
engine's field-to-sink precision/recall, external-destination recall, and
false-`protected` rate (PRD section 22.3's release thresholds).

Milestone 0 established the fixture SHAPE and seeded the first 3 entries.
Sub-project F, increment F1 added the runner (`runner.mjs`, below) and a
4th seed fixture, so the corpus is now genuinely executable against a real
`DataFlowGraph v1` document. It is not yet wired into the pre-push gate —
gate wiring waits until the corpus is large enough to be meaningful proof.

## Target corpus shape (PRD section 22.2)

At least:
- 100 vulnerable/positive field flows
- 100 clean/negative or protected flows
- every supported language (initial order: JS/TS, Python, then Java/C#/Go,
  then Kotlin/Ruby/PHP — PRD section 22.1)
- every source and sink category (PRD sections 11, 12)
- direct, aliased, cross-file, interprocedural, serialized, database,
  queue, API, and AI paths
- masked, hashed, tokenized, encrypted, weakly-encrypted, branch-partial,
  and reversed transformations
- HTTPS, cleartext, certificate-verification-disabled, dynamic-scheme,
  proxy-terminated, and unknown-transport cases
- dynamic destinations and unsupported-candidate cases
- policy-permitted and policy-prohibited flows

## Fixture shape

Each entry is a directory under `fixtures/<id>/`:
- `source.<ext>` — a small, self-contained source file exercising exactly
  one flow shape. Named descriptively: `<lang>-<source-category>-to-<sink-category>-<distinguishing-trait>`.
- `expected.json` — the human-labeled expected result, independent of any
  engine implementation:
  ```json
  {
    "language": "js",
    "dataClass": ["PCI"],
    "sourceCategory": "http-body",
    "sinkCategory": "log",
    "expectedProtection": { "handling": "protected" },
    "expectedTransformKind": "mask",
    "tier": "regression",
    "notes": "maskCard() applied on every feasible path before the log call"
  }
  ```
  `tier` and the optional `expectedConnected` are described under
  "Two `expected.json` fields the runner adds", below.

## Seeded entries

- `js-api-to-log-masked/` — positive case, masked (protected handling).
- `js-api-to-log-raw/` — positive case, raw (unprotected handling, RAW PCI).
- `js-api-to-external-http-cleartext/` — positive case, unprotected transit
  over literal HTTP.
- `js-api-to-log-disconnected/` — AC-11's negative case (added by F1): a
  PCI source and a log sink coexist in one file with nothing connecting
  them. The log node must still appear in the graph with a coverage
  reason; `expectedConnected: false` is what tells the runner to assert
  the absence of a flow rather than its presence.

## The runner (`runner.mjs`)

The runner now exists — the lineage engine it scores against shipped with
Milestone 1, Sub-project E. From `scanner/`:

```
npm run bench:data-lineage         # score every fixture, always exit 0
npm run bench:data-lineage:check   # gating mode: exit 1 on a regression-tier failure
```

Or directly: `node bench/data-lineage/runner.mjs [--check]`. Exit codes
mirror `bench/cve-replay/runner.mjs` (0 clean, 1 gate failure, 2 setup
error), but the SCORER is structurally different, and deliberately so.
cve-replay asks a binary question — is this entry detected as vulnerable,
yes or no. This corpus asks whether the built graph correctly REPRESENTS
the labeled flow, so scoring is a **shape-match** against `expected.json`:

1. a node exists whose `subtype` is the labeled `sourceCategory`, and one
   for the `sinkCategory`;
2. a `flow` connects those two nodes carrying a `dataElement` tagged with
   at least one of the labeled `dataClass` values;
3. that flow carries a `transformation` of the labeled
   `expectedTransformKind` — or, when the label is `null`, at least one
   matching flow carries no transformation at all.

Each fixture is built through `buildGraphWithCoverage`
(`scanner/src/lineage/coverage.js`) from its own `source.js`, with a fixed
`generatedAt` and the fixture's directory name as the repository, so the
runner's output is byte-identical run to run for the same corpus state.
There is no `corpus-baseline.json`: unlike cve-replay, each entry's
`expected.json` already IS the full ground truth, so a separate baseline
file would add nothing to check against. See
`scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` for the projection model the
shape-match is written against.

**`expectedProtection` is recorded and printed, never asserted.** Every
graph Milestone 1 can produce carries `protectionSummary: 'not_assessed'`
and an empty `edge.protection` — `graph.limitations` says so explicitly —
so scoring that field today would either always fail or force the corpus
to record a placeholder as if it were a verdict. It is the Milestone 2
analyzers' job to make it scoreable.

### Two `expected.json` fields the runner adds

- `tier` — `"regression"` (the default when absent) or `"capability"`.
  Gating is purely a function of this field: a `regression` entry must
  pass for `--check` to exit 0; a `capability` entry is always scored and
  its failure is printed in the report, but never flips the exit code.
- `expectedConnected` — boolean, default `true`. Setting it to `false`
  marks a deliberately-disconnected, AC-11-shaped fixture: the runner then
  asserts that NO connecting flow exists AND that the sink node is still
  present in `graph.nodes` with a `coverageReason`. A discovered sink that
  simply vanished from the graph is the failure AC-11 exists to catch.

### Corpus state

4 fixtures (the 3 seeded above plus `js-api-to-log-disconnected/`, the
AC-11 disconnected-node proof), all `regression`-tier, all passing.
Sub-project F's remaining increments (F2 onward) mass-author the rest of
the ~200-entry floor described under "Target corpus shape" above.

Two of the nine corpus dimensions listed there — the transport-protection
states (HTTPS / cleartext / cert-verification-disabled / dynamic-scheme /
proxy-terminated / unknown) and the policy-permitted/prohibited flows —
are **not scoreable until Milestone 2** ships the analyzers that decide
those verdicts. Fixtures for them can be authored now, but must be
labeled `"tier": "capability"`, which keeps them visible in the report
without failing `--check` before the engine can possibly satisfy them.
