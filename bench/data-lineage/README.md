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

**24 fixtures, all `regression`-tier and all passing since 0.195.24
(GA-03.1); before that, 17 passed and 7 were `capability`-tier.
`--check` exits 0.** Re-measure with
`node bench/data-lineage/runner.mjs --check` rather than trusting this
paragraph; it is a snapshot, not a gate.

The 4 seed fixtures above came from Milestone 0 and F1. Increment F2
added 19; Sub-project H's AC-07 closure added the 24th,
`js-ai-model-output-to-ai-model-provider-phi/` — the first fixture able
to name `ai-model-provider` as a `sinkCategory` at all, since the
AI-sink catalog bridge that made that category reachable landed with it.
F2's 19:

- **14 category-coverage fixtures**, one per reachable
  `SOURCE_CATEGORIES` value, exercising between them the 10
  `SINK_CATEGORIES` that were reachable at the time (`database`, `log`,
  `external-api`, `analytics`, `http-response`, `queue`,
  `client-storage`, `object-storage`, `file`, `email`). The 11th,
  `ai-model-provider`, was not reachable until Sub-project H and is
  covered by that increment's own fixture instead.
- **3 aliasing/interprocedural fixtures** —
  `js-http-body-to-log-alias-of-field/`,
  `js-http-body-to-log-aliased/` and
  `js-http-body-to-log-interprocedural/`.
- **2 negative/clean fixtures** —
  `js-http-query-to-log-unclassified-clean/` and
  `js-exec-unsupported-sink/`.

#### How the last 7 fixtures became scoreable (0.195.24, GA-03.1)

Until 0.195.24 seven fixtures were `capability`-tier: real ground truth
the engine or the runner could not satisfy. Each fixture's own `notes`
records what changed and how it was measured; the four causes and their
resolutions:

1. **Four source categories had no `language: 'js'` catalog entry**
   (`http-upload`, `cli-argument`, `storage-read`, `user-input`), so the
   four fixtures were written in Python syntax and could never mint a
   source node. They are now real JavaScript (`process.argv`,
   `req.files`, `fs.readFileSync`, `prompt()`), matched by
   `scanner/src/lineage/lineage-source-catalog.js`, a lineage-only
   catalog: a file's contents or a console prompt are collection points
   for the graph, not attacker-controlled taint for the SAST engine, so
   the main taint catalog is unchanged (pinned by
   `test/lineage/seeding-across-calls.test.js`). The two call-shaped
   ones (`readFileSync`, `prompt`) are seeded on the assignment target
   after the node runs (`source-seeding.js`, `after-node` seeds); before
   they would have landed in `unseedable[]`. The element named by a
   positional index (`process.argv[2]`) and a file's contents carry no
   data class, so those two fixtures label `dataClass: []`, which the
   runner now reads as "match on the two categories alone".
   `js-user-input-to-log-unclassified` became `js-user-input-to-log-pii`
   once its element (`ssn`) had a name to classify.
2. **An aliased CONTAINER lost field-level classification.**
   `source-seeding.js` now follows the alias within the function and
   mints the field seed on the original path, so `const body =
   req.body; body.card_number` carries `card_number` `[PCI]` through the
   hop.
3. **The projection did not span a call boundary.** The call-summary
   resolver joins the callee's own seeds onto the call-derived entry
   state (`DESIGN_GRAPH_BUILDER.md` §3.8), so a field read in a helper
   and returned reaches the caller's sink. **Still open, measured and
   pinned:** a sink INSIDE the callee (`emit(logger, req.body.x)` with
   the log call in `emit`) never sees the argument, because a bare call
   statement is not resolved through the summary; see `engine.js`'s
   bare `call` case for why the attempt was reverted.
4. **`scoreFixture` could not address an unsupported/process-kind sink.**
   `expectUnsupportedSink: true` now asserts the `kind: 'process'`,
   `subtype: null`, `coverageStatus: 'unsupported'` node with a
   `coverageReason`, which is the AC-11 property that matters.

#### Authoring constraint: a scoreable sink call MUST be a bare statement

Found while authoring the AC-07 fixture (Sub-project H), and general to
every fixture author, not just AI ones: `graph-builder.js`'s
`enumerateSinkSites` only enumerates **bare-statement `call`-kind CFG
nodes** (`DESIGN_GRAPH_BUILDER.md` §4.1). Two extremely common real-world
shapes are therefore invisible to this corpus's own scoring:

- a call **nested inside another call's arguments** —
  `client.send(new InvokeModelCommand({ body: phi }))`, the way the AWS
  SDK v3 is actually used;
- an **assign-form** call whose response is captured —
  `const resp = anthropic.messages.create({ … })`, the way every AI SDK
  is actually used (you need the response).

Both are recorded only in the coverage ledger's
`nonStatementSitesNotEnumerable`; neither ever becomes an `escape`
provenance node, so neither can anchor a lineage flow. A fixture written
in either shape produces `no node with subtype '<sink category>'` and
fails, no matter how correct the catalog entry behind it is.

This is a disclosed lineage-engine limitation, **not** a catalog gap —
`dataflow/engine.js`'s `_nestedSinkFindings` does walk into nested call
arguments for ordinary SAST/taint purposes, so the same catalog entry
fires correctly for a real scan; only the lineage projection cannot see
it. So: **write the sink call as a bare, un-assigned statement**, and say
so in the fixture's own `notes` (as
`js-ai-model-output-to-ai-model-provider-phi/` does), so nobody later
"realistically" rewrites it and silently breaks the fixture. Extending
`enumerateSinkSites` to nested/assign-form calls is a separate change
with blast radius across every sink category, deferred.

#### A shipped-code defect found while authoring this batch — FIXED

`coverage.js`'s FR-203 hook guarded itself with
`if (site.entry?.vuln?.cwe === undefined) return undefined;`, whose
comment claimed privacy-catalog entries carry no `vuln.cwe`. They all
do — every `PRIVACY_SINK_CATALOG` entry carries `vuln.cwe: 'CWE-359'`.
So the guard excluded nothing, and `resolveSiteDecision` re-ran
`reclassifySink` (which keys on `CWE_MAP`) on privacy entries, producing
a `null` category and collapsing a perfectly good `store`/`object-storage`
node to `process`/`null`/`unsupported`. Reproduced with
`s3.putObject({ Body: x })` — a computed first argument is what makes
the arg0 signal fire. `js-ai-model-output-to-object-storage-phi/` uses a
LITERAL key argument, which routed around the bug rather than exercising
it — kept as-is even after the fix, since it's still a valid fixture.
**Fixed** in a dedicated hotfix (guard now keys on `site.entry.category`,
a field only privacy entries carry) — see
`docs/superpowers/plans/2026-08-31-lineage-coverage-privacy-catalog-fr203-hotfix.md`.

Sub-project F's remaining increments (F3 onward) mass-author the rest of
the ~200-entry floor described under "Target corpus shape" above.

Two of the nine corpus dimensions listed there — the transport-protection
states (HTTPS / cleartext / cert-verification-disabled / dynamic-scheme /
proxy-terminated / unknown) and the policy-permitted/prohibited flows —
are **not scoreable until Milestone 2** ships the analyzers that decide
those verdicts. Fixtures for them can be authored now, but must be
labeled `"tier": "capability"`, which keeps them visible in the report
without failing `--check` before the engine can possibly satisfy them.
