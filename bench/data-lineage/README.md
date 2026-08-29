# bench/data-lineage/ — Data-Flow Explorer accuracy corpus (design)

Successor to `bench/privacy-recall/` (PRD section 3: "Baseline contains
only four fixtures and is not adequate proof of broad, cross-language
lineage accuracy"). This corpus measures the Milestone 1/2 lineage
engine's field-to-sink precision/recall, external-destination recall, and
false-`protected` rate (PRD section 22.3's release thresholds) — it does
NOT exist to gate anything yet, because the engine it measures has not
been built. This milestone (M0) only establishes the fixture SHAPE and
seeds the first 3 entries; a runner/checker script lands with Milestone 1
(DFG-018), once there is an engine to run fixtures through.

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
    "notes": "maskCard() applied on every feasible path before the log call"
  }
  ```

## Seeded first entries (this milestone)

- `js-api-to-log-masked/` — positive case, masked (protected handling).
- `js-api-to-log-raw/` — positive case, raw (unprotected handling, RAW PCI).
- `js-api-to-external-http-cleartext/` — positive case, unprotected transit
  over literal HTTP.

These establish the fixture-authoring pattern; Milestone 1's DFG-018 mass-authors
the remaining ~194+ entries against it, plus the runner/checker script
(`bench/data-lineage/runner.mjs`, mirroring `bench/cve-replay/runner.mjs`'s
pre/post scoring shape) once the lineage engine exists to score against.
