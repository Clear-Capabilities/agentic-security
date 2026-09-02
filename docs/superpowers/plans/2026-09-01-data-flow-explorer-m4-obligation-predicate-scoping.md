# Milestone 4, sub-project 6b (obligation predicate/mapping engine): scoping

Per the parent sub-project #6 scoping doc's own decomposition: *"6b — the
predicate/mapping engine. The real work: a new graph-fact-reading predicate
type added to the SAME typed-predicate architecture `auditor-walkthrough.js`
already implements, evaluated against 5 real framework catalogs."* 6a (the
`ObligationMapping` record shape) is now COMPLETE and merged. This document
investigates the real current code that predicate type must integrate with
and makes the explicit design rulings a plan needs.

## What already exists (confirmed by direct source read this session)

- **`scanner/src/posture/auditor-walkthrough.js`**'s `evaluateFramework(scanRoot, fw, scan)`
  dispatches each control's `mapsTo[]` entries through a hardcoded
  `if/else-if` chain on `String.prototype.startsWith` — `family:`,
  `module:`, `rule:`, no registry, no handler table. A 4th `graph:` branch
  slots into the SAME loop with zero restructuring. `scan` is already the
  full `runFullScan` result object, and `scan.lineageGraph` is ALREADY a
  real field on it (`engine.js`'s own return statement) — a `graph:`
  predicate needs **zero signature change** to `evaluateFramework` to read
  the graph.
- **9 real framework catalogs** (`scanner/src/posture/compliance-frameworks/
  *.json`) — confirmed exact control shape: `{id, summary, codeTestable,
  evidence?, mapsTo?}`, framework envelope `{id, name, publisher, license,
  url, scope, controlsDigest, controlCount, controls[]}`. **No
  `frameworkVersion` field exists anywhere in any of the 9 catalogs** —
  confirmed by grep. Several existing `mapsTo` entries are weak,
  file-wide/repo-wide proxies for what a `graph:` predicate could check
  precisely: HIPAA `§164.312(e)` and GDPR `Art.32` both map to
  `family:crypto-tls-*` (any TLS finding ANYWHERE in the repo) where the
  real requirement is "does data classified X, flowing to an external
  sink, cross a protected transit edge" — a materially stronger, flow-
  scoped claim `edge.protection.transit` + data classification can make.
  One control, NIST Privacy Framework's `CT.DM-P8` ("mechanisms for
  transmitting data elements in accordance with processing permissions"),
  has NO `mapsTo` at all today and is a close, literal match for
  `flow.policyVerdict === 'permitted'`.
- **`flow.policyVerdict`** (`POLICY_STATES`:
  `prohibited`/`permitted`/`conditionally_permitted`/
  `manual_review_required`/`not_evaluated`), **`edge.protection.{transit,
  atRest,handling}`** (`{verdict, evidenceGrade}` per `protection.js`) —
  `transit` and `atRest` both have real, non-file-wide producers;
  `handling` is never written by any code today. Reading these off a
  SHIPPED graph document requires the caller to build its own id→entity
  `Map`s and join `flow.dataElementIds[0]`/`flow.edgeIds[0]`/`flow.sink`
  against `graph.dataElements[]`/`graph.edges[]`/`graph.nodes[]` — no
  pre-joined "enriched flow" view exists.
- **No reusable graph query engine for a SHIPPED graph document.**
  `path-query.js`/`path-store.js` operate on the internal hop-provenance
  DAG that exists only transiently during `buildDataFlowGraph`'s own
  build — gone by the time a graph is persisted or attached to
  `scan.lineageGraph`. The real, load-bearing precedent instead is
  `dataflow/catalog.js`'s own `match` field shape: a small declarative
  object (`{type:'call', callee:'query', ...}`) evaluated by a
  hand-written matcher function — never a general query language. This is
  the established codebase convention to follow, not path-query.js.
- **`applicabilityInputs` (entity role, jurisdiction, etc.) is NOT tracked
  as operator config anywhere in this codebase.** Confirmed by a
  repo-wide grep for all seven key names outside `obligation-mapping.js`
  itself: zero hits. One near-miss, explicitly a TRAP not a foundation:
  `posture/blast-radius.js` computes a `jurisdictions` Set, but
  HEURISTICALLY (regex/manifest inference for cost estimation) — exactly
  the "guessed from a field name" pattern FR-504's own rule and 6a's own
  validator forbid. Must never be silently repurposed here.

## Design rulings (this document's own, binding on the implementation plan)

1. **Predicate dispatch**: add a `graph:` branch to
   `auditor-walkthrough.js`'s existing `if/else-if` chain inside
   `evaluateFramework`, alongside `family:`/`module:`/`rule:` — not a new
   dispatch mechanism, not a rewrite of the existing three. `scan` already
   carries `scan.lineageGraph`; no signature change needed.
2. **Predicate expression shape**: a small declarative match object,
   mirroring `dataflow/catalog.js`'s own established `match`-object/
   hand-written-matcher pattern — e.g. `{type:'graph-flow', dataClass:
   'PHI', sinkKind:'external', dimension:'transit', requiredVerdict:
   'protected'}` — evaluated by a hand-written matcher that builds its own
   id→entity `Map`s and iterates `graph.flows[]`. No new query language,
   no reuse of `path-query.js` (confirmed unusable — operates on a DAG
   that no longer exists once a graph ships).
3. **`frameworkVersion` synthesis**: since no catalog carries a real
   version field, use `fw.controlsDigest` (already present on every
   catalog, a real content hash that changes when the catalog's content
   changes) — never a hand-typed literal that can silently drift from the
   catalog it's supposed to describe.
4. **State-vocabulary remapping is NEW logic, not a passthrough.**
   `evaluateFramework`'s existing 4-state vocabulary
   (`present`/`partial`/`absent`/`manual`) does not map 1:1 onto 6a's
   6-state `OBLIGATION_STATES`. A `graph:` predicate's own result needs
   its own state derivation: `evidence_supported` only when the check ran
   AND cleared with real evidence (never "no findings" as a vacuous
   pass — the same trap `family:`'s own `COMPLIANCE_FAMILY_GAPS`
   disclosure already exists to prevent); `gap_detected` when it ran and
   failed; `unknown` when `scan.lineageGraph` is absent entirely (the
   common case — lineage analysis is opt-in behind
   `AGENTIC_SECURITY_LINEAGE_DEEP=1`, so most real scans have no graph at
   all, and every `graph:` predicate must degrade to `unknown` cleanly,
   never throw, never silently skip).
5. **`applicabilityInputs` stays all-`null` in this sub-project's first
   delivery.** Confirmed no real operator-config mechanism exists for it
   anywhere in this codebase, and inventing one is a genuinely separate,
   unscoped increment (mirroring `.agentic-security/privacy-policy.json`'s
   own precedent as its own Milestone-2 sub-project). All-`null` is
   structurally legal per 6a's own `validateObligationMapping` (only
   `accepted_exception` requires non-null fields) and is the HONEST
   answer FR-504's own rule requires when an input genuinely was never
   configured — not a shortcut. **Ruling: defer real applicability-input
   config to a later, separately-scoped increment; ship with every
   record's `applicabilityInputs` explicitly null in this delivery.**
6. **First real predicate, proving the whole pipeline end-to-end**:
   HIPAA `§164.312(e)` (Transmission security), replacing/augmenting its
   current `family:crypto-tls-*` mapping with a `graph:` predicate over
   `edge.protection.transit` for flows whose dataElement carries PHI/PII
   to an `external`-kind sink. Chosen because `transit` is the one
   dimension with BOTH a real, non-file-wide producer
   (`transit-protection.js`, Milestone 2 Sub-project B, complete) AND a
   real classification join (`classification.js`'s PHI/PII classes) —
   the single strongest, most provable real signal available today.
   GDPR `Art.32` is a natural, mechanical second case (same shape,
   different framework/control id) once the first is proven.
7. **PCI DSS excluded** — no catalog exists (per the parent sub-project's
   own already-ruled deferral).

## Explicitly out of scope for this sub-project's first delivery

- **`edge.protection.handling`-based predicates** — never written by any
  code today; zero real signal to read. A predicate expressing a masking/
  tokenization requirement has nothing to check against yet.
- **`flow.governanceRefs`-based predicates** — per the parent scoping
  doc's own already-established ruling, this field is not populated by
  the real pipeline; any predicate touching recipient/purpose/lawful-
  basis/retention/transfer facts stays out of scope until a separate
  governance-fact annotator exists.
- **Real (non-null) `applicabilityInputs`** — see ruling 5 above.
- **A general graph-fact query language** — the declarative-match-object
  pattern (ruling 2) is deliberately narrow and hand-matched, not a DSL.
- **PCI DSS, evidence-pack export (6c)** — separately scoped elsewhere.

## Recommended next step

A real implementation plan for this first delivery: (a) the declarative
match-object shape + its hand-written matcher, reading a shipped
`DataFlowGraph v1` document's `flows[]`/`edges[]`/`dataElements[]`/
`nodes[]`, joined by id; (b) the `graph:` predicate-dispatch branch in
`auditor-walkthrough.js`; (c) the state-vocabulary remapping producing a
real, `validateObligationMapping`-clean `ObligationMapping` record via
`obligationId`/`computeGraphDigest`; (d) the one real HIPAA `§164.312(e)`
case, proven end-to-end against a real built graph with both a
protected-transit and an unprotected-transit fixture (positive AND
negative proof, matching this session's own established discipline for
every prior sub-project's own predicate/verdict logic).
