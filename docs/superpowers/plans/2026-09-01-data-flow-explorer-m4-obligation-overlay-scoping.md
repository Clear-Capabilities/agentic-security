# Milestone 4, sub-project #6 (Regulatory Obligation Overlay + evidence packs, FR-504): scoping

Per the M4 top-level scoping doc's own sub-project table: *"Large |
ObligationMapping extension contract (new) | Most tractable of the 4
decision-intelligence FRs — real framework/control data already exists
(docs/compliance/, NIST catalog generator) and real per-flow governance
data already exists (flow.governanceRefs)."* #1–#5 are all now COMPLETE
and merged. This document investigates the real current code and PRD text
(not the top-level doc's pre-investigation assumptions) and finds the
sizing rationale needs real correction, plus one PRD-internal defect and
one PRD-vs-M4-doc dependency contradiction that need explicit rulings
before a plan is written.

## Real, disclosed corrections to the M4 top-level doc's framing

1. **`flow.governanceRefs` is NOT populated by the real pipeline —
   this is the M4 doc's central "most tractable" argument, and it's
   false as stated.** The real production graph-builder
   (`scanner/src/lineage/graph-builder.js`, both the node-mint site and
   the flow-mint site) hardcodes `governanceRefs: {}` unconditionally.
   The only place non-empty values exist anywhere in the repo is the
   hand-authored demo/golden fixture
   (`scanner/src/lineage/fixtures/flagship-graph.json`) — never a real
   scan of a real repository. The schema (`dataflow-graph.schema.json`)
   is untyped (`{"type":"object"}`, no enum, no required keys) and
   `validate.js` checks presence, never content. The field IS a real,
   wired, consumed contract (`frontend/src/views/privacy-view.js`
   renders per-lifecycle-stage badges from it) — the gap is entirely on
   the PRODUCER side. **Ruling: do not build ObligationMapping
   predicates that assume `governanceRefs` is populated.** Any
   predicate keyed to recipient/purpose/lawfulBasis/retention/deletion/
   transfer facts must resolve to `manual_required` or `unknown` for
   every real scan until a separate governance-fact annotator exists —
   which itself does not exist and is not scoped here (see "Explicitly
   out of scope" below). This is consistent with, not a workaround of,
   the PRD's own explicit rule (§10.10, and FR-504's own applicability-
   inputs rule): never guess a fact from a field name; mark it unknown
   instead.

2. **A materially stronger real foundation exists and was never cited
   by the M4 doc: `flow.policyVerdict`.** Real, wired since Milestone 2
   (`scanner/src/lineage/CLAUDE.md`'s Sub-project G): computed in
   `graph-builder.js` via `isSinkPermitted`, reading an
   operator-declared `.agentic-security/privacy-policy.json`,
   fail-closed (missing policy → `not_evaluated`, not `permitted`), and
   evidence-backed (mints a real `graph.evidence[]` entry per rule).
   Obligations anchored to `policyVerdict`, `edge.protection.{transit,
   atRest}`, and node/data classification are the ones that can
   genuinely resolve to `evidence_supported`/`gap_detected` today — not
   the governance-lifecycle ones.

3. **A strong, directly-reusable architectural precedent already
   exists for exactly the honesty problem FR-504 describes, and the M4
   doc undersold it.** `scanner/src/posture/auditor-walkthrough.js` (the
   engine behind `/compliance`, 9 real framework catalogs under
   `scanner/src/posture/compliance-frameworks/`) already implements
   typed predicate mappings (`family:`, `module:`, `rule:`) resolving
   to `present`/`partial`/`absent`/`manual` — the same four-or-more-way
   honesty split FR-504 needs, just for SAST/SCA findings instead of
   graph facts. `scanner/src/report/oscal.js`'s own header is, in
   effect, a design document for "never claim satisfied for a control
   the engine didn't decide" — the exact discipline AC-28 demands.
   **Ruling: FR-504's mapping/predicate engine should be architected as
   a new predicate TYPE added to this same typed-predicate family
   (reading graph facts instead of findings), not an unrelated new
   design.**

4. **PCI DSS — one of the PRD's 6 named "initial packs" — has zero
   existing catalog.** `scanner/src/posture/compliance-frameworks/`
   has 9 frameworks; PCI DSS isn't one of them. Existing PCI-adjacent
   code is all data-*classification* (tagging a field as
   PCI-scoped), never a control catalog. Authoring even a minimal PCI
   DSS catalog (12 requirements + sub-requirements) is real,
   un-estimated content work the M4 doc's one-liner didn't mention.
   **Ruling: ship the other 5 packs (GDPR, CCPA/CPRA, HIPAA, EU AI Act,
   NIST Privacy Framework — all 5 already have real catalogs) in this
   sub-project's first delivery; PCI DSS catalog authoring is a
   separate, explicitly deferred follow-up**, not silently dropped
   (name it, don't hide it).

5. **PRD-internal defect: "FR-504" is used for two unrelated
   requirements.** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md:497`
   ("Regulatory Obligation Overlay and evidence packs," §7.12 — this
   sub-project) and `:1493` ("No unsupported 'protected' verdict," §20,
   a Milestone-2-era honesty rule, unrelated) are both numbered FR-504.
   Each section restarts its own FR-50x numbering locally. **Ruling:
   cite this requirement as "FR-504 (§7.12, Regulatory Obligation
   Overlay)" in all further docs/code comments to disambiguate — never
   bare "FR-504."**

6. **PRD-vs-M4-doc dependency contradiction.** The PRD's own dependency
   table (`DFG-038`, line 1897) lists **DFG-020 (graph-derived
   DPIA/RoPA, M4 deliverable #10) as a prerequisite of** the Regulatory
   Overlay. The M4 top-level doc's own deliverable #10 row and
   "Recommended sub-project order" say the reverse — DPIA/RoPA depends
   on #6, "a thin templating layer once #6 exists." **Ruling: the M4
   doc's order is kept** — building the obligation-mapping engine
   first, with DPIA/RoPA as a template consumer of it afterward, is the
   only one of the two orderings that is actually buildable (DPIA/RoPA
   has no independent data model of its own in the PRD; §10.10 doesn't
   list `DPIA`/`RoPA` among the 9 extension contracts, so it must be
   derived from something — the natural candidate is ObligationMapping
   output). This reverses the PRD's own literal DFG-038 dependency
   edge — a real, disclosed deviation, not a silent one.

## What already exists (confirmed by direct source read this session)

- `scanner/src/posture/auditor-walkthrough.js` + 9 JSON catalogs under
  `scanner/src/posture/compliance-frameworks/` — typed-predicate
  (`family:`/`module:`/`rule:`) evaluation, `present`/`partial`/
  `absent`/`manual` states, `COMPLIANCE_FAMILY_GAPS` disclosure for
  known detector gaps.
- `scanner/src/report/oscal.js` — the "never claim satisfied for an
  undecided control" precedent (EXAMINE-method observations for
  `manual`/gap controls).
- `flow.policyVerdict` (`permitted`/`prohibited`/`not_evaluated`,
  `graph-builder.js`, Milestone 2) — real, evidence-backed, fail-closed.
- `edge.protection.{transit,atRest}`, node externality/data
  classification — real, wired since earlier milestones (cited
  repeatedly across this session's own prior sub-project docs).
- `scanner/src/posture/evidence-bundle.js` — Ed25519 sign/verify
  primitives (`canonicalBytes`, `ensureKeyPair`,
  `signEvidenceBundle`/`verifyEvidenceBundle`), but its own schema is
  hardcoded to a per-FINDING shape (`BUNDLE_SCHEMA =
  'agentic-security/finding-evidence@1'`) — NOT directly reusable for a
  per-obligation pack; its own header explicitly warns against widening
  it ("Merging them would produce an artefact worse at both"). The
  low-level canonicalization/signing PRIMITIVES generalize; the
  finding-shaped schema does not.
- `computeGraphDigest` (`scanner/src/lineage/export-json.js`) — the
  right precedent for "reference the exact base graph digest an
  extension record was computed against" (§10.10's own cross-cutting
  rule) — directly reusable as-is.
- `cmdDataflowExport` (`scanner/bin/agentic-security.js`, sub-project
  #5) — the existing six-format CLI contract (png/pdf/svg/json/csv/
  html) an evidence-pack export most naturally extends as a 7th format,
  or a sibling `agentic-security compliance evidence-pack` subcommand.
- `flow.governanceRefs` — real contract + real consumer
  (`privacy-view.js`), but NOT a real producer (see correction #1
  above). Genuinely absent as a usable signal today.
- No PCI DSS catalog anywhere (see correction #4).

## Explicitly out of scope for this sub-project's first delivery

- **A governance-fact annotator** that would actually populate
  `governanceRefs` from real evidence (operator-declared config, most
  plausibly — nothing in this codebase infers recipient/lawful-basis/
  transfer facts from code). Real, separate, unscoped work; without it,
  governance-lifecycle obligations honestly resolve to
  `manual_required`/`unknown`, which is a correct (not degraded)
  outcome per the PRD's own applicability-inputs honesty rule.
- **A PCI DSS control catalog** (see correction #4) — content-authoring
  work, not an engineering blocker; deferred and named, not hidden.
- **DPIA/RoPA export** (M4 deliverable #10) — a separate sub-project,
  consuming this one's output once it ships (see correction #6).

## Recommended decomposition (this sub-project is itself "Large" — split it)

Matching this session's own established convention (M3 was split into
many sub-projects rather than planned as one), and per the
writing-plans skill's own "Scope Check" guidance (a spec covering
multiple independent subsystems should be broken into sub-project
specs), recommend three further-scoped pieces, in dependency order:

1. **6a — `ObligationMapping` extension contract.** Small, mechanical **— COMPLETE (2026-09-01)**: schema additions in `scanner/src/lineage/` (the six PRD-specified
   states: `evidence_supported`/`gap_detected`/`unknown`/
   `manual_required`/`not_applicable`/`accepted_exception`), a stable-ID
   function, and a self-contained structural validator (`obligation-mapping.js`'s
   own `validateObligationMapping` — deliberately OUTSIDE `validate.js`,
   which stays byte-identical, per this doc's own binding ruling above
   that records are not `DataFlowGraph v1` entities) — following the same
   design-doc-then-module pattern every prior `src/lineage/` addition
   this session used.
2. **6b — the predicate/mapping engine — scoped (2026-09-01), see own
   doc.** The real work: a new graph-fact-reading predicate type added
   to the SAME typed-predicate architecture `auditor-walkthrough.js`
   already implements, evaluated against 5 real framework catalogs
   (GDPR/CCPA/HIPAA/EU AI Act/NIST Privacy Framework — reusing the 5
   that already have real catalogs; PCI DSS excluded per correction
   #4), honoring the OSCAL precedent's "never claim decided for what
   wasn't" discipline and AC-28's "evidence ≠ compliance" wording
   verbatim in any rendered output. Its own scoping doc
   (`2026-09-01-data-flow-explorer-m4-obligation-predicate-scoping.md`)
   found `evaluateFramework`'s dispatch is a hardcoded if/else-if chain
   (a `graph:` branch slots in with zero signature change — it already
   receives `scan.lineageGraph`), that no catalog carries a real
   `frameworkVersion` field (ruling: synthesize from `controlsDigest`),
   that `applicabilityInputs` has no real operator-config source
   anywhere in this codebase and stays honestly all-`null` in this
   delivery (a genuinely separate, deferred increment — mirroring the
   privacy-policy.json precedent), and that the first real, most
   provable predicate is HIPAA §164.312(e)'s transit-protection check
   (the one dimension with both a real producer and a real
   classification join). Not yet planned.
3. **6c — evidence-pack export.** A new, parallel signed-bundle module
   (own schema constant, own allowlist — NOT a widened
   `evidence-bundle.js`) composing `computeGraphDigest`'s reusable
   digest pattern, wired as a 7th `dataflow export` format or a
   dedicated `compliance evidence-pack` subcommand, matching PRD line
   516's real field list (scope, framework versions, facts, evidence
   index, unknown/manual items, accepted exceptions, scan health,
   limitations, graph digest, reproducibility metadata).

## Recommended next step

A real scoping+plan doc for **6a** first (smallest, unblocks 6b/6c,
lowest risk of a wrong design decision propagating), following this
sub-project's own now-corrected architecture and explicit ruling set
above — matching this session's own established discipline of a
grounded scoping pass before any task-level implementation plan.
