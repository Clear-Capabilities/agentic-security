# M4 Deliverable #7 (FR-501, DFG-035): Executive Risk Story Mode — Scoping

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` §14 lines 436-460
(the "Executive Risk Story Mode" requirement — **note a real PRD ID
collision**: `FR-501` also names an unrelated §20 "Coverage banner"
requirement at line 1462; every reference in this doc means the §14
capability, never the banner). `DecisionStory` extension contract:
§10.10, line 966. Acceptance criterion: AC-25 (lines 1725-1731). Backlog
row: DFG-035 (deps DFG-012, DFG-017, DFG-019, DFG-027, DFG-028 — all
already shipped in Milestone 3/4; **DFG-022/DFG-037, the Time Machine
snapshot/diff work, are NOT listed as formal dependencies**, despite one
of the 5 required chapters needing exactly that — see below). Parent doc:
`2026-09-01-data-flow-explorer-m4-scoping.md`'s own row 7.

## What the PRD requires

A `Briefing` entry point producing an interactive, evidence-linked
`DecisionStory` with 5 chapters (scope/confidence, sensitive-data
footprint, external exposure, control/governance gaps, change/decisions),
a transparent 9-factor ranking engine (sensitivity, externality, control
verdict, recipient/jurisdiction, AI use, breadth/blast radius, evidence
confidence, policy state, change recency), 6 audience-language modes
(Board/CISO/Privacy/Compliance/Regulator/Technical), and export to
self-contained HTML, PDF/print, and presentation-mode images.

## Real investigation (grounds every scope decision below — no factor or
chapter here is estimated without checking the real graph/module)

**7 of 9 ranking factors are direct reads off the already-shipped
`DataFlowGraph v1` today, zero new computation:**

| Factor | Real signal |
|---|---|
| Sensitivity | `dataElement.dataClasses[]` |
| Externality | `node.externality.value` |
| Control verdict | `flow.protectionSummary` (`protection.js#aggregateVerdicts`) |
| AI use | `node.subtype === 'ai-model-provider'` (sink-registry category — NOT `dataElement.aiContexts[]`, which is hardcoded `[]` at `graph-builder.js:518` and never populated in this milestone; the node-level destination signal is the real, usable one) |
| Evidence confidence | `flow.confidence`/`node.confidence` `{score, tier}`, plus `protection.js`'s per-dimension `EVIDENCE_GRADES` |
| Policy state | `flow.policyVerdict` (`graph-builder.js:758-871`) |

**1 factor needs a small, real, buildable-now addition:**

- **Breadth/blast radius** — no field exists (`flow.alternatePathCount`
  and edge/dataElement counts are weak proxies only). Real addition: a
  small new aggregation counting distinct flows/nodes sharing a node or
  dataElement across the graph. Self-contained; no external dependency.

**2 factors are real, honest gaps — NOT buildable in this sub-project:**

- **Recipient/jurisdiction** — no jurisdiction field anywhere in the
  schema. Needs a `RecipientProfile` extension, which is capability #6
  (Third-Party/Cross-Border Intelligence) — the M4 parent doc's own row
  for that capability already flags it "weakest data foundation,"
  recommended LAST in the sub-project order, for exactly this reason
  (no provider-name resolution, no jurisdiction database exists yet).
- **Change recency** — confirmed absent: no `GraphSnapshot`/`GraphDiff`
  module exists anywhere under `scanner/src/lineage/` (only
  forward-declarations in `obligation-mapping.js`/`ids.js`/`CLAUDE.md`).
  Needs capability #3 (Data-Flow Time Machine, FR-503, DFG-022/DFG-037),
  not yet built.

**Chapters 1-4 are fully buildable now** (chapter 4's only gap is the
same jurisdiction gap as the ranking factor — retention/purpose/
lawful-basis/policy-conflict sub-claims all have direct reads via
`flow.governanceRefs`/`flow.policyVerdict`). **Chapter 5 (change and
decisions) is NOT fully buildable** — it needs the same
`GraphSnapshot`/`GraphDiff` prerequisite as the change-recency factor.

**Export/evidence infrastructure to reuse, not rebuild:**
`scanner/src/posture/obligation-evidence-pack.js` is the exact precedent
— `evidence-bundle.js`'s `ensureKeyPair`/`keyPaths`/`canonicalJson` +
`export-json.js`'s `computeGraphDigest` already produce a signed,
versioned pack with graph digest + reproducibility metadata + evidence
grade, which is literally AC-25's own requirement list ("preserves graph
digest and reproducibility metadata").

## Scope decision (mirrors this project's own "manual_required, never
silently absent" discipline — the same choice DPIA/RoPA made for an
unclassified flow, generalized here)

**In scope for this sub-project:**
- `DecisionStory` extension contract (§10.10 shape).
- Ranking engine: 8 of 9 factors computed for real (7 direct-read + 1
  new small aggregation); the 9th (recipient/jurisdiction) explicitly
  disclosed as unavailable per-story (not silently dropped from the
  factor list — shown, scored as `unknown`, never fabricated), matching
  `MANUAL_REQUIRED`'s own convention.
- Chapters 1-4, fully real. Chapter 5 present but honestly degraded: no
  "new/worsened flow" claims (no baseline to compare against), but still
  surfaces real, currently-decision-relevant facts (e.g., flows whose
  `policyVerdict` is `manual_review_required` — genuinely "a decision
  needed now," not a change claim) with an explicit
  "no historical baseline available in this milestone" disclosure,
  satisfying AC-25's "coverage limitations remain prominent" requirement
  rather than silently omitting a PRD-required chapter.
- 6 audience-language modes — text/wording variation over the SAME
  underlying facts (PRD's own "without changing the underlying facts"
  constraint), not 6 separate ranking/chapter computations.
- CLI export: `dataflow export --format briefing` (Markdown/HTML,
  mirroring the `dpia`/`ropa` precedent) with graph digest +
  reproducibility metadata, reusing `obligation-evidence-pack.js`'s own
  signing composition for a signable variant.

**Out of scope (disclosed, not silently dropped):**
- The interactive `Briefing` frontend view (global-header entry point,
  chapter rail, drill-down links, presentation-mode image capture) — a
  genuinely separate, large undertaking matching Milestone 3's own
  multi-sub-project scale for each interactive view (golden/render/wire/
  xss/a11y/perf/ux-filters/ux-query took ~8 sub-projects for THREE
  views). This sub-project ships the deterministic data + CLI/export
  layer only, exactly the same scope cut DPIA/RoPA made (CLI-only,
  frontend button explicitly deferred). PDF/print and presentation-mode
  images depend on this same frontend work and are deferred with it —
  only the Markdown/HTML self-contained export ships now (matching the
  `html` format's own existing Chrome-optional generation path).
- Change-recency ranking factor and chapter 5's "new/worsened flows"
  claims — blocked on Time Machine (capability #3, FR-503), the PRD's
  own next-ranked capability after this one. Recommend Time Machine as
  the NEXT sub-project after this one, both because it is next in the
  PRD's own capability ranking and because it unblocks this gap.
- Recipient/jurisdiction ranking factor — blocked on capability #6
  (Third-Party Intelligence), already recommended last in the M4 parent
  doc's own sub-project order for its own, independently-found reasons.
- Any optional model-written narrative (PRD explicitly requires it
  off-by-default, gated by existing egress/consent policy) — not
  attempted; the deterministic template engine alone satisfies FR-501's
  binding requirement ("a deterministic template engine is required").

## Recommended task breakdown

1. **`DecisionStory` contract + ranking engine** — new
   `scanner/src/lineage/decision-story.js` (or similar), the 8
   real-factor computation + the 9th's honest-gap representation, one new
   small aggregation for breadth/blast-radius. Mirrors sub-project 6a/6b's
   shape (small contract + real analytical engine).
2. **Chapter content generation** — 5 deterministic emit functions over
   the ranking engine's output + direct graph reads, mirroring
   `export-privacy.js`'s own emit-function shape (and its
   Markdown-escaping discipline — operator-supplied governance prose
   flows into chapter 4 the same way it flowed into DPIA/RoPA).
3. **CLI wiring + audience modes** — `dataflow export --format briefing`,
   `--audience board|ciso|privacy|compliance|regulator|technical`,
   `commands/dataflow.md` updates, signed-evidence-pack variant reusing
   `obligation-evidence-pack.js`'s composition.
