# M4 sub-project 6c (evidence-pack export) — scoping

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md`, FR-504 (line 497-517)
and PRD §10.10 (extension-record contract). Parent decomposition:
`2026-09-01-data-flow-explorer-m4-obligation-overlay-scoping.md`'s own #6
row — "6c (evidence-pack export, a new signed-bundle module — NOT a reuse
of the finding-shaped `evidence-bundle.js` — not yet planned)."

## What FR-504 requires, verbatim

> Evidence packs include scope, framework versions, facts, evidence index,
> unknown/manual items, accepted exceptions, scan health, limitations,
> graph digest, and reproducibility metadata.
>
> Framework packs are signed/versioned local content.

Nine named fields plus the signing requirement. Every field below is
mapped to a real, already-computed source — nothing is invented.

## What already exists (read directly, not assumed)

- `scanner/src/lineage/obligation-predicates.js` (6b, merged) — produces
  real `ObligationMapping` records (`state`, `predicate`,
  `contributingGraphIds`, `evidence`, `framework`, `frameworkVersion`,
  `requirementId`, `applicabilityInputs`) via `evaluateFramework` in
  `posture/auditor-walkthrough.js`. Each control's evaluation entry
  carries `obligationMappings: ObligationMapping[]`.
- `scanner/src/lineage/export-json.js#computeGraphDigest(graph)` — the
  "reusable digest pattern" the parent doc names for #6c. Canonicalizes
  the whole graph via an EXCLUDE-list (not a hand-maintained allowlist),
  sha256 hex digest.
- **Three existing signed-artifact siblings, a firmly established
  pattern, not a one-off:**
  - `posture/evidence-bundle.js` (D2) — per-FINDING Ed25519 bundle. Exports
    the REUSABLE primitives every sibling since has imported directly:
    `ensureKeyPair()`, `keyPaths()`, `canonicalJson()` (generic,
    shape-agnostic deterministic serializer — safe for any bundle shape).
    `canonicalBytes()`/`buildEvidenceBundle()`/etc. are finding-specific,
    never reused.
  - `posture/provenance-evidence-bundle.js` (Finding Provenance PRD M4
    §4.1) — per-FINDING-PROVENANCE bundle. Second sibling. Imports
    `ensureKeyPair, keyPaths, canonicalJson` from `evidence-bundle.js`
    directly ("same Ed25519 key material — reused, not reimplemented").
    Signs `canonicalJson(bundle)` directly (no separate `canonicalBytes`
    needed, since nothing unlisted is ever put on the object before
    signing) — own `PROVENANCE_BUNDLE_SCHEMA` string, own top-level-key
    allowlist, own build/sign/verify trio.
  - `posture/compliance-evidence-signing.js` (assurance-hardening PRD
    FR-505) — signs `emitEvidenceJsonLd()`'s WALKTHROUGH-STATUS output
    (`present`/`partial`/`absent`/`manual`, family:/module:/rule:-driven).
    Third sibling, same reused-key pattern. **Confirmed NOT the same
    artifact FR-504 wants**: it carries nothing about `ObligationMapping`
    records, graph digests, or `contributingGraphIds` — it is the
    walkthrough's pre-existing present/partial/absent/manual status,
    signed. FR-504's evidence pack is a distinct, fourth artifact.
  - `bin/agentic-security.js`'s `cmdAttest`/`cmdVerifyAttestation` already
    dispatch on a flag (`--provenance`) / a schema marker
    (`bundle.schema === PROVENANCE_BUNDLE_SCHEMA`, checked before the
    `ComplianceEvidence`/plain-finding-bundle fallbacks) to route to the
    right sibling's build/sign or verify function. A fourth artifact
    slots into this exact, already-proven dispatch shape.
- `posture/evidence-grade-wording.js`'s `EVIDENCE_GRADE_DISCLAIMER` — the
  PRD-mandated "this does not certify compliance" wording, already reused
  verbatim by `compliance-policy.js`/`privacy-framework.js`/
  `auditor-walkthrough.js`. FR-504's own line 514 ("`evidence_supported`
  ... does not mean the organization is compliant... in full") is this
  same disclaimer's own point — no new prose needed.
- `posture/auditor-walkthrough.js#loadFramework(scanRoot, id)` — real
  framework metadata (`id`, `name`, `publisher`, `license`, `url`,
  `controlsDigest` used as `frameworkVersion` throughout 6b, `scope`).
- `DataFlowGraph v1`'s own `graph.scope`/`graph.coverage`/
  `graph.limitations` fields (already read by `export-json.js`) — real,
  already-populated scope/coverage/limitations data, no new detection.

## The one real gap: "evidence index"

6b's final review (Recommended 3, disclosed in `obligation-predicates.js`'s
own header) found `record.evidence` is **structurally always empty** on a
real graph — `graph-builder.js:692` hardcodes `edge.evidenceRefs: []` and
nothing downstream populates it. An evidence pack that just re-serializes
`record.evidence` per fact would ship an "evidence index" that is
honestly, permanently empty — technically compliant with the PRD's field
list, uselessly so.

**Decision**: build the evidence index from `record.contributingGraphIds`
instead — real flow ids `evaluateGraphFlowPredicate` already returns,
resolved back into a small, real summary per flow (source/sink kind,
`dataElement.dataClasses`, the edge's `protection.transit/atRest/handling`
verdicts) by joining against `graph.flows`/`.nodes`/`.edges`/
`.dataElements`, mirroring `obligation-predicates.js`'s own
id→entity-Map-join pattern (a design precedent to follow, not code to
import — that module doesn't export a joiner). This is genuinely
reproducible, graph-digest-anchored evidence, unlike the vestigial empty
array. `record.evidence` is still carried through verbatim (honest, even
though empty today) — the evidence index is an ADDITIONAL, populated
section, not a replacement that hides the gap.

## Design

**New module**: `scanner/src/posture/obligation-evidence-pack.js` —
fourth sibling in the `evidence-bundle.js` family, living in `posture/`
(not `lineage/`) for the same reason `provenance-evidence-bundle.js` and
`compliance-evidence-signing.js` do: it needs the shared Ed25519 key
infrastructure that already lives in `posture/`, and `posture/` already
imports `lineage/` (the one-way boundary 6b established) — so this module
importing `computeGraphDigest` from `lineage/export-json.js` extends an
already-proven direction. It never needs `lineage/` to import back.

```js
export const OBLIGATION_EVIDENCE_PACK_SCHEMA = 'agentic-security/obligation-evidence-pack@1';

export function buildObligationEvidencePack({
  graph, framework, evaluation, scanHealth, engineVersion, rulesetVersion, bundleSha, generatedAt,
}) { ... }

export function signObligationEvidencePack(pack, privateKeyPem) { ... }
export function verifyObligationEvidencePack(pack, publicKeyPem) { ... }
export { ensureKeyPair, keyPaths } from './evidence-bundle.js';
```

`buildObligationEvidencePack`'s output (all nine PRD-named fields plus the
disclaimer and schema/generatedAt housekeeping):

| Field | Source |
|---|---|
| `schema` | `OBLIGATION_EVIDENCE_PACK_SCHEMA` |
| `framework` | `{id, name, version: framework.controlsDigest, publisher, url}` |
| `scope` | `graph?.scope ?? null` |
| `facts` | `evaluation.flatMap(e => e.obligationMappings ?? [])` |
| `evidenceIndex` | per fact, `contributingGraphIds` resolved to real flow summaries (see above) |
| `unknownItems` | facts filtered `state === 'unknown'` |
| `manualItems` | facts filtered `state === 'manual_required'` |
| `acceptedExceptions` | facts filtered `state === 'accepted_exception'` |
| `scanHealth` | passed through verbatim from the caller (`scan.scanHealth` when present), `null` otherwise — never fabricated |
| `limitations` | `graph?.limitations ?? []` |
| `graphDigest` | `computeGraphDigest(graph)`, `null` when no graph |
| `reproducibility` | `{graphId, graphDigest, engineVersion, rulesetVersion, bundleSha, generatedAt}` |
| `disclaimer` | `EVIDENCE_GRADE_DISCLAIMER` (verbatim reuse) |

A `null`/absent `graph` (the framework has a `graph:` mapping but no
`AGENTIC_SECURITY_LINEAGE_DEEP=1` scan ran) must degrade honestly — empty
`facts`/`evidenceIndex`, `null` `graphDigest`/`scope` — never throw, never
fabricate, matching every sibling module's "never throws on malformed
input" convention `obligation-predicates.js`'s own header cites.

**CLI wiring**: `agentic-security attest --obligations <frameworkId>` —
mirrors `--provenance`'s exact shape in `cmdAttest` (own `if
(args.flags.obligations)` branch, own output filename, same
`ensureKeyPair()`/output-dir/public-key-sharing message pattern).
`cmdVerifyAttestation` gains a fifth auto-detected branch (checked
alongside the existing `ComplianceEvidence`/provenance-bundle checks,
before the plain-finding-bundle fallback) keyed on
`bundle.schema === OBLIGATION_EVIDENCE_PACK_SCHEMA`.

**Out of scope for 6c** (real, disclosed, deferred — matching 6a/6b's own
precedent of naming rather than silently dropping):
- Multi-framework packs (one pack per framework per attest call, matching
  `evaluateFramework`'s own one-framework-per-call shape — no bundled
  "evaluate every framework" loop exists anywhere in this codebase today).
- Populating `record.evidence` itself at the source (`graph-builder.js`) —
  a real, disclosed upstream gap 6b already named; not this sub-project's
  job.
- A PDF/HTML rendering of the evidence pack (FR-504 names the artifact's
  CONTENT, not a rendering format; `renderWalkthrough`'s existing markdown
  output already surfaces per-control obligation state — a dedicated
  evidence-pack renderer is real, separate, deferred scope).

## Task breakdown (SDD-sized)

- **Task 1**: `obligation-evidence-pack.js` — the pure builder + sign/verify
  trio, unit-tested against real `buildGraphWithCoverage` output (never a
  hand-built fixture alone, per this session's own hard-won lesson from
  6b's final review) plus the real `evaluateFramework` HIPAA §164.312(e)
  case already wired in 6b.
- **Task 2**: CLI wiring (`cmdAttest --obligations`,
  `cmdVerifyAttestation`'s fifth branch) + docs (`scanner/CLAUDE.md`'s
  "Signed, portable evidence" section, `scanner/src/lineage/CLAUDE.md`'s
  sub-project #6 table row).

This closes out M4 sub-project #6 (6a + 6b + 6c) in full once merged.
