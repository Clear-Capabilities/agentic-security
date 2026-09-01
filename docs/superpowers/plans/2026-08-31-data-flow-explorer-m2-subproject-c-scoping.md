# Milestone 2, Sub-project C scoping: at-rest protection analyzer (FR-402)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-scoping.md`
§5's row C: *"The largest genuinely-new-detection sub-project in the
milestone (§3.1 — zero reusable call-site precedent exists). Correlates
application-layer field encryption evidence (where a recognizable
`transform-catalog.js` `encrypt` call sits directly on the path to a store
write), storage/IaC encryption configuration..., and database column/
transparent-encryption configuration..., into a per-store-edge
`protection.atRest` verdict... Very Large."* This document corrects that
framing for ONE of its three named evidence sources after reading
`handling-analyzer.js` (Milestone 1, Sub-project D, increment 1) and
`graph-builder.js`'s own flow-construction loop directly — the same
"verify before scoping" discipline every other Sub-project B/E correction
this session applied.

## Finding: the application-layer evidence source is ALREADY substantially built — not new detection

Confirmed by direct read: `handling-analyzer.js`'s `classifyHandling(path,
callGraph)` (shipped Milestone 2, Sub-project D, increment 1) already maps
a recognized `transform-catalog.js` `encrypt`-kind call found ON THE PATH
to `handling: 'encrypted'` (`KIND_TO_HANDLING.encrypt === 'encrypted'`,
`handling-analyzer.js:53`). `graph-builder.js`'s flow-construction loop
already calls this EXACT function, on the EXACT representative path each
flow is built from, and stores the result as `flow.handling`
(`graph-builder.js:724`) — this is the SAME "does a recognized transform
sit directly on the path to this sink" question FR-402's own bullet asks
for the application-layer evidence source. **The parent scoping doc's "zero
reusable call-site precedent exists" (§3.1) is accurate for the
STORAGE/IaC-config and database-column evidence sources (independently
confirmed during Sub-project B's own scoping: `grep -rn "CWE-311\|CWE-312"
scanner/src/sast/*.js` returns nothing, no SAST module anywhere in this
codebase detects missing/weak at-rest encryption) — but NOT accurate for
the application-layer source, which needed zero new detection, only
wiring.**

**FR-402's own anti-pattern guard — "the presence of any cipher in the same
file or repository cannot establish at-rest protection for a store" — is
ALREADY satisfied by construction**, not something this increment needs to
build defensively: `classifyHandling` walks `path.hops` (the SPECIFIC
reconstructed path for THIS flow), never "the whole file" or "the whole
repo" — an unrelated `encrypt()` call elsewhere in the same file that isn't
on this flow's own path is structurally invisible to it. This is the exact
same "correlate by real structural path, not by file proximity" precision
Sub-project A/D/E's own increments already established, genuinely stronger
than Sub-project B's own file+line-WINDOW correlation (which B2 itself
disclosed as a coarser, line-proximity heuristic) — because a reconstructed
path IS a real data-flow proof, not a nearby-text heuristic.

## The exact wiring point (mirroring Sub-project D2's own "look up an already-minted entity, mutate a field in place" precedent)

Confirmed by direct read: `flow.edgeIds: [edgeIdStr]` (line 707) and
`flow.handling: classifyHandling(p, callGraph).handling` (line 724) are
set in the SAME flow-construction loop iteration, both from the SAME
`group[0]` destructuring (`p`, `snk`, `edgeIdStr` all already in scope
there). The edge itself was already minted earlier, in the site-processing
loop, into `edgesById` (the same map Sub-project A/B's own `resolveDestination`/
`resolveTransitProtection` hooks compose into at MINT time — but THIS
increment's evidence, `flow.handling`, is only known LATER, in the
flow-loop, exactly like Sub-project D2's `transformation.appliesToAllPaths`
computation was). The design this implies, precisely: **in the SAME
flow-construction loop, right where `handling: classifyHandling(...)` is
already computed, if the result is `'encrypted'` AND `snk.kind === 'store'`
(the node-kind Sub-project E confirmed `database`/`file`/`object-storage`
categories all map to via `CATEGORY_NODE_KIND`), look up
`edgesById.get(edgeIdStr)` and set its `protection.atRest =
{verdict: 'protected', evidenceGrade: 'code'}` in place** — mirroring
`transformsById.get(tid).appliesToAllPaths = ...`'s own established
mutate-after-mint pattern (Sub-project D, increment 2), not a new
architectural pattern.

## What genuinely remains new, unbuilt detection (the OTHER two evidence sources)

- **Storage/IaC encryption configuration** — confirmed zero precedent
  (`iac-cloud-templates.js`/`iac-terraform.js` have no at-rest-encryption
  rule today, per Sub-project B's own scoping-doc finding). Extending
  either module to detect e.g. an S3 bucket's `ServerSideEncryptionConfiguration`,
  an RDS instance's `StorageEncrypted: true`, a Terraform resource's
  `kms_key_id`, etc., correlated back to a SPECIFIC store node by name/
  resource-identifier matching, is real, substantial, genuinely new
  detection work — its own increment, its own precision-design questions
  (an IaC resource NAME rarely matches a lineage node's own
  category-granular identity directly; this needs its own correlation
  strategy, not reused from anywhere in this document).
- **Database column/transparent-encryption configuration** — FR-402's own
  "database column or transparent encryption configuration when supplied"
  clause. No existing detector or schema field carries this today either;
  a real, separate increment.

## Recommended increment breakdown

- **C1 (application-layer wiring, Small — comparable in size/risk to B1,
  genuinely smaller than B2 since NO new correlation heuristic is needed,
  only a lookup-and-mutate):** wire `flow.handling === 'encrypted'` into
  `edge.protection.atRest` for `store`-kind sinks, per the exact design
  above. Closes the application-layer THIRD of AC-06's own evidence
  surface (AC-06's own worked example — "PHI written to
  `patients.diagnosis` and no correlated at-rest configuration is
  available... at-rest protection is `unknown`, not protected" — is
  actually the NEGATIVE case: C1 alone cannot make AC-06 itself pass,
  since AC-06 specifically tests the ABSENCE of encryption evidence
  staying honestly `unknown` — C1 gives this increment something REAL to
  test the presence-case against, and confirms the absence-case already
  falls through to `emptyProtection()`'s own honest default with zero new
  code, the same "does nothing when there's no evidence" property every
  prior additive hook has proven).
- **C2 (storage/IaC encryption detection, Very Large — the genuinely new
  detection work, deserves its OWN dedicated scoping pass when picked up,
  not pre-scoped here):** named, not attempted in this document.
- **C3 (database column/transparent-encryption, Medium — needs its own
  scoping pass too):** named, not attempted here.
- **C4 (AC-06 exit-gate proof + the anti-pattern guard's own dedicated
  regression test):** proves the negative case explicitly (an
  `encrypt()` call present in the SAME FILE but NOT on the flow's own
  path must not make `atRest` read protected) — likely foldable into C1's
  own test suite once C1 exists, confirm rather than pre-decide.

## What this does NOT do

AC-12's at-rest half of the "mixed" aggregate verdict (needs an
aggregation rule, same boundary Sub-project B/D's own signal-vs-verdict
distinction already drew). Any language beyond JS/TS. `runtime` evidence
grade. **Correction, re-verified against the real `CATEGORY_NODE_KIND`
table before finalizing this document:** `kind: 'store'` already covers
`database`/`file`/`object-storage`/`cache`/`client-storage`/`backup`/
`export` — a BROADER set than this document's own earlier draft credited,
closely matching most of FR-402's own list already. Only `queue` (its own
distinct `kind: 'queue'`) and `vector-store`/`model`/`training` (not
`SINK_CATEGORIES` values at all, per Milestone 1's own D1 unreachable-list
finding) fall genuinely outside a plain `snk.kind === 'store'` filter —
name THIS narrower, corrected gap as C1's own deferred widening question,
not the wider one an earlier draft of this paragraph implied.
implementation plan to decide against the real `CATEGORY_NODE_KIND` table,
not assumed here.
