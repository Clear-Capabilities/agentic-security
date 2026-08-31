# Milestone 2, Sub-project B scoping: transit protection analyzer (FR-401)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-scoping.md`
§5's row B: *"New `lineage/`-side analyzer joining a reconstructed path's
hops to their underlying call sites and consulting `crypto-protocol.js`'s
existing TLS/cipher pattern-recognition functions (reused as pure evidence
lookups, per Decision 1) to compute a per-edge `protection.transit`
verdict + evidence grade. Closes AC-03, AC-04, and the transit half of
AC-05/AC-06/AC-12."* This document corrects and grounds that framing
after reading `crypto-protocol.js` and the lineage pipeline's own current
plumbing directly — the same discipline Sub-project E's own scoping
correction applied before Sub-project E's implementation began.

## Finding 1: `crypto-protocol.js` is a whole-file, line-numbered scanner — not a per-call-site matcher

Confirmed by direct read: its only real export is
`scanCryptoProtocol(fp, raw)` — `fp` a file path, `raw` the file's WHOLE
source text — returning a flat array of findings, each carrying its own
`{file, line, ...}` but with NO structural tie to any parsed call
expression or CFG node. `detectTlsNoVerify`/`detectTlsMinVersion`/etc.
(exposed via `_internals` for its own tests only) are regex passes over
the whole file, the same architectural shape as `posture/cross-lang-orm.js`
and `posture/cross-lang-queues.js` (Sub-project E's own Finding 1). **This
is genuinely reusable, unlike the ORM-write case, because the SIGNAL
needed here is coarser and the reuse mechanism is different: `network-
policy-import.js`'s own established precedent** (`scanner/src/posture/
network-policy-import.js`, already read this session for Sub-project E)
**— correlating a whole-file/whole-repo finding to a specific location by
`(file, line)` proximity, not by re-deriving structural call-site
identity.** "Was TLS verification disabled ANYWHERE in this file near
this network call's own line" is a coarser, defensible question a
line-proximity join can honestly answer; it is NOT the same precision bar
E1's ORM-write recognition needed (which required exact call-site
identity to avoid false-attributing an unrelated `.create()` call).

## Finding 2: the lineage build pipeline has NO raw file text today — new plumbing is required

Confirmed by direct read: `coverage.js`'s `buildCoverageLedger`'s
`opts.perFile` is `{file: irRecord}` — an ALREADY-PARSED IR record (used
only for language-coverage stats), never raw source text. Neither
`coverage.js` nor `graph-builder.js` accepts, stores, or threads through a
file's raw string content anywhere in their current signatures. This is a
real, new plumbing concern Sub-project A/D/E's own increments never had to
solve (Sub-project A's `resolveDestination` and Sub-project D/E's
extraction functions all work purely from the ALREADY-PARSED `calleeExpr`/
`args` shapes `enumerateSinkSites` already carries — no raw text needed).
Sub-project B is the first Milestone 2 increment that genuinely needs a
new input channel into the build pipeline.

**Two real options, a genuine design decision for B1 to make, not decided
here:**

1. **Thread `opts.rawFileContents` (or similar) into `buildGraphWithCoverage`**,
   populated by whichever caller has it — ultimately `src/lineage/index.js`'s
   `buildLineageGraph`, called from `engine.js`'s `runFullScan`, which
   DOES have every file's raw content in scope already (the same
   `fileContents` map `posture/*.js`'s own whole-file scanners, including
   `network-policy-import.js`/`cross-lang-orm.js`, already consume) — a
   widening of the SAME opts-object pattern `opts.resolveSiteDecision`/
   `opts.resolveDestination` already established, just carrying data
   instead of a function.
2. **Run transit-protection analysis as a SEPARATE, later pass**, entirely
   outside `coverage.js`/`graph-builder.js`, taking an ALREADY-BUILT graph
   plus a `{file: rawText}` map and mutating `edge.protection.transit` in
   place for network-external-api edges — mirroring how `index.js` itself
   wraps `coverage.js` for scan-facing concerns, one layer further out.

**Confirmed, not just likely: Option 2 is directly buildable today.**
Read `index.js` and its real caller, `engine.js`'s `runFullScan`, directly:
`buildLineageGraph`'s own `opts.perFile` is (like `coverage.js`'s) an
already-parsed-IR record, carrying no raw text either — but `runFullScan`
ITSELF is declared as `async function runFullScan({fileContents={}, ...})`
(line 8625), and the `buildLineageGraph(callGraph, {...})` call site (line
9264) sits inside that SAME function scope — `fileContents` (the real
`{path: rawSourceString}` map, already used pervasively elsewhere in
`runFullScan` for `dropGuardedFindings`/`_isInlineSuppressed`/etc.) is
directly in scope there today, unused by the lineage call. Threading it
through is a one-line addition to the existing call site plus a new
`opts.fileContents` parameter on `buildLineageGraph`, not a new discovery
problem. **Option 2 (a separate post-pass module consuming `{graph,
fileContents}`) is the recommended design** — it touches neither
`coverage.js` nor `graph-builder.js` at all (a real, tested,
six-increment-old pipeline this session has been careful never to
destabilize), keeps the raw-text dependency isolated to one new, small
module, and the plumbing to reach it is now confirmed trivial. B1's own
plan should still re-verify this exact call site before writing code
(it may have shifted by even one more increment's line-count drift), but
the design question itself is settled here, not left open.

## Finding 3: `edge.protection.transit` is already a real, typed target — nothing new to design there

`protection.js`'s `emptyProtection()` (Milestone 0, unchanged since) already
gives every edge a `{transit: {verdict: 'not_assessed', evidenceGrade:
'none'}, atRest: {...}, handling: {...}}` shape. `PROTECTION_VERDICTS`
(`protected`/`unprotected`/`unknown`/`not_applicable`/`not_assessed`) and
`EVIDENCE_GRADES` (`runtime`/`code_and_config`/`code`/`config`/`declared`/
`manual`/`none`) are both already-shipped enums. Sub-project B's job is
purely to COMPUTE a real value for `transit` on network edges — the
target shape needs no new schema work, unlike Sub-project D/E's own
`node.storeDetail`/`node.queueDetail`, which had to mint brand-new fields.

## Recommended increment breakdown

- **B1 (design + plumbing, Small-Medium):** resolve Finding 2's design
  question against `index.js`'s real current shape; if option 2, build the
  new module skeleton (no verdict logic yet) taking a graph + file-text map
  and doing nothing (byte-identical passthrough) — proving the plumbing
  compiles and wires in before any detection logic is added, mirroring
  Sub-project A/D's own "increment 1 is a design spike + the simplest real
  slice" precedent.
- **B2 (the verdict computation, Medium-Large):** for every edge whose
  `to` node has `category: 'external-api'` (an HTTP/network call — read
  `SINK_CATEGORIES`/`CATEGORY_NODE_KIND` to confirm which categories count
  as "network" precisely, don't assume `external-api` is the only one),
  run `scanCryptoProtocol` over that edge's own source file (cache per
  file — never re-scan the same file once per edge), then join by `(file,
  line)` proximity to the sink's own call-site line: a `crypto-tls-no-
  verify`/`crypto-tls-version` finding at or adjacent to that line →
  `unprotected`/`code` evidence; a literal `https://` destination (already
  resolvable via Sub-project A's `node.destination.literalValue`, when
  `resolutionStatus === 'literal'`) with NO such finding nearby →
  `protected`/`code`; a literal `http://` destination → `unprotected`/
  `code` regardless of any crypto-protocol finding (the scheme itself is
  the evidence, no correlation needed); a dynamic/unresolved destination
  with no nearby finding → `unknown`/`none` — closes AC-03, AC-04, and the
  literal-scheme half of AC-05.
- **B3 (exit-gate proof, Small):** real fixtures for AC-03 (cleartext
  external call — `node.destination.literalValue` starts `http://`)
  and AC-04 (`https://` literal with `rejectUnauthorized: false`/
  equivalent nearby) — reusing the SAME "real parsed code, not a hand-built
  decision object" discipline every prior increment's own exit-gate proof
  used.

## Correction (post-B1, before B2): the join must happen INSIDE `graph-builder.js`, not as a pure post-pass

B1 shipped exactly what this document recommended — a post-pass at the
`index.js` layer, touching neither `coverage.js` nor `graph-builder.js` —
and that was the RIGHT call for B1's own job (proving `fileContents` flows
through and `scanCryptoProtocol` runs). But re-reading `graph-builder.js`
directly while scoping B2 found this document's Option 2 recommendation
does NOT extend to the verdict-computation job itself, and B2's own plan
must not inherit it unmodified.

**The real constraint, confirmed by direct read:** `DESIGN_GRAPH_BUILDER.md`
§6.1's own rule — "a node is a REGISTRY DECISION, not a provenance node and
not a call site" — means a node's own `location` field is unconditionally
`null` (confirmed in `mintNode`'s node-construction object). Many distinct
call sites, in different files, at different lines, can collide onto ONE
network sink node. **The per-site `file`/`line` this whole increment needs
to correlate against a `crypto-protocol.js` finding is available ONLY on
the `site` object `enumerateSinkSites` builds — and that object is
consumed and discarded INSIDE `graph-builder.js`'s own edge-construction
loop, never surfaced onto the final `graph.edges[]` output.** Confirmed by
reading the exact edge-construction line: `protocol: { name: 'in-process',
destinationResolution: site.destination?.resolutionStatus ?? 'unknown' }`
(`graph-builder.js`, inside the same block that sets `protection:
emptyProtection()`, immediately below it) — `site` is ALREADY in scope
there, reading Sub-project A's own per-site resolution the identical way
B2 needs to read a per-site transit verdict.

**Corrected design for B2:** a new `opts.resolveTransitProtection(site) ->
{verdict, evidenceGrade} | undefined` hook on `buildDataFlowGraph`
(`graph-builder.js`), applied at that exact same block, composing into
`protection: {...emptyProtection(), transit: resolved ?? emptyProtection().transit}`
— mirroring `opts.resolveDestination`'s own additive-hook precedent
EXACTLY (Sub-project A, increment 1), not a new pattern. `coverage.js`'s
`buildGraphWithCoverage` gains the matching `opts.fileContents` passthrough
(one more parameter alongside `opts.perFile`/`opts.parseFailures`, already
an established list) and wires in a DEFAULT `resolveTransitProtection`
built from it — calling B1's own `scanTransitEvidence` once per build
(cached, never once per site) plus a new file+line join function, the
exact "hook composes with a caller-supplied override, defaults to the
real implementation" pattern `resolveDestination`/`resolveOrmWriteAtCallSite`
already established. `index.js`'s own B1-shipped `opts.fileContents` →
`transitEvidence` plumbing is UNCHANGED and still valid — it was never
wrong, just not sufficient on its own for B2's deeper hook point; B2 adds
a SECOND `opts.fileContents` consumer one layer down, in `coverage.js`,
not a replacement.

This is disclosed here, in the scoping doc, rather than silently
corrected inside B2's own plan without a trace — the same "when a plan and
reality disagree, fix it here and say so" discipline this session's other
increments have already established (`DESIGN_GRAPH_BUILDER.md`'s own
§9.1 policy, `DESIGN_DESTINATION_RESOLVER.md`'s corrections, and Sub-project
E's own scoping-doc-level corrections).

## What this does NOT do

AC-06 (database encryption unknown — that's Sub-project C, at-rest, an
entirely different protection dimension). AC-12's full "mixed" aggregate
verdict (needs Sub-project D's own `appliesToAllPaths` PLUS a transit
verdict PLUS an aggregation rule none of Milestone 2's increments have
built yet — B2 populates one INPUT to that future aggregation, not the
aggregation itself, the same "signal, not verdict" boundary D2's own
`appliesToAllPaths` work drew). Any language beyond JS/TS (`crypto-
protocol.js` itself IS multi-language, but Milestone 2's own scope
decision, carried forward from Milestone 1's §22.1 reading, stays JS/TS
lineage-side regardless of what the underlying detector could theoretically
support). Runtime corroboration (`runtime` evidence grade — Milestone 5).
