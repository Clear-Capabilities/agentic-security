# DESIGN_TRANSIT_PROTECTION.md — Sub-project B's binding design record (increments 1-2)

**Status:** increment **1** (plumbing skeleton) and increment **2** (real
`edge.protection.transit` verdicts, closing AC-03/AC-04) are both landed.
Increment 1 shipped per
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-b1-plan.md`
and the scoping correction at
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-b-scoping.md`.
Increment 2 shipped per
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-b2-plan.md`
and that same scoping doc's own "Correction (post-B1, before B2)" section —
which overrides §2 below's "separate post-pass, touches neither `coverage.js`
nor `graph-builder.js`" framing for the VERDICT-COMPUTATION job specifically
(§2 remains correct and unchanged for increment 1's own plumbing job — see
§6 for exactly what changed and why). Binding on later Sub-project B
increments (B3, if anything remains once B2 lands) the same way `DESIGN_
DESTINATION_RESOLVER.md` binds Sub-project A.

---

## 1. What this increment actually is

FR-401 needs a real, computed `edge.protection.transit` verdict for
network-outbound edges. Before any verdict logic can run, two things had to
exist that didn't: (1) a way to run `crypto-protocol.js`'s already-proven
TLS/cipher pattern recognition over the lineage engine's own input, and (2)
a way for that raw file text to reach the lineage build pipeline at all —
neither `coverage.js` nor `graph-builder.js` accepts, stores, or threads a
file's raw source string anywhere in their current signatures (confirmed by
direct read; see the scoping doc's Finding 2). This increment builds ONLY
those two things — the plumbing — and proves it end to end. No verdict
logic. `edge.protection.transit` is not written to anywhere in this
increment; every edge still gets `emptyProtection()`'s
`{verdict: 'not_assessed', evidenceGrade: 'none'}` exactly as before.

## 2. The isolation decision (Finding 2's Option 2, confirmed buildable and taken)

A **separate post-pass module**, `transit-protection.js`, consuming
`fileContents` directly — never a change to `coverage.js`/`graph-builder.js`
(the six-increment-old, real, tested pipeline this whole session has been
careful never to destabilize). `scanTransitEvidence(fileContents)` runs
`scanCryptoProtocol` once per file and returns a `Map<file, findings[]>` —
genuinely reusable here (unlike, say, an ORM-write catalog reuse case)
because the signal needed is coarser: "was TLS verification disabled
ANYWHERE in this file" is a defensible question for a whole-file scanner to
answer, the same reuse shape `posture/network-policy-import.js` already
established for correlating a whole-file finding to a specific location by
`(file, line)` proximity — not by re-deriving structural call-site identity.

Option 1 (threading raw text into `coverage.js`/`graph-builder.js` directly)
was rejected for the same reason `index.js` itself already wraps
`coverage.js` for scan-facing concerns one layer further out: it would
couple a whole-file regex scanner's raw-text dependency into a pipeline that
today only ever sees already-parsed IR, for no benefit this increment needs.

## 3. The `fileContents` plumbing path

`runFullScan`'s own signature already carries `fileContents` (the real
`{path: rawSourceString}` map, used pervasively elsewhere in that function
for `dropGuardedFindings`/`_isInlineSuppressed`/etc.) as a live local in the
exact scope that calls `buildLineageGraph(callGraph, {...})`. This
increment adds one field to that call site's opts object —
`fileContents` — and one corresponding optional parameter,
`opts.fileContents`, to `buildLineageGraph` itself, mirroring the existing
`opts.perFile`/`opts.parseFailures` passthrough pattern. `buildLineageGraph`
calls `scanTransitEvidence(opts.fileContents ?? {})` and attaches the
result to its own returned status object as a new field, `transitEvidence`
— a `Map`, alongside the existing `{status, graph, failure, elapsedMs}`
shape. It is a `Map`, not `Object.fromEntries(...)`, because every consumer
proven so far (this increment's own test, and B2's future join logic) reads
it in-process, never serializes it — `bin/agentic-security.js`'s
JSON-persistence path (`.agentic-security/lineage-graph.json`) only ever
persists `scan.lineageGraph` (the `graph` field), never the status object
this field lives on, so no serialization boundary exists yet to force a
plain-object shape. A future increment that needs to serialize
`transitEvidence` can convert at that boundary then, not here.

**Load-bearing invariant, proven by this increment's own test**: `graph`
itself is byte-identical whether or not `opts.fileContents` is supplied —
the same "byte-identical when a hook is omitted" proof every additive hook
this session has shipped (`opts.resolveSiteDecision`, `opts.resolveDestination`)
already carries. `scanTransitEvidence`'s own result is attached
ALONGSIDE `graph`, never folded into it.

## 4. The candidate "network" category list (named, not yet used)

`sink-registry.js`'s `CATEGORY_NODE_KIND` maps a `SINK_CATEGORIES` value to
a node kind of `'external'` for the following categories: `external-api`,
`webhook`, `email`, `sms`, `push-notification`, `collaboration`,
`analytics`, `monitoring`, and every `ai-*` category except
`ai-local-model` (which maps to `'process'`, correctly — a local model is
not a network call). Of these, `external-api` is the unambiguous case: an
HTTP/RPC call to an external service. The others are all named here as
candidates a future increment must decide on, not decided now:

- `webhook`, `email`, `sms`, `push-notification` — all genuinely
  network-outbound in every real implementation (an email/SMS/push send is
  itself an API call to a provider); plausibly all "network,
  transit-relevant" the same way `external-api` is.
- `analytics`, `monitoring`, `collaboration` — also network-outbound in
  practice (a SaaS analytics/monitoring/chat-integration SDK call), but
  named separately here because their `CATEGORY_EXTERNALITY` entry
  (`'external'`) and node kind (`'external'`) are the same signal
  `external-api` carries, so nothing in the registry currently
  distinguishes "this external call matters for transit-protection" from
  "this external call happens to be classified `analytics`" — a future
  increment may find a reason to exclude some of these (e.g. a
  fire-and-forget beacon with no response path) that this increment has no
  basis to decide.
- Every `ai-*` category except `ai-local-model` — an AI SDK call
  (`ai-model-provider`, `ai-agent`, `ai-tool`, `ai-vector-store`,
  `ai-memory`, `ai-training`, `ai-evaluation`, `ai-telemetry`) is a network
  call to an external service by construction, per Sub-project A's own
  literal-URL AI-provider resolution work — a strong candidate for
  inclusion.

**Not** candidates: everything `CATEGORY_NODE_KIND` maps to `'log'`,
`'sink'`, `'store'`, `'queue'`, or `'process'` — none of those describe a
genuine outbound network call in the transit-protection sense (a `store`
category like `database`/`file`/`object-storage` may itself cross a
network in a real deployment, e.g. a managed database over TLS, but that is
Sub-project C's at-rest/connection concern, not this one, per the scoping
doc's own AC-06 exclusion).

This list is deliberately a naming exercise only in increment 1 — increment
2 (§6 below) decides the filter for THIS increment (`external-api` only) and
names the rest of this list as still-deferred widening, not silently
resolved.

## 5. Explicitly deferred as of increment 1 (superseded in part by §6)

- ~~The file+line correlation join~~ — **closed by increment 2**, §6 below.
- ~~Any write to `edge.protection.transit`~~ — **closed by increment 2**,
  for `external-api` sites only; every other category's edges still get
  `emptyProtection()`'s own `not_assessed`/`none` defaults, unchanged.
- **The final candidate "network category" list's actual USE in filtering
  which edges matter** — increment 2 uses only `external-api` (the
  unambiguous case named in §4); the rest of §4's list remains named,
  deferred widening for a future increment (see §6.2).
- **AC-03/AC-04 fixtures** — **closed by increment 2**, §6 below.

## 6. Increment 2: the corrected hook point, the verdict logic, and what's still deferred

### 6.1 The correction this increment implements

§2 above (increment 1's own design) chose a separate post-pass — a real,
correct, buildable design for the PLUMBING job (getting raw file text into
the pipeline). Re-reading `graph-builder.js` directly while scoping the
verdict-computation job itself found that this does NOT extend to the
verdict job: `DESIGN_GRAPH_BUILDER.md` §6.1's own rule — "a node is a
REGISTRY DECISION, not a provenance node and not a call site" — means a
node's own `location` is unconditionally `null`, and many distinct call
sites (different files, different lines) can collide onto ONE network sink
node. The per-site `file`/`line` this correlation needs is available ONLY
on the `site` object `enumerateSinkSites` builds, and that object is
consumed and discarded INSIDE `graph-builder.js`'s own edge-construction
loop — never surfaced onto `graph.edges[]`.

**Corrected design, implemented exactly as specified:** a new
`opts.resolveTransitProtection(site) -> {verdict, evidenceGrade} |
undefined` hook on `buildDataFlowGraph` (`graph-builder.js`), applied at
the exact same block that already reads `site.destination` for
`protocol.destinationResolution` — the same point `opts.resolveDestination`
(Sub-project A) hooks — composing into
`protection: { ...emptyProtection(), transit: resolved ??
emptyProtection().transit }`. `coverage.js`'s `buildGraphWithCoverage`
gains a new `opts.transitEvidenceByFile` parameter and wires in a DEFAULT
`resolveTransitProtection` closing over it, composing with a
caller-supplied override exactly the way `resolveSiteDecision`/
`resolveDestination` already do (`opts.resolveTransitProtection ?? <default
built from transitEvidenceByFile>`).

### 6.2 The single-computation requirement

`index.js`'s own `buildLineageGraph` is now the ONLY place
`scanTransitEvidence` is ever called. Its result — a `Map<file,
findings[]>` — feeds BOTH the existing, unchanged `transitEvidence` return
field AND the new `opts.transitEvidenceByFile` passed to
`buildGraphWithCoverage`, the SAME `Map` reference, computed once.
`coverage.js`'s default hook never calls `scanTransitEvidence`/
`scanCryptoProtocol` itself — it only reads the pre-computed Map handed to
it. This is load-bearing, not a nice-to-have: before this change,
`index.js`'s own `buildGraphWithCoverage(callGraph, {...})` call passed no
`fileContents` at all, so `scanTransitEvidence` ran exactly once (for the
`transitEvidence` field alone); a second, independent call inside
`coverage.js`'s own default hook (re-deriving the Map from raw
`fileContents` a second time) would have silently doubled the per-file
regex-scan cost of every scan that supplies `fileContents`. A live test
(`transit-protection.test.js`, the call-count instrumentation case) proves
`scanCryptoProtocol` is invoked exactly once per file per
`buildLineageGraph` call, not merely architected that way.

### 6.3 The verdict logic (`resolveTransitProtectionForSite`)

Lives in `transit-protection.js`, exported alongside `scanTransitEvidence`.
`TRANSIT_PROTECTION_WINDOW_LINES = 10` — a named, disclosed constant, a
real tuning choice and NOT a calibrated one (no real fixture corpus exists
yet to tune against): a TLS-config object (`{ rejectUnauthorized: false }`)
is often on the same line as, or a few lines before, the network call it
configures. This is a NEW, independently-chosen value for THIS
correlation, following this codebase's own established line-window
correlation precedent (`engine.js`'s `dropGuardedFindings` and several
other detectors use their own independently-chosen windows — measured
directly at `-2/+3`, `-2/+4`, `+10` lines depending on the detector) — not
copied from any one existing example.

`category !== 'external-api'` is a deliberate, NARROW first slice.
`webhook`/`email`/`sms`/`push-notification`/`analytics`/`monitoring`/
`collaboration`/`ai-*` (§4's own candidate list) are all real, plausible
"also network" categories — widening the filter to include them is
separate, deliberate scope for a later increment, named here, not silently
included or silently excluded.

Decision table, in order:

| # | Condition | Result |
|---|---|---|
| 1 | `site.decision.category !== 'external-api'` | `undefined` (not assessed) |
| 2 | Literal destination starts with `http://` | `{verdict: 'unprotected', evidenceGrade: 'code'}` — the scheme alone is sufficient evidence |
| 3 | A `crypto-tls-no-verify`/`crypto-tls-version` finding in the site's file within `TRANSIT_PROTECTION_WINDOW_LINES` lines of the site's line | `{verdict: 'unprotected', evidenceGrade: 'code'}` — overrides a literal `https://` scheme; a plain scheme is never sufficient once a nearby finding says verification was disabled (AC-04's own core property: the UI must not award protection based on the scheme alone) |
| 4 | Literal destination starts with `https://`, no nearby finding | `{verdict: 'protected', evidenceGrade: 'code'}` |
| 5 | Anything else (dynamic/unresolved destination, or no scheme opinion) | `undefined` — the honest answer; `emptyProtection()`'s own default (`not_assessed`/`none`) already means exactly that, so this function declines to overwrite it rather than manufacturing a fabricated verdict |

Returning `undefined` (never a fabricated `unknown`/`none` string) is the
same discipline `resolveDestination`/`resolveSiteDecision` already
established: a function that didn't really analyze something must never
manufacture a verdict that implies it did.

### 6.4 Still explicitly deferred after increment 2

- Widening the network-category filter beyond `external-api` (§4's own
  named list) — a later increment's job.
- AC-05's own dynamic-destination clause beyond "stays `not_assessed`" (the
  PRD's AC-05 wording is about the Unresolved-outbound-destination NODE
  existing, already shipped by Sub-project A/E4 — this increment's own
  transit-verdict contribution to that scenario is exactly "stays
  `not_assessed`," proven by a dedicated test, not more).
- AC-06 (database encryption / at-rest — Sub-project C, an entirely
  different protection dimension).
- AC-12's aggregate "mixed" verdict (needs an aggregation rule no increment
  has built yet — this increment populates one INPUT to that future
  aggregation, not the aggregation itself).
- `atRest`/`handling` protection dimensions — untouched by this increment.
- Any language beyond JS/TS.
- `runtime` evidence grade (Milestone 5).
