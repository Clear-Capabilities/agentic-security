# DESIGN_TRANSIT_PROTECTION.md — Sub-project B's binding design record (increment 1)

**Status:** landed as Milestone 2, Sub-project B, increment **1** — a
plumbing-skeleton-sized first slice, per
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-b1-plan.md`
and the scoping correction at
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-b-scoping.md`.
Binding on later Sub-project B increments the same way `DESIGN_
DESTINATION_RESOLVER.md` binds Sub-project A — MUCH shorter, on purpose:
this is the first slice of the sub-project (FR-401), not the whole thing.

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

This list is deliberately a naming exercise only — B2 is the increment that
decides the final filter and applies it. Nothing in this increment reads or
filters on it.

## 5. Explicitly deferred (named, not silently skipped)

- **The file+line correlation join** — which specific graph edge (if any) a
  `scanTransitEvidence` finding applies to. B2's own job entirely; this
  increment's `Map<file, findings[]>` has no edge-awareness at all.
- **Any write to `edge.protection.transit`** — stays
  `{verdict: 'not_assessed', evidenceGrade: 'none'}` on every edge after
  this increment, exactly as `emptyProtection()` already set it before this
  increment existed.
- **The final candidate "network category" list's actual USE in filtering
  which edges matter** — named in §4 above, used starting in B2.
- **AC-03/AC-04 fixtures** — B3's job, once B2's verdict logic exists to
  prove against real code.
