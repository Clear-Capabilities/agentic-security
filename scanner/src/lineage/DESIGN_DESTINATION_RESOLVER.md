# DESIGN_DESTINATION_RESOLVER.md — Sub-project A's binding design record (increment 1)

**Status:** landed as Milestone 2, Sub-project A, increment **1** — a
design-spike-sized first slice, per
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-a1-plan.md`.
Binding on later Sub-project A increments the same way `DESIGN_
INTRAPROCEDURAL.md` binds A/B, `DESIGN_PATH_PROVENANCE.md` binds C, and
`DESIGN_GRAPH_BUILDER.md` binds E — but MUCH shorter, on purpose: this is
the first slice of a "Large" sub-project (FR-202), not the whole thing.

---

## 1. What this increment actually is

Every `DataFlowGraph v1` node has carried `destination: null` unconditionally
since Milestone 1, and every edge `protocol.destinationResolution: 'unknown'`
unconditionally — deliberately unimplemented (`graph-builder.js`'s own
header, `DESIGN_GRAPH_BUILDER.md`'s `graph.limitations` entry). This
increment fills in a real, non-null `destination` object for exactly two
shapes of call site: a literal destination argument/receiver, and a
call site FR-203 (Sub-project E, increment 4) already proved is NOT
statically resolvable. Everything else stays `unknown` — the same answer
Milestone 1 always gave.

No new detection. Both real outcomes below are built entirely from two
primitives `coverage.js` already shipped for FR-203: `detectUnresolvedDestination`
(the receiver/arg0 unresolvability heuristic) and `renderExpr` (expression →
string). This increment does not re-derive a second opinion on "is this
expression statically nameable" — it reuses FR-203's own answer.

---

## 2. The `destination` object shape

The single source of truth both `resolve-destination.js` and
`graph-builder.js` target:

```
{
  resolutionStatus: DestinationResolutionValue,  // schema.js's DESTINATION_RESOLUTION_VALUES
  raw: string | null,                            // renderExpr() of the resolved expression;
                                                   // null only when resolutionStatus === 'unknown'
  literalValue: string | null,                    // String(value) of the literal; null unless
                                                   // resolutionStatus === 'literal'
  blockingExpression: string | null,              // FR-203's own blockingExpression, carried
                                                   // straight through; null unless
                                                   // resolutionStatus === 'dynamic'
}
```

`raw` and `blockingExpression` are byte-identical for the `'dynamic'` case —
`raw` exists as its own field (rather than callers reading
`blockingExpression` for the same information) because a LATER increment
resolving `resolved_from_constant`/`resolved_from_config`/etc. will populate
`raw` with something that is NOT a "the resolution failed, here's why"
string, and `blockingExpression` must stay reserved for exactly that meaning
across every resolution status.

`raw` for the `'literal'` case is `renderExpr(expr)`, which JSON-stringifies
a literal's value (`renderExpr({kind:'literal', value:'https://x'})` →
`'"https://x"'`, quotes included) — the same rendering FR-203's own
`blockingExpression` strings already use for consistency. `literalValue` is
the unwrapped, human-usable form (`'https://x'`, no quotes) — a caller
displaying "resolves to X" wants `literalValue`; a caller wanting the exact
source-text rendering (for a diagnostic message, matching FR-203's own
`reason` string convention) wants `raw`.

## 3. The two real resolution rules

1. **`'literal'`** — the destination-bearing argument (arg0, but ONLY when
   `site.decision.category` is one of `FR203_ARG0_DESTINATION_CATEGORIES`
   — `external-api`/`file`/`object-storage`, the exact same narrower set
   MUST-FIX 1 established for FR-203, since arg0 is a PAYLOAD everywhere
   else) or the call's receiver (a member callee's `object`) is itself a
   `literal`-kind expression.
2. **`'dynamic'`** — anything `detectUnresolvedDestination(site)` already
   flags, respecting the SAME arg0 category gate: a `via: 'arg0'` result
   only counts when the category is eligible (otherwise a non-literal SQL/
   HTML payload on a database/client-storage call would be misread as a
   "dynamic destination", reintroducing the exact false positive MUST-FIX 1
   fixed for FR-203's own ledger). A `via: 'receiver'` result always counts
   — the receiver signal carries no narrower category gate in FR-203 either.
3. **`'unknown'`** — everything else. Deliberately the same answer
   Milestone 1 always gave; this increment only upgrades the two cases
   above.

The literal check runs BEFORE the `detectUnresolvedDestination` check, on
purpose: a literal receiver (`"https://x".request()`, unusual but
IR-representable) is not a plain identifier either, so
`detectUnresolvedDestination` would flag it via `'receiver'` — checking
literal-ness first means it resolves as `'literal'`, not `'dynamic'`.

## 4. Wiring — two independent, composable hooks

`opts.resolveDestination(site) -> destination | undefined` is a SEPARATE
hook from `opts.resolveSiteDecision` (FR-203's own hook), applied at the
same point in `graph-builder.js`'s pipeline, right after it. The two must
never collapse into one: `resolveSiteDecision` answers "is this sink's
CLASSIFICATION (`kind`/`category`/`coverageStatus`) still trustworthy", and
`resolveDestination` answers "what does this call site's destination
EXPRESSION look like" — a site can be BOTH `decision.kind: 'unresolved'`
(FR-203) AND carry `destination.resolutionStatus: 'dynamic'` (this
increment) at once; they are not restatements of each other; a future site
could plausibly have a `'modeled'`/non-unresolved decision AND still only
resolve to `'unknown'` here (e.g. a well-classified sink whose destination
argument is a plain, un-flagged variable reference).

`node.destination` is set once, at node MINT time — never part of the
node's own identity discriminator (`ids.nodeId`'s inputs are unchanged).
This is a deliberate, disclosed coarsening: when two different call sites
collide onto one node (same `kind`/`subtypeKey`/`coverageStatus`/
`externality`), that node's `destination` is whichever site's resolution
was applied first, not a set/union of every site's destination. Widening
the node identity to include `destination` — so distinct literal
destinations mint distinct nodes — is real, undecided scope for a later
increment, not attempted here (it changes every downstream node id, a much
larger blast radius than this increment's stated goal).

## 5. Explicitly deferred (named, not silently skipped)

Every one of these needs its own extraction/resolution rule and its own
increment — bundling them into increment 1 risks the exact "Very Large, do
it all at once" trap Milestone 1's own sub-projects deliberately avoided:

- **Hostname/port/route/SDK-provider/model/cloud-resource-id/trust-zone
  extraction** — FR-202's full nine-fact destination profile. This
  increment resolves only WHETHER a destination is knowable and its raw
  string form, never structured facts parsed out of it.
- **`resolved_from_constant`** (local-const folding, e.g. `const URL =
  'https://x'; fetch(URL)`) — needs a constant-propagation pass this
  increment does not build.
- **`resolved_from_config`** (env var / config-object chain resolution,
  e.g. `fetch(config.apiUrl)`) — needs config-shape resolution.
- **`resolved_from_schema`** / **`declared_service`** — needs schema
  correlation or an operator-declared service registry; plausibly a later
  Sub-project A increment, or Sub-projects E/F's own schema-correlation
  work.
- **`runtime_corroborated`** — never in Milestone 2 at all; this is
  Milestone 5's Digital Twin.
- **AI-provider/model resolution** (AC-01/AC-07's "provider, model when
  known" clause, Decision 5 of the M2 scoping doc) — this increment's
  literal-URL case is a real but partial step toward it (an AI SDK call's
  base URL, when literal, now resolves), not a claim that AI-provider
  resolution itself is done.
- **Node-identity widening by destination** (§4 above) — the node stays
  category-granular, not per-destination-granular, in this increment.
- **A kind/category eligibility gate on the RECEIVER signal** — unlike the
  arg0 signal (gated by `FR203_ARG0_DESTINATION_CATEGORIES`), a computed
  receiver on a `log`/`sink`-kind site (categories FR-203's own
  `FR203_ELIGIBLE_KINDS` excludes from the coverage ledger, since those
  destinations are always fixed) can still resolve to `'dynamic'` here —
  mirroring `coverage.js`'s own disclosed imprecision for the RECEIVER
  signal in general ("will inflate `unresolvedDestinations` on any repo
  using an ORM/repository pattern ... not narrowed in this increment").
  Narrowing this to match `FR203_ELIGIBLE_KINDS` exactly is a natural
  follow-up if it proves noisy in practice, not attempted here.
