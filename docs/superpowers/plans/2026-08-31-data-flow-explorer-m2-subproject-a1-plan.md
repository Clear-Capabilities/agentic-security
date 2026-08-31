# Milestone 2, Sub-project A, increment 1: destination shape + literal/config resolution

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-scoping.md`,
Sub-project A ("External destination resolver," Large). This is increment 1
— a design-spike-sized first slice, mirroring how every "Large"/"Very Large"
Milestone 1 sub-project (A, B, C, D) started with a design note plus the
simplest real case, not the whole thing at once.

## What already exists (confirmed by direct read, this session)

- `schema.js`'s `DESTINATION_RESOLUTION_VALUES` (8 values: `literal`,
  `resolved_from_constant`, `resolved_from_config`, `resolved_from_schema`,
  `declared_service`, `runtime_corroborated`, `dynamic`, `unknown`) — already
  defined in Milestone 0, unused for real resolution until now.
- `validate.js` line 128 already validates `edge.protocol.destinationResolution`
  against that enum — every edge today sets it to the literal string
  `'unknown'` (`graph-builder.js` lines 424, 506, 522) or `'not-attempted'`
  (`coverage.js` line 356, on the ledger, a different field).
- `graph-builder.js` line 267 sets `node.destination: null` unconditionally —
  no shape for a resolved destination exists anywhere in this codebase yet.
- `coverage.js`'s `detectUnresolvedDestination`/`resolveSiteDecision` (FR-203,
  Sub-project E increment 4) already distinguish "receiver is a computed
  expression" from "arg0 is a computed expression," with a `blockingExpression`
  string when resolution fails — real, tested, reusable AS THE FAILURE SIGNAL
  this increment's resolver must feed when it can't do better.
- `renderExpr(e, depth)` (`coverage.js` line 80) already renders a parsed
  expression tree back to a readable string — reusable for building a literal
  destination fact from a `literal`-kind arg/receiver.

## Scope for this increment

1. **Design note** (`scanner/src/lineage/DESIGN_DESTINATION_RESOLVER.md`,
   following this package's established `DESIGN_*.md` precedent): define the
   `destination` object's field shape once, to be the single source of truth
   `resolve-destination.js` (below) and the graph builder both target. At
   minimum: `resolutionStatus` (one of `DESTINATION_RESOLUTION_VALUES`),
   `raw` (the rendered expression string, always present when resolution
   isn't fully `unknown`), `literalValue` (the resolved string when
   `resolutionStatus === 'literal'`, else `null`), `blockingExpression`
   (carried over from FR-203's existing field when resolution fails, else
   `null`). Do NOT attempt the full FR-202 nine-fact list (hostname, port,
   route, SDK/provider, model, cloud-resource-id, trust zone) in this
   increment — name each of those as explicitly deferred to a later
   increment of Sub-project A, with a one-line reason (each needs its own
   extraction rule; bundling them all into one increment risks the
   "Very Large, do it all at once" trap Milestone 1's Sub-project A
   deliberately avoided).
2. **`scanner/src/lineage/resolve-destination.js`** (new module): exports
   `resolveDestination(site)` where `site` is the same shape
   `detectUnresolvedDestination`/`resolveSiteDecision` already consume
   (`site.calleeExpr`, `site.args`). Handles exactly two cases for this
   increment:
   - The call's destination-bearing argument (arg0, when
     `FR203_ARG0_DESTINATION_CATEGORIES`-eligible) or receiver is a
     `literal`-kind expression: `resolutionStatus: 'literal'`,
     `literalValue` set to the literal's rendered value.
   - Anything FR-203 already flags as unresolvable
     (`detectUnresolvedDestination` returns non-null): `resolutionStatus:
     'dynamic'`, `blockingExpression` carried straight through — this
     increment does NOT attempt `resolved_from_constant`/
     `resolved_from_config`/`resolved_from_schema`/`declared_service`/
     `runtime_corroborated` (those need constant-folding, config-object
     resolution, or schema correlation — each its own follow-up increment,
     named as such in the design note, not silently skipped).
   - Everything else (a non-literal argument/receiver that FR-203 itself
     doesn't flag — i.e., a plain identifier or plain member chain):
     `resolutionStatus: 'unknown'`. This is deliberately the SAME answer
     Milestone 1 always gave, for now — this increment only upgrades the two
     cases above, not everything.
3. **Wire into `graph-builder.js`**: `opts.resolveSiteDecision` already
   exists as a hook `coverage.js` uses (E4). Add an analogous, SEPARATE
   `opts.resolveDestination(site) -> destination-object | undefined` hook,
   applied at the same point `resolveSiteDecision` is applied, setting
   `node.destination` (currently always `null`) and
   `edge.protocol.destinationResolution` (currently always `'unknown'`) when
   supplied. Composes with, never replaces, FR-203's existing
   `resolveSiteDecision` — a site can be BOTH `kind: 'unresolved'` (FR-203)
   AND carry a `resolutionStatus: 'dynamic'` destination object; they answer
   different questions (node classification vs. destination-fact detail) and
   must not be collapsed into one flag, mirroring `coverage.js`'s own
   existing "composes with, never clobbers" discipline for
   `resolveSiteDecision`.
4. **`coverage.js`'s `buildGraphWithCoverage`**: wire `resolveDestination`
   in as the default, the same way `resolveSiteDecision` already is,
   composing with any caller-supplied override exactly like that field does
   today.
5. **`validate.js`**: add a structural check for the new `destination`
   object shape (when non-null) — `resolutionStatus` must be one of
   `DESTINATION_RESOLUTION_VALUES` (the enum already exists; only the
   presence check is new), and `literalValue` must be `null` unless
   `resolutionStatus === 'literal'`.
6. **Do NOT touch**: `sink-registry.js`/`source-registry.js` (categories are
   unaffected — this increment only fills in a previously-null field on
   already-classified nodes), `path-store.js`/`path-query.js`/
   `flow-grade.js` (no new hop/edge semantics), any SAST detector.

## Test plan

- New `scanner/test/lineage/resolve-destination.test.js`: unit tests against
  hand-built `site` shapes for all three resolution outcomes above, plus
  malformed-input safety (never throws, mirrors `detectUnresolvedDestination`'s
  own defensiveness).
- Extend `scanner/test/lineage/coverage.test.js` and/or `graph-builder.test.js`
  with a real-parsed-code case: `fetch('https://payments.example/charge', ...)`
  (literal URL — `resolutionStatus: 'literal'`) vs. `fetch(url, ...)` where
  `url` is a parameter (already FR-203-flagged — `resolutionStatus: 'dynamic'`)
  vs. `db.query(sql)` (arg0 is the payload, not eligible — stays `'unknown'`,
  proving this increment doesn't regress FR-203's own arg0-eligibility fix).
- `validate.js` gains a test for the new `destination` shape check
  (valid/invalid `resolutionStatus`, the `literalValue`-only-when-`literal`
  constraint).
- Full `npm test` must stay green; `npm run test:lineage` must stay green.

## Explicitly deferred (name it, don't silently drop it)

Hostname/port/route/SDK-provider/model/cloud-resource-id/trust-zone
extraction; `resolved_from_constant` (simple local-const folding);
`resolved_from_config` (env var / config-object chain resolution);
`resolved_from_schema`/`declared_service` (needs Sub-project A's own later
increments, or E/F's schema-correlation work); `runtime_corroborated` (never
in Milestone 2 at all — Milestone 5's Digital Twin). AI-provider/model
resolution (the "provider, model when known" clause of AC-01/AC-07,
Decision 5 of the M2 scoping doc) is also deferred to a later Sub-project A
increment — this increment's literal-URL case is a real but partial step
toward it (an AI SDK call's base URL, when literal, now resolves), not a
claim that AI-provider resolution is done.
