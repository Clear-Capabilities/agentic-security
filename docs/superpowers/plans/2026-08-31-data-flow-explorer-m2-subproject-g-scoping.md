# Milestone 2, Sub-project G scoping: scoped policy verdict for AC-09

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-scoping.md`
§5's row G: *"Adapts `privacy-sink-policy.js`'s existing fail-closed (data
class × sink × environment × destination) rule-matching mechanism (Decision
3) into `flow.policyVerdict`, populating `permitted`/`not_evaluated` (and
implicit `prohibited`) with rule/reason/environment/destination/evidence
exactly as AC-09 requires."* Unlike Sub-project B/E's own scoping
corrections, this document CONFIRMS the parent doc's framing after direct
verification — `privacy-sink-policy.js` genuinely is a pure, reusable
function library, not a whole-file scanner needing a correlation
heuristic.

## Confirmed by direct read: `isSinkPermitted`/`permittingRules` are genuinely, directly reusable

`scanner/src/dataflow/privacy-sink-policy.js` exports three pure functions
— no whole-file text scanning, no regex-over-source anywhere in this
module (unlike `crypto-protocol.js`/`cross-lang-orm.js`):

- `loadPrivacySinkPolicy(scanRoot)` — reads `.agentic-security/privacy-
  policy.json` (via `posture/state-dir.js`'s `statePath`), returns
  `{allow: [{sink, class?, environment?, destination?, reason?}]}`. Never
  throws (ENOENT → the empty, "everything prohibited" default).
- `isSinkPermitted(classes, sinkKind, policy, ctx)` — `classes` a data-
  class array, `sinkKind` a plain string, `ctx: {environment?,
  destination?}`. Fail-closed on both new axes (FR-408): an unset rule
  field is unconstrained, but a SET rule field the caller supplied no
  context for does not match — "we don't know" never silently satisfies a
  scoped permission.
- `permittingRules(classes, sinkKind, policy, ctx)` — the specific
  matching rule(s), for evidence disclosure.

**Critically, `sinkKind` is matched by plain string equality
(`r.sink === sinkKind`) with NO hardcoded vocabulary check anywhere in
this module** — it never validates against `privacy-taint.js`'s own
`SINK_PATTERNS` keys (`log`/`response`/`outboundHttp`/`thirdPartySdk`/
`fileWrite`/`s3Upload`/`emailSend`, confirmed by direct read of that
module). This means passing the LINEAGE engine's own `SINK_CATEGORIES`
vocabulary (`schema.js` — 28 values, confirmed to include `'analytics'`,
matching AC-09's own worked example verbatim: *"a policy allows masked PII
to a named analytics provider"*) works with ZERO adaptation to
`isSinkPermitted`/`permittingRules` themselves — no translation table
needed, unlike a first instinct might assume. The two engines' own findings
will naturally use DIFFERENT (mostly non-overlapping) vocabularies in an
operator's SAME `privacy-policy.json` `sink` field — a real, disclosed
dual-vocabulary consideration to document, not a blocking design problem.

**Data-class compatibility, also confirmed**: `classification.js`'s
`LINEAGE_DATA_CLASSES` is built from the SAME `DEFAULT_TAXONOMY` (PII/PHI/
PCI/etc.) `dataflow/privacy-taxonomy.js` already defines — no translation
needed here either.

## The exact real-usage precedent to follow

`dataflow/privacy-taint.js` (the OLD engine's own consumer, confirmed by
direct read) establishes the EXACT pattern this increment should mirror:

```js
const sinkPolicy = opts.sinkPolicy || (opts.scanRoot ? loadPrivacySinkPolicy(opts.scanRoot) : { allow: [] });
const ctx = { environment: opts.environment || process.env.AGENTIC_SECURITY_ENVIRONMENT || null, destination: ... };
if (isSinkPermitted(classes, sinkLabel, sinkPolicy, ctx)) {
  // permittingRules(...).map(r => ({sink: r.sink, class: r.class || null, reason: r.reason || null, environment: r.environment || null, destination: r.destination || null}))
}
```

`opts.sinkPolicy` (a caller-supplied, already-loaded policy) taking
precedence over loading from `opts.scanRoot` is the SAME "caller override
wins" composition every additive hook this session has shipped already
uses — genuinely the same pattern, not a new one to invent.
`environment` resolution (`opts.environment || process.env
.AGENTIC_SECURITY_ENVIRONMENT || null`) is copied verbatim from this exact
precedent, not re-derived. `permittingRules(...).map(...)`'s own shape is
ALREADY the precise `{sink, class, reason, environment, destination}`
evidence structure AC-09 asks for ("matching rule, reason, environment,
destination, and evidence") — directly reusable, not redesigned.

## The one real, resolved design decision: `'not_evaluated'` vs `'prohibited'`

`POLICY_STATES` (`schema.js`, unchanged, Milestone 0): `prohibited`,
`permitted`, `conditionally_permitted`, `manual_review_required`,
`not_evaluated`. `privacy-sink-policy.js`'s own header states the
governing philosophy plainly: *"a finding still fires by default...
nothing changes for a repo with no policy file"* — a DENY-BY-DEFAULT
model once a policy is genuinely in play. Resolved here, not left
ambiguous for the implementation plan to guess:

- **No policy file exists at all** (`loadPrivacySinkPolicy` returns the
  empty `{allow: []}` because the file is missing) → `flow.policyVerdict
  = 'not_evaluated'`. Nothing was actually evaluated against anything;
  claiming `'prohibited'` here would overstate what happened — the same
  "never claim more analysis occurred than actually did" discipline
  `resolveTransitProtectionForSite`'s own `undefined`-return case already
  established for Sub-project B.
- **A policy file exists, and `isSinkPermitted` returns true** →
  `'permitted'`, with `permittingRules`'s own output as evidence.
- **A policy file exists, and `isSinkPermitted` returns false** →
  `'prohibited'` — the deny-by-default stance the OLD engine's own
  header comment already establishes as this repo's convention, not a
  new invention.
- **A malformed policy file** — `loadPrivacySinkPolicy` already degrades
  to the EMPTY policy on a parse error (logging a warning, never
  throwing) — this is INDISTINGUISHABLE, from this increment's own
  vantage point, from "no policy file exists," so it also reads
  `'not_evaluated'`. Confirm this is genuinely the right read (a
  malformed file arguably represents an ATTEMPTED-but-failed policy setup,
  which could argue for a different signal) as part of the
  implementation plan's own test-writing, not decided with more
  certainty than this scoping pass actually has.

`conditionally_permitted`/`manual_review_required` are explicitly NOT
implemented — the parent scoping doc's own Decision 3 already names this,
reconfirmed here: no mechanism anywhere in `privacy-sink-policy.js`
produces either state, and inventing one is real, separate, deferred
scope (Milestone 4, per the parent doc).

## The wiring point (mirrors Sub-project D2/C1's own "same flow-construction loop" precedent, a THIRD addition to it)

`flow.policyVerdict: 'not_evaluated'` is currently a hardcoded default
literal, set in the SAME flow-construction loop `flow.handling`/this
session's own `edge.protection.atRest` wiring (Sub-project C1) already
extended twice. `classes` for a flow — `de.dataClasses` (the flow's own
referenced data element, via `mintDataElement(seed)`'s own already-
classified result, already computed earlier in the SAME per-site loop,
per Sub-project A-E's own established data flow through this file — RE-
VERIFY the exact variable/field name against the current file, don't
assume `de.dataClasses` is exactly right without checking). `sinkKind` —
the flow's own sink node's `category` (confirm whether that's stored as
`snk.subtype` or a separate field — Sub-project C1's own review found
`snk.kind` for the COARSE kind; the FINER `SINK_CATEGORIES` value needs
its own field check, likely `subtypeKey`/`subtype`, not `kind`).
`destination` for `ctx` — likely `site.destination?.literalValue`
(Sub-project A) or a rendered form of the sink's own callee, needs its
own small design decision in the implementation plan, not assumed here.

## New plumbing needed (smaller than Sub-project B1's own)

`scanRoot` (or a pre-loaded `policy` object) needs to reach
`buildDataFlowGraph`'s own opts, from `engine.js`'s `runFullScan` — which
ALREADY has `scanRoot` in scope at the `buildLineageGraph` call site
(confirmed: it's already read there today, for `repository:
scanRoot ? path.basename(...) : undefined`). Unlike Sub-project B1's own
`fileContents` plumbing (which needed careful single-computation
discipline across potentially many files), `loadPrivacySinkPolicy` is a
SINGLE, cheap JSON-file read — call it ONCE, in `index.js`'s
`buildLineageGraph` (mirroring B1's own "compute once, thread the result
down" precedent exactly), pass the loaded `policy` object (never raw
`scanRoot`) down through `coverage.js` to `graph-builder.js`'s own new
per-flow policy-check logic — the SAME "pass the pre-computed result, not
the raw input, to avoid re-deriving it at a lower layer" discipline
Sub-project B2's own scoping correction established as required, not
optional.

## Recommended increment breakdown

Given how directly reusable the core mechanism is (confirmed, not
corrected, unlike B/E), this is likely ONE increment, not split into a
plumbing-only slice + a verdict-computation slice the way Sub-project B
needed — the plumbing here is small enough (one JSON-file read, computed
once) to fold into the same increment as the verdict logic. Confirm this
judgment when writing the actual implementation plan; split further if
the real code reveals more complexity than this scoping pass found.

## What this does NOT do

`conditionally_permitted`/`manual_review_required` (Decision 3, Milestone
4). Approver/owner/expiration fields (Decision 3, Milestone 4). Any
language beyond JS/TS. AC-12's own aggregate verdict (a DIFFERENT
dimension — `flow.protectionSummary`, not `flow.policyVerdict` — untouched
by this sub-project). Widening `privacy-policy.json`'s own schema/shape —
this increment is a NEW READER of an already-shipped file format, never a
schema change to it.
