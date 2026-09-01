# Milestone 2, Sub-project G, increment 1: scoped policy verdicts (closes AC-09)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-g-scoping.md`.
That document confirmed `privacy-sink-policy.js`'s `isSinkPermitted`/
`permittingRules` are directly, genuinely reusable (no correction needed,
unlike Sub-project B/E), resolved the `not_evaluated`-vs-`prohibited`
design question, and found the exact real-usage precedent in
`dataflow/privacy-taint.js`. This plan implements it as one increment.

## What already exists (confirmed by direct read, this session, HEAD `5633e513`)

- `dataflow/privacy-sink-policy.js`: `loadPrivacySinkPolicy(scanRoot)`,
  `isSinkPermitted(classes, sinkKind, policy, ctx)`,
  `permittingRules(classes, sinkKind, policy, ctx)` — all pure, vocabulary-
  agnostic, never throw.
- `dataflow/privacy-taint.js`'s own real usage (the precedent to copy, not
  redesign): `opts.sinkPolicy || (opts.scanRoot ? loadPrivacySinkPolicy(
  opts.scanRoot) : {allow: []})`; `ctx.environment = opts.environment ||
  process.env.AGENTIC_SECURITY_ENVIRONMENT || null`;
  `permittingRules(...).map(r => ({sink: r.sink, class: r.class || null,
  reason: r.reason || null, environment: r.environment || null,
  destination: r.destination || null}))`.
- `graph-builder.js`'s flow-construction loop, re-verified this session:
  `de = mintDataElement(seed)` (already in scope) carries `de.dataClasses`
  (confirmed: `mintDataElement` sets `dataClasses: s.dataClasses`
  verbatim). The sink node `snk` carries its `SINK_CATEGORIES` value on
  `snk.subtype` (confirmed: `mintNode` sets `subtype: category ?? null` —
  NOT `snk.kind`, which is the coarser kind like `'store'`/`'log'`, already
  used by Sub-project C1's own filter). `flow.policyVerdict:
  'not_evaluated'` is currently a hardcoded literal in the SAME
  flow-construction loop `flow.handling` (Sub-project D1) and `edge
  .protection.atRest` (Sub-project C1) are already set in — this is the
  THIRD field this exact loop gains real computed logic for. **Re-verify
  the current exact line/variable state before writing code** — this loop
  has been extended twice already this session and may have shifted.
- `engine.js`'s `runFullScan` already has `scanRoot` in scope at the
  `buildLineageGraph(callGraph, {...})` call site (confirmed: used today
  for `repository: scanRoot ? path.basename(path.resolve(scanRoot)) :
  undefined`) — the SAME plumbing entry point Sub-project B1 used for
  `fileContents`.
- `site.destination?.literalValue` (Sub-project A, increment 1) — the
  candidate `ctx.destination` value when the sink's own destination
  resolved to a literal; `null`/`undefined` otherwise (never fabricate a
  destination string when none was resolved — `_matchesDestination`'s own
  fail-closed contract already handles a missing `destText` correctly, per
  `privacy-sink-policy.js`'s own code, so passing `null` here is safe and
  correct, not a gap to work around).

## Scope for this increment

1. **`index.js`**: `buildLineageGraph(callGraph, opts)` gains
   `opts.scanRoot` (or reuse `opts.repository`'s own already-passed value
   if it turns out to already carry the right path — VERIFY, don't
   assume; `repository` today is a basename string per the comment above,
   likely NOT the full path `loadPrivacySinkPolicy` needs, so a genuinely
   separate `opts.scanRoot` parameter is the safer default assumption,
   confirm against the real code before deciding). Calls
   `loadPrivacySinkPolicy(opts.scanRoot)` ONCE (mirroring B1's own
   "compute once, thread the result down" precedent — never re-load the
   policy file at a lower layer), and threads the loaded `policy` object
   down via a new `opts.privacySinkPolicy` (or similar name — pick one and
   use it consistently across `index.js`/`coverage.js`/`graph-builder.js`,
   don't drift) parameter to `buildGraphWithCoverage`.
2. **`coverage.js`**: `buildGraphWithCoverage(callGraph, opts)` gains
   `opts.privacySinkPolicy` (a pre-loaded policy object, NOT `scanRoot` —
   `coverage.js` never reads the filesystem itself, matching Sub-project
   B2's own established "pass the pre-computed result down, never
   re-derive it at a lower layer" discipline exactly), threaded to
   `buildDataFlowGraph`.
3. **`graph-builder.js`**: `buildDataFlowGraph(callGraph, opts)` gains
   `opts.privacySinkPolicy` (default `{allow: []}` when omitted — the
   SAME "genuinely no policy configured" empty shape
   `loadPrivacySinkPolicy` itself returns on ENOENT, so omitting this opt
   entirely is indistinguishable from "no policy file exists," both
   correctly reading `not_evaluated`) and `opts.environment` (optional
   override, falling back to `process.env.AGENTIC_SECURITY_ENVIRONMENT`,
   copied verbatim from `privacy-taint.js`'s own precedent). In the SAME
   flow-construction loop, right where `flow.policyVerdict:
   'not_evaluated'` is currently hardcoded, replace it with real
   computed logic:

   ```js
   const classes = de.dataClasses ?? [];
   const sinkKind = snk.subtype;
   const ctx = {
     environment: opts.environment || process.env.AGENTIC_SECURITY_ENVIRONMENT || null,
     destination: site.destination?.literalValue ?? null,
   };
   const policyLoaded = opts.privacySinkPolicy != null;
   let policyVerdict = 'not_evaluated';
   let policyRules = [];
   if (policyLoaded && classes.length && sinkKind) {
     if (isSinkPermitted(classes, sinkKind, opts.privacySinkPolicy, ctx)) {
       policyVerdict = 'permitted';
       policyRules = permittingRules(classes, sinkKind, opts.privacySinkPolicy, ctx)
         .map((r) => ({ sink: r.sink, class: r.class || null, reason: r.reason || null, environment: r.environment || null, destination: r.destination || null }));
     } else {
       policyVerdict = 'prohibited';
     }
   }
   ```

   `policyLoaded` gates on the OPTS FIELD being present (`!= null`), never
   on `opts.privacySinkPolicy.allow.length > 0` — a policy file that
   exists but is genuinely empty (`{allow: []}`, an operator's deliberate
   "nothing is permitted yet" state) must still read `prohibited`, not
   `not_evaluated` — only a MISSING policy (the opt itself never supplied)
   is `not_evaluated`. Re-verify this distinction is actually achievable
   given how `index.js` threads the value through (an omitted
   `opts.privacySinkPolicy` at the `buildDataFlowGraph` layer must stay
   distinguishably `undefined`/absent, never coerced to `{allow: []}`
   before this point — confirm the whole chain preserves that distinction,
   don't let an intermediate `?? {allow: []}` erase it).
4. Where does `policyRules` (the evidence) get stored? `flow` has no
   existing `policyRules`/`evidence`-shaped field for this specifically —
   check `flow.evidenceRefs` (an array of evidence IDs, referencing
   `graph.evidence[]` entries per the Milestone 0 schema) versus adding a
   NEW, dedicated field. **This is a real, undecided design question this
   plan does not resolve** — read `schema.js`'s own `flow` contract and
   `evidence.js`'s/`EVIDENCE_TYPES`' shape directly before deciding; if
   `evidenceRefs`+`graph.evidence[]` is the established, correct
   mechanism (most likely, given Milestone 0's own contract was built
   expecting exactly this kind of "attach real evidence to a flow" need),
   use it — mint a real `evidence` entry per permitting rule via `ids.js`'s
   own `evidenceId` function (already shipped, unused until now — confirm
   this by checking whether anything currently calls it), don't invent a
   parallel ad-hoc field. If genuinely no existing mechanism fits, name
   the gap explicitly and propose the smallest fix, don't build something
   speculative.

## Do NOT touch

`privacy-sink-policy.js`, `privacy-taint.js` (read-only reference for the
usage precedent — never modify the OLD engine's own code), `transit-
protection.js`/Sub-project B's own files, `handling-analyzer.js`/Sub-
project C's own `atRest` wiring, `node.storeDetail`/`node.queueDetail`.
This increment writes ONLY `flow.policyVerdict` (and whatever evidence
mechanism item 4 above resolves to) — never `edge.protection.*`.

## Test plan

New `scanner/test/lineage/policy-verdict.test.js`:

1. **No policy file** (`opts.privacySinkPolicy` omitted entirely, or
   `buildLineageGraph` called with no `opts.scanRoot`) → `flow
   .policyVerdict === 'not_evaluated'` on every flow, regardless of data
   class/sink.
2. **A policy file with a matching `allow` rule** (a real fixture: PII
   reaching an `analytics`-category sink, matching AC-09's own worked
   example, with a rule `{sink: 'analytics', class: 'PII', environment:
   'production', reason: '...'}` and `ctx.environment: 'production'`
   supplied) → `'permitted'`, with the evidence mechanism item 4 resolves
   to correctly carrying `{sink, class, reason, environment, destination}`.
3. **A policy file that exists but does NOT cover this specific flow**
   (empty `{allow: []}`, or a rule for a different class/sink) →
   `'prohibited'` — the deny-by-default proof.
4. **The environment fail-closed proof** (FR-408): a rule scoped to
   `environment: 'production'`, but `ctx.environment` resolves to
   something else (or is null) → stays `'prohibited'`, never accidentally
   `'permitted'`.
5. **The destination fail-closed proof**: a rule scoped to a `destination`
   regex, but the flow's own `site.destination` never resolved to a
   literal (`ctx.destination: null`) → stays `'prohibited'`.
6. **A flow whose data element has NO recognized data classes** (an
   ordinary, non-sensitive field) → `'not_evaluated'` (or confirm the
   correct honest answer here — a policy engine has nothing meaningful to
   say about a flow it was never asked to gate; don't guess, ground this
   against `isSinkPermitted`'s own `if (!classes.length) return false`
   early-return and decide whether that should read as `not_evaluated`
   rather than `prohibited` for THIS case specifically, since "prohibited"
   implies a real judgment was made about sensitive data, which didn't
   happen here).
7. Full `npm run test:lineage`, `npm run test:dataflow` (confirm
   `privacy-sink-policy.js`/`privacy-taint.js`'s own existing tests
   unaffected — you're a second consumer, not a modifier), and `npm test`
   stay green, real captured exit codes.

## Explicitly deferred

`conditionally_permitted`/`manual_review_required` (Milestone 4).
Approver/owner/expiration fields (Milestone 4). AC-12's own aggregate
verdict dimension (`flow.protectionSummary`, untouched). Any language
beyond JS/TS.
