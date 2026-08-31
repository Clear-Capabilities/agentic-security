# Milestone 2, Sub-project B, increment 1: transit-protection plumbing skeleton

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-b-scoping.md`,
which already settled the one real design question this increment would
otherwise have to make: a SEPARATE post-pass module, never touching
`coverage.js`/`graph-builder.js`, fed `fileContents` threaded from
`engine.js`'s `runFullScan` (confirmed already in scope, unused, at the
`buildLineageGraph` call site). This increment builds that plumbing and
proves it end to end — no verdict logic yet (that's B2).

## What already exists (confirmed by direct read, this session, HEAD `7ff20c39`)

- `engine.js`'s `runFullScan` is declared
  `async function runFullScan({fileContents={}, ...})` (line ~8625) and
  calls `buildLineageGraph(callGraph, {...})` at line ~9264, inside that
  SAME function scope — `fileContents` is already a live local there,
  simply never passed through today. **Re-verify these two line numbers
  against the CURRENT file before writing code** — this plan's own
  citations may have drifted by the time you read it; every prior
  increment's own plan carried this same caveat for good reason.
- `index.js`'s `buildLineageGraph(callGraph, opts)` already threads
  `opts.repository`/`opts.deterministic`/`opts.perFile`/`opts.parseFailures`
  straight into `buildGraphWithCoverage` — the exact opts-object pattern
  to extend, not replace.
- `protection.js`'s `emptyProtection()` already gives every edge
  `{transit: {verdict: 'not_assessed', evidenceGrade: 'none'}, atRest:
  {...}, handling: {...}}` — `graph-builder.js` sets this on every edge
  unconditionally today (confirmed: `protection: emptyProtection()` in the
  edge-construction block). Nothing in `coverage.js`/`graph-builder.js`
  needs to change for this field to exist; B2 will overwrite it for
  network edges, not add it.
- `sink-registry.js`'s `CATEGORY_NODE_KIND`/`SINK_CATEGORIES` — confirm
  which category(ies) represent a genuine outbound network call before B2
  needs the answer (`external-api` is the obvious one; check whether
  `webhook`/`email`/`sms`/`push-notification` should also count as
  "network, transit-relevant" — this increment does not need the final
  answer, but should NAME the categories it will eventually filter on in
  its own design doc, so B2 starts from a checked list, not a guess).
- `dataflow/CLAUDE.md`'s own documented `scanCryptoProtocol(fp, raw)`
  contract (already read this session): returns a flat array of findings,
  each with `{file, line, family, ...}` (`family` values include
  `crypto-tls-no-verify`, `crypto-tls-version` per that module's own
  `EMITS` export) — opt-out via `AGENTIC_SECURITY_NO_CRYPTO_PROTO=1`,
  silently returns `[]` for a file over 500KB or with no crypto-relevant
  content (`_isCryptoRelevant`) — both are pre-existing, harmless
  behaviors this increment inherits for free, not something to work around.

## Scope for this increment

1. **New module**, `scanner/src/lineage/transit-protection.js`. Header
   comment mirrors this package's established isolation-and-reuse-boundary
   discipline (see `resolve-destination.js`/`handling-analyzer.js`'s own
   headers as the template). Imports ONLY `scanCryptoProtocol` from
   `../sast/crypto-protocol.js` — confirm that's a valid, correct relative
   path from `src/lineage/` before writing the import (it should be
   `../sast/crypto-protocol.js`, verify against the real directory
   layout). Exports one function:

   ```js
   export function scanTransitEvidence(fileContents) {
     const byFile = new Map();
     for (const [file, raw] of Object.entries(fileContents ?? {})) {
       if (typeof raw !== 'string') continue;
       let findings;
       try { findings = scanCryptoProtocol(file, raw); } catch { findings = []; }
       if (findings.length) byFile.set(file, findings);
     }
     return byFile;
   }
   ```

   This is the REAL, complete, working half of this increment — it is not
   a stub. It genuinely runs the existing detector over every file and
   returns a real, inspectable `Map<file, findings[]>`. What it does NOT
   do yet: join those findings to any specific graph edge, or write
   anything onto `edge.protection.transit` — that join logic is B2's own
   unit, deliberately not attempted here (per the plan's own "prove the
   plumbing before the logic" discipline, matching Sub-project A/D's own
   increment-1 precedent).
2. **A short design doc**, `scanner/src/lineage/DESIGN_TRANSIT_PROTECTION.md`,
   mirroring `DESIGN_DESTINATION_RESOLVER.md`'s scale: record the isolation
   decision (separate post-pass, never `coverage.js`/`graph-builder.js`),
   the `fileContents` plumbing path, the candidate "network" category list
   named above (not yet used, but written down so B2 doesn't have to
   re-derive it), and explicitly name what B2 will do that this increment
   does not (the file+line correlation join, writing real verdicts).
3. **`index.js`**: `buildLineageGraph(callGraph, opts)` gains an optional
   `opts.fileContents` parameter, threaded to a new, additive step — call
   `scanTransitEvidence(opts.fileContents ?? {})` and attach its result
   to the RETURNED status object as a new field, e.g. `transitEvidence`
   (a `Map`, or `Object.fromEntries(...)` if a caller/test needs a
   JSON-serializable shape — decide and document which, don't leave it
   ambiguous), alongside the existing `{status, graph, failure, elapsedMs}`
   shape. **The `graph` field itself must stay byte-identical to before
   this increment** — this increment proves that explicitly, in its own
   test, by running with and without `opts.fileContents` supplied and
   asserting `graph` is `deepEqual` either way, the same
   "byte-identical when a hook is omitted" proof every additive hook this
   session has shipped (`opts.resolveSiteDecision`, `opts.resolveDestination`)
   already carries.
4. **`engine.js`**: at the `buildLineageGraph(callGraph, {...})` call site
   inside `runFullScan`, add `fileContents` to the passed opts object —
   the one-line addition Finding 2 already confirmed is trivial. Verify
   this doesn't change `runFullScan`'s own output for a scan with
   `AGENTIC_SECURITY_LINEAGE_DEEP` unset (the lineage block is skipped
   entirely then — already true, this increment doesn't change that gate).

## Do NOT touch

`coverage.js`, `graph-builder.js`, `resolve-destination.js`,
`orm-write-catalog.js`/`sink-registry.js`'s ORM-write pieces, anything
under `src/lineage/` that E1-E3/A1/D1-D2 already shipped — all read-only
references (`sink-registry.js`'s `CATEGORY_NODE_KIND`/`SINK_CATEGORIES`
are read to CONFIRM the candidate network-category list, never edited).
`edge.protection.transit` itself is not written to by this increment at
all — it stays `not_assessed`/`none` on every edge after this increment,
exactly as before. Do not attempt any file+line correlation join logic —
that is explicitly B2's job, named as deferred, not improvised here.

## Test plan

New `scanner/test/lineage/transit-protection.test.js`:

1. `scanTransitEvidence` on a real fixture containing a
   `rejectUnauthorized: false`-shaped call (the same shape
   `crypto-protocol.js`'s own `test/crypto-protocol.test.js` already
   proves fires `crypto-tls-no-verify`) → returns a `Map` with that file
   as a key, findings including a `family: 'crypto-tls-no-verify'` entry.
2. `scanTransitEvidence` on a clean fixture (no crypto-relevant content)
   → returns an empty `Map` (or a `Map` with no entry for that file —
   confirm `scanCryptoProtocol`'s own real behavior on a clean file before
   asserting which, don't guess).
3. `scanTransitEvidence({})` / `scanTransitEvidence(undefined)` → returns
   an empty `Map`, never throws.
4. `buildLineageGraph`'s own byte-identical proof: build a graph twice
   from the same real `callGraph` fixture, once with `opts.fileContents`
   supplied (containing real crypto-relevant content) and once without —
   `result.graph` must be `assert.deepEqual` between the two runs.
   `result.transitEvidence` (or whatever field name step 3 above settles
   on) must be present and non-empty in the WITH-fileContents run.
5. Full `npm run test:lineage`, `npm run test:sast` (crypto-protocol.js's
   own scope — confirm this increment doesn't perturb its existing tests,
   since you're now a second consumer of `scanCryptoProtocol`), and
   `npm test` stay green, real captured exit codes.

## Explicitly deferred

The file+line correlation join (which edge gets which verdict) — B2. Any
write to `edge.protection.transit` — B2. The final candidate "network
category" list's actual USE in filtering which edges matter — named here,
used in B2. AC-03/AC-04 fixtures — B3.
