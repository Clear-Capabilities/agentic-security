# Milestone 2, Sub-project B, increment 2: transit protection verdicts (closes AC-03/AC-04)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-b-scoping.md`'s
own "Correction (post-B1, before B2)" section — READ THAT SECTION FIRST,
it overrides the document's own earlier "Option 2" recommendation. This
increment computes real `edge.protection.transit` verdicts for network
edges, hooking `graph-builder.js` directly (not a pure post-pass), per the
corrected design.

## What already exists (confirmed by direct read, this session, HEAD `51bdadbf`)

- `graph-builder.js`'s edge-construction block already reads `site` at the
  exact point `protection: emptyProtection()` is set — the same block
  that reads `site.destination?.resolutionStatus` for `protocol
  .destinationResolution` (Sub-project A, increment 1's own hook point).
  **Re-verify this exact block's current line numbers before writing
  code** — the scoping doc's own correction cited it without a line
  number deliberately, for exactly this reason.
- `transit-protection.js`'s `scanTransitEvidence(fileContents) ->
  Map<file, findings[]>` (B1, already shipped) — each finding is a real
  `crypto-protocol.js` shape: `{id, file, line, vuln, severity, cwe,
  family, parser: 'CRYPTO-PROTO', ...}`. The two families this increment
  cares about: `crypto-tls-no-verify` and `crypto-tls-version` (confirmed
  against `crypto-protocol.js`'s own `EMITS` export and `detectTlsNoVerify`/
  `detectTlsMinVersion`'s own `_shape(...)` calls).
- `node.destination` (Sub-project A, increment 1) already gives
  `{resolutionStatus, raw, literalValue, blockingExpression}` per site,
  accessible as `site.destination` at the SAME edge-construction point.
  `literalValue` is the unwrapped string (`'https://x'`, no quotes) when
  `resolutionStatus === 'literal'`.
- `protection.js`'s `PROTECTION_VERDICTS`/`EVIDENCE_GRADES`/`emptyProtection()`
  — unchanged, already shipped in Milestone 0, nothing to add here.
- This codebase's own established line-WINDOW correlation precedent:
  `engine.js`'s `dropGuardedFindings` and several other detectors already
  correlate a finding to a nearby line via a small, disclosed window
  (examples measured directly: `-2/+3`, `-2/+4`, `+10` lines, depending on
  the detector) — this increment's own window constant is a NEW,
  independently-chosen value for THIS correlation (a TLS-config object is
  often on the same line as, or a few lines before, the network call it
  configures), not copied from any one existing example, but following the
  SAME established technique.

## Scope for this increment

1. **`transit-protection.js`** (extend, additively): add
   `TRANSIT_PROTECTION_WINDOW_LINES = 10` (a named, disclosed constant —
   do not inline a magic number) and a new exported function:

   ```js
   const TRANSIT_FINDING_FAMILIES = new Set(['crypto-tls-no-verify', 'crypto-tls-version']);

   export function resolveTransitProtectionForSite(site, transitEvidenceByFile) {
     if (!site || site.decision?.category !== 'external-api') return undefined;
     const dest = site.destination;
     const raw = dest?.resolutionStatus === 'literal' ? dest.literalValue : null;
     if (typeof raw === 'string' && raw.startsWith('http://')) {
       return { verdict: 'unprotected', evidenceGrade: 'code' };
     }
     const findings = transitEvidenceByFile?.get(site.file) ?? [];
     const nearby = findings.some((f) =>
       TRANSIT_FINDING_FAMILIES.has(f.family) &&
       typeof site.line === 'number' && typeof f.line === 'number' &&
       Math.abs(f.line - site.line) <= TRANSIT_PROTECTION_WINDOW_LINES);
     if (nearby) return { verdict: 'unprotected', evidenceGrade: 'code' };
     if (typeof raw === 'string' && raw.startsWith('https://')) {
       return { verdict: 'protected', evidenceGrade: 'code' };
     }
     return undefined;
   }
   ```

   `category !== 'external-api'` is a deliberate, NARROW first slice —
   `webhook`/`email`/`sms`/`push-notification`/`analytics`/`monitoring`/
   `collaboration`/`ai-*` (B1's own `DESIGN_TRANSIT_PROTECTION.md`
   candidate list) are all real, plausible "also network" categories, but
   widening the filter is separate, deliberate scope for a later
   increment — name this explicitly in this increment's own design-doc
   update, don't silently include or silently exclude without saying so.
   Returning `undefined` (not a fabricated `unknown`/`none`) for a dynamic/
   unresolved destination with no nearby finding is the HONEST answer —
   `emptyProtection()`'s own default (`not_assessed`/`none`) already means
   exactly that, so this function correctly declines to overwrite it
   rather than manufacturing a `'unknown'` verdict that implies more
   analysis happened than actually did.
2. **`graph-builder.js`**: `buildDataFlowGraph(callGraph, opts)` gains
   `opts.resolveTransitProtection(site) -> {verdict, evidenceGrade} |
   undefined`, applied at the exact block identified above (the same one
   that reads `site.destination?.resolutionStatus`), composing into the
   edge's `protection` object: `protection: { ...emptyProtection(),
   transit: opts.resolveTransitProtection?.(site) ?? emptyProtection().transit }`
   — mirroring `opts.resolveDestination`'s own "hook composes, defaults to
   the pre-hook value when omitted or returning falsy" contract exactly.
   Byte-identical to before this increment when the hook is omitted — this
   increment's own test must prove that directly (the same proof every
   additive hook this session has shipped carries).
3. **`coverage.js`**: `buildGraphWithCoverage(callGraph, opts)` gains
   `opts.transitEvidenceByFile` (a pre-computed `Map<file, findings[]>` —
   NOT raw `fileContents`; see item 4 below for why the computation must
   happen exactly once, in `index.js`), threaded to a NEW default
   `opts.resolveTransitProtection` closing over that map, composing with
   any caller-supplied override the same way `resolveDestination`'s own
   default composition already works (`opts.resolveTransitProtection ??
   <default built from transitEvidenceByFile>`).
4. **`index.js`**: `buildLineageGraph`'s own `opts.fileContents` (B1,
   already shipped) is now the ONLY place `scanTransitEvidence` is ever
   called — its result feeds BOTH the existing, unchanged `transitEvidence`
   return field AND the new `opts.transitEvidenceByFile` passed to
   `buildGraphWithCoverage` (item 3), the same `Map` reference, computed
   once. **Confirmed, not hypothetical: as
   currently shipped, `index.js`'s own `buildGraphWithCoverage(callGraph,
   {...})` call passes NO `fileContents` at all — `scanTransitEvidence` is
   invoked exactly once today, only for the separate `transitEvidence`
   field.** Adding a second call inside `coverage.js`'s own default hook
   WOULD double-scan every file (once for `index.js`'s `transitEvidence`,
   once inside `coverage.js`'s hook) unless deduplicated. **Required, not
   optional:** compute `scanTransitEvidence(opts.fileContents ?? {})`
   exactly ONCE in `index.js`, and pass the resulting `Map` itself down as
   part of `opts` (e.g. `opts.transitEvidenceByFile`) to
   `buildGraphWithCoverage`/`buildDataFlowGraph`'s default hook, rather
   than having `coverage.js` independently re-derive it from raw
   `fileContents` a second time. This is a real, load-bearing
   architecture decision this increment must get right, not a nice-to-have
   optimization — write a test proving `scanCryptoProtocol` (or
   `scanTransitEvidence`) is called exactly once per file per
   `buildLineageGraph` call (e.g. by instrumenting a call counter in the
   test, the same "measure it live, don't just argue it" discipline this
   session's other increments already used for similar single-pass claims).
5. **`DESIGN_TRANSIT_PROTECTION.md`**: add a new section covering the
   corrected hook point, the window constant and why 10 (a real, disclosed
   tuning choice — not derived from measurement, since no real fixture
   corpus exists yet to tune against; name this honestly as a starting
   value, not a calibrated one), the `external-api`-only filter and the
   named-but-deferred wider category list, and the `http://`/`https://`/
   nearby-finding decision table above as a literal table.

## Do NOT touch

`sink-registry.js`, `orm-write-catalog.js`, `resolve-destination.js` (read
its `literalValue` shape, never modify it), `handling-analyzer.js`,
`node.storeDetail`/`node.queueDetail`'s own extraction code (Sub-project
E — entirely unrelated fields), `flow-grade.js`/`path-store.js`/
`path-query.js`. `edge.protection.atRest`/`.handling` stay untouched
(Sub-project C's and a later Sub-project D/handling-verdict increment's
own jobs respectively) — this increment writes `transit` only.

## Test plan

Extend `scanner/test/lineage/transit-protection.test.js` (the existing B1
file — this is the same feature's own next increment, not a new file):

1. **AC-03 proof**: a real fixture, `fetch('http://payments.example/charge',
   {...})` reaching an `external-api` sink → `edge.protection.transit ===
   {verdict: 'unprotected', evidenceGrade: 'code'}`. Build via
   `buildDataFlowGraph` directly (no `fileContents` needed for THIS case —
   the literal `http://` scheme alone is sufficient evidence, proving the
   scheme-only path works even with `opts.fileContents` entirely omitted).
2. **AC-04 proof**: `https.request('https://payments.example/charge', {
   rejectUnauthorized: false }, cb)` (or an equivalent real shape
   `crypto-protocol.js`'s own test suite already proves fires
   `crypto-tls-no-verify`), built via `buildGraphWithCoverage` WITH
   `opts.fileContents` supplying that file's real text → `edge.protection
   .transit === {verdict: 'unprotected', evidenceGrade: 'code'}` — the
   literal HTTPS scheme alone must NOT read as protected once the nearby
   finding overrides it (this is the core AC-04 property: "the UI must
   not award protection based on the scheme alone").
3. **A real protected case**: the same HTTPS literal shape with NO nearby
   crypto-protocol finding → `{verdict: 'protected', evidenceGrade: 'code'}`.
4. **A dynamic-destination case**: `fetch(url, ...)` where `url` is a
   parameter (already FR-203-flagged as `dynamic`) → `edge.protection
   .transit` stays the DEFAULT `{verdict: 'not_assessed', evidenceGrade:
   'none'}` — proving `resolveTransitProtectionForSite` correctly declines
   rather than guessing.
5. **A non-network category case**: a `database`/`log` sink edge →
   `edge.protection.transit` stays default, proving the `category !==
   'external-api'` filter works and this increment doesn't over-fire on
   unrelated sink kinds.
6. **Byte-identical proof**: `buildDataFlowGraph`'s own output with
   `opts.resolveTransitProtection` omitted entirely must be byte-identical
   to pre-increment behavior — the same hook-omitted proof every prior
   additive hook has shipped.
7. Full `npm run test:lineage`, `npm run test:sast` (confirm
   `crypto-protocol.js`'s own suite still unaffected — now consumed by
   TWO lineage-side call paths), and `npm test` stay green, real captured
   exit codes.

## Explicitly deferred

Widening the network-category filter beyond `external-api` (named, not
attempted). AC-05's own dynamic-destination clause beyond what item 4
above already proves (the PRD's AC-05 wording is about the Unresolved-
outbound-destination NODE existing, already shipped by Sub-project A/E4 —
this increment's own transit-verdict contribution to that scenario is
exactly "stays not_assessed," proven, not more). AC-06 (Sub-project C).
AC-12's aggregate "mixed" verdict (needs an aggregation rule no increment
has built). `atRest`/`handling` protection dimensions. Any language beyond
JS/TS. `runtime` evidence grade. B3 (the dedicated exit-gate fixture pass,
if anything beyond this increment's own tests 1-2 above turns out to be
needed once this lands — likely subsumed by them, confirm rather than
assume when B3 is actually scoped).
