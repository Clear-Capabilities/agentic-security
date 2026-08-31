# Sub-project E, increment E5 — scoping report

**Status:** research/scoping only, no implementation code. Written to ground a
subsequent real implementation plan for `scanner/src/lineage/index.js` +
`runFullScan` wiring — the last increment in Sub-project E.

**Binding starting point:** `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` §9.5's
four-item checklist. This report measures each item against the real code and
resolves the open questions §9.5 left implicit.

---

## 1. The `AGENTIC_SECURITY_PRIVACY_DEEP` template — measured, and one correction

`scanner/src/dataflow/index.js:132-141`, inside `runDeepAnalysis(perFileIR,
callGraph, opts)`:

```js
if (process.env.AGENTIC_SECURITY_PRIVACY_DEEP === '1') {
  try {
    const privacyFindings = runPrivacyTaintEngine(callGraph, opts);
    const existing = new Set(findings.map(f => `${f.file}:${f.line}:${f.sink?.label || f.cwe || ''}`));
    for (const f of privacyFindings) {
      const key = `${f.file}:${f.line}:${f.sink?.label || f.cwe || ''}`;
      if (!existing.has(key)) findings.push(f);
    }
  } catch { /* privacy-deep failure should not fail the scan */ }
}
```

Gated by a single env var read at call time (no CLI flag, no `opts` override).
Best-effort: yes, a thrown error never propagates past this block. **Failure
recorded in `scanHealth`: NO — this block's own `catch` is a bare, silent
swallow with only a comment.** §9.5 item 1's own wording ("failure recorded in
`scanHealth`") does not describe this block; it describes a *different*,
outer mechanism — see §2 below. This is a real correction to make explicit in
the implementation plan: mirroring `AGENTIC_SECURITY_PRIVACY_DEEP`'s *shape*
(opt-in, best-effort) is right; mirroring its *failure handling* verbatim
would silently swallow a lineage-build failure with no `scanHealth` signal at
all, contradicting §9.5 item 1's own requirement.

The mechanism that DOES record failure into `scanHealth` is the **outer**
`_deepEnabled` block in `engine.js` (§2), not anything inside `dataflow/index.js`.

## 2. `runFullScan`'s `_sharedIR` memo — exact mechanics

**Naming:** §9.5 item 1 says "runFullScan", and that IS the real internal
function name — `scanner/src/engine.js` exports `runFullScan` (the ~1600-line
function spanning roughly lines 9000-10600); `scanner/src/runScan.js`'s public
`runScan(rootDir, opts)` is a thin wrapper that calls it
(`runScan.js:8` imports `{ runFullScan, ... } from './engine.js'`).
`src/index.js` re-exports `runScan`/`scanPath` — never `runFullScan` directly.
**E5 wires into `runFullScan` in `engine.js`; the plan should say `runFullScan`,
not `runScan`, when it means the function E5 edits.**

**`_sharedIR` lifecycle** (`engine.js`):
- `let _sharedIR = null;` (~line 9115).
- Built EAGERLY only when IR-stats instrumentation is on
  (`_irStatsTarget`, ~9131-9142) — an opt-in diagnostics path, not something a
  normal scan enables.
- Built LAZILY inside the `_deepEnabled` block (~9161-9178):
  `const { perFile, callGraph } = _sharedIR || (_sharedIR = await _buildIR());`
  — i.e. **`_sharedIR` is only guaranteed built when `AGENTIC_SECURITY_DEEP=1`
  (or `opts.deep === true`) is already in effect**, or CI has it forced off, in
  which case `_sharedIR` stays `null` for the whole rest of the scan.
- Reused (not rebuilt) later for privacy-taint annotation (~9598-9629), with an
  explicit **degraded fallback when `_sharedIR` is null**: `irBacked =
  !!(_sharedIR && _sharedIR.perFile)`; when false, a NON-IR adapter is used
  instead of forcing a second parse pass, and the result is honestly marked
  `irBacked: false`. The comment there is explicit about the tradeoff: forcing
  an IR build here would reintroduce the exact cost `AGENTIC_SECURITY_DEEP`'s
  opt-in gate exists to avoid (NFR: "no more than 15% overhead ... excluding
  newly enabled deep analysis").

**This is the single most important scoping fact for E5.** Unlike privacy-taint,
lineage analysis has **no degraded/non-IR-backed mode at all** — `coverage.js`'s
`buildGraphWithCoverage(callGraph, opts)` requires a real `callGraph` with real
CFGs; there is no meaningful "lineage graph without IR" fallback the way
privacy-taint has a regex-ish `{_content, decls:[], calls:[]}` stand-in. So E5
cannot silently piggyback on `_sharedIR` being present-or-absent the way
privacy-taint does — it must make an explicit choice (§9's open question, below):
run only when `_sharedIR` is already available (piggybacking on deep mode being
on), or force its own IR build when its own env var is set even if deep mode
is off.

**Shape match — measured live, zero glue code needed.** Built `_sharedIR` for
real via `buildProjectIR` on `test/fixtures/vulnerable-js` and fed
`callGraph` straight into `buildGraphWithCoverage`:

```
perFile keys: [ 'app.js' ]
callGraph.functions type: Map size: 8
validateGraph errors: []
nodes/edges/dataElements/flows: 9 6 6 6
```

`callGraph.functions` is a `Map`, exactly what `graph-builder.js`'s own
`enumerateSinkSites`/`buildDataFlowGraph` iterate via `.values()`. The output
is byte-for-byte the numbers already pinned in `graph-builder.test.js`/
`coverage.test.js`. **No adapter, no shape translation needed** — `runFullScan`'s
`_sharedIR.callGraph` is exactly `graph-builder.js`'s own test fixtures'
`buildCallGraph(perFile)` output, because it's literally produced by the same
`buildProjectIR` → `buildCallGraph` path both the lineage package's own tests
and `runFullScan` call.

## 3. `--deterministic` — an exact, ready-made precedent for `generatedAt`

`bin/agentic-security.js` imports `isDeterministic`/`makeDeterministic` from
`scanner/src/posture/deterministic.js`; `--deterministic` sets
`args.flags['deterministic']`, which (per that module, not re-read in full
here since its shape is already summarized correctly by the parent scoping
doc) is what `isDeterministic()` reads.

**The exact pattern to copy is already shipped**, at `engine.js:10347-10353`,
for `findingProvenance.firstObserved.observedAt`:

```js
// Frozen under --deterministic so SARIF ... stays byte-identical run-to-run
observedAt: isDeterministic() ? '1970-01-01T00:00:00.000Z' : new Date().toISOString(),
```

This is not just a similar pattern — it is **the identical literal**
`graph-builder.js`'s own `buildDataFlowGraph` already defaults `generatedAt`
to (`opts.generatedAt ?? '1970-01-01T00:00:00.000Z'`). E5's wiring code needs
exactly one line:

```js
generatedAt: isDeterministic() ? undefined : new Date().toISOString(),
```

(passing `undefined` lets `buildGraphWithCoverage`'s own default apply,
rather than duplicating the literal a second place — one source of truth for
the frozen value, in `graph-builder.js`).

## 4. Where scan artifacts are written — two-layer split, not one

**Critical structural fact for scoping task boundaries:** `runFullScan`
(`engine.js`) never writes anything to disk itself — it returns a plain
result object. Persistence is a **CLI-layer** (`bin/agentic-security.js`)
concern:

```js
// bin/agentic-security.js:1048-1052
const lastScanBody = JSON.stringify(persistedScan, null, 2);
await fsp.writeFile(path.join(stateDirPath, 'last-scan.json'), lastScanBody);
try {
  await fsp.writeFile(path.join(stateDirPath, 'last-scan.json.sig'), _signLastScan(lastScanBody));
} catch { /* non-fatal — sig file is best-effort */ }
```

gated earlier by a project-marker check (state is refused when the target
isn't recognized as a project root — `stateDirPath` computation, not
re-derived here). `_signLastScan` is imported as
`import { signLastScan as _signLastScan, verifyLastScan as _verifyLastScanShared } from '../src/posture/integrity.js'`
— the per-install HMAC-SHA256 signer the root CLAUDE.md's "last-scan.json
integrity" bullet describes.

**Implication: E5 spans two layers, not one.**
1. `engine.js`/`runFullScan` — build the graph in-process, attach it to the
   returned scan-result object (e.g. a new `scan.lineageGraph` field,
   mirroring how `scanHealth`/`coverageLedger`/etc. are already attached at
   the big return-object literal, `engine.js:10603`), and record
   success/failure into `scanHealth` (a NEW condition, since none of
   `computeScanHealth`'s existing inputs — `deepStatus`, `analyzerCoverage`,
   etc. — currently has a lineage-shaped slot; §11 below).
2. `bin/agentic-security.js` — persist it to disk, mirroring
   `last-scan.json`'s own write+sign pattern, at a sibling path (recommended:
   `.agentic-security/lineage-graph.json` + `.agentic-security/lineage-graph.json.sig`).

**Gitignore/settings — zero new config needed.** `.gitignore:43` already has
`**/.agentic-security/` (every depth), so a new file under that directory
needs no gitignore change. `.claude/settings.json`'s read-deny list was not
re-read in full for this report (out of scope — it denies READS of generated
bundles/caches for the *editor*, not writes; a new state file there follows
the same existing directory-level pattern the rest of `.agentic-security/`
already uses, so nothing suggests it needs a bespoke entry, but the
implementer should grep `.claude/settings.json` once before assuming).

**Whether `signLastScan`/`verifyLastScan` are generic enough to reuse for a
second artifact, or hardcoded to the "last-scan" name/shape, was NOT verified
in this pass** (`posture/integrity.js` was not read) — flagged as an open
question for the implementation plan, not resolved here.

## 5. `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS` — confirmed genuinely inert today

```
$ grep -rn "AGENTIC_SECURITY_LINEAGE" scanner/src/ scanner/bin/
scanner/src/lineage/summaries.js:11:  (comment)
scanner/src/lineage/summaries.js:30:  (comment)
scanner/src/lineage/summaries.js:44:  const envCap = Number(process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS);
```

Only `summaries.js` reads it; nothing under `src/`/`bin/` sets, threads, or
documents it as a scan-facing knob. Confirms `CLAUDE.md`'s own claim
verbatim: "Operator-facing" is aspirational until Sub-project E's own driver
is reachable from `runFullScan` — which is exactly E5's job. No plan action
needed beyond documenting the env var once E5 lands (§9.5 item 4) — the
variable itself needs no code change, only for a real caller (E5's own
`runFieldIdentityAnalysis`/`buildGraphWithCoverage` call, which already
threads `opts.maxContextsPerFn` down to `summaries.js` via
`graph-builder.js`'s own `buildDataFlowGraph`) to exist in the `runFullScan`
path.

## 6. Existing deep-mode gating precedent — the real template for E5's OWN gate

`engine.js:9143-9231` (already quoted in part above) is the actual, complete,
load-bearing precedent — more relevant than `AGENTIC_SECURITY_PRIVACY_DEEP`'s
inner block, because it's the one that:
- reads BOTH an explicit `opts.deep`-style override AND an env var
  (`AGENTIC_SECURITY_DEEP`), matching `deep === true || process.env.X === '1'`;
- auto-disables in CI unless a second override is set
  (`AGENTIC_SECURITY_DEEP_IN_CI` / `opts.deepInCi`);
- emits a non-blocking info finding when skipped in CI so operators see it
  (`ir-taint-ci-skipped`);
- builds a `_deepStatus` object (`requested`/`enabled`/`inCi`/
  `ciOverrideAllowed`/`reason`/`failure`) that becomes `computeScanHealth`'s
  `deepStatus` argument;
- records a REAL failure into that object's `failure` field via its own
  try/catch around the actual analysis call (`_deepFailure = String(...)`,
  `engine.js:9196-9202`), which is what makes `scanHealth.conditions` report
  `"deep analysis (IR-taint) threw and fell back to pattern-only results: ..."`
  (`pipeline/scan-health.js:60-61`).

**Recommendation: E5 should be its own top-level block in `runFullScan`,
structurally parallel to this `_deepEnabled` block — not nested inside
`runDeepAnalysis`/`dataflow/index.js` at all.** Reasons: (a) lineage produces
an ARTIFACT (a graph document attached to the scan result), not `findings` —
`runDeepAnalysis`'s whole contract is "return an array of findings", and
shoehorning a graph into that return shape (or into a side-channel from
inside it) is a worse fit than a sibling top-level block that already has the
exact right shape (its own gate, its own status object, its own place in the
final return literal). (b) Lineage's cost profile (a full field-identity
fixed-point analysis over every function) is closer to `runDeepAnalysis`
itself than to one of `runDeepAnalysis`'s OWN optional sub-passes (IFDS,
privacy-deep, symbolic exec) — it deserves its own budget/timeout treatment
mirroring `AGENTIC_SECURITY_DEEP_TIMEOUT_MS`/`AGENTIC_SECURITY_DEEP_FN_LIMIT`,
not inheriting `runDeepAnalysis`'s existing budget silently. (c) It lets E5
reuse the `_sharedIR || (_sharedIR = await _buildIR())` idiom directly and
explicitly, at the same syntactic level `_deepEnabled`'s own block already
does it, rather than reaching into `dataflow/index.js`'s internals.

**No existing `AGENTIC_SECURITY_LINEAGE_DEEP`-style flag exists yet** — grep
confirms zero references anywhere in `src/`/`bin/` to any env var starting
`AGENTIC_SECURITY_LINEAGE` besides `_MAX_CONTEXTS` (§5). E5 must mint one.
Recommended name, matching the sibling `AGENTIC_SECURITY_PRIVACY_DEEP`/
`AGENTIC_SECURITY_DEEP` convention: `AGENTIC_SECURITY_LINEAGE_DEEP=1` (a
`_DEEP` suffix, not a bare `AGENTIC_SECURITY_LINEAGE=1`, to keep the "this is
the expensive opt-in analysis pass" naming pattern consistent with its two
siblings).

## 7. `runFullScan` vs `runScan` — resolved

Confirmed in §2: `runFullScan` is the real, internal function in `engine.js`
(the ~1600-line one); `runScan` (`runScan.js`) is the thin public wrapper.
§9.5 item 1's wording was accurate, not stale. The implementation plan should
name `runFullScan` (`engine.js`) as the file/function E5 edits.

## 8. Live end-to-end shape check — see §2's inline transcript

No glue code needed. `buildProjectIR(fc).callGraph` → `buildGraphWithCoverage`
works with zero adapters, confirmed by direct execution (not assumed).

---

## 9. Open questions the implementation plan must resolve explicitly

1. **Does `AGENTIC_SECURITY_LINEAGE_DEEP=1` force its own `_sharedIR` build
   when deep mode (`AGENTIC_SECURITY_DEEP`) is OFF, or does it only run when
   `_sharedIR` is already available?** Per §2, there is no meaningful
   degraded lineage output the way privacy-taint has one, so "only run when
   piggybacking on deep mode" would make `AGENTIC_SECURITY_LINEAGE_DEEP` alone
   insufficient to ever produce a graph — a confusing contract (operator sets
   the flag, nothing happens, no clear reason surfaced) unless CAREFULLY
   documented and reflected in `scanHealth`'s `reason` field the same way
   `_deepStatus.reason` already handles "requested but did not run". The
   other option — `AGENTIC_SECURITY_LINEAGE_DEEP=1` forces its own
   `_sharedIR || (_sharedIR = await _buildIR())` build independent of
   `AGENTIC_SECURITY_DEEP` — is more useful (a lineage-only scan doesn't need
   to also pay for the full taint-finding pass) but means E5 can trigger an IR
   build that `AGENTIC_SECURITY_DEEP`'s absence was supposed to prevent,
   which needs to be a disclosed, deliberate decision, not an accident of
   code ordering. **Recommendation: the second option** (E5 gates and builds
   independently), since Sub-project E's entire value proposition is a
   standalone lineage capability, not a deep-mode add-on — but this must be
   an explicit, written ruling in the plan, not implied by code structure.

2. **`computeScanHealth`'s signature needs a new optional input** — none of
   its existing params (`scanMeta`, `annotatorErrors`, `engineErrors`,
   `deepStatus`, `analyzerCoverage`) is lineage-shaped. Two options: (a) add a
   new `lineageStatus` param mirroring `deepStatus`'s own shape
   (`{requested, enabled, failure}`) plus a new condition-builder line in
   `computeScanHealth` itself (an additive change to
   `scanner/src/pipeline/scan-health.js`, matching that module's own stated
   "additive-only" design principle); (b) fold it into the existing
   `deepStatus` object as an extra field. **Recommendation: (a)**, a
   sibling field — `deepStatus`'s own JSDoc names it specifically for
   IR-taint, and conflating the two would make `scanHealth.deepAnalysis.failure`
   ambiguous about which subsystem actually failed, which is exactly the
   "distinguish A from B" discipline `computeScanHealth`'s own §16.7-style
   commentary already practices elsewhere in this codebase (see
   `analyzerCoverage`'s own comment on why it's a distinct condition from
   `annotatorErrors`).

3. **Where exactly in the ~1600-line `runFullScan` body should the new block
   live?** Candidates, not yet decided: right after the existing
   `_deepEnabled` block (§2/§6) so it can see `_sharedIR` if deep mode already
   built it and reuse it for free, before `_deepStatus` is finalized so a
   lineage condition can ride into the SAME `_scanHealth` computation call
   (`engine.js:10582`) as everything else, in one `computeScanHealth(...)`
   call rather than a second patch pass (avoiding the exact `applyFreshness`
   two-call complexity `scan-health.js`'s own header explains was needed for
   an unrelated reason — custom-rules timing).

4. **`signLastScan`/`verifyLastScan` (`posture/integrity.js`) reuse** —
   confirm whether they're generic (any JSON body, any filename) or
   hardcoded to `last-scan.json`'s own shape before assuming they can sign a
   second artifact unchanged. Not verified in this report.

5. **Artifact filename/path bikeshed** — `.agentic-security/lineage-graph.json`
   is this report's recommendation (parallel to `last-scan.json`), but
   confirm nothing else in `.agentic-security/` already claims that name
   (not checked here) and confirm the CLI needs a new flag
   (`--lineage`? implied by `AGENTIC_SECURITY_LINEAGE_DEEP=1` alone, matching
   how `--deterministic` and env vars coexist elsewhere) to trigger the
   CLI-layer write step, separate from the engine-layer gate in point 1.

6. **Budget/timeout knobs** — per §6's reasoning (lineage deserves its own
   budget, not `runDeepAnalysis`'s inherited one), name and default
   `AGENTIC_SECURITY_LINEAGE_TIMEOUT_MS`/`AGENTIC_SECURITY_LINEAGE_FN_LIMIT`
   explicitly, mirroring `AGENTIC_SECURITY_DEEP_TIMEOUT_MS`/
   `AGENTIC_SECURITY_DEEP_FN_LIMIT`'s existing defaults (300_000ms / 5000
   functions) as a starting point — not yet measured against lineage's own
   actual per-function cost, which is more expensive per function than
   taint analysis (full fixed-point field-identity analysis vs. k=2
   monovariant taint).
