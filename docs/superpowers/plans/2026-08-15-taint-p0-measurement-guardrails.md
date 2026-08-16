# Taint Engine P0 — Measurement + Guardrails Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the honest-measurement and precision-guardrail infrastructure that every later phase of `docs/TAINT_ENGINE_IMPROVEMENT_PRD.md` depends on — a taint-shaped recall breakout in the scorecard, and a completed per-language taint false-positive negative control — without touching any detector or IR parser.

**Architecture:** Two independent, additive extensions to existing, already-gated instruments. (1) `bench/layer-recall/runner.mjs` already computes per-language IR-TAINT recall over the whole 214-entry corpus, diluted by the ~204 entries that don't need taint; it gains a second breakout scoped to the `deep/` tier — entries already required to be *provably invisible without deep mode* — which is what "taint-shaped" means operationally in this codebase. That breakout flows into `docs/SCORECARD.md` via the existing pure-aggregation/impure-driver split (`accuracy-scorecard.js` / `scripts/scorecard.mjs`). (2) `bench/self-scan/fixtures/polyglot/` already tests "does an untainted local literal threaded through one function call reach a sink cleanly" as a negative control, for 4 of 9 languages (go, c#, kotlin, php); its own header comment documents the gap for the rest. Closing that gap for java, js, python, and ruby turns the existing exact-drift `bench:self-scan:check` gate into the taint FP budget the PRD's Theme 6 calls for — no new gate mechanism needed, just a complete negative-control fixture set.

**Tech Stack:** Plain ESM Node scripts (`bench/`, `scripts/`), `node --test` for unit tests, no new dependencies.

## Global Constraints

- Node ≥ 24, ESM throughout (`import`/`export`, no CommonJS) — per root `CLAUDE.md`.
- Every rate this project publishes is carried as `{n, d}` and rendered only through `formatRate()` — never a bare percentage (`scanner/src/posture/accuracy-scorecard.js` header, "INTEGRITY CONTRACT").
- An entry that could not be scored is excluded from every denominator **and** disclosed by name — never silently dropped, never counted as a miss.
- `docs/SCORECARD.md` regeneration must be deterministic: running `npm run scorecard` twice on an unchanged tree produces identical output apart from the `Generated (UTC)` line.
- Never claim a corpus entry belongs to the taint-shaped subset without proving it: `AGENTIC_SECURITY_DEEP=0` must produce zero matching findings, `AGENTIC_SECURITY_DEEP=1 AGENTIC_SECURITY_DEEP_IN_CI=1` must produce one (`bench/cve-replay/CONTRIBUTING.md`, "deep/" tier rule).
- No external tool names in any shipped file (comments, docs, commit messages) — standing project rule.
- After any change under `scanner/src/`, run `npm run build` (from `scanner/`) before relying on the bundle — but this plan touches no file the bundle path re-exports at runtime differently from source, since `bench/`/`scripts/` import `scanner/src/` directly; still rebuild before the final commit so the committed bundle isn't stale relative to `accuracy-scorecard.js`.
- Every gate this plan touches must be proven in **both directions** before being trusted: it passes on the current (correct) state, and it fails when the state is deliberately broken.

---

### Task 1: Fix the stale sanitizer-gate blocker note in CONTRIBUTING.md

**Files:**
- Modify: `bench/cve-replay/CONTRIBUTING.md:34`

**Interfaces:** None — documentation only, no code consumes this.

- [ ] **Step 1: Re-confirm the claim is actually stale (don't trust the earlier finding blindly — re-verify in this task)**

Run:
```bash
cd /Users/ross/code/agentic-security
grep -n "applySanitizerGate\|sanitizersOnPath" scanner/src/engine.js
```

Expected output includes these lines (confirming `sanitizersOnPath` is built from real findings' `_sanitizersOnPath` field, not hardcoded empty):
```
8454:    const sanitizersOnPath = {};
8456:      const names = f && f._sanitizersOnPath;
8458:      if (f.id) sanitizersOnPath[f.id] = names;
8459:      if (f.stableId) sanitizersOnPath[f.stableId] = names;
8461:    _runAnnotator("applySanitizerGate", () => { applySanitizerGate(finalFindings, { sanitizersOnPath }); });
```

If this doesn't match, STOP — the note may not be stale after all, and this task should be dropped rather than edited on a false premise.

- [ ] **Step 2: Edit the stale paragraph**

In `bench/cve-replay/CONTRIBUTING.md`, find this paragraph (currently line 34):

```markdown
  **A known current gap:** the catalog's `sanitizer` entries (e.g. `escapeHtml`, `bleach.clean`) are not consulted anywhere in `dataflow/engine.js`'s live taint walk — the generalized sanitizer-gate (`dataflow/sanitizer-gate.js`) is wired into the pipeline but fed a hardcoded empty `sanitizersOnPath` map (see the comment at `scanner/src/engine.js` around the `applySanitizerGate` call), so it is a documented no-op today. A value passed through a catalog sanitizer is currently still reported as tainted by the interprocedural engine, whether the sanitizer call is inline, assigned, or returned. Until that plumbing lands, don't add a `deep/` entry that depends on sanitizer recognition to score `post:TN` (or an inverted `pre:`-clean entry) — it will fail honestly, which is correct, but per the global corpus rule a failing entry must not be committed. Track it as a coverage gap instead.
```

Replace it with:

```markdown
  **Resolved (verified 2026-08-15):** the catalog's `sanitizer` entries (e.g. `escapeHtml`, `bleach.clean`) ARE consulted in `dataflow/engine.js`'s live taint walk. `engine.js` (`_sanitizersForExpr`) records every sanitizer callee applied to a value reaching a sink argument and stamps it on the finding as `_sanitizersOnPath`; `scanner/src/engine.js` (around the `applySanitizerGate` call) rebuilds a real `sanitizersOnPath` map from those per-finding fields — not a hardcoded empty one — before calling `applySanitizerGate`. This paragraph previously said otherwise; that was stale by the time it was checked, not aspirational. A `deep/` entry that depends on sanitizer recognition to score `post:TN` is buildable now, subject to the ordinary rule that the sanitizer's `appliesTo` family must actually cover the finding's threat class (`scanner/src/dataflow/CLAUDE.md`, "Sanitizer entries are RECORDED, never trusted to kill taint" — a blanket sanitizer never silently clears an unrelated vuln class).
```

- [ ] **Step 3: Verify the doc-links gate still passes**

Run:
```bash
cd /Users/ross/code/agentic-security
node scripts/check-doc-drift.mjs --gate
```
Expected: `doc-links: all user-facing markdown links resolve.` (exit 0). This file has no links, but this confirms the edit didn't accidentally break markdown structure that the checker also walks.

- [ ] **Step 4: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/cve-replay/CONTRIBUTING.md
git commit -m "docs: correct stale sanitizer-gate no-op claim in CVE-replay CONTRIBUTING

sanitizersOnPath is built from real per-finding _sanitizersOnPath fields
(scanner/src/engine.js ~8454-8461), not a hardcoded empty map. A deep/
entry depending on sanitizer recognition is buildable now."
```

---

### Task 2: Add `summarize()` to `bench/layer-recall/attribute.mjs`, TDD

**Files:**
- Modify: `bench/layer-recall/attribute.mjs`
- Test: `scanner/test/layer-recall.test.js`

**Interfaces:**
- Consumes: nothing new — pure function over plain objects.
- Produces: `summarize(rows)` — exported function. `rows` is `Array<{ language: string, detected: boolean, layers: string[] }>` (the same row shape `buildMatrix` already accepts). Returns:
  ```js
  {
    entriesScored: number,
    taintByLanguage: { [language: string]: number },  // count of rows whose layers include LAYER_TAINT
    totalByLanguage: { [language: string]: number },  // count of rows, regardless of detection
  }
  ```
  This is the exact shape `bench/layer-recall/runner.mjs` currently builds inline as its `summary` object (lines 159–164) — this task extracts that inline logic into a tested, reusable pure function so Task 3 can call it twice (once over all rows, once over the `deep`-tier subset) without duplicating logic.

- [ ] **Step 1: Write the failing tests**

Add to the end of `scanner/test/layer-recall.test.js`:

```js
test('summarize() reports entriesScored, taintByLanguage, and totalByLanguage', () => {
  const rows = [
    { language: 'ruby', detected: true, layers: ['IR-TAINT'] },
    { language: 'ruby', detected: true, layers: ['REGEX'] },
    { language: 'go', detected: false, layers: [] },
  ];
  const s = summarize(rows);
  assert.equal(s.entriesScored, 3);
  assert.deepEqual(s.taintByLanguage, { ruby: 1 });
  assert.deepEqual(s.totalByLanguage, { ruby: 2, go: 1 });
});

test('summarize() on an empty row set reports zero everywhere, not undefined', () => {
  const s = summarize([]);
  assert.equal(s.entriesScored, 0);
  assert.deepEqual(s.taintByLanguage, {});
  assert.deepEqual(s.totalByLanguage, {});
});

test('summarize() never puts a language in taintByLanguage with zero taint hits', () => {
  // A language present in totalByLanguage but absent from taintByLanguage means
  // "zero taint recall", not "not measured" — the two must stay distinguishable,
  // and a stray zero-valued key would blur that in downstream JSON consumers.
  const s = summarize([{ language: 'kotlin', detected: true, layers: ['REGEX'] }]);
  assert.deepEqual(s.totalByLanguage, { kotlin: 1 });
  assert.equal('kotlin' in s.taintByLanguage, false);
});
```

Also add `summarize` to the existing import line at the top of the file:

```js
import { layersOf, buildMatrix, summarize, LAYER_TAINT } from '../../bench/layer-recall/attribute.mjs';
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/ross/code/agentic-security/scanner
node --test test/layer-recall.test.js
```
Expected: FAIL — `summarize is not a function` (or a `SyntaxError` on the import, since it doesn't exist yet).

- [ ] **Step 3: Implement `summarize()`**

Add to `bench/layer-recall/attribute.mjs`, after the existing `languageOf` function (end of file):

```js
/**
 * Reduce per-entry rows to the summary shape the corpus baseline and the
 * scorecard both consume: total entries scored, and per-language taint /
 * total counts. Extracted from what `runner.mjs` used to build inline so it
 * can be called twice — once over every row, once over a tier-filtered
 * subset (deep-tier only) — without duplicating the reduction logic.
 *
 * A language present in `totalByLanguage` but absent from `taintByLanguage`
 * means zero taint recall for that language — deliberately not a zero-valued
 * key, so "zero" and "not measured" stay distinguishable downstream.
 */
export function summarize(rows) {
  const taintByLanguage = {};
  const totalByLanguage = {};
  for (const r of rows || []) {
    const lang = r.language || '(unknown)';
    totalByLanguage[lang] = (totalByLanguage[lang] || 0) + 1;
    if ((r.layers || []).includes(LAYER_TAINT)) {
      taintByLanguage[lang] = (taintByLanguage[lang] || 0) + 1;
    }
  }
  return { entriesScored: (rows || []).length, taintByLanguage, totalByLanguage };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/ross/code/agentic-security/scanner
node --test test/layer-recall.test.js
```
Expected: all tests pass, including the 3 new ones and every pre-existing one in this file (10 total).

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/layer-recall/attribute.mjs scanner/test/layer-recall.test.js
git commit -m "feat(bench): extract summarize() from layer-recall runner into attribute.mjs

Pure, unit-tested reduction from per-entry rows to {entriesScored,
taintByLanguage, totalByLanguage} — the shape the corpus baseline and
scorecard consume. Lets the runner call it twice (all entries, deep-tier
only) without duplicating the reduction. No behavior change yet."
```

---

### Task 3: Extend `bench/layer-recall/runner.mjs` — thread tier, deep-tier breakout, `--json` mode

**Files:**
- Modify: `bench/layer-recall/runner.mjs`

**Interfaces:**
- Consumes: `summarize(rows)` from Task 2 (`bench/layer-recall/attribute.mjs`).
- Produces: the CLI now supports a `--json` flag. Its stdout (when passed) is FLAT — the existing top-level keys (`generatedAt`, `entriesScored`, `taintByLanguage`, `totalByLanguage`) are unchanged in shape and meaning ("all entries"), with one new sibling key added:
  ```js
  {
    generatedAt: '2026-08-15',
    entriesScored: 214,                          // unchanged meaning: every corpus entry
    taintByLanguage: { javascript: 8, ... },      // unchanged meaning: over every entry
    totalByLanguage: { javascript: 38, ... },     // unchanged meaning: over every entry
    deepTier: { entriesScored: 6, taintByLanguage: { javascript: 3, ... }, totalByLanguage: { javascript: 3, ... } },
  }
  ```
  This is the exact shape `Task 4`'s `buildScorecard` expects as its `layerRecall` input, and what Task 5 (`scripts/scorecard.mjs`) consumes via `runJson('bench/layer-recall/runner.mjs', ['--json'], 'layer-recall')`, mirroring the exact pattern already used for the corpus runner and self-scan. This is also the shape written to `bench/layer-recall/baseline.json` by `--update-baseline` — the JSON payload and the baseline file describe the same object.
- `baseline.json`'s schema gains a `deepTier` sibling to the existing top-level `taintByLanguage`/`totalByLanguage`/`entriesScored` keys, written by `--update-baseline` and compared by `--check`. The existing top-level keys are UNCHANGED in meaning (still "all entries") — this is additive, not a breaking schema change.

- [ ] **Step 1: Thread `tier` through the row returned by `scoreEntry`**

In `bench/layer-recall/runner.mjs`, find `scoreEntry` (currently returns `{ id, language, detected, layers }` on the success path and `{ id, language, detected: false, layers: [], error }` on the catch path). Change both return statements to include `tier: entry.tier`:

```js
    const { scan } = await runScan(pre);
    const matched = matchingFindings(scan, manifest, matcherFor(manifest));
    return { id: entry.id, tier: entry.tier, language, detected: matched.length > 0, layers: layersOf(matched) };
  } catch (e) {
    // A scan that threw is UNSCORED, not "not detected" — counting a crash as a
    // taint miss would understate the engine and hide the crash.
    return { id: entry.id, tier: entry.tier, language, detected: false, layers: [], error: e.message };
```

(`entry` is already in scope — it's `scoreEntry`'s own parameter, and `listEntries()` already attaches `tier` to every entry it returns.)

- [ ] **Step 2: Import `summarize` and build both summaries**

Change the import line near the top:

```js
import { layersOf, buildMatrix, summarize, languageOf, LAYER_TAINT } from './attribute.mjs';
```

Find the existing summary construction:

```js
const summary = {
  generatedAt: new Date().toISOString().slice(0, 10),
  entriesScored: rows.length,
  taintByLanguage: Object.fromEntries(langs.map(l => [l, matrix[l].byLayer[LAYER_TAINT] || 0])),
  totalByLanguage: Object.fromEntries(langs.map(l => [l, matrix[l].total])),
};
```

Replace it with:

```js
const allSummary = summarize(rows);
const deepRows = rows.filter(r => r.tier === 'deep');
const deepSummary = summarize(deepRows);
const summary = {
  generatedAt: new Date().toISOString().slice(0, 10),
  ...allSummary,
  deepTier: deepSummary,
};
```

(`allSummary`'s `entriesScored`/`taintByLanguage`/`totalByLanguage` are spread directly onto `summary` so the top-level baseline schema keys are unchanged — only the new `deepTier` key is added.)

- [ ] **Step 3: Add a deep-tier-only console table, printed after the existing full-corpus table**

Find the block right before `const summary = {` (i.e., right after the existing `if (blind.length) { ... }` block that prints the "languages with ZERO taint-layer recall" warning). Insert this new block there, before the `const summary =` line:

```js
console.log('\nTaint-shaped subset only (deep/ tier — provably invisible without deep mode)\n');
if (!deepRows.length) {
  console.log('  (no deep-tier entries)');
} else {
  const deepLangs = [...new Set(deepRows.map(r => r.language))].sort();
  console.log([pad('language', 10), pad('entries', 9), pad('IR-TAINT', 13)].join(''));
  console.log('-'.repeat(32));
  for (const lang of deepLangs) {
    const total = deepSummary.totalByLanguage[lang] || 0;
    const taint = deepSummary.taintByLanguage[lang] || 0;
    console.log([pad(lang, 10), pad(total, 9), pad(`${taint} (${pct(taint, total)})`, 13)].join(''));
  }
  const deepLangsWithNoEntry = langs.filter(l => !deepLangs.includes(l));
  if (deepLangsWithNoEntry.length) {
    console.log(`\n  languages with NO deep-tier entry yet: ${deepLangsWithNoEntry.join(', ')}`);
    console.log(`  (not zero recall — simply not measured on the taint-shaped subset)`);
  }
}
```

- [ ] **Step 4: Add `--json` mode**

Find the `argv`/`CHECK`/`UPDATE`/`ONLY` block near the top:

```js
const argv = process.argv.slice(2);
const CHECK = argv.includes('--check');
const UPDATE = argv.includes('--update-baseline');
const ONLY = (argv.find(a => a.startsWith('--language=')) || '').split('=')[1] || null;
```

Add a sibling flag right after it:

```js
const JSON_OUT = argv.includes('--json');
```

Now find the whole block from `console.log('\nPer-layer recall over the CVE-replay corpus...')` down through the `if (blind.length) { ... }` block and the new deep-tier block from Step 3 — all of it is human-readable output that must be SKIPPED in `--json` mode (so stdout carries only the JSON payload, matching `bench/cve-replay/runner.mjs`'s convention of keeping JSON output free of banner/table noise). Wrap that entire section:

```js
if (!JSON_OUT) {
  console.log('\nPer-layer recall over the CVE-replay corpus (deep mode forced on for every entry)\n');
  // ... (all the existing table-printing code, and the new Step-3 block, unchanged) ...
}
```

Then, immediately after that `if (!JSON_OUT) { ... }` block closes (and before the `const summary = {` / `const allSummary =` lines from Step 2 — reorder so the summary objects are built BEFORE the `if (!JSON_OUT)` block, since the deep-tier table in Step 3 needs `deepSummary`/`deepRows` to already exist). To keep this ordering clean, the final structure of this section of the file should read, in order:

```js
const allSummary = summarize(rows);
const deepRows = rows.filter(r => r.tier === 'deep');
const deepSummary = summarize(deepRows);

if (!JSON_OUT) {
  console.log('\nPer-layer recall over the CVE-replay corpus (deep mode forced on for every entry)\n');
  // ... existing full-corpus table code (unchanged) ...
  // ... existing blind-languages warning (unchanged) ...
  console.log('\nTaint-shaped subset only (deep/ tier — provably invisible without deep mode)\n');
  // ... Step 3's deep-tier table code ...
}

const summary = {
  generatedAt: new Date().toISOString().slice(0, 10),
  ...allSummary,
  deepTier: deepSummary,
};

if (JSON_OUT) {
  console.log(JSON.stringify(summary, null, 2));
}
```

Move the `matrix`/`langs` computation (`const matrix = buildMatrix(rows); const langs = Object.keys(matrix).sort();`) so it stays BEFORE the `if (!JSON_OUT)` block too, since the full-corpus table inside that block still needs `matrix`/`langs` — they were already computed earlier in the file (right after `const rows = [];` loop finishes), so no change needed there; just confirm the ordering: `matrix`/`langs` computed → `allSummary`/`deepRows`/`deepSummary` computed → `if (!JSON_OUT) { tables }` → `summary` object built → `if (JSON_OUT) { print }` → the existing `if (UPDATE) { ... }` / `if (CHECK) { ... }` blocks (unchanged in position, they already come after `summary` is built).

- [ ] **Step 5: Extend `--check` to also compare the deep-tier breakdown**

Find the existing `if (CHECK) { ... }` block:

```js
if (CHECK) {
  if (!fs.existsSync(BASELINE)) {
    console.error('\n✖ no baseline — run with --update-baseline first');
    process.exit(1);
  }
  const base = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
  const regressions = [];
  for (const [lang, was] of Object.entries(base.taintByLanguage || {})) {
    const now = summary.taintByLanguage[lang] ?? 0;
    if (now < was) regressions.push(`${lang}: taint recall ${was} → ${now}`);
  }
  if (regressions.length) {
    console.error(`\n✖ taint-layer recall regressed:\n   ${regressions.join('\n   ')}`);
    process.exit(1);
  }
  console.log('\n✓ no taint-layer recall regression');
}
```

Replace the body between `const base = ...` and the final `console.log` with:

```js
  const base = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
  const regressions = [];
  for (const [lang, was] of Object.entries(base.taintByLanguage || {})) {
    const now = summary.taintByLanguage[lang] ?? 0;
    if (now < was) regressions.push(`${lang}: taint recall ${was} → ${now}`);
  }
  const baseDeep = (base.deepTier && base.deepTier.taintByLanguage) || {};
  for (const [lang, was] of Object.entries(baseDeep)) {
    const now = (deepSummary.taintByLanguage && deepSummary.taintByLanguage[lang]) ?? 0;
    if (now < was) regressions.push(`${lang} (deep-tier taint-shaped subset): taint recall ${was} → ${now}`);
  }
  if (regressions.length) {
    console.error(`\n✖ taint-layer recall regressed:\n   ${regressions.join('\n   ')}`);
    process.exit(1);
  }
  console.log('\n✓ no taint-layer recall regression (whole corpus or deep-tier subset)');
```

(The `if (!fs.existsSync(BASELINE))` guard above it, and the `if (CHECK) {` wrapper itself, stay unchanged.)

- [ ] **Step 6: Run against the real corpus and inspect the output manually**

```bash
cd /Users/ross/code/agentic-security
node bench/layer-recall/runner.mjs
```
Expected: the existing full-corpus table prints exactly as before, followed by a new "Taint-shaped subset only (deep/ tier...)" table showing 4 rows (cpp, javascript, php, python — the 4 languages the existing 6 `deep/` entries cover) plus a "languages with NO deep-tier entry yet" line naming the other languages (c#, go, java, kotlin, ruby, and any IaC/other buckets `layer-recall` tracks).

- [ ] **Step 7: Run in `--json` mode and confirm valid, well-shaped JSON**

```bash
cd /Users/ross/code/agentic-security
node bench/layer-recall/runner.mjs --json | node -e "
const s = JSON.parse(require('fs').readFileSync(0, 'utf8'));
console.log('has all:', !!s.all, 'has deepTier:', !!s.deepTier);
console.log('deepTier.entriesScored:', s.deepTier.entriesScored);
console.log('deepTier.taintByLanguage:', JSON.stringify(s.deepTier.taintByLanguage));
"
```
Expected: `has all: true has deepTier: true`, `deepTier.entriesScored: 6` (the current count of `deep/`-tier entries), and `deepTier.taintByLanguage` showing nonzero counts for `javascript`/`python`/`php`/`cpp` (exact language-label spelling as emitted by `languageOf()` — verify it matches what `layersOf`/`buildMatrix` already produced in Step 6's table, since `--json` must describe the same rows the human-readable path does).

If `has all` prints `false`, the issue is almost certainly that `summary` was built with `...allSummary` spread but `allSummary` itself doesn't carry an `all` key — re-read Step 2: `summary` should have `entriesScored`/`taintByLanguage`/`totalByLanguage` spread flat at the top level (matching the ORIGINAL schema, unchanged), not nested under an `all` key. **Correct this now if the check above shows `has all: false`** — the JSON payload's top level is `{ generatedAt, entriesScored, taintByLanguage, totalByLanguage, deepTier }`, not `{ all: {...}, deepTier: {...} }`. Re-run this step's verification command adjusted accordingly:
```bash
node bench/layer-recall/runner.mjs --json | node -e "
const s = JSON.parse(require('fs').readFileSync(0, 'utf8'));
console.log('entriesScored:', s.entriesScored, 'deepTier.entriesScored:', s.deepTier.entriesScored);
"
```
Expected: `entriesScored: 214 deepTier.entriesScored: 6` (or whatever the corpus total currently is — confirm against `bench/cve-replay/corpus-baseline.json`'s entry count if the number looks unexpected).

- [ ] **Step 8: Prove the check gate fails in the broken direction**

Temporarily edit `bench/layer-recall/baseline.json` (do NOT commit this edit) to inflate one deep-tier language's expected count above reality:

```bash
cd /Users/ross/code/agentic-security
node -e "
const fs = require('fs');
const p = 'bench/layer-recall/baseline.json';
const b = JSON.parse(fs.readFileSync(p, 'utf8'));
b.deepTier = b.deepTier || { taintByLanguage: {}, totalByLanguage: {}, entriesScored: 0 };
b.deepTier.taintByLanguage.python = 99;
fs.writeFileSync(p, JSON.stringify(b, null, 2) + '\n');
"
node bench/layer-recall/runner.mjs --check; echo "exit=$?"
```
Expected: exit 1, with a line like `python (deep-tier taint-shaped subset): taint recall 99 → 1` (or whatever python's real deep-tier count is).

Then restore the file (it will be properly regenerated in Task 7 anyway, but restore now so Task 3's commit doesn't carry a corrupted baseline):
```bash
cd /Users/ross/code/agentic-security
git checkout -- bench/layer-recall/baseline.json
```

- [ ] **Step 9: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/layer-recall/runner.mjs
git commit -m "feat(bench): layer-recall runner reports a deep-tier-only taint breakout

The full-corpus taint recall table is diluted by the ~204 entries that
don't need taint at all (docs/METRICS.md already documents this). Adds a
second breakout scoped to the deep/ tier — entries already required to be
provably invisible without deep mode — plus a --json mode for the
scorecard driver to consume, and extends --check to gate on deep-tier
regressions too. baseline.json's existing top-level keys are unchanged;
deepTier is additive. Proven both directions: passes clean, fails on a
deliberately inflated baseline value (reverted before commit)."
```

---

### Task 4: Add a taint-recall section to `accuracy-scorecard.js`, TDD

**Files:**
- Modify: `scanner/src/posture/accuracy-scorecard.js`
- Test: `scanner/test/accuracy-scorecard.test.js`

**Interfaces:**
- Consumes: `layerRecall` — a new key on `buildScorecard`'s `inputs` argument, shaped exactly like Task 3's `--json` output: `{ generatedAt, entriesScored, taintByLanguage, totalByLanguage, deepTier: { entriesScored, taintByLanguage, totalByLanguage } }`.
- Produces: `buildScorecard(inputs)`'s returned model gains a `taintRecall` key:
  ```js
  {
    measuredThisRun: true,
    wholeCorpus: { entriesScored, byLanguage: [{ language, taint: {n, d} }, ...] },   // diagnostic, diluted
    deepTierOnly: { entriesScored, byLanguage: [{ language, taint: {n, d} }, ...] },  // headline, taint-shaped
  }
  ```
  `byLanguage` arrays are sorted by `language` ascending (matching every other `byX` array in this file, e.g. `corpus.byLanguage`) so the rendered document is stable run-to-run. `renderScorecardMarkdown(m)` gains a new `## Taint-layer recall by language` section using `m.taintRecall`.

- [ ] **Step 1: Write the failing tests**

Add to `scanner/test/accuracy-scorecard.test.js`, after the existing `FIXTURE_DETAIL` block and its surrounding tests (find a natural insertion point — after the last `test(...)` call in the file; check the file's ending with `tail -30 scanner/test/accuracy-scorecard.test.js` first to see the exact tail to append after):

```js
// ── Taint-recall section (hand-computable fixture) ─────────────────────────
//
//   whole corpus:  ruby  1 taint / 4 total   |  go  0 taint / 2 total
//   deep-tier:     ruby  1 taint / 1 total   |  go  0 taint / 0 total (no entry)
const FIXTURE_LAYER_RECALL = {
  generatedAt: '2026-01-01',
  entriesScored: 6,
  taintByLanguage: { ruby: 1 },
  totalByLanguage: { ruby: 4, go: 2 },
  deepTier: {
    entriesScored: 1,
    taintByLanguage: { ruby: 1 },
    totalByLanguage: { ruby: 1 },
  },
};

test('buildScorecard: taintRecall.wholeCorpus reports {n,d} per language, sorted', () => {
  const model = buildScorecard({ ...fixtureInputs(), layerRecall: FIXTURE_LAYER_RECALL });
  assert.equal(model.taintRecall.measuredThisRun, true);
  assert.deepEqual(model.taintRecall.wholeCorpus.byLanguage, [
    { language: 'go', taint: { n: 0, d: 2 } },
    { language: 'ruby', taint: { n: 1, d: 4 } },
  ]);
});

test('buildScorecard: taintRecall.deepTierOnly reports the same shape over the deep-tier subset', () => {
  const model = buildScorecard({ ...fixtureInputs(), layerRecall: FIXTURE_LAYER_RECALL });
  assert.deepEqual(model.taintRecall.deepTierOnly.byLanguage, [
    { language: 'ruby', taint: { n: 1, d: 1 } },
  ]);
  // go has no deep-tier entry at all — it must be ABSENT from deepTierOnly,
  // not present with d:0, which would misreport "measured zero" as "not measured".
  assert.equal(model.taintRecall.deepTierOnly.byLanguage.some(r => r.language === 'go'), false);
});

test('buildScorecard: missing layerRecall input degrades to an empty, well-shaped section', () => {
  // A scorecard run must never crash because one optional input was omitted —
  // matches every other section's degrade-gracefully convention in this file.
  const model = buildScorecard(fixtureInputs());
  assert.equal(model.taintRecall.measuredThisRun, false);
  assert.deepEqual(model.taintRecall.wholeCorpus.byLanguage, []);
  assert.deepEqual(model.taintRecall.deepTierOnly.byLanguage, []);
});

test('renderScorecardMarkdown: taint section renders every rate through formatRate (n/d visible)', () => {
  const model = buildScorecard({ ...fixtureInputs(), layerRecall: FIXTURE_LAYER_RECALL });
  const md = renderScorecardMarkdown(model);
  assert.match(md, /## Taint-layer recall by language/);
  // Whole-corpus ruby row: 1/4.
  assert.match(md, /ruby[^\n]*1\/4/);
  // Deep-tier ruby row: 1/1.
  assert.match(md, /ruby[^\n]*1\/1/);
  // Never a bare percentage with no denominator anywhere in this section.
  const section = md.split('## Taint-layer recall by language')[1].split('\n## ')[0];
  assert.doesNotMatch(section, /\b\d+%(?!\s*\()/, 'a percentage must always be paired with its (n/d)');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/ross/code/agentic-security/scanner
node --test test/accuracy-scorecard.test.js
```
Expected: FAIL — `model.taintRecall` is `undefined` (`TypeError: Cannot read properties of undefined`).

- [ ] **Step 3: Implement in `accuracy-scorecard.js`**

Add a new pure helper function right after `sliceBy` (before `aggregateCorpus`):

```js
/**
 * Build the { byLanguage: [{language, taint:{n,d}}] } shape for one
 * taintByLanguage/totalByLanguage pair. Sorted by language so the rendered
 * document is stable run-to-run, matching every other byX array here.
 *
 * A language present in `total` but absent from `taint` reports n:0 — a real
 * measured zero. A language absent from BOTH is simply not included in the
 * output at all, so "measured zero" and "not measured on this subset" never
 * collapse into the same row (see the deepTierOnly caller below).
 */
function taintRateByLanguage(taintByLanguage, totalByLanguage) {
  const langs = Object.keys(totalByLanguage || {}).sort();
  return langs.map(language => ({
    language,
    taint: { n: (taintByLanguage || {})[language] || 0, d: totalByLanguage[language] },
  }));
}
```

Now add the `taintRecall` key to the object `buildScorecard` returns. Find the `return { ... }` statement (the one starting `schema: 'agentic-security/accuracy-scorecard@1',`). Add a new key right after the `selfScan:` line:

```js
    selfScan: { measuredThisRun: true, targets, polyglot: selfScan.polyglot || { total: 0, byLanguage: {} } },
    taintRecall: (() => {
      const lr = inputs.layerRecall;
      if (!lr) {
        return { measuredThisRun: false, wholeCorpus: { entriesScored: 0, byLanguage: [] }, deepTierOnly: { entriesScored: 0, byLanguage: [] } };
      }
      const deep = lr.deepTier || { entriesScored: 0, taintByLanguage: {}, totalByLanguage: {} };
      return {
        measuredThisRun: true,
        wholeCorpus: {
          entriesScored: lr.entriesScored || 0,
          byLanguage: taintRateByLanguage(lr.taintByLanguage, lr.totalByLanguage),
        },
        deepTierOnly: {
          entriesScored: deep.entriesScored || 0,
          byLanguage: taintRateByLanguage(deep.taintByLanguage, deep.totalByLanguage),
        },
      };
    })(),
```

- [ ] **Step 4: Run the tests to verify the model-building tests now pass (rendering test still fails)**

```bash
cd /Users/ross/code/agentic-security/scanner
node --test test/accuracy-scorecard.test.js
```
Expected: the three `buildScorecard: taintRecall...` tests pass; `renderScorecardMarkdown: taint section renders...` still fails (no such section yet).

- [ ] **Step 5: Implement the markdown section**

In `renderScorecardMarkdown(m)`, find the line `L.push('## Precision-side signal: self-scan (measured this run)');` — insert the new section immediately BEFORE it (so taint-recall sits between the corpus-tier tables and the self-scan section):

```js
  L.push('## Taint-layer recall by language');
  L.push('');
  L.push('Two views of the same layer-recall instrument, because reporting only the');
  L.push('first would silently overstate taint capability and reporting only the');
  L.push('second would understate coverage of what the corpus actually contains:');
  L.push('');
  L.push('- **Whole corpus** — diagnostic only. ~96% of this corpus is caught by the');
  L.push('  pattern/structural layers without needing taint at all, so a language\'s');
  L.push('  rate here is diluted by every entry that never exercised the taint');
  L.push('  engine. A language reading near-zero here is not necessarily a taint');
  L.push('  defect — see `docs/METRICS.md`.');
  L.push('- **Deep-tier only (the taint-shaped subset)** — the number to quote for');
  L.push('  taint capability. Every entry in this bucket is required, before it can');
  L.push('  be committed, to be provably invisible with the deep engine off and');
  L.push('  detected with it on (`bench/cve-replay/CONTRIBUTING.md`, "deep/" tier).');
  L.push('  A language absent from this table has no deep-tier entry yet — that is');
  L.push('  "not yet measured", never "zero capability".');
  L.push('');
  L.push('**No taint-specific precision percentage is reported here, deliberately —');
  L.push('same reasoning as the corpus-wide F1 omission above.** A precision figure');
  L.push('needs a labelled population containing both true and false positives; this');
  L.push('section\'s denominator is all-vulnerable by construction (`pre/` fixtures),');
  L.push('so it cannot supply one. The false-positive side is instrumented instead as');
  L.push('a gate, not a rate: `bench/self-scan/fixtures/polyglot/` carries one');
  L.push('untainted, negative-control fixture per language (nine languages), and');
  L.push('`bench:self-scan:check`\'s existing exact per-file drift gate fails the');
  L.push('build the moment any of them stops reading zero. See the self-scan section');
  L.push('below for current counts.');
  L.push('');
  L.push('### Whole corpus (diagnostic)');
  L.push('');
  L.push(`Entries scored: ${m.taintRecall.wholeCorpus.entriesScored}`);
  L.push('');
  L.push('| Language | IR-TAINT recall |');
  L.push('| --- | --- |');
  for (const r of m.taintRecall.wholeCorpus.byLanguage) {
    L.push(`| ${r.language} | ${formatRate(r.taint.n, r.taint.d)} |`);
  }
  L.push('');
  L.push('### Deep-tier only — taint-shaped subset (headline)');
  L.push('');
  L.push(`Entries scored: ${m.taintRecall.deepTierOnly.entriesScored}`);
  L.push('');
  if (m.taintRecall.deepTierOnly.byLanguage.length) {
    L.push('| Language | IR-TAINT recall |');
    L.push('| --- | --- |');
    for (const r of m.taintRecall.deepTierOnly.byLanguage) {
      L.push(`| ${r.language} | ${formatRate(r.taint.n, r.taint.d)} |`);
    }
  } else {
    L.push('No deep-tier entries scored this run.');
  }
  L.push('');
```

- [ ] **Step 6: Run the tests to verify they all pass**

```bash
cd /Users/ross/code/agentic-security/scanner
node --test test/accuracy-scorecard.test.js
```
Expected: all tests pass (the 4 new ones plus every pre-existing one in the file).

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/accuracy-scorecard.js scanner/test/accuracy-scorecard.test.js
git commit -m "feat(scorecard): add taint-layer recall section (whole-corpus + deep-tier)

buildScorecard() gains a taintRecall model built from an optional
layerRecall input (bench/layer-recall/runner.mjs --json shape); missing
input degrades to an empty, well-shaped section rather than crashing.
Reports two views explicitly: whole-corpus (diagnostic, diluted by the
~204 entries that don't need taint) and deep-tier-only (the taint-shaped
subset — the number to quote). Every rate goes through formatRate(), no
bare percentages. TDD, hand-computed fixture."
```

---

### Task 5: Wire `scripts/scorecard.mjs` to run layer-recall and pass it through

**Files:**
- Modify: `scripts/scorecard.mjs`

**Interfaces:**
- Consumes: Task 3's `bench/layer-recall/runner.mjs --json`, Task 4's `buildScorecard({ ..., layerRecall })`.
- Produces: nothing new downstream — this is the final wiring step that makes `docs/SCORECARD.md`/`docs/scorecard.json` actually carry the taint section on a real `npm run scorecard` run.

- [ ] **Step 1: Add the layer-recall run**

In `scripts/scorecard.mjs`, find:

```js
  process.stderr.write('· running the self-scan precision harness…\n');
  const selfScan = runJson('bench/self-scan/measure.mjs', ['--json'], 'self-scan');
```

Insert a new run right after it:

```js
  process.stderr.write('· running the per-language taint layer-recall breakout…\n');
  const layerRecall = runJson('bench/layer-recall/runner.mjs', ['--json'], 'layer-recall');
```

- [ ] **Step 2: Pass it into `buildScorecard`**

Find the `buildScorecard({ ... })` call. Add `layerRecall,` as a new top-level key (alongside `corpusDetail`, `selfScan`, `committed`):

```js
  const model = buildScorecard({
    provenance: { ... },
    corpusDetail: corpus.detail || [],
    selfScan,
    layerRecall,
    committed: { ... },
  });
```

(Leave `provenance`/`committed`'s existing contents exactly as they are — only add the `layerRecall,` line.)

- [ ] **Step 3: Run the full scorecard generator and inspect the output**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run scorecard
```
Expected: succeeds, prints the existing summary lines, and `docs/SCORECARD.md` now contains a `## Taint-layer recall by language` section between the corpus-tier tables and the self-scan section.

```bash
cd /Users/ross/code/agentic-security
grep -A5 "## Taint-layer recall by language" docs/SCORECARD.md
```
Expected: the section header followed by the explanatory prose from Task 4 Step 5.

- [ ] **Step 4: Verify determinism — run twice, diff (excluding the timestamp line)**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run scorecard
cp ../docs/SCORECARD.md /tmp/scorecard-run1.md
npm run scorecard
diff <(grep -v 'Generated (UTC)' /tmp/scorecard-run1.md) <(grep -v 'Generated (UTC)' ../docs/SCORECARD.md)
```
Expected: no output (files identical apart from the timestamp line, which was excluded from both sides).

- [ ] **Step 5: Commit** (do NOT commit the regenerated `docs/SCORECARD.md`/`docs/scorecard.json` yet — that happens in Task 7, after `bench/layer-recall/baseline.json` is also regenerated, so both land together and describe the same measurement run)

```bash
cd /Users/ross/code/agentic-security
git add scripts/scorecard.mjs
git commit -m "feat(scorecard): wire layer-recall --json into the scorecard driver

npm run scorecard now runs bench/layer-recall/runner.mjs --json alongside
the corpus and self-scan runs, and passes the result into buildScorecard
as layerRecall. docs/SCORECARD.md / docs/scorecard.json regeneration is
deferred to the task that also refreshes bench/layer-recall/baseline.json,
so both describe the same run."
```

---

### Task 6: Update `docs/METRICS.md` to document the deep-tier-only breakout

**Files:**
- Modify: `docs/METRICS.md`

**Interfaces:** None — documentation only.

- [ ] **Step 1: Read the current "Per-layer recall (D1)" section**

```bash
cd /Users/ross/code/agentic-security
sed -n '/## Per-layer recall/,/^## /p' docs/METRICS.md | head -60
```

- [ ] **Step 2: Add a paragraph documenting the new breakout, right after the existing command block**

Find this text in `docs/METRICS.md`:

```markdown
```bash
cd scanner && npm run bench:layer-recall          # print the matrix
cd scanner && npm run bench:layer-recall:check    # gate against baseline.json
```

Deep mode is **forced on for every entry**, unlike the corpus gate, which
enables it only for the 6 `deep`-tier entries. Measuring under the corpus's own
```

Insert a new paragraph immediately after that command block and before the "Deep mode is **forced on**..." sentence:

```markdown
```bash
cd scanner && npm run bench:layer-recall          # print the matrix
cd scanner && npm run bench:layer-recall:check    # gate against baseline.json
```

**As of the docs-overhaul-era measurement work, the printed matrix and
`docs/SCORECARD.md`'s "Taint-layer recall by language" section both report
two views, not one.** The whole-corpus view below is diluted: ~96% of this
corpus is caught by the pattern/structural layers without needing taint,
so a near-zero rate for a language here does not by itself mean the taint
engine cannot see that language. The **deep-tier-only** breakout — printed
as a second table by the same command, and as its own section in the
scorecard — is scoped to entries that are *required*, before they can be
committed, to be provably invisible with the deep engine off and detected
with it on. That is the number to quote for taint capability; the
whole-corpus number below is diagnostic context, not the claim.

Deep mode is **forced on for every entry**, unlike the corpus gate, which
enables it only for the 6 `deep`-tier entries. Measuring under the corpus's own
```

- [ ] **Step 3: Verify the doc-links gate still passes**

```bash
cd /Users/ross/code/agentic-security
node scripts/check-doc-drift.mjs --gate
```
Expected: `doc-links: all user-facing markdown links resolve.` (exit 0).

- [ ] **Step 4: Commit**

```bash
cd /Users/ross/code/agentic-security
git add docs/METRICS.md
git commit -m "docs: document the deep-tier-only taint recall breakout in METRICS.md

Points readers at the new second table (bench:layer-recall) and scorecard
section, and states plainly which number is diagnostic (whole-corpus,
diluted) vs. which is the headline (deep-tier, taint-shaped)."
```

---

### Task 7: Regenerate `bench/layer-recall/baseline.json` and the scorecard together

**Files:**
- Modify: `bench/layer-recall/baseline.json`
- Modify: `docs/SCORECARD.md`, `docs/scorecard.json`

**Interfaces:** None new — this task runs the two regeneration commands wired up in Tasks 3 and 5, and commits their real output together so both describe the same measurement.

- [ ] **Step 1: Wipe stale scan state before measuring (standing project rule)**

```bash
cd /Users/ross/code/agentic-security
find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} +
```

- [ ] **Step 2: Regenerate the layer-recall baseline**

```bash
cd /Users/ross/code/agentic-security
node bench/layer-recall/runner.mjs --update-baseline
cat bench/layer-recall/baseline.json
```
Expected: valid JSON with `entriesScored`, `taintByLanguage`, `totalByLanguage`, and a `deepTier: { entriesScored, taintByLanguage, totalByLanguage }` key showing the 4 currently-covered languages (cpp, javascript, php, python).

- [ ] **Step 3: Confirm the check gate passes clean against the freshly written baseline**

```bash
cd /Users/ross/code/agentic-security
node bench/layer-recall/runner.mjs --check; echo "exit=$?"
```
Expected: exit 0, `✓ no taint-layer recall regression (whole corpus or deep-tier subset)`.

- [ ] **Step 4: Regenerate the scorecard**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run scorecard
```
Expected: succeeds; stderr shows the three run lines (corpus, self-scan, layer-recall) plus the existing summary.

- [ ] **Step 5: Run the full dataflow + posture test scopes to catch any regression this touched**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run test:dataflow
npm run test:posture
```
Expected: both green. (`test:dataflow` includes `test/layer-recall.test.js`; `test:posture` includes `test/accuracy-scorecard.test.js` and `test/scorecard-gate.test.js` — if `scorecard-gate.test.js` asserts anything about the exact set of keys `buildScorecard` returns, re-read its failure output carefully and extend it the same way Task 4 extended `accuracy-scorecard.test.js`, rather than weakening the assertion.)

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/layer-recall/baseline.json docs/SCORECARD.md docs/scorecard.json
git commit -m "chore(bench): regenerate layer-recall baseline + scorecard with the new taint breakout

Both describe the same measurement run. deepTier now covers cpp,
javascript, php, python (the 4 languages with an existing deep/-tier
entry) — java, c#, kotlin, ruby, go show 'no deep-tier entry yet' rather
than a misleading zero. Closing that gap is P1's job, not P0's."
```

---

### Task 8: Add `bench/self-scan/fixtures/polyglot/App.java` (Theme 6 — taint FP negative control)

**Files:**
- Create: `bench/self-scan/fixtures/polyglot/App.java`

**Interfaces:** None — a scanned fixture file, no code imports it.

- [ ] **Step 1: Write the fixture**

Create `bench/self-scan/fixtures/polyglot/App.java`:

```java
import java.sql.Statement;

public class App {
    public String identity(String payload) {
        return payload;
    }

    public void emit(Statement stmt) throws Exception {
        String query = identity("SELECT 1");
        stmt.executeUpdate(query);
    }
}
```

This mirrors the shape already established by `App.cs`/`App.kt`/`app.php` in this same directory: a two-method identity→emit chain where the value passed to the sink is a single variable (never a literal, never a string-concat expression), so ONLY an interprocedural taint walker that correctly resolves `query` back through `identity()` to an untainted local literal can produce the correct "no finding" verdict — a taint walker that conservatively taints anything reaching a sink through any call is exactly the false positive this fixture exists to catch.

- [ ] **Step 2: Live-fire verify the sink is genuinely catalog-matched (per this directory's own documented verification method)**

Confirm `stmt.executeUpdate(...)` is a real catalog sink for Java before trusting the negative result:

```bash
cd /Users/ross/code/agentic-security
grep -A2 "id: 'java-stmt-executeUpdate'" scanner/src/dataflow/catalog.js
```
Expected: shows `match: { type: 'call', callee: 'executeUpdate' }` with no `receiver`/`receiverBase` constraint — confirming a bare `stmt.executeUpdate(query)` call matches by callee name alone.

Now temporarily swap the identity-sourced literal for a real cataloged Java source, to prove the sink fires when the value IS genuinely tainted (so a "0 findings" result later is trusted as "correctly resolved as safe", not "the sink never fires at all"):

```bash
cd /Users/ross/code/agentic-security
cp bench/self-scan/fixtures/polyglot/App.java /tmp/App.java.orig
python3 -c "
content = open('bench/self-scan/fixtures/polyglot/App.java').read()
content = content.replace(
    'public void emit(Statement stmt) throws Exception {\n        String query = identity(\"SELECT 1\");',
    'public void emit(Statement stmt, javax.servlet.http.HttpServletRequest req) throws Exception {\n        String query = req.getParameter(\"q\");'
)
open('bench/self-scan/fixtures/polyglot/App.java', 'w').write(content)
"
cat bench/self-scan/fixtures/polyglot/App.java
AGENTIC_SECURITY_DEEP=1 AGENTIC_SECURITY_DEEP_IN_CI=1 node -e "
const { runScan } = require('./scanner/src/runScan.js');
runScan('bench/self-scan/fixtures/polyglot').then(({ scan }) => {
  const hits = (scan.findings || []).filter(f => f.file && f.file.endsWith('App.java'));
  console.log('findings on App.java with a real tainted source:', hits.length);
  for (const h of hits) console.log(' -', h.vuln, h.parser);
});
"
```
Expected: at least 1 finding, ideally with `parser: 'IR-TAINT'` and `vuln` mentioning SQL Injection — proving the sink genuinely fires when the value is tainted.

Restore the real (untainted) fixture:
```bash
cd /Users/ross/code/agentic-security
cp /tmp/App.java.orig bench/self-scan/fixtures/polyglot/App.java
rm /tmp/App.java.orig
diff <(cat bench/self-scan/fixtures/polyglot/App.java) - <<'EOF'
import java.sql.Statement;

public class App {
    public String identity(String payload) {
        return payload;
    }

    public void emit(Statement stmt) throws Exception {
        String query = identity("SELECT 1");
        stmt.executeUpdate(query);
    }
}
EOF
echo "diff exit=$?"
```
Expected: `diff exit=0` (file restored exactly).

If Step 2's tainted-swap produced ZERO findings (meaning the sink doesn't actually fire even when tainted — Java taint may not resolve `req.getParameter` the way this quick edit assumes), STOP and use `scanner/test/java-taint-flow.test.js`'s own proven template instead of guessing further — that file already contains a verified-working Java taint fixture; adapt ITS exact source/sink pair into the `emit()` method here rather than inventing a new one.

- [ ] **Step 3: Confirm the real (untainted) fixture produces zero findings**

```bash
cd /Users/ross/code/agentic-security
AGENTIC_SECURITY_DEEP=1 AGENTIC_SECURITY_DEEP_IN_CI=1 node -e "
const { runScan } = require('./scanner/src/runScan.js');
runScan('bench/self-scan/fixtures/polyglot').then(({ scan }) => {
  const hits = (scan.findings || []).filter(f => f.file && f.file.endsWith('App.java'));
  console.log('findings on App.java (untainted):', hits.length);
  for (const h of hits) console.log(' -', h.vuln, h.parser, h.line);
});
"
```
Expected: `findings on App.java (untainted): 0`. If nonzero, this is a REAL taint imprecision the engine has right now (the untainted local literal is being conservatively treated as tainted) — this is valuable P1 input, not something to work around by picking a different fixture. Record the exact finding(s) in the Task 10 commit message rather than silently changing the fixture to dodge it.

- [ ] **Step 4: Clean up any scan state the manual runs left behind**

```bash
cd /Users/ross/code/agentic-security
rm -rf bench/self-scan/fixtures/polyglot/.agentic-security
git status --short bench/self-scan/fixtures/polyglot/
```
Expected: only `App.java` shown as untracked/new — no `.agentic-security` directory.

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/self-scan/fixtures/polyglot/App.java
git commit -m "test(bench): add Java negative-control fixture to the polyglot precision set

Two-method identity->emit chain into Statement.executeUpdate, matching the
shape App.cs/App.kt/app.php already use. measure.mjs's own header
documented 'no fixture at all for Java (Task 7)' as an open gap in the
interprocedural FP negative-control coverage — this closes it. Verified
both directions: fires when the value is genuinely tainted (temporary
swap, reverted), silent when it is the real untainted-literal fixture."
```

---

### Task 9: Upgrade `app.js`, `app.py`, `app.rb` to two-function interprocedural fixtures

**Files:**
- Modify: `bench/self-scan/fixtures/polyglot/app.js`
- Modify: `bench/self-scan/fixtures/polyglot/app.py`
- Modify: `bench/self-scan/fixtures/polyglot/app.rb`

**Interfaces:** None — scanned fixture files.

- [ ] **Step 1: Rewrite `app.js`**

Current content (single-function, sink-only, no caller — cannot detect an interprocedural FP):
```js
function emit(payload) {
  process.stdout.write(payload);
}

module.exports = { emit };
```

Replace with the two-function identity→emit shape, matching this directory's own convention (`app.go`'s `identity`/`emit` naming):

```js
function identity(payload) {
  return payload;
}

function emit() {
  const cmd = identity('status: ok');
  require('child_process').exec(cmd);
}

module.exports = { identity, emit };
```

(`child_process.exec` is the JS catalog's canonical command-injection sink — used throughout `scanner/test/fixtures/vulnerable-js/app.js` and the corpus — so this is a proven-matched sink, not a guess.)

- [ ] **Step 2: Rewrite `app.py`**

Current content:
```python
import sys


def emit(payload):
    sys.stderr.write(payload)
    fh = open("/tmp/out.log", "w")
    fh.write(payload)
    fh.close()
```

Replace with:

```python
def identity(payload):
    return payload


def emit():
    path = identity("/tmp/out.log")
    fh = open(path, "w")
    fh.close()
```

(`open()` is confirmed cataloged: `scanner/src/dataflow/catalog.js` has `{ kind: 'sink', id: 'py-open', language: 'py', framework: 'stdlib', match: { type: 'call', callee: 'open' }, argIndex: 0, ... }`, bare callee-name match, no receiver constraint — the identity-resolved `path` variable is a single argument, no concatenation.)

- [ ] **Step 3: Rewrite `app.rb`**

Current content:
```ruby
def emit(payload)
  fh = File.open("/tmp/out.log", "w")
  fh.write(payload)
  fh.close
end
```

Replace with:

```ruby
def identity(payload)
  payload
end

def emit
  cmd = identity("status: ok")
  system(cmd)
end
```

(`system` is confirmed cataloged: `{ kind: 'sink', id: 'rb-system', language: 'rb', framework: 'stdlib', match: { type: 'call', callee: 'system' }, argIndex: 0, ... }` — this is also the exact sink family this codebase's own `bench/engine-recall/RESULTS.md` used as its canonical Ruby taint proof point (`params[:c]` → `system(c)`), so it's a doubly-proven choice.)

- [ ] **Step 4: Confirm all three produce zero findings (untainted)**

```bash
cd /Users/ross/code/agentic-security
AGENTIC_SECURITY_DEEP=1 AGENTIC_SECURITY_DEEP_IN_CI=1 node -e "
const { runScan } = require('./scanner/src/runScan.js');
runScan('bench/self-scan/fixtures/polyglot').then(({ scan }) => {
  const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
  for (const ext of ['app.js', 'app.py', 'app.rb']) {
    const hits = all.filter(f => f.file && f.file.endsWith(ext));
    console.log(ext + ':', hits.length, 'finding(s)');
    for (const h of hits) console.log('  -', h.vuln, h.parser, h.line);
  }
});
"
```
Expected: `app.js: 0 finding(s)`, `app.py: 0 finding(s)`, `app.rb: 0 finding(s)`. If any is nonzero, treat it as a real taint imprecision to document (same rule as Task 8 Step 3) rather than silently swapping the fixture to avoid it.

- [ ] **Step 5: Live-fire verify each sink actually fires when genuinely tainted (same discipline as Task 8)**

```bash
cd /Users/ross/code/agentic-security
mkdir -p /tmp/taint-verify
cat > /tmp/taint-verify/app.js <<'EOF'
function emit(req) {
  require('child_process').exec(req.query.cmd);
}
module.exports = { emit };
EOF
cat > /tmp/taint-verify/app.py <<'EOF'
from flask import request
def emit():
    path = request.args.get("path")
    fh = open(path, "w")
    fh.close()
EOF
cat > /tmp/taint-verify/app.rb <<'EOF'
def emit(params)
  cmd = params[:c]
  system(cmd)
end
EOF
AGENTIC_SECURITY_DEEP=1 AGENTIC_SECURITY_DEEP_IN_CI=1 node -e "
const { runScan } = require('./scanner/src/runScan.js');
runScan('/tmp/taint-verify').then(({ scan }) => {
  const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
  console.log('total findings on genuinely-tainted variants:', all.length);
  for (const h of all) console.log(' -', h.file, h.vuln, h.parser);
});
"
rm -rf /tmp/taint-verify
```
Expected: at least 1 finding for each of the three files (they don't need to all fire via `IR-TAINT` specifically — a structural/pattern-layer hit here still proves the sink is reachable and matched; the point is only to rule out "this sink never fires on this shape at all", which would make the app.js/app.py/app.rb zero-findings result meaningless). If any file produces zero findings even when genuinely tainted, its sink choice needs reconsidering before Step 4's zero-findings result can be trusted — do not proceed to commit on an unverified sink.

- [ ] **Step 6: Clean up scan state**

```bash
cd /Users/ross/code/agentic-security
rm -rf bench/self-scan/fixtures/polyglot/.agentic-security
```

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/self-scan/fixtures/polyglot/app.js bench/self-scan/fixtures/polyglot/app.py bench/self-scan/fixtures/polyglot/app.rb
git commit -m "test(bench): upgrade JS/Python/Ruby polyglot fixtures to interprocedural chains

measure.mjs's own header documented these three as single-function,
sink-only, unable to see an interprocedural FP change ('this bench still
cannot see an interprocedural change in JS/Python/Ruby'). Rewrites each to
the same identity->emit two-function shape go/cs/kt/php already use, on
proven-cataloged sinks (child_process.exec, py-open, rb-system — the last
matching this codebase's own canonical Ruby taint proof point). Verified
both directions per file: silent on the real untainted fixture, fires on
a genuinely-tainted variant (temp files, cleaned up)."
```

---

### Task 10: Close out the polyglot fixture coverage gap in `measure.mjs`'s header

**Files:**
- Modify: `bench/self-scan/measure.mjs`

**Interfaces:** None — comment-only change.

- [ ] **Step 1: Replace the stale coverage-gap paragraph**

Find this text in `bench/self-scan/measure.mjs` (the header comment, roughly lines 28–41):

```js
// Coverage note (Phase 2 / task 3, 2026-07-26): `hooks/` and `scripts/` are
// JS/Python only, so they cannot detect a precision change in any other
// language's interprocedural analysis. `fixtures/polyglot/` is the only part
// of this bench that can, and only for the languages it contains a genuine
// caller->callee chain for: each of `app.go`, `App.cs`, `App.kt`, `app.php`
// is a two-function `identity(x) -> emit()` chain where the callee returns
// its argument and the caller passes the result to a sink, with the value
// originating from a hardcoded local literal (not argv/env/network/request)
// — so the correct polyglot total is 0, and a nonzero result there is a real
// false positive on an interprocedural chain over untainted data, not noise
// to tune away. `app.js`/`app.py`/`app.rb` remain single-function, sink-only
// fixtures (no caller), so this bench still cannot see an interprocedural
// change in JS/Python/Ruby, and it has no fixture at all for Java (Task 7).
// Do not over-trust a 0 here as proof nothing moved outside what's listed.
```

Replace it with:

```js
// Coverage note (Phase 2 / task 3, 2026-07-26; closed 2026-08-15 — taint
// engine PRD P0). `hooks/` and `scripts/` are JS/Python only, so they cannot
// detect a precision change in any other language's interprocedural
// analysis. `fixtures/polyglot/` is the part of this bench that can, and now
// covers all nine first-class languages plus C/C++: `app.go`, `App.cs`,
// `App.kt`, `app.php`, `App.java`, `app.js`, `app.py`, `app.rb` are each a
// two-function `identity(x) -> emit()` chain where the callee returns its
// argument and the caller passes the result to a sink, with the value
// originating from a hardcoded local literal (not argv/env/network/request)
// — so the correct polyglot total is 0, and a nonzero result there is a real
// false positive on an interprocedural chain over untainted data, not noise
// to tune away. Every sink used here was live-fire verified against a
// genuinely-tainted variant before being trusted as a negative control (see
// the git history for `bench/self-scan/fixtures/polyglot/*` around the P0
// taint-engine-PRD commits) — this is what makes `bench:self-scan:check`'s
// existing exact-drift gate function as a real per-language taint
// false-positive budget: any future imprecision on any of these nine
// languages now fails the build, per file, immediately.
```

- [ ] **Step 2: Regenerate `BASELINE.json`**

```bash
cd /Users/ross/code/agentic-security/scanner
node ../bench/self-scan/check.mjs --update-baseline
```
Expected: prints `✓ baseline updated → ../bench/self-scan/BASELINE.json` followed by per-target totals, including `polyglot: 0` (confirming the whole 9-file set still nets to zero — if this prints anything other than 0, STOP: Task 8 or Task 9 left a real finding unaddressed and it must be resolved, not baselined over, per the standing project rule that a corpus/fixture gate must never silently absorb an unexplained finding).

- [ ] **Step 3: Confirm the check gate passes clean**

```bash
cd /Users/ross/code/agentic-security/scanner
node ../bench/self-scan/check.mjs; echo "exit=$?"
```
Expected: exit 0, `✓ no drift — per-file counts match BASELINE.json exactly`.

- [ ] **Step 4: Prove the gate fails in the broken direction**

Temporarily reintroduce a real finding to prove the negative-control set actually catches a regression:

```bash
cd /Users/ross/code/agentic-security
cp bench/self-scan/fixtures/polyglot/app.rb /tmp/app.rb.orig
python3 -c "
content = open('bench/self-scan/fixtures/polyglot/app.rb').read()
content = content.replace('def emit\n  cmd = identity(\"status: ok\")', 'def emit(params)\n  cmd = params[:c]')
open('bench/self-scan/fixtures/polyglot/app.rb', 'w').write(content)
"
cd scanner
node ../bench/self-scan/check.mjs; echo "exit=$?"
```
Expected: exit 1, with drift reported against `app.rb` (a new finding appeared where the baseline expected none).

Restore:
```bash
cd /Users/ross/code/agentic-security
cp /tmp/app.rb.orig bench/self-scan/fixtures/polyglot/app.rb
rm /tmp/app.rb.orig
cd scanner
node ../bench/self-scan/check.mjs; echo "exit=$?"
```
Expected: exit 0 again.

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/self-scan/measure.mjs bench/self-scan/BASELINE.json
git commit -m "docs(bench): close the polyglot fixture coverage gap in measure.mjs's header

Java/JS/Python/Ruby are no longer exceptions — the negative-control set
now covers all nine first-class languages. Regenerated BASELINE.json
(polyglot total still 0). Proven both directions: clean on the real
fixtures, fails when a genuine taint FP is reintroduced (temporary edit,
reverted)."
```

---

### Task 11: Full verification pass

**Files:** None modified — this task only runs gates and confirms green, per this project's verification discipline (root `CLAUDE.md`: "A green local gate is the price of pushing").

**Interfaces:** None.

- [ ] **Step 1: Run the full scoped test suites this plan touched**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run test:dataflow
npm run test:posture
npm run test:smoke
```
Expected: all green.

- [ ] **Step 2: Run the full CI-equivalent test gate**

```bash
cd /Users/ross/code/agentic-security/scanner
npm test
```
Expected: all 12 scoped sub-scripts green.

- [ ] **Step 3: Run every bench gate this plan touched, both report and check modes**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run bench:layer-recall
npm run bench:layer-recall:check
npm run bench:self-scan
npm run bench:self-scan:check
```
Expected: all green; `bench:layer-recall`'s printed output shows both the whole-corpus table and the new deep-tier-only table.

- [ ] **Step 4: Regenerate the scorecard one final time (in case any earlier step's manual runs left it stale) and verify determinism again**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run scorecard
git status --short ../docs/SCORECARD.md ../docs/scorecard.json
```
Expected: `npm run scorecard` succeeds; `git status` shows no changes (Task 7 already committed the correct, current output) — or, if it does show a diff, that diff must be ONLY the `Generated (UTC)` timestamp line. If it shows any other diff, something drifted between Task 7 and now; investigate before proceeding (do not commit a diff you don't understand).

- [ ] **Step 5: Rebuild the bundle** (per root `CLAUDE.md`: "After any change to `scanner/src/` or `scanner/bin/`, run `npm run build`")

```bash
cd /Users/ross/code/agentic-security/scanner
npm run build
git status --short dist/
```
Expected: `dist/agentic-security.mjs` and its `.sha256` sidecar show as modified (this plan touched `scanner/src/posture/accuracy-scorecard.js`, which the bundle re-exports).

- [ ] **Step 6: Commit the rebuilt bundle**

```bash
cd /Users/ross/code/agentic-security
git add scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "chore: rebuild bundle after taint-engine P0 accuracy-scorecard changes"
```

- [ ] **Step 7: Run the pre-push gate itself, not just its component pieces**

```bash
cd /Users/ross/code/agentic-security
node scripts/pre-push-gate.mjs
```
(If this script expects stdin describing the refs being pushed, follow whatever this repo's `.githooks/pre-push` shim does to invoke it — check `cat .githooks/pre-push` first if the bare invocation errors on missing input.)

Expected: `pre-push gate PASSED` with all listed checks green: worktree-matches-push, push-blast-radius, bundle-integrity, package-contents, test-suite, corpus-gate, self-scan-gate, mutation-gate, layer-recall-gate.

- [ ] **Step 8: Report the final state**

Print a short summary for the human reviewer:

```bash
cd /Users/ross/code/agentic-security
git log --oneline -12
echo "---"
node bench/layer-recall/runner.mjs 2>&1 | sed -n '/Taint-shaped subset only/,/^$/p'
```

This closes P0. Every later phase of `docs/TAINT_ENGINE_IMPROVEMENT_PRD.md` (P1: laggard IR parity for java/c#/kotlin/ruby) now has a taint-shaped recall baseline to move and a completed FP negative control to protect while doing it.
