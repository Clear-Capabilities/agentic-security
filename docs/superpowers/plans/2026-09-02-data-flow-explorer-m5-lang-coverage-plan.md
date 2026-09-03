# M5 Language Coverage-Tier Disclosure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Data Flow Explorer an honest, per-language coverage-tier disclosure — a real, curated tier (`full`/`partial`/`pattern-only`/`unknown`) plus the current `docs/METRICS.md` recall figure, attached to the already-real, already-populated per-repo `graph.coverage.languages[]` file-count data, and exported as a new `dataflow export --format coverage` Markdown report.

**Architecture:** One new static, zero-dependency curated-data module (`language-coverage-tiers.js`) is consulted by an additive change to `coverage.js`'s existing `buildCoverageLedger`, which already computes real per-language file counts from `opts.perFile`. A new CLI export format renders the resulting `graph.coverage.languages[]` (now carrying `tier`/`irTaintRecallPct`/`measuredAt`/`source`) as a Markdown table, mirroring the already-shipped `recipients` format's exact wiring shape.

**Tech Stack:** Node.js ESM, no new dependencies.

**Spec:** `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-lang-coverage-scoping.md`

## Global Constraints

- Never fabricate a recall number for a language with no curated entry — `coverageTierForLanguage` returns `null` for anything not in the table; the ledger falls back to `tier: 'unknown'` with no `irTaintRecallPct`/`measuredAt`/`source` fields at all.
- Every curated recall number is copied VERBATIM from `docs/METRICS.md`'s currently-committed table (measured 2026-08-19, engine v0.137.1) — do not re-derive or round differently.
- `graph.coverage` needs zero `schema.json`/`validate.js` changes — it is validated only as `{"type": "object"}` (confirmed). `LANGUAGE_COVERAGE_TIER_VALUES` still gets added to `schema.js` as a real, exported, single source of truth, even though nothing in `validateGraph()` structurally checks it.
- `LANGUAGE_COVERAGE_TIER_VALUES` is its OWN enum, never a reuse of `COVERAGE_STATUS_VALUES` — they answer different questions (per-language product-level tier vs. per-node classification confidence).
- No frontend/UI work in this plan.
- `--filter` and `--no-redact` are documented no-ops for `--format coverage`, matching the established `csv`/`recipients` precedent, each with its own one-line justification in both the code comment and `commands/dataflow.md`.

---

### Task 1: `language-coverage-tiers.js` + `schema.js` enum + `coverage.js` wiring

**Files:**
- Create: `scanner/src/lineage/language-coverage-tiers.js`
- Modify: `scanner/src/lineage/schema.js` (add `LANGUAGE_COVERAGE_TIER_VALUES`)
- Modify: `scanner/src/lineage/coverage.js` (extend `LANGUAGE_EXT_PATTERNS`, wire tier data into `buildCoverageLedger`'s `languages` computation)
- Test: `scanner/test/lineage/language-coverage-tiers.test.js` (new)
- Test: `scanner/test/lineage/coverage.test.js` (extend)

**Interfaces:**
- Consumes: nothing new from earlier tasks (this is the first task).
- Produces: `LANGUAGE_COVERAGE_TIER_VALUES` (exported from `schema.js`), `LANGUAGE_COVERAGE_TIERS` + `coverageTierForLanguage(language) -> entry | null` (exported from `language-coverage-tiers.js`) — Task 2's CLI renderer reads `graph.coverage.languages[].tier`/`.irTaintRecallPct`/`.measuredAt`/`.source` directly off the built graph, it does not import `language-coverage-tiers.js` itself.

- [ ] **Step 1: Write the failing tests for `language-coverage-tiers.js`**

Create `scanner/test/lineage/language-coverage-tiers.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LANGUAGE_COVERAGE_TIERS, coverageTierForLanguage } from '../../src/lineage/language-coverage-tiers.js';
import { LANGUAGE_COVERAGE_TIER_VALUES } from '../../src/lineage/schema.js';

const LINEAGE_WIRED_LANGUAGES = ['js', 'python', 'java', 'csharp', 'kotlin', 'go', 'php', 'ruby', 'cpp'];
const PATTERN_ONLY_LANGUAGES = ['rust', 'solidity', 'swift', 'dart'];

test('LANGUAGE_COVERAGE_TIERS has exactly the 9 lineage-wired languages plus the 4 pattern-only ones, no more, no fewer', () => {
  const keys = LANGUAGE_COVERAGE_TIERS.map((e) => e.language).sort();
  const expected = [...LINEAGE_WIRED_LANGUAGES, ...PATTERN_ONLY_LANGUAGES].sort();
  assert.deepEqual(keys, expected);
});

test('every entry has a value in LANGUAGE_COVERAGE_TIER_VALUES', () => {
  for (const e of LANGUAGE_COVERAGE_TIERS) {
    assert.ok(LANGUAGE_COVERAGE_TIER_VALUES.includes(e.tier), `${e.language} has unrecognized tier "${e.tier}"`);
  }
});

test('every lineage-wired language is tier "partial" with a real recall number and no entry reaches "full" yet (docs/METRICS.md, measured 2026-08-19: best is python at 66%, well under the 85% bar)', () => {
  for (const lang of LINEAGE_WIRED_LANGUAGES) {
    const e = coverageTierForLanguage(lang);
    assert.equal(e.tier, 'partial');
    assert.equal(typeof e.irTaintRecallPct, 'number');
    assert.ok(e.irTaintRecallPct > 0 && e.irTaintRecallPct < 85);
    assert.equal(e.measuredAt, '2026-08-19');
    assert.equal(e.source, 'docs/METRICS.md');
  }
});

test('the exact 9 recall numbers match docs/METRICS.md verbatim', () => {
  const expected = { python: 66, go: 59, js: 58, csharp: 57, ruby: 55, java: 52, php: 52, kotlin: 48, cpp: 18 };
  for (const [lang, pct] of Object.entries(expected)) {
    assert.equal(coverageTierForLanguage(lang).irTaintRecallPct, pct, `${lang} recall mismatch`);
  }
});

test('every pattern-only language is tier "pattern-only" with no recall number (no lineage engine ever runs against them)', () => {
  for (const lang of PATTERN_ONLY_LANGUAGES) {
    const e = coverageTierForLanguage(lang);
    assert.equal(e.tier, 'pattern-only');
    assert.equal(e.irTaintRecallPct, null);
  }
});

test('coverageTierForLanguage returns null for unknown/unrecognized languages, never fabricates a tier', () => {
  assert.equal(coverageTierForLanguage('unknown'), null);
  assert.equal(coverageTierForLanguage('cobol'), null);
  assert.equal(coverageTierForLanguage(''), null);
  assert.equal(coverageTierForLanguage(undefined), null);
});

test('the table is frozen (Object.freeze) at both the array and entry level', () => {
  assert.ok(Object.isFrozen(LANGUAGE_COVERAGE_TIERS));
  assert.ok(Object.isFrozen(LANGUAGE_COVERAGE_TIERS[0]));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/lineage/language-coverage-tiers.test.js`
Expected: FAIL — `Cannot find module '../../src/lineage/language-coverage-tiers.js'` (or `LANGUAGE_COVERAGE_TIER_VALUES` undefined from `schema.js`).

- [ ] **Step 3: Add `LANGUAGE_COVERAGE_TIER_VALUES` to `schema.js`**

Find `schema.js`'s existing `export const COVERAGE_STATUS_VALUES = ...` line (grep for it — it's near the other top-level enum exports). Add immediately after it:

```js
// Milestone 5, language coverage-tier disclosure: a product-level tier for
// an entire LANGUAGE (per docs/METRICS.md's own curated recall measurements),
// deliberately NOT a reuse of COVERAGE_STATUS_VALUES above — that enum
// answers a different question (is this one NODE's own classification
// confident), not "does this language, as a whole, clear the PRD's own
// field-to-sink recall bar." 'full' is real and reachable (a future
// docs/METRICS.md update crossing 85% needs no code change here to report
// it) even though no language currently resolves to it.
export const LANGUAGE_COVERAGE_TIER_VALUES = Object.freeze(['full', 'partial', 'pattern-only', 'unknown']);
```

- [ ] **Step 4: Create `language-coverage-tiers.js`**

Create `scanner/src/lineage/language-coverage-tiers.js`:

```js
// language-coverage-tiers.js — Milestone 5, language coverage-tier
// disclosure. A small, curated, static table answering "how much can this
// codebase's Data Flow Explorer actually see for language X today" —
// PRD §22.1's own explicitly-sanctioned alternative to claiming a language
// is fully "supported" before it clears §22.3's 85% field-to-sink-recall
// bar (as of docs/METRICS.md, measured 2026-08-19, NONE of the 9
// lineage-wired languages do — best is python at 66%).
//
// Every number here is copied VERBATIM from docs/METRICS.md's own
// currently-committed table (bench/layer-recall's IR-TAINT column — the
// closest existing proxy for the PRD's own field-to-sink recall definition,
// not a byte-identical measurement of it). This module does not re-measure
// anything; re-run bench/layer-recall and update BOTH docs/METRICS.md and
// this table together if the numbers ever change, or this file goes stale
// silently. Zero imports — a pure, static data module, mirroring
// flow-grade.js's own "zero imports" precedent for a self-contained
// vocabulary/data table.
//
// The 9 keys below are languageForFile's own normalized vocabulary
// (coverage.js) — js/python/java/csharp/kotlin/go/php/ruby/cpp — the exact
// languages with real IR-to-lineage wiring today. The 4 pattern-only keys
// (rust/solidity/swift/dart) have ZERO lineage/taint wiring: they exist
// only as tree-sitter grammar loads feeding sast/tree-sitter-sinks.js's
// pattern matching, never scanner/src/lineage/ or scanner/src/dataflow/ —
// confirmed by the M5 top-level scoping doc's own investigation. No
// lineage engine ever runs against them, so they carry no recall number at
// all (irTaintRecallPct: null) — never a fabricated 0%, which would read
// as "measured and found to be zero" rather than "never measured, because
// nothing here can produce a lineage finding for this language yet."

export const LANGUAGE_COVERAGE_TIERS = Object.freeze([
  Object.freeze({ language: 'python', tier: 'partial', irTaintRecallPct: 66, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'go', tier: 'partial', irTaintRecallPct: 59, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'js', tier: 'partial', irTaintRecallPct: 58, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'csharp', tier: 'partial', irTaintRecallPct: 57, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'ruby', tier: 'partial', irTaintRecallPct: 55, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'java', tier: 'partial', irTaintRecallPct: 52, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'php', tier: 'partial', irTaintRecallPct: 52, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'kotlin', tier: 'partial', irTaintRecallPct: 48, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'cpp', tier: 'partial', irTaintRecallPct: 18, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'rust', tier: 'pattern-only', irTaintRecallPct: null, measuredAt: null, source: null }),
  Object.freeze({ language: 'solidity', tier: 'pattern-only', irTaintRecallPct: null, measuredAt: null, source: null }),
  Object.freeze({ language: 'swift', tier: 'pattern-only', irTaintRecallPct: null, measuredAt: null, source: null }),
  Object.freeze({ language: 'dart', tier: 'pattern-only', irTaintRecallPct: null, measuredAt: null, source: null }),
]);

const _byLanguage = new Map(LANGUAGE_COVERAGE_TIERS.map((e) => [e.language, e]));

/**
 * `coverageTierForLanguage(language) -> entry | null`. Never fabricates —
 * returns `null` for any language string not in the curated table above
 * (including coverage.js's own `'unknown'` fallback), so a caller must
 * decide its own honest default (coverage.js's ledger uses `'unknown'`).
 */
export function coverageTierForLanguage(language) {
  if (typeof language !== 'string' || language.length === 0) return null;
  return _byLanguage.get(language) ?? null;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd scanner && node --test test/lineage/language-coverage-tiers.test.js`
Expected: PASS, 7/7.

- [ ] **Step 6: Extend `LANGUAGE_EXT_PATTERNS` in `coverage.js` for the 4 pattern-only languages**

In `scanner/src/lineage/coverage.js`, find:

```js
const LANGUAGE_EXT_PATTERNS = Object.freeze([
  [/\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i, 'js'],
  [/\.py$/i, 'python'],
  [/\.java$/i, 'java'],
  [/\.cs$/i, 'csharp'],
  [/\.kt$/i, 'kotlin'],
  [/\.go$/i, 'go'],
  [/\.(?:php|phtml)$/i, 'php'],
  [/\.rb$/i, 'ruby'],
  [/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i, 'cpp'],
]);
```

Replace with (adding the 4 new rows, keeping every existing row byte-identical):

```js
const LANGUAGE_EXT_PATTERNS = Object.freeze([
  [/\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i, 'js'],
  [/\.py$/i, 'python'],
  [/\.java$/i, 'java'],
  [/\.cs$/i, 'csharp'],
  [/\.kt$/i, 'kotlin'],
  [/\.go$/i, 'go'],
  [/\.(?:php|phtml)$/i, 'php'],
  [/\.rb$/i, 'ruby'],
  [/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i, 'cpp'],
  // Milestone 5, language coverage-tier disclosure: these 4 have ZERO
  // lineage/taint wiring (tree-sitter-pattern-only, sast/tree-sitter-sinks.js
  // only) — added here purely so a coverage-ledger `languages[]` entry can
  // honestly attribute their files to a real language bucket, distinct from
  // a genuinely unrecognized extension, rather than silently folding them
  // into the shared 'unknown' fallback below.
  [/\.rs$/i, 'rust'],
  [/\.sol$/i, 'solidity'],
  [/\.swift$/i, 'swift'],
  [/\.dart$/i, 'dart'],
]);
```

- [ ] **Step 7: Wire `tier`/`irTaintRecallPct`/`measuredAt`/`source` into `buildCoverageLedger`'s `languages` computation**

In `scanner/src/lineage/coverage.js`, add the import near the top of the file (alongside the other imports — check the file's existing import block and add this line in the same style):

```js
import { coverageTierForLanguage } from './language-coverage-tiers.js';
```

Find:

```js
  const languages = [...allLangs].sort().map((language) => {
    const filesAnalyzed = filesAnalyzedByLang.get(language) ?? 0;
    return { language, filesExpected: filesAnalyzed + (filesFailedByLang.get(language) ?? 0), filesAnalyzed };
  });
```

Replace with:

```js
  const languages = [...allLangs].sort().map((language) => {
    const filesAnalyzed = filesAnalyzedByLang.get(language) ?? 0;
    const base = { language, filesExpected: filesAnalyzed + (filesFailedByLang.get(language) ?? 0), filesAnalyzed };
    // Milestone 5, language coverage-tier disclosure: coverageTierForLanguage
    // never fabricates — a language with no curated entry (including the
    // shared 'unknown' bucket for anything languageForFile can't recognize)
    // gets tier: 'unknown' and no recall/measuredAt/source fields at all,
    // never a guessed or zeroed-out number.
    const tierEntry = coverageTierForLanguage(language);
    if (!tierEntry) return { ...base, tier: 'unknown' };
    const { tier, irTaintRecallPct, measuredAt, source } = tierEntry;
    return irTaintRecallPct == null ? { ...base, tier } : { ...base, tier, irTaintRecallPct, measuredAt, source };
  });
```

- [ ] **Step 8: Run tests to verify they pass, extend `coverage.test.js`**

Run: `cd scanner && node --test test/lineage/coverage.test.js`
Expected: existing tests still PASS (this change is purely additive to each `languages[]` entry's own shape — no existing assertion reads an exact object shape for `languages[]` entries that this would break; confirm this directly by running the suite before writing new tests, and if an existing test DOES do an exact-shape `deepEqual` on a `languages[]` entry, extend that assertion's expected shape to include the new fields rather than leaving it failing).

Add to `scanner/test/lineage/coverage.test.js` (find the section testing `languages`/`buildCoverageLedger` and add nearby):

```js
test('M5: buildCoverageLedger attaches a real tier to each language bucket, never fabricating one for an unrecognized language', () => {
  const cg = irOf({ 'a.py': "def h(): print(input())" });
  const built = buildDataFlowGraph(cg, { repository: 'lang-tier-check' });
  const ledger = buildCoverageLedger(built, { perFile: { 'a.py': {} } });
  const py = ledger.languages.find((l) => l.language === 'python');
  assert.equal(py.tier, 'partial');
  assert.equal(py.irTaintRecallPct, 66);
  assert.equal(py.measuredAt, '2026-08-19');
  assert.equal(py.source, 'docs/METRICS.md');
});

test('M5: an unrecognized language file gets tier "unknown" and no recall fields', () => {
  const cg = irOf({});
  const built = buildDataFlowGraph(cg, { repository: 'lang-tier-unknown' });
  const ledger = buildCoverageLedger(built, { perFile: { 'a.zig': {} } });
  const unk = ledger.languages.find((l) => l.language === 'unknown');
  assert.equal(unk.tier, 'unknown');
  assert.equal('irTaintRecallPct' in unk, false);
});

test('M5: a rust file gets tier "pattern-only" with no recall number, distinct from "unknown"', () => {
  const cg = irOf({});
  const built = buildDataFlowGraph(cg, { repository: 'lang-tier-rust' });
  const ledger = buildCoverageLedger(built, { perFile: { 'a.rs': {} } });
  const rust = ledger.languages.find((l) => l.language === 'rust');
  assert.equal(rust.tier, 'pattern-only');
  assert.equal('irTaintRecallPct' in rust, false);
});
```

Check the exact real signature/imports `coverage.test.js` already uses for `irOf`/`buildDataFlowGraph`/`buildCoverageLedger` (they're already imported at the top of the file for other tests) and match them exactly — do not re-import or redefine anything already in scope.

Run: `cd scanner && node --test test/lineage/coverage.test.js`
Expected: PASS, all tests including the 3 new ones.

- [ ] **Step 9: Run the full lineage scope**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, exit 0, growing by 7 (new file) + 3 (extended file) from baseline.

- [ ] **Step 10: Commit**

```bash
git add src/lineage/language-coverage-tiers.js src/lineage/schema.js src/lineage/coverage.js test/lineage/language-coverage-tiers.test.js test/lineage/coverage.test.js
git commit -m "feat(lineage): curated per-language coverage-tier data + wire into graph.coverage.languages[] (M5 language coverage-tier disclosure, Task 1)"
```

---

### Task 2: `dataflow export --format coverage` CLI rendering

**Files:**
- Modify: `scanner/bin/agentic-security.js` (new format, new render function, new escaping helpers, `--filter`/`--no-redact` no-op wiring)
- Modify: `commands/dataflow.md` (new `coverage` row + flag-description updates)
- Test: `scanner/test/cli/dataflow-coverage.test.js` (new)

**Interfaces:**
- Consumes: `graph.coverage.languages[]` entries shaped `{language, filesExpected, filesAnalyzed, tier, irTaintRecallPct?, measuredAt?, source?}` (Task 1's own output — read directly off the already-loaded graph, no import of `language-coverage-tiers.js` needed here).
- Produces: nothing further downstream — this is the last task.

- [ ] **Step 1: Write the failing CLI test**

Create `scanner/test/cli/dataflow-coverage.test.js` — mirrors `scanner/test/cli/dataflow-recipients.test.js`'s own real structure exactly (same imports, same `createGitFixture`/`spawnSync` helper shape, same real-scan-then-export pattern):

```js
// dataflow-coverage.test.js — Milestone 5, language coverage-tier
// disclosure: real CLI integration tests for
// `agentic-security dataflow export --format coverage`.
//
// Mirrors test/cli/dataflow-recipients.test.js's own real-git-fixture +
// real-deep-scan + real-CLI-subprocess pattern.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

// A plain JS source file — enough to produce a real graph.coverage.languages
// entry for 'js' with real filesAnalyzed/filesExpected counts.
const JS_SOURCE = `function h(req, res){ res.send(req.body.name); }`;

function _scanWithLineage(fx) {
  return spawnSync(process.execPath, [CLI, 'scan', '.'], {
    cwd: fx.root, encoding: 'utf8', timeout: 60000,
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
  });
}

function _exportCli(fx, args) {
  return spawnSync(process.execPath, [CLI, 'dataflow', 'export', '.', ...args], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
}

test('dataflow export --format coverage writes a Markdown table with a real per-language row, tier, and recall figure', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', JS_SOURCE);
  fx.commit('add a plain JS flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'coverage.md');
  const exportR = _exportCli(fx, ['--format', 'coverage', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format coverage failed: ${exportR.stderr}\n${exportR.stdout}`);
  assert.ok(fs.existsSync(outFile), 'expected coverage.md to be written');

  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /# Language Coverage/);
  assert.match(md, /\| Language \| Files Analyzed \| Files Expected \| Tier \| Recall \(docs\/METRICS\.md\) \|/);
  assert.match(md, /\| js \|/);
  assert.match(md, /\bpartial\b/);
  assert.match(md, /58% \(as of 2026-08-19\)/);
});

test('dataflow export --format coverage: --filter is a documented no-op with a warning', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', JS_SOURCE);
  fx.commit('add a plain JS flow');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const filterPath = path.join(fx.root, 'filter.json');
  fs.writeFileSync(filterPath, JSON.stringify({ nodeIds: [], edgeIds: [] }));
  const outFile = path.join(fx.root, 'coverage-filtered.md');
  const exportR = _exportCli(fx, ['--format', 'coverage', '--output', outFile, '--filter', filterPath]);
  assert.equal(exportR.status, 0);
  assert.match(exportR.stderr, /--filter has no effect on --format coverage/);
});

test('dataflow export --format coverage: --no-redact and --view are documented no-ops with a warning', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', JS_SOURCE);
  fx.commit('add a plain JS flow');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'coverage-noredact.md');
  const noRedactR = _exportCli(fx, ['--format', 'coverage', '--output', outFile, '--no-redact']);
  assert.equal(noRedactR.status, 0);
  assert.match(noRedactR.stderr, /--no-redact has no effect on --format coverage/);

  const outFile2 = path.join(fx.root, 'coverage-view.md');
  const viewR = _exportCli(fx, ['--format', 'coverage', '--output', outFile2, '--view', 'privacy']);
  assert.equal(viewR.status, 0);
  assert.match(viewR.stderr, /--view has no effect on --format coverage/);
});

test('dataflow export --format coverage never fabricates a recall number for an unrecognized language', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  // No source files at all — graph.coverage.languages should come back
  // empty (or, if perFile ever includes an unrecognized extension in a
  // future fixture, that entry must show tier "unknown" with no percentage
  // printed). This test only pins the "no fabrication" property, not a
  // specific unrecognized-language shape, since this repo's own scan
  // pipeline may not surface a language for an empty tree at all.
  fx.commit('empty tree');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'coverage-empty.md');
  const exportR = _exportCli(fx, ['--format', 'coverage', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format coverage failed: ${exportR.stderr}\n${exportR.stdout}`);
  const md = fs.readFileSync(outFile, 'utf8');
  // Whatever the table contains, it must never print a bare, unlabeled
  // percentage next to an "unknown" tier row — every recall figure shown
  // must be paired with its own "(as of docs/METRICS.md date)" provenance,
  // enforced structurally by _renderDataflowCoverageMarkdown's own '—'
  // fallback for a missing irTaintRecallPct.
  const unknownRows = md.split('\n').filter((l) => /\| unknown \|/.test(l));
  for (const row of unknownRows) assert.match(row, /\| — \|$/, `unknown-tier row must show "—" for recall, never a number: ${row}`);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/cli/dataflow-coverage.test.js`
Expected: FAIL — `coverage` not in `DATAFLOW_EXPORT_FORMATS`, exits 2 with the format-validation error.

- [ ] **Step 3: Add `'coverage'` to `DATAFLOW_EXPORT_FORMATS`**

In `scanner/bin/agentic-security.js`, find:

```js
const DATAFLOW_EXPORT_FORMATS = new Set(['png', 'pdf', 'svg', 'json', 'csv', 'html', 'dpia', 'ropa', 'briefing', 'recipients']);
```

Replace with:

```js
const DATAFLOW_EXPORT_FORMATS = new Set(['png', 'pdf', 'svg', 'json', 'csv', 'html', 'dpia', 'ropa', 'briefing', 'recipients', 'coverage']);
```

- [ ] **Step 4: Add `coverage` to the `--view` no-op set**

Find the `--view` no-op block (search for `--view has no effect on --format`):

```js
  if (viewExplicit && (format === 'json' || format === 'csv' || format === 'html' || format === 'dpia' || format === 'ropa' || format === 'briefing' || format === 'recipients')) {
    process.stderr.write(`agentic-security dataflow export: --view has no effect on --format ${format} — ${format} exports are not view-scoped.\n`);
  }
```

Replace the condition (and extend the preceding comment block with one more sentence) with:

```js
  // coverage (M5, language coverage-tier disclosure) joins the same set —
  // a Markdown table over graph.coverage.languages[] has no --view concept
  // either.
  if (viewExplicit && (format === 'json' || format === 'csv' || format === 'html' || format === 'dpia' || format === 'ropa' || format === 'briefing' || format === 'recipients' || format === 'coverage')) {
    process.stderr.write(`agentic-security dataflow export: --view has no effect on --format ${format} — ${format} exports are not view-scoped.\n`);
  }
```

- [ ] **Step 5: Add `coverage` to the `--no-redact` no-op set**

Find the `--no-redact` no-op block (search for `--no-redact has no effect on --format \\\${format}`):

```js
  if (!redact && (format === 'dpia' || format === 'ropa' || format === 'briefing' || format === 'recipients')) {
    process.stderr.write(`agentic-security dataflow export: --no-redact has no effect on --format ${format} — ${format} export does not support redaction yet.\n`);
  }
```

First confirm directly (read `graph.coverage.languages[]`'s real shape — `language`/`filesExpected`/`filesAnalyzed`/`tier`/`irTaintRecallPct`/`measuredAt`/`source`) that none of these fields is a destination literal, evidence snippet, or any other scanned-source-derived string that `redact-graph.js` has an opinion about — they are all either curated static data (`tier`/`irTaintRecallPct`/`measuredAt`/`source`, from `language-coverage-tiers.js`) or plain integers/enum strings (`filesExpected`/`filesAnalyzed`/`language`). Once confirmed, add `coverage` to the set:

```js
  // coverage (M5, language coverage-tier disclosure) joins the same set —
  // graph.coverage.languages[] carries only curated static tier data and
  // plain per-repo file counts, never a destination literal or evidence
  // snippet redact-graph.js has any opinion about.
  if (!redact && (format === 'dpia' || format === 'ropa' || format === 'briefing' || format === 'recipients' || format === 'coverage')) {
    process.stderr.write(`agentic-security dataflow export: --no-redact has no effect on --format ${format} — ${format} export does not support redaction yet.\n`);
  }
```

- [ ] **Step 6: Add `coverage` to the `--filter` no-op set**

Find the `--filter`-no-op-for-csv block:

```js
    if (format === 'csv') {
      process.stderr.write('agentic-security dataflow export: --filter has no effect on --format csv — CSV export does not support scoping yet.\n');
    }
```

Replace with:

```js
    // coverage (M5, language coverage-tier disclosure) joins the same set —
    // a per-language table has no node/edge-id-scoped meaning to narrow by.
    if (format === 'csv' || format === 'coverage') {
      process.stderr.write(`agentic-security dataflow export: --filter has no effect on --format ${format} — ${format} export does not support scoping yet.\n`);
    }
```

- [ ] **Step 7: Wire the new format into the export dispatch**

Find:

```js
    } else if (format === 'recipients') {
      data = _renderDataflowRecipientsMarkdown(graph, opts);
    }
```

Replace with:

```js
    } else if (format === 'recipients') {
      data = _renderDataflowRecipientsMarkdown(graph, opts);
    } else if (format === 'coverage') {
      data = _renderDataflowCoverageMarkdown(graph, opts);
    }
```

- [ ] **Step 8: Add the escaping helpers + render function**

After the existing `_dfRecipientsMdCode` function (and before `_renderDataflowRecipientsMarkdown`, or immediately after it — place it as a new, clearly-separated block), add:

```js
// Local Markdown-escaping helpers for `--format coverage` — byte-identical
// to _dfRecipientsMdInline/_dfRecipientsMdCell/_dfRecipientsMdCode above,
// reimplemented locally per this codebase's established
// per-module-owns-its-own-escaping-helpers convention.
function _dfCoverageMdInline(value) {
  return String(value).replace(/\r\n|\r|\n/g, ' ');
}
function _dfCoverageMdCell(value) {
  return _dfCoverageMdInline(value).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

// Milestone 5, language coverage-tier disclosure. Renders graph.coverage.
// languages[] (Task 1's own additive fields: tier/irTaintRecallPct/
// measuredAt/source, alongside the pre-existing filesExpected/filesAnalyzed)
// as a Markdown table, with an explicit disclosure paragraph distinguishing
// the two different KINDS of fact in this report: real, per-repo file
// counts (filesAnalyzed/filesExpected, computed fresh on every scan) versus
// a curated, product-level recall estimate (irTaintRecallPct/measuredAt/
// source, unchanged since docs/METRICS.md was last measured) — never
// presented as one number, since conflating them would imply this scan
// itself measured its own recall, which it did not.
function _renderDataflowCoverageMarkdown(graph, opts = {}) {
  const lines = [];
  lines.push('# Language Coverage');
  lines.push('');
  lines.push(`**Graph:** \`${_dfCoverageMdInline(graph.graphId ?? '(no graphId)')}\``);
  lines.push(`**Generated:** ${_dfCoverageMdInline(opts.generatedAt ?? graph.generatedAt ?? '')}`);
  lines.push('');
  lines.push('`Files Analyzed`/`Files Expected` are real counts from THIS scan. `Tier` and `Recall (docs/METRICS.md)` are a curated, product-level estimate — unchanged since the date shown, not measured on this repository. The two are never the same kind of fact.');
  lines.push('');
  const languages = Array.isArray(graph.coverage?.languages) ? graph.coverage.languages : [];
  if (languages.length === 0) {
    lines.push('_No language coverage data available for this scan._');
  } else {
    lines.push('| Language | Files Analyzed | Files Expected | Tier | Recall (docs/METRICS.md) |');
    lines.push('|---|---|---|---|---|');
    for (const l of languages) {
      const recall = typeof l.irTaintRecallPct === 'number'
        ? `${l.irTaintRecallPct}% (as of ${_dfCoverageMdInline(l.measuredAt ?? '?')})`
        : '—';
      lines.push(`| ${_dfCoverageMdCell(l.language)} | ${_dfCoverageMdCell(l.filesAnalyzed)} | ${_dfCoverageMdCell(l.filesExpected)} | ${_dfCoverageMdCell(l.tier)} | ${recall} |`);
    }
  }
  lines.push('');
  return lines.join('\n');
}
```

- [ ] **Step 9: Update the hardcoded `USAGE` string**

`bin/agentic-security.js` has a separate, hand-maintained `USAGE` line (does NOT auto-derive from `DATAFLOW_EXPORT_FORMATS`) — find:

```
  dataflow export [path] --format png|pdf|svg|json|csv|html|dpia|ropa|briefing|recipients --output <file>
```

Replace with:

```
  dataflow export [path] --format png|pdf|svg|json|csv|html|dpia|ropa|briefing|recipients|coverage --output <file>
```

- [ ] **Step 10: Update `commands/dataflow.md`**

Add a new row to the `## Formats` table (mirror the `recipients` row's own structure/wording exactly) documenting `coverage`, and extend the `--view`/`--no-redact`/`--filter` flag descriptions to name `coverage` alongside the other non-view-scoped/non-redaction/non-scoping formats, matching how `recipients` was added there in the FR-506 sub-project.

- [ ] **Step 11: Run tests to verify they pass**

Register the new test file in `package.json`: `dataflow-recipients.test.js` (its sibling) is registered under `test:posture` (confirmed by direct grep of `package.json` — NOT `test:server`, despite `scanner/CLAUDE.md`'s table describing `test:server` as covering "the `explore`/`dataflow export` CLI commands"; the real wiring for this specific file lives in `test:posture`, follow the real registration, not the table's general description). Add `test/cli/dataflow-coverage.test.js` immediately after `test/cli/dataflow-recipients.test.js` in that same script's file list.

Run: `cd scanner && node --test test/cli/dataflow-coverage.test.js`
Expected: PASS, all new tests.

Run: `cd scanner && npm run test:posture`
Expected: PASS, exit 0.

- [ ] **Step 12: `npm run build`**

`bin/agentic-security.js` was touched — per this repo's own build-invariant rule, rebuild:

```bash
cd scanner && npm run build
```

Confirm exit 0, bundle + sha256 sidecar regenerated.

- [ ] **Step 13: Commit**

```bash
git add bin/agentic-security.js dist/agentic-security.mjs dist/agentic-security.mjs.sha256 commands/dataflow.md test/cli/dataflow-coverage.test.js package.json
git commit -m "feat(cli): dataflow export --format coverage (M5 language coverage-tier disclosure, Task 2)"
```
