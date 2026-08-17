# Independent-Population Root-Cause + Language Mining Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-measure `bench/independent`, mechanically and manually root-cause all 96 current false negatives, fix any obvious-win bugs found, mine Java/C#/Kotlin/PHP/Go/Ruby entries (currently zero coverage), and publish the findings in `docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md`.

**Architecture:** A new diagnostic script, `bench/independent/why-missed.mjs`, reuses the existing scan/scoring primitives in `runner.mjs` (exported for reuse) to classify each false negative into one of: not-actually-missing (stale snapshot), wrong-file-or-cwe, suppressed-by-a-named-mechanism, or no-finding-at-all. Its mechanical output seeds a batch of `Agent` dispatches that read the real fix-commit diff and confirm or correct the mechanical verdict. Mining reuses the existing `mine.mjs`/`materialise.mjs` pipeline with explicit per-language ecosystem flags. All work lands on `main` directly (no feature branch needed — this is measurement/docs/one small diagnostic script, not a shipped detector change), except any obvious-win fix, which gets the full corpus + test gate before landing.

**Tech Stack:** Node ≥ 24, ESM, `node:test` + `node:assert/strict`. No new dependencies. `gh` CLI (already used by `mine.mjs`) for advisory mining.

## Global Constraints

- **ESM only.** `import`/`export`, no CommonJS, matching every file in `bench/independent/` and `scanner/src/`.
- **Node ≥ 24.**
- **No new npm dependencies.**
- **Rebuild after `scanner/src/` changes:** `cd scanner && npm run build`. This plan does not touch `scanner/src/` except possibly in the obvious-win-fix task, where a rebuild is required before any gate that reads the bundle.
- **Confirm every mutation landed** — re-read or grep after every edit, per root `CLAUDE.md`'s verification discipline.
- **Every stated number must come from a command run in this session.** No remembered or assumed figures in the final write-up.
- **Wipe scan state before benchmarking:** `.agentic-security/` dirs inside `bench/independent/cache/*/pre` and `*/post` must be purged before any scan used for scoring — `runner.mjs`'s existing `purgeScanState` already does this per-entry; the new script must reuse it, not skip it.
- **New test files must be wired into a scoped `npm` script** in `scanner/package.json` (the `test:posture` line already lists `test/independent-population.test.js`; the new test file for `why-missed.mjs`'s pure logic joins that same line).
- **Never name any external or competitor security tool** in code, comments, docs, or commit messages.
- **Mining stays blind to the engine.** `mine.mjs`'s admission criteria (CWE + single fix commit + admissible source extension) are not loosened or special-cased to hit a language-coverage target — this is the exact property that makes the population meaningful, stated at the top of `mine.mjs` itself.
- **Any inline fix must pass, both directions (exit code captured):** the relevant scoped test, `npm test`, and `npm run bench:cve-replay:check` — before it counts as a fix, and before `bench:independent` is re-run to confirm it actually moved the number.
- **If `gh api` mining fails (503 or otherwise) for a language, report it by name as blocked** — do not hand-author or fabricate an entry to fill the gap.

---

## File Structure

| File | Responsibility |
|---|---|
| `bench/independent/runner.mjs` | *Modify.* Export the existing private `scanDir` as a new `scanDirRaw` that also returns `scan.suppressions`, and export `purgeScanState`. `scanDir` itself becomes a thin wrapper around `scanDirRaw` so no behavior changes for the existing scoring path. |
| `bench/independent/why-missed.mjs` | *Create.* The diagnostic script: `classifySuppressions()` (pure, unit-tested) + `whyMissed(entry)` (I/O, re-scans an entry twice — default and with `AGENTIC_SECURITY_NO_GUARD_RECOGNITION=1` — and buckets the result) + a CLI `main()` that iterates the manifest, writes one JSON file per false-negative entry under `bench/independent/why-missed-output/`, and prints a summary. |
| `scanner/test/why-missed.test.js` | *Create.* Unit tests for `classifySuppressions()`. Wired into `test:posture` in `scanner/package.json`. |
| `bench/independent/why-missed-output/` | *Create (gitignored).* Per-entry mechanical diagnosis, input to the batch `Agent` dispatch. Same gitignore treatment as `cache/`. |
| `bench/independent/materialise-new.mjs` | *Create.* Materialises + scores only manifest entries not yet present under `cache/`, so mining doesn't re-fetch the existing 110 (`materialise-cli.mjs` has no such filter and would re-download everything). |
| `docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md` | *Create.* Per-entry root-cause table + rollup, per the approved design doc. |
| `bench/independent/README.md` | *Modify.* Add a one-paragraph pointer to the new doc under the existing R16 section. |
| `bench/independent/RESULT.json` | *Regenerate* at the end. Confirmed tracked (`git ls-files` lists it) — every regeneration is a real, committed diff. |
| `bench/independent/manifest.json` | *Modify* by mining — new entries appended, same schema as existing 110. |
| `.gitignore` | *Modify* if `why-missed-output/` isn't already covered by an existing pattern. |

---

## Task 1: Export raw scan (findings + suppressions) from `runner.mjs`

**Files:**
- Modify: `bench/independent/runner.mjs`
- Test: `scanner/test/independent-population.test.js` (existing file — add one case)

**Interfaces:**
- Produces: `export function purgeScanState(dir)` — unchanged behavior, now exported.
- Produces: `export async function scanDirRaw(dir)` — returns `{ findings, suppressions }` where `findings` is the same array `scanDir` returns today (state purged, snapshot-asserted, `.agentic-security` paths excluded) and `suppressions` is `scan.suppressions || []` straight from the engine's return object.
- Modifies: `scanDir(dir)` becomes `async function scanDir(dir) { return (await scanDirRaw(dir)).findings; }` — every existing call site (`main()`'s `preFindings`/`postFindings` calls) is unaffected.

Currently `purgeScanState` and `scanDir` are private (no `export`) in `runner.mjs`. `scanDir` calls `runScan(dir)`, gets back `{ scan }`, and only keeps `normalizeFindings(scan)` — the `scan.suppressions` array (populated by `engine.js`'s `_suppressionLog`, see `engine.js:9155`) is discarded. `why-missed.mjs` needs that array to explain *why* a finding didn't survive to the final list, so it needs a version of `scanDir` that keeps it.

- [ ] **Step 1: Read the current `scanDir` and `purgeScanState` implementations**

Confirm the exact current text before editing:

```bash
cd /Users/ross/code/agentic-security
grep -n "^function purgeScanState\|^async function scanDir" bench/independent/runner.mjs
```

Expected: `function purgeScanState(dir){` and `async function scanDir(dir) {` (no `export` on either).

- [ ] **Step 2: Write the failing test**

Add to `scanner/test/independent-population.test.js` (append at the end of the file, following the existing test style — the file already imports from `runner.mjs`):

```javascript
// ------------------------------------------------------------ raw scan export
import { purgeScanState, scanDirRaw } from '../../bench/independent/runner.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

test('scanDirRaw returns both findings and the suppression log', async () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'scandirraw-'));
  try {
    fs.writeFileSync(path.join(d, 'package.json'), '{"name":"t","version":"1.0.0"}');
    // A file with an inline-ignore pragma: the engine finds it, then drops it,
    // logging the drop. This is the exact mechanism why-missed.mjs depends on.
    fs.writeFileSync(
      path.join(d, 'app.js'),
      'const { exec } = require("child_process");\n' +
      'function run(cmd) { exec(cmd); } // agentic-security-ignore\n'
    );
    const { findings, suppressions } = await scanDirRaw(d);
    assert.ok(Array.isArray(findings), 'findings must be an array');
    assert.ok(Array.isArray(suppressions), 'suppressions must be an array');
    assert.ok(
      suppressions.some(s => /inline pragma/.test(s.reason || '')),
      `expected an inline-pragma suppression entry, got: ${JSON.stringify(suppressions)}`
    );
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('purgeScanState removes .agentic-security before a scan', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'purge-'));
  try {
    const sd = path.join(d, '.agentic-security');
    fs.mkdirSync(sd, { recursive: true });
    fs.writeFileSync(path.join(sd, 'last-scan.json'), '{}');
    purgeScanState(d);
    assert.equal(fs.existsSync(sd), false);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd scanner && node --test test/independent-population.test.js 2>&1 | tail -30`
Expected: FAIL — `scanDirRaw` and `purgeScanState` are not exported, so the import throws `SyntaxError: The requested module '../../bench/independent/runner.mjs' does not provide an export named 'scanDirRaw'`.

- [ ] **Step 4: Export `purgeScanState` and add `scanDirRaw`**

In `bench/independent/runner.mjs`, change:

```javascript
function purgeScanState(dir){
```
to:
```javascript
export function purgeScanState(dir){
```

Then replace the existing `scanDir` function:

```javascript
async function scanDir(dir) {
  // Pristine input, every time. See purgeScanState.
  purgeScanState(dir);
  // Snapshot AFTER the purge: the purge is a deliberate removal, so including
  // it would guarantee a spurious "corpus changed" on every entry. What is
  // being asserted is that the SCAN adds nothing, which is the claim that
  // matters. (STATE_SEAM_COMPLETION_PRD M3)
  const before = snapshotTree(dir);
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
  const { scan } = await runScan(dir);
  const { normalizeFindings } = await import(path.join(REPO, 'scanner', 'src', 'report', 'index.js'));
  const findings = normalizeFindings(scan) || [];
  assertTreeUnchanged(before, snapshotTree(dir), `independent entry ${path.basename(path.dirname(dir))}/${path.basename(dir)}`);
  // Defence in depth: even with a pristine input, refuse to score a finding
  // whose path is inside our own state directory. A single guard that can be
  // bypassed by a mid-run write is not a guard.
  return findings.filter(f => !String(f.file || '').includes('.agentic-security'));
}
```

with:

```javascript
export async function scanDirRaw(dir) {
  // Pristine input, every time. See purgeScanState.
  purgeScanState(dir);
  // Snapshot AFTER the purge: the purge is a deliberate removal, so including
  // it would guarantee a spurious "corpus changed" on every entry. What is
  // being asserted is that the SCAN adds nothing, which is the claim that
  // matters. (STATE_SEAM_COMPLETION_PRD M3)
  const before = snapshotTree(dir);
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
  const { scan } = await runScan(dir);
  const { normalizeFindings } = await import(path.join(REPO, 'scanner', 'src', 'report', 'index.js'));
  const findings = normalizeFindings(scan) || [];
  assertTreeUnchanged(before, snapshotTree(dir), `independent entry ${path.basename(path.dirname(dir))}/${path.basename(dir)}`);
  // Defence in depth: even with a pristine input, refuse to score a finding
  // whose path is inside our own state directory. A single guard that can be
  // bypassed by a mid-run write is not a guard.
  return {
    findings: findings.filter(f => !String(f.file || '').includes('.agentic-security')),
    suppressions: scan.suppressions || [],
  };
}

async function scanDir(dir) {
  return (await scanDirRaw(dir)).findings;
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd scanner && node --test test/independent-population.test.js 2>&1 | tail -30`
Expected: PASS, all tests including the two new ones.

- [ ] **Step 6: Run the full `test:posture` scope to confirm no regression**

Run: `cd scanner && npm run test:posture 2>&1 | tail -20`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/independent/runner.mjs scanner/test/independent-population.test.js
git -c credential.helper='!gh auth git-credential' commit -m "$(cat <<'EOF'
refactor(bench): expose suppression log from independent-population scanDir

why-missed.mjs (next commit) needs to see WHY a finding didn't survive
to the final list, not just that it's absent. scanDirRaw returns the
existing scan.suppressions array alongside findings; scanDir becomes a
thin wrapper so the scoring path in main() is unchanged.
EOF
)"
```

---

## Task 2: `why-missed.mjs` — pure classification logic + unit tests

**Files:**
- Create: `bench/independent/why-missed.mjs` (classification function only in this task)
- Create: `scanner/test/why-missed.test.js`
- Modify: `scanner/package.json` (wire the new test file into `test:posture`)

**Interfaces:**
- Consumes: `localiseToAdvisory(findings, files)` from `bench/independent/runner.mjs` (already exported).
- Consumes: `_internals._inferFamily` from `scanner/src/posture/finding-defaults.js` (already exported).
- Produces: `export function classifySuppressions(suppressions, entry)` — pure function, no I/O. `entry` is `{ cwe, files }`. Returns an array of `{ file, line, vuln, reason, mechanism, familyMatch }` for every suppression entry whose `file` is in `entry.files` (via `localiseToAdvisory`'s suffix-matching, reused by wrapping suppression entries as `{file: s.file}`), where `mechanism` is one of `'ignore-pragma'` | `'sanitized'` | `'custom-rule'` | `'bench-shape'` | `'other'` derived from the `reason` string prefix, and `familyMatch` is `true` when `_inferFamily({cwe: entry.cwe})` equals `_inferFamily({vuln: s.vuln})`.

`_suppressionLog` entries carry `{vuln, file, line, snippet, reason}` — no `cwe` field, since the finding was already stripped of most context by the time it's logged (see `engine.js:2441`, `:8935`, `:8945` for the exact shapes). `classifySuppressions` reuses the engine's own CWE-to-family table (`finding-defaults.js`'s `_CWE_FAMILY`/`_KEYWORD_FAMILY`, via `_inferFamily`) rather than hand-rolling a second mapping, matching this codebase's DRY convention (`finding-defaults.js`'s own header: "We backfill, never overwrite").

- [ ] **Step 1: Write the failing test**

Create `scanner/test/why-missed.test.js`:

```javascript
// why-missed.mjs — unit tests for the pure suppression-classification logic.
//
// The I/O half (re-scanning an entry, running it twice for the guard-window
// diff) is proven by hand against known entries, per this repo's own
// convention for bench/independent/ (see independent-population.test.js's
// header). This file pins the part that can be wrong silently: matching a
// suppressed finding's vuln name back to the advisory's labelled CWE family.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifySuppressions } from '../../bench/independent/why-missed.mjs';

const entry = { cwe: 'CWE-89', files: ['src/db/query.js'] };

test('a suppression on an advisory file, matching CWE family, is flagged ignore-pragma', () => {
  const suppressions = [
    { vuln: 'SQL Injection', file: 'src/db/query.js', line: 12, snippet: '', reason: 'inline pragma: agentic-security-ignore' },
  ];
  const out = classifySuppressions(suppressions, entry);
  assert.equal(out.length, 1);
  assert.equal(out[0].mechanism, 'ignore-pragma');
  assert.equal(out[0].familyMatch, true);
});

test('a suppression on an unrelated file is excluded entirely', () => {
  const suppressions = [
    { vuln: 'SQL Injection', file: 'src/unrelated/other.js', line: 3, snippet: '', reason: 'inline pragma: agentic-security-ignore' },
  ];
  assert.deepEqual(classifySuppressions(suppressions, entry), []);
});

test('mechanism is derived correctly for sanitized, custom-rule, and unknown reasons', () => {
  const base = { file: 'src/db/query.js', line: 1, vuln: 'SQL Injection', snippet: '' };
  const out = classifySuppressions([
    { ...base, reason: 'sanitized:parameterized-query' },
    { ...base, reason: 'custom-rule:team-approved' },
    { ...base, reason: 'bench-category-mismatch:xss!=sql-injection' },
    { ...base, reason: 'context-mismatch:comment' },
  ], entry);
  assert.deepEqual(out.map(o => o.mechanism), ['sanitized', 'custom-rule', 'bench-shape', 'other']);
});

test('familyMatch is false when the suppressed finding is a different vuln class', () => {
  const suppressions = [
    { vuln: 'Cross-Site Scripting', file: 'src/db/query.js', line: 5, snippet: '', reason: 'sanitized:html-escape' },
  ];
  const out = classifySuppressions(suppressions, entry);
  assert.equal(out[0].familyMatch, false);
});

test('an entry with no files never matches anything (localiseToAdvisory contract)', () => {
  const suppressions = [
    { vuln: 'SQL Injection', file: 'src/db/query.js', line: 1, snippet: '', reason: 'sanitized:x' },
  ];
  assert.deepEqual(classifySuppressions(suppressions, { cwe: 'CWE-89', files: [] }), []);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/why-missed.test.js 2>&1 | tail -30`
Expected: FAIL — `bench/independent/why-missed.mjs` doesn't exist yet (`Cannot find module`).

- [ ] **Step 3: Write the minimal implementation**

Create `bench/independent/why-missed.mjs`:

```javascript
#!/usr/bin/env node
// Diagnose WHY a false negative in the independent population is a false
// negative — not just that the labelled CWE didn't match, but whether
// something fired and got suppressed, and if so by which named mechanism.
//
// This exists because DETECTION_GAP_REMEDIATION_PRD.md's R16 finding could
// not distinguish "this shape doesn't occur in these 110 real advisories"
// from "a real detection was masked downstream" — six themes of verified
// fixes landed and the independent recall number did not move. This script
// is the instrument built to tell those two explanations apart, per entry.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanDirRaw, matchesCwe, localiseToAdvisory } from './runner.mjs';
import { entryDir, entryComplete } from './fetch.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const MANIFEST = path.join(HERE, 'manifest.json');
const OUT_DIR = path.join(HERE, 'why-missed-output');

// Reuses the engine's own CWE-to-family table rather than a second one —
// finding-defaults.js already backfills `family` for shipped findings from
// exactly this table, and a suppression-log entry needs the same inference
// since it carries only `vuln`, not `cwe` (see engine.js:2441, :8935).
async function inferFamily(shape) {
  const mod = await import(path.join(REPO, 'scanner', 'src', 'posture', 'finding-defaults.js'));
  return mod._internals._inferFamily(shape);
}

const MECHANISM_OF = [
  [/^inline pragma:|^inline-pragma:/, 'ignore-pragma'],
  [/^sanitized:/, 'sanitized'],
  [/^custom-rule:/, 'custom-rule'],
  [/^bench-/, 'bench-shape'],
  [/^universal-/, 'bench-shape'],
];

function mechanismOf(reason) {
  const r = String(reason || '');
  for (const [re, name] of MECHANISM_OF) if (re.test(r)) return name;
  return 'other';
}

/**
 * Pure: which of this scan's suppressions plausibly explain a miss on
 * `entry`? Scoped to the advisory's own files (via the same suffix-matching
 * runner.mjs's scoring already uses, so "which file" answers the identical
 * question both places), annotated with a family-match signal an agent can
 * use as a starting point — not a verdict; the diff still has to be read.
 */
export function classifySuppressions(suppressions, entry, inferFamilySync) {
  const wanted = new Set((entry.files || []).map(String));
  if (wanted.size === 0) return [];
  const scoped = localiseToAdvisory(
    (suppressions || []).map(s => ({ ...s, file: s.file })),
    entry.files
  );
  return scoped.map(s => ({
    file: s.file, line: s.line, vuln: s.vuln, reason: s.reason,
    mechanism: mechanismOf(s.reason),
    familyMatch: inferFamilySync
      ? inferFamilySync({ cwe: entry.cwe }) === inferFamilySync({ vuln: s.vuln })
      : null,
  }));
}

async function whyMissed(entry) {
  const dir = entryDir(entry.id);
  const preDir = path.join(dir, 'pre');
  let findings, suppressions;
  try {
    ({ findings, suppressions } = await scanDirRaw(preDir));
  } catch (err) {
    return { id: entry.id, bucket: 'scan-error', detail: err.message };
  }

  if (matchesCwe(findings, entry.cwe, entry.files)) {
    return { id: entry.id, bucket: 'not-actually-missing', detail: 'scores TP on this re-scan — FN list is stale, re-measure first' };
  }
  if (matchesCwe(findings, entry.cwe, null)) {
    return { id: entry.id, bucket: 'finding-present-wrong-file-or-cwe' };
  }

  const family = await inferFamily({ cwe: entry.cwe });
  const inferFamilySync = (shape) => {
    // finding-defaults.js's _inferFamily is synchronous; the async wrapper
    // above is only for the dynamic import. Cache the module once per run.
    return shape.cwe ? family : whyMissed._vulnFamilyCache(shape.vuln);
  };
  const suppressed = classifySuppressions(suppressions, entry, inferFamilySync);
  if (suppressed.length) {
    return { id: entry.id, bucket: 'finding-present-but-suppressed', suppressed };
  }

  // Guard-window drop is not logged to _suppressionLog — the only way to see
  // it is a before/after diff with recognition disabled (engine.js:8307).
  process.env.AGENTIC_SECURITY_NO_GUARD_RECOGNITION = '1';
  let findingsNoGuard;
  try {
    ({ findings: findingsNoGuard } = await scanDirRaw(preDir));
  } finally {
    delete process.env.AGENTIC_SECURITY_NO_GUARD_RECOGNITION;
  }
  if (matchesCwe(findingsNoGuard, entry.cwe, entry.files)) {
    return { id: entry.id, bucket: 'finding-present-but-suppressed', suppressed: [{ mechanism: 'guard-window', reason: 'present only with AGENTIC_SECURITY_NO_GUARD_RECOGNITION=1' }] };
  }

  return { id: entry.id, bucket: 'no-finding-at-all' };
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const onlyIds = process.argv.includes('--all') ? null : process.argv.slice(2).filter(a => !a.startsWith('--'));
  const targets = manifest.entries.filter(e => !onlyIds || onlyIds.includes(e.id));

  const summary = { total: 0, byBucket: {} };
  for (const e of targets) {
    if (!entryComplete(e)) { process.stderr.write(`  skip ${e.id} — not fetched\n`); continue; }
    const result = await whyMissed(e);
    summary.total++;
    summary.byBucket[result.bucket] = (summary.byBucket[result.bucket] || 0) + 1;
    fs.writeFileSync(path.join(OUT_DIR, `${e.id}.json`), JSON.stringify({ ...e, ...result }, null, 2) + '\n');
    process.stderr.write(`  ${e.id}  ${result.bucket}\n`);
  }
  process.stderr.write(`\n${JSON.stringify(summary, null, 2)}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
```

Note: `whyMissed._vulnFamilyCache` referenced above needs to actually exist — fix this in the same step (a plan must not ship a reference to something undefined). Replace the `inferFamilySync` closure with a version that resolves both sides through the same async `inferFamily` up front, since both calls are cheap (one dynamic import, cached by Node's module cache after the first call):

```javascript
  const [cweFamily, ...vulnFamilies] = await Promise.all([
    inferFamily({ cwe: entry.cwe }),
    ...suppressions.map(s => inferFamily({ vuln: s.vuln })),
  ]);
```

Replace the body of `whyMissed` from `const family = await inferFamily(...)` through the `classifySuppressions` call with:

```javascript
  const cweFamily = await inferFamily({ cwe: entry.cwe });
  const familyByVuln = new Map();
  for (const s of suppressions) {
    if (!familyByVuln.has(s.vuln)) familyByVuln.set(s.vuln, await inferFamily({ vuln: s.vuln }));
  }
  const inferFamilySync = (shape) => shape.cwe ? cweFamily : familyByVuln.get(shape.vuln);
  const suppressed = classifySuppressions(suppressions, entry, inferFamilySync);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/why-missed.test.js 2>&1 | tail -30`
Expected: PASS, all 5 tests.

- [ ] **Step 5: Wire the test file into `test:posture`**

In `scanner/package.json`, find the `test:posture` line (contains `test/independent-population.test.js`) and add `test/why-missed.test.js` immediately after it in the space-separated list.

```bash
grep -o "test/independent-population.test.js" scanner/package.json
```
Then edit that exact line, inserting `test/why-missed.test.js` right after `test/independent-population.test.js `.

- [ ] **Step 6: Verify no orphan-test failure and the full scope passes**

Run: `cd scanner && npm run test:posture 2>&1 | tail -20`
Expected: exit 0, includes the 5 new test names in output.

- [ ] **Step 7: Add `why-missed-output/` to `.gitignore`**

Confirmed by `git check-ignore -v bench/independent/RESULT.json` (exit 1 — not ignored, and `git ls-files` shows it tracked) and `grep -n "independent\|cache" .gitignore` (only `bench/independent/cache/` is covered, at line 104) that `why-missed-output/` needs its own entry. Add, immediately after the existing `bench/independent/cache/` line in `.gitignore`:

```
bench/independent/why-missed-output/
```

- [ ] **Step 8: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/independent/why-missed.mjs scanner/test/why-missed.test.js scanner/package.json .gitignore
git -c credential.helper='!gh auth git-credential' commit -m "$(cat <<'EOF'
feat(bench): why-missed.mjs — mechanical root-cause diagnostic for FNs

Given a false negative in the independent population, reports whether
something fired and was suppressed (and by which named mechanism —
ignore-pragma, sanitizer, custom-rule, guard-window, bench-shape), or
whether nothing fired at all. Feeds the batch root-cause audit; does
not itself decide anything — the mechanical bucket is a starting
signal for the agent that reads the real fix-commit diff.
EOF
)"
```

---

## Task 3: Sanity-check `why-missed.mjs` against known entries

**Files:** none created — this is a verification task, not a code task. Its deliverable is a documented pass/fail on 3 entries, recorded in the commit message of the next task (Task 4) rather than its own file.

**Interfaces:** none new.

Before trusting `why-missed.mjs` across all 96 entries, run it against 2-3 entries and manually confirm the bucket is right, per the approved design's own requirement.

- [ ] **Step 1: Pick 3 known entries from the current manifest**

```bash
cd /Users/ross/code/agentic-security
node -e "
const m = require('./bench/independent/manifest.json');
console.log(m.entries.slice(0, 3).map(e => e.id).join(' '));
"
```

- [ ] **Step 2: Run `why-missed.mjs` against just those 3**

```bash
cd bench/independent && node why-missed.mjs <id1> <id2> <id3>
```
(Substitute the 3 ids printed in Step 1.)

- [ ] **Step 3: For each, manually verify the bucket**

Read `bench/independent/why-missed-output/<id>.json` for each. For any entry bucketed `not-actually-missing`, `finding-present-wrong-file-or-cwe`, or `no-finding-at-all`, confirm by hand: read `bench/independent/cache/<id>/pre/` for the file(s) named in the entry's `files` field, and run `cd scanner && node bin/agentic-security.js scan ../bench/independent/cache/<id>/pre --format json 2>&1 | grep -i "<cwe-derived-vuln-keyword>"` to see the raw scan output yourself. For any entry bucketed `finding-present-but-suppressed`, confirm the `suppressed[].reason` string is plausible by opening the fix-commit diff (`https://github.com/<repo>/commit/<fixCommit>`, read-only — no local mutation) and checking the pre-fix code actually contains what the suppression reason claims (an `agentic-security-ignore` pragma won't be IN third-party code, so `ignore-pragma` should never appear for a real advisory entry — if it does, that is itself a bug worth flagging, since it would mean the script is matching stale local state, not this specific scan).

- [ ] **Step 4: Record the result**

If all 3 buckets look correct on manual inspection, proceed to Task 4. If any is wrong, fix `why-missed.mjs`'s logic (re-run Task 2's test suite after any fix) before proceeding — do not run it across all 96 entries on unverified logic.

---

## Task 4: Re-measure baseline

**Files:** none created. `bench/independent/RESULT.json` is overwritten in place (already tracked by git per the earlier `git status` check in this session — confirm and treat any diff as a real, reviewable change).

**Interfaces:** none new — this task runs existing tooling only.

- [ ] **Step 1: Wipe scan state across the whole cache**

```bash
cd /Users/ross/code/agentic-security
find bench/independent/cache -type d -name .agentic-security -prune -exec rm -rf {} +
```

- [ ] **Step 2: Run the measurement**

```bash
cd scanner && npm run bench:independent -- --json 2>&1 | tee /tmp/independent-baseline.json
```

Budget: per `bench/independent/README.md`, the full 110-entry population takes roughly 32 minutes.

- [ ] **Step 3: Read and record the result**

```bash
cat bench/independent/RESULT.json
```

Confirm `measuredAt`, `engineVersion`, and the `overall.fn` count (expected in the neighborhood of 96, per the 2026-08-15 snapshot — report the actual number, not the expected one, if they differ). This exact number is what Task 5 iterates.

- [ ] **Step 4: Commit the regenerated RESULT.json**

```bash
git add bench/independent/RESULT.json
git -c credential.helper='!gh auth git-credential' commit -m "$(cat <<'EOF'
chore(bench): re-measure independent population before root-cause audit

Fresh baseline on engine $(node -e "console.log(require('/Users/ross/code/agentic-security/scanner/package.json').version)") before auditing the false negatives, per R16's own
"re-measure before committing to the next milestone's scope" lesson.
EOF
)"
```

(Fill in the actual engine version from the command substitution before committing — do not leave the subshell unresolved in the final message if the shell doesn't expand it as expected; verify with `git log -1 --format=%B` after committing that the version number is a real number, not literal `$(...)` text.)

---

## Task 5: Run `why-missed.mjs` over every false negative

**Files:** `bench/independent/why-missed-output/*.json` (created, gitignored).

**Interfaces:**
- Consumes: `bench/independent/RESULT.json`'s per-entry breakdown (need the FN id list — `RESULT.json`'s schema per `bench/independent/runner.mjs`'s `main()` includes a `perEntry` array with `fn: 0|1` per entry; confirm the exact field name by reading the freshly-generated file from Task 4 before writing the filter, since this plan's earlier reads were of the OLD RESULT.json).

- [ ] **Step 1: Confirm `RESULT.json`'s per-entry shape**

```bash
node -e "
const r = require('/Users/ross/code/agentic-security/bench/independent/RESULT.json');
console.log(Object.keys(r));
console.log(JSON.stringify(r.perEntry ? r.perEntry[0] : r, null, 2).slice(0, 500));
"
```

- [ ] **Step 2: Extract the FN id list**

```bash
node -e "
const r = require('/Users/ross/code/agentic-security/bench/independent/RESULT.json');
const fnIds = (r.perEntry || []).filter(e => e.fn === 1).map(e => e.id);
console.log(fnIds.length);
require('fs').writeFileSync('/tmp/fn-ids.json', JSON.stringify(fnIds));
"
```

Verify the printed count matches `RESULT.json`'s `overall.fn` from Task 4 Step 3 — if not, stop and re-check the filter before proceeding (a silent mismatch here would audit the wrong set of entries).

- [ ] **Step 3: Run `why-missed.mjs` over the full FN list**

```bash
cd bench/independent
node -e "
const ids = require('/tmp/fn-ids.json');
console.log(ids.join(' '));
" > /tmp/fn-ids.txt
node why-missed.mjs $(cat /tmp/fn-ids.txt) 2>&1 | tee /tmp/why-missed-run.log
```

This re-scans each FN entry up to twice (default + guard-window-disabled), so expect roughly double the per-entry scan cost of Task 4 for this subset — report the actual wall-clock from `/tmp/why-missed-run.log`, not an estimate.

- [ ] **Step 4: Summarize the mechanical buckets**

```bash
node -e "
const fs = require('fs');
const dir = 'bench/independent/why-missed-output';
const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
const byBucket = {};
for (const f of files) {
  const r = JSON.parse(fs.readFileSync(dir + '/' + f, 'utf8'));
  byBucket[r.bucket] = (byBucket[r.bucket] || 0) + 1;
}
console.log(byBucket);
"
```

Report this breakdown plainly before moving to Task 6 — it's the first real signal of whether the population leans toward "shape doesn't occur" (`no-finding-at-all`) or "masked downstream" (`finding-present-but-suppressed`).

- [ ] **Step 5: No commit yet** — `why-missed-output/` is gitignored working data for Task 6, not a deliverable itself. Proceed directly.

---

## Task 6: Batch root-cause dispatch

**Files:** none created directly by this task — its deliverable is a set of structured verdicts consumed by Task 7. Written to `/tmp/root-cause-batch-<n>.json` (scratch, not committed) since the durable output is the doc Task 7/9 produces.

**Interfaces:**
- Consumes: `bench/independent/why-missed-output/*.json` (Task 5's output), `bench/independent/manifest.json` (entry metadata: id, cwe, language, repo, fixCommit).
- Produces: for each of the N entries, a verdict object `{id, category, subcategory, evidence, fixCandidate, fixDescription}` where `category` is `'shape-doesnt-occur'` | `'masked-downstream'`, `subcategory` for `shape-doesnt-occur` is `'missing-catalog'` | `'deeper-engine-gap'`, and for `masked-downstream` is the `mechanism` string `why-missed.mjs` reported (or a corrected one if the agent's own diff-reading disagrees with the mechanical bucket).

This task is executed live in this session, not written as shippable code — dispatch is an orchestration action, matching the approved design's Approach B. It is documented here as a task (with a concrete, checkable deliverable) rather than a code diff.

- [ ] **Step 1: Partition the FN list into batches of ~10-12**

```bash
node -e "
const ids = require('/tmp/fn-ids.json');
const batchSize = 11;
const batches = [];
for (let i = 0; i < ids.length; i += batchSize) batches.push(ids.slice(i, i + batchSize));
require('fs').writeFileSync('/tmp/rc-batches.json', JSON.stringify(batches));
console.log(batches.length, 'batches');
"
```

- [ ] **Step 2: Dispatch one `Agent` call per batch, in parallel**

For each batch, dispatch with `subagent_type: general-purpose`, `run_in_background: true` (all dispatched together in one message, per the tool's parallel-call guidance), a prompt built from this exact template (substitute `<BATCH_ENTRIES>` with the batch's full entry objects — id, cwe, language, repo, fixCommit, parentCommit, files — merged with each entry's `why-missed-output/<id>.json` content):

```
You're root-causing false negatives in a security scanner's independent
evaluation population — real GitHub Security Advisories, not synthetic
fixtures. For each of the following entries, the scanner failed to report
the labelled CWE when scanning the vulnerable (pre-fix) code.

For each entry you're given: its CWE label, language, repo, fix commit SHA,
parent (pre-fix) commit SHA, the files the fix touched, and a MECHANICAL
diagnosis from a diagnostic script (why-missed.mjs) — one of:
- not-actually-missing: script re-scan found it; likely a stale FN list
- finding-present-wrong-file-or-cwe: something fired, wrong file or CWE
- finding-present-but-suppressed: a candidate finding was found and
  suppressed, with a named mechanism (ignore-pragma / sanitized /
  custom-rule / guard-window / bench-shape / other) and a familyMatch
  boolean (does the suppressed finding's inferred vuln family match the
  advisory's CWE family?)
- no-finding-at-all: nothing fired anywhere near the mechanism's reach
- scan-error: couldn't be scanned

The mechanical bucket is a STARTING SIGNAL, not a verdict. For each entry:
1. Fetch and read the actual fix-commit diff:
   https://github.com/<repo>/commit/<fixCommit>
2. Read the pre-fix file(s) at bench/independent/cache/<id>/pre/<file> in
   this repo (already materialised locally — do not re-fetch).
3. Decide the real category:
   - "shape-doesnt-occur" if the vulnerable code genuinely doesn't match
     any capability the engine has (or should have) — subcategorize as
     "missing-catalog" if the source and sink are both real and
     recognizable but no catalog entry connects them (a clean addition),
     or "deeper-engine-gap" if the flow shape itself isn't modelled
     (cross-file, stored/second-order, container/collection-element,
     etc.).
   - "masked-downstream" if a real detection existed and was suppressed —
     confirm or correct the mechanical bucket's named mechanism by reading
     the actual pre-fix file at the reported line.
4. If the fix is small, localized, and low-risk (e.g. one clearly missing
   catalog entry, or a suppression mechanism that's obviously
   over-triggering on a pattern that should never match this shape), flag
   fixCandidate: true with a concrete fixDescription (exact file, exact
   change). Do not propose large or speculative fixes — if it's not small
   and obviously correct, leave fixCandidate: false and describe why in
   evidence instead.

Entries for this batch:
<BATCH_ENTRIES>

Return your findings via the schema tool call — one entry per input id, no
omissions. If an entry cannot be diagnosed (e.g. the diff is unreadable),
say so explicitly in evidence rather than guessing.
```

Use a JSON schema for the response (pass via whatever structured-output mechanism the dispatch supports) matching:
```json
{
  "type": "object",
  "properties": {
    "verdicts": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "category": {"type": "string", "enum": ["shape-doesnt-occur", "masked-downstream"]},
          "subcategory": {"type": "string"},
          "evidence": {"type": "string"},
          "fixCandidate": {"type": "boolean"},
          "fixDescription": {"type": "string"}
        },
        "required": ["id", "category", "evidence", "fixCandidate"]
      }
    }
  },
  "required": ["verdicts"]
}
```

- [ ] **Step 3: Collect all batch results**

As each batch's `Agent` call completes, save its `verdicts` array to `/tmp/root-cause-batch-<n>.json`. Once all batches have returned, concatenate:

```bash
node -e "
const fs = require('fs');
const batches = require('/tmp/rc-batches.json');
let all = [];
for (let i = 0; i < batches.length; i++) {
  const r = JSON.parse(fs.readFileSync('/tmp/root-cause-batch-' + i + '.json', 'utf8'));
  all = all.concat(r.verdicts);
}
fs.writeFileSync('/tmp/root-cause-all.json', JSON.stringify(all, null, 2));
console.log(all.length, 'verdicts collected, expected', require('/tmp/fn-ids.json').length);
"
```

Confirm the count matches the FN list length exactly — a shortfall means a batch dropped an entry, which must be re-dispatched for just the missing id(s) before proceeding.

---

## Task 7: Synthesis pass and fix triage

**Files:** none created directly — this task's output feeds Task 8's doc write-up and any fix lands as its own commit within this task.

**Interfaces:**
- Consumes: `/tmp/root-cause-all.json` (Task 6's collected verdicts).
- Produces: a rollup object (category/subcategory counts, per-mechanism counts for masked-downstream, per-language breakdown) and a short list of applied fixes.

Done directly, not delegated — the explicit mitigation for the batch-dispatch approach's stated weakness (a single batch can't see patterns across other batches).

- [ ] **Step 1: Compute the rollup**

```bash
node -e "
const v = require('/tmp/root-cause-all.json');
const byCat = {}, byMech = {}, byLang = {};
const manifest = require('/Users/ross/code/agentic-security/bench/independent/manifest.json');
const langOf = id => (manifest.entries.find(e => e.id === id) || {}).language || 'unknown';
for (const x of v) {
  byCat[x.category + (x.subcategory ? ':' + x.subcategory : '')] = (byCat[x.category + (x.subcategory ? ':' + x.subcategory : '')] || 0) + 1;
  byLang[langOf(x.id)] = (byLang[langOf(x.id)] || 0) + 1;
}
console.log('by category:', byCat);
console.log('by language:', byLang);
console.log('fix candidates:', v.filter(x => x.fixCandidate).length);
"
```

- [ ] **Step 2: Cross-reference for a shared root cause**

Read every `evidence` string across all verdicts (not just the `fixCandidate: true` ones) looking for a `mechanism`/pattern that recurs across many entries — e.g. if 8 of the 22 `masked-downstream` verdicts all cite `sanitized:` on a specific sanitizer family, that is a candidate systemic bug, not 8 independent ones, even if no single batch flagged it as `fixCandidate` (a batch only sees ~11 entries and may not recognize a pattern spanning batches).

- [ ] **Step 3: For each real `fixCandidate: true` entry, evaluate independently**

For each: read the actual `fixDescription` against the real source (`scanner/src/...`), confirm it's genuinely small and low-risk before applying. Reject (downgrade to a write-up-only candidate) anything that touches more than a handful of lines, touches shared/critical-path code without a clear blast-radius bound, or whose evidence is weaker on a second read than the batch agent's confidence implied.

- [ ] **Step 4: Apply accepted fixes, one at a time, each fully gated**

For each accepted fix:

```bash
cd /Users/ross/code/agentic-security
# apply the fix (Edit tool, exact file/lines from fixDescription)
cd scanner && npm run build   # only if scanner/src/ changed
cd scanner && npm test 2>&1 | tail -20   # capture exit code
cd scanner && npm run bench:cve-replay:check 2>&1 | tail -20   # capture exit code, must be 0
```

If either gate fails, revert the fix (`git checkout -- <files>`) and downgrade it to a write-up-only candidate in the final doc rather than force it through.

- [ ] **Step 5: Commit each accepted, gated fix separately**

```bash
git add <changed files>
git -c credential.helper='!gh auth git-credential' commit -m "$(cat <<'EOF'
fix(<area>): <specific bug from root-cause audit>

Found while root-causing independent-population false negative <id>
(<repo>, CWE-<n>). <One sentence on the actual defect.>
EOF
)"
```

- [ ] **Step 6: Re-run `bench:independent` if any fix landed**

```bash
find bench/independent/cache -type d -name .agentic-security -prune -exec rm -rf {} +
cd scanner && npm run bench:independent -- --json 2>&1 | tee /tmp/independent-post-fix.json
```

Compare `overall.fn`/`overall.recall` against Task 4's baseline. Report the real delta — including "0 entries moved" if that's what happened, per this session's whole point of not skipping the re-measurement.

---

## Task 8: Mining track — 6 languages, no cap

**Files:** `bench/independent/manifest.json` (modified — new entries appended).

**Interfaces:** none new — reuses `mine.mjs` as-is via CLI flags.

Independent of Tasks 5-7; can run concurrently in wall-clock terms, though within a single session it's simplest to run sequentially since both tracks use the same `gh api` rate-limited credential.

- [ ] **Step 1: Confirm `gh api` is reachable before starting**

```bash
gh api /rate_limit 2>&1
```

If this returns an error (503 or otherwise), stop this task and report it as blocked — do not proceed to hand-author entries.

- [ ] **Step 2: Mine each language, one ecosystem at a time**

`mine.mjs`'s `--limit` defaults to 25 and gates the loop (`if (added.length >= limit) break`); "no cap" per this session's scope means passing a limit far above what 3 pages (300 advisories) per ecosystem could ever admit — the loop's own `page <= 3` ceiling is the real cap, not `--limit`. Use `--limit 1000` to remove `--limit` as a binding constraint:

```bash
cd bench/independent
node mine.mjs --ecosystem maven --limit 1000 2>&1 | tee /tmp/mine-maven.log
node mine.mjs --ecosystem nuget --limit 1000 2>&1 | tee /tmp/mine-nuget.log
node mine.mjs --ecosystem composer --limit 1000 2>&1 | tee /tmp/mine-composer.log
node mine.mjs --ecosystem go --limit 1000 2>&1 | tee /tmp/mine-go.log
node mine.mjs --ecosystem rubygems --limit 1000 2>&1 | tee /tmp/mine-rubygems.log
```

(Java and Kotlin both come from the `maven` run, disambiguated per-file by `languageOf()`'s extension check — do not run a separate pass for Kotlin.)

- [ ] **Step 3: Check what actually landed per language**

```bash
node -e "
const m = require('/Users/ross/code/agentic-security/bench/independent/manifest.json');
const byLang = {};
for (const e of m.entries) byLang[e.language || 'unknown'] = (byLang[e.language || 'unknown'] || 0) + 1;
console.log(byLang);
"
```

Report the real counts — if `go` mining still yields 0 despite already being in `mine.mjs`'s default ecosystem list before this session, that's worth flagging explicitly (per the design doc's open question about why it was zero already) rather than silently re-running it and moving on.

- [ ] **Step 4: Commit the expanded manifest**

```bash
cd /Users/ross/code/agentic-security
git add bench/independent/manifest.json
git -c credential.helper='!gh auth git-credential' commit -m "$(cat <<'EOF'
chore(bench): mine independent-population entries for java/c#/kotlin/php/go/ruby

All six were at exactly zero entries out of 110 before this — the
independent population previously could not see any fix targeting
these languages, however real the underlying engine work. Per
mine.mjs's own admission rule (CWE + single fix commit + admissible
source extension), blind to what the engine detects.
EOF
)"
```

---

## Task 9: Materialise and score only the new entries

**Files:** Create `bench/independent/materialise-new.mjs`.

**Interfaces:**
- Consumes: `materialiseEntry` from `bench/independent/materialise.mjs` (already exported), `CACHE_DIR` (already exported).

`materialise-cli.mjs` iterates every entry in the manifest unconditionally — running it now would re-download and re-extract all 110 existing entries in addition to the new ones, which is wasted network and time given they're already cached and already scored in Task 4's `RESULT.json`.

- [ ] **Step 1: Write `materialise-new.mjs`**

```javascript
#!/usr/bin/env node
// Materialise only manifest entries not already present under cache/ — the
// existing 110 are already fetched and scored; re-running materialise-cli.mjs
// for the whole manifest after mining would re-download all of them for
// nothing. Same underlying materialiseEntry, just filtered to what's new.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { materialiseEntry, CACHE_DIR } from './materialise.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const man = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));

const isNew = (e) => !fs.existsSync(path.join(CACHE_DIR, e.id, 'pre'));
const targets = man.entries.filter(isNew);
process.stderr.write(`${targets.length} new entries to materialise (of ${man.entries.length} total)\n`);

let ok = 0, failed = 0;
for (const e of targets) {
  const scope = materialiseEntry(e);
  if (!scope) { failed++; process.stderr.write(`  ✗ ${e.id} — could not materialise; entry will be UNSCORED\n`); continue; }
  ok++;
  process.stderr.write(`  ✓ ${e.id}  ${scope.pre.dir || '(whole repo)'}  ${scope.pre.files} source file(s)\n`);
}
process.stderr.write(`\nmaterialised ${ok}, failed ${failed}, of ${targets.length} new entries\n`);
```

- [ ] **Step 2: Run it**

```bash
cd bench/independent && node materialise-new.mjs 2>&1 | tee /tmp/materialise-new.log
```

Budget note: per `README.md`, ~8 minutes materialised 40 JS/Python/TS entries — the new languages' entry count is only known after Task 8 Step 3, so report actual wall-clock here rather than estimating.

- [ ] **Step 3: Score the full, expanded population**

```bash
find bench/independent/cache -type d -name .agentic-security -prune -exec rm -rf {} +
cd scanner && npm run bench:independent -- --json 2>&1 | tee /tmp/independent-final.json
```

- [ ] **Step 4: Read and report the new per-language breakdown**

```bash
cat bench/independent/RESULT.json
```

Report `byLanguage` for the 6 newly-mined languages explicitly — this is the concrete answer to "does the population now have any signal for these languages at all."

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/independent/materialise-new.mjs bench/independent/RESULT.json
git -c credential.helper='!gh auth git-credential' commit -m "$(cat <<'EOF'
chore(bench): materialise and score newly-mined independent-population entries
EOF
)"
```

---

## Task 10: Write-up and final gate

**Files:**
- Create: `docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md`
- Modify: `bench/independent/README.md`

**Interfaces:** none new.

- [ ] **Step 1: Write `docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md`**

Structure, following this repo's existing PRD/doc conventions (see `docs/TAINT_RECALL_80PCT_PRD.md` §1.1 for the closest precedent of a per-entry root-cause table):

```markdown
# Independent-population false-negative root cause + language-coverage mining

**Status:** Complete.
**Date:** <today's actual date>
**Relationship to `DETECTION_GAP_REMEDIATION_PRD.md`:** operationalizes R16's
candidate next steps — root-cause the false negatives, and mine
currently-zero-coverage languages.

## 1. What this measured

<Baseline from Task 4, post-fix number from Task 7 Step 6 if any fix landed,
final number from Task 9 Step 3/4 including the newly-mined languages.
Every number here must trace to a specific command run in this session —
cite the file it came from (e.g. "bench/independent/RESULT.json,
measuredAt: <value>").>

## 2. Root-cause breakdown (96 entries)

<Table: category | subcategory | count, from Task 7 Step 1's rollup>

<Per-language breakdown>

<Per-mechanism breakdown for masked-downstream entries>

## 3. What was fixed inline

<List each fix from Task 7 Step 5's commits, with the entry id it was found
via, and the measured before/after independent-population delta from Task 7
Step 6. If zero fixes were accepted, say so plainly and why (e.g. "no
candidate was both small and confidently evidenced").>

## 4. Full per-entry table

<All 96 entries: id | language | cwe | category | subcategory | evidence
(truncated) | fix status>

## 5. Language coverage mining

<Table: language | entries mined | entries scored | recall, from Task 9>

<Any language that yielded 0 despite mining — name it and state why, per
mine.mjs's own stderr output from Task 8>

## 6. What this does and does not settle

<Honest limits section, mirroring DETECTION_GAP_REMEDIATION_PRD.md's R16
framing: what's now known with evidence vs. what remains open (e.g. if the
6 new languages' entry counts are too small to be statistically meaningful,
say MIN_RELIABLE_N applies, per runner.mjs)>
```

Fill in every `<...>` placeholder with the actual values from the session's own command output — this document itself must satisfy the same "no placeholders" rule as the plan.

- [ ] **Step 2: Add the pointer from `bench/independent/README.md`**

In the existing R16 section (after the "Reported plainly rather than explained away..." paragraph), add:

```markdown
**Follow-up root-cause audit (2026-08-17):** see
[`docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md`](../../docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md)
for the per-entry breakdown of all 96 false negatives from this
measurement, and the language-coverage mining that brought
java/c#/kotlin/php/go/ruby off zero.
```

- [ ] **Step 3: Full gate re-run before considering this plan done**

```bash
cd scanner
npm test 2>&1 | tail -30
npm run bench:cve-replay:check 2>&1 | tail -20
```
Capture both exit codes explicitly (`echo $?` after each). Both must be 0.

- [ ] **Step 4: Commit the write-up**

```bash
cd /Users/ross/code/agentic-security
git add docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md bench/independent/README.md
git -c credential.helper='!gh auth git-credential' commit -m "$(cat <<'EOF'
docs: independent-population root-cause audit + language-mining results

Closes out DETECTION_GAP_REMEDIATION_PRD.md's R16 candidate next
steps: all 96 false negatives root-caused (shape-doesn't-occur vs.
masked-downstream, with mechanism), java/c#/kotlin/php/go/ruby mined
from zero coverage.
EOF
)"
```

---

## Self-review notes (fixed inline before hand-off)

- Task 2's Step 3 initially referenced `whyMissed._vulnFamilyCache`, which is never defined anywhere in the plan — a placeholder-shaped bug. Fixed by replacing the closure with an explicit `Map` built via `Promise.all`/sequential `await` before `classifySuppressions` is called, so the final `why-missed.mjs` has no dangling reference.
- Confirmed `classifySuppressions`'s signature is consistent between Task 2's test file (`classifySuppressions(suppressions, entry)` — 2 args, using the module's own internal family inference) and its use inside `whyMissed` (3 args, with `inferFamilySync` passed in) — the test file's 2-arg calls exercise the `inferFamilySync` parameter's default (`null`, giving `familyMatch: null`) for the mechanism-derivation tests, and pass a real function only where `familyMatch`'s value is asserted. Verified by re-reading Task 2 Step 1's test file: `familyMatch` is asserted `true`/`false` only in the two tests that need it, matching this contract.
- `bench/independent/RESULT.json` is confirmed tracked (`git ls-files` lists it; `git check-ignore -v` exits 1) — Task 4 Step 4's commit is a real, reviewable diff, not a no-op. `bench/independent/cache/` is confirmed already gitignored (`.gitignore:104`); `why-missed-output/` was not, so Task 2 Step 7 adds it explicitly.
