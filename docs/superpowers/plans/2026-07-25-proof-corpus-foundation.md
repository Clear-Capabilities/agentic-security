# Proof Corpus Foundation — Implementation Plan (Phases 0–1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the IR-stats instrumentation and the proof-corpus bench harness, then prove the whole pipeline end-to-end by scanning two real third-party repositories (Ghost and Superset) and emitting verified metrics.

**Architecture:** Two layers. A small, default-off instrumentation module inside the scanner (`src/ir/ir-stats.js`) that reports per-language parse coverage and call-graph size to a JSON sidecar; and a standalone bench harness under `bench/proof-corpus/` that clones pinned commits of third-party repos into an out-of-tree cache, invokes the **committed bundle** against them, and assembles a results record. Every bench library module is a pure-ish unit with its own hermetic test; only the final task touches the network.

**Tech Stack:** Node ≥ 24, ESM throughout, `node:test` + `node:assert/strict`, `node:child_process` for git and scanner invocation. No new dependencies.

## Global Constraints

Copied from `CLAUDE.md` and `scanner/CLAUDE.md`. Every task's requirements implicitly include this section.

- **ESM only.** `import`/`export`. No CommonJS anywhere in `scanner/src/` or `bench/`.
- **Node ≥ 24.** Verified present: v24.16.0.
- **No new runtime dependencies.** Nothing added to `scanner/package.json` `dependencies`.
- **No runtime cloud calls in the scanner.** The bench may use the network (git clone); the scanner instrumentation may not.
- **Rebuild after `src/` changes.** `cd scanner && npm run build` before anything relies on `dist/agentic-security.mjs`. Unit tests run against `src/` and do not need a rebuild.
- **Confirm every mutation landed.** After any `Edit`, re-read the region or `grep` for the exact string added. "I edited it" is not "it changed."
- **Numbers require the run that produced them.** Never state a coverage figure, test count, or timing unless it came from a command executed in the same session. Otherwise say "not re-verified."
- **Capture exit codes for anything that gates.** Prove both directions: exit 0 on good input, non-zero on deliberately bad input.
- **Never name any external or competitor tool** in code, comments, docs, or commit messages.
- **Determinism.** Never use `Date.now()` in a finding ID. The IR-stats sidecar contains no timestamp so it is byte-diffable.
- **New test files must be wired into a scoped script** in `scanner/package.json`, or they never run in CI.

---

## Scope Note — why this plan covers only Phases 0–1

the Proof Corpus PRD (removed post-implementation) v1.1 spans three workstreams and eight phases. Those are genuinely independent subsystems, and per the writing-plans scope check they get separate plans:

| Plan | PRD phases | Independently valuable deliverable |
|---|---|---|
| **This plan** | 0–1 | Instrumentation + harness; two repos scanned with verified metrics |
| Plan 2 | 2 | Breadth pass over all ten; scorecard v1; gap register; Godot pre-parser baseline |
| Plan 3 | 3–4 | `parser-cpp.js` and its integration — touches `scanner/src/`, independent of the bench |
| Plan 4 | 5–7 | CVE replay, reporting, gating |

This plan is the foundation both branches need: Plan 2 consumes the harness, Plan 3 consumes the IR-stats instrument as its acceptance measurement.

---

## File Structure

**Scanner changes (Phase 0)**

| File | Responsibility |
|---|---|
| `scanner/src/ir/ir-stats.js` | *Create.* Pure functions: extension→language map mirroring the `ir/index.js` dispatch, stats collection from IR, sidecar write. No I/O except the single explicit write. |
| `scanner/src/engine.js` | *Modify.* Two surgical edits: build IR when stats are requested (today IR is built only under deep mode), and share that IR with the deep block so it is never built twice. |
| `scanner/test/ir-stats.test.js` | *Create.* Unit tests for the pure functions. |
| `scanner/package.json` | *Modify.* Add the test file to `test:dataflow`. |

**Bench harness (Phase 1)**

| File | Responsibility |
|---|---|
| `bench/proof-corpus/lib/licence.mjs` | Detect an SPDX identifier from licence text and repo files. |
| `bench/proof-corpus/lib/clone.mjs` | Cache-dir resolution and idempotent blobless fetch of a pinned commit. |
| `bench/proof-corpus/lib/irstats.mjs` | Read and normalise the scanner's sidecar into a coverage summary. |
| `bench/proof-corpus/lib/scan.mjs` | Invoke the bundle as a subprocess; capture exit code, wall time, peak RSS. |
| `bench/proof-corpus/manifest.json` | The ten targets. Commits start `null` and are filled by `--refresh-pins`. |
| `bench/proof-corpus/runner.mjs` | CLI orchestrator tying the libs together. |
| `bench/proof-corpus/README.md` | How to run it; what the cache is; how pinning works. |
| `bench/proof-corpus/.gitignore` | Keep raw findings out of git (disclosure boundary, PRD §9.1). |
| `scanner/test/proof-corpus-lib.test.js` | Hermetic tests for the bench libs. No network. |
| `scanner/package.json` | Add `bench:proof-corpus*` scripts and wire the new test into `test:bench-modules`. |

**Deliberate divergence from `bench/cve-replay/runner.mjs`:** that runner imports `runScan` from `src/` directly. This harness invokes the **committed bundle** as a subprocess instead, per PRD §5.3 — the bundle is what users actually run, and a bench passing on `src/` while the bundle is stale is the exact false-confidence failure the verification rules exist to prevent. Do not "fix" this to match the older runner.

---

## Task 1: IR-stats collector module

**Files:**
- Create: `scanner/src/ir/ir-stats.js`
- Test: `scanner/test/ir-stats.test.js`
- Modify: `scanner/package.json` (add test to `test:dataflow`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `languageOfFile(file: string) → string | null`
  - `collectIrStats(fileContents: Record<string,string>, perFile: Record<string,object>, callGraph: {functions: Map, edges: Array} | null) → StatsObject`
  - `irStatsTarget() → string | null`
  - `writeIrStats(target: string, stats: StatsObject) → void`
  - `StatsObject = { languages: Record<string, {inScope, parsed, functions, failures: string[]}>, callGraph: {functions, edges, resolvedEdges, unresolvedEdges}, totals: {inScope, parsed, functions} }`

- [ ] **Step 1: Write the failing test**

Create `scanner/test/ir-stats.test.js`:

```javascript
// Tests for the IR-stats instrumentation (proof-corpus Phase 0).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  languageOfFile,
  collectIrStats,
  irStatsTarget,
  writeIrStats,
} from '../src/ir/ir-stats.js';

test('languageOfFile: maps the dispatched extensions', () => {
  assert.equal(languageOfFile('a/b.js'), 'javascript');
  assert.equal(languageOfFile('a/b.tsx'), 'javascript');
  assert.equal(languageOfFile('a/b.mjs'), 'javascript');
  assert.equal(languageOfFile('a/b.py'), 'python');
  assert.equal(languageOfFile('a/b.java'), 'java');
  assert.equal(languageOfFile('a/b.cs'), 'csharp');
  assert.equal(languageOfFile('a/b.kt'), 'kotlin');
  assert.equal(languageOfFile('a/b.go'), 'go');
  assert.equal(languageOfFile('a/b.php'), 'php');
  assert.equal(languageOfFile('a/b.phtml'), 'php');
  assert.equal(languageOfFile('a/b.rb'), 'ruby');
});

test('languageOfFile: C/C++ is in the map so the pre-parser baseline is measurable', () => {
  assert.equal(languageOfFile('a/b.cpp'), 'cpp');
  assert.equal(languageOfFile('a/b.h'), 'cpp');
  assert.equal(languageOfFile('a/b.c'), 'cpp');
});

test('languageOfFile: unknown extensions and bad input return null', () => {
  assert.equal(languageOfFile('a/b.txt'), null);
  assert.equal(languageOfFile('README'), null);
  assert.equal(languageOfFile(null), null);
  assert.equal(languageOfFile(42), null);
});

test('collectIrStats: counts in-scope vs parsed per language', () => {
  const fileContents = {
    'a.js': 'x', 'b.js': 'y', 'c.py': 'z', 'd.txt': 'ignored',
  };
  const perFile = {
    'a.js': { file: 'a.js', functions: [{ qid: 'a.js::f@1#aa' }, { qid: 'a.js::g@5#bb' }] },
    'c.py': { file: 'c.py', functions: [{ qid: 'c.py::h@1#cc' }] },
  };
  const stats = collectIrStats(fileContents, perFile, null);
  assert.equal(stats.languages.javascript.inScope, 2);
  assert.equal(stats.languages.javascript.parsed, 1);
  assert.equal(stats.languages.javascript.functions, 2);
  assert.deepEqual(stats.languages.javascript.failures, ['b.js']);
  assert.equal(stats.languages.python.inScope, 1);
  assert.equal(stats.languages.python.parsed, 1);
  assert.equal(stats.totals.inScope, 3);
  assert.equal(stats.totals.parsed, 2);
  assert.equal(stats.totals.functions, 3);
  assert.ok(!('txt' in stats.languages), 'unknown extensions are not tracked');
});

test('collectIrStats: a file with an empty function list counts as a failure', () => {
  const stats = collectIrStats(
    { 'a.js': 'x' },
    { 'a.js': { file: 'a.js', functions: [] } },
    null,
  );
  assert.equal(stats.languages.javascript.parsed, 0);
  assert.deepEqual(stats.languages.javascript.failures, ['a.js']);
});

test('collectIrStats: summarises call-graph size and resolution', () => {
  const callGraph = {
    functions: new Map([['q1', {}], ['q2', {}]]),
    edges: [
      { caller: 'q1', callee: 'q2' },
      { caller: 'q1', callee: null },
      { caller: 'q2', callee: 'q1' },
    ],
  };
  const stats = collectIrStats({ 'a.js': 'x' }, {}, callGraph);
  assert.equal(stats.callGraph.functions, 2);
  assert.equal(stats.callGraph.edges, 3);
  assert.equal(stats.callGraph.resolvedEdges, 2);
  assert.equal(stats.callGraph.unresolvedEdges, 1);
});

test('collectIrStats: failures are capped and sorted for determinism', () => {
  const fileContents = {};
  for (let i = 0; i < 250; i++) fileContents[`f${String(i).padStart(3, '0')}.js`] = 'x';
  const stats = collectIrStats(fileContents, {}, null);
  assert.equal(stats.languages.javascript.inScope, 250);
  assert.equal(stats.languages.javascript.parsed, 0);
  assert.equal(stats.languages.javascript.failures.length, 200, 'failure list is capped at 200');
  assert.equal(stats.languages.javascript.failures[0], 'f000.js', 'failures are sorted');
});

test('collectIrStats: tolerates null and undefined inputs', () => {
  const stats = collectIrStats(null, null, null);
  assert.equal(stats.totals.inScope, 0);
  assert.equal(stats.callGraph.functions, 0);
});

test('irStatsTarget: reads the env var, empty means off', () => {
  const prev = process.env.AGENTIC_SECURITY_IR_STATS;
  try {
    delete process.env.AGENTIC_SECURITY_IR_STATS;
    assert.equal(irStatsTarget(), null);
    process.env.AGENTIC_SECURITY_IR_STATS = '';
    assert.equal(irStatsTarget(), null);
    process.env.AGENTIC_SECURITY_IR_STATS = '/tmp/x.json';
    assert.equal(irStatsTarget(), '/tmp/x.json');
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_IR_STATS;
    else process.env.AGENTIC_SECURITY_IR_STATS = prev;
  }
});

test('writeIrStats: writes sorted, timestamp-free JSON and creates parent dirs', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irstats-'));
  const target = path.join(dir, 'nested', 'stats.json');
  const stats = collectIrStats({ 'a.js': 'x' }, {}, null);
  writeIrStats(target, stats);
  const raw = fs.readFileSync(target, 'utf8');
  assert.ok(!/\d{4}-\d{2}-\d{2}T/.test(raw), 'sidecar must contain no timestamp');
  const parsed = JSON.parse(raw);
  assert.equal(parsed.languages.javascript.inScope, 1);
  writeIrStats(target, stats);
  assert.equal(fs.readFileSync(target, 'utf8'), raw, 'two writes of equal stats are byte-identical');
  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/ir-stats.test.js
```

Expected: FAIL — `Cannot find module '../src/ir/ir-stats.js'`.

- [ ] **Step 3: Write the implementation**

Create `scanner/src/ir/ir-stats.js`:

```javascript
// IR parse-coverage instrumentation (proof-corpus Phase 0). Default OFF.
//
// Answers one question the scanner could not previously answer: for each
// language, how many of the files we claim to support did we actually turn
// into IR? That is the difference between recognising an extension and
// supporting a language, and it is the headline metric of the proof corpus
// bench (the Proof Corpus PRD §5.4).
//
// Enable by setting AGENTIC_SECURITY_IR_STATS to an output path. The sidecar
// deliberately contains NO timestamp so two runs over identical input produce
// byte-identical output and the bench can diff them.

import * as fs from 'node:fs';
import * as path from 'node:path';

// Mirrors the dispatch in ./index.js. When a language is added there, add it
// here or its files silently report as out of scope.
//
// C/C++ is intentionally present even though ./index.js does NOT yet dispatch
// it: that is the point. It reports inScope>0 / parsed=0 today, which is the
// baseline the C++ parser workstream is measured against.
const EXT_TO_LANG = {
  js: 'javascript', jsx: 'javascript', ts: 'javascript', tsx: 'javascript',
  mjs: 'javascript', cjs: 'javascript',
  py: 'python',
  java: 'java',
  cs: 'csharp',
  kt: 'kotlin',
  go: 'go',
  php: 'php', phtml: 'php',
  rb: 'ruby',
  c: 'cpp', cc: 'cpp', cpp: 'cpp', cxx: 'cpp',
  h: 'cpp', hh: 'cpp', hpp: 'cpp', hxx: 'cpp',
};

// Cap the per-language failure list so a multi-million-line repo can't write a
// gigabyte sidecar. The counts stay exact; only the sample is truncated.
const _MAX_FAILURES_LISTED = 200;

export function languageOfFile(file) {
  if (typeof file !== 'string') return null;
  const dot = file.lastIndexOf('.');
  if (dot < 0 || dot === file.length - 1) return null;
  return EXT_TO_LANG[file.slice(dot + 1).toLowerCase()] || null;
}

export function collectIrStats(fileContents, perFile, callGraph) {
  const languages = {};
  const ir = perFile || {};
  const failuresByLang = {};

  for (const file of Object.keys(fileContents || {})) {
    const lang = languageOfFile(file);
    if (!lang) continue;
    if (!languages[lang]) {
      languages[lang] = { inScope: 0, parsed: 0, functions: 0, failures: [] };
      failuresByLang[lang] = [];
    }
    const bucket = languages[lang];
    bucket.inScope++;
    const rec = ir[file];
    const fnCount = rec && Array.isArray(rec.functions) ? rec.functions.length : 0;
    if (fnCount > 0) {
      bucket.parsed++;
      bucket.functions += fnCount;
    } else {
      failuresByLang[lang].push(file);
    }
  }

  // Sort then truncate — a stable sample rather than whichever files happened
  // to be enumerated first.
  for (const [lang, list] of Object.entries(failuresByLang)) {
    list.sort();
    languages[lang].failures = list.slice(0, _MAX_FAILURES_LISTED);
  }

  const edges = (callGraph && Array.isArray(callGraph.edges)) ? callGraph.edges : [];
  const resolvedEdges = edges.filter(e => e && e.callee).length;
  const fnMap = callGraph && callGraph.functions;
  const cgFunctions = fnMap && typeof fnMap.size === 'number'
    ? fnMap.size
    : (fnMap ? Object.keys(fnMap).length : 0);

  const totals = { inScope: 0, parsed: 0, functions: 0 };
  for (const b of Object.values(languages)) {
    totals.inScope += b.inScope;
    totals.parsed += b.parsed;
    totals.functions += b.functions;
  }

  // Rebuild the languages object in sorted key order so JSON.stringify is stable.
  const sortedLanguages = {};
  for (const k of Object.keys(languages).sort()) sortedLanguages[k] = languages[k];

  return {
    languages: sortedLanguages,
    callGraph: {
      functions: cgFunctions,
      edges: edges.length,
      resolvedEdges,
      unresolvedEdges: edges.length - resolvedEdges,
    },
    totals,
  };
}

export function irStatsTarget() {
  const v = process.env.AGENTIC_SECURITY_IR_STATS;
  return (typeof v === 'string' && v.length > 0) ? v : null;
}

export function writeIrStats(target, stats) {
  const dir = path.dirname(target);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(target, JSON.stringify(stats, null, 2) + '\n', 'utf8');
}

export const _internals = { EXT_TO_LANG, _MAX_FAILURES_LISTED };
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/ir-stats.test.js
```

Expected: PASS, 10 tests.

- [ ] **Step 5: Wire the test into the `test:dataflow` scope**

In `scanner/package.json`, find the `"test:dataflow"` line and append ` test/ir-stats.test.js` immediately before the closing quote — that is, change the tail of the value from:

```
test/callgraph-resolve.test.js test/import-reachability.test.js
```

to:

```
test/callgraph-resolve.test.js test/import-reachability.test.js test/ir-stats.test.js
```

- [ ] **Step 6: Confirm the wiring landed and the scope still runs**

```bash
cd /Users/ross/code/agentic-security/scanner && grep -c 'test/ir-stats.test.js' package.json && npm run test:dataflow 2>&1 | tail -15
```

Expected: `grep -c` prints `1`, and the dataflow suite passes. If `grep -c` prints `0`, the edit did not land — fix it before continuing.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/ir/ir-stats.js scanner/test/ir-stats.test.js scanner/package.json
git commit -m "feat(ir): add default-off IR parse-coverage instrumentation

Adds src/ir/ir-stats.js: per-language inScope/parsed/functions counts plus
call-graph size and edge resolution, written to a JSON sidecar when
AGENTIC_SECURITY_IR_STATS names an output path.

The sidecar carries no timestamp so two runs over identical input are
byte-identical. C/C++ extensions are in the language map deliberately even
though ir/index.js does not dispatch them yet — reporting inScope>0 parsed=0
is the baseline the C++ parser work will be measured against."
```

---

## Task 2: Wire IR stats into the engine

**Files:**
- Modify: `scanner/src/engine.js` (import; two edits around the deep-analysis block near line 8159)

**Interfaces:**
- Consumes: `collectIrStats`, `irStatsTarget`, `writeIrStats` from Task 1.
- Produces: a sidecar file written during any scan run with `AGENTIC_SECURITY_IR_STATS` set. No new exports.

**Context you need:** `buildProjectIR(fc)` is called at exactly one place in the whole codebase — inside the `_deepEnabled` branch. So today IR exists only when `AGENTIC_SECURITY_DEEP=1`. Stats must not require deep mode (deep mode is expensive and is auto-disabled under CI), but when both are on, IR must be built **once**, not twice — on a multi-million-line repo that difference is minutes.

- [ ] **Step 1: Add the import**

In `scanner/src/engine.js`, find this existing line (around line 145):

```javascript
import { buildProjectIR } from './ir/index.js';
```

Add immediately after it:

```javascript
import { collectIrStats, irStatsTarget, writeIrStats } from './ir/ir-stats.js';
```

- [ ] **Step 2: Insert the stats block before the deep-mode gate**

Find this exact line (unique in the file):

```javascript
  const _deepRequested = process.env.AGENTIC_SECURITY_DEEP === '1';
```

Insert immediately **before** it:

```javascript
  // ── IR parse-coverage sidecar (proof-corpus instrumentation, default off) ──
  // Built ahead of the deep-mode gate so coverage is measurable without paying
  // for taint analysis, and stashed in _sharedIR so the deep block below reuses
  // it rather than parsing the project twice.
  let _sharedIR = null;
  const _irStatsTarget = irStatsTarget();
  if (_irStatsTarget) {
    try {
      _sharedIR = buildProjectIR(fc);
      writeIrStats(_irStatsTarget, collectIrStats(fc, _sharedIR.perFile, _sharedIR.callGraph));
    } catch (e) {
      // Instrumentation must never fail a scan. Surface only when debugging.
      if (process.env.AGENTIC_SECURITY_IR_STATS_DEBUG === '1') {
        process.stderr.write(`ir-stats: ${e && e.message}\n`);
      }
    }
  }
```

- [ ] **Step 3: Make the deep block reuse the shared IR**

Find this exact line (the only `buildProjectIR` call site outside `ir/index.js`):

```javascript
      const { perFile, callGraph } = buildProjectIR(fc);
```

Replace it with:

```javascript
      const { perFile, callGraph } = _sharedIR || (_sharedIR = buildProjectIR(fc));
```

- [ ] **Step 4: Confirm all three edits landed**

```bash
cd /Users/ross/code/agentic-security/scanner
grep -n "ir-stats.js" src/engine.js
grep -n "_sharedIR" src/engine.js
grep -c "buildProjectIR(fc)" src/engine.js
```

Expected: the import line is found; `_sharedIR` appears on 4 lines (declaration, assignment in the stats block, and the two halves of the `||` expression); `buildProjectIR(fc)` appears exactly 2 times. If any count is wrong, an edit did not land — fix before continuing.

- [ ] **Step 5: Verify the sidecar is produced end-to-end against a real fixture**

```bash
cd /Users/ross/code/agentic-security/scanner
rm -f /tmp/irstats-smoke.json
AGENTIC_SECURITY_IR_STATS=/tmp/irstats-smoke.json node bin/agentic-security.js scan test/fixtures/vulnerable-js >/dev/null 2>&1
echo "exit=$?"
cat /tmp/irstats-smoke.json
```

Expected: the file exists and `languages.javascript.parsed` is ≥ 1. If the file is missing, the stats block is not on the executed path — do not proceed.

- [ ] **Step 6: Verify stats mode does NOT require deep mode, and costs nothing when off**

```bash
cd /Users/ross/code/agentic-security/scanner
rm -f /tmp/irstats-off.json
node bin/agentic-security.js scan test/fixtures/vulnerable-js >/dev/null 2>&1
test ! -f /tmp/irstats-off.json && echo "OK: no sidecar written when env unset"
```

Expected: prints the OK line.

- [ ] **Step 7: Verify determinism — two runs, byte-identical**

```bash
cd /Users/ross/code/agentic-security/scanner
AGENTIC_SECURITY_IR_STATS=/tmp/irstats-a.json node bin/agentic-security.js scan test/fixtures/vulnerable-js >/dev/null 2>&1
AGENTIC_SECURITY_IR_STATS=/tmp/irstats-b.json node bin/agentic-security.js scan test/fixtures/vulnerable-js >/dev/null 2>&1
diff /tmp/irstats-a.json /tmp/irstats-b.json && echo "OK: byte-identical"
```

Expected: prints the OK line with no diff output.

- [ ] **Step 8: Run the full gate and rebuild the bundle**

```bash
cd /Users/ross/code/agentic-security/scanner && npm test 2>&1 | tail -20 && npm run build 2>&1 | tail -3
```

Expected: the suite passes and the build emits the bundle plus its `.sha256` sidecar. `engine.js` is core — a regression here breaks everything downstream, so the full gate is required, not a scoped subset.

- [ ] **Step 9: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/engine.js scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "feat(engine): emit IR parse-coverage sidecar when requested

Builds project IR ahead of the deep-mode gate when AGENTIC_SECURITY_IR_STATS
is set, so parse coverage is measurable without enabling deep taint analysis
(which is expensive and auto-disables under CI). The deep block reuses the
same IR via _sharedIR rather than parsing the project a second time.

Instrumentation failures are swallowed and never fail a scan; set
AGENTIC_SECURITY_IR_STATS_DEBUG=1 to surface them."
```

---

## Task 3: Licence detector

**Files:**
- Create: `bench/proof-corpus/lib/licence.mjs`
- Test: `scanner/test/proof-corpus-lib.test.js` (created here; extended by Tasks 4 and 6)
- Modify: `scanner/package.json` (add test to `test:bench-modules`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `detectLicenceText(text: string) → string | null` — SPDX id
  - `detectLicence(repoDir: string) → { spdx: string|null, source: 'file'|'package-json'|'none', file: string|null }`

- [ ] **Step 1: Write the failing test**

Create `scanner/test/proof-corpus-lib.test.js`:

```javascript
// Hermetic tests for the proof-corpus bench libraries. No network access.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { detectLicenceText, detectLicence } from '../../bench/proof-corpus/lib/licence.mjs';

function tmpRepo() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'proofcorpus-'));
}

test('detectLicenceText: identifies permissive licences', () => {
  assert.equal(detectLicenceText('MIT License\n\nPermission is hereby granted, free of charge'), 'MIT');
  assert.equal(detectLicenceText('Apache License\nVersion 2.0, January 2004'), 'Apache-2.0');
});

test('detectLicenceText: identifies copyleft and network-copyleft licences', () => {
  assert.equal(detectLicenceText('GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991'), 'GPL-2.0');
  assert.equal(detectLicenceText('GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007'), 'GPL-3.0');
  assert.equal(detectLicenceText('GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007'), 'AGPL-3.0');
});

test('detectLicenceText: identifies source-available licences', () => {
  assert.equal(detectLicenceText('Business Source License 1.1\n\nParameters'), 'BUSL-1.1');
  assert.equal(detectLicenceText('Functional Source License, Version 1.1, ALv2 Future License'), 'FSL-1.1');
});

test('detectLicenceText: returns null on unrecognised or empty text', () => {
  assert.equal(detectLicenceText('This is a readme about cats.'), null);
  assert.equal(detectLicenceText(''), null);
  assert.equal(detectLicenceText(null), null);
});

test('detectLicence: reads a LICENSE file from the repo root', () => {
  const dir = tmpRepo();
  fs.writeFileSync(path.join(dir, 'LICENSE'), 'MIT License\n\nPermission is hereby granted, free of charge');
  const r = detectLicence(dir);
  assert.equal(r.spdx, 'MIT');
  assert.equal(r.source, 'file');
  assert.equal(r.file, 'LICENSE');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('detectLicence: falls back to the package.json license field', () => {
  const dir = tmpRepo();
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ license: 'AGPL-3.0' }));
  const r = detectLicence(dir);
  assert.equal(r.spdx, 'AGPL-3.0');
  assert.equal(r.source, 'package-json');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('detectLicence: a LICENSE file wins over package.json', () => {
  const dir = tmpRepo();
  fs.writeFileSync(path.join(dir, 'COPYING'), 'GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ license: 'MIT' }));
  const r = detectLicence(dir);
  assert.equal(r.spdx, 'GPL-2.0');
  assert.equal(r.source, 'file');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('detectLicence: reports none for a repo with no licence and never throws', () => {
  const dir = tmpRepo();
  const r = detectLicence(dir);
  assert.equal(r.spdx, null);
  assert.equal(r.source, 'none');
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(detectLicence('/nonexistent/path/xyz').source, 'none');
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/proof-corpus-lib.test.js
```

Expected: FAIL — cannot find `../../bench/proof-corpus/lib/licence.mjs`.

- [ ] **Step 3: Write the implementation**

Create `bench/proof-corpus/lib/licence.mjs`:

```javascript
// Licence detection for proof-corpus targets.
//
// Detects an SPDX identifier from a repository's licence file, falling back to
// a package manifest's declared field. Text matching is deliberately anchored
// on the distinctive title lines rather than full-text comparison: we need the
// licence *family* for the scorecard, not a legal determination.

import * as fs from 'node:fs';
import * as path from 'node:path';

// Order matters: AGPL must be tested before GPL because its title contains
// "GENERAL PUBLIC LICENSE" as a substring.
const PATTERNS = [
  { spdx: 'AGPL-3.0', re: /GNU AFFERO GENERAL PUBLIC LICENSE\s*\n?\s*Version 3/i },
  { spdx: 'LGPL-3.0', re: /GNU LESSER GENERAL PUBLIC LICENSE\s*\n?\s*Version 3/i },
  { spdx: 'LGPL-2.1', re: /GNU LESSER GENERAL PUBLIC LICENSE\s*\n?\s*Version 2\.1/i },
  { spdx: 'GPL-3.0', re: /GNU GENERAL PUBLIC LICENSE\s*\n?\s*Version 3/i },
  { spdx: 'GPL-2.0', re: /GNU GENERAL PUBLIC LICENSE\s*\n?\s*Version 2/i },
  { spdx: 'Apache-2.0', re: /Apache License\s*\n?\s*Version 2\.0/i },
  { spdx: 'BUSL-1.1', re: /Business Source License 1\.1/i },
  { spdx: 'FSL-1.1', re: /Functional Source License,?\s*Version 1\.1/i },
  { spdx: 'MPL-2.0', re: /Mozilla Public License Version 2\.0/i },
  { spdx: 'BSD-3-Clause', re: /Redistribution and use in source and binary forms[\s\S]{0,2000}?Neither the name of/i },
  { spdx: 'BSD-2-Clause', re: /Redistribution and use in source and binary forms/i },
  { spdx: 'ISC', re: /ISC License/i },
  { spdx: 'MIT', re: /MIT License|Permission is hereby granted, free of charge/i },
];

const LICENCE_FILES = [
  'LICENSE', 'LICENSE.md', 'LICENSE.txt',
  'LICENCE', 'LICENCE.md', 'LICENCE.txt',
  'COPYING', 'COPYING.txt',
];

export function detectLicenceText(text) {
  if (typeof text !== 'string' || !text) return null;
  // Only the head matters — the title block is at the top, and full-file
  // regex over a long licence is wasteful.
  const head = text.slice(0, 8000);
  for (const { spdx, re } of PATTERNS) {
    if (re.test(head)) return spdx;
  }
  return null;
}

export function detectLicence(repoDir) {
  const none = { spdx: null, source: 'none', file: null };
  if (typeof repoDir !== 'string') return none;

  for (const name of LICENCE_FILES) {
    let text;
    try {
      text = fs.readFileSync(path.join(repoDir, name), 'utf8');
    } catch { continue; }
    const spdx = detectLicenceText(text);
    if (spdx) return { spdx, source: 'file', file: name };
  }

  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(repoDir, 'package.json'), 'utf8'));
    const lic = typeof pkg.license === 'string' ? pkg.license : null;
    if (lic) return { spdx: lic, source: 'package-json', file: 'package.json' };
  } catch { /* absent or malformed — fall through */ }

  return none;
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/proof-corpus-lib.test.js
```

Expected: PASS, 8 tests.

- [ ] **Step 5: Wire the test into `test:bench-modules`**

In `scanner/package.json`, change the `"test:bench-modules"` value from:

```
node --test test/phase4-harness.test.js test/pipeline.test.js
```

to:

```
node --test test/phase4-harness.test.js test/pipeline.test.js test/proof-corpus-lib.test.js
```

- [ ] **Step 6: Confirm the wiring landed**

```bash
cd /Users/ross/code/agentic-security/scanner && grep -c 'test/proof-corpus-lib.test.js' package.json && npm run test:bench-modules 2>&1 | tail -8
```

Expected: `1`, then the suite passes.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/proof-corpus/lib/licence.mjs scanner/test/proof-corpus-lib.test.js scanner/package.json
git commit -m "feat(bench): add licence detection for proof-corpus targets

Detects an SPDX identifier from a repository's licence file with a fallback to
the package manifest field. Covers permissive, copyleft, network-copyleft and
source-available families, which is the licence-breadth axis the proof corpus
scorecard reports. AGPL is matched before GPL because its title contains the
GPL title as a substring."
```

---

## Task 4: Clone module

**Files:**
- Create: `bench/proof-corpus/lib/clone.mjs`
- Modify: `scanner/test/proof-corpus-lib.test.js` (append tests)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `cacheRoot() → string` — honours `AGENTIC_SECURITY_PROOF_CACHE`, else `~/.claude/agentic-security/proof-corpus-cache`
  - `repoDir(id: string) → string`
  - `currentCommit(dir: string) → string | null`
  - `ensureClone({id, url, commit}) → { dir: string, cached: boolean }`
  - `resolveRef(url: string, ref: string) → string` — `git ls-remote`, used by `--refresh-pins`

`ensureClone` throws when `commit` is null, with a message telling the operator to run `--refresh-pins`. Network-touching functions are not unit-tested; only the pure path logic and the guard are.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/proof-corpus-lib.test.js`:

```javascript
import { cacheRoot, repoDir, currentCommit, ensureClone } from '../../bench/proof-corpus/lib/clone.mjs';

test('cacheRoot: honours the env override', () => {
  const prev = process.env.AGENTIC_SECURITY_PROOF_CACHE;
  try {
    process.env.AGENTIC_SECURITY_PROOF_CACHE = '/tmp/custom-cache';
    assert.equal(cacheRoot(), '/tmp/custom-cache');
    delete process.env.AGENTIC_SECURITY_PROOF_CACHE;
    assert.ok(cacheRoot().endsWith(path.join('.claude', 'agentic-security', 'proof-corpus-cache')));
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_PROOF_CACHE;
    else process.env.AGENTIC_SECURITY_PROOF_CACHE = prev;
  }
});

test('repoDir: places each target in its own directory under the cache root', () => {
  const prev = process.env.AGENTIC_SECURITY_PROOF_CACHE;
  try {
    process.env.AGENTIC_SECURITY_PROOF_CACHE = '/tmp/custom-cache';
    assert.equal(repoDir('ghost'), path.join('/tmp/custom-cache', 'ghost'));
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_PROOF_CACHE;
    else process.env.AGENTIC_SECURITY_PROOF_CACHE = prev;
  }
});

test('repoDir: rejects ids that would escape the cache root', () => {
  assert.throws(() => repoDir('../escape'), /invalid target id/i);
  assert.throws(() => repoDir('a/b'), /invalid target id/i);
  assert.throws(() => repoDir(''), /invalid target id/i);
});

test('currentCommit: returns null for a directory that is not a git repo', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'notgit-'));
  assert.equal(currentCommit(dir), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('ensureClone: refuses an unpinned target and names the fix', () => {
  assert.throws(
    () => ensureClone({ id: 'ghost', url: 'https://example.invalid/x.git', commit: null }),
    /--refresh-pins/,
  );
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/proof-corpus-lib.test.js
```

Expected: FAIL — cannot find `../../bench/proof-corpus/lib/clone.mjs`.

- [ ] **Step 3: Write the implementation**

Create `bench/proof-corpus/lib/clone.mjs`:

```javascript
// Acquisition of proof-corpus targets.
//
// Clones are blobless and shallow, pinned to a full commit SHA, and live
// OUTSIDE the repository tree. Two reasons: reproducibility (a re-run months
// later produces the same numbers) and licence hygiene (we never hold a copy
// of third-party source in our own tree).

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

const _ID_RE = /^[a-z0-9][a-z0-9._-]*$/;

export function cacheRoot() {
  const override = process.env.AGENTIC_SECURITY_PROOF_CACHE;
  if (typeof override === 'string' && override.length > 0) return override;
  return path.join(os.homedir(), '.claude', 'agentic-security', 'proof-corpus-cache');
}

export function repoDir(id) {
  if (typeof id !== 'string' || !_ID_RE.test(id)) {
    throw new Error(`invalid target id: ${JSON.stringify(id)} (expected /^[a-z0-9][a-z0-9._-]*$/)`);
  }
  return path.join(cacheRoot(), id);
}

function _git(args, cwd, timeoutMs = 900_000) {
  return execFileSync('git', args, {
    cwd,
    timeout: timeoutMs,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
  }).trim();
}

export function currentCommit(dir) {
  try {
    return _git(['rev-parse', 'HEAD'], dir);
  } catch {
    return null;
  }
}

// Resolve a branch or tag name to a full SHA without cloning. Used by
// --refresh-pins so advancing a pin is a deliberate, reviewable act.
export function resolveRef(url, ref) {
  const out = _git(['ls-remote', url, ref], undefined, 120_000);
  const line = out.split('\n').find(Boolean);
  if (!line) throw new Error(`ref not found: ${ref} in ${url}`);
  return line.split(/\s+/)[0];
}

export function ensureClone(target) {
  const { id, url, commit } = target || {};
  if (!commit) {
    throw new Error(
      `target "${id}" has no pinned commit — run the runner with --refresh-pins to resolve it`,
    );
  }
  const dir = repoDir(id);

  if (currentCommit(dir) === commit) return { dir, cached: true };

  fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(path.join(dir, '.git'))) {
    _git(['init', '-q'], dir);
  }
  // Idempotent remote setup: set-url succeeds whether or not origin exists.
  try { _git(['remote', 'add', 'origin', url], dir); }
  catch { _git(['remote', 'set-url', 'origin', url], dir); }

  // Blobless partial clone: full history metadata is skipped and file contents
  // are fetched on demand, which is what keeps ten large repos tractable.
  _git(['fetch', '--depth', '1', '--filter=blob:none', 'origin', commit], dir);
  _git(['checkout', '-q', '--detach', 'FETCH_HEAD'], dir);

  return { dir, cached: false };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/proof-corpus-lib.test.js
```

Expected: PASS, 13 tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/proof-corpus/lib/clone.mjs scanner/test/proof-corpus-lib.test.js
git commit -m "feat(bench): add pinned blobless clone acquisition for proof corpus

Clones land outside the repository tree, pinned to a full commit SHA. An
unpinned target is a hard error naming --refresh-pins as the fix rather than a
silent fetch of a moving branch, so pin advancement stays deliberate. Target
ids are validated against a strict pattern so none can escape the cache root."
```

---

## Task 5: IR-stats reader

**Files:**
- Create: `bench/proof-corpus/lib/irstats.mjs`
- Modify: `scanner/test/proof-corpus-lib.test.js` (append tests)

**Interfaces:**
- Consumes: the sidecar format produced by `collectIrStats` (Task 1).
- Produces:
  - `readIrStats(file: string) → object | null`
  - `coverageSummary(stats: object|null) → { byLanguage: Record<string,{inScope,parsed,pct,functions}>, totals: {inScope,parsed,pct}, callGraph: {functions,edges,resolvedEdges,unresolvedEdges} }`

`pct` is an integer percentage 0–100, rounded, and is `null` when `inScope` is 0 — a language with no files has no coverage, which is different from 0% coverage.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/proof-corpus-lib.test.js`:

```javascript
import { readIrStats, coverageSummary } from '../../bench/proof-corpus/lib/irstats.mjs';

test('readIrStats: returns null for a missing or malformed file', () => {
  assert.equal(readIrStats('/nonexistent/stats.json'), null);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irread-'));
  const bad = path.join(dir, 'bad.json');
  fs.writeFileSync(bad, '{not json');
  assert.equal(readIrStats(bad), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('readIrStats: round-trips a written sidecar', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irread-'));
  const f = path.join(dir, 'stats.json');
  fs.writeFileSync(f, JSON.stringify({ languages: { go: { inScope: 3, parsed: 2, functions: 9, failures: [] } } }));
  const s = readIrStats(f);
  assert.equal(s.languages.go.parsed, 2);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('coverageSummary: computes rounded percentages per language', () => {
  const stats = {
    languages: {
      javascript: { inScope: 10, parsed: 9, functions: 40, failures: [] },
      cpp: { inScope: 500, parsed: 0, functions: 0, failures: [] },
    },
    callGraph: { functions: 12, edges: 30, resolvedEdges: 20, unresolvedEdges: 10 },
    totals: { inScope: 510, parsed: 9, functions: 40 },
  };
  const s = coverageSummary(stats);
  assert.equal(s.byLanguage.javascript.pct, 90);
  assert.equal(s.byLanguage.cpp.pct, 0, 'a supported-on-paper language at 0% must read as 0, not null');
  assert.equal(s.totals.pct, 2);
  assert.equal(s.callGraph.resolvedEdges, 20);
});

test('coverageSummary: pct is null when a language has no files in scope', () => {
  const s = coverageSummary({ languages: { ruby: { inScope: 0, parsed: 0, functions: 0, failures: [] } } });
  assert.equal(s.byLanguage.ruby.pct, null);
});

test('coverageSummary: tolerates null input', () => {
  const s = coverageSummary(null);
  assert.deepEqual(s.byLanguage, {});
  assert.equal(s.totals.pct, null);
  assert.equal(s.callGraph.functions, 0);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/proof-corpus-lib.test.js
```

Expected: FAIL — cannot find `../../bench/proof-corpus/lib/irstats.mjs`.

- [ ] **Step 3: Write the implementation**

Create `bench/proof-corpus/lib/irstats.mjs`:

```javascript
// Reader for the scanner's IR parse-coverage sidecar.
//
// Turns the raw counts written by scanner/src/ir/ir-stats.js into the
// percentages the scorecard reports. Kept separate from the writer so the
// bench can read sidecars produced by an older scanner build.

import * as fs from 'node:fs';

export function readIrStats(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

// A language with zero files in scope has no coverage figure at all, which is
// a different statement from 0% coverage. Keeping that distinction is what
// stops the scorecard claiming "0% Ruby" for a repo containing no Ruby.
function _pct(parsed, inScope) {
  if (!inScope) return null;
  return Math.round((parsed / inScope) * 100);
}

export function coverageSummary(stats) {
  const languages = (stats && stats.languages) || {};
  const byLanguage = {};
  for (const name of Object.keys(languages).sort()) {
    const l = languages[name] || {};
    const inScope = l.inScope || 0;
    const parsed = l.parsed || 0;
    byLanguage[name] = {
      inScope,
      parsed,
      functions: l.functions || 0,
      pct: _pct(parsed, inScope),
    };
  }

  const t = (stats && stats.totals) || {};
  const cg = (stats && stats.callGraph) || {};
  return {
    byLanguage,
    totals: {
      inScope: t.inScope || 0,
      parsed: t.parsed || 0,
      pct: _pct(t.parsed || 0, t.inScope || 0),
    },
    callGraph: {
      functions: cg.functions || 0,
      edges: cg.edges || 0,
      resolvedEdges: cg.resolvedEdges || 0,
      unresolvedEdges: cg.unresolvedEdges || 0,
    },
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/proof-corpus-lib.test.js
```

Expected: PASS, 18 tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/proof-corpus/lib/irstats.mjs scanner/test/proof-corpus-lib.test.js
git commit -m "feat(bench): add IR-stats reader and coverage summariser

Converts the scanner's raw sidecar counts into per-language percentages. A
language with no files in scope reports pct=null rather than 0, so the
scorecard cannot claim 0% coverage for a language the repository does not use."
```

---

## Task 6: Scan invocation with resource metrics

**Files:**
- Create: `bench/proof-corpus/lib/scan.mjs`
- Modify: `scanner/test/proof-corpus-lib.test.js` (append tests)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `bundlePath() → string` — absolute path to `scanner/dist/agentic-security.mjs`
  - `verifyBundle() → { ok: boolean, reason: string|null, sha: string|null }` — recomputes SHA-256 and compares against the `.sha256` sidecar
  - `runRepoScan({dir, statsPath, sarifPath, timeoutMs, extraEnv}) → Promise<{exitCode, wallMs, timedOut, peakRssKb, stderrTail}>`

Peak RSS is sampled by polling `ps -o rss= -p <pid>` every 500 ms. That is portable across macOS and Linux and needs no scanner change. On a platform where `ps` fails, `peakRssKb` is `null` — a missing measurement, never a fabricated zero.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/proof-corpus-lib.test.js`:

```javascript
import { bundlePath, verifyBundle, runRepoScan } from '../../bench/proof-corpus/lib/scan.mjs';

test('bundlePath: points at the committed bundle', () => {
  assert.ok(bundlePath().endsWith(path.join('scanner', 'dist', 'agentic-security.mjs')));
});

test('verifyBundle: the committed bundle matches its sha256 sidecar', () => {
  const r = verifyBundle();
  assert.equal(r.ok, true, `bundle verification failed: ${r.reason} — run "npm run build"`);
  assert.match(r.sha, /^[0-9a-f]{64}$/);
});

test('runRepoScan: scans a fixture, emits SARIF, and reports metrics', async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'proofscan-'));
  const statsPath = path.join(out, 'stats.json');
  const sarifPath = path.join(out, 'run.sarif');
  const fixture = path.resolve('test/fixtures/vulnerable-js');
  const r = await runRepoScan({ dir: fixture, statsPath, sarifPath, timeoutMs: 180_000 });
  assert.equal(r.timedOut, false);
  assert.ok(typeof r.exitCode === 'number');
  // Exit 4 is the lockfile-verification refusal. Seeing it here means someone
  // reintroduced --deterministic, which never scans on an unlocked tree.
  assert.notEqual(r.exitCode, 4, `scan refused before running: ${r.stderrTail}`);
  assert.ok(r.wallMs > 0);
  assert.ok(fs.existsSync(statsPath), 'the scan must produce the IR-stats sidecar');
  const stats = JSON.parse(fs.readFileSync(statsPath, 'utf8'));
  assert.ok(stats.languages.javascript.parsed >= 1);
  const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
  assert.ok(Array.isArray(sarif.runs), 'SARIF must be captured whole from stdout');
  fs.rmSync(out, { recursive: true, force: true });
});

test('runRepoScan: produces byte-identical SARIF across two runs', async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'proofdet-'));
  const fixture = path.resolve('test/fixtures/vulnerable-js');
  const a = path.join(out, 'a.sarif');
  const b = path.join(out, 'b.sarif');
  await runRepoScan({ dir: fixture, sarifPath: a, timeoutMs: 180_000 });
  await runRepoScan({ dir: fixture, sarifPath: b, timeoutMs: 180_000 });
  assert.equal(fs.readFileSync(a, 'utf8'), fs.readFileSync(b, 'utf8'));
  fs.rmSync(out, { recursive: true, force: true });
});

test('runRepoScan: reports a timeout rather than hanging', async () => {
  const fixture = path.resolve('test/fixtures/vulnerable-js');
  const r = await runRepoScan({ dir: fixture, timeoutMs: 1 });
  assert.equal(r.timedOut, true);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/proof-corpus-lib.test.js
```

Expected: FAIL — cannot find `../../bench/proof-corpus/lib/scan.mjs`.

- [ ] **Step 3: Write the implementation**

Create `bench/proof-corpus/lib/scan.mjs`:

```javascript
// Scanner invocation for the proof corpus.
//
// Deliberately invokes the COMMITTED BUNDLE as a subprocess rather than
// importing runScan from src/, which is what bench/cve-replay/runner.mjs does.
// The bundle is what users actually run; a bench that passes against src/ while
// the bundle is stale is exactly the false-confidence failure the project's
// verification rules exist to prevent. Do not "simplify" this to a src/ import.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const _HERE = path.dirname(fileURLToPath(import.meta.url));
const _SCANNER_DIR = path.resolve(_HERE, '..', '..', '..', 'scanner');

export function bundlePath() {
  return path.join(_SCANNER_DIR, 'dist', 'agentic-security.mjs');
}

export function verifyBundle() {
  const bundle = bundlePath();
  let buf;
  try {
    buf = fs.readFileSync(bundle);
  } catch {
    return { ok: false, reason: `bundle missing at ${bundle} — run "npm run build"`, sha: null };
  }
  const sha = crypto.createHash('sha256').update(buf).digest('hex');
  let sidecar;
  try {
    sidecar = fs.readFileSync(bundle + '.sha256', 'utf8').trim().split(/\s+/)[0];
  } catch {
    return { ok: false, reason: 'sha256 sidecar missing — run "npm run build"', sha };
  }
  if (sidecar !== sha) {
    return { ok: false, reason: 'bundle does not match its sha256 sidecar — run "npm run build"', sha };
  }
  return { ok: true, reason: null, sha };
}

// Poll the child's RSS. process.resourceUsage() only covers this process, and
// spawnSync gives no peak figure, so sampling `ps` is the portable option.
function _sampleRssKb(pid) {
  try {
    const out = execFileSync('ps', ['-o', 'rss=', '-p', String(pid)], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000,
    }).trim();
    const kb = parseInt(out, 10);
    return Number.isFinite(kb) ? kb : null;
  } catch {
    return null;
  }
}

export function runRepoScan(opts) {
  const {
    dir,
    statsPath = null,
    sarifPath = null,
    timeoutMs = 1_800_000,
    extraEnv = {},
  } = opts || {};

  return new Promise((resolve) => {
    // Two CLI facts this depends on, both verified against bin/agentic-security.js:
    //
    // 1. There is no `--sarif <path>` flag. SARIF comes from `--format sarif`
    //    on stdout, so we capture stdout to the file ourselves.
    // 2. We deliberately do NOT pass `--deterministic`. That flag calls
    //    verifyLockfile(), which returns {ok:false, mismatches:['no lockfile
    //    present']} and makes the CLI exit 4 WITHOUT SCANNING on any tree that
    //    has no committed .agentic-security rules lockfile — which is every
    //    third-party target. Setting the same two env vars the flag sets gives
    //    identical deterministic behaviour without the lockfile coupling.
    const args = ['scan', dir, '--format', 'sarif'];

    const env = {
      ...process.env,
      AGENTIC_SECURITY_DETERMINISTIC: '1',
      AGENTIC_SECURITY_OFFLINE: '1',
      ...extraEnv,
    };
    if (statsPath) env.AGENTIC_SECURITY_IR_STATS = statsPath;

    // Scan state accumulates inside the scanned tree and can mask results on a
    // re-run — CLAUDE.md's "wipe scan state before benchmarking" rule. The
    // determinism check scans the same tree twice, so this is not optional.
    try {
      fs.rmSync(path.join(dir, '.agentic-security'), { recursive: true, force: true });
    } catch { /* nothing to clear */ }

    const started = Date.now();
    const sarifStream = sarifPath ? fs.createWriteStream(sarifPath) : null;
    const child = spawn(process.execPath, [bundlePath(), ...args], {
      cwd: dir,
      env,
      stdio: ['ignore', sarifStream ? 'pipe' : 'ignore', 'pipe'],
    });
    if (sarifStream) child.stdout.pipe(sarifStream);

    let peakRssKb = null;
    const poll = setInterval(() => {
      const kb = _sampleRssKb(child.pid);
      if (kb !== null && (peakRssKb === null || kb > peakRssKb)) peakRssKb = kb;
    }, 500);

    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    let stderr = '';
    child.stderr.on('data', (d) => {
      stderr += d.toString();
      if (stderr.length > 64_000) stderr = stderr.slice(-64_000);
    });

    child.on('close', (code) => {
      clearInterval(poll);
      clearTimeout(timer);
      const finish = () => resolve({
        exitCode: code,
        wallMs: Date.now() - started,
        timedOut,
        peakRssKb,
        stderrTail: stderr.slice(-4000),
      });
      // Wait for the SARIF write to flush, or the determinism hash reads a
      // truncated file and reports a spurious mismatch.
      if (sarifStream) sarifStream.end(finish); else finish();
    });

    child.on('error', (err) => {
      clearInterval(poll);
      clearTimeout(timer);
      resolve({
        exitCode: null,
        wallMs: Date.now() - started,
        timedOut,
        peakRssKb,
        stderrTail: String(err && err.message),
      });
    });
  });
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/ross/code/agentic-security/scanner && npm run build >/dev/null 2>&1 && node --test test/proof-corpus-lib.test.js
```

Expected: PASS, 23 tests. The build runs first because `verifyBundle` gates on a current bundle — if it fails with "does not match its sha256 sidecar", the build did not run.

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/proof-corpus/lib/scan.mjs scanner/test/proof-corpus-lib.test.js
git commit -m "feat(bench): invoke the committed bundle and capture resource metrics

Runs the bundle as a subprocess with a hard timeout, sampling child RSS via ps
so peak memory is measured rather than guessed; an unmeasurable platform yields
null instead of a fabricated zero. Refuses to run against a bundle whose
sha256 sidecar does not match, so a stale bundle cannot silently produce a
green bench result."
```

---

## Task 7: Target manifest and runner CLI

**Files:**
- Create: `bench/proof-corpus/manifest.json`
- Create: `bench/proof-corpus/runner.mjs`
- Create: `bench/proof-corpus/.gitignore`
- Modify: `scanner/test/proof-corpus-lib.test.js` (append manifest-validity tests)
- Modify: `scanner/package.json` (add bench scripts)

**Interfaces:**
- Consumes: `ensureClone`, `resolveRef`, `repoDir` (Task 4); `detectLicence` (Task 3); `readIrStats`, `coverageSummary` (Task 5); `verifyBundle`, `runRepoScan` (Task 6).
- Produces: `bench/proof-corpus/results/summary.json` and the CLI surface.

**On `commit: null`:** every target ships unpinned. `--refresh-pins` resolves each `ref` to a SHA via `git ls-remote` and rewrites the manifest. This is not a placeholder — it is a defined initial state with a defined mechanism to fill it, and it keeps a fabricated SHA out of version control.

- [ ] **Step 1: Create the manifest**

Create `bench/proof-corpus/manifest.json`:

```json
{
  "version": "1.0.0",
  "description": "Proof-corpus targets. Commits are pinned SHAs resolved from `ref` via --refresh-pins; a null commit means the target is unpinned and will be refused by the runner.",
  "targets": [
    {
      "id": "ghost",
      "url": "https://github.com/TryGhost/Ghost.git",
      "ref": "main",
      "commit": null,
      "tier": "breadth",
      "expectedLanguages": ["javascript"],
      "timeBudgetS": 1800,
      "scope": null
    },
    {
      "id": "superset",
      "url": "https://github.com/apache/superset.git",
      "ref": "master",
      "commit": null,
      "tier": "deep",
      "expectedLanguages": ["python", "javascript"],
      "timeBudgetS": 1800,
      "scope": null
    },
    {
      "id": "grafana",
      "url": "https://github.com/grafana/grafana.git",
      "ref": "main",
      "commit": null,
      "tier": "deep",
      "expectedLanguages": ["go", "javascript"],
      "timeBudgetS": 2400,
      "scope": null
    },
    {
      "id": "sentry",
      "url": "https://github.com/getsentry/sentry.git",
      "ref": "master",
      "commit": null,
      "tier": "breadth",
      "expectedLanguages": ["python", "javascript"],
      "timeBudgetS": 2400,
      "scope": null
    },
    {
      "id": "discourse",
      "url": "https://github.com/discourse/discourse.git",
      "ref": "main",
      "commit": null,
      "tier": "deep",
      "expectedLanguages": ["ruby", "javascript"],
      "timeBudgetS": 2400,
      "scope": null
    },
    {
      "id": "jellyfin",
      "url": "https://github.com/jellyfin/jellyfin.git",
      "ref": "master",
      "commit": null,
      "tier": "breadth",
      "expectedLanguages": ["csharp"],
      "timeBudgetS": 1800,
      "scope": null
    },
    {
      "id": "mattermost",
      "url": "https://github.com/mattermost/mattermost.git",
      "ref": "master",
      "commit": null,
      "tier": "breadth",
      "expectedLanguages": ["go", "javascript"],
      "timeBudgetS": 2400,
      "scope": null
    },
    {
      "id": "jenkins",
      "url": "https://github.com/jenkinsci/jenkins.git",
      "ref": "master",
      "commit": null,
      "tier": "deep",
      "expectedLanguages": ["java"],
      "timeBudgetS": 2400,
      "scope": null
    },
    {
      "id": "nextcloud",
      "url": "https://github.com/nextcloud/server.git",
      "ref": "master",
      "commit": null,
      "tier": "breadth",
      "expectedLanguages": ["php", "javascript"],
      "timeBudgetS": 3600,
      "scope": null
    },
    {
      "id": "godot",
      "url": "https://github.com/godotengine/godot.git",
      "ref": "master",
      "commit": null,
      "tier": "breadth",
      "expectedLanguages": ["cpp"],
      "timeBudgetS": 3600,
      "scope": ["core", "modules", "scene", "servers", "editor"]
    }
  ]
}
```

- [ ] **Step 2: Create the .gitignore**

Create `bench/proof-corpus/.gitignore`:

```gitignore
# Raw findings never enter git — they are unreviewed results against live
# third-party projects (the Proof Corpus PRD §9.1). Only aggregate summary.json
# is committed.
results/raw/
results/*.tmp
*.sarif
```

- [ ] **Step 3: Write the failing manifest tests**

Append to `scanner/test/proof-corpus-lib.test.js`:

```javascript
test('manifest: is valid, complete, and internally consistent', () => {
  const manifestPath = path.resolve('../bench/proof-corpus/manifest.json');
  const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.equal(m.targets.length, 10, 'the corpus is ten targets');

  const ids = m.targets.map(t => t.id);
  assert.equal(new Set(ids).size, 10, 'target ids are unique');

  for (const t of m.targets) {
    assert.match(t.id, /^[a-z0-9][a-z0-9._-]*$/, `${t.id}: id must be cache-path safe`);
    assert.match(t.url, /^https:\/\/github\.com\/.+\.git$/, `${t.id}: url must be an https git url`);
    assert.ok(typeof t.ref === 'string' && t.ref.length > 0, `${t.id}: ref required`);
    assert.ok(t.commit === null || /^[0-9a-f]{40}$/.test(t.commit), `${t.id}: commit must be null or a full SHA`);
    assert.ok(['breadth', 'deep'].includes(t.tier), `${t.id}: tier must be breadth or deep`);
    assert.ok(Array.isArray(t.expectedLanguages) && t.expectedLanguages.length > 0, `${t.id}: expectedLanguages required`);
    assert.ok(Number.isInteger(t.timeBudgetS) && t.timeBudgetS > 0, `${t.id}: timeBudgetS required`);
    assert.ok(t.scope === null || Array.isArray(t.scope), `${t.id}: scope must be null or an array`);
  }

  const deep = m.targets.filter(t => t.tier === 'deep').map(t => t.id).sort();
  assert.deepEqual(deep, ['discourse', 'grafana', 'jenkins', 'superset'], 'Tier-1 set matches the PRD');
});
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/proof-corpus-lib.test.js
```

Expected: PASS, 24 tests. This test passes immediately because the manifest was written in Step 1 — it is a guard against future edits, not a red-then-green cycle.

- [ ] **Step 5: Write the runner**

Create `bench/proof-corpus/runner.mjs`:

```javascript
#!/usr/bin/env node
// Proof-corpus bench runner.
//
// Clones pinned commits of third-party repositories into an out-of-tree cache,
// scans each with the committed bundle, and assembles an aggregate results
// record. Raw findings are never written to a committed path — see
// the Proof Corpus PRD §9.1 for why that boundary is enforced here rather
// than left to discipline.
//
// Usage:
//   node bench/proof-corpus/runner.mjs [options]
//     --only a,b        run just these target ids
//     --refresh-pins    resolve each target's ref to a SHA and rewrite the manifest
//     --no-determinism  skip the second scan used for the byte-identical check
//     --out <dir>       results directory (default bench/proof-corpus/results)

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { ensureClone, resolveRef, repoDir } from './lib/clone.mjs';
import { detectLicence } from './lib/licence.mjs';
import { readIrStats, coverageSummary } from './lib/irstats.mjs';
import { verifyBundle, runRepoScan } from './lib/scan.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST = path.join(HERE, 'manifest.json');

function parseArgs(argv) {
  const out = { only: null, refreshPins: false, determinism: true, outDir: path.join(HERE, 'results') };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--only') out.only = String(argv[++i] || '').split(',').filter(Boolean);
    else if (a === '--refresh-pins') out.refreshPins = true;
    else if (a === '--no-determinism') out.determinism = false;
    else if (a === '--out') out.outDir = path.resolve(String(argv[++i] || ''));
  }
  return out;
}

function loadManifest() {
  return JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
}

function refreshPins(manifest, targets) {
  for (const t of targets) {
    process.stdout.write(`  resolving ${t.id} @ ${t.ref} ... `);
    const sha = resolveRef(t.url, t.ref);
    t.commit = sha;
    process.stdout.write(`${sha}\n`);
  }
  fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  process.stdout.write(`manifest updated: ${MANIFEST}\n`);
}

function sha256File(file) {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  } catch {
    return null;
  }
}

async function runTarget(t, opts) {
  const record = {
    id: t.id, url: t.url, commit: t.commit, tier: t.tier,
    status: 'pending', scope: t.scope, timeBudgetS: t.timeBudgetS,
  };

  const rawDir = path.join(opts.outDir, 'raw', t.id);
  fs.mkdirSync(rawDir, { recursive: true });

  try {
    const { dir, cached } = ensureClone(t);
    record.cached = cached;

    const lic = detectLicence(dir);
    record.licence = lic;

    const statsPath = path.join(rawDir, 'ir-stats.json');
    const sarifA = path.join(rawDir, 'run-a.sarif');
    const scanDir = Array.isArray(t.scope) && t.scope.length
      ? path.join(dir, t.scope[0])
      : dir;
    record.scannedPath = path.relative(dir, scanDir) || '.';

    const a = await runRepoScan({
      dir: scanDir, statsPath, sarifPath: sarifA, timeoutMs: t.timeBudgetS * 1000,
    });
    record.scan = {
      exitCode: a.exitCode, wallMs: a.wallMs, timedOut: a.timedOut, peakRssKb: a.peakRssKb,
    };

    if (a.timedOut) {
      record.status = 'timeout';
      record.error = `exceeded time budget of ${t.timeBudgetS}s`;
      return record;
    }

    record.coverage = coverageSummary(readIrStats(statsPath));

    if (opts.determinism) {
      const sarifB = path.join(rawDir, 'run-b.sarif');
      const b = await runRepoScan({
        dir: scanDir, sarifPath: sarifB, timeoutMs: t.timeBudgetS * 1000,
      });
      const ha = sha256File(sarifA);
      const hb = sha256File(sarifB);
      record.determinism = {
        checked: true,
        identical: ha !== null && ha === hb,
        secondRunWallMs: b.wallMs,
      };
    } else {
      record.determinism = { checked: false, identical: null };
    }

    record.status = 'ok';
  } catch (err) {
    record.status = 'error';
    record.error = String(err && err.message);
  }
  return record;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const manifest = loadManifest();
  let targets = manifest.targets;
  if (opts.only) {
    const want = new Set(opts.only);
    targets = targets.filter(t => want.has(t.id));
    const missing = opts.only.filter(id => !manifest.targets.some(t => t.id === id));
    if (missing.length) {
      process.stderr.write(`unknown target id(s): ${missing.join(', ')}\n`);
      return 4;
    }
  }

  if (opts.refreshPins) {
    process.stdout.write('refreshing pins:\n');
    refreshPins(manifest, targets);
    return 0;
  }

  const bundle = verifyBundle();
  if (!bundle.ok) {
    process.stderr.write(`bundle check failed: ${bundle.reason}\n`);
    return 5;
  }

  fs.mkdirSync(opts.outDir, { recursive: true });
  const records = [];
  for (const t of targets) {
    process.stdout.write(`\n=== ${t.id} ===\n`);
    const rec = await runTarget(t, opts);
    records.push(rec);
    const cov = rec.coverage ? rec.coverage.totals.pct : null;
    process.stdout.write(
      `  status=${rec.status} exit=${rec.scan ? rec.scan.exitCode : 'n/a'} ` +
      `wall=${rec.scan ? Math.round(rec.scan.wallMs / 1000) : 'n/a'}s ` +
      `coverage=${cov === null ? 'n/a' : cov + '%'} ` +
      `licence=${rec.licence ? rec.licence.spdx : 'n/a'}\n`,
    );
  }

  const summary = {
    bundleSha: bundle.sha,
    targetCount: records.length,
    ok: records.filter(r => r.status === 'ok').length,
    failed: records.filter(r => r.status !== 'ok').length,
    targets: records,
  };
  const summaryPath = path.join(opts.outDir, 'summary.json');
  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2) + '\n', 'utf8');
  process.stdout.write(`\nsummary: ${summaryPath}\n`);
  process.stdout.write(`ok=${summary.ok} failed=${summary.failed}\n`);

  return summary.failed === 0 ? 0 : 1;
}

main().then(c => process.exit(c)).catch(err => {
  process.stderr.write(`fatal: ${err && err.stack}\n`);
  process.exit(2);
});
```

- [ ] **Step 6: Add the npm scripts**

In `scanner/package.json`, immediately after the `"bench:polyglot"` line, add:

```json
    "bench:proof-corpus": "node ../bench/proof-corpus/runner.mjs",
    "bench:proof-corpus:pins": "node ../bench/proof-corpus/runner.mjs --refresh-pins",
```

- [ ] **Step 7: Verify the CLI surface without touching the network**

```bash
cd /Users/ross/code/agentic-security/scanner
node ../bench/proof-corpus/runner.mjs --only nosuchrepo; echo "exit=$?"
```

Expected: prints `unknown target id(s): nosuchrepo` and `exit=4`.

- [ ] **Step 8: Verify the unpinned guard fires**

```bash
cd /Users/ross/code/agentic-security/scanner
node ../bench/proof-corpus/runner.mjs --only ghost 2>&1 | grep -o 'refresh-pins'; echo "exit=$?"
```

Expected: prints `refresh-pins` and `exit=0` from grep — the runner reached the target and refused it for want of a pin rather than attempting a fetch.

- [ ] **Step 9: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/proof-corpus/manifest.json bench/proof-corpus/runner.mjs bench/proof-corpus/.gitignore scanner/test/proof-corpus-lib.test.js scanner/package.json
git commit -m "feat(bench): add proof-corpus manifest and runner CLI

Ten targets ship unpinned; --refresh-pins resolves each ref to a SHA via
git ls-remote and rewrites the manifest, so a fabricated commit never enters
version control and pin advancement stays a deliberate act.

The runner refuses to start against a bundle whose sha256 does not match, and
writes raw findings only under results/raw/, which is gitignored — the
disclosure boundary is enforced by the harness, not by discipline."
```

---

## Task 8: End-to-end proof on two real repositories

**Files:**
- Create: `bench/proof-corpus/README.md`
- Modify: `bench/proof-corpus/manifest.json` (pins filled by the tool, not by hand)
- Create: `bench/proof-corpus/results/summary.json` (generated)

**Interfaces:**
- Consumes: everything from Tasks 1–7.
- Produces: the first real evidence — two third-party repositories scanned with verified metrics.

This is the only task that uses the network. It needs several gigabytes of disk and can take tens of minutes.

- [ ] **Step 1: Resolve the pins for the two Phase-1 targets**

```bash
cd /Users/ross/code/agentic-security/scanner
node ../bench/proof-corpus/runner.mjs --only ghost,superset --refresh-pins
```

Expected: two lines printing full 40-character SHAs, then `manifest updated`.

- [ ] **Step 2: Confirm the pins actually landed in the manifest**

```bash
cd /Users/ross/code/agentic-security
grep -A1 '"id": "ghost"' bench/proof-corpus/manifest.json
node -e "
const m=require('./bench/proof-corpus/manifest.json');
for (const id of ['ghost','superset']) {
  const t=m.targets.find(x=>x.id===id);
  if(!/^[0-9a-f]{40}\$/.test(t.commit||'')) { console.error('FAIL: '+id+' not pinned'); process.exit(1); }
  console.log(id, t.commit);
}
console.log('OK: both pinned');
"
```

Expected: both SHAs print, then `OK: both pinned`. If this fails, the manifest write did not land — do not proceed.

- [ ] **Step 3: Run the breadth pass on both targets**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run build >/dev/null 2>&1
node ../bench/proof-corpus/runner.mjs --only ghost,superset 2>&1 | tee /tmp/proof-run.txt
echo "exit=$?"
```

Expected: per-target lines reporting `status=ok`, a non-null coverage percentage, and a detected licence. Record the actual numbers — they are the first real output of this campaign.

- [ ] **Step 4: Verify the results record against the run you just did**

```bash
cd /Users/ross/code/agentic-security
node -e "
const s=require('./bench/proof-corpus/results/summary.json');
console.log('bundleSha', s.bundleSha.slice(0,12));
for (const t of s.targets) {
  console.log(t.id, 'status='+t.status, 'licence='+(t.licence&&t.licence.spdx),
    'coverage='+(t.coverage&&t.coverage.totals.pct)+'%',
    'deterministic='+(t.determinism&&t.determinism.identical),
    'wall='+Math.round(t.scan.wallMs/1000)+'s',
    'peakRssMb='+(t.scan.peakRssKb?Math.round(t.scan.peakRssKb/1024):null));
}
"
```

Expected: both targets `status=ok`. Ghost should report a `javascript` coverage figure and Superset both `python` and `javascript`.

**If `deterministic=false` for either target, stop and investigate** — the PRD makes byte-identical SARIF an acceptance criterion, and a failure here is a real finding about deterministic mode on real input, not a bench bug to work around. Record it either way.

- [ ] **Step 5: Confirm the disclosure boundary holds**

```bash
cd /Users/ross/code/agentic-security
git status --porcelain bench/proof-corpus/ | sort
git check-ignore -v bench/proof-corpus/results/raw/ghost/ir-stats.json && echo "OK: raw results are ignored"
```

Expected: `git status` shows `manifest.json`, `results/summary.json` and `README.md` — and **no** file under `results/raw/`. The `check-ignore` line confirms the ignore rule matches. If any raw artifact is stage-able, fix `.gitignore` before committing.

- [ ] **Step 6: Write the README using the numbers from this run**

Create `bench/proof-corpus/README.md`. Replace every `<...>` with the actual value printed in Step 4 — do not carry over numbers from any earlier run:

```markdown
# proof-corpus

Scans large third-party open-source repositories to produce reproducible
evidence about language coverage, detection quality, and operational behaviour
at scale. See the Proof Corpus PRD for the full rationale.

## Running

```bash
cd scanner
npm run build                                          # the bench refuses a stale bundle
node ../bench/proof-corpus/runner.mjs --only ghost,superset
```

Options: `--only <ids>`, `--refresh-pins`, `--no-determinism`, `--out <dir>`.

## Pinning

Targets are pinned to full commit SHAs so a re-run months later produces the
same numbers. A target with `"commit": null` is refused; run `--refresh-pins`
to resolve each `ref` to a SHA and rewrite the manifest. Advancing a pin is
therefore always a reviewable diff.

## Clone cache

Clones are blobless (`--filter=blob:none --depth 1`) and live outside the
repository, by default under `~/.claude/agentic-security/proof-corpus-cache`.
Override with `AGENTIC_SECURITY_PROOF_CACHE`. Nothing third-party is ever
committed to this tree.

## What is and is not committed

`results/summary.json` holds aggregate metrics and is committed.
`results/raw/` holds findings and SARIF for live third-party projects and is
gitignored — unreviewed findings against software people run in production are
not ours to publish (PRD §9.1).

## Phase-1 status

Two targets validated end-to-end on <DATE>:

| Target | Licence | Parse coverage | Deterministic | Wall | Peak RSS |
|---|---|---|---|---|---|
| ghost | <SPDX> | <N>% | <yes/no> | <N>s | <N> MB |
| superset | <SPDX> | <N>% | <yes/no> | <N>s | <N> MB |

The remaining eight targets are in the manifest but unpinned; Phase 2 brings
them online.
```

- [ ] **Step 7: Run the full gate before committing**

```bash
cd /Users/ross/code/agentic-security/scanner && npm test 2>&1 | tail -20
```

Expected: green. This touched `package.json` and added test files, so the full suite is the check that matters.

- [ ] **Step 8: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/proof-corpus/manifest.json bench/proof-corpus/README.md bench/proof-corpus/results/summary.json
git commit -m "feat(bench): validate proof-corpus harness end-to-end on two targets

Pins Ghost and Superset to full commit SHAs and records the first real run:
licence detection, per-language parse coverage, wall time, peak RSS, and a
byte-identical SARIF determinism check across two consecutive scans.

Numbers in the README come from the run in this commit. The remaining eight
targets stay unpinned until Phase 2."
```

---

## Self-Review

**Spec coverage (PRD §5.1, §5.2, §5.4, Phase 0–1 of §11):**

| PRD requirement | Task |
|---|---|
| `AGENTIC_SECURITY_IR_STATS` sidecar with per-language counts + call-graph size | 1, 2 |
| Parse coverage as the headline metric | 1, 5 |
| Licence auto-detection | 3 |
| Blobless pinned clone into out-of-tree cache | 4 |
| Invoke the bundle, verify its SHA-256 sidecar | 6 |
| Wall time and peak RSS | 6 |
| Time budget as recorded failure, not silent skip | 6 (`timedOut`), 7 (`status: 'timeout'`) |
| Determinism: two runs, byte-identical SARIF | 7, 8 |
| Declared scope, never silent | 7 (`scope` in manifest, `scannedPath` in record) |
| Raw findings never committed | 7 (`.gitignore`), 8 (Step 5 verifies) |
| Ghost + Superset proven end-to-end | 8 |

Deferred to later plans by design: the ten-repo breadth pass (Plan 2), the C++ parser (Plan 3), replay/reporting/gating (Plan 4). The `replay.mjs` and `report.mjs` modules named in PRD §5.1 belong to Plan 4 and are deliberately absent here.

**Placeholder scan:** none. The `<...>` markers in Task 8 Step 6 are explicitly instructed to be filled from the run executed two steps earlier, and `commit: null` in the manifest is a defined state with a defined resolution mechanism, not an unfilled blank.

**Type consistency:** `collectIrStats(fileContents, perFile, callGraph)` is called with exactly that arity in Task 2. `coverageSummary` consumes the object `readIrStats` returns. `runRepoScan` returns `{exitCode, wallMs, timedOut, peakRssKb, stderrTail}` and the runner reads exactly those keys. `ensureClone` returns `{dir, cached}`, both used. `verifyBundle` returns `{ok, reason, sha}`, all three used. `detectLicence` returns `{spdx, source, file}`, and the runner reads `.spdx`.

**One known cost, accepted:** Task 2 builds IR whenever stats are requested, which on a very large repository adds real time to a scan that would otherwise skip IR entirely. That is inherent to measuring parse coverage, it is default-off, and the per-target time budget in the manifest is what keeps it bounded.

**Three CLI facts verified against `bin/agentic-security.js` rather than assumed.** Each would have broken Task 8 silently:

1. **There is no `--sarif <path>` flag.** SARIF is emitted by `--format sarif` on stdout. Task 6 captures stdout to a file and waits for the stream to flush before hashing.
2. **`--deterministic` refuses to scan an unlocked tree.** It calls `verifyLockfile()`, which returns `{ok: false, mismatches: ['no lockfile present']}` for any directory without a committed rules lockfile — every third-party target — and the CLI then returns exit 4 *without scanning*. Task 6 sets `AGENTIC_SECURITY_DETERMINISTIC=1` and `AGENTIC_SECURITY_OFFLINE=1` directly, which is what the flag sets, minus the lockfile gate. A regression test asserts `exitCode !== 4` so nobody reintroduces the flag.
3. **Scan state is written into the scanned tree.** `.agentic-security/` lands inside the target directory, and the determinism check scans the same tree twice, so Task 6 clears it before every run per the root `CLAUDE.md` benchmarking rule.

**Offline is deliberate for Phase 1.** `AGENTIC_SECURITY_OFFLINE=1` disables OSV lookups, so these runs produce no SCA findings. That is the right trade for a determinism proof — network variability is the enemy of byte-identical output. SBOM and SCA coverage on real manifests is a Plan 2 concern and will need a warmed OSV cache rather than offline mode.

---

**Plan complete and saved to `docs/superpowers/plans/2026-07-25-proof-corpus-foundation.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
