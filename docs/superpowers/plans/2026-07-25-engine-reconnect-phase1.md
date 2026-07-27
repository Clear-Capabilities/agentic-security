# Reconnect the Taint Engine — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make interprocedural taint analysis actually produce findings — it currently produces none in any language — and put a regression tier in place so it cannot silently break again.

**Architecture:** Five call sites ask `callGraph.resolve()` for a function *record* but it returns a qid *string*, so the record is always null: parameters never bind, summaries are never computed on demand, and the callback path is dead. A small tolerant helper in `callgraph.js` resolves the record; the call sites use it. Two adjacent key-type bugs (an object used as an object key, and a name-keyed map queried by qid) are fixed alongside. Sanitizer consumption is generalised beyond SQL using the existing recall-preserving demotion pattern. A new `deep/` corpus tier runs with deep mode on so all of this is guarded.

**Tech Stack:** Node ≥ 24, ESM, `node:test` + `node:assert/strict`. No new dependencies.

## Global Constraints

Copied from `CLAUDE.md`, `scanner/CLAUDE.md`, and the design spec. Every task's requirements implicitly include this section.

- **ESM only.** `import`/`export`. No CommonJS in `scanner/src/`.
- **Node ≥ 24.** Verified present: v24.16.0.
- **No new npm dependencies.**
- **Rebuild after `src/` changes:** `cd scanner && npm run build`. Unit tests run against `src/` and need no rebuild.
- **Confirm every mutation landed.** After any edit, re-read the region or grep for the exact string added.
- **Every stated number must come from a run in the same session.** No remembered figures.
- **New test files must be wired into a scoped script** in `scanner/package.json` or they never run in CI.
- **Corpus discipline.** An entry is added only after it scores `pre:TP post:TN`. Then `npm run bench:cve-replay:check` → `npm run bench:cve-replay:update-baseline` → commit the regenerated baseline.
- **Wipe scan state before benchmarking:** `find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} +` from the repo root.
- **Never name any external or competitor security tool** in code, comments, docs, or commit messages.
- **Recall-preserving demotion only.** A sanitized finding is demoted and labelled, never dropped.

## Branch

Already created: `feat/engine-reconnect`, with the design spec committed. It branches from `feat/cpp-ir-parser` (PR #43), which branches from `docs/proof-corpus-prd` (PR #42). Do not rebase; both parents are open PRs.

---

## The thesis this plan tests

Fixing roughly six small defects should unlock more real detection capability than months of new rules. **Task 1 captures the "before" measurement precisely so this can be falsified.** If Task 7's "after" shows no new interprocedural findings, the programme stops and re-plans rather than proceeding to Phase 2 — that decision is part of this plan, not a later judgement call.

---

## Verified facts this plan depends on

Each was confirmed by reading or running the code. Do not assume otherwise.

| Fact | Evidence |
|---|---|
| `callGraph.resolve()` returns a qid string | `ir/callgraph.js` — `resolve` returns `m.get(name)` values which are qids; `edges[].callee` holds qid strings |
| `callGraph.functions` is a Map keyed by qid | `ir/callgraph.js:36` — `functions.set(fn.qid, fn)` |
| Five sites test `resolved && resolved.qid` | `dataflow/engine.js:235`, `:344`, `:795`; `dataflow/ifds.js:261`; `dataflow/points-to.js:251` |
| `dataflow/engine.js:236` already tolerates a string | `const qid = resolved && (resolved.qid \|\| resolved)` — so the cached lookup works; only the record path is dead |
| A null record kills three things | `paramNames` falls back to `[]`; `if (!sum && fn && fn.cfg)` gates on-demand summary computation; `:795` does `if (!cbFn …) continue` |
| `fn.calls` shape | `parser-js.js:19` documents `{site, callee, args, line}`; populated at `:311` |
| Corpus tiers are directory-based | `bench/cve-replay/runner.mjs:37` — `const TIERS = ['regression', 'capability']` |
| The corpus runner never sets deep mode | `runner.mjs` calls `await runScan(prePath)` with no env manipulation |
| Deep mode auto-disables under CI | `engine.js` requires `AGENTIC_SECURITY_DEEP_IN_CI=1` when a CI env var is present |
| Recall-preserving demotion already exists | `proven-clean.js:145-146` sets `f.provenClean` + `f.provenanceProof`, explicitly informational; `engine.js:7915` demotes via the proof gate, opt-out `AGENTIC_SECURITY_NO_PROOF_GATE=1` |
| 65 sanitizer entries exist; only `appliesTo:['sql']` is consumed | `catalog.js`; `proven-clean.js:38-40` filters on `appliesTo.includes('sql')` |

---

## File Structure

| File | Responsibility |
|---|---|
| `scanner/src/ir/callgraph.js` | *Modify.* Export `functionRecord(callGraph, resolved)` — a tolerant qid-or-record → record resolver. Natural home: it owns the `functions` Map. |
| `scanner/src/dataflow/engine.js` | *Modify.* Three call sites use the helper. |
| `scanner/src/dataflow/ifds.js` | *Modify.* One call site. |
| `scanner/src/dataflow/points-to.js` | *Modify.* One call site. |
| `scanner/src/dataflow/index.js` | *Modify.* Fix object-as-object-key when building the reverse call graph. |
| `scanner/src/dataflow/tabulation.js` | *Modify.* Key `callersOf` by resolved qid, not source-level name. |
| `scanner/src/ir/parser-py.helper.py` + `parser-py-cst.js` | *Modify.* Emit `fn.calls` from the Python CST path. |
| `scanner/src/dataflow/sanitizer-gate.js` | *Create.* Generalised, recall-preserving sanitizer demotion for all `appliesTo` families. |
| `scanner/test/engine-reconnect.test.js` | *Create.* Interprocedural, caller-map and sanitizer tests. Wired into `test:dataflow`. |
| `bench/engine-reconnect/measure.mjs` | *Create.* The before/after harness — committed so both runs are reproducible. |
| `bench/cve-replay/runner.mjs` | *Modify.* Add the `deep` tier and enable deep mode for it only. |
| `bench/cve-replay/deep/` | *Create.* Five corpus entries requiring interprocedural analysis. |

---

## Task 1: Capture the "before" measurement

**Files:**
- Create: `bench/engine-reconnect/measure.mjs`
- Create: `bench/engine-reconnect/fixtures/{js,py,cpp}/`
- Create: `bench/engine-reconnect/BASELINE.md`
- Modify: `scanner/package.json` (add `bench:engine-reconnect`)

**Interfaces:**
- Consumes: nothing.
- Produces: `node ../bench/engine-reconnect/measure.mjs --json` printing `{ perLanguage: { js|python|cpp: { total, irTaint, interprocedural } }, sanitized }`, and a committed `BASELINE.md` recording the pre-fix numbers.

**Why first:** the C++ workstream's most expensive mistake was measuring "before" after the change had partly landed. This task exists so the thesis is falsifiable. **Do not skip it, and do not reconstruct these numbers later.**

- [ ] **Step 1: Write the fixtures**

Each fixture is a minimal two-function program where a source in one function reaches a sink in another — impossible to detect without interprocedural analysis.

Create `bench/engine-reconnect/fixtures/js/app.js`:

```javascript
function readInput(req) {
  return req.query.cmd;
}

function runIt(req) {
  const cmd = readInput(req);
  require('child_process').exec(cmd);
}

module.exports = { runIt };
```

Create `bench/engine-reconnect/fixtures/py/app.py`:

```python
import os


def read_input(request):
    return request.args.get("cmd")


def run_it(request):
    cmd = read_input(request)
    os.system(cmd)
```

Create `bench/engine-reconnect/fixtures/cpp/app.cpp`:

```cpp
#include <cstdlib>

char* read_input() {
  return getenv("CMD");
}

void run_it() {
  char* cmd = read_input();
  system(cmd);
}
```

Create `bench/engine-reconnect/fixtures/js/sanitized.js` — the sanitizer case, which must be demoted rather than reported at full confidence:

```javascript
function handler(req, res) {
  const raw = req.query.name;
  const safe = escapeHtml(raw);
  res.send(safe);
}

module.exports = { handler };
```

- [ ] **Step 2: Write the measurement harness**

Create `bench/engine-reconnect/measure.mjs`:

```javascript
#!/usr/bin/env node
// Before/after harness for the engine-reconnect work.
//
// Scans three minimal fixtures in which a taint source sits in one function and
// the sink in another. Such a flow is undetectable without interprocedural
// analysis, so the `interprocedural` count is the number this whole phase is
// judged on. Committed rather than ad-hoc so the "before" and "after" runs are
// the same measurement.

import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../scanner/src/runScan.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANGS = [
  { id: 'js', dir: 'fixtures/js' },
  { id: 'python', dir: 'fixtures/py' },
  { id: 'cpp', dir: 'fixtures/cpp' },
];

// A finding counts as interprocedural when its reported line is the SINK line
// and the taint originated in a different function. The engine labels IR-derived
// findings with parser 'IR-TAINT'; anything else came from a syntactic rule and
// does not demonstrate the engine working.
function classify(scan) {
  const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
  const irTaint = all.filter(f => (f.parser || '') === 'IR-TAINT');
  return { total: all.length, irTaint: irTaint.length, interprocedural: irTaint.length };
}

async function main() {
  const json = process.argv.includes('--json');
  // Deep mode is what builds IR at all for an in-process caller.
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

  const perLanguage = {};
  for (const l of LANGS) {
    const { scan } = await runScan(path.join(HERE, l.dir));
    perLanguage[l.id] = classify(scan);
  }

  const { scan: san } = await runScan(path.join(HERE, 'fixtures/js'));
  const sanitizedDemoted = [...(san.findings || [])]
    .filter(f => f.sanitized === true || f.provenClean === true).length;

  const out = { perLanguage, sanitizedDemoted };
  if (json) process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  else {
    for (const [k, v] of Object.entries(perLanguage)) {
      process.stdout.write(`${k}: total=${v.total} irTaint=${v.irTaint} interprocedural=${v.interprocedural}\n`);
    }
    process.stdout.write(`sanitizedDemoted=${sanitizedDemoted}\n`);
  }
  return 0;
}

main().then(c => process.exit(c)).catch(e => {
  process.stderr.write(`fatal: ${e && e.stack}\n`);
  process.exit(2);
});
```

- [ ] **Step 3: Add the npm script**

In `scanner/package.json`, after the `bench:proof-corpus` entries, add:

```json
    "bench:engine-reconnect": "node ../bench/engine-reconnect/measure.mjs",
```

- [ ] **Step 4: Run it and record the real numbers**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run bench:engine-reconnect 2>&1 | tee /tmp/engine-before.txt
```

- [ ] **Step 5: Write BASELINE.md from that output**

Create `bench/engine-reconnect/BASELINE.md` recording, for each of `js`, `python`, `cpp`: `total`, `irTaint`, `interprocedural`, plus `sanitizedDemoted`, and the date (2026-07-25) and commit SHA the run was taken at.

**Fill every figure from the Step 4 output.** If `interprocedural` is non-zero for any language before any fix has landed, stop and report it — that would contradict the spec's central claim and the plan needs revisiting before proceeding.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/engine-reconnect scanner/package.json
git commit -m "test(bench): capture pre-fix interprocedural taint baseline

Three minimal fixtures where the taint source is in one function and the sink
in another — undetectable without interprocedural analysis. Committed as a
harness rather than an ad-hoc script so the before and after runs are the same
measurement. BASELINE.md records the pre-fix figures."
```

---

## Task 2: Resolve the function record at all five call sites

**Files:**
- Modify: `scanner/src/ir/callgraph.js` (add and export `functionRecord`)
- Modify: `scanner/src/dataflow/engine.js` (3 sites), `scanner/src/dataflow/ifds.js` (1), `scanner/src/dataflow/points-to.js` (1)
- Test: `scanner/test/engine-reconnect.test.js` (create)
- Modify: `scanner/package.json` (wire test into `test:dataflow`)

**Interfaces:**
- Consumes: `callGraph.functions` (Map, qid → record) and `callGraph.resolve(name, callerFile) → qid|null`.
- Produces: `functionRecord(callGraph, resolved) → record|null`, exported from `scanner/src/ir/callgraph.js`.

**This is the task the whole phase turns on.** `resolve()` returns a qid string; every site tests `resolved && resolved.qid`, so the record is always null. That silently costs three things: formal parameters never bind to actual arguments, a summary is never computed on demand, and the callback path at `engine.js:795` `continue`s unconditionally.

**Do not change `resolve()`'s return type.** `edges[].callee` stores qid strings and the C/C++ qualified-name path added in PR #43 relies on that. Resolve the record at the call sites instead.

- [ ] **Step 1: Write the failing test**

Create `scanner/test/engine-reconnect.test.js`:

```javascript
// Tests for the Phase 1 engine-reconnect work.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIR, functionRecord } from '../src/ir/callgraph.js';
```

Replace that import line with the correct split once you check where each symbol lives — `buildProjectIR` is exported from `../src/ir/index.js`, `functionRecord` from `../src/ir/callgraph.js`. Then the tests:

```javascript
test('functionRecord: resolves a qid string to its record', () => {
  const { perFile, callGraph } = buildProjectIR({
    'a.js': 'function helper(x){ return x; }\nfunction main(r){ return helper(r.query.q); }\n',
  });
  const helperQid = perFile['a.js'].functions.find(f => f.name === 'helper').qid;
  const rec = functionRecord(callGraph, helperQid);
  assert.ok(rec, 'a qid string must resolve to a record');
  assert.equal(rec.qid, helperQid);
  assert.ok(Array.isArray(rec.params), 'the record must carry params so binding can happen');
});

test('functionRecord: passes a record through unchanged', () => {
  const { perFile, callGraph } = buildProjectIR({
    'a.js': 'function helper(x){ return x; }\n',
  });
  const rec = perFile['a.js'].functions[0];
  assert.equal(functionRecord(callGraph, rec), rec);
});

test('functionRecord: null, unknown qid and bad input yield null, never throw', () => {
  const { callGraph } = buildProjectIR({ 'a.js': 'function f(){}\n' });
  assert.equal(functionRecord(callGraph, null), null);
  assert.equal(functionRecord(callGraph, 'no-such-qid'), null);
  assert.equal(functionRecord(callGraph, 42), null);
  assert.equal(functionRecord(null, 'x'), null);
  assert.equal(functionRecord(undefined, undefined), null);
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-reconnect.test.js
```

Expected: FAIL — `functionRecord` is not exported.

- [ ] **Step 3: Add the helper to `callgraph.js`**

In `scanner/src/ir/callgraph.js`, above `buildCallGraph`, add:

```javascript
// Resolve whatever a caller has — a qid string or an already-resolved record —
// into the function record.
//
// `resolve()` returns a qid STRING (edges[].callee holds qids, and the C/C++
// qualified-name path depends on that), but several dataflow call sites want the
// record so they can bind parameters and compute a summary on demand. Those
// sites previously tested `resolved && resolved.qid`, which is never true for a
// string, so the record was always null: parameters never bound, summaries were
// never computed, and the callback path never ran. This helper is the bridge.
//
// Tolerant of a record so a future caller that already has one still works.
export function functionRecord(callGraph, resolved) {
  if (!resolved || !callGraph) return null;
  if (typeof resolved === 'object') return resolved.qid ? resolved : null;
  if (typeof resolved !== 'string') return null;
  const fns = callGraph.functions;
  if (!fns || typeof fns.get !== 'function') return null;
  return fns.get(resolved) || null;
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-reconnect.test.js
```

Expected: PASS, 3 tests.

- [ ] **Step 5: Use the helper at all five call sites**

Add the import to each of the three files (check whether a `callgraph.js` import already exists and extend it rather than duplicating):

```javascript
import { functionRecord } from '../ir/callgraph.js';
```

Then replace each occurrence of the pattern. In `scanner/src/dataflow/engine.js` there are three, at roughly lines 235, 344 and 795:

```javascript
        const fn  = resolved && resolved.qid ? resolved : null;
```
becomes
```javascript
        const fn  = functionRecord(callGraph, resolved);
```

and at ~795:

```javascript
      const cbFn = resolved && resolved.qid ? resolved : null;
```
becomes
```javascript
      const cbFn = functionRecord(callGraph, resolved);
```

In `scanner/src/dataflow/ifds.js:261`:

```javascript
      const callee = resolved && resolved.qid ? resolved : null;
```
becomes
```javascript
      const callee = functionRecord(callGraph, resolved);
```

In `scanner/src/dataflow/points-to.js:251`:

```javascript
      const target = resolved && resolved.qid ? resolved : null;
```
becomes
```javascript
      const target = functionRecord(callGraph, resolved);
```

**In each file, confirm `callGraph` is actually in scope at that point.** If a site names it differently (`cg`, `graph`), use the local name. If it is genuinely not in scope, thread it in from the nearest caller rather than reaching for a module-level variable, and say so in your report.

- [ ] **Step 6: Confirm every site changed**

```bash
cd /Users/ross/code/agentic-security/scanner
grep -rn 'resolved && resolved.qid' src/ | wc -l
grep -rn 'functionRecord(' src/dataflow/ | wc -l
```

Expected: `0`, then `5`. If the first is non-zero a site was missed; if the second is under 5, likewise.

- [ ] **Step 7: Add the interprocedural end-to-end test**

Append to `scanner/test/engine-reconnect.test.js`:

```javascript
import { runScan } from '../src/runScan.js';
import * as path from 'node:path';

const FIXTURES = path.resolve('../bench/engine-reconnect/fixtures');

async function scanFixture(rel) {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  const { scan } = await runScan(path.join(FIXTURES, rel));
  return [...(scan.findings || []), ...(scan.logicVulns || [])];
}

test('interprocedural: a JS source in one function reaches a sink in another', async () => {
  const findings = await scanFixture('js');
  const ir = findings.filter(f => (f.parser || '') === 'IR-TAINT');
  assert.ok(ir.length >= 1,
    `expected at least one IR-TAINT finding; got ${findings.length} findings, none from the IR engine`);
});

test('interprocedural: the same holds for Python', async () => {
  const findings = await scanFixture('py');
  assert.ok(findings.filter(f => (f.parser || '') === 'IR-TAINT').length >= 1);
});

test('interprocedural: the same holds for C++', async () => {
  const findings = await scanFixture('cpp');
  assert.ok(findings.filter(f => (f.parser || '') === 'IR-TAINT').length >= 1);
});
```

- [ ] **Step 8: Run the interprocedural tests**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-reconnect.test.js 2>&1 | tail -20
```

**If these still fail, that is the single most important result in this plan — do not work around it.** It means a further blocker sits behind the record resolution. Report precisely where the chain breaks: does `resolve()` return a qid at all for that call site? Does `functions.get(qid)` find a record? Does `fn.cfg` exist? Does `analyzeFunction` run? Walk it with a debug print and report the first step that fails, then stop and escalate rather than continuing to Task 3.

- [ ] **Step 9: Wire the test file into `test:dataflow` and confirm**

Append ` test/engine-reconnect.test.js` to the `"test:dataflow"` value in `scanner/package.json`, then:

```bash
cd /Users/ross/code/agentic-security/scanner && grep -c 'test/engine-reconnect.test.js' package.json && npm run test:dataflow 2>&1 | tail -8
```

Expected: `1`, then green.

- [ ] **Step 10: Full gate and rebuild**

```bash
cd /Users/ross/code/agentic-security/scanner && npm test 2>&1 | tail -12 && npm run build 2>&1 | tail -3
```

Expected: green, bundle and `.sha256` regenerated. These are core dataflow files, so the full suite is required.

- [ ] **Step 11: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/ir/callgraph.js scanner/src/dataflow/ scanner/test/engine-reconnect.test.js scanner/package.json scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "fix(dataflow): resolve the callee record so interprocedural taint runs

callGraph.resolve() returns a qid string, but five call sites tested
resolved && resolved.qid, which is never true for a string. The record was
therefore always null, which silently cost three things: formal parameters
never bound to actual arguments, a callee summary was never computed on
demand, and the callback path continued unconditionally.

Adds functionRecord() to callgraph.js — tolerant of a qid or a record — and
uses it at all five sites. resolve()'s return type is deliberately unchanged:
edges[].callee holds qids and the C/C++ qualified-name path depends on it."
```

---

## Task 3: Fix the two key-type bugs

**Files:**
- Modify: `scanner/src/dataflow/index.js:175-178`
- Modify: `scanner/src/dataflow/tabulation.js:86-88`
- Modify: `scanner/test/engine-reconnect.test.js` (append)

**Interfaces:**
- Consumes: `fn.calls` entries of shape `{site, callee, args, line}` (`parser-js.js:19`), and `functionRecord` from Task 2.
- Produces: a reverse call map keyed by **qid**, non-empty for a project with a resolvable cross-file call.

**The two bugs:** `dataflow/index.js` iterates `fn.calls` and uses each entry — an object — directly as an object key, so every entry collapses to the string `"[object Object]"`. `tabulation.js` keys `callersOf` by `callee.callee`, a source-level name like `"b.fill"`, while the worklist looks it up by qid, so the lookup can never match.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/engine-reconnect.test.js`:

```javascript
import { buildProjectIR as _bpir } from '../src/ir/index.js';

test('reverse call map: keys are qids, not stringified objects', () => {
  const { perFile, callGraph } = _bpir({
    'a.js': 'function helper(x){ return x; }\nfunction main(r){ return helper(r.query.q); }\n',
  });
  const helperQid = perFile['a.js'].functions.find(f => f.name === 'helper').qid;
  const callers = {};
  for (const fn of callGraph.functions.values()) {
    for (const c of (fn.calls || [])) {
      const key = c && c.callee ? (callGraph.resolve(c.callee, fn.file) || null) : null;
      if (!key) continue;
      (callers[key] = callers[key] || []).push(fn.qid);
    }
  }
  assert.ok(!Object.keys(callers).includes('[object Object]'),
    'an entry object must never be used as a key');
  assert.ok(callers[helperQid] && callers[helperQid].length >= 1,
    'helper must have at least one recorded caller, keyed by qid');
});
```

That test pins the *shape* the production code must produce. It deliberately reimplements the mapping so it fails loudly if the production version diverges.

- [ ] **Step 2: Run it to see the current behaviour**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-reconnect.test.js 2>&1 | tail -12
```

Record what it reports. If it passes, the reference mapping is correct and the production code is the thing that differs — proceed to fix production and add the assertion against production in Step 4.

- [ ] **Step 3: Fix `dataflow/index.js`**

Find:

```javascript
        for (const callee of fn.calls) {
          if (!callers[callee]) callers[callee] = [];
          callers[callee].push(fn.qid);
        }
```

Replace with:

```javascript
        for (const c of fn.calls) {
          // fn.calls entries are objects ({site, callee, args, line}); using one
          // as an object key stringifies it to "[object Object]" and collapses
          // every entry into a single bogus bucket. Key by the RESOLVED qid so
          // this map is queryable by the qids the worklist actually uses.
          const name = c && typeof c === 'object' ? c.callee : c;
          if (!name) continue;
          const qid = callGraph.resolve ? callGraph.resolve(name, fn.file) : null;
          if (!qid) continue;
          if (!callers[qid]) callers[qid] = [];
          callers[qid].push(fn.qid);
        }
```

- [ ] **Step 4: Fix `tabulation.js`**

Find:

```javascript
    for (const callee of (fn.calls || [])) {
      if (!callersOf.has(callee.callee)) callersOf.set(callee.callee, []);
      callersOf.get(callee.callee).push(fn.qid);
    }
```

Replace with:

```javascript
    for (const callee of (fn.calls || [])) {
      // callee.callee is a SOURCE-LEVEL name ("b.fill"); the worklist below
      // looks this map up by qid, so keying by the name means the lookup can
      // never match. Resolve to a qid first.
      const name = callee && typeof callee === 'object' ? callee.callee : callee;
      if (!name) continue;
      const qid = callGraph.resolve ? callGraph.resolve(name, fn.file) : null;
      if (!qid) continue;
      if (!callersOf.has(qid)) callersOf.set(qid, []);
      callersOf.get(qid).push(fn.qid);
    }
```

**Check `fn.file` is in scope in both places.** If the record does not carry `file`, pass `undefined` — `resolve()` accepts a missing caller file — and note it in your report, because the C/C++ cross-language guard uses that argument.

- [ ] **Step 5: Confirm both edits landed and run the suite**

```bash
cd /Users/ross/code/agentic-security/scanner
grep -c 'callers\[callee\]' src/dataflow/index.js
grep -c 'callersOf.set(callee.callee' src/dataflow/tabulation.js
node --test test/engine-reconnect.test.js 2>&1 | tail -8
npm run test:dataflow 2>&1 | tail -6
```

Expected: `0`, `0`, then both suites green.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/dataflow/index.js scanner/src/dataflow/tabulation.js scanner/test/engine-reconnect.test.js
git commit -m "fix(dataflow): key reverse call maps by resolved qid

Two adjacent bugs made the reverse call graph unusable. dataflow/index.js used
each fn.calls entry — an object — directly as an object key, so every entry
collapsed into a single \"[object Object]\" bucket. tabulation.js keyed
callersOf by the source-level callee name while the worklist looked it up by
qid, so the IFDS caller lookup could never match.

Both now resolve the name to a qid before keying."
```

---

## Task 4: Emit `fn.calls` from the Python parser

**Files:**
- Modify: `scanner/src/ir/parser-py.helper.py`
- Modify: `scanner/src/ir/parser-py-cst.js`
- Modify: `scanner/test/engine-reconnect.test.js` (append)

**Interfaces:**
- Consumes: the shape documented at `parser-js.js:19` — `calls: [{ site, callee, args, line }]`.
- Produces: `fn.calls` populated for Python functions, so Python participates in every consumer that reads it (`tabulation.js`, `dataflow/index.js`, `callgraph.js`).

**Why Python:** `fn.calls` is emitted by only 3 of 8 parsers (JS, Ruby, C++). Python is the highest-value gap — it is one of the three languages the project claims deep flow maturity for. Doing one parser here proves the remaining four (Go, C#, Kotlin, PHP) are mechanical follow-on work for Phase 4, without expanding this phase.

- [ ] **Step 1: Write the failing test**

Append to `scanner/test/engine-reconnect.test.js`:

```javascript
test('python: fn.calls is populated with the documented shape', () => {
  const { perFile } = _bpir({
    'a.py': 'def helper(x):\n    return x\n\n\ndef main(r):\n    v = helper(r)\n    return v\n',
  });
  const ir = perFile['a.py'];
  assert.ok(ir, 'the Python file must produce IR');
  const main = ir.functions.find(f => f.name === 'main');
  assert.ok(Array.isArray(main.calls) && main.calls.length >= 1,
    'main must record its call to helper');
  const c = main.calls.find(x => x.callee === 'helper');
  assert.ok(c, 'the callee name must be recorded');
  assert.ok(c.site && main.cfg.nodes[c.site], 'site must reference a real CFG node id');
  assert.ok(Array.isArray(c.args), 'args must be an array');
  assert.ok(typeof c.line === 'number' && c.line > 0, 'line must be set');
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-reconnect.test.js 2>&1 | tail -10
```

Expected: FAIL — `main.calls` is undefined or empty.

- [ ] **Step 3: Implement**

The Python IR is produced by a Python helper script whose JSON output `parser-py-cst.js` consumes. Read `parser-py.helper.py` and find where it emits each function's CFG nodes. Every node of kind `call` already carries a callee and args; collect those into a sibling `calls` list on the function record, using the node's own id as `site`.

Prefer deriving `calls` from the CFG in `parser-py-cst.js` after parsing, rather than changing the Python helper's wire format — it is the smaller change and keeps the helper's contract stable. Mirror the approach `parser-cpp.js` uses (`_callSitesFromCfg`): walk `cfg.nodes`, and for each node of kind `call`, push `{site: nodeId, callee, args, line}`. Also collect calls appearing on an assignment's right-hand side, since `v = helper(r)` is exactly the source-introducing shape that matters.

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-reconnect.test.js 2>&1 | tail -8
```

Expected: PASS.

- [ ] **Step 5: Confirm no Python regression**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/parser-py-cst.test.js 2>&1 | tail -6 && npm run test:dataflow 2>&1 | tail -6
```

Expected: both green.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/ir/parser-py-cst.js scanner/src/ir/parser-py.helper.py scanner/test/engine-reconnect.test.js
git commit -m "feat(ir): emit fn.calls from the Python parser

fn.calls was emitted by only three of eight parsers, so five languages could
not participate in the consumers that read it — tabulation.js, dataflow/index.js
and callgraph.js. Python is the highest-value gap of the five.

Derived from the CFG after parsing rather than by changing the helper's wire
format, mirroring parser-cpp.js. Calls on an assignment right-hand side are
collected too, since that is the source-introducing shape."
```

---

## Task 5: Generalise sanitizer consumption

**Files:**
- Create: `scanner/src/dataflow/sanitizer-gate.js`
- Modify: `scanner/src/engine.js` (call the gate in the annotation pipeline)
- Modify: `scanner/test/engine-reconnect.test.js` (append)

**Interfaces:**
- Consumes: `CATALOG` sanitizer entries — `{kind:'sanitizer', id, language, match:{type:'call',callee}, effect, appliesTo:[...]}`.
- Produces: `applySanitizerGate(findings, ctx) → findings`, which sets `f.sanitized = true` and `f.sanitizerProof = { sanitizers: string[], family: string }` on findings whose flow passes through a sanitizer matching the finding's vuln family. **It never removes a finding.**

**The gap:** 65 sanitizer entries exist, but only those tagged `appliesTo: ['sql']` are consumed, by `proven-clean.js`. Every other family — `xss`, `url`, `cmd` — is inert, so a correctly sanitized flow is still reported at full confidence. That is a pure false-positive source across every language.

**Recall-preserving is mandatory.** The C/C++ work found `strncpy` and `snprintf` mislabelled `effect: 'strip'` when they bound length rather than sanitising content. A mislabelled sanitizer that *deletes* findings would hide real vulnerabilities. Follow the existing precedent instead: `proven-clean.js:145-146` sets `f.provenClean` plus a proof object and is explicitly informational, with `engine.js:7915` doing the demotion behind an opt-out. Mirror that exactly.

- [ ] **Step 1: Write the failing test**

Append to `scanner/test/engine-reconnect.test.js`:

```javascript
import { applySanitizerGate, _sanitizerFamilies } from '../src/dataflow/sanitizer-gate.js';

test('sanitizer gate: families beyond sql are recognised', () => {
  const fams = _sanitizerFamilies();
  for (const f of ['sql', 'xss', 'url', 'cmd']) {
    assert.ok(fams.includes(f), `${f} must be a recognised sanitizer family`);
  }
});

test('sanitizer gate: a sanitized finding is labelled, never removed', () => {
  const findings = [
    { id: 'a', vuln: 'Reflected XSS', cwe: 'CWE-79', file: 'a.js', line: 3, severity: 'high' },
  ];
  const out = applySanitizerGate(findings, {
    sanitizersOnPath: { a: ['escapeHtml'] },
  });
  assert.equal(out.length, 1, 'the finding must never be dropped');
  assert.equal(out[0].sanitized, true);
  assert.deepEqual(out[0].sanitizerProof.sanitizers, ['escapeHtml']);
  assert.equal(out[0].sanitizerProof.family, 'xss');
});

test('sanitizer gate: a mismatched family does not mark the finding', () => {
  const findings = [
    { id: 'a', vuln: 'SQL Injection', cwe: 'CWE-89', file: 'a.js', line: 3, severity: 'critical' },
  ];
  const out = applySanitizerGate(findings, { sanitizersOnPath: { a: ['escapeHtml'] } });
  assert.equal(out[0].sanitized, undefined,
    'an xss sanitizer must not clear a sql finding');
});

test('sanitizer gate: tolerates missing context without throwing', () => {
  const findings = [{ id: 'a', vuln: 'X', cwe: 'CWE-1', file: 'a.js', line: 1 }];
  assert.equal(applySanitizerGate(findings, {}).length, 1);
  assert.equal(applySanitizerGate(findings, null).length, 1);
  assert.equal(applySanitizerGate(null, null).length, 0);
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-reconnect.test.js 2>&1 | tail -10
```

Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `scanner/src/dataflow/sanitizer-gate.js`:

```javascript
// Generalised, recall-preserving sanitizer gate.
//
// The catalog carries 65 sanitizer entries tagged by family via `appliesTo`
// (sql, xss, url, cmd). Before this module only `appliesTo: ['sql']` was ever
// consumed — by proven-clean.js — so a correctly sanitized xss/url/cmd flow was
// still reported at full confidence. That is a pure false-positive source.
//
// This gate NEVER removes a finding. It sets `sanitized` plus a proof object and
// lets the existing proof gate in engine.js do the demotion, exactly as
// proven-clean.js does. That matters because a mislabelled sanitizer would
// otherwise hide a real vulnerability: the C/C++ work found strncpy and snprintf
// tagged effect:'strip' when they bound length rather than sanitising content.

import { CATALOG } from './catalog.js';

// Map a finding to a sanitizer family using its CWE first (stable) and its vuln
// text second (human-authored, so only a fallback).
const _CWE_FAMILY = {
  'CWE-89': 'sql',
  'CWE-79': 'xss',
  'CWE-78': 'cmd',
  'CWE-22': 'url',
  'CWE-918': 'url',
  'CWE-601': 'url',
};

const _TEXT_FAMILY = [
  [/sql/i, 'sql'],
  [/xss|cross-site scripting/i, 'xss'],
  [/command injection/i, 'cmd'],
  [/path traversal|ssrf|redirect/i, 'url'],
];

export function familyOfFinding(f) {
  if (!f) return null;
  if (f.cwe && _CWE_FAMILY[f.cwe]) return _CWE_FAMILY[f.cwe];
  const text = `${f.vuln || ''} ${f.family || ''}`;
  for (const [re, fam] of _TEXT_FAMILY) if (re.test(text)) return fam;
  return null;
}

// callee name → set of families it sanitizes, built once from the catalog.
let _index = null;
function _sanitizerIndex() {
  if (_index) return _index;
  _index = new Map();
  for (const e of CATALOG) {
    if (!e || e.kind !== 'sanitizer') continue;
    const callee = e.match && e.match.type === 'call' ? e.match.callee : null;
    if (!callee) continue;
    const fams = Array.isArray(e.appliesTo) ? e.appliesTo : [];
    const cur = _index.get(callee) || new Set();
    for (const f of fams) cur.add(f);
    _index.set(callee, cur);
  }
  return _index;
}

export function _sanitizerFamilies() {
  const out = new Set();
  for (const fams of _sanitizerIndex().values()) for (const f of fams) out.add(f);
  return [...out].sort();
}

// ctx.sanitizersOnPath: { [findingId]: string[] } — callee names observed on the
// flow that produced the finding. The engine supplies it; when absent the gate
// is a no-op, which keeps this safe to call unconditionally.
export function applySanitizerGate(findings, ctx) {
  const list = Array.isArray(findings) ? findings : [];
  const onPath = (ctx && ctx.sanitizersOnPath) || null;
  if (!onPath) return list;
  const index = _sanitizerIndex();

  for (const f of list) {
    const fam = familyOfFinding(f);
    if (!fam) continue;
    const observed = onPath[f.id] || onPath[f.stableId];
    if (!Array.isArray(observed) || !observed.length) continue;
    const matching = observed.filter(name => {
      const fams = index.get(name);
      return fams && fams.has(fam);
    });
    if (!matching.length) continue;
    // Label only. The proof gate decides what to do with the label.
    f.sanitized = true;
    f.sanitizerProof = { sanitizers: matching, family: fam };
  }
  return list;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-reconnect.test.js 2>&1 | tail -8
```

Expected: PASS.

- [ ] **Step 5: Wire the gate into the engine and have the proof gate demote on it**

In `scanner/src/engine.js`, find the proof-gate block near line 7915 (the comment mentioning `proven-clean` and `AGENTIC_SECURITY_NO_PROOF_GATE`). Call `applySanitizerGate(finalFindings, { sanitizersOnPath })` immediately before it, and extend the demotion condition so a finding carrying `sanitized === true` is demoted in the same way a `provenClean` one is.

`sanitizersOnPath` must be built from what the flow engine already observed. If the engine does not currently retain sanitizer callees per finding, **do not invent a new traversal for it** — pass `{}` so the gate is a no-op, land the module and its tests, and record in your report exactly what plumbing is missing. A no-op gate with honest reporting is a better outcome than a fabricated data source, and Task 7's measurement will show `sanitizedDemoted: 0`, which is the truthful result.

- [ ] **Step 6: Full gate and rebuild**

```bash
cd /Users/ross/code/agentic-security/scanner && npm test 2>&1 | tail -12 && npm run build 2>&1 | tail -3
```

Expected: green.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/dataflow/sanitizer-gate.js scanner/src/engine.js scanner/test/engine-reconnect.test.js scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "feat(dataflow): consume sanitizers for every family, not just sql

The catalog carries 65 sanitizer entries tagged by family, but only
appliesTo:['sql'] was ever consumed, so a correctly sanitized xss, url or cmd
flow was still reported at full confidence — a pure false-positive source.

The gate labels and never removes: it sets sanitized plus a proof object and
leaves demotion to the existing proof gate, mirroring proven-clean.js. That is
deliberate — a mislabelled sanitizer that deleted findings would hide real
vulnerabilities, and the C/C++ work already found strncpy and snprintf tagged
as content sanitizers when they only bound length."
```

---

## Task 6: Add the deep corpus tier

**Files:**
- Modify: `bench/cve-replay/runner.mjs`
- Create: `bench/cve-replay/deep/` with five entries
- Modify: `bench/cve-replay/corpus-baseline.json` (regenerated, never hand-edited)
- Modify: `bench/cve-replay/CONTRIBUTING.md` (document the tier)

**Interfaces:**
- Consumes: everything from Tasks 2–5.
- Produces: a third tier alongside `regression` and `capability`, run with deep mode enabled, containing entries that provably cannot pass without interprocedural analysis.

**Why a new tier rather than flipping the existing one:** the existing 193 entries are deliberately deep-off, which is what makes them fast and deterministic enough to gate CI. Turning deep on for them would change both their meaning and their runtime. A separate tier guards the new capability without disturbing the old guarantee.

**The CI detail that will bite you:** `engine.js` auto-disables deep mode when a CI environment variable is present unless `AGENTIC_SECURITY_DEEP_IN_CI=1` is also set. The deep tier must set **both** `AGENTIC_SECURITY_DEEP=1` and `AGENTIC_SECURITY_DEEP_IN_CI=1`, or it will silently degrade to the syntactic layer in CI and pass for the wrong reason.

- [ ] **Step 1: Add the tier to the runner**

In `bench/cve-replay/runner.mjs`, change:

```javascript
const TIERS = ['regression', 'capability'];
```

to:

```javascript
// `deep` entries require interprocedural analysis, so they run with deep mode
// on. The other two tiers stay deep-off deliberately: that is what keeps them
// fast and deterministic enough to gate CI.
const TIERS = ['regression', 'capability', 'deep'];
const DEEP_TIER = 'deep';
```

Then, around the `runScan` calls, enable deep for that tier only and restore afterwards. Both variables are required — see the note above.

```javascript
  const _deepEntry = entry.tier === DEEP_TIER;
  const _savedDeep = process.env.AGENTIC_SECURITY_DEEP;
  const _savedDeepCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  if (_deepEntry) {
    process.env.AGENTIC_SECURITY_DEEP = '1';
    process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  }
  try {
    // … existing runScan(prePath) / runScan(postPath) work …
  } finally {
    if (_deepEntry) {
      if (_savedDeep === undefined) delete process.env.AGENTIC_SECURITY_DEEP;
      else process.env.AGENTIC_SECURITY_DEEP = _savedDeep;
      if (_savedDeepCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
      else process.env.AGENTIC_SECURITY_DEEP_IN_CI = _savedDeepCi;
    }
  }
```

Check how `entry.tier` is actually populated when the runner walks the tier directories, and use whatever field it already sets rather than adding a parallel one.

- [ ] **Step 2: Write ONE entry and confirm it scores before writing the rest**

Create `bench/cve-replay/deep/js-interproc-cmdi-shape/` with:

`manifest.json`:
```json
{
  "cve": "js-interproc-cmdi-shape",
  "cwe": "CWE-78",
  "family": "command-injection",
  "language": "javascript",
  "summary": "Request input returned from a helper reaches exec() in another function",
  "expected": { "file": "app.js", "vuln_match": "command|CWE-78" },
  "source": "synthetic-shape-of-disclosed-cve",
  "added_at": "2026-07-25"
}
```

`pre/app.js`:
```javascript
const { exec } = require('child_process');

function readTarget(req) {
  return req.query.host;
}

function ping(req) {
  const host = readTarget(req);
  exec('ping -c 1 ' + host);
}

module.exports = { ping };
```

`post/app.js`:
```javascript
const { execFile } = require('child_process');

function readTarget(req) {
  return req.query.host;
}

function ping(req) {
  const host = readTarget(req);
  if (!/^[a-z0-9.-]+$/i.test(host)) return;
  execFile('ping', ['-c', '1', host]);
}

module.exports = { ping };
```

- [ ] **Step 3: Score that single entry**

```bash
cd /Users/ross/code/agentic-security
find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} + 2>/dev/null
cd scanner && npm run bench:cve-replay 2>&1 | grep -i 'js-interproc-cmdi-shape'
```

Expected: `pre:TP post:TN`.

**If it does not score, stop and diagnose before writing four more.** Report which side failed. In particular, confirm the finding actually came from the IR engine — an entry that passes via a syntactic rule proves nothing about this phase's work and must be reworked so the sink is unreachable without interprocedural analysis.

- [ ] **Step 4: Verify the entry genuinely requires deep mode**

```bash
cd /Users/ross/code/agentic-security/scanner
node -e "
process.env.AGENTIC_SECURITY_DEEP='0';
const { runScan } = await import('./src/runScan.js');
const { scan } = await runScan('../bench/cve-replay/deep/js-interproc-cmdi-shape/pre');
const hit = [...(scan.findings||[])].some(f => /command|CWE-78/i.test((f.vuln||'')+(f.cwe||'')));
console.log('deep-off detects:', hit);
" 2>&1 | tail -2
```

Expected: `deep-off detects: false`. **If it prints `true`, the entry does not test interprocedural analysis** — a syntactic rule is catching it. Rework the fixture (for example, so the sink argument is only tainted via the helper's return value) until deep-off misses it and deep-on finds it. That contrast is the entire point of the tier.

- [ ] **Step 5: Write the remaining four entries**

Same structure, one directory each, each verified by Steps 3 and 4:

| Directory | CWE | Language | Shape |
|---|---|---|---|
| `py-interproc-cmdi-shape` | CWE-78 | python | `request.args.get` returned by a helper reaches `os.system` in another function |
| `cpp-interproc-cmdi-shape` | CWE-78 | cpp | `getenv` returned by a helper reaches `system` in another function |
| `js-interproc-sqli-shape` | CWE-89 | javascript | request value passed *into* a helper that concatenates it into a query |
| `js-interproc-sanitized-tn` | CWE-79 | javascript | request value passed through `escapeHtml` before reaching the sink — `pre/` must produce **no** finding, exercising Task 5's gate |

The last entry is inverted deliberately: it guards against the sanitizer gate regressing into either extreme — failing to recognise a sanitizer, or deleting findings outright.

- [ ] **Step 6: Score the whole corpus and confirm no pre-existing entry moved**

```bash
cd /Users/ross/code/agentic-security
find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} + 2>/dev/null
cd scanner && npm run bench:cve-replay 2>&1 | tail -30
npm run bench:cve-replay:check 2>&1 | tail -20; echo "CHECK_EXIT=$?"
```

New entries appearing as drift is expected. **A verdict change on any of the existing 193 is a regression from Tasks 2–5 and must be reported, not absorbed into the new baseline.**

- [ ] **Step 7: Regenerate the baseline and prove the gate both ways**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run bench:cve-replay:update-baseline 2>&1 | tail -5
npm run bench:cve-replay:check >/dev/null 2>&1; echo "clean=$?"
cp ../bench/cve-replay/corpus-baseline.json /tmp/baseline.bak
node -e "
const fs=require('fs');const p='../bench/cve-replay/corpus-baseline.json';
const b=JSON.parse(fs.readFileSync(p,'utf8'));
// baseline.entries is an OBJECT keyed by entry id with a 'pass'/'fail' string
// value — NOT an array. Inject a phantom entry so the checker reports a
// baselined entry that no longer exists.
b.entries['__corrupted_probe__'] = 'pass';
b.total = (b.total || 0) + 1;
fs.writeFileSync(p,JSON.stringify(b,null,2));
"
npm run bench:cve-replay:check >/dev/null 2>&1; echo "corrupted=$?"
cp /tmp/baseline.bak ../bench/cve-replay/corpus-baseline.json
npm run bench:cve-replay:check >/dev/null 2>&1; echo "restored=$?"
```

Expected: `clean=0`, `corrupted` non-zero, `restored=0`.

- [ ] **Step 8: Document the tier**

In `bench/cve-replay/CONTRIBUTING.md`, add the `deep` tier to the tier description: what it is for, that it runs with deep mode on, that an entry must be verified to fail deep-off, and that it is gated separately from `regression`.

- [ ] **Step 9: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/cve-replay/
git commit -m "test(corpus): add a deep tier that exercises interprocedural taint

All 193 existing entries pass via syntactic rules because the runner never
enables deep mode, so the corpus could not see the IR or taint stack — which is
why every defect this phase fixes went unnoticed.

Adds a third tier, run with deep mode on, whose entries are each verified to be
MISSED deep-off and found deep-on. The existing tiers stay deep-off so their
speed and determinism are unchanged. One entry is an inverted sanitizer case,
guarding against the new gate either failing to recognise a sanitizer or
deleting findings outright.

Both AGENTIC_SECURITY_DEEP and AGENTIC_SECURITY_DEEP_IN_CI are set for the
tier, since the engine auto-disables deep under CI without the latter."
```

---

## Task 7: Measure "after" and decide whether the thesis held

**Files:**
- Create: `bench/engine-reconnect/RESULTS.md`
- Modify: `docs/superpowers/specs/2026-07-25-detection-remediation-effectiveness-design.md` (record the outcome)

**Interfaces:**
- Consumes: the harness from Task 1 and everything from Tasks 2–6.
- Produces: the before/after comparison that decides whether Phase 2 proceeds.

- [ ] **Step 1: Re-run the harness**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run build
npm run bench:engine-reconnect 2>&1 | tee /tmp/engine-after.txt
```

- [ ] **Step 2: Measure precision on real code**

The concern with raising recall is noise. Run the two already-pinned proof-corpus targets and record total finding counts, so a precision regression is visible rather than discovered later:

```bash
cd /Users/ross/code/agentic-security/scanner
node ../bench/proof-corpus/runner.mjs --only ghost,superset 2>&1 | tail -12
```

Record each target's finding count and compare against the figures in `bench/proof-corpus/README.md`.

- [ ] **Step 3: Write RESULTS.md**

Create `bench/engine-reconnect/RESULTS.md` with a before/after table per language for `total`, `irTaint` and `interprocedural`, taken from `/tmp/engine-before.txt` (Task 1) and `/tmp/engine-after.txt` (Step 1); the `sanitizedDemoted` figures; the Ghost and Superset finding counts before and after; and the deep-tier entry count and verdicts.

**Every number comes from those two runs.** If a figure is unavailable, write "not measured" rather than estimating.

- [ ] **Step 4: Make the go/no-go call explicitly**

Append a "Verdict" section to `RESULTS.md` answering, in plain terms:

1. Did `interprocedural` go from zero to non-zero in JS, Python and C++?
2. Did the deep tier gain at least 5 entries that are missed deep-off?
3. Did Ghost or Superset finding counts rise sharply enough to suggest a precision problem?

If (1) is no, state that the thesis did not hold and that Phase 2 should not proceed until the real blocker is understood — that is a legitimate and valuable outcome, and the spec commits to it in advance. If (3) shows a large rise, note that Phase 2's precision work becomes the priority rather than optional.

- [ ] **Step 5: Record the outcome in the spec**

Add a short "Phase 1 outcome" section to `docs/superpowers/specs/2026-07-25-detection-remediation-effectiveness-design.md` linking to `RESULTS.md` and stating the verdict in one sentence, so a future reader sees whether the thesis survived contact with reality.

- [ ] **Step 6: Final gate**

```bash
cd /Users/ross/code/agentic-security/scanner
npm test 2>&1 | tail -12; echo "TEST_EXIT=$?"
npm run bench:cve-replay:check >/dev/null 2>&1; echo "CORPUS_EXIT=$?"
```

Expected: both 0.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/engine-reconnect/RESULTS.md docs/superpowers/specs/2026-07-25-detection-remediation-effectiveness-design.md
git commit -m "test(bench): record the engine-reconnect before/after and the verdict

Figures come from the two harness runs in this commit's session and from a
proof-corpus run over Ghost and Superset for precision. RESULTS.md states
explicitly whether interprocedural findings went from zero to non-zero, and
therefore whether Phase 2 should proceed."
```

---

## Self-Review

**Spec coverage — design spec §4 Phase 1:**

| Spec requirement | Task |
|---|---|
| Defect 1 — five `resolved.qid` sites | 2 |
| Defect 3 — object used as object key | 3 |
| Defect 4 — name-keyed map queried by qid | 3 |
| Defect 6 — sanitizers only consumed for sql | 5 |
| Defect 7 — corpus is deep-off | 6 |
| Defect 2 proof — `fn.calls` for one more parser | 4 |
| §7.1 cross-function finding in JS, Python, C++ | 2 (tests), 7 (measurement) |
| §7.2 caller lookups resolve to real qids | 3 |
| §7.3 sanitized flow demoted, demotion visible | 5 |
| §7.4 ≥5 deep-tier entries, existing 193 green | 6 |
| §7.5 Ghost/Superset counts before and after | 1 (before), 7 (after) |

Deferred to later phases by design: language-scoped catalog matching for all entries, the bidirectional cross-language guard, `_isStrcpyGuarded`, the remediation test gate, and `fn.calls` for the remaining four parsers. Each belongs to Phase 2, 3 or 4 in the spec.

**Placeholder scan:** none. Task 5 Step 5 contains a conditional — pass `{}` if the engine does not retain sanitizer callees — but it is a decision with a defined fallback and a reporting obligation, not an unfilled blank.

**Type consistency:** `functionRecord(callGraph, resolved) → record|null` is defined in Task 2 and used in Tasks 2 and 3. `fn.calls` entries are `{site, callee, args, line}` throughout Tasks 3 and 4, matching `parser-js.js:19`. `applySanitizerGate(findings, ctx) → findings` and `_sanitizerFamilies() → string[]` are defined and consumed in Task 5. The harness output shape `{perLanguage: {…: {total, irTaint, interprocedural}}, sanitizedDemoted}` is produced in Task 1 and consumed in Task 7.

**Ordering note:** Task 1 must run before any fix lands. The C++ workstream's costliest error was reconstructing a baseline after the change, and this plan is structured so that cannot happen.

**Known risk, stated rather than hidden:** Task 2 Step 8 may fail — the interprocedural tests may still find nothing after the record is resolved, because a further blocker sits behind it. The plan treats that as the most valuable possible outcome rather than an obstacle, and instructs the implementer to localise the break and stop rather than work around it.

---

**Plan complete and saved to `docs/superpowers/plans/2026-07-25-engine-reconnect-phase1.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
