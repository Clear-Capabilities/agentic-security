# Engine Recall Gaps — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two verified recall gaps — assignment-position sink calls are never matched in any language, and every `match.type: 'global'` catalog source is unreachable, which leaves PHP's `$_GET` family dead.

**Architecture:** `case 'call'` in the taint engine's `step()` already does catalog sink matching correctly; `case 'assign'` does source matching but never sink matching. The sink-matching logic moves to a shared helper both cases call, rather than being duplicated. Separately, the catalog's index builder gains a `global` branch and `matchSource` consults it for bare identifier references.

**Tech Stack:** Node ≥ 24, ESM, `node:test` + `node:assert/strict`. No new dependencies.

## Global Constraints

- **ESM only.** `import`/`export`. No CommonJS in `scanner/src/`.
- **Node ≥ 24.** Verified present: v24.16.0.
- **No new npm dependencies.**
- **Rebuild after `src/` changes:** `cd scanner && npm run build`. Unit tests run against `src/` and need no rebuild.
- **Confirm every mutation landed.** After any edit, re-read the region or grep for the exact string added.
- **Every stated number must come from a run in the same session.** If a figure is unavailable, write "not measured".
- **New test files must be wired into a scoped script** in `scanner/package.json` or they never run in CI.
- **Corpus discipline.** An entry is added only after it scores `pre:TP post:TN`. Then `npm run bench:cve-replay:check` → `npm run bench:cve-replay:update-baseline` → commit the regenerated baseline.
- **Wipe scan state before benchmarking:** `find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} +` from the repo root.
- **Never name any external or competitor security tool** in code, comments, docs, or commit messages.
- **Both fixes raise recall, so false positives are the risk.** Every task that changes `src/` must run `bench:self-scan:check` and `bench:cve-replay:check`, and both must exit 0.

## Branch

Already created: `fix/engine-recall-gaps`, from merged `main`. All four earlier PRs (#42–#45) are merged, so this branches from a clean base with no stacking.

---

## Verified facts this plan depends on

Reproduced by execution on merged `main`, 2026-07-26.

| Fact | Evidence |
|---|---|
| Assignment-RHS sinks are invisible | Identical flow (`req.query.c` → helper return → `exec`): statement `exec(c)` gives total=1 IR-TAINT=1; `const out = exec(c)` gives **total=0 IR-TAINT=0** |
| `case 'call'` matches sinks correctly | `engine.js:388` — `const cat = matchSinkOrSanitizer(node.callee, _currentFile)` |
| `case 'assign'` never does | `engine.js:261` — begins `const src = exprIsSource(node.source)`; no `matchSinkOrSanitizer` anywhere in the case |
| The catalog index builder handles only two match types | `catalog.js:933` `'call'`, `:937` `'member'` — no `'global'` branch |
| 10 `global` entries exist and none are reachable | js 1 (`location`), rb 4 (`params`, `cookies`, `session`, `ENV`), php 5 (`_REQUEST`, `_GET`, `_POST`, `_SERVER`, `_COOKIE`); **0 of 10** returned by `matchSource` |
| Precision guards exist and are green | `bench:self-scan:check` (hooks 24, scripts 24, polyglot 0), `bench:cve-replay:check` (197/197), proof-corpus (ghost 94% / 1124, superset 100% / 860, godot 100% / 145) |

---

## File Structure

| File | Responsibility |
|---|---|
| `bench/engine-recall/measure.mjs` | *Create.* Before/after harness for both defects. Committed so both runs are the same measurement. |
| `bench/engine-recall/BASELINE.md` | *Create.* The pre-fix figures. |
| `scanner/src/dataflow/engine.js` | *Modify.* Extract the sink-matching logic from `case 'call'` into a helper; call it from `case 'assign'` too. |
| `scanner/src/dataflow/catalog.js` | *Modify.* Add a `global` branch to the index builder and consult it from `matchSource`. |
| `scanner/test/engine-recall.test.js` | *Create.* Unit tests for both fixes. Wired into `test:dataflow`. |
| `bench/cve-replay/deep/` | *Create.* Two entries, one per defect. |

---

## Task 1: Capture the before

**Files:** Create `bench/engine-recall/measure.mjs`, `bench/engine-recall/BASELINE.md`; modify `scanner/package.json`.

**Interfaces produced:** `node ../bench/engine-recall/measure.mjs --json` printing `{ assignSink: { statement, assignment }, globalSources: { total, reachable, byLanguage } }`.

**This runs before any fix.** Three prior phases in this repo were damaged by reconstructing a baseline afterwards; this task exists so the result is falsifiable.

- [ ] **Step 1: Write the harness**

Create `bench/engine-recall/measure.mjs`:

```javascript
#!/usr/bin/env node
// Before/after harness for the two engine recall gaps.
//
// Defect 1: a sink call on an assignment's right-hand side is never matched,
// so `const out = exec(tainted)` is silent while `exec(tainted)` is not.
// Defect 2: every catalog entry declared match.type:'global' is unreachable
// from matchSource(), which kills PHP's $_GET family among others.
//
// Committed rather than ad-hoc so the before and after runs are identical.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../../scanner/src/runScan.js';
import { CATALOG, matchSource } from '../../scanner/src/dataflow/catalog.js';

async function scanSnippet(filename, src) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'engine-recall-'));
  try {
    fs.writeFileSync(path.join(dir, filename), src);
    const { scan } = await runScan(dir);
    const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
    return {
      total: all.length,
      irTaint: all.filter(f => /^IR-TAINT/.test(f.parser || '')).length,
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// Identical taint flow; the only difference is where the sink call sits.
const STATEMENT = `const { exec } = require('child_process');
function h(req) { return req.query.c; }
function f(req) { const c = h(req); exec(c); }
module.exports = { f };
`;

const ASSIGNMENT = `const { exec } = require('child_process');
function h(req) { return req.query.c; }
function f(req) { const c = h(req); const out = exec(c); return out; }
module.exports = { f };
`;

function globalSourceReach() {
  const globals = CATALOG.filter(e => e && e.match && e.match.type === 'global');
  const byLanguage = {};
  let reachable = 0;
  for (const e of globals) {
    byLanguage[e.language] = (byLanguage[e.language] || 0) + 1;
    const asIdent = matchSource({ kind: 'ident', name: e.match.name }, 'a.php');
    const asMemberRoot = matchSource(
      { kind: 'member', object: { kind: 'ident', name: e.match.name }, prop: 'x' }, 'a.php');
    if ((asIdent && asIdent.id === e.id) || (asMemberRoot && asMemberRoot.id === e.id)) reachable++;
  }
  return { total: globals.length, reachable, byLanguage };
}

async function main() {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

  const out = {
    assignSink: {
      statement: await scanSnippet('app.js', STATEMENT),
      assignment: await scanSnippet('app.js', ASSIGNMENT),
    },
    globalSources: globalSourceReach(),
  };

  if (process.argv.includes('--json')) process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  else {
    const a = out.assignSink;
    process.stdout.write(`assign-sink  statement: total=${a.statement.total} irTaint=${a.statement.irTaint}\n`);
    process.stdout.write(`assign-sink  assignment: total=${a.assignment.total} irTaint=${a.assignment.irTaint}\n`);
    const g = out.globalSources;
    process.stdout.write(`global-sources reachable=${g.reachable}/${g.total} ${JSON.stringify(g.byLanguage)}\n`);
  }
  return 0;
}

main().then(c => process.exit(c)).catch(e => {
  process.stderr.write(`fatal: ${e && e.stack}\n`);
  process.exit(2);
});
```

- [ ] **Step 2: Add the npm script**

In `scanner/package.json`, after the `bench:self-scan` entries, add:

```json
    "bench:engine-recall": "node ../bench/engine-recall/measure.mjs",
```

- [ ] **Step 3: Run it and record**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run bench:engine-recall 2>&1 | tee /tmp/recall-before.txt
```

- [ ] **Step 4: Write BASELINE.md from that output**

Record the statement and assignment figures, the global-source reach, and the date and commit SHA.

**Expected, from the reproduction that motivated this plan:** statement `total=1 irTaint=1`, assignment `total=0 irTaint=0`, global sources `0/10`. **If any differs, stop and report it** — it would mean the defect is not what this plan is built on.

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/engine-recall scanner/package.json
git commit -m "test(bench): capture the engine recall-gap baseline

Two defects, each measured before any fix: a sink call on an assignment's
right-hand side is never matched, and every match.type:'global' catalog source
is unreachable. Committed as a harness so the after-run is the same
measurement."
```

---

## Task 2: Match sinks on assignment right-hand sides

**Files:** Modify `scanner/src/dataflow/engine.js`; create `scanner/test/engine-recall.test.js`; modify `scanner/package.json`.

**Interfaces consumed:** `matchSinkOrSanitizer(callee, file)` from `catalog.js`.

**The defect:** `case 'call'` (`engine.js:388`) opens with `const cat = matchSinkOrSanitizer(node.callee, _currentFile)`. `case 'assign'` (`engine.js:261`) opens with `const src = exprIsSource(node.source)` and never sink-matches at all. So the sink is seen only when the call is a bare statement.

**Extract, do not duplicate.** This repository has twice had a rule implemented at one call site and re-broken by the next change — a resolver guard in one phase, a callee normaliser in another — and both had to be relocated to a shared home afterwards. Pull the sink-matching and finding-emission logic out of `case 'call'` into a helper that takes the callee expression, the argument expressions and the current state, and call it from both cases.

- [ ] **Step 1: Write the failing test**

Create `scanner/test/engine-recall.test.js`:

```javascript
// Regression tests for the two engine recall gaps.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

async function scanJs(src) {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'recall-test-'));
  try {
    fs.writeFileSync(path.join(dir, 'app.js'), src);
    const { scan } = await runScan(dir);
    const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
    return all.filter(f => /^IR-TAINT/.test(f.parser || ''));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const HEAD = `const { exec } = require('child_process');\nfunction h(req) { return req.query.c; }\n`;

test('assign-sink: a sink call in statement position is found (control)', async () => {
  const hits = await scanJs(HEAD + `function f(req) { const c = h(req); exec(c); }\nmodule.exports={f};\n`);
  assert.ok(hits.length >= 1, 'the control case must still be detected');
});

test('assign-sink: the same sink call on an assignment RHS is found', async () => {
  const hits = await scanJs(HEAD + `function f(req) { const c = h(req); const out = exec(c); return out; }\nmodule.exports={f};\n`);
  assert.ok(hits.length >= 1,
    `an assignment-position sink must be detected; got ${hits.length} IR-TAINT findings`);
});

test('assign-sink: a clean assignment RHS produces no finding', async () => {
  const hits = await scanJs(`const { exec } = require('child_process');\nfunction f() { const out = exec('ls -la'); return out; }\nmodule.exports={f};\n`);
  assert.equal(hits.length, 0, 'a literal argument must not be reported as tainted');
});
```

- [ ] **Step 2: Run it to verify the second test fails**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-recall.test.js 2>&1 | tail -12
```

Expected: test 1 and 3 pass, test 2 **fails** — that failure is the defect.

- [ ] **Step 3: Extract the sink-matching helper**

Read `case 'call'` in `engine.js` starting at line 386 and identify the portion that: matches the catalog, evaluates argument taint, and pushes a finding when a tainted argument reaches a sink argument index. Move it into a named helper above `step()` — for example `_sinkFindingsForCall(calleeExpr, argExprs, state, node)` returning `{ findings, cat, argTaints }` — and have `case 'call'` call it.

**Confirm `case 'call'` behaves identically after the extraction** before touching `case 'assign'`: run `npm run test:dataflow` and the corpus check, and confirm both are unchanged. An extraction that alters the working path would be worse than the bug being fixed.

- [ ] **Step 4: Call the helper from `case 'assign'`**

In `case 'assign'`, when `node.source` is a call expression, invoke the same helper with `node.source.callee` and `node.source.args`, and merge the returned findings into the case's own `findings` array.

**Preserve the existing assign behaviour.** The case currently handles source matching, target binding and taint propagation into the assigned variable. Sink matching is additive — the assignment must still bind taint to its target exactly as before, because `const c = h(req)` binding `c` is what makes the very flow under test work.

- [ ] **Step 5: Run the tests**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-recall.test.js 2>&1 | tail -8
```

Expected: 3/3 pass.

- [ ] **Step 6: Wire the test file in and check for regressions**

Append ` test/engine-recall.test.js` to the `"test:dataflow"` value in `scanner/package.json`, then:

```bash
cd /Users/ross/code/agentic-security/scanner
grep -c 'test/engine-recall.test.js' package.json
npm run test:dataflow 2>&1 | tail -6
npm run bench:cve-replay:check >/dev/null 2>&1; echo "corpus=$?"
npm run bench:self-scan:check 2>&1 | tail -5; echo "selfscan=$?"
```

Expected: `1`, dataflow green, `corpus=0`.

**The self-scan is the one to watch.** This fix raises recall across every language, so this repository's own finding count may rise. If it does, inspect each new finding and decide whether it is a true positive before touching the baseline. If they are genuine, regenerate the baseline with `npm run bench:self-scan:update-baseline` and say so in your report with the per-file deltas. If any is a false positive, report it rather than baselining it.

- [ ] **Step 7: Full gate, rebuild, commit**

```bash
cd /Users/ross/code/agentic-security/scanner && npm test > /tmp/t2.log 2>&1; echo "TEST_EXIT=$?"; tail -4 /tmp/t2.log
npm run build 2>&1 | tail -3
```

Note the exit code is captured directly, not through a pipe — a `$?` after a pipeline reports the last command in the pipe, not the test run.

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/dataflow/engine.js scanner/test/engine-recall.test.js scanner/package.json scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "fix(dataflow): match sinks on assignment right-hand sides

case 'call' matched the catalog; case 'assign' never did, so an identical taint
flow was reported for exec(c) and silent for const out = exec(c). That silenced
const rows = db.query(tainted) in every language.

The matching logic is extracted into a shared helper rather than duplicated —
this repository has twice had a rule implemented at one call site and re-broken
by the next change."
```

---

## Task 3: Make `global` catalog sources reachable

**Files:** Modify `scanner/src/dataflow/catalog.js`; modify `scanner/test/engine-recall.test.js`.

**The defect:** the index builder at `catalog.js:933` branches on `match.type === 'call'` and `:937` on `'member'`. There is no `'global'` branch, and `matchSource` consults only `CALLEE_INDEX` and `MEMBER_INDEX`. All 10 `global` entries are therefore dead: PHP's `$_REQUEST`, `$_GET`, `$_POST`, `$_SERVER`, `$_COOKIE`; Ruby's `params`, `cookies`, `session`, `ENV`; and JavaScript's `location`.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/engine-recall.test.js`:

```javascript
import { CATALOG, matchSource } from '../src/dataflow/catalog.js';

test('global sources: every global entry is reachable from matchSource', () => {
  const globals = CATALOG.filter(e => e && e.match && e.match.type === 'global');
  assert.ok(globals.length >= 10, `expected at least 10 global entries, got ${globals.length}`);
  const unreachable = [];
  for (const e of globals) {
    const file = e.language === 'php' ? 'a.php' : e.language === 'rb' ? 'a.rb' : 'a.js';
    const hit = matchSource({ kind: 'ident', name: e.match.name }, file);
    if (!hit || hit.id !== e.id) unreachable.push(`${e.id}(${e.match.name})`);
  }
  assert.deepEqual(unreachable, [], `these global sources are unreachable: ${unreachable.join(', ')}`);
});

test('global sources: a global is language-scoped like every other entry', () => {
  const phpOnJs = matchSource({ kind: 'ident', name: '_GET' }, 'a.js');
  assert.ok(!phpOnJs || phpOnJs.language !== 'php',
    'a php superglobal must not match a .js file');
});

test('global sources: an unrelated identifier does not match', () => {
  assert.equal(matchSource({ kind: 'ident', name: 'notAGlobalAnywhere' }, 'a.php'), null);
});
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-recall.test.js 2>&1 | tail -12
```

Expected: the first new test fails listing all 10 unreachable entries.

- [ ] **Step 3: Add the index branch and the lookup**

In `catalog.js`, extend the index builder with a `global` branch keyed by `e.match.name`, following the shape of the existing `'call'` and `'member'` branches:

```javascript
  } else if (e.match.type === 'global' && e.match.name) {
    // Globals (PHP superglobals, rails params/session, JS location) were
    // indexed nowhere, so matchSource could never return one — every entry
    // declared this way was dead. Keyed by the bare name the source appears
    // under in code.
    const k = e.match.name;
    if (!GLOBAL_INDEX.has(k)) GLOBAL_INDEX.set(k, []);
    GLOBAL_INDEX.get(k).push(e);
  }
```

Declare `GLOBAL_INDEX` alongside `CALLEE_INDEX` and `MEMBER_INDEX`. Then in `matchSource`, consult it for a bare identifier — and, because `$_GET['x']` and `params[:id]` reach the engine as a member read off the global, also consult it for the *root* of a member expression. Apply `filterByProvenance` and `_languageAllowed` exactly as the existing branches do, so globals are language-scoped like everything else.

- [ ] **Step 4: Run the tests**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/engine-recall.test.js 2>&1 | tail -8
```

Expected: 6/6 pass.

- [ ] **Step 5: Check both directions**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run test:dataflow 2>&1 | tail -6
npm run bench:cve-replay:check >/dev/null 2>&1; echo "corpus=$?"
npm run bench:self-scan 2>&1 | tail -4
npm run bench:engine-recall 2>&1 | tail -4
```

Expected: dataflow green, `corpus=0`, and the harness now reporting global sources reachable `10/10`.

Apply the same self-scan judgement as Task 2 Step 6: a rise is plausible because PHP's `$_GET` family becoming live is a real recall increase. Inspect any new finding before baselining it.

- [ ] **Step 6: Full gate, rebuild, commit**

```bash
cd /Users/ross/code/agentic-security/scanner && npm test > /tmp/t3.log 2>&1; echo "TEST_EXIT=$?"; tail -4 /tmp/t3.log
npm run build 2>&1 | tail -3
```

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/dataflow/catalog.js scanner/test/engine-recall.test.js scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "fix(dataflow): index and match global catalog sources

The catalog index handled only call and member match types, so all ten
match.type:'global' entries were unreachable from matchSource — PHP's \$_GET,
\$_POST, \$_REQUEST, \$_SERVER and \$_COOKIE, Ruby's params, cookies, session
and ENV, and JS location. PHP had interprocedural analysis that could not see
its canonical taint source.

Globals are language-scoped through the same filter as every other entry."
```

---

## Task 4: Corpus entries proving both fixes

**Files:** Create two directories under `bench/cve-replay/deep/`; modify `bench/cve-replay/corpus-baseline.json`.

**Interfaces consumed:** both fixes from Tasks 2 and 3.

The `deep` tier runs with `AGENTIC_SECURITY_DEEP=1` and `AGENTIC_SECURITY_DEEP_IN_CI=1`, so its entries exercise the IR and taint stack rather than the syntactic layer.

- [ ] **Step 1: Write the assignment-sink entry**

Create `bench/cve-replay/deep/js-assign-sink-cmdi-shape/` with `manifest.json`:

```json
{
  "cve": "js-assign-sink-cmdi-shape",
  "cwe": "CWE-78",
  "family": "command-injection",
  "language": "javascript",
  "summary": "Request input reaches exec() on an assignment right-hand side across a function boundary",
  "expected": { "file": "app.js", "vuln_match": "command|CWE-78" },
  "source": "synthetic-shape-of-disclosed-cve",
  "added_at": "2026-07-26"
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
  const child = exec('ping -c 1 ' + host);
  return child;
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
  if (!/^[a-z0-9.-]+$/i.test(host)) return null;
  const child = execFile('ping', ['-c', '1', host]);
  return child;
}

module.exports = { ping };
```

- [ ] **Step 2: Write the PHP superglobal entry**

Create `bench/cve-replay/deep/php-superglobal-cmdi-shape/` with `manifest.json`:

```json
{
  "cve": "php-superglobal-cmdi-shape",
  "cwe": "CWE-78",
  "family": "command-injection",
  "language": "php",
  "summary": "A PHP superglobal reaches exec() through a helper function",
  "expected": { "file": "app.php", "vuln_match": "command|CWE-78" },
  "source": "synthetic-shape-of-disclosed-cve",
  "added_at": "2026-07-26"
}
```

`pre/app.php`:
```php
<?php
function read_host() {
    return $_GET['host'];
}

function ping() {
    $host = read_host();
    exec('ping -c 1 ' . $host);
}
```

`post/app.php`:
```php
<?php
function read_host() {
    return $_GET['host'];
}

function ping() {
    $host = read_host();
    if (!preg_match('/^[a-z0-9.-]+$/i', $host)) { return; }
    exec('ping -c 1 ' . escapeshellarg($host));
}
```

- [ ] **Step 3: Score both**

```bash
cd /Users/ross/code/agentic-security
find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} + 2>/dev/null
cd scanner && npm run bench:cve-replay 2>&1 | grep -iE 'assign-sink|superglobal'
```

Expected: both `pre:TP post:TN`.

**If either fails, do not weaken the fixture.** Report which side failed and why — for the PHP entry in particular, confirm the finding actually comes from the IR engine rather than a syntactic rule, since a syntactic `exec` match would prove nothing about the global-source fix.

- [ ] **Step 4: Verify each entry proves its own fix**

For each entry, confirm it is *missed* without the corresponding fix. The cleanest way is to check out the parent of the relevant fix commit into a temporary worktree, build there, and score the entry against it.

```bash
cd /Users/ross/code/agentic-security
git worktree add /tmp/pre-fix HEAD~3 2>/dev/null || git worktree add /tmp/pre-fix HEAD~2
cd /tmp/pre-fix/scanner && npm run build >/dev/null 2>&1
node -e "
process.env.AGENTIC_SECURITY_DEEP='1'; process.env.AGENTIC_SECURITY_DEEP_IN_CI='1';
const { runScan } = await import('/tmp/pre-fix/scanner/src/runScan.js');
for (const d of ['js-assign-sink-cmdi-shape','php-superglobal-cmdi-shape']) {
  const { scan } = await runScan('/Users/ross/code/agentic-security/bench/cve-replay/deep/'+d+'/pre');
  const all=[...(scan.findings||[]),...(scan.logicVulns||[])];
  console.log(d, 'pre-fix findings:', all.length, all.map(f=>f.parser+':'+f.cwe).join(','));
}
"
cd /Users/ross/code/agentic-security && git worktree remove /tmp/pre-fix --force
```

Record what each reported. **An entry that already fires pre-fix does not prove its fix** — rework it so the flow is only reachable through the fixed path, and say so.

- [ ] **Step 5: Confirm no pre-existing entry moved, then regenerate the baseline**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run bench:cve-replay:check 2>&1 | tail -20; echo "CHECK_EXIT=$?"
```

New entries showing as drift is expected. **A verdict change on any of the 197 existing entries is a regression from Tasks 2 or 3** and must be reported, not absorbed.

```bash
npm run bench:cve-replay:update-baseline 2>&1 | tail -5
npm run bench:cve-replay:check >/dev/null 2>&1; echo "clean=$?"
```

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/cve-replay/
git commit -m "test(corpus): add deep entries for the two recall gaps

One entry per fix: a sink on an assignment right-hand side across a function
boundary, and a PHP superglobal reaching a sink through a helper. Each is
verified to be missed without its fix, so a regression in either path fails the
corpus rather than passing silently."
```

---

## Task 5: Measure and decide

**Files:** Create `bench/engine-recall/RESULTS.md`.

- [ ] **Step 1: Re-run the harness and the guards**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run build >/dev/null 2>&1
npm run bench:engine-recall 2>&1 | tee /tmp/recall-after.txt
npm run bench:self-scan 2>&1 | tail -4
npm run bench:self-scan:check >/dev/null 2>&1; echo "selfscan=$?"
npm run bench:cve-replay:check >/dev/null 2>&1; echo "corpus=$?"
npm test > /tmp/t5.log 2>&1; echo "TEST_EXIT=$?"; tail -4 /tmp/t5.log
```

- [ ] **Step 2: Check precision on real third-party code**

```bash
cd /Users/ross/code/agentic-security/scanner
node ../bench/proof-corpus/runner.mjs --only ghost,superset 2>&1 | tail -10
```

Run in the background and poll; these clone large repositories. Compare against the recorded figures — ghost coverage 94% with 1124 findings, superset 100% with 860. If a target cannot complete, record "not measured" rather than guessing.

- [ ] **Step 3: Write RESULTS.md**

Record: the before/after for both defects from `/tmp/recall-before.txt` and `/tmp/recall-after.txt`; the self-scan before and after with per-file deltas if any changed; the proof-corpus comparison; the corpus entry count and verdicts; and every gate exit code.

- [ ] **Step 4: Answer three questions explicitly**

1. Are assignment-position sinks now detected, and does the statement-position control still work?
2. Are all 10 global sources reachable, and are they language-scoped?
3. **Did precision hold?** Self-scan, polyglot, and the proof-corpus targets. Both fixes raise recall, so a rise in findings is expected somewhere — the question is whether the new findings are true positives. If the self-scan baseline had to be regenerated, list each new finding and say why it is genuine.

Be willing to write an unfavourable answer to (3). A recall fix that floods a real codebase with false positives is not a win, and the honest result is more useful than a green summary.

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/engine-recall/RESULTS.md
git commit -m "test(bench): record the engine recall-gap before/after"
```

---

## Self-Review

**Coverage:** Defect 1 — Tasks 1 (baseline), 2 (fix), 4 (corpus), 5 (measure). Defect 2 — Tasks 1, 3, 4, 5. Precision guards — Tasks 2 Step 6, 3 Step 5, 5 Steps 1–2.

**Placeholder scan:** none. Task 4 Step 4's worktree offset (`HEAD~3` or `HEAD~2`) is a fallback for commit-count variance, not an unfilled blank, and the step states what to do with the result either way.

**Type consistency:** the harness output shape `{ assignSink: { statement, assignment }, globalSources: { total, reachable, byLanguage } }` is produced in Task 1 and consumed in Task 5. `matchSource(expr, file)` and `matchSinkOrSanitizer(callee, file)` are used with the file argument that exists on `main` today. `GLOBAL_INDEX` is introduced in Task 3 alongside the existing `CALLEE_INDEX` and `MEMBER_INDEX`.

**Known risks, stated rather than hidden.** Task 2's extraction touches the one taint path that currently works — an extraction that subtly changes `case 'call'` would be worse than the bug, which is why Step 3 requires confirming it unchanged before `case 'assign'` is touched. And both fixes raise recall, so the self-scan may legitimately rise; the plan requires inspecting each new finding rather than baselining it reflexively, because a reflexive baseline update would convert this repo's precision gate into a rubber stamp.

---

**Plan complete and saved to `docs/superpowers/plans/2026-07-26-engine-recall-gaps.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
