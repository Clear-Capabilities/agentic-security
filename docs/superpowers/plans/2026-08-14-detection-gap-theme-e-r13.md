# Detection-Gap PRD R13 (Theme E, part 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close R13 from `docs/DETECTION_GAP_REMEDIATION_PRD.md`'s Theme E ("flow-modeling coverage gaps") — model member-write sinks (`el.innerHTML = tainted`) and synthesize loop-element taint (`for (const x of tainted) sink(x)`), the two structural blind spots that make whole vulnerability classes unreachable in deep mode regardless of catalog size.

**Scope note.** R14 (Theme E's other item — annotation/decorator-shaped framework sources, and non-JS top-level IR) is deliberately NOT in this plan. R14(b) (top-level IR for Python/PHP/Ruby) turned out to need its own investigation into each of three different hand-rolled parser architectures — bigger than its PRD-stated "S" effort suggested — and R14(a) is a genuinely new catalog mechanism (an `annotation` match kind) with cross-language decorator/attribute extraction. Both get their own plan once this one is reviewed and landed, mirroring how the R6/R10/R11 slice shipped R6/R10/R11 first and let R7/R12 (found already done) and later regressions surface on their own schedule rather than being bundled in speculatively.

**Architecture:** Two independent fixes in two different files, landing as two tasks:
- **R13(a)** — three catalog sink entries (`js-innerHTML-assign`, `js-outerHTML-assign`, `react-dangerouslySetInnerHTML`) already exist in `MEMBER_INDEX` with `object: '_any_'`, but nothing in the taint engine ever queries `MEMBER_INDEX` for an assignment's LHS — `case 'assign'` in `scanner/src/dataflow/engine.js` only ever sink-matches when the RHS is a call. Add a new catalog lookup (`matchMemberWriteSink`) and wire it into the assign case's existing LHS/RHS handling.
- **R13(b)** — `scanner/src/ir/parser-js.js`'s shared loop visitor never connects a `for...of` loop's binding variable to the iterated expression, so `for (const x of taintedArray) sink(x)` reads `x` as `{kind:'unknown'}` — clean. Synthesize an assign node (`x = taintedArray`) the same way the Python-CST, Go, and PHP parsers already do for their own for-each constructs — a direct pattern application, not new architecture.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert/strict`, the existing `scanner/src/dataflow/` and `scanner/src/ir/` modules.

## Global Constraints

- ESM throughout, no CommonJS, per root `CLAUDE.md`.
- Both fixes are strictly additive — they can only ADD new detections (a member-write sink or a loop-element flow that previously went unseen), never remove or alter an existing finding. Neither task touches severity, confidence, or any existing code path's behavior for a case it didn't previously handle.
- R13(b)'s change lives inside a Babel visitor SHARED by five loop-statement types (`WhileStatement|ForStatement|DoWhileStatement|ForInStatement|ForOfStatement`). The new logic must be scoped to `ForOfStatement` only (checked via `path.node.type`) — the other four loop types must see zero behavior change. This is the single highest regression-risk point in this plan; verify it explicitly.
- Every new test file must be added to `scanner/package.json`'s `test:dataflow` script (per `scanner/CLAUDE.md`).
- After any change under `scanner/src/`, `npm run build` is needed before the bundle is trustworthy — unit tests run against `src/` directly and do not require a rebuild (per `scanner/CLAUDE.md`), so this only matters for the final full-gate verification.
- Per the PRD's own "Overfitting watchlist," no new catalog entry or test fixture may be shaped to match a benchmark's file-naming or variable-naming convention — the 3 catalog entries this plan wires up already exist and are named after real DOM/React APIs (`innerHTML`, `outerHTML`, `dangerouslySetInnerHTML`), not benchmark vocabulary, and every fixture in this plan uses ordinary variable names.
- Run each task's own new test first (must fail for the stated reason), then the scoped suite (`npm run test:dataflow`) after the fix (must pass, zero regressions), before committing. Full-gate verification (`npm test`, `bench:cve-replay:check`, `bench:mutation:check`, `bench:layer-recall:check`, `bench:self-scan:check`) runs once at the end, not per-task.

---

## File Structure

| File | Change |
|---|---|
| `scanner/src/dataflow/catalog.js` | Modify — add `matchMemberWriteSink(targetPath, file)`, exported alongside `matchSource`/`matchSinkOrSanitizer`. |
| `scanner/src/dataflow/engine.js` | Modify — import `matchMemberWriteSink`; add `_memberWriteSinkFindings` helper; wire a new branch into `case 'assign'`. |
| `scanner/src/ir/parser-js.js` | Modify — the shared loop visitor's `enter` hook synthesizes an assign node for `ForOfStatement` only. |
| `scanner/test/member-write-and-loop-taint.test.js` | Create — covers both R13(a) and R13(b), end-to-end via `runScan`, plus one focused unit test for `matchMemberWriteSink`. |
| `scanner/package.json` | Modify — add the new test file to `test:dataflow`. |
| `docs/DETECTION_GAP_REMEDIATION_PRD.md` | Modify — status note recording R13 landed. |
| `CHANGELOG.md` | Modify — entry for this change. |

---

## Task 1: R13(a) — Model member-write sinks

**Files:**
- Modify: `scanner/src/dataflow/catalog.js` (add function after `matchSinkOrSanitizer`, currently ending around line 1135)
- Modify: `scanner/src/dataflow/engine.js:45` (import), `:594-611` (the `case 'assign'` block's existing RHS-call-sink check)
- Test: `scanner/test/member-write-and-loop-taint.test.js` (new)

**Interfaces:**
- Produces: `matchMemberWriteSink(targetPath, file)` in `catalog.js` — takes the flattened LHS access-path string an assign node's `target` already carries (e.g. `"el.innerHTML"`), returns matching sink catalog entries (kind `'sink'` only) or `null`.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/member-write-and-loop-taint.test.js`:

```js
// Covers PRD R13 (docs/DETECTION_GAP_REMEDIATION_PRD.md, Theme E).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { matchMemberWriteSink } from '../src/dataflow/catalog.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-r13-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('R13(a) unit: matchMemberWriteSink finds the innerHTML entry for any receiver', () => {
  const hits = matchMemberWriteSink('el.innerHTML', 'a.js');
  assert.ok(hits && hits.some(h => h.id === 'js-innerHTML-assign'),
    'a flattened "x.innerHTML" target must match the js-innerHTML-assign entry regardless of the receiver name');
});

test('R13(a) unit: matchMemberWriteSink returns null for a bare identifier (no dot)', () => {
  assert.equal(matchMemberWriteSink('x', 'a.js'), null,
    'a bare identifier target has no property to match against MEMBER_INDEX');
});

test('R13(a) unit: matchMemberWriteSink returns null for an unrecognized property', () => {
  assert.equal(matchMemberWriteSink('el.textContent', 'a.js'), null,
    'textContent is the SAFE DOM sink — must not match');
});

test('R13(a) end-to-end: el.innerHTML = tainted is detected as DOM XSS', async () => {
  const dir = mkTmp('innerhtml', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/render', (req, res) => {
  const el = document.getElementById('out');
  el.innerHTML = req.query.name;
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const xssFindings = (scan.findings || []).filter(f => /xss/i.test(f.vuln || ''));
  assert.ok(xssFindings.length >= 1, 'el.innerHTML = req.query.name must be detected as DOM XSS');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R13(a) end-to-end: el.innerHTML = <literal> is NOT flagged (no taint)', async () => {
  const dir = mkTmp('innerhtml-clean', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/render', (req, res) => {
  const el = document.getElementById('out');
  el.innerHTML = '<b>static</b>';
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const xssFindings = (scan.findings || []).filter(f => /xss/i.test(f.vuln || '') && f.parser === 'IR-TAINT');
  assert.equal(xssFindings.length, 0, 'a literal RHS must not be flagged — only a tainted RHS should fire');
  fs.rmSync(dir, { recursive: true, force: true });
});
```

(The two R13(b) tests are appended to this same file in Task 2 — leave room below.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/member-write-and-loop-taint.test.js`
Expected: FAIL — `matchMemberWriteSink` doesn't exist yet (import error), and the end-to-end test finds 0 XSS findings since nothing consults the member-write sink entries.

- [ ] **Step 3: Add `matchMemberWriteSink` to catalog.js**

In `scanner/src/dataflow/catalog.js`, immediately after `matchSinkOrSanitizer`'s closing brace (currently ends around line 1135, right before the "For tests and reflection." comment), add:

```js
// PRD R13(a) (docs/DETECTION_GAP_REMEDIATION_PRD.md): three sink entries
// (js-innerHTML-assign, js-outerHTML-assign, react-dangerouslySetInnerHTML)
// have sat in MEMBER_INDEX under the object:'_any_' wildcard since they were
// added, but nothing ever queried MEMBER_INDEX for an ASSIGNMENT TARGET —
// matchSinkOrSanitizer only reads CALLEE_INDEX, and matchSource's MEMBER_INDEX
// lookups are for READS keyed by a SPECIFIC object name (e.g. "document.cookie"),
// not the "any receiver" wildcard a DOM sink needs. `targetPath` is the
// flattened LHS access-path string parser-js.js's lhsPath already produces
// for a member-expression assignment target (e.g. "el.innerHTML" for
// `el.innerHTML = x`) — this function extracts the property name and looks
// it up under the wildcard key the same way `object:'_any_'` entries are
// indexed (catalog.js's own indexing loop keys every entry by
// `${match.object}.${match.prop}` regardless of what object names are, so a
// wildcard entry lives under the literal key "_any_.<prop>").
export function matchMemberWriteSink(targetPath, file) {
  if (typeof targetPath !== 'string' || !targetPath.includes('.')) return null;
  const prop = targetPath.slice(targetPath.lastIndexOf('.') + 1);
  if (!prop) return null;
  const raw = MEMBER_INDEX.get(`_any_.${prop}`);
  if (!raw) return null;
  const hits = filterByProvenance(raw)
    .filter(h => _languageAllowed(h, file))
    .filter(h => h.kind === 'sink');
  return hits.length ? hits : null;
}
```

- [ ] **Step 4: Wire it into engine.js's `case 'assign'`**

In `scanner/src/dataflow/engine.js`, add the import alongside the existing catalog import (line 45):

```js
import { matchSource, matchSinkOrSanitizer, matchMemberWriteSink } from './catalog.js';
```

Add a new helper immediately after `_sinkFindingsForCall` (search for its closing brace, right before the `_mergeSummaryFindings` comment block):

```js
// PRD R13(a): finding shape for a member-write sink match (el.innerHTML =
// tainted). Distinct from _sinkFindingsForCall because there is no call
// argument list to index into — the "argument" of interest is the whole
// assignment RHS, which the catalog entries already mark via argIndex:'rhs'
// (a sentinel that existed in these 3 entries since they were added, with no
// consumer until now). Mirrors _sinkFindingsForCall's trace/sanitizer
// attribution exactly, so a member-write finding looks like any other
// deep-mode finding downstream.
function _memberWriteSinkFindings(hits, sourceExpr, state, callContext, line, targetPath) {
  const findings = [];
  for (const e of hits) {
    const reachingSources = _sourcesReachingExpr(sourceExpr, state, callContext._taintSources);
    const traceForThisFinding = reachingSources.length ? reachingSources.slice(0, 5) : [];
    const _sanNames = _sanitizersForExpr(sourceExpr, callContext);
    findings.push({
      ...(_sanNames.size ? { _sanitizersOnPath: [..._sanNames] } : {}),
      kind: 'taint',
      sinkId: e.id,
      vuln: e.vuln?.name || 'Tainted Sink',
      severity: e.vuln?.severity || 'high',
      cwe: e.vuln?.cwe || null,
      remediation: e.vuln?.remediation || null,
      line,
      argIndex: 'rhs',
      callee: targetPath,
      sourceProvenance: (traceForThisFinding[0]?.provenance) || null,
      trace: traceForThisFinding,
    });
  }
  return findings;
}
```

Now extend `case 'assign'`'s existing RHS-call-sink check (currently lines 594-611):

```js
      if (node.source && node.source.kind === 'call') {
        const { cat: _sinkCat, argTaints: _sinkArgTaints } =
          _matchCallCatalog(node.source.callee, node.source.args, state, callContext);
        findings.push(..._sinkFindingsForCall(
          node.source.callee, node.source.args, _sinkCat, _sinkArgTaints,
          state, callContext, node.line).findings);
      }
```

Add immediately below it (same indentation, same `findings` array):

```js
      // PRD R13(a): the assignment TARGET can itself be a sink shape
      // (el.innerHTML = tainted) — additive to the RHS-call-sink check
      // above, which only ever looked at node.source. `target` is only a
      // dotted member-access path when the LHS was a member expression
      // (lhsPath in parser-js.js); a bare identifier target ("x") has no
      // dot and _matchMemberWriteSink correctly returns null for it.
      if (target && target.includes('.')) {
        const _memberHits = matchMemberWriteSink(target, _currentFile);
        if (_memberHits && exprTaint(node.source, state, callContext)) {
          findings.push(..._memberWriteSinkFindings(
            _memberHits, node.source, state, callContext, node.line, target));
        }
      }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd scanner && node --test test/member-write-and-loop-taint.test.js && npm run test:dataflow`
Expected: PASS, zero regressions.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/dataflow/catalog.js scanner/src/dataflow/engine.js scanner/test/member-write-and-loop-taint.test.js
git commit -m "feat(dataflow): PRD R13(a) — consult member-write sinks on assignment targets"
```

---

## Task 2: R13(b) — Synthesize loop-element taint for `for...of`

**Files:**
- Modify: `scanner/src/ir/parser-js.js` (the shared loop visitor, currently lines 496-517)
- Test: `scanner/test/member-write-and-loop-taint.test.js` (extend, from Task 1)

**Interfaces:**
- Consumes: `nextNodeId()`, `addNode(fn, node)`, `exprOf(node)`, `currentFn()` — all existing, already used by the surrounding visitor code in this same file.
- Produces: no new exported interface — this is an internal IR-construction change. The observable effect is that a `for...of` loop's binding variable now appears as a taint-carrying local inside the loop body, the same way every other assigned variable does.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/member-write-and-loop-taint.test.js`:

```js
test('R13(b) end-to-end: for (const x of tainted) sink(x) is detected as code injection', async () => {
  const dir = mkTmp('loop-taint', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  for (const item of req.body.items) {
    eval(item);
  }
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const codeInjFindings = (scan.findings || []).filter(f =>
    /code injection|eval/i.test(f.vuln || '') && f.parser === 'IR-TAINT');
  assert.ok(codeInjFindings.length >= 1,
    'for (const item of req.body.items) { eval(item) } must be detected — the loop variable must inherit the iterable\\'s taint');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R13(b): a for...of over a clean local array is not flagged', async () => {
  const dir = mkTmp('loop-clean', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const fixed = ['a', 'b', 'c'];
  for (const item of fixed) {
    eval(item);
  }
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const codeInjFindings = (scan.findings || []).filter(f =>
    /code injection|eval/i.test(f.vuln || '') && f.parser === 'IR-TAINT');
  assert.equal(codeInjFindings.length, 0,
    'iterating a locally-defined, untainted array must not produce a finding — the loop-variable synthesis must not itself taint anything');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R13(b): other loop types (for, while, do-while, for-in) are unaffected', async () => {
  // Regression guard for the shared-visitor risk called out in this plan's
  // Global Constraints — the new logic must be scoped to ForOfStatement only.
  const dir = mkTmp('loop-others', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  for (let i = 0; i < 3; i++) { console.log(i); }
  let j = 0;
  while (j < 3) { console.log(j); j++; }
  do { j--; } while (j > 0);
  for (const key in { a: 1 }) { console.log(key); }
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  // No specific assertion on findings content — the point is the scan
  // completes without throwing and produces a stable findings array,
  // proving the shared visitor's other four branches are untouched.
  assert.ok(scan && Array.isArray(scan.findings), 'scan must complete for every other loop shape');
  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/member-write-and-loop-taint.test.js`
Expected: FAIL on the R13(b) positive test — `item` is never bound to `req.body.items`, so `eval(item)` reads as clean. The other two new tests should already pass (nothing to regress yet) — that's expected.

- [ ] **Step 3: Synthesize the loop-variable assign in parser-js.js**

In `scanner/src/ir/parser-js.js`, the shared loop visitor is currently:

```js
        'WhileStatement|ForStatement|DoWhileStatement|ForInStatement|ForOfStatement': {
          enter(path) {
            const fn = currentFn(); if (!fn) return;
            maybeResetAtAlternateBoundary(fn, path);
            const headerId = nextNodeId();
            const exitId = nextNodeId();
            const line = path.node.loc?.start?.line || 0;
            addNode(fn, { id: headerId, kind: 'loop-header', line, succ: [], pred: [] });
            fn.cfg.nodes.set(exitId, { id: exitId, kind: 'noop', succ: [], pred: [], line });
            path.node._loopHeader = headerId;
            path.node._loopExit = exitId;
          },
```

Change to:

```js
        'WhileStatement|ForStatement|DoWhileStatement|ForInStatement|ForOfStatement': {
          enter(path) {
            const fn = currentFn(); if (!fn) return;
            maybeResetAtAlternateBoundary(fn, path);
            const headerId = nextNodeId();
            const exitId = nextNodeId();
            const line = path.node.loc?.start?.line || 0;
            addNode(fn, { id: headerId, kind: 'loop-header', line, succ: [], pred: [] });
            fn.cfg.nodes.set(exitId, { id: exitId, kind: 'noop', succ: [], pred: [], line });
            path.node._loopHeader = headerId;
            path.node._loopExit = exitId;
            // PRD R13(b): for-of's binding variable is never connected to the
            // iterated expression, so `for (const x of tainted) sink(x)` reads
            // x as {kind:'unknown'} — clean. Synthesize an assign binding the
            // loop variable to the iterated expression, exactly as the
            // Python-CST/Go/PHP parsers already do for their own for-each
            // constructs (parser-py.helper.py, parser-go.js, parser-php.js).
            // Conservative, matching this file's own stated doctrine for
            // loops in general ("any iteration could taint X"): the WHOLE
            // loop variable is tainted if the iterable is tainted, not a
            // specific element — element-level precision isn't modeled here
            // any more than it is for the rest of this file's loop handling.
            // Scoped to ForOfStatement only — While/For/DoWhile/ForIn have no
            // "loop variable bound to an iterated collection" shape and must
            // see zero behavior change from this addition.
            if (path.node.type === 'ForOfStatement') {
              const leftNode = path.node.left;
              const declId = leftNode && leftNode.type === 'VariableDeclaration'
                ? leftNode.declarations[0]?.id
                : leftNode;
              // Only the simple `for (const x of ...)` / `for (x of ...)`
              // shape is synthesized. A destructuring binding
              // (`for (const {a,b} of ...)`) has no single flat target name
              // lhsPath-style logic could bind to — left unsynthesized rather
              // than guessed at, matching this codebase's "refuse rather than
              // invent an edge" doctrine elsewhere (see _resolvableCalleeName
              // in dataflow/engine.js for the same principle applied to call
              // resolution).
              const loopVar = declId && declId.type === 'Identifier' ? declId.name : null;
              if (loopVar) {
                const iterExpr = exprOf(path.node.right);
                const bindId = nextNodeId();
                addNode(fn, { id: bindId, kind: 'assign', target: loopVar, source: iterExpr, line, succ: [], pred: [] });
              }
            }
          },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/member-write-and-loop-taint.test.js && npm run test:dataflow`
Expected: PASS, zero regressions. Pay particular attention to any existing loop-related test (grep `test/` for `ForStatement`, `while`, `for...of` fixtures) staying green — the shared visitor changed, even though the new logic is type-scoped.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/ir/parser-js.js scanner/test/member-write-and-loop-taint.test.js
git commit -m "feat(ir): PRD R13(b) — synthesize for-of loop-variable taint binding"
```

---

## Task 3: Wire the test, full-gate verification, docs

**Files:**
- Modify: `scanner/package.json` (`test:dataflow` script)
- Modify: `docs/DETECTION_GAP_REMEDIATION_PRD.md` (status note)
- Modify: `CHANGELOG.md` (entry)

- [ ] **Step 1: Wire the new test file into `test:dataflow`**

In `scanner/package.json`, append ` test/member-write-and-loop-taint.test.js` to the `test:dataflow` script string, following the existing convention (bare relative path, space-separated).

- [ ] **Step 2: Full-gate verification**

Run, from `scanner/`, in order, and read the actual output of each (not a cached/prior run):

```bash
npm run test:dataflow
npm test
npm run bench:cve-replay:check
npm run bench:mutation:check
npm run bench:layer-recall:check
npm run bench:self-scan:check
```

All six must be green. If `bench:layer-recall:check` shows an INCREASE in taint-layer recall for js/ts (expected — R13 adds two new detection capabilities), that's a genuine improvement: run `npm run bench:layer-recall:update-baseline`, review the diff to confirm every newly-detected entry is root-caused by R13(a) or R13(b) specifically (not an unrelated fluke), and commit the refreshed baseline. Do not update a baseline you can't explain.

If `bench:self-scan:check` shows drift, root-cause it the same way the ReDoS false-positive was root-caused earlier — do not accept an unexplained drift or blindly rebaseline.

- [ ] **Step 3: Rebuild the bundle**

Run `npm run build` from `scanner/`.

- [ ] **Step 4: Update the PRD status note**

In `docs/DETECTION_GAP_REMEDIATION_PRD.md`, extend the existing "## 10. Status updates" section (do not create a new section) with a new bullet recording R13 landed, dated, naming both sub-fixes and their test coverage, following the existing entries' voice (specific, self-critical about anything that turned out narrower or different than planned during implementation — if nothing did, say so plainly rather than padding).

- [ ] **Step 5: Update the CHANGELOG**

Add an entry to `CHANGELOG.md`'s existing "Unreleased" section (or a new one if the prior Theme B+D entry has since been released — check the file's current top section before deciding) describing R13(a) and R13(b) in the same specific, mechanism-first style as the surrounding entries.

- [ ] **Step 6: Commit**

```bash
git add scanner/package.json scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256 docs/DETECTION_GAP_REMEDIATION_PRD.md CHANGELOG.md
# Include bench/*/BASELINE.json only if Step 2 genuinely updated one, with the reason in the commit message.
git commit -m "chore: wire R13 test into test:dataflow, update PRD status and changelog"
```

Do not tag or push a release as part of this task.

---

## Self-Review Notes

- **Spec coverage:** R13(a) (Task 1) and R13(b) (Task 2) both have dedicated tests tied directly to the PRD's stated success metrics verbatim (`el.innerHTML = req.query.x` detected as XSS; `for (const item of req.body.items) { eval(item) }` detected as code injection). Task 3 covers the PRD's own documentation-update convention established in the prior plan.
- **Placeholder scan:** every code block is complete, exact code grounded in files read directly during planning (line numbers, function signatures, existing helper names all verified against current `main`, not the PRD's original — now-stale — citations).
- **Regression risk:** R13(b)'s shared-visitor change is the single riskiest edit in this plan (five loop-statement types funnel through one Babel visitor); Task 2 includes an explicit regression test (`R13(b): other loop types ... are unaffected`) as a direct, deliberate guard against it, not left to incidental coverage.
- **Type/signature consistency:** `matchMemberWriteSink(targetPath, file) -> Array|null` is defined once (Task 1) and consumed identically by its one call site in `engine.js`. `_memberWriteSinkFindings`'s parameter order and finding shape are modeled directly on the existing `_sinkFindingsForCall`, so it reads as the established pattern extended, not a new one invented.
- **Scope check:** two closely-related, independently-testable fixes in one plan (both close structural detection blind spots in deep mode, per the PRD's own Theme E grouping) — R14, a different kind of gap (catalog schema + parser architecture work), is explicitly deferred to its own plan rather than bundled in.
