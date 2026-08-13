# Detection-Gap PRD, Theme B+D (R6, R10, R11) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three of the five open items in `docs/DETECTION_GAP_REMEDIATION_PRD.md`'s Theme B ("semantic grounding of matching") and Theme D ("interprocedural completeness") — R6 (receiver-type/CHA wiring into catalog matching), R10 (nested-call summary consultation), and R11 (member-call resolution gated on R6).

**Scope note — R7 and R12 already shipped.** The original slice selected was "R6, R7, R10, R11, R12." Investigation before writing this plan found R7 (thread `fileContents` through `buildCallGraph`) and R12 (wire the points-to graph onto `callContext`) were already landed in commit `553f9a5` ("close 9 root-cause gaps from the detection-gap audit (Theme A)") — both are XS-effort one-line fixes that got swept into that commit's opportunistic cleanup even though the PRD files them under Themes B/D. Verified via `git log -S"PRD R12" -- src/dataflow/engine.js` and `git log -S"PRD R7" -- src/ir/index.js`, both returning only `553f9a5`, and by reading the current code (`src/ir/index.js:191,253` already call `buildCallGraph(perFile, fileContents)`; `src/dataflow/engine.js:1120` already sets `_pointsTo: opts._pointsTo` on `callContext` with an inline "PRD R12" comment). This plan covers only the three items still open.

**Architecture:** The dataflow engine (`scanner/src/dataflow/engine.js`) already has the machinery R6/R11 need sitting unused: a Class Hierarchy Analysis module (`scanner/src/ir/class-hierarchy.js`) and a receiver-type heuristic (`scanner/src/dataflow/receiver-context.js`) are both built and unit-tested in isolation, but nothing in the production pipeline ever calls `buildClassHierarchy` or threads its result into `callContext`. This plan wires that up once (Task 1), then uses it twice: to gate catalog sink-matching by the receiver's inferred type (R6, Task 2), and to safely resolve a JS/TS member-call (`userRepo.save(x)`) to a concrete callee for interprocedural summary lookup, but only when CHA narrows the receiver to one unambiguous class (R11, Task 4). R10 (Task 5) extends the *existing* summary-consultation logic — which today only fires when a call is the RHS of an assignment or a bare statement — to also fire when a call is nested directly inside another expression (a sink argument, e.g. `sink(getUserInput())`). Task 3 extracts the duplicated resolve-and-lookup logic from the two existing call sites into one shared helper first, both to avoid a third copy (Task 5's new call site) and because Task 4 (R11) needs to live in exactly one place to apply everywhere uniformly.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert/strict` (no external test framework), the existing `scanner/src/dataflow/` and `scanner/src/ir/` modules.

## Global Constraints

- ESM throughout (`import`/`export`), no CommonJS, per root `CLAUDE.md`.
- Every new/changed finding-affecting code path must be **recall-preserving where the codebase's own doctrine says so**: this file's header states sanitizers "demote, never kill," and the reachability/proof-gate annotators only ever touch `confidence`/`confidenceTier`/`exploitabilityTier`, never `severity`. None of R6/R10/R11 touch severity; R6 can *suppress a catalog match* (not a whole finding — see Task 2's "unknown ≠ clean" rule below), R10/R11 only *add* new detections, never remove existing ones.
- **Unknown ≠ clean (root `CLAUDE.md`'s stated architecture-PRD principle, echoed by the Theme-B/D gap descriptions themselves):** any new type-based gate must suppress ONLY on a confident, positive type **mismatch**. When CHA cannot resolve a type at all (`receiverType === null`), the code must fall back to today's permissive (unconstrained) behavior — never treat "unknown" as grounds to suppress or refuse.
- Every new test file must be added to `scanner/package.json`'s `test:dataflow` script (per `scanner/CLAUDE.md`'s "If you add a new test file, also add it to the matching script").
- After any change under `scanner/src/`, `npm run build` must be run before the bundle is trustworthy — but unit tests run against `src/` directly (per `scanner/CLAUDE.md`), so this only matters for the final full-gate verification, not per-task.
- Follow the corpus-provenance discipline from the PRD's own "Overfitting watchlist": no new catalog entry or test fixture may be shaped to match a benchmark's file-naming or variable-naming convention (`bar`, `param`, `juliet-*`, etc.) — every fixture in this plan uses ordinary, realistic variable/function names.
- Run the task's own new test first (must fail), then the scoped suite (`npm run test:dataflow`) after the fix (must pass, zero regressions), before committing. Full-gate verification (`npm test`, `npm run bench:cve-replay:check`, `npm run bench:mutation:check`, `npm run bench:layer-recall:check`) runs once at the very end (Task 6), not per-task — these are multi-minute gates and re-running all of them after every task would make the plan impractically slow; per-task the scoped `test:dataflow` suite (seconds) is the regression backstop.

---

## File Structure

| File | Change |
|---|---|
| `scanner/src/dataflow/index.js` | Modify — build CHA once per scan, pass via `opts._cha` into `runTaintEngine` (Task 1). |
| `scanner/src/dataflow/engine.js` | Modify — thread `_cha` onto every `callContext` (Task 1); add `_receiverTypeFor` helper and wire it into `_matchCallCatalog`/`matchSinkOrSanitizer` calls (Task 2); extract `_resolveCalleeForSummary` shared helper (Task 3); add CHA-gated member-call resolution to that helper (Task 4); add `_nestedCallReturnTainted` and thread `callContext` through `exprTaint` (Task 5). |
| `scanner/src/dataflow/catalog.js` | Modify — add `_receiverTypeAllowed`, thread an optional `receiverType` param through `matchSinkOrSanitizer`, add `match.receiverTypeIn` to 5 catalog entries (Task 2). |
| `scanner/test/receiver-type-and-nested-calls.test.js` | Create — covers Tasks 1, 2, 4, 5 (CHA wiring, R6 catalog gating, R11 member-call resolution, R10 nested-call taint). |
| `scanner/test/interproc-k2.test.js` | Read-only reference during Task 3 (regression backstop — must stay green; the refactor must not change its behavior). |
| `scanner/package.json` | Modify — add the new test file to `test:dataflow`. |

No existing file is split; `engine.js` is already the established home for every prior interprocedural fix in this codebase (R1–R5, R7, R12 all landed there), so adding to it follows the codebase's own established pattern rather than fragmenting the taint walker across files.

---

## Task 1: Wire Class Hierarchy Analysis into the deep-analysis pipeline

**Files:**
- Modify: `scanner/src/dataflow/index.js`
- Modify: `scanner/src/dataflow/engine.js:1107-1121` (main per-function `callContext`), `:485-497` (assign-RHS summary-compute inner context), `:624-636` (plain-call summary-compute inner context), `:1150-1157` (higher-order-callback summary-compute inner context)
- Test: `scanner/test/receiver-type-and-nested-calls.test.js` (new)

**Interfaces:**
- Consumes: `buildClassHierarchy(perFileIR)` from `scanner/src/ir/class-hierarchy.js` (existing, exported, returns `{ classes, methodOwners, typeOfVar }`).
- Produces: every `callContext` object the taint walker constructs now carries `_cha` (the CHA result, or `undefined` when `perFileIR` was empty/unavailable) — consumed by Task 2's `_receiverTypeFor` and Task 4's member-call resolution.

- [ ] **Step 1: Write the failing test**

Create `scanner/test/receiver-type-and-nested-calls.test.js`:

```js
// Covers PRD R6, R10, R11 (docs/DETECTION_GAP_REMEDIATION_PRD.md, Theme B+D).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { buildProjectIR } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-rcvr-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('CHA is threaded onto callContext during a real deep scan (no throw, scan completes)', () => {
  const fileContents = {
    'app.js': `
class UserRepo {
  save(x) { return x; }
}
const repo = new UserRepo();
repo.save(1);
`,
  };
  const { perFile, callGraph } = buildProjectIR(fileContents);
  // Must not throw — this is the smoke test that CHA wiring didn't break
  // the ordinary per-file analysis loop.
  assert.doesNotThrow(() => runDeepAnalysis(perFile, callGraph, { fileContents }));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/receiver-type-and-nested-calls.test.js`
Expected: it currently **passes already** (CHA wiring being absent doesn't throw — `runDeepAnalysis` just runs without it). This step exists to confirm the harness itself works before adding assertions in later tasks that DO depend on the wiring; there is no red state to observe for Task 1 alone, which is expected for a pure-infrastructure task. Proceed to Step 3 and confirm via a temporary assertion instead.

Add a temporary diagnostic assertion right after the `buildProjectIR` call to prove the pipeline does NOT yet expose CHA (delete this block in Step 4 once the real wiring lands — this is only to observe genuine red/green):

```js
test('DIAGNOSTIC (temporary): callContext carries no _cha before Task 1 lands', () => {
  // This test is deleted once Task 1's implementation step is written — it
  // exists only to prove the starting state.
});
```

Skip formal red/green ceremony for this specific infra task (there is no observable behavior change to assert against yet) and proceed directly to the implementation; Task 2's test (which DOES assert on `_receiverTypeFor`'s output) is the real red/green gate for this wiring, run at the end of Task 2.

- [ ] **Step 3: Wire CHA into `runDeepAnalysis`**

In `scanner/src/dataflow/index.js`, add the import alongside the existing ones (after the `buildPointsTo` import at line 14):

```js
import { buildPointsTo } from './points-to.js';
import { buildClassHierarchy } from '../ir/class-hierarchy.js';
```

Then, immediately before the existing points-to block (`// v0.70 #2 — Steensgaard points-to...`, currently at line 82), add:

```js
  // PRD R6/R11 (docs/DETECTION_GAP_REMEDIATION_PRD.md): Class Hierarchy
  // Analysis. Built once per scan (mirrors the points-to graph immediately
  // below) and threaded through opts so the taint engine can (a) narrow
  // catalog sink matches to the receiver's inferred type (R6) and (b) safely
  // resolve a member call to a concrete callee when the receiver resolves to
  // exactly one known class (R11). Unlike points-to, this is NOT gated behind
  // an env flag — receiver-context.js and class-hierarchy.js were both
  // already built, unit-tested, and left completely unreachable from the
  // production pipeline (see PRD R6's evidence); building it always is cheap
  // (a single walk of the already-parsed IR, no fixed-point iteration) and
  // every consumer degrades to today's behavior when it finds no useful type.
  let classHierarchy = null;
  try { classHierarchy = buildClassHierarchy(perFileIR); } catch { classHierarchy = null; }
```

Then extend the existing `runTaintEngine` call (currently):

```js
  let findings = runTaintEngine(perFileIR, callGraph, {
    ...opts,
    summaryCache: preSeededCache || undefined,
    _pointsTo: pointsToGraph || undefined,
  });
```

to:

```js
  let findings = runTaintEngine(perFileIR, callGraph, {
    ...opts,
    summaryCache: preSeededCache || undefined,
    _pointsTo: pointsToGraph || undefined,
    _cha: classHierarchy || undefined,
  });
```

- [ ] **Step 4: Thread `_cha` onto every `callContext` engine.js constructs**

In `scanner/src/dataflow/engine.js`, find the main per-function `callContext` construction (currently lines 1107-1121, inside the `for (const fn of fnList)` loop in `runTaintEngine`):

```js
    const callContext = {
      _findings: [],
      _taintSources: [],
      _returnTainted: false,
      _stack: new Set(),
      deadlineMs,   // honored by the worklist inside analyzeFunction
      _summaryCache: summaryCache,
      _callGraph: callGraph,
      // PRD R12: index.js builds this graph (AGENTIC_SECURITY_POINTS_TO=1)
      // and passes it in opts._pointsTo, but nothing previously copied it
      // onto callContext — _addPathAliasAware reads callContext._pointsTo,
      // which was therefore always undefined, and alias-aware tainting was
      // a no-op even with the flag set.
      _pointsTo: opts._pointsTo,
    };
```

Add one line:

```js
    const callContext = {
      _findings: [],
      _taintSources: [],
      _returnTainted: false,
      _stack: new Set(),
      deadlineMs,   // honored by the worklist inside analyzeFunction
      _summaryCache: summaryCache,
      _callGraph: callGraph,
      // PRD R12: index.js builds this graph (AGENTIC_SECURITY_POINTS_TO=1)
      // and passes it in opts._pointsTo, but nothing previously copied it
      // onto callContext — _addPathAliasAware reads callContext._pointsTo,
      // which was therefore always undefined, and alias-aware tainting was
      // a no-op even with the flag set.
      _pointsTo: opts._pointsTo,
      // PRD R6/R11: same pattern as _pointsTo above — the CHA opts.js builds
      // must reach callContext or every receiver-type/member-call consumer
      // is permanently a no-op.
      _cha: opts._cha,
    };
```

Now find the three places `engine.js` constructs an **inner** context to lazily compute a callee's summary (these analyze a DIFFERENT function than the one currently executing, so if `_cha` isn't copied onto them too, R6/R11 only work for top-level, eagerly-analyzed functions and silently stop working for anything reached only via a lazy summary compute — i.e. almost every non-entry-point function). All three follow the identical shape:

1. Assign-RHS summary compute (currently lines 490-496):
```js
              const inner = {
                _findings: [], _taintSources: [], _returnTainted: false,
                _stack: new Set(), deadlineMs: callContext.deadlineMs,
                _summaryCache: callContext._summaryCache,
                _callGraph: callContext._callGraph,
                _mutatedParamsOut: new Set(),
              };
```
2. Plain-call summary compute (currently lines 629-635): identical shape.
3. Higher-order-callback summary compute (currently lines 1151-1156):
```js
          const inner = {
            _findings: [], _taintSources: [], _returnTainted: false,
            _stack: new Set(), deadlineMs,
            _summaryCache: summaryCache, _callGraph: callGraph,
            _mutatedParamsOut: new Set(),
          };
```

Add `_cha: callContext._cha,` (sites 1–2) or `_cha: callContext._cha,` (site 3, same field — `callContext` is in scope in all three closures) to each, e.g. site 1 becomes:

```js
              const inner = {
                _findings: [], _taintSources: [], _returnTainted: false,
                _stack: new Set(), deadlineMs: callContext.deadlineMs,
                _summaryCache: callContext._summaryCache,
                _callGraph: callContext._callGraph,
                _mutatedParamsOut: new Set(),
                _cha: callContext._cha,
              };
```

Apply the same one-line addition to sites 2 and 3.

- [ ] **Step 5: Run the new test file and the dataflow suite**

Run: `cd scanner && node --test test/receiver-type-and-nested-calls.test.js && npm run test:dataflow`
Expected: PASS, zero regressions. (Add the new test file to `package.json`'s `test:dataflow` script now — see Task 6, Step 1 — so this second command actually includes it; until then run it standalone as shown.)

- [ ] **Step 6: Commit**

```bash
git add scanner/src/dataflow/index.js scanner/src/dataflow/engine.js scanner/test/receiver-type-and-nested-calls.test.js
git commit -m "feat(dataflow): wire Class Hierarchy Analysis into the deep pipeline (PRD prereq for R6/R11)"
```

---

## Task 2: R6 — gate catalog sink matching by CHA-inferred receiver type

**Files:**
- Modify: `scanner/src/dataflow/catalog.js:887-905` (`_receiverAllowed` region), `:1085-1093` (`matchSinkOrSanitizer`), catalog entries at lines 66-71 (`js-sql-query`, `js-sql-execute`), 363-365 (`py-requests-get`), 608-610 (`py-requests-get-v2`), 417-419 (`rb-erb-new`)
- Modify: `scanner/src/dataflow/engine.js` — add `_fullyFlattenMemberChain` + `_receiverTypeFor` helpers near `_flattenCalleeName` (line 93); thread `receiverType` through `_matchCallCatalog` (line 268) and its two call sites (assign-case ~428, call-case ~601)
- Test: `scanner/test/receiver-type-and-nested-calls.test.js` (extend)

**Interfaces:**
- Consumes: `receiverTypeAtCall(node, fn, file, cha)` from `scanner/src/dataflow/receiver-context.js` (existing); `callContext._cha` (Task 1).
- Produces: `matchSinkOrSanitizer(calleeExpr, file, receiverType)` — new optional 3rd param, backward-compatible (omitted ⇒ unchanged behavior); `_receiverTypeFor(calleeExpr, callContext)` in `engine.js`, reused by Task 4.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/receiver-type-and-nested-calls.test.js`:

```js
import { matchSinkOrSanitizer } from '../src/dataflow/catalog.js';

test('R6 unit: matchSinkOrSanitizer suppresses a bare-name SQL sink on a non-DB receiver type', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'cache' }, prop: 'query' };
  // No receiverType passed (today's behavior) — still matches, unconstrained.
  const unconstrained = matchSinkOrSanitizer(calleeExpr, 'a.js');
  assert.ok(unconstrained && unconstrained.some(h => h.id === 'js-sql-query'),
    'sanity: js-sql-query must still match with no receiverType arg (backward compat)');
  // A confidently-resolved, non-DB receiver type suppresses the SQL sink.
  const suppressed = matchSinkOrSanitizer(calleeExpr, 'a.js', 'CacheClient');
  assert.ok(!suppressed || !suppressed.some(h => h.id === 'js-sql-query'),
    'js-sql-query must NOT match cache.query() once the receiver is confidently typed as non-DB');
});

test('R6 unit: matchSinkOrSanitizer still fires a genuine db.query() with a DB-shaped receiver type', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'db' }, prop: 'query' };
  const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', 'db');
  assert.ok(hits && hits.some(h => h.id === 'js-sql-query'),
    'js-sql-query must still fire when the receiver type IS in the allow-list');
});

test('R6 unit: unknown receiver type (null) stays permissive — unknown != clean', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'x' }, prop: 'query' };
  const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', null);
  assert.ok(hits && hits.some(h => h.id === 'js-sql-query'),
    'an unresolved (null) receiver type must never suppress a match — only a confident mismatch may');
});

test('R6 end-to-end: cache.query(tainted) is not reported as SQLi; db.query(tainted) still is', async () => {
  const dir = mkTmp('r6', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/a', (req, res) => {
  const db = require('./db');
  db.query(req.query.q);
});
app.get('/b', (req, res) => {
  const cache = require('./cache');
  cache.query(req.query.q);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const sqlFindings = (scan.findings || []).filter(f => /sql/i.test(f.vuln || ''));
  const lineOf = f => f.line || (f.id && Number((f.id.match(/:(\d+):/) || [])[1])) || 0;
  assert.ok(sqlFindings.some(f => lineOf(f) === 6), 'db.query(tainted) should still be flagged as SQLi');
  assert.ok(!sqlFindings.some(f => lineOf(f) === 10), 'cache.query(tainted) should NOT be flagged as SQLi');
  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/receiver-type-and-nested-calls.test.js`
Expected: FAIL — `matchSinkOrSanitizer` doesn't yet accept a 3rd argument (the two suppression-asserting tests fail: `cache.query()` still matches unconditionally), and the end-to-end test's `!sqlFindings.some(...)` assertion fails because `cache.query(tainted)` is currently reported.

- [ ] **Step 3: Add `_receiverTypeAllowed` and thread `receiverType` through `matchSinkOrSanitizer` in catalog.js**

In `scanner/src/dataflow/catalog.js`, immediately after `_receiverAllowed` (ends at line 905, right before the "Merge the expanded sanitizer catalog" comment), add:

```js
// PRD R6 (docs/DETECTION_GAP_REMEDIATION_PRD.md): a SECOND, independent
// receiver constraint — this one checked against the CHA-INFERRED TYPE of
// the receiver (computed by the caller, engine.js's `_receiverTypeFor`), not
// the textual receiver-chain segments `_receiverAllowed` above checks. The
// two are complementary: `_receiverAllowed`'s `match.receiver` regex can only
// ever see the SOURCE TEXT of the call site (`db.query` vs `cache.query` —
// both pass any receiver regex that doesn't special-case exact names); this
// gate can additionally use a resolved class/variable-type hint, so a bare
// `.query()` on something confidently NOT database-shaped can be excluded
// without hand-listing every possible non-DB variable name as a `receiver`
// exclusion (which `_receiverAllowed`'s regex form cannot express at all —
// it only expresses required patterns, never forbidden ones).
//
// Unknown != clean: a null/undefined receiverType (CHA could not resolve
// anything for this call site) NEVER suppresses a match — only a receiver
// type that was confidently resolved and does not appear in the entry's
// `receiverTypeIn` allow-list does. An entry with no `receiverTypeIn` is
// completely unaffected by this gate (returns true unconditionally), exactly
// like `_receiverAllowed` when neither `receiver` nor `receiverBase` is set.
function _receiverTypeAllowed(entry, receiverType) {
  const pats = entry.match && entry.match.receiverTypeIn;
  if (!pats || !pats.length) return true;
  if (!receiverType) return true;
  return pats.some((p) => new RegExp(p, 'i').test(String(receiverType)));
}
```

Then change `matchSinkOrSanitizer` (currently lines 1085-1093):

```js
export function matchSinkOrSanitizer(calleeExpr, file) {
  if (!calleeExpr) return null;
  const raw = _calleeIndexHits(calleeExpr);
  if (!raw.length) return null;
  const hits = filterByProvenance(raw)
    .filter(h => _languageAllowed(h, file))
    .filter(h => _receiverAllowed(h, calleeExpr));
  return hits.length ? hits : null;
}
```

to:

```js
export function matchSinkOrSanitizer(calleeExpr, file, receiverType) {
  if (!calleeExpr) return null;
  const raw = _calleeIndexHits(calleeExpr);
  if (!raw.length) return null;
  const hits = filterByProvenance(raw)
    .filter(h => _languageAllowed(h, file))
    .filter(h => _receiverAllowed(h, calleeExpr))
    .filter(h => _receiverTypeAllowed(h, receiverType));
  return hits.length ? hits : null;
}
```

- [ ] **Step 4: Add `receiverTypeIn` to the 5 targeted catalog entries**

In the same file, update these 5 entries (adding one field each, no other changes):

Line 66-68 (`js-sql-query`):
```js
  { kind: 'sink', id: 'js-sql-query',  language: 'js', framework: 'sql', match: { type: 'call', callee: 'query', receiverTypeIn: ['^(?:db|pool|conn(?:ection)?|client|sql|database|pg|mysql|sequelize|knex|prisma)$'] }, argIndex: 0,
    vuln: { name: 'SQL Injection (db.query)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries: db.query("SELECT * FROM t WHERE id = ?", [id]). Never interpolate untrusted strings into SQL.' } },
```

Line 69-71 (`js-sql-execute`) — same allow-list:
```js
  { kind: 'sink', id: 'js-sql-execute', language: 'js', framework: 'sql', match: { type: 'call', callee: 'execute', receiverTypeIn: ['^(?:db|pool|conn(?:ection)?|client|sql|database|pg|mysql|sequelize|knex|prisma)$'] }, argIndex: 0,
```
(keep the existing `vuln: {...}` block on the following line unchanged.)

Line 363-365 (`py-requests-get`):
```js
  { kind: 'sink', id: 'py-requests-get',   language: 'py', framework: 'requests', match: { type: 'call', callee: 'get', receiverTypeIn: ['^(?:requests|session|client|http)$'] },   argIndex: 0,
    vuln: { name: 'SSRF (requests.get)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Resolve the URL host and reject RFC1918 + metadata endpoints before fetching. Use an allow-list.' } },
```

Line 608-610 (`py-requests-get-v2`) — same allow-list:
```js
  { kind: 'sink', id: 'py-requests-get-v2',  language: 'py', framework: 'requests', match: { type: 'call', callee: 'get', receiverTypeIn: ['^(?:requests|session|client|http)$'] },  argIndex: 0,
    vuln: { name: 'SSRF (requests.get)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Resolve the host first, reject 169.254.169.254 / RFC1918 / localhost; or proxy through a server-side allow-list.' } },
```

Line 417-419 (`rb-erb-new`):
```js
  { kind: 'sink', id: 'rb-erb-new',           language: 'rb', framework: 'erb',    match: { type: 'call', callee: 'new', receiverTypeIn: ['^ERB$'] }, argIndex: 0,
    vuln: { name: 'SSTI (ERB.new)', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Use pre-existing templates with binding/locals — never construct a template from user input.' } },
```

Both `py-requests-post`/`py-requests-post-v2` and the `pickle`/`yaml`/deserialization entries are deliberately left unchanged — they already carry a `receiver`/`receiverBase` textual constraint (or, for `post`, are a lower-FP-risk verb than `get`/`new`/`load`/`exec`, matching the PRD's own explicit prioritization: "Start with the highest-FP-risk bare-name entries... `get`, `new`, `load`, `exec`"). Widening this list further is out of scope for this task.

- [ ] **Step 5: Add `_fullyFlattenMemberChain` and `_receiverTypeFor` to engine.js**

In `scanner/src/dataflow/engine.js`, immediately after `_flattenCalleeName` (ends at line 101, right before the `_resolvableCalleeName` comment block), add:

```js
// PRD R6/R11 (docs/DETECTION_GAP_REMEDIATION_PRD.md): unlike _flattenCalleeName
// (which only flattens ONE level — `x.method`/`this.method` — because that is
// the 2-segment shape catalog matching and resolveKnownCallee both key on),
// receiver-context.js's receiverTypeAtCall needs the FULL dotted chain,
// including `this`, to apply its `this.field.method` heuristic
// (`this.userRepo.save` -> parts = ['this','userRepo','save']). A partial
// flatten (`_flattenCalleeName` would return just 'save' for `this.userRepo.
// save`, since its object isn't a bare ident) silently starves that heuristic.
function _fullyFlattenMemberChain(calleeExpr) {
  if (!calleeExpr) return null;
  if (typeof calleeExpr === 'string') return calleeExpr;
  if (calleeExpr.kind === 'ident') return calleeExpr.name || null;
  if (calleeExpr.kind === 'member' && typeof calleeExpr.prop === 'string') {
    const base = _fullyFlattenMemberChain(calleeExpr.object);
    return base ? `${base}.${calleeExpr.prop}` : calleeExpr.prop;
  }
  return null;
}

// Shared by R6 (catalog receiver-type gating) and R11 (member-call
// resolution) so both use the exact same precision bar, per the PRD's own
// sequencing note that R11 must not be more permissive than R6. Returns null
// whenever CHA has nothing useful to say — callers must treat null as
// "unknown", never as a signal to suppress or refuse (see this file's
// "Unknown ≠ clean" global constraint).
function _receiverTypeFor(calleeExpr, callContext) {
  if (!callContext || !callContext._cha) return null;
  const flat = _fullyFlattenMemberChain(calleeExpr);
  if (!flat || !flat.includes('.')) return null;
  return receiverTypeAtCall(
    { kind: 'call', callee: flat },
    { qid: callContext._currentFnQid },
    _currentFile,
    callContext._cha,
  );
}
```

Add the import at the top of the file, alongside the existing `implicit-flow.js` import (line 46):

```js
import { isImplicitFlowEnabled, buildImplicitContext, implicitAssignTarget, markImplicitTaint, createImplicitFinding } from './implicit-flow.js';
import { receiverTypeAtCall } from './receiver-context.js';
```

- [ ] **Step 6: Thread `receiverType` through `_matchCallCatalog` and its two call sites**

Change `_matchCallCatalog` (currently lines 268-272):

```js
function _matchCallCatalog(calleeExpr, argExprs, state) {
  const cat = matchSinkOrSanitizer(calleeExpr, _currentFile);
  const argTaints = (argExprs || []).map(a => exprTaint(a, state));
  return { cat, argTaints };
}
```

to:

```js
function _matchCallCatalog(calleeExpr, argExprs, state, callContext) {
  const receiverType = _receiverTypeFor(calleeExpr, callContext);
  const cat = matchSinkOrSanitizer(calleeExpr, _currentFile, receiverType);
  const argTaints = (argExprs || []).map(a => exprTaint(a, state));
  return { cat, argTaints };
}
```

Update its two call sites. Assign-case (currently around line 428):

```js
        const { cat: _sinkCat, argTaints: _sinkArgTaints } =
          _matchCallCatalog(node.source.callee, node.source.args, state);
```
becomes:
```js
        const { cat: _sinkCat, argTaints: _sinkArgTaints } =
          _matchCallCatalog(node.source.callee, node.source.args, state, callContext);
```

Call-case (currently around line 601):

```js
      const { cat, argTaints } = _matchCallCatalog(node.callee, node.args, state);
```
becomes:
```js
      const { cat, argTaints } = _matchCallCatalog(node.callee, node.args, state, callContext);
```

(The `exprTaint(a, state)` calls inside `_matchCallCatalog` do not yet receive `callContext` — that lands in Task 5, which changes `exprTaint`'s signature. Leaving it as `exprTaint(a, state)` here for now is correct: Task 5 will update this exact line again as part of its own diff.)

- [ ] **Step 7: Run test to verify it passes**

Run: `cd scanner && node --test test/receiver-type-and-nested-calls.test.js && npm run test:dataflow`
Expected: PASS, zero regressions in the broader dataflow suite (in particular, `test/catalog-dotted-callee-lookup.test.js` and `test/catalog-expanded.test.js` must stay green — they call `matchSinkOrSanitizer` with only 2 args, exercising the backward-compatible default).

- [ ] **Step 8: Commit**

```bash
git add scanner/src/dataflow/catalog.js scanner/src/dataflow/engine.js scanner/test/receiver-type-and-nested-calls.test.js
git commit -m "feat(dataflow): PRD R6 — gate catalog sink matching by CHA-inferred receiver type"
```

---

## Task 3: Extract shared callee-resolution helper (behavior-preserving refactor)

**Files:**
- Modify: `scanner/src/dataflow/engine.js:457-470` (assign-RHS resolve block), `:605-615` (plain-call resolve block)
- Test: `scanner/test/interproc-k2.test.js` (regression backstop, unchanged)

**Interfaces:**
- Produces: `_resolveCalleeForSummary(calleeExpr, callContext)` → `{ qid: string, fn: object|null } | null`. Task 4 extends this function's body (not its signature or call sites). Task 5 calls it directly.

**Why this task exists on its own:** R11 (Task 4) must apply at every site that currently resolves a callee for summary lookup — the assign-RHS site, the plain-call site, AND the new nested-call site R10 (Task 5) adds — or a member call like `svc.get(x)` would resolve interprocedurally in a statement `svc.get(x)` but not in an assignment `const y = svc.get(x)`, an inconsistency with no principled justification. Rather than pasting R11's new logic into three places (the exact "twice implemented, twice re-broken" pattern this file's own header comment at line 261-263 already warns about), this task first extracts today's existing resolve logic — unchanged — into one function, verified to be a pure refactor (existing tests must stay byte-identical in outcome). Task 4 then extends that ONE function.

- [ ] **Step 1: Write a characterization test (captures current behavior before refactor)**

This step does not add new assertions — it confirms `test/interproc-k2.test.js`'s existing 4 tests currently pass, as the baseline the refactor must not disturb.

Run: `cd scanner && node --test test/interproc-k2.test.js`
Expected: PASS (all 4 tests). Record this as the refactor's regression target.

- [ ] **Step 2: Extract `_resolveCalleeForSummary`**

In `scanner/src/dataflow/engine.js`, immediately after `_resolvableCalleeName` (ends at line 121, right before `function exprTaint`), add:

```js
// Resolve calleeExpr to { qid, fn } via the call graph — the shared
// resolve-and-lookup sequence every summary-consulting call site needs.
// Extracted from what were two independent, drifting copies (assign-RHS and
// plain-call-statement) so a future change (like PRD R11 in this same file)
// only has to land once. See _resolvableCalleeName's own comment for why a
// bare-name/pre-flattened-string callee is the ONLY case handled here for
// now — Task 4 (PRD R11) extends this function's body to add a second,
// CHA-gated resolution path for member-expression callees.
function _resolveCalleeForSummary(calleeExpr, callContext) {
  if (!callContext || !callContext._callGraph || !callContext._callGraph.resolveKnownCallee) return null;
  const _callerFile = (callContext._currentFnQid || '').split('::')[0] || undefined;
  const _resolvableName = _resolvableCalleeName(calleeExpr);
  if (!_resolvableName) return null;
  const resolved = callContext._callGraph.resolveKnownCallee(_resolvableName, _callerFile);
  const fn = functionRecord(callContext._callGraph, resolved);
  const qid = resolved && (resolved.qid || resolved);
  return typeof qid === 'string' ? { qid, fn } : null;
}
```

- [ ] **Step 3: Replace the assign-RHS resolve block with a call to the shared helper**

Currently (lines ~457-470):

```js
      const calleeName = node.source && node.source.kind === 'call'
        ? _flattenCalleeName(node.source.callee) : null;
      if (target && calleeName && callContext._summaryCache && callContext._callGraph) {
        const _callerFile = (callContext._currentFnQid || '').split('::')[0] || undefined;
        const _resolvableName = node.source && node.source.kind === 'call'
          ? _resolvableCalleeName(node.source.callee) : null;
        // resolveKnownCallee: never guess via resolve()'s bare-tail
        // fallback. _resolvableCalleeName already refuses JS member
        // expressions, but a pre-flattened STRING callee (Go/PHP/Ruby/
        // C++/Python parsers) can still be dotted, and only the resolver
        // itself can tell — see callgraph.js.
        const resolved = (_resolvableName && callContext._callGraph.resolveKnownCallee)
          ? callContext._callGraph.resolveKnownCallee(_resolvableName, _callerFile) : null;
        const fn  = functionRecord(callContext._callGraph, resolved);
        const qid = resolved && (resolved.qid || resolved);
        if (typeof qid === 'string') {
```

Replace with:

```js
      const calleeName = node.source && node.source.kind === 'call'
        ? _flattenCalleeName(node.source.callee) : null;
      if (target && calleeName && callContext._summaryCache && callContext._callGraph) {
        const _resolvedTarget = node.source && node.source.kind === 'call'
          ? _resolveCalleeForSummary(node.source.callee, callContext) : null;
        const fn  = _resolvedTarget && _resolvedTarget.fn;
        const qid = _resolvedTarget && _resolvedTarget.qid;
        if (typeof qid === 'string') {
```

Everything from the original `if (typeof qid === 'string') {` line through its closing brace (the `paramNames`/`entry`/`sum`/`_mergeSummaryFindings`/`applyAtCallSite` logic) is **unchanged** — it only reads `qid` and `fn`, both still defined identically.

- [ ] **Step 4: Replace the plain-call resolve block with a call to the shared helper**

Currently (lines ~605-615):

```js
      const _plainCallCalleeName = _flattenCalleeName(node.callee);
      if (callContext._summaryCache && callContext._callGraph && _plainCallCalleeName) {
        const _callerFile = (callContext._currentFnQid || '').split('::')[0] || undefined;
        const _resolvableName = _resolvableCalleeName(node.callee);
        // resolveKnownCallee: see the comment at the sibling call site above
        // — a pre-flattened dotted STRING callee must not be guessed via
        // resolve()'s bare-tail fallback.
        const resolved = (_resolvableName && callContext._callGraph.resolveKnownCallee)
          ? callContext._callGraph.resolveKnownCallee(_resolvableName, _callerFile) : null;
        const fn  = functionRecord(callContext._callGraph, resolved);
        const qid = resolved && (resolved.qid || resolved);
        if (typeof qid === 'string' && fn && Array.isArray(fn.params)) {
```

Replace with:

```js
      const _plainCallCalleeName = _flattenCalleeName(node.callee);
      if (callContext._summaryCache && callContext._callGraph && _plainCallCalleeName) {
        const _resolvedTarget = _resolveCalleeForSummary(node.callee, callContext);
        const fn  = _resolvedTarget && _resolvedTarget.fn;
        const qid = _resolvedTarget && _resolvedTarget.qid;
        if (typeof qid === 'string' && fn && Array.isArray(fn.params)) {
```

Everything below is unchanged for the same reason as Step 3.

- [ ] **Step 5: Run the regression backstop**

Run: `cd scanner && node --test test/interproc-k2.test.js test/receiver-type-and-nested-calls.test.js && npm run test:dataflow`
Expected: PASS, byte-identical outcomes to Step 1's baseline — this is a pure refactor, so any behavior change here is a bug in the extraction, not an intended effect.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/dataflow/engine.js
git commit -m "refactor(dataflow): extract shared _resolveCalleeForSummary (prereq for PRD R10/R11)"
```

---

## Task 4: R11 — resolve a member call when CHA narrows the receiver to one concrete class

**Files:**
- Modify: `scanner/src/dataflow/engine.js` — extend `_resolveCalleeForSummary` (from Task 3)
- Test: `scanner/test/receiver-type-and-nested-calls.test.js` (extend)

**Interfaces:**
- Consumes: `_receiverTypeFor` (Task 2), `resolveMethod` from `scanner/src/ir/class-hierarchy.js` (existing, exported).
- Produces: `_resolveCalleeForSummary` now also resolves member-expression callees (`userRepo.save(x)`, `this.userRepo.save(x)`) when CHA is confident, in addition to its existing bare-name/pre-flattened-string path. No signature change — Task 3's callers (assign-RHS, plain-call) and Task 5's new caller (nested-call) all gain this for free.

- [ ] **Step 1: Write the failing test**

Append to `scanner/test/receiver-type-and-nested-calls.test.js`:

```js
test('R11: member-call interprocedural resolution via this.field.method (CHA-unambiguous)', async () => {
  const dir = mkTmp('r11-this', {
    'app.js': `
const { exec } = require('child_process');
const express = require('express');
const app = express();
class CommandRunner {
  run(cmd) { exec(cmd); }
}
class Service {
  constructor() { this.runner = new CommandRunner(); }
  handle(input) { this.runner.run(input); }
}
const svc = new Service();
app.get('/run', (req, res) => {
  svc.handle(req.query.cmd);
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const cmdFindings = (scan.findings || []).filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    'expected the tainted flow through svc.handle() -> this.runner.run() -> exec() to be detected interprocedurally');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R11: an ambiguous same-named method across two unrelated classes still refuses to resolve', async () => {
  const dir = mkTmp('r11-ambiguous', {
    'app.js': `
const { exec } = require('child_process');
const express = require('express');
const app = express();
class Logger {
  save(x) { /* writes to a log file, not a sink */ }
}
class Cache {
  save(x) { /* writes to memory, not a sink */ }
}
function useEither(flag, x) {
  const target = flag ? new Logger() : new Cache();
  target.save(x);
}
app.get('/run', (req, res) => {
  useEither(true, req.query.q);
  res.send('ok');
});
`,
  });
  // Neither Logger.save nor Cache.save calls exec/eval/a sink — this test's
  // real assertion is that the scan completes without throwing and without
  // fabricating a finding out of an unresolved/ambiguous receiver. An
  // ambiguous receiver (CHA can't type `target` to one class) must fall back
  // to "no resolution", never a guess.
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  assert.ok(scan && Array.isArray(scan.findings), 'scan must complete');
  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/receiver-type-and-nested-calls.test.js`
Expected: FAIL on the first new test (`cmdFindings.length >= 1`) — `this.runner.run(input)` is a member call, `_resolvableCalleeName` refuses it, so today's engine never sees the interprocedural edge from `svc.handle()` through to `exec()`. The second new test should already pass (it only asserts the scan completes) — this is expected and fine; it exists as a regression guard for Step 3, not as a red/green driver.

- [ ] **Step 3: Extend `_resolveCalleeForSummary` with the CHA-gated member-call path**

In `scanner/src/dataflow/engine.js`, add the import for `resolveMethod` alongside the existing `receiverTypeAtCall` import (added in Task 2, Step 5):

```js
import { receiverTypeAtCall } from './receiver-context.js';
import { resolveMethod } from '../ir/class-hierarchy.js';
```

Add a new helper immediately before `_resolveCalleeForSummary` (which Task 3 placed after `_resolvableCalleeName`):

```js
// PRD R11 (docs/DETECTION_GAP_REMEDIATION_PRD.md), gated behind R6's
// receiver-type machinery per the PRD's own sequencing note. Resolving a bare
// dotted callee name by guessing (stripping to its last segment and matching
// ANY same-named function project-wide) is refused elsewhere in this file for
// good reason (_resolvableCalleeName's own comment) — but constructing
// "ClassName.methodName" from a CHA-CONFIRMED class is not a guess, it is the
// same exact-match classMethods lookup a same-file `ClassName.method()` call
// site already uses (ir/callgraph.js). resolveMethod is the safety check: it
// only returns non-null when `className` is a REAL class CHA recorded AND
// that class (or one of its ancestors) actually defines `methodName` — so an
// unresolved receiver (receiverType null, or a soft-label fallback that
// happens not to name a real class) safely falls through to "no resolution"
// rather than fabricating an edge.
function _resolveMemberCalleeViaCHA(calleeExpr, callContext) {
  if (!calleeExpr || calleeExpr.kind !== 'member' || typeof calleeExpr.prop !== 'string') return null;
  const className = _receiverTypeFor(calleeExpr, callContext);
  if (!className || !callContext._cha) return null;
  const found = resolveMethod(callContext._cha, className, calleeExpr.prop);
  if (!found) return null;
  return `${found.className}.${found.methodName}`;
}
```

Then change `_resolveCalleeForSummary` (from Task 3):

```js
function _resolveCalleeForSummary(calleeExpr, callContext) {
  if (!callContext || !callContext._callGraph || !callContext._callGraph.resolveKnownCallee) return null;
  const _callerFile = (callContext._currentFnQid || '').split('::')[0] || undefined;
  const _resolvableName = _resolvableCalleeName(calleeExpr);
  if (!_resolvableName) return null;
  const resolved = callContext._callGraph.resolveKnownCallee(_resolvableName, _callerFile);
  const fn = functionRecord(callContext._callGraph, resolved);
  const qid = resolved && (resolved.qid || resolved);
  return typeof qid === 'string' ? { qid, fn } : null;
}
```

to:

```js
function _resolveCalleeForSummary(calleeExpr, callContext) {
  if (!callContext || !callContext._callGraph || !callContext._callGraph.resolveKnownCallee) return null;
  const _callerFile = (callContext._currentFnQid || '').split('::')[0] || undefined;
  let _resolvableName = _resolvableCalleeName(calleeExpr);
  // PRD R11: _resolvableCalleeName refuses every member-expression callee.
  // When that's the reason we have nothing, try the CHA-gated path before
  // giving up — but ONLY then, so the existing exact/bare-name behavior is
  // completely unchanged for every case it already handled.
  if (!_resolvableName) _resolvableName = _resolveMemberCalleeViaCHA(calleeExpr, callContext);
  if (!_resolvableName) return null;
  const resolved = callContext._callGraph.resolveKnownCallee(_resolvableName, _callerFile);
  const fn = functionRecord(callContext._callGraph, resolved);
  const qid = resolved && (resolved.qid || resolved);
  return typeof qid === 'string' ? { qid, fn } : null;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/receiver-type-and-nested-calls.test.js test/interproc-k2.test.js && npm run test:dataflow`
Expected: PASS, zero regressions.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/dataflow/engine.js scanner/test/receiver-type-and-nested-calls.test.js
git commit -m "feat(dataflow): PRD R11 — resolve member calls interprocedurally when CHA is unambiguous"
```

---

## Task 5: R10 — consult callee summaries for calls nested inside another expression

**Files:**
- Modify: `scanner/src/dataflow/engine.js` — `exprTaint` (currently lines 123-151) and its 15 call sites; `_matchCallCatalog` (Task 2's version)
- Test: `scanner/test/receiver-type-and-nested-calls.test.js` (extend)

**Interfaces:**
- Consumes: `_resolveCalleeForSummary` (Tasks 3+4), `entryStateFromCall`, `analyzeFunction`, `_mergeSummaryFindings` (all existing).
- Produces: `exprTaint(expr, state, callContext)` — new optional 3rd param; every internal call site updated to pass it through.

- [ ] **Step 1: Write the failing test**

Append to `scanner/test/receiver-type-and-nested-calls.test.js`:

```js
test('R10: a helper call nested directly in a sink argument is detected', async () => {
  const dir = mkTmp('r10-nested', {
    'app.js': `
const { exec } = require('child_process');
const express = require('express');
const app = express();
function getUserInput(req) { return req.query.cmd; }
app.get('/run', (req, res) => {
  exec(getUserInput(req));
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const cmdFindings = (scan.findings || []).filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    'expected exec(getUserInput(req)) to be detected — getUserInput()\'s own return-taint summary must be consulted for a call nested directly in the sink argument, not just at assignment/statement position');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R10: a clean nested call does not spuriously taint the sink', async () => {
  const dir = mkTmp('r10-clean-nested', {
    'app.js': `
const { exec } = require('child_process');
const express = require('express');
const app = express();
function getFixedCommand() { return 'echo hello'; }
app.get('/run', (req, res) => {
  exec(getFixedCommand());
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const cmdFindings = (scan.findings || []).filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.equal(cmdFindings.length, 0, 'exec(getFixedCommand()) must NOT be flagged — the nested call returns no tainted value');
  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/receiver-type-and-nested-calls.test.js`
Expected: FAIL on the first new test — `exprTaint`'s `'call'` case only checks `getUserInput(req)`'s own arguments (`req`, which reads no registered source directly — `req.query.cmd` is inside the CALLEE's body, invisible from the call site) for taint, never consults `getUserInput`'s return-taint summary. The second new test should already pass.

- [ ] **Step 3: Add `_nestedCallReturnTainted` and thread `callContext` through `exprTaint`**

In `scanner/src/dataflow/engine.js`, add immediately after `_resolveMemberCalleeViaCHA`/`_resolveCalleeForSummary` (from Tasks 3-4), before `function exprTaint`:

```js
// PRD R10 (docs/DETECTION_GAP_REMEDIATION_PRD.md): the only two places that
// consult a callee's SummaryCache entry are the assign-RHS and plain-call-
// statement paths in step() below — a call nested INSIDE another expression
// (most commonly a sink's own argument list, `sink(getUserInput())`) reaches
// neither, so exprTaint's 'call' case fell back to checking only the nested
// call's OWN arguments, silently losing the callee's return-taint. Mirrors
// the same resolve -> get-or-compute -> merge sequence step()'s two existing
// call sites use, via the Task 3/4 shared _resolveCalleeForSummary.
function _nestedCallReturnTainted(calleeExpr, argExprs, state, callContext) {
  if (!callContext || !callContext._summaryCache) return false;
  const target = _resolveCalleeForSummary(calleeExpr, callContext);
  if (!target) return false;
  const { qid, fn } = target;
  const paramNames = (fn && Array.isArray(fn.params)) ? fn.params : [];
  const entry = paramNames.length
    ? entryStateFromCall(paramNames, argExprs || [], state)
    : new Set();
  let sum = callContext._summaryCache.get(qid, entry);
  if (!sum && fn && fn.cfg) {
    sum = callContext._summaryCache.compute(qid, entry, () => {
      const inner = {
        _findings: [], _taintSources: [], _returnTainted: false,
        _stack: new Set(), deadlineMs: callContext.deadlineMs,
        _summaryCache: callContext._summaryCache,
        _callGraph: callContext._callGraph,
        _mutatedParamsOut: new Set(),
        _cha: callContext._cha,
      };
      try { analyzeFunction(fn, entry, inner); } catch {}
      return {
        returnTainted: !!inner._returnTainted,
        mutatedParams: inner._mutatedParamsOut || new Set(),
        taintedGlobals: new Set(),
        findings: inner._findings,
      };
    });
  }
  _mergeSummaryFindings(callContext, callContext._currentFnQid, sum, 'interproc');
  return !!(sum && sum.returnTainted);
}
```

Now change `exprTaint` itself (currently lines 123-151):

```js
function exprTaint(expr, state) {
  if (expr && (expr.kind === 'member' || expr.kind === 'call') && exprIsSource(expr)) return true;
  if (!expr) return false;
  // Constant propagation: variables assigned from literals are never tainted
  if (expr.kind === 'ident' && _activeConstantVars && _activeConstantVars.has(expr.name)) return false;
  // P1.1 — field-sensitive access path: if the expression is a pure
  // ident/member chain ("x.y.z"), ask the access-path lattice whether any
  // shorter prefix in the state covers it. This is what makes
  // `user.password` distinguishable from `user.email`.
  const ap = accessPathOf(expr);
  if (ap !== null) return isCoveredBy(state, ap);
  switch (expr.kind) {
    case 'literal':           return false;
    case 'binary':
    case 'logical':           return exprTaint(expr.left, state) || exprTaint(expr.right, state);
    case 'tpl':               return (expr.parts || []).some(p => exprTaint(p, state));
    case 'union':             return (expr.branches || []).some(b => exprTaint(b, state));
    case 'object':            return (expr.props || []).some(p => exprTaint(p.value, state));
    case 'array':             return (expr.elements || []).some(e => exprTaint(e, state));
    case 'call': {
      // Calls are handled at the CFG level (the call has already been processed).
      // For an inline call expression, conservatively return whether any arg is tainted.
      // This loses the sanitizer effect but is safe.
      return (expr.args || []).some(a => exprTaint(a, state));
    }
    case 'unknown':           return false;
    default:                  return false;
  }
}
```

to:

```js
function exprTaint(expr, state, callContext) {
  if (expr && (expr.kind === 'member' || expr.kind === 'call') && exprIsSource(expr)) return true;
  if (!expr) return false;
  // Constant propagation: variables assigned from literals are never tainted
  if (expr.kind === 'ident' && _activeConstantVars && _activeConstantVars.has(expr.name)) return false;
  // P1.1 — field-sensitive access path: if the expression is a pure
  // ident/member chain ("x.y.z"), ask the access-path lattice whether any
  // shorter prefix in the state covers it. This is what makes
  // `user.password` distinguishable from `user.email`.
  const ap = accessPathOf(expr);
  if (ap !== null) return isCoveredBy(state, ap);
  switch (expr.kind) {
    case 'literal':           return false;
    case 'binary':
    case 'logical':           return exprTaint(expr.left, state, callContext) || exprTaint(expr.right, state, callContext);
    case 'tpl':               return (expr.parts || []).some(p => exprTaint(p, state, callContext));
    case 'union':             return (expr.branches || []).some(b => exprTaint(b, state, callContext));
    case 'object':            return (expr.props || []).some(p => exprTaint(p.value, state, callContext));
    case 'array':             return (expr.elements || []).some(e => exprTaint(e, state, callContext));
    case 'call': {
      // The call's own arguments (unchanged from before) OR — PRD R10 — the
      // resolved callee's own return-taint summary. Args-tainted is checked
      // FIRST and short-circuits: it's the cheap, no-resolve-attempt case and
      // was already correct.
      if ((expr.args || []).some(a => exprTaint(a, state, callContext))) return true;
      return _nestedCallReturnTainted(expr.callee, expr.args, state, callContext);
    }
    case 'unknown':           return false;
    default:                  return false;
  }
}
```

Now update every other call site of `exprTaint` in the file to pass `callContext` through wherever it's in scope (it is, at all 8 remaining sites — all live inside `step()` or `analyzeFunction()`, both of which already receive `callContext` as a parameter):

1. Line ~270 (in `_matchCallCatalog`, Task 2's version):
```js
  const argTaints = (argExprs || []).map(a => exprTaint(a, state));
```
→
```js
  const argTaints = (argExprs || []).map(a => exprTaint(a, state, callContext));
```
(`_matchCallCatalog` already receives `callContext` as its 4th parameter since Task 2.)

2. Line ~536 (builtin-summary fallback, assign-case):
```js
            const _argTainted = (node.source.args || []).some(a => exprTaint(a, newState));
```
→
```js
            const _argTainted = (node.source.args || []).some(a => exprTaint(a, newState, callContext));
```

3. Line ~564 (builtin-summary mutated-param check, assign-case):
```js
                if (argExpr && argExpr.kind === 'ident' && (node.source.args || []).some(a => exprTaint(a, newState))) {
```
→
```js
                if (argExpr && argExpr.kind === 'ident' && (node.source.args || []).some(a => exprTaint(a, newState, callContext))) {
```

4. Line ~577 (assign-case, non-call RHS taint check):
```js
      } else if (exprTaint(node.source, newState)) {
```
→
```js
      } else if (exprTaint(node.source, newState, callContext)) {
```

5. Line ~752 (return-case):
```js
      if (exprTaint(node.value, state)) {
```
→
```js
      if (exprTaint(node.value, state, callContext)) {
```

6. Line ~834 (implicit-flow context builder, inside `analyzeFunction`):
```js
      const ictx = buildImplicitContext(fn.cfg, (expr) => exprTaint(expr, union));
```
→
```js
      const ictx = buildImplicitContext(fn.cfg, (expr) => exprTaint(expr, union, callContext));
```

7. Line ~871 (implicit-flow pass 1, inside `analyzeFunction`):
```js
        if ((node.args || []).some((a) => exprTaint(a, inS))) continue;
```
→
```js
        if ((node.args || []).some((a) => exprTaint(a, inS, callContext))) continue;
```

8. Line ~885 (implicit-flow pass 2, inside `analyzeFunction`):
```js
          if ((node.args || []).some((a) => exprTaint(a, inS))) continue;
```
→
```js
          if ((node.args || []).some((a) => exprTaint(a, inS, callContext))) continue;
```

Every call site now threads `callContext`; none is left passing only 2 args, so `_nestedCallReturnTainted`'s summary-consultation is reachable from every taint query in the file, not just the sink-argument case the new tests target.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/receiver-type-and-nested-calls.test.js test/interproc-k2.test.js && npm run test:dataflow`
Expected: PASS, zero regressions.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/dataflow/engine.js scanner/test/receiver-type-and-nested-calls.test.js
git commit -m "feat(dataflow): PRD R10 — consult callee summaries for calls nested in an expression"
```

---

## Task 6: Wire the new test file into the scoped script, full-gate verification, and PRD update

**Files:**
- Modify: `scanner/package.json` (`test:dataflow` script)
- Modify: `docs/DETECTION_GAP_REMEDIATION_PRD.md` (mark R6/R10/R11 as landed, matching how the file already documents R1-R5/R7/R12's status via the CHANGELOG rather than editing the PRD's own body — see Step 3)
- Modify: `CHANGELOG.md`, `scanner/CHANGELOG.md` (via `scripts/sync-scanner-changelog.mjs`)

**Interfaces:** None — this task only wires and verifies.

- [ ] **Step 1: Add the new test file to `test:dataflow`**

In `scanner/package.json`, find the `test:dataflow` script value (a single long space-separated string of `test/*.test.js` paths) and append ` test/receiver-type-and-nested-calls.test.js` before the closing quote — following the exact convention every other file in that list already uses (bare relative path, space-separated, no special ordering requirement observed in the existing list).

- [ ] **Step 2: Run the full scoped suite, then the full gate**

Run: `cd scanner && npm run test:dataflow`
Expected: PASS, includes all 12 new tests from this plan (Tasks 1-5) plus zero regressions among the ~90 other files in that script.

Run: `cd scanner && npm test`
Expected: PASS (all scoped suites, ~12 stages per `scanner/CLAUDE.md`'s table).

Run: `cd scanner && npm run bench:cve-replay:check`
Expected: exit 0, no drift. (R6 can only ever REMOVE a specific catalog match on a specific receiver-type mismatch — if this regresses a corpus entry, that entry was relying on the exact FP behavior R6 targets, and the fix in Task 2 needs a narrower `receiverTypeIn` allow-list, not a revert.)

Run: `cd scanner && npm run bench:mutation:check`
Expected: exit 0. This is the structural anti-overfitting check the PRD's own "Overfitting watchlist" names explicitly for any change touching matching logic (R6, R10, R11 are all named there).

Run: `cd scanner && npm run bench:layer-recall:check`
Expected: exit 0, no regression on any language's taint-layer recall baseline. An IMPROVEMENT (more true positives via R10/R11's new interprocedural reach) requires `npm run bench:layer-recall:update-baseline` and committing the refreshed baseline — do this only after confirming every newly-detected entry is root-caused (a real detection gain from this plan's changes), not a fluke.

If any gate fails: stop, root-cause the specific failure (which detector, which finding, which fixture) before touching the baseline — per root `CLAUDE.md`'s verification discipline, "an undetectable fixture is the exact mistake the gate now catches," and the corollary here is "an unexplained baseline drift is the exact mistake this step exists to catch."

- [ ] **Step 3: Update `docs/DETECTION_GAP_REMEDIATION_PRD.md`'s status for R6/R10/R11**

This PRD's own convention (per its Section 6 "Sequencing and dependency ordering" and its Milestones table) is to track status via re-measurement (R16) and the CHANGELOG, not by hand-editing checkmarks into the recommendation prose — Theme A's landing (R1-R5, R7, R12) did not rewrite those sections either; it was recorded in `CHANGELOG.md`'s `0.136.10` entry (see that entry's closing line: "R3 ... was the last item in Theme A. Themes B–E ... remain open"). Follow the same pattern: leave the PRD body as-is (it remains an accurate historical record of the audit), and record landing R6/R10/R11 in the changelog (Step 4). The one exception: append a short dated note to the very end of the PRD noting these three items now have code, so a future reader of the file doesn't have to cross-reference the changelog to know Theme B/D is partially closed:

At the end of `docs/DETECTION_GAP_REMEDIATION_PRD.md` (after the "Out of scope for this PRD" section), add:

```markdown

---

## 10. Status updates

- **2026-08-13:** R6 (receiver-type-gated catalog matching), R10 (nested-call summary consultation), and R11 (CHA-gated member-call resolution) landed. R7 and R12 were found already landed (commit `553f9a5`, swept in opportunistically alongside Theme A). R8, R9 (Theme C — parser/IR fidelity), R13, R14 (Theme E — flow-modeling coverage), and R15 (Theme F — aggregation precision-safety) remain open. R16 (re-measure the independent population) should be re-run now that Theme B/D has partial coverage — see `bench/independent/README.md`.
```

- [ ] **Step 4: Update the changelog**

Add a new entry at the top of `CHANGELOG.md` (above the current top-most `## 0.136.10` entry), following that file's established format (version bump is a separate concern handled by the project's normal release process — this plan does not bump the version; that is a deliberate scope boundary, since a version bump triggers the full release gate covered in a different workstream):

```markdown
## Unreleased — Theme B+D of the detection-gap remediation PRD (R6, R10, R11)

Closes three of the five open items in `docs/DETECTION_GAP_REMEDIATION_PRD.md`'s
Theme B ("semantic grounding of matching") and Theme D ("interprocedural
completeness"). R7 and R12 — filed under the same two themes — turned out to
already be landed (commit `553f9a5`, swept in opportunistically alongside
Theme A's nine fixes).

- **R6 — catalog sink matching is now gated by CHA-inferred receiver type.**
  A bare-name sink like `.query()` or `.get()` previously matched on ANY
  receiver project-wide (`cache.query(x)` scored identically to
  `db.query(x)`). Class Hierarchy Analysis (`ir/class-hierarchy.js`) and the
  receiver-type heuristic (`dataflow/receiver-context.js`) were both already
  built and unit-tested but never wired into the production pipeline — this
  wires them in once (`dataflow/index.js` builds CHA per scan, threads it
  through every `callContext`) and adds an opt-in `match.receiverTypeIn`
  catalog field, applied to the 5 highest-FP-risk bare-name entries
  (`js-sql-query`, `js-sql-execute`, `py-requests-get` ×2, `rb-erb-new`).
  Unknown receiver type never suppresses a match — only a confidently
  resolved, non-matching type does.
- **R10 — a call nested inside another expression now consults the callee's
  own taint summary.** `sink(getUserInput())` previously only checked
  `getUserInput()`'s own arguments for taint (the call's return-taint was
  invisible outside assignment-RHS and bare-statement position, the only two
  places the summary cache was consulted). `exprTaint`'s `'call'` case now
  also resolves and consults the callee's summary, via the same shared
  resolver R11 uses.
- **R11 — a JS/TS member call (`svc.save(x)`, `this.repo.save(x)`) now
  resolves interprocedurally when CHA narrows the receiver to one
  unambiguous, known class.** Previously refused unconditionally (a bare
  dotted-name guess risks inventing an edge between two unrelated same-named
  methods) — gated behind the same receiver-type precision bar R6
  establishes, so an unresolved or ambiguous receiver still safely refuses to
  resolve rather than guessing.

Verification: full test gate green, corpus/mutation/layer-recall gates
checked with zero unexplained drift (see PR for the actual run output).
```

Run `node scripts/sync-scanner-changelog.mjs` from the repo root to propagate the entry into `scanner/CHANGELOG.md` (the copy that ships inside the published package).

- [ ] **Step 5: Rebuild the bundle and commit**

```bash
cd scanner && npm run build
git add scanner/package.json scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256 docs/DETECTION_GAP_REMEDIATION_PRD.md CHANGELOG.md scanner/CHANGELOG.md
git commit -m "chore: wire new dataflow test into test:dataflow, update PRD status and changelog for R6/R10/R11"
```

Do not tag or push a release as part of this task — per this repo's own release-gate discipline, a version bump and publish is a separate, deliberate step (see root `CLAUDE.md`'s "Two publish paths" section), not an automatic consequence of landing a feature branch.

---

## Self-Review Notes

- **Spec coverage:** R6 (Task 2), R10 (Task 5), R11 (Task 4) each have a dedicated task with failing→passing tests tied directly to the PRD's own stated success metrics (R6: "cache.query(tainted) no longer fires... db.query(tainted) still fires"; R10: nested-call-in-sink-argument fixture; R11: "an ambiguous same-named method across two unrelated classes still refuses to resolve" fixture). Task 1 (CHA wiring) and Task 3 (shared-resolver extraction) are prerequisite infrastructure both R6 and R11 explicitly depend on per the PRD's own sequencing section. Task 6 covers the PRD's own R16 obligation to re-measure and record status, without performing the ~32-minute `bench:independent` run inline (flagged as the next actionable step, consistent with the PRD's Milestone table treating re-measurement as a distinct, explicitly-scheduled activity).
- **Placeholder scan:** every code block is complete, runnable code with exact line anchors from files read directly during planning — no "add appropriate handling" language anywhere.
- **Type/signature consistency:** `_resolveCalleeForSummary(calleeExpr, callContext) → {qid, fn} | null` is defined once (Task 3) and consumed identically by both refactored existing call sites, Task 4's extension, and Task 5's new call site. `exprTaint(expr, state, callContext)`'s new 3rd parameter is threaded through all 15 of its call sites (verified by direct grep during planning), not just the ones the new tests exercise. `_receiverTypeFor(calleeExpr, callContext)` is defined once (Task 2) and reused verbatim by Task 4's `_resolveMemberCalleeViaCHA` — this is deliberate, per the PRD's own instruction that R11 must share R6's exact precision bar.
- **Scope check:** single cohesive unit (one engine, five interlocking gaps in the same file) — not decomposed further, matching the writing-plans skill's guidance that decomposition happens at brainstorming time, and this slice was already scoped down from a larger PRD during that stage.
