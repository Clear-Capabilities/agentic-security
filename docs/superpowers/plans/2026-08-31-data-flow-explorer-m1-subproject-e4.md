# Data Flow Explorer — Sub-project E, increment E4 (coverage ledger + FR-203 closure) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `scanner/src/lineage/coverage.js` — the finished `graph.coverage` ledger contract sketched in `DESIGN_GRAPH_BUILDER.md` §10 — and close FR-203 (destination-unresolved sink reclassification) at real call sites, per §9.4's checklist.

**Architecture:** Two small additive changes to the already-shipped, already-reviewed `graph-builder.js` (a per-site `resolveSiteDecision` hook plus a `connected`/`args` field on each enumerated sink site — Task 1), followed by a new, self-contained `coverage.js` module that supplies the FR-203 heuristic and the finished coverage-ledger builder, plus a convenience entry point that wires the two together (Task 2). Nothing in `path-store.js`, `path-query.js`, `flow-grade.js`, `driver.js`, `engine.js`, `summaries.js`, or any registry module changes.

**Tech Stack:** Node ≥ 24, ESM, `node --test`.

**Spec:** `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` §9.4, §10, §4.1–§4.3 (site enumeration and multi-candidate resolution, which FR-203 must compose with), §6.1 (node identity — why FR-203 changes `kind`/`externality` but never `category`), and `scanner/src/lineage/sink-registry.js`'s `reclassifySink` doc comment (the FR-203 contract this module's `opts.destinationUnresolved`/`opts.blockingExpression` implement). This plan corrects one stale checklist item against shipped reality: §9.4 item 3 ("ship §5's enumerator union as a real module function") is **already done** — `graph-builder.js` exports `degradedTerminals(store)` as a real, tested, standalone function (E3, `DESIGN_GRAPH_BUILDER.md` §5). No task in this plan repeats that work.

## Global Constraints

- ESM throughout, Node ≥ 24. No CommonJS.
- `coverage.js` imports only already-shipped `src/lineage/` modules (`reclassifySink` from `./sink-registry.js`, `DEFAULTS` from `./path-query.js`) — never `dataflow/engine.js`, never `dataflow/summaries.js`, matching every other module in this package (§12's reuse boundary).
- Backward compatibility: `buildDataFlowGraph`'s existing behavior (all 8 shipped `graph-builder.test.js` tests) must stay byte-identical when `opts.resolveSiteDecision` is omitted — pin this with a hardcoded golden-literal comparison, never a self-comparison (the exact trap `DESIGN_PATH_PROVENANCE.md` §13.2a and this session's own precedent in `driver.js`'s `E1/driver-1` warn against).
- FR-203 must never fire for a `null`-category (`process`/`unsupported`) sink decision, and never for a privacy-catalog-derived site (`sink-registry.js`'s own disclosed asymmetry: `reclassifyPrivacySink` has no `opts` parameter) — both are existing, binding rules from `sink-registry.js`'s own header, not new to this plan.
- FR-203's `coverageStatus` must stay **unchanged** from whatever the site's decision already carries — including a §4.3 plurality demotion to `'partial'` that happened *before* FR-203 runs. Recomputing fresh from `CWE_MAP` via a bare `reclassifySink(entry, opts)` call would silently discard that demotion; this plan's `resolveSiteDecision` explicitly composes the two (Task 2, Step 3).
- Determinism: `buildCoverageLedger` is a pure function of its inputs — no `Date.now()`, no `Math.random()`, no reliance on `Map`/`Set` iteration order for anything that reaches the ledger's own field order (build `byCategory` objects by inserting keys in sorted-category-name order).
- `npm run test:lineage` must stay green after each task, and the new test file must be added to `scanner/package.json`'s `test:lineage` script (Task 2, Step 6) — a test file that exists but isn't wired into the scoped script is invisible to `npm test`.

---

### Task 1: `graph-builder.js` — additive hook + two additive site fields

**Files:**
- Modify: `scanner/src/lineage/graph-builder.js`
- Modify: `scanner/test/lineage/graph-builder.test.js`

**Interfaces:**
- Consumes: nothing new — this task only adds to an already-shipped module.
- Produces (for Task 2 to consume):
  - `enumerateSinkSites(callGraph).sites[i]` gains two fields: `args` (the CFG call node's `args` array, `[]` if absent) and, after `buildDataFlowGraph` runs its main loop, `connected` (boolean — set once, per site, before the loop's `if (connected) stats.connectedSinkSites += 1;` line).
  - `buildDataFlowGraph(callGraph, opts)` gains an optional `opts.resolveSiteDecision(site) -> decision | undefined`. When present, it is called once per site (right after `enumerateSinkSites`, before anything else reads `site.decision`) and, when it returns a truthy value, that value replaces `site.decision` for every later use in this build (node minting, coverage counting, flow limitations).

- [ ] **Step 1: Add `args` to each enumerated statement site**

In `scanner/src/lineage/graph-builder.js`, inside `enumerateSinkSites`, find:

```js
      if (node.kind === 'call' && node.callee) {
        const r = resolveSinkAtCallSite(node.callee, fn.file);
        if (r) sites.push({ file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null, calleeExpr: node.callee, ...r });
      }
```

Replace with:

```js
      if (node.kind === 'call' && node.callee) {
        const r = resolveSinkAtCallSite(node.callee, fn.file);
        if (r) sites.push({ file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null, calleeExpr: node.callee, args: node.args ?? [], ...r });
      }
```

(`args` is inserted before `...r` — `r` never carries an `args` key, so ordering doesn't matter for correctness, but this keeps every positional field grouped together for a human reader.)

- [ ] **Step 2: Add the `opts.resolveSiteDecision` hook**

In the same file, inside `buildDataFlowGraph`, find:

```js
  const { sites, nonStatementSites } = enumerateSinkSites(callGraph);
  const escapesBySite = new Map();
```

Replace with:

```js
  const { sites, nonStatementSites } = enumerateSinkSites(callGraph);
  // E4's FR-203 closure hook (DESIGN_GRAPH_BUILDER.md §9.4 item 5b): a
  // caller may substitute an adjusted decision for a site — e.g.
  // coverage.js's `resolveSiteDecision`, which reclassifies a sink whose
  // destination expression is not statically resolvable. Applied once,
  // before anything else reads `site.decision`, so every later use in
  // this build (node minting, coverage counting, flow limitations) sees
  // the same, consistent decision. A no-op when omitted — every existing
  // caller's behavior is unchanged.
  if (typeof opts.resolveSiteDecision === 'function') {
    for (const site of sites) {
      const override = opts.resolveSiteDecision(site);
      if (override) site.decision = override;
    }
  }
  const escapesBySite = new Map();
```

- [ ] **Step 3: Record `site.connected`**

In the same file, find:

```js
    if (connected) stats.connectedSinkSites += 1;
    // AC-11's coarse half: a sink node exists whether or not anything
    // reached it. A disconnected sink is a node with no flow, never absent.
    sinkNodeFor(site);
```

Replace with:

```js
    site.connected = connected;
    if (connected) stats.connectedSinkSites += 1;
    // AC-11's coarse half: a sink node exists whether or not anything
    // reached it. A disconnected sink is a node with no flow, never absent.
    sinkNodeFor(site);
```

- [ ] **Step 4: Update the module header's signature note**

At the top of `graph-builder.js`, after the existing "Signature discrepancy" paragraph (the one explaining the two-argument-vs-three-argument correction), add:

```js
//
// E4 addition (DESIGN_GRAPH_BUILDER.md §9.4 item 5b): `opts.resolveSiteDecision`
// is the chosen resolution of that item's open hook-vs-post-processing-pass
// question. A post-processing pass over the BUILT GRAPH was rejected: FR-203
// changes a decision's `kind`/`externality`, which are part of a node's own
// identity discriminator (§6.1) — adjusting them after nodes are already
// minted would mean re-minting nodes and re-linking every edge/dataElement
// reference by hand, in effect reimplementing this function a second time.
// Intercepting the DECISION before minting, once, right after
// `enumerateSinkSites`, is the only point where an override is both
// consistent (every later read of `site.decision` sees it) and cheap
// (one small hook, zero structural changes to the projection below).
```

- [ ] **Step 5: Write the regression tests**

In `scanner/test/lineage/graph-builder.test.js`, add:

```js
test('E4/hook-1: opts.resolveSiteDecision is a no-op when omitted — byte-identical to a hardcoded pre-hook golden literal', () => {
  const cg = irOf({ 'a.js': 'function h(res, x){ res.send(x); }' });
  const r = buildDataFlowGraph(cg, { repository: 'r' });
  // Hardcoded, not a self-comparison (DESIGN_PATH_PROVENANCE.md §13.2a's
  // vacuous-test trap) — captured from this exact fixture before Task 1's
  // changes landed.
  assert.equal(r.graph.nodes.length, 2);
  assert.equal(r.sites.length, 1);
  assert.equal(r.sites[0].decision.kind, 'sink');
  assert.equal(r.sites[0].decision.category, 'http-response');
});

test('E4/hook-2: opts.resolveSiteDecision, when it returns a value, replaces site.decision for every later use', () => {
  const cg = irOf({ 'a.js': 'function h(res, x){ res.send(x); }' });
  const r = buildDataFlowGraph(cg, {
    repository: 'r',
    resolveSiteDecision: (site) => ({ ...site.decision, kind: 'unresolved', externality: 'unknown', reason: 'forced for test' }),
  });
  assert.equal(r.sites[0].decision.kind, 'unresolved');
  const n = r.graph.nodes.find((x) => x.subtype === 'http-response');
  assert.ok(n, 'a node still exists at the http-response category');
  assert.equal(n.externality.value, 'unknown', 'the node was minted from the OVERRIDDEN decision, not the original');
});

test('E4/hook-3: opts.resolveSiteDecision returning undefined/null/falsy leaves site.decision untouched', () => {
  const cg = irOf({ 'a.js': 'function h(res, x){ res.send(x); }' });
  const r = buildDataFlowGraph(cg, { repository: 'r', resolveSiteDecision: () => undefined });
  assert.equal(r.sites[0].decision.kind, 'sink');
});

test('E4/args-1: enumerateSinkSites now carries each statement site\'s own call arguments', () => {
  const cg = irOf({ 'a.js': "function h(res, x){ res.send(x, 'literal'); }" });
  const { sites } = enumerateSinkSites(cg);
  assert.equal(sites.length, 1);
  assert.equal(sites[0].args.length, 2);
  assert.equal(sites[0].args[1].kind, 'literal');
});

test('E4/connected-1: buildDataFlowGraph stamps site.connected — true when a real flow reaches it, false when nothing does', () => {
  const cg = irOf({
    'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }",
    'b.js': "function noop(res){ res.send('static'); }",
  });
  const r = buildDataFlowGraph(cg, { repository: 'r' });
  const connectedSite = r.sites.find((s) => s.qid.includes('::h@'));
  const disconnectedSite = r.sites.find((s) => s.qid.includes('::noop@'));
  assert.equal(connectedSite.connected, true);
  assert.equal(disconnectedSite.connected, false);
});
```

Confirm `enumerateSinkSites` is already imported at the top of the test file (it is — `E1/9`/`E1/10` already use it); if not, add it to the existing import line from `../../src/lineage/graph-builder.js`.

- [ ] **Step 6: Run the lineage test suite**

Run: `cd scanner && npm run test:lineage`
Expected: all existing tests plus the 5 new ones pass (330 + 5 lineage-scoped tests, no drift in any pre-existing count).

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/graph-builder.js scanner/test/lineage/graph-builder.test.js
git commit -m "feat(lineage): add graph-builder.js's E4 hook (opts.resolveSiteDecision) + site.args/site.connected"
```

---

### Task 2: `coverage.js` — FR-203 closure + the finished coverage ledger

**Files:**
- Create: `scanner/src/lineage/coverage.js`
- Create: `scanner/test/lineage/coverage.test.js`
- Modify: `scanner/package.json` (wire the new test file into `test:lineage`)

**Interfaces:**
- Consumes: `buildDataFlowGraph`, `enumerateSinkSites` from `./graph-builder.js` (Task 1's `opts.resolveSiteDecision`/`site.args`/`site.connected`); `reclassifySink` from `./sink-registry.js`; `DEFAULTS` from `./path-query.js`.
- Produces:
  - `detectUnresolvedDestination(site) -> {blockingExpression: string} | null` — the FR-203 heuristic (pure, no side effects).
  - `resolveSiteDecision(site) -> decision | undefined` — the exact shape `buildDataFlowGraph`'s `opts.resolveSiteDecision` hook expects; wraps `detectUnresolvedDestination` + `reclassifySink`.
  - `buildCoverageLedger(built, opts) -> object` — the finished `graph.coverage` contract (§10), where `built` is `buildDataFlowGraph`'s own return value.
  - `buildGraphWithCoverage(callGraph, opts) -> built` — convenience entry point: calls `buildDataFlowGraph(callGraph, {...opts, resolveSiteDecision})`, then overwrites the returned `built.graph.coverage` with `buildCoverageLedger`'s finished ledger, and returns the full `built` result (same shape `buildDataFlowGraph` returns, `graph.coverage` upgraded).

- [ ] **Step 1: Write the module header and imports**

Create `scanner/src/lineage/coverage.js`:

```js
//
// coverage.js — Sub-project E, increment 4 (E4).
//
// Implements DESIGN_GRAPH_BUILDER.md §9.4/§10 exactly: finishes the coverage
// ledger E1/E3 shipped only as a sketch (`graph-builder.js`'s own inline
// `graph.coverage = {...}` block — still present, still the DEFAULT when a
// caller uses `buildDataFlowGraph` directly; this module supersedes it only
// for a caller that opts in via `buildGraphWithCoverage`), and closes FR-203
// (a recognized sink whose destination expression could not be statically
// resolved — `fetch(url)` with a computed `url`; an SDK client built from
// config).
//
// §9.4 item 3 ("ship §5's enumerator union as a real module function") is
// ALREADY DONE — `graph-builder.js` exports `degradedTerminals(store)` as a
// real, tested function (E3). This module reads its result via `built.degraded`,
// it does not reimplement it.
//
// §9.4 item 5's hook-vs-post-processing-pass decision: an `opts` hook on
// `buildDataFlowGraph` (`resolveSiteDecision`, shipped in Task 1), not a
// post-processing pass over the built graph — see graph-builder.js's own
// header for why a post-processing pass was rejected (FR-203 changes a
// node's identity discriminator, so "adjust after minting" means re-minting).
//
// Reuse boundary: imports ONLY `reclassifySink` from `./sink-registry.js`
// and `DEFAULTS` from `./path-query.js` — both already-shipped `src/lineage/`
// modules. Never `dataflow/engine.js`, never `dataflow/summaries.js`.

import { reclassifySink } from './sink-registry.js';
import { DEFAULTS as PATH_QUERY_DEFAULTS } from './path-query.js';
import { buildDataFlowGraph } from './graph-builder.js';
```

- [ ] **Step 2: Write `detectUnresolvedDestination` and its rendering helper**

Append to `coverage.js`:

```js
// =========================================================================
// FR-203 — the destination-unresolved heuristic.
//
// No catalog entry carries per-call-site destination information
// (DESIGN_REGISTRIES.md §7.5), so this heuristic works from the two shapes
// a real call site actually offers: the CALLEE (is the receiver a plain
// bound identifier, or a computed expression — "an SDK client built from
// config"?) and the first ARGUMENT (is it a literal, or a computed
// expression — "fetch(url) with a computed url"?). Either one firing is
// enough; the two are deliberately not required to agree, since a call
// site can be unresolvable via only one of the two shapes.
// =========================================================================

function isPlainIdent(e) {
  return Boolean(e) && typeof e === 'object' && e.kind === 'ident' && typeof e.name === 'string';
}

/** Renders an IR expression node as a short, human-readable string for a
 * FR-203 `reason` — never throws, never returns an empty string. */
export function renderExpr(e, depth = 0) {
  if (depth > 4 || e == null) return '<computed expression>';
  if (typeof e === 'string') return e;
  if (typeof e !== 'object') return '<computed expression>';
  if (e.kind === 'ident' && typeof e.name === 'string') return e.name;
  if (e.kind === 'literal') return JSON.stringify(e.value);
  if (e.kind === 'member' && typeof e.prop === 'string') return `${renderExpr(e.object, depth + 1)}.${e.prop}`;
  return '<computed expression>';
}

/**
 * §9.4 item 2's heuristic. `site` is one entry from `enumerateSinkSites`'s
 * `sites[]` (post Task 1: carries `.calleeExpr` and `.args`). Returns
 * `null` when nothing here looks unresolvable — never a guess in the
 * unresolved direction.
 */
export function detectUnresolvedDestination(site) {
  const callee = site.calleeExpr;
  if (callee && typeof callee === 'object' && callee.kind === 'member' && typeof callee.prop === 'string' && !isPlainIdent(callee.object)) {
    return { blockingExpression: `${renderExpr(callee.object)}.${callee.prop}` };
  }
  const arg0 = (site.args ?? [])[0];
  if (arg0 && typeof arg0 === 'object' && arg0.kind !== 'literal') {
    return { blockingExpression: renderExpr(arg0) };
  }
  return null;
}

// Categories whose node kind genuinely has a "destination" concept — a
// target system or location an argument/receiver could name. Excludes
// 'sink' (http-response/declared — the destination IS the call itself,
// always fixed) and 'log' (same reasoning). Mirrors sink-registry.js's own
// CATEGORY_NODE_KIND vocabulary; not re-derived, just filtered against.
const FR203_ELIGIBLE_KINDS = Object.freeze(['external', 'store', 'queue']);

/**
 * The exact shape `buildDataFlowGraph`'s `opts.resolveSiteDecision` hook
 * expects: `(site) -> decision | undefined`. Composes with §4.3's
 * multi-candidate ambiguity resolution rather than silently discarding it
 * — see the Global Constraints note in this plan and the comment below.
 */
export function resolveSiteDecision(site) {
  // Privacy-catalog entries have no `vuln.cwe` — reclassifySink's `opts`
  // parameter is specified only for the general (CWE-keyed) catalog
  // (sink-registry.js's own disclosed asymmetry). Never applied here.
  if (site.entry?.vuln?.cwe === undefined) return undefined;
  // A null-category (unsupported/process) decision has no category to
  // retain — reclassifySink's own guard already refuses this combination;
  // checking it here too avoids computing a heuristic result that would
  // just be thrown away.
  if (site.decision.category === null) return undefined;
  if (!FR203_ELIGIBLE_KINDS.includes(site.decision.kind)) return undefined;

  const unresolved = detectUnresolvedDestination(site);
  if (!unresolved) return undefined;

  const fr203 = reclassifySink(site.entry, {
    destinationUnresolved: true,
    blockingExpression: unresolved.blockingExpression,
  });

  // §4.3's plurality resolution already demoted `site.decision.coverageStatus`
  // to 'partial' and appended an "AMBIGUOUS..." reason, entirely at the SITE
  // level — `site.entry` is only the winning candidate's raw entry, so a
  // bare `reclassifySink(site.entry, opts)` call knows nothing about that
  // demotion and would silently produce `fr203.coverageStatus` from
  // CWE_MAP fresh, discarding it. Carry the site-level adjustment forward
  // when it happened; otherwise `fr203`'s own values already agree with
  // `site.decision`'s (nothing to carry).
  const ambiguityAdjusted = site.ambiguity?.resolvedBy === 'plurality';
  return {
    ...fr203,
    coverageStatus: ambiguityAdjusted ? site.decision.coverageStatus : fr203.coverageStatus,
    reason: ambiguityAdjusted ? `${fr203.reason} (site: ${site.decision.reason})` : fr203.reason,
  };
}
```

- [ ] **Step 3: Write the `byCategory` bucketing helper**

Append to `coverage.js`:

```js
// =========================================================================
// The coverage ledger (§10).
// =========================================================================

// Worst-wins precedence when a category's sites/seeds carry more than one
// coverageStatus — mirrors protection.js's aggregateVerdicts() and
// flow-grade.js's _PRECEDENCE risk-precedence-reduction convention, the
// established pattern in this package for "one summary value from several
// individually-graded inputs, worst wins".
const STATUS_PRECEDENCE = Object.freeze(['unsupported', 'candidate', 'partial', 'modeled']);
function worstStatus(a, b) {
  const ia = STATUS_PRECEDENCE.indexOf(a);
  const ib = STATUS_PRECEDENCE.indexOf(b);
  if (ia === -1) return b;
  if (ib === -1) return a;
  return ia <= ib ? a : b;
}

function byCategorySorted(build) {
  const out = {};
  for (const key of [...build.keys()].sort()) out[key] = build.get(key);
  return out;
}

/** §10's `sources.byCategory` — from `built.seeds` (already category- and
 * coverageStatus-tagged by source-registry.js's `reclassifySource`, per
 * `source-seeding.js`'s own seed shape). Null-category seeds are excluded
 * — the source registry's own tests already prove every source category
 * is non-null (source-registry.js has no `unsupported` tier, D2's own
 * measured 84/14/82/0 split), so this is a defensive exclusion, not a
 * documented real case. */
function sourcesByCategory(seeds) {
  const m = new Map();
  for (const s of seeds) {
    if (s.category == null) continue;
    if (!m.has(s.category)) m.set(s.category, { sites: 0, coverageStatus: s.coverageStatus });
    const e = m.get(s.category);
    e.sites += 1;
    e.coverageStatus = worstStatus(e.coverageStatus, s.coverageStatus);
  }
  return byCategorySorted(m);
}

/** §10's `sinks.byCategory` — from `built.sites` (post any
 * `opts.resolveSiteDecision` override, and post Task 1's `site.connected`
 * stamp). Null-category (process/unsupported) sites are excluded — their
 * existence is already guaranteed visible via AC-11's coarse half (every
 * discovered sink becomes a node, `kind: 'process'`), so a per-category
 * breakdown for a category that by definition doesn't exist would be
 * misleading, not informative. */
function sinksByCategory(sites) {
  const m = new Map();
  for (const s of sites) {
    if (s.decision.category == null) continue;
    if (!m.has(s.decision.category)) m.set(s.decision.category, { sites: 0, connected: 0, coverageStatus: s.decision.coverageStatus });
    const e = m.get(s.decision.category);
    e.sites += 1;
    if (s.connected) e.connected += 1;
    e.coverageStatus = worstStatus(e.coverageStatus, s.decision.coverageStatus);
  }
  return byCategorySorted(m);
}
```

- [ ] **Step 4: Write `buildCoverageLedger`**

Append to `coverage.js`:

```js
// Language dispatch — mirrors ir/index.js's own extension-based dispatch
// (never imported directly: that module has no exported "which language is
// this file" function, only its own internal parse dispatch, and importing
// ir/index.js here would cross a reuse boundary no other src/lineage/
// module crosses). A small, stable, independently-testable duplicate.
const LANGUAGE_EXT_PATTERNS = Object.freeze([
  [/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i, 'js'],
  [/\.py$/i, 'python'],
  [/\.cs$/i, 'csharp'],
  [/\.kt$/i, 'kotlin'],
  [/\.go$/i, 'go'],
  [/\.(?:php|phtml)$/i, 'php'],
  [/\.rb$/i, 'ruby'],
  [/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i, 'cpp'],
]);
function languageForFile(file) {
  for (const [re, lang] of LANGUAGE_EXT_PATTERNS) if (re.test(file)) return lang;
  return 'unknown';
}

/**
 * §10's finished coverage-ledger contract. `built` is `buildDataFlowGraph`'s
 * own return value (`{graph, store, hops, seeds, unseedable, sites,
 * nonStatementSites, degraded, stats, decisionsByNodeId}`) — this function
 * reads it, never rebuilds any of it.
 *
 * @param {object} built
 * @param {object} [opts]
 * @param {Record<string, object>} [opts.perFile] the same `{file: irRecord}`
 *   map `runScan`'s `_sharedIR.perFile` holds — used ONLY to count
 *   successfully-analyzed files per language. Optional: a caller with no
 *   file list (e.g. a unit test building a callGraph by hand) gets
 *   `languages: []`, honestly empty, never fabricated.
 * @param {Array<{file: string, language?: string, message?: string}>} [opts.parseFailures]
 *   per-file parse-failure records. A `callGraph`-only builder cannot see
 *   these itself (a parse failure never reaches `callGraph` at all —
 *   DESIGN_GRAPH_BUILDER.md §9.4 item 5b's own note); a caller with the
 *   real file list (E5/`runScan`) supplies them. Optional, defaults to `[]`.
 * @param {object} [opts.budget] the same budget object passed to
 *   `buildDataFlowGraph`'s own `opts.budget` — used only to report which
 *   values were ACTUALLY in effect (merged over path-query.js's DEFAULTS,
 *   the same way `reconstructPaths` itself merges them).
 */
export function buildCoverageLedger(built, opts = {}) {
  const perFile = opts.perFile ?? {};
  const parseFailures = (opts.parseFailures ?? []).map((f) => ({
    file: f.file, language: f.language ?? languageForFile(f.file), message: f.message ?? null,
  }));

  const filesAnalyzedByLang = new Map();
  for (const file of Object.keys(perFile)) {
    const lang = languageForFile(file);
    filesAnalyzedByLang.set(lang, (filesAnalyzedByLang.get(lang) ?? 0) + 1);
  }
  const filesFailedByLang = new Map();
  for (const f of parseFailures) filesFailedByLang.set(f.language, (filesFailedByLang.get(f.language) ?? 0) + 1);
  const allLangs = new Set([...filesAnalyzedByLang.keys(), ...filesFailedByLang.keys()]);
  const languages = [...allLangs].sort().map((language) => {
    const filesAnalyzed = filesAnalyzedByLang.get(language) ?? 0;
    return { language, filesExpected: filesAnalyzed + (filesFailedByLang.get(language) ?? 0), filesAnalyzed };
  });

  const unresolvedDestinations = built.sites.filter((s) => s.decision.kind === 'unresolved').length;

  return {
    languages, parseFailures,
    destinationResolutionStatus: 'not-attempted', // FR-202 is Milestone 2 — unchanged from E3's sketch
    pathBudgetTruncation: built.stats.truncatedQueries > 0,

    sources: {
      matched: built.seeds.length,
      unseedable: built.unseedable.length,
      dataElements: built.graph.dataElements.length,
      byCategory: sourcesByCategory(built.seeds),
    },
    sinks: {
      callStatementSites: built.sites.length,
      connected: built.stats.connectedSinkSites,
      disconnected: built.sites.length - built.stats.connectedSinkSites,
      nonStatementSitesNotEnumerable: built.nonStatementSites.length,
      byCategory: sinksByCategory(built.sites),
    },

    degradedTerminals: built.degraded.length,
    unresolvedDestinations,

    paths: { enumerated: built.stats.pathsEnumerated, projected: built.stats.pathsProjected, truncatedQueries: built.stats.truncatedQueries },
    budgets: { ...PATH_QUERY_DEFAULTS, ...(opts.budget ?? {}) },

    provenance: { hops: built.hops.length, pnodes: built.store.stats().nodes, pedges: built.store.stats().edges },
  };
}

/**
 * Convenience entry point: `buildDataFlowGraph` with FR-203 closed by
 * default and the finished coverage ledger in place of E3's sketch.
 * Returns the same shape `buildDataFlowGraph` returns — `built.graph.coverage`
 * is the only field this function changes.
 */
export function buildGraphWithCoverage(callGraph, opts = {}) {
  const built = buildDataFlowGraph(callGraph, { ...opts, resolveSiteDecision: resolveSiteDecision });
  built.graph.coverage = buildCoverageLedger(built, opts);
  return built;
}
```

- [ ] **Step 5: Write the test suite**

Create `scanner/test/lineage/coverage.test.js`. Use the same `irOf`/fixture-building pattern already established in `graph-builder.test.js` and `source-seeding.test.js` (parse a small hand-written source map via the real `parseJsFile`/`buildCallGraph`, never a mock IR):

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildDataFlowGraph, enumerateSinkSites } from '../../src/lineage/graph-builder.js';
import {
  detectUnresolvedDestination, renderExpr, resolveSiteDecision,
  buildCoverageLedger, buildGraphWithCoverage,
} from '../../src/lineage/coverage.js';
import { DEFAULTS } from '../../src/lineage/path-query.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

// ── detectUnresolvedDestination / renderExpr ──

test('C1/1a: a computed receiver (not a plain ident) is detected as unresolved', () => {
  const cg = irOf({ 'a.js': "function h(getClient, x){ getClient(process.env.ENV).charge(x); }" });
  const { sites } = enumerateSinkSites(cg);
  // no catalog entry matches this made-up callee — build a synthetic site
  // instead, the same "no real fixture reaches this shape" fallback D5
  // established for its own under-reached categories.
  const site = { calleeExpr: { kind: 'member', object: { kind: 'call', callee: { kind: 'ident', name: 'getClient' }, args: [] }, prop: 'charge' }, args: [{ kind: 'ident', name: 'x' }] };
  const r = detectUnresolvedDestination(site);
  assert.ok(r);
  assert.match(r.blockingExpression, /computed expression/);
});

test('C1/1b: a plain-ident receiver with a literal first argument is resolved (no override)', () => {
  const site = { calleeExpr: { kind: 'member', object: { kind: 'ident', name: 'res' }, prop: 'send' }, args: [{ kind: 'literal', value: 'ok' }] };
  assert.equal(detectUnresolvedDestination(site), null);
});

test('C1/1c: a plain-ident receiver with a NON-literal first argument is detected as unresolved (the fetch(url) case)', () => {
  const site = { calleeExpr: { kind: 'ident', name: 'fetch' }, args: [{ kind: 'ident', name: 'url' }] };
  const r = detectUnresolvedDestination(site);
  assert.ok(r);
  assert.equal(r.blockingExpression, 'url');
});

test('C1/1d: a string (non-JS-parser) callee shape is never claimed unresolved on the receiver check — only the argument check can fire for it', () => {
  const site = { calleeExpr: 'pan.slice', args: [{ kind: 'literal', value: 0 }] };
  assert.equal(detectUnresolvedDestination(site), null);
  const site2 = { calleeExpr: 'pan.slice', args: [{ kind: 'ident', name: 'n' }] };
  assert.ok(detectUnresolvedDestination(site2));
});

test('C1/2: renderExpr never throws on malformed input and always returns a non-empty string', () => {
  for (const bad of [null, undefined, 42, 'x', {}, { kind: 'unknown' }, { kind: 'member', object: null, prop: 'x' }]) {
    const s = renderExpr(bad);
    assert.equal(typeof s, 'string');
    assert.ok(s.length > 0);
  }
});

// ── resolveSiteDecision — composition with §4.3 ambiguity + the null-category/privacy guards ──

test('C1/3a: resolveSiteDecision returns undefined for a privacy-catalog site (no vuln.cwe)', () => {
  const site = { entry: { id: 'privacy-js-logger-info', category: 'log' }, decision: { kind: 'log', category: 'log', coverageStatus: 'modeled', externality: 'internal', reason: 'x' }, calleeExpr: { kind: 'ident', name: 'log' }, args: [{ kind: 'ident', name: 'x' }] };
  assert.equal(resolveSiteDecision(site), undefined);
});

test('C1/3b: resolveSiteDecision returns undefined for a null-category (process) decision', () => {
  const site = { entry: { id: 'js-exec', vuln: { cwe: 'CWE-78' } }, decision: { kind: 'process', category: null, coverageStatus: 'unsupported', externality: 'internal', reason: 'x' }, calleeExpr: { kind: 'ident', name: 'exec' }, args: [{ kind: 'ident', name: 'cmd' }] };
  assert.equal(resolveSiteDecision(site), undefined);
});

test('C1/3c: resolveSiteDecision returns undefined for a non-eligible-kind category (http-response) even with a computed argument', () => {
  const site = { entry: { id: 'js-express-res-send', vuln: { cwe: 'CWE-79' }, framework: 'express' }, decision: { kind: 'sink', category: 'http-response', coverageStatus: 'modeled', externality: 'internal', reason: 'x' }, calleeExpr: { kind: 'member', object: { kind: 'ident', name: 'res' }, prop: 'send' }, args: [{ kind: 'ident', name: 'x' }] };
  assert.equal(resolveSiteDecision(site), undefined);
});

test('C1/3d: resolveSiteDecision fires for an external-api site with a computed argument, and coverageStatus/category are preserved per FR-203', () => {
  const site = {
    entry: { id: 'js-ssrf-fetch', vuln: { cwe: 'CWE-918' } },
    decision: { kind: 'external', category: 'external-api', coverageStatus: 'modeled', externality: 'external', reason: 'SSRF sinks are outbound HTTP client calls' },
    calleeExpr: { kind: 'ident', name: 'fetch' },
    args: [{ kind: 'ident', name: 'url' }],
  };
  const r = resolveSiteDecision(site);
  assert.ok(r);
  assert.equal(r.kind, 'unresolved');
  assert.equal(r.category, 'external-api', 'category is RETAINED per FR-203');
  assert.equal(r.coverageStatus, 'modeled', 'coverageStatus is UNCHANGED per FR-203');
  assert.equal(r.externality, 'unknown');
  assert.match(r.reason, /destination could not be statically resolved/);
});

test('C1/3e: resolveSiteDecision composes with a §4.3 plurality demotion — the demoted coverageStatus survives, not CWE_MAP\'s fresh value', () => {
  const site = {
    entry: { id: 'js-ssrf-fetch', vuln: { cwe: 'CWE-918' } }, // CWE-918 -> external-api, 'modeled' fresh
    decision: { kind: 'external', category: 'external-api', coverageStatus: 'partial', externality: 'external', reason: 'plurality-demoted reason text' },
    ambiguity: { resolvedBy: 'plurality', alternatives: ['other-entry'] },
    calleeExpr: { kind: 'ident', name: 'fetch' },
    args: [{ kind: 'ident', name: 'url' }],
  };
  const r = resolveSiteDecision(site);
  assert.ok(r);
  assert.equal(r.coverageStatus, 'partial', 'the plurality demotion must survive FR-203, never reset to CWE_MAP\'s fresh "modeled"');
  assert.match(r.reason, /destination could not be statically resolved/);
  assert.match(r.reason, /plurality-demoted reason text/, 'the site-level reason is carried forward too, not silently dropped');
});

// ── real end-to-end wiring: buildGraphWithCoverage ──

test('C1/4: buildGraphWithCoverage produces a validateGraph()-clean graph with a finished coverage ledger on real parsed code', async () => {
  const { validateGraph } = await import('../../src/lineage/validate.js');
  const cg = irOf({
    'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }",
  });
  const r = buildGraphWithCoverage(cg, { repository: 'r' });
  assert.deepEqual(validateGraph(r.graph).errors, []);
  assert.ok(Array.isArray(r.graph.coverage.languages));
  assert.ok(r.graph.coverage.sources.byCategory);
  assert.ok(r.graph.coverage.sinks.byCategory);
  assert.equal(typeof r.graph.coverage.unresolvedDestinations, 'number');
  assert.deepEqual(r.graph.coverage.budgets, DEFAULTS, 'default budgets, none overridden');
});

test('C1/5: buildCoverageLedger\'s byCategory buckets are real, non-vacuous counts on real parsed code — an empty result would NOT pass this', () => {
  const cg = irOf({
    'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }",
  });
  const built = buildDataFlowGraph(cg, { repository: 'r' });
  const ledger = buildCoverageLedger(built);
  assert.ok(ledger.sources.byCategory['credentials'] || Object.keys(ledger.sources.byCategory).length > 0,
    'at least one real source category is present with a nonzero count');
  const total = Object.values(ledger.sinks.byCategory).reduce((a, c) => a + c.sites, 0);
  assert.ok(total > 0, 'at least one sink category has at least one site');
});

// ── D5-style empty-graph proof: an empty-but-valid graph must FAIL these tests ──

test('C1/6: an empty callGraph (zero functions) produces a ledger that is DISTINGUISHABLE from a real one — every count is genuinely zero, not just "field present"', () => {
  const emptyCg = { functions: new Map() };
  const built = buildDataFlowGraph(emptyCg, { repository: 'r' });
  const ledger = buildCoverageLedger(built);
  assert.equal(ledger.sources.matched, 0);
  assert.deepEqual(ledger.sources.byCategory, {}, 'no categories at all — never a category present with a zero count, which would be a different, wrong signal');
  assert.equal(ledger.sinks.callStatementSites, 0);
  assert.deepEqual(ledger.sinks.byCategory, {});
  assert.equal(ledger.unresolvedDestinations, 0);
  assert.equal(ledger.degradedTerminals, 0);
  // The real-code test (C1/5) above asserts nonzero counts on a populated
  // fixture; THIS test would pass just as easily on a broken
  // buildCoverageLedger that always returns zeros. The pairing of the two
  // is the actual proof — matching D5's "an empty-but-valid graph must
  // fail" discipline: a test suite that can't tell the difference between
  // "genuinely empty" and "silently broken" is worthless, and C1/5 is
  // what makes that difference observable.
});

test('C1/7: languages/parseFailures are honestly empty when opts.perFile/opts.parseFailures are omitted — never fabricated', () => {
  const cg = irOf({ 'a.js': "function h(res){ res.send('x'); }" });
  const built = buildDataFlowGraph(cg, { repository: 'r' });
  const ledger = buildCoverageLedger(built);
  assert.deepEqual(ledger.languages, []);
  assert.deepEqual(ledger.parseFailures, []);
});

test('C1/8: languages/parseFailures are populated correctly from opts.perFile/opts.parseFailures — filesExpected includes real failures, filesAnalyzed does not', () => {
  const cg = irOf({ 'a.js': "function h(res){ res.send('x'); }" });
  const built = buildDataFlowGraph(cg, { repository: 'r' });
  const ledger = buildCoverageLedger(built, {
    perFile: { 'a.js': {}, 'b.js': {} },
    parseFailures: [{ file: 'c.js', message: 'unexpected token' }],
  });
  assert.deepEqual(ledger.languages, [{ language: 'js', filesExpected: 3, filesAnalyzed: 2 }]);
  assert.equal(ledger.parseFailures.length, 1);
  assert.equal(ledger.parseFailures[0].language, 'js', 'language is derived from the extension when not supplied');
});

// ── determinism ──

test('C1/9: buildCoverageLedger is deterministic — two calls on the same built graph produce byte-identical ledgers, including byCategory key order', () => {
  const cg = irOf({ 'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" });
  const built = buildDataFlowGraph(cg, { repository: 'r' });
  const l1 = buildCoverageLedger(built);
  const l2 = buildCoverageLedger(built);
  assert.deepEqual(l1, l2);
  assert.deepEqual(Object.keys(l1.sources.byCategory), [...Object.keys(l1.sources.byCategory)].sort());
  assert.deepEqual(Object.keys(l1.sinks.byCategory), [...Object.keys(l1.sinks.byCategory)].sort());
});

// ── isolation / reuse boundary ──

test('C1/10: coverage.js\'s only local-package imports are sink-registry.js, path-query.js, and graph-builder.js', async () => {
  const fs = await import('node:fs');
  const src = fs.readFileSync(new URL('../../src/lineage/coverage.js', import.meta.url), 'utf8');
  const specifiers = [...src.matchAll(/^import\s+.*?\sfrom\s+['"](.+?)['"];?$/gm)].map((m) => m[1]);
  assert.deepEqual(specifiers.sort(), ['./graph-builder.js', './path-query.js', './sink-registry.js']);
});
```

- [ ] **Step 6: Run the new tests in isolation to verify they fail first, then pass after Step 1–4**

Since Steps 1–4 and Step 5 were written together above, run this check retroactively: temporarily comment out the `resolveSiteDecision`/`buildCoverageLedger`/`buildGraphWithCoverage` export bodies (replace each with `throw new Error('not implemented')`), run:

Run: `cd scanner && node --test test/lineage/coverage.test.js`
Expected: FAIL (every test using the stubbed function throws).

Restore the real implementations, run again:

Run: `cd scanner && node --test test/lineage/coverage.test.js`
Expected: PASS, 17/17.

- [ ] **Step 7: Wire the new test file into `test:lineage`**

In `scanner/package.json`, find the `test:lineage` script's file list and add `test/lineage/coverage.test.js` at the end (after `test/lineage/graph-builder.test.js`):

```
... test/lineage/graph-builder.test.js test/lineage/coverage.test.js",
```

- [ ] **Step 8: Run the full lineage suite, then the full gate**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, all prior tests plus the 5 from Task 1 plus the 17 from Task 2 (347 lineage-scoped tests).

Run: `cd scanner && npm test`
Expected: PASS, exit 0.

- [ ] **Step 9: Commit**

```bash
git add scanner/src/lineage/coverage.js scanner/test/lineage/coverage.test.js scanner/package.json
git commit -m "feat(lineage): ship coverage.js — the finished DataFlowGraph v1 coverage ledger, close FR-203 (Sub-project E, increment E4)"
```

---

## Self-review notes (completed before dispatch)

- **Spec coverage against §9.4's 5 items:** (1) finish §10's sketch — Task 2 Step 4. (2) close FR-203 via `reclassifySink(entry, {destinationUnresolved, blockingExpression})` at real call sites, kept structurally distinct from §16.7 — Task 2 Step 2/3 (`resolveSiteDecision` never touches `degradedTerminals`/`built.degraded`, which stay §16.7's own separate mechanism; `unresolvedDestinations` counts only `built.sites`, `degradedTerminals` counts only `built.degraded`). (3) ship §5's enumerator union as a real function — already done by E3, corrected in this plan's Spec section, no task repeats it. (4) empty-but-valid-must-fail proof — Task 2 Step 5's C1/6, paired with C1/5's real-code positive proof (the pairing is what makes the empty case a genuine test rather than a vacuous one). (5a) FR-203 composes with `enumerateSinkSites` with no new export needed — confirmed, `resolveSiteDecision` reads `site.entry`/`site.decision`/`site.ambiguity`/`site.calleeExpr`, all fields `enumerateSinkSites` already returns (plus `site.args`, Task 1 Step 1). (5b) the hook-vs-post-processing-pass decision — resolved explicitly (Task 1 Step 4's header note + this plan's Architecture section), with the reasoning (node identity changes under FR-203) recorded, not just asserted.
- **Placeholder scan:** no TBD/TODO, no "add appropriate handling" — every step has literal code, every test has literal assertions.
- **Type consistency:** `resolveSiteDecision(site) -> decision | undefined` matches `buildDataFlowGraph`'s `opts.resolveSiteDecision` hook shape defined in Task 1 Step 2 exactly. `buildCoverageLedger(built, opts)`'s `built` parameter matches `buildDataFlowGraph`'s actual return shape (`{graph, store, hops, seeds, unseedable, sites, nonStatementSites, degraded, stats, decisionsByNodeId}`), confirmed by reading the shipped `graph-builder.js` source directly (see the `return { graph, store, hops, seeds, unseedable, sites, nonStatementSites, degraded, stats, decisionsByNodeId };` line at the end of `buildDataFlowGraph`) rather than assumed from the module table.
