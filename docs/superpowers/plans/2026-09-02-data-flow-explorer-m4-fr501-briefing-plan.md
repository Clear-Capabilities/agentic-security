# M4 Deliverable #7 (FR-501, DFG-035): Executive Risk Story Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the deterministic data + CLI export layer for Executive
Risk Story Mode: a `DecisionStory` extension contract, an 8-of-9-factor
transparent ranking engine over real flows, and 5 narrative chapters
(one honestly degraded), exported via `dataflow export --format
briefing`.

**Architecture:** A new pure contract/validation module
(`decision-story.js`, mirroring `obligation-mapping.js`'s shape exactly);
a new ranking-engine module scoring every flow on 9 named factors (7
direct graph reads + 1 new small aggregation + 1 honest `unavailable`);
5 new chapter-emit functions (mirroring `export-privacy.js`'s
escaping-safe Markdown pattern); CLI wiring into the existing `dataflow
export` command as a new `--format briefing` value with a new
`--audience` flag.

**Tech Stack:** Plain ESM, no new dependencies. Reuses
`dataflow/privacy-taxonomy.js`'s `SEVERITY_RANK`/`DEFAULT_TAXONOMY`,
`lineage/protection.js`'s verdict/grade vocab,
`posture/obligation-evidence-pack.js`'s signing composition for the
signed variant, `lineage/ids.js`'s hash-id pattern.

**Spec:** `2026-09-02-data-flow-explorer-m4-fr501-briefing-scoping.md`
(FR-501, DFG-035, PRD §14 lines 436-460, §10.10 line 966, AC-25 lines
1725-1731 — read the scoping doc first, every design decision below is
grounded there).

## Global Constraints

- Never fabricate a fact. Every ranking factor is either a direct read
  off the real graph, a small real aggregation defined in this plan, or
  explicitly `unavailable` (never silently omitted from the factor
  list, never guessed).
- The ranking engine must NEVER produce a single opaque "risk score"
  presented as financial loss or breach probability (PRD's own binding
  constraint) — every factor stays individually inspectable; the overall
  ordering is a documented, transparent, configurable multi-key sort
  over factor tiers, not a blended float.
- `DecisionStory` records are explicitly NOT `DataFlowGraph v1` entities
  (§10.10, same rule as `ObligationMapping`) — never added to
  `dataflow-graph.schema.json`, never routed through `validate.js`.
- Every value interpolated into chapter Markdown must be escaped, same
  discipline as `export-privacy.js`'s `_mdInline`/`_mdCell`/`_mdCode`
  (operator-supplied governance prose flows into chapter 4 the same way
  it flows into DPIA/RoPA).
- Audience modes vary WORDING only, never underlying facts or ranking —
  the PRD's own binding constraint ("without changing the underlying
  facts").
- Real-graph tests required for every new function (this session's own
  hard-won lesson) — at least one test per new function must use
  `bench/data-lineage/runner.mjs#buildFixtureGraph` against a real
  fixture, not only hand-built graphs.
- New test files must be added to `scanner/package.json`'s
  `test:lineage` script.

---

### Task 1: `decision-story.js` — contract + ranking engine

**Files:**
- Create: `scanner/src/lineage/decision-story.js`
- Test: `scanner/test/lineage/decision-story.test.js` (new)

**Interfaces:**
- Consumes: `SEVERITY_RANK`, `DEFAULT_TAXONOMY` from
  `../dataflow/privacy-taxonomy.js`; a real `DataFlowGraph v1` object
  (`graph.nodes`, `graph.flows`, `graph.dataElements`).
- Produces: `RANKING_FACTORS` (array of 9 factor names), `validateDecisionStory(record)`
  (mirrors `obligation-mapping.js#validateObligationMapping`'s
  `{valid, errors}` shape), `scoreFlow(flow, graph, nodesById)` (one
  flow's own 9-factor score), `rankFlows(graph, opts)` (all flows,
  scored + sorted). Task 2 consumes `rankFlows`'s output directly.

- [ ] **Step 1: Write the failing tests for the contract + a single-factor scorer**

```js
// scanner/test/lineage/decision-story.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  RANKING_FACTORS, validateDecisionStory, scoreFlow, rankFlows,
} from '../../src/lineage/decision-story.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';

function _buildRealGraph(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  return buildGraphWithCoverage(callGraph, { repository: 'test-repo', generatedAt: '1970-01-01T00:00:00.000Z', ...opts }).graph;
}

// Real PHI-to-AI-model-provider shape (proven throughout M4) — PHI is
// 'high' severity in DEFAULT_TAXONOMY, destination is a real
// ai-model-provider node (externality: external), giving every
// available factor a real, non-default value to assert against.
const PHI_TO_AI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

test('RANKING_FACTORS lists exactly the 9 PRD-named factors', () => {
  assert.deepEqual(RANKING_FACTORS, [
    'sensitivity', 'externality', 'controlVerdict', 'recipientJurisdiction',
    'aiUse', 'breadth', 'evidenceConfidence', 'policyState', 'changeRecency',
  ]);
});

test('scoreFlow: a real PHI -> AI-model-provider flow scores sensitivity=high, externality=external, aiUse=true', () => {
  const graph = _buildRealGraph(PHI_TO_AI_SOURCE);
  assert.ok(graph.flows.length >= 1, 'fixture assumption drifted: expected a real PHI->AI flow');
  const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  const flow = graph.flows[0];
  const scored = scoreFlow(flow, graph, nodesById);
  assert.equal(scored.factors.sensitivity.tier, 'high');
  assert.equal(scored.factors.sensitivity.available, true);
  assert.equal(scored.factors.externality.tier, 'external');
  assert.equal(scored.factors.aiUse.available, true);
  assert.equal(scored.factors.aiUse.tier, 'ai_destination');
});

test('scoreFlow: recipientJurisdiction and changeRecency are ALWAYS unavailable — never fabricated, never silently dropped from the factor list', () => {
  const graph = _buildRealGraph(PHI_TO_AI_SOURCE);
  const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  const scored = scoreFlow(graph.flows[0], graph, nodesById);
  assert.equal(scored.factors.recipientJurisdiction.available, false);
  assert.equal(scored.factors.changeRecency.available, false);
  // Every factor in RANKING_FACTORS is present on every scored flow —
  // "disclosed as unknown" per the scoping doc, never omitted.
  for (const f of RANKING_FACTORS) assert.ok(f in scored.factors, `${f} missing from scored.factors`);
});

test('rankFlows: a flow with a real dataElement outranks a genuinely unclassified, internal, unprotected-but-unremarkable flow', () => {
  // Two independent real flows: one PHI->external-AI (should rank
  // first under every reasonable factor priority), one an unclassified,
  // fully-internal log write (should rank last).
  const MIXED_SOURCE = `
    function handle(anthropic, params, logger) {
      const patientRecord = params.arguments.patient_record;
      anthropic.messages.create({ model: 'claude-3', messages: [{ role: 'user', content: patientRecord }] });
      const page = params.query.page;
      logger.info('listing page', page);
    }
  `;
  const graph = _buildRealGraph(MIXED_SOURCE);
  assert.ok(graph.flows.length >= 2, 'fixture assumption drifted: expected two real, distinguishable flows');
  const ranked = rankFlows(graph);
  assert.ok(ranked.length >= 2);
  const top = ranked[0];
  const topDe = graph.dataElements.find((d) => d.id === top.flow.dataElementIds[0]);
  assert.ok((topDe?.dataClasses ?? []).length > 0, 'the top-ranked flow must be the classified one, not the unclassified log write');
});

test('rankFlows: opts.factorOrder lets a caller override the default priority sequence (PRD "configurable factors" requirement)', () => {
  const graph = _buildRealGraph(PHI_TO_AI_SOURCE);
  const defaultOrder = rankFlows(graph);
  const reordered = rankFlows(graph, { factorOrder: [...RANKING_FACTORS].reverse() });
  // Not asserting a specific different order (a single-flow graph can't
  // prove reordering moved anything) — asserting the override is
  // genuinely THREADED THROUGH, not silently ignored: both calls must
  // report the SAME factorOrder they were actually given.
  assert.deepEqual(defaultOrder[0].factorOrderUsed, RANKING_FACTORS);
  assert.deepEqual(reordered[0].factorOrderUsed, [...RANKING_FACTORS].reverse());
});

test('validateDecisionStory: rejects a record missing a required §10.10 field, accepts a well-formed one', () => {
  const bad = validateDecisionStory({ id: 'story:abc' });
  assert.equal(bad.valid, false);
  assert.ok(bad.errors.length > 0);

  const good = validateDecisionStory({
    id: 'story:abc123', version: '1', audienceMode: 'ciso',
    scopeQuery: {}, chapters: [], contributingGraphIds: [],
    rankingFactors: RANKING_FACTORS, evidenceGrade: 'code',
    coverage: { complete: true }, decisions: [],
    generatedAt: '1970-01-01T00:00:00.000Z', graphDigest: 'sha256:abc',
  });
  assert.deepEqual(good.errors, []);
  assert.equal(good.valid, true);
});

test('REAL CORPUS: sweeping bench/data-lineage/ fixtures never throws scoring or ranking flows', async () => {
  const { buildFixtureGraph } = await import('../../../bench/data-lineage/runner.mjs');
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const FIXTURES_ROOT = path.join(__dirname, '../../../bench/data-lineage/fixtures');
  const fixtureIds = fs.readdirSync(FIXTURES_ROOT).filter((f) => fs.statSync(path.join(FIXTURES_ROOT, f)).isDirectory());
  assert.ok(fixtureIds.length > 0);
  let checked = 0;
  for (const fixtureId of fixtureIds) {
    const srcPath = path.join(FIXTURES_ROOT, fixtureId, 'source.js');
    if (!fs.existsSync(srcPath)) continue;
    const source = fs.readFileSync(srcPath, 'utf8');
    const graph = buildFixtureGraph(fixtureId, source);
    assert.doesNotThrow(() => rankFlows(graph), `${fixtureId}: rankFlows threw`);
    checked++;
  }
  assert.ok(checked > 0, 'the sweep must exercise at least one real fixture, or this test is vacuous');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/lineage/decision-story.test.js`.
Expected: FAIL — `decision-story.js` does not exist yet.

- [ ] **Step 3: Write `decision-story.js`**

```js
// decision-story.js — M4 deliverable #7 (FR-501 §14, DFG-035): the
// DecisionStory extension contract (§10.10) + a transparent 9-factor
// ranking engine over real flows.
//
// Mirrors obligation-mapping.js's own shape exactly: a record is
// explicitly NOT a DataFlowGraph v1 entity (§10.10 — "associated with,
// but not required inside, the immutable base graph"), never added to
// dataflow-graph.schema.json, never routed through validate.js.
//
// Ranking-factor availability, grounded in real investigation (see this
// sub-project's own scoping doc): 7 of 9 factors are direct reads off
// the graph, 1 (breadth) is a small new aggregation defined here, and 2
// (recipientJurisdiction, changeRecency) are honestly `available: false`
// on every flow — never fabricated, never silently dropped from the
// factor list. recipientJurisdiction needs a RecipientProfile extension
// (capability #6, not yet built); changeRecency needs GraphSnapshot/
// GraphDiff (capability #3, Data-Flow Time Machine, not yet built).
//
// PRD's own binding constraint: "never represents an uncalibrated score
// as expected financial loss or breach probability." This module NEVER
// blends factors into a single opaque float — rankFlows performs a
// documented, transparent, CONFIGURABLE (opts.factorOrder) multi-key
// sort over each factor's own ordinal tier. Every factor stays
// individually inspectable on the returned record.

import { SEVERITY_RANK, DEFAULT_TAXONOMY } from '../dataflow/privacy-taxonomy.js';

export const RANKING_FACTORS = Object.freeze([
  'sensitivity', 'externality', 'controlVerdict', 'recipientJurisdiction',
  'aiUse', 'breadth', 'evidenceConfidence', 'policyState', 'changeRecency',
]);

// Ordinal tier ranks, worst-first, used both to score a flow's own
// factor and to compare two flows during rankFlows's own sort. Every
// factor uses a SMALL, real, disclosed vocabulary — never a blended
// number.
const _TIER_RANK = {
  sensitivity: { critical: 4, high: 3, medium: 2, low: 1, none: 0 },
  externality: { external: 2, unknown: 1, internal: 0 },
  controlVerdict: { unprotected: 4, mixed: 3, unknown: 2, not_assessed: 1, protected: 0, not_applicable: 0 },
  recipientJurisdiction: { unknown: 0 },
  aiUse: { ai_destination: 1, none: 0 },
  breadth: { high: 2, medium: 1, low: 0 },
  // Lower confidence is MORE attention-worthy (an uncertain flow needs
  // review), so the tier rank is inverted relative to the raw score —
  // disclosed here, not left implicit.
  evidenceConfidence: { low: 2, medium: 1, high: 0 },
  policyState: { prohibited: 4, manual_review_required: 3, conditionally_permitted: 2, not_evaluated: 1, permitted: 0 },
  changeRecency: { unknown: 0 },
};

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function _isArray(v) { return Array.isArray(v); }

/**
 * Structural validation only — mirrors
 * obligation-mapping.js#validateObligationMapping's own {valid, errors}
 * shape and "never throws" contract.
 */
export function validateDecisionStory(record) {
  const errors = [];
  const err = (path, message) => errors.push({ path, message });

  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'DecisionStory record must be an object');
    return { valid: false, errors };
  }
  if (!_isNonEmptyString(record.id) || !record.id.startsWith('story:')) {
    err('$.id', 'id is required and must start with "story:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.audienceMode)) err('$.audienceMode', 'audienceMode is required');
  if (!_isPlainObject(record.scopeQuery)) err('$.scopeQuery', 'scopeQuery is required and must be an object');
  if (!_isArray(record.chapters)) err('$.chapters', 'chapters must be an array');
  if (!_isArray(record.contributingGraphIds)) err('$.contributingGraphIds', 'contributingGraphIds must be an array');
  if (!_isArray(record.rankingFactors)) err('$.rankingFactors', 'rankingFactors must be an array');
  if (!_isNonEmptyString(record.evidenceGrade)) err('$.evidenceGrade', 'evidenceGrade is required');
  if (!_isPlainObject(record.coverage)) err('$.coverage', 'coverage is required and must be an object');
  if (!_isArray(record.decisions)) err('$.decisions', 'decisions must be an array');
  if (!_isNonEmptyString(record.generatedAt)) err('$.generatedAt', 'generatedAt is required');
  if (!_isNonEmptyString(record.graphDigest)) err('$.graphDigest', 'graphDigest is required');

  return { valid: errors.length === 0, errors };
}

function _sensitivityFactor(flow, graph) {
  const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const classes = de?.dataClasses ?? [];
  if (classes.length === 0) return { available: true, tier: 'none', evidence: [] };
  let worst = 'low';
  for (const cls of classes) {
    const sev = DEFAULT_TAXONOMY[cls]?.severity ?? 'medium';
    if ((SEVERITY_RANK[sev] ?? 0) > (SEVERITY_RANK[worst] ?? 0)) worst = sev;
  }
  return { available: true, tier: worst, evidence: [de.id] };
}

function _externalityFactor(flow, nodesById) {
  const sink = nodesById.get(flow.sink);
  const value = sink?.externality?.value ?? 'unknown';
  return { available: true, tier: value, evidence: [flow.sink] };
}

function _controlVerdictFactor(flow) {
  return { available: true, tier: flow.protectionSummary ?? 'not_assessed', evidence: flow.edgeIds ?? [] };
}

function _recipientJurisdictionFactor() {
  // Honest gap — see this file's own header. Never fabricated.
  return { available: false, tier: 'unknown', evidence: [], unavailableReason: 'RecipientProfile extension not yet built (capability #6, Third-Party/Cross-Border Intelligence)' };
}

function _aiUseFactor(flow, nodesById) {
  const sink = nodesById.get(flow.sink);
  const isAi = sink?.subtype === 'ai-model-provider' || sink?.subtype === 'ai-agent' || sink?.subtype === 'ai-tool';
  return { available: true, tier: isAi ? 'ai_destination' : 'none', evidence: isAi ? [flow.sink] : [] };
}

/**
 * New small aggregation (the scoping doc's own "smallest real addition"
 * for breadth/blast-radius): how many OTHER flows in the same graph
 * share this flow's own sink node or dataElement. A crude but real,
 * non-fabricated proxy for "how widely does this exposure reach" —
 * never presented as a calibrated blast-radius count, just an ordinal
 * tier over a real, disclosed count.
 */
function _breadthFactor(flow, graph) {
  let sharedCount = 0;
  for (const other of graph.flows) {
    if (other.id === flow.id) continue;
    const sharesSink = other.sink === flow.sink;
    const sharesData = other.dataElementIds.some((id) => flow.dataElementIds.includes(id));
    if (sharesSink || sharesData) sharedCount++;
  }
  const tier = sharedCount >= 5 ? 'high' : sharedCount >= 1 ? 'medium' : 'low';
  return { available: true, tier, evidence: [], sharedFlowCount: sharedCount };
}

function _evidenceConfidenceFactor(flow) {
  const tier = flow.confidence?.tier ?? 'medium';
  return { available: true, tier, evidence: [] };
}

function _policyStateFactor(flow) {
  return { available: true, tier: flow.policyVerdict ?? 'not_evaluated', evidence: flow.evidenceRefs ?? [] };
}

function _changeRecencyFactor() {
  // Honest gap — see this file's own header. Never fabricated.
  return { available: false, tier: 'unknown', evidence: [], unavailableReason: 'GraphSnapshot/GraphDiff not yet built (capability #3, Data-Flow Time Machine)' };
}

/** Score ONE flow on all 9 factors. Never throws on a well-formed graph. */
export function scoreFlow(flow, graph, nodesById) {
  return {
    flowId: flow.id,
    factors: {
      sensitivity: _sensitivityFactor(flow, graph),
      externality: _externalityFactor(flow, nodesById),
      controlVerdict: _controlVerdictFactor(flow),
      recipientJurisdiction: _recipientJurisdictionFactor(),
      aiUse: _aiUseFactor(flow, nodesById),
      breadth: _breadthFactor(flow, graph),
      evidenceConfidence: _evidenceConfidenceFactor(flow),
      policyState: _policyStateFactor(flow),
      changeRecency: _changeRecencyFactor(),
    },
  };
}

/**
 * Score and rank every flow in the graph. opts.factorOrder (default
 * RANKING_FACTORS) is the PRD's own "transparent configurable factors"
 * requirement, made real: a lexicographic multi-key sort over each
 * factor's own ordinal tier rank, in the given priority order — NEVER a
 * blended single score. Ties within all factors preserve original flow
 * order (stable sort).
 */
export function rankFlows(graph, opts = {}) {
  const factorOrder = opts.factorOrder ?? RANKING_FACTORS;
  const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  const scored = graph.flows.map((flow) => ({
    flow,
    ...scoreFlow(flow, graph, nodesById),
    factorOrderUsed: factorOrder,
  }));
  const rankOf = (scoredFlow, factor) => {
    const f = scoredFlow.factors[factor];
    return _TIER_RANK[factor]?.[f.tier] ?? 0;
  };
  return scored.sort((a, b) => {
    for (const factor of factorOrder) {
      const diff = rankOf(b, factor) - rankOf(a, factor);
      if (diff !== 0) return diff;
    }
    return 0;
  });
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/lineage/decision-story.test.js`.
Expected: all PASS.

- [ ] **Step 5: Wire the new test file into `test:lineage`, run the full scope, commit**

Add `test/lineage/decision-story.test.js` to the `test:lineage` script in
`scanner/package.json`. Run `npm run test:lineage` and confirm it passes
with the new file included (compare the total test count before/after to
confirm it was actually picked up, not silently skipped).

```bash
git add scanner/src/lineage/decision-story.js scanner/test/lineage/decision-story.test.js scanner/package.json
git commit -m "feat(lineage): DecisionStory contract + 9-factor ranking engine (M4 deliverable #7, FR-501)"
```

---

### Task 2: Chapter content generation

**Files:**
- Create: `scanner/src/lineage/export-briefing.js`
- Test: `scanner/test/lineage/export-briefing.test.js`

**Interfaces:**
- Consumes: `rankFlows(graph, opts)`, `RANKING_FACTORS` from Task 1's
  `decision-story.js`; the same Markdown-escaping helpers pattern as
  `export-privacy.js` (`_mdInline`/`_mdCell`/`_mdCode` — re-implement
  locally in this new file rather than importing across files, matching
  `export-privacy.js`'s own choice not to export them either; DO NOT
  skip escaping just because it's a "new" file — the exact BLOCKING-1
  bug class from the DPIA/RoPA sub-project applies here identically,
  since chapter 4 interpolates the same `flow.governanceRefs` operator
  prose).
- Produces: `emitDecisionStory(graph, opts)` — returns
  `{record: <DecisionStory>, markdown: <string>}`. `opts: {filter?,
  generatedAt?, audienceMode?}`. `audienceMode` one of `'board' |
  'ciso' | 'privacy' | 'compliance' | 'regulator' | 'technical'`
  (default `'technical'`).

**Design, grounded in Task 1's real output and the scoping doc:**

- Chapter 1 (scope/confidence): read directly off `graph.scope`,
  `graph.scanHealth`, `graph.coverage`, `graph.limitations` (all
  required top-level `DataFlowGraph v1` fields — read
  `scanner/src/lineage/dataflow-graph.schema.json`'s own top-level
  `required` list before writing this chapter, to get the exact field
  names right; do not guess).
- Chapter 2 (sensitive-data footprint): group `rankFlows`'s output by
  the `sensitivity` factor's tier, list dataClasses/stores/AI contexts —
  mirror `export-privacy.js#_groupRowsByClass`'s own
  never-silently-drop-a-flow discipline for a flow whose sensitivity
  tier is `'none'`.
- Chapter 3 (external exposure): filter to `externality.tier ===
  'external'`, list destinations/AI providers/unresolved destinations
  (`node.kind === 'unresolved'`).
- Chapter 4 (control/governance gaps): filter to
  `controlVerdict.tier !== 'protected'`, list raw-logging/unencrypted-
  transit/at-rest-unknown flows plus `flow.governanceRefs` gaps
  (`source === 'manual_required'`) and `policyState.tier !==
  'permitted'` conflicts.
- Chapter 5 (change and decisions): **NO "new/worsened flow" claims** —
  Task 1's `changeRecency` factor is always `unavailable`. Instead:
  (a) an explicit, prominent disclosure — "No historical baseline is
  available in this milestone; change-over-time claims require the
  Data-Flow Time Machine (not yet shipped)" — satisfying AC-25's
  "coverage limitations remain prominent" requirement rather than
  silently omitting a PRD-required chapter; (b) still-real,
  currently-decision-relevant content: every flow whose `policyState`
  tier is `manual_review_required` or `prohibited`, presented as
  "decisions needed now" (genuinely real today, not a change claim).
- Audience modes: a `_AUDIENCE_WORDING` lookup table controlling prose
  register only (e.g., Board mode: plain language, cap chapter 2's
  observation list at 7 items per FR-501's own "maximum of seven primary
  observations" requirement; Technical mode: full detail, no cap).
  Ranking/facts/order of chapters never change between modes — only
  which fields are shown and how verbosely.
- Every document includes `opts.generatedAt ?? graph.generatedAt`
  (never wall-clock — same `AGENTIC_SECURITY_DETERMINISTIC=1` test
  technique DPIA/RoPA's own Task 3 fix round established, reuse it for
  the regression test here) and `computeGraphDigest(graph)` from
  `export-json.js`, satisfying AC-25's "preserves graph digest."

**Tests to write** (mirror `export-privacy.test.js`'s own structure —
real graphs via `buildGraphWithCoverage`/`buildLineageGraph`, at least
one REAL CORPUS sweep test, and — copying BLOCKING-1's own regression
test verbatim in spirit — a test that a governance value containing `|`
and a newline does not corrupt any Markdown table this file emits):

- [ ] Write the failing tests (mirror the list above; do not skip the
  Markdown-escaping regression test — this is not optional given the
  BLOCKING-1 precedent).
- [ ] Run to verify failure.
- [ ] Write `export-briefing.js`.
- [ ] Run to verify pass.
- [ ] Wire into `test:lineage`, run the full scope, commit.

---

### Task 3: CLI wiring + audience modes

**Files:**
- Modify: `scanner/bin/agentic-security.js`
  (`DATAFLOW_EXPORT_FORMATS`, `cmdDataflowExport`)
- Modify: `commands/dataflow.md`
- Test: `scanner/test/cli/dataflow-export-briefing.test.js` (new,
  mirroring `test/cli/dataflow-export-privacy.test.js`'s own structure
  exactly — real end-to-end scan → export, not mocks)

**Design:**
- Add `'briefing'` to `DATAFLOW_EXPORT_FORMATS`; a new `else if (format
  === 'briefing')` branch calling `emitDecisionStory` (Task 2), inside
  the SAME try/catch `cmdDataflowExport` already has.
- New `--audience <mode>` CLI flag, validated against Task 2's own
  audience-mode enum before use (a clear exit-2 error on an unknown
  value, matching every other flag's own validation precedent in this
  file — e.g. the `--format`/`--filter` shape-validation blocks
  immediately above the existing format dispatch).
- `briefing` joins `dpia`/`ropa`/`csv` in the non-view-scoped,
  `--no-redact`-is-a-no-op set (warn + no-op, matching precedent
  exactly); `--filter` genuinely scopes it (threaded into
  `emitDecisionStory`'s own `opts.filter`, reusing `export-json.js`'s
  `_filterGraph` the SAME way `export-privacy.js` already does — read
  that file's own `_scopedViewModel` before writing this).
- `commands/dataflow.md`: add `briefing` to the format table,
  argument-hint, all no-op option lists, and a new `--audience` row in
  Options — mirror the DPIA/RoPA sub-project's own fix-round update to
  this same file exactly (it is the precedent for how a new format gets
  documented here).

- [ ] Write the failing CLI test(s).
- [ ] Run to verify failure.
- [ ] Wire the CLI.
- [ ] Run to verify pass.
- [ ] Update `commands/dataflow.md`.
- [ ] `npm run build`, confirm bundle sha256 regenerates, commit.

---

## Self-review notes (per the writing-plans skill, already applied above)

- **Spec coverage:** all 5 chapters and 9 ranking factors are accounted
  for in Task 1/2 (7 real, 1 new aggregation, 2 honestly unavailable —
  every one of the 9 named in the PRD appears somewhere above, none
  silently dropped).
- **Placeholder scan:** Task 1 ships complete, real code. Tasks 2/3 cite
  EXACT files/functions to mirror rather than inventing new patterns —
  this is a grounded specification, not a "TBD"; an implementer with
  Task 1's real output in hand and the cited files open has everything
  needed.
- **Type consistency:** `rankFlows`'s return shape
  (`{flow, flowId, factors, factorOrderUsed}`) is the exact shape Task
  2's chapter functions must consume — confirmed consistent between
  Task 1's code and Task 2's design section above.
- **Out-of-scope reminder for whoever picks up Task 2/3:** no interactive
  frontend Briefing view in this plan (see the scoping doc's own
  "Out of scope" section) — CLI/Markdown export only.
