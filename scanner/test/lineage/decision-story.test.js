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

// Real PHI-to-AI-model-provider shape (proven throughout M4, same shape
// as bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi)
// — PHI is 'high' severity in DEFAULT_TAXONOMY, destination is a real
// ai-model-provider node (externality: unknown — FR-203's receiver signal
// fires on the `anthropic.messages` member-expression receiver, so the
// sink lands as kind:'unresolved' with an unresolved destination rather
// than a plain external one), giving every available factor a real,
// non-default value to assert against.
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

test('scoreFlow: a real PHI -> AI-model-provider flow scores sensitivity=high, externality=unknown (FR-203 unresolved receiver), aiUse=true', () => {
  const graph = _buildRealGraph(PHI_TO_AI_SOURCE);
  assert.ok(graph.flows.length >= 1, 'fixture assumption drifted: expected a real PHI->AI flow');
  const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  const flow = graph.flows[0];
  const scored = scoreFlow(flow, graph, nodesById);
  assert.equal(scored.factors.sensitivity.tier, 'high');
  assert.equal(scored.factors.sensitivity.available, true);
  // Measured against the real graph builder: `anthropic.messages.create`
  // is a member-expression receiver (not a plain identifier), so FR-203's
  // receiver signal fires and the sink node lands as kind:'unresolved'
  // with externality:'unknown' (destination not statically resolvable) —
  // not 'external' as an earlier draft of this test assumed. This is the
  // SAME shape bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi
  // uses, so it's real, current, disclosed behavior, not a fixture bug.
  assert.equal(scored.factors.externality.tier, 'unknown');
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
  // NOTE: `req.query.page` is used rather than the task brief's original
  // `params.query.page` — measured against the real catalog, `params.query`
  // matches no source entry at all (only `params.arguments.*` does, an MCP
  // tool-argument shape), so the original fixture produced only ONE flow,
  // not two, making this test's own premise false. `req.query` IS a real
  // catalog entry (js-req-query), and 'page' classifies to no dataClass,
  // giving the genuinely unclassified second flow this test needs.
  const MIXED_SOURCE = `
    function handle(anthropic, params, req, logger) {
      const patientRecord = params.arguments.patient_record;
      anthropic.messages.create({ model: 'claude-3', messages: [{ role: 'user', content: patientRecord }] });
      const page = req.query.page;
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
