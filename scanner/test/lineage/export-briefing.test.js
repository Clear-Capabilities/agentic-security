// export-briefing.test.js — M4 deliverable #7 (FR-501 §14, DFG-035), Task 2:
// emitDecisionStory's 5-chapter Executive Risk Story generation.
//
// Mirrors export-privacy.test.js's own structure (real graphs via
// buildGraphWithCoverage/buildLineageGraph, a REAL CORPUS sweep test, and —
// copying its own BLOCKING-1 regression test verbatim in spirit — a test
// that a governance value containing a literal "|" and an embedded newline
// does not corrupt any Markdown table this file emits).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { RANKING_FACTORS, validateDecisionStory } from '../../src/lineage/decision-story.js';
import { computeGraphDigest } from '../../src/lineage/export-json.js';
import { AUDIENCE_MODES, emitDecisionStory } from '../../src/lineage/export-briefing.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function _mkScanRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'export-briefing-'));
}

function _writeGovernanceConfig(scanRoot, config) {
  fs.mkdirSync(path.join(scanRoot, '.agentic-security'), { recursive: true });
  fs.writeFileSync(
    path.join(scanRoot, '.agentic-security', 'privacy-governance.json'),
    JSON.stringify(config),
  );
}

function _buildRealGraph(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  const { graph } = buildGraphWithCoverage(callGraph, { repository: 'test-repo', generatedAt: '1970-01-01T00:00:00.000Z', ...opts });
  assert.deepEqual(validateGraph(graph).errors, [], 'test fixture must produce a schema-valid graph');
  return graph;
}

function _buildRealGraphViaScan(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  const r = buildLineageGraph(callGraph, { repository: 'test-repo', deterministic: true, generatedAt: '1970-01-01T00:00:00.000Z', ...opts });
  assert.equal(r.status, 'complete', `buildLineageGraph did not complete: ${JSON.stringify(r.failure)}`);
  return r.graph;
}

function _emptyGraph() {
  return _buildRealGraph('function noop() { return 1 + 1; }');
}

// AC-01's own real fixture (test/lineage/ac01-multi-sink.test.js): PCI
// card_number reaching a log sink (raw, internal, not_assessed), a
// database sink (internal-ish/unknown externality, atRest not_assessed —
// no encrypt call anywhere), and an external-api sink over a literal
// https:// url (external, transit protected). One field, three
// independently-observable flows with three genuinely different
// sensitivity/externality/control shapes — enough to exercise every
// chapter's real content in one fixture.
const MULTI_SINK_SOURCE = `
  function handleCheckout(req, logger, db) {
    const cardNumber = req.body.card_number;
    logger.info('processing payment', cardNumber);
    const sql = \`SELECT * FROM cards WHERE number = '\${cardNumber}'\`;
    db.query(sql);
    fetch('https://payments.example/charge', { method: 'POST', body: cardNumber });
  }
`;

// Same shape, but the external call is a literal http:// URL — real,
// measured transit-unprotected evidence (transit-protection.test.js's own
// AC-03 fixture), giving chapter 4's "unencrypted transit" bucket a real
// case to fire on.
const HTTP_INSECURE_SOURCE = `
  function handleCheckout(req) {
    const cardNumber = req.body.card_number;
    fetch('http://payments.example/charge', { method: 'POST', body: cardNumber });
  }
`;

// Real PHI -> AI-model-provider shape (decision-story.test.js's own
// fixture) — PHI is 'high' severity, the sink lands as kind:'unresolved'
// (FR-203's receiver signal fires on the member-expression receiver).
const PHI_TO_AI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

test('AUDIENCE_MODES lists exactly the 6 brief-specified modes', () => {
  assert.deepEqual([...AUDIENCE_MODES].sort(), ['board', 'ciso', 'compliance', 'privacy', 'regulator', 'technical']);
});

test('emitDecisionStory: an unrecognized audienceMode throws rather than silently misrendering', () => {
  const graph = _emptyGraph();
  assert.throws(() => emitDecisionStory(graph, { audienceMode: 'nope' }), /unrecognized audienceMode/);
});

test('emitDecisionStory: default audienceMode is technical', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const { record } = emitDecisionStory(graph, {});
  assert.equal(record.audienceMode, 'technical');
});

test('emitDecisionStory: produces a valid DecisionStory record with all 5 chapters, in order, over a real multi-sink graph', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  assert.ok(graph.flows.length >= 3, 'fixture assumption drifted: expected at least 3 real PCI flows');

  const { record, markdown } = emitDecisionStory(graph, {});
  const { valid, errors } = validateDecisionStory(record);
  assert.deepEqual(errors, []);
  assert.equal(valid, true);

  assert.equal(record.chapters.length, 5);
  assert.deepEqual(record.chapters.map((c) => c.number), [1, 2, 3, 4, 5]);
  assert.deepEqual(record.chapters.map((c) => c.id), [
    'scope-confidence', 'sensitive-footprint', 'external-exposure', 'control-governance-gaps', 'change-and-decisions',
  ]);
  for (const c of record.chapters) assert.ok(c.markdown.length > 0, `chapter ${c.id} must have real content`);

  assert.deepEqual(record.rankingFactors, RANKING_FACTORS);
  assert.equal(record.graphDigest, computeGraphDigest(graph));
  assert.equal(record.generatedAt, graph.generatedAt);
  assert.deepEqual(record.contributingGraphIds, [graph.graphId]);

  assert.match(markdown, /# Executive Risk Story/);
  assert.match(markdown, /## Chapter 1: Scope & Confidence/);
  assert.match(markdown, /## Chapter 2: Sensitive-Data Footprint/);
  assert.match(markdown, /## Chapter 3: External Exposure/);
  assert.match(markdown, /## Chapter 4: Control & Governance Gaps/);
  assert.match(markdown, /## Chapter 5: Change & Decisions Needed/);
});

test('Chapter 1 reads real scope/scanHealth/coverage/limitations fields off the graph', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const { record } = emitDecisionStory(graph, {});
  const ch1 = record.chapters[0];
  assert.equal(ch1.id, 'scope-confidence');
  assert.match(ch1.markdown, new RegExp(graph.scope.source));
  assert.match(ch1.markdown, new RegExp(graph.scanHealth.status));
  assert.match(ch1.markdown, /Sources matched: \d+/);
  assert.match(ch1.markdown, /Sink call sites: \d+/);
  assert.ok(graph.limitations.length > 0, 'fixture assumption drifted: expected real graph.limitations content');
  for (const l of graph.limitations) assert.ok(ch1.markdown.includes(l), `chapter 1 must disclose limitation: ${l}`);
  assert.match(ch1.markdown, /recipientJurisdiction/);
  assert.match(ch1.markdown, /changeRecency/);
});

test('Chapter 2 groups real flows by sensitivity tier, never silently drops a "none"-tier flow', () => {
  // req.query.page classifies to no dataClass at all (sensitivity tier
  // 'none') alongside a real PCI flow (sensitivity tier 'high') reaching
  // the same log sink — mirrors export-privacy.test.js's own MIXED_CLASS
  // precedent for proving an unclassified flow is disclosed, not dropped.
  const MIXED_SOURCE = `
    function handle(req, logger) {
      const cardNumber = req.body.card_number;
      logger.info('processing payment', cardNumber);
      const page = req.query.page;
      logger.info('listing page', page);
    }
  `;
  const graph = _buildRealGraph(MIXED_SOURCE);
  assert.equal(graph.flows.length, 2, 'fixture assumption drifted: expected one PCI flow + one unclassified flow');
  const { record } = emitDecisionStory(graph, {});
  const ch2 = record.chapters[1];
  assert.match(ch2.markdown, /### High \(1 flow\(s\)\)/);
  assert.match(ch2.markdown, /### None \/ unclassified \(1 flow\(s\)\)/);
  assert.equal(ch2.itemCount, 2, 'both flows — including the none-tier one — must be counted, never silently dropped');
});

test('Chapter 3 filters to externality.tier === "external" and reports the real destination', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const { record } = emitDecisionStory(graph, { audienceMode: 'technical' });
  const ch3 = record.chapters[2];
  assert.match(ch3.markdown, /1 flow\(s\) reach an external or unresolved destination — 1 resolved external, 0 destination not statically resolved\./);
  // Node labels are registry-decision-derived, not per-call-site domain
  // names (DESIGN_GRAPH_BUILDER.md §6.1 — node identity is bounded by the
  // taxonomy, not by repository/call-site content), so the real sink
  // node's own label is the generic 'external-api (external)' form, not
  // the literal 'payments.example' URL.
  const sinkNode = graph.nodes.find((n) => n.subtype === 'external-api');
  assert.ok(sinkNode, 'fixture assumption drifted: expected a real external-api node');
  assert.ok(ch3.markdown.includes(sinkNode.label), 'chapter 3 must name the real sink node label');
  // Verbose (technical) mode renders the per-flow table.
  assert.match(ch3.markdown, /\| Data element \| Destination \| Externality \| Sensitivity \| Control \|/);
});

test('Chapter 3: a graph with no external flows reports the honest zero, never a crash', () => {
  const graph = _buildRealGraph('function h(req, logger) { logger.info("x", req.body.name); }');
  const { record } = emitDecisionStory(graph, {});
  const ch3 = record.chapters[2];
  assert.match(ch3.markdown, /No flows in this graph scope reach an external or unresolved destination\./);
  assert.equal(ch3.itemCount, 0);
});

// Final whole-branch review, BLOCKING-3 (fixed): FR-203's unresolved-
// destination path sets externality:'unknown' (never 'external') on the
// same object as kind:'unresolved' — Chapter 3 originally filtered on
// 'external' alone, silently dropping every unresolved-destination flow,
// including every real AI-provider flow in this JS catalog (every AI SDK
// entry is a member-chain receiver that always triggers FR-203).
test('Chapter 3: an unresolved-destination flow (externality "unknown") is included, not silently dropped, and AI providers among them are named', () => {
  const graph = _buildRealGraph(PHI_TO_AI_SOURCE);
  const flow = graph.flows[0];
  assert.ok(flow, 'fixture assumption drifted: expected a real flow');
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
  assert.equal(sinkNode.kind, 'unresolved', 'fixture assumption drifted: expected FR-203 to fire on this AI SDK receiver');
  assert.equal(sinkNode.externality.value, 'unknown', 'fixture assumption drifted: expected externality unknown, not external');

  const { record } = emitDecisionStory(graph, {});
  const ch3 = record.chapters[2];
  assert.equal(ch3.itemCount, 1, 'the unresolved flow must be counted in Chapter 3, not dropped');
  assert.match(ch3.markdown, /destination not statically resolved/i);
  assert.match(ch3.markdown, /AI providers\/agents\/tools among them/);
  assert.ok(ch3.markdown.includes(sinkNode.label), 'chapter 3 must name the real unresolved sink node');
});

test('Chapter 4: raw-logging and at-rest-unknown gap categories fire on the real multi-sink graph, the protected https flow does not appear', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const { record } = emitDecisionStory(graph, {});
  const ch4 = record.chapters[3];
  assert.match(ch4.markdown, /Raw data reaching a log sink \(1\):/);
  assert.match(ch4.markdown, /at-rest protection unknown/);
  // The https:// external-api flow is real transit-protected evidence
  // (AC-03/AC-01) — its own protectionSummary is 'protected', so it must
  // NOT be counted among the gap flows this chapter lists.
  const externalFlow = graph.flows.find((f) => {
    const snk = graph.nodes.find((n) => n.id === f.sink);
    return snk?.subtype === 'external-api';
  });
  assert.ok(externalFlow, 'fixture assumption drifted: expected a real external-api flow');
  assert.equal(externalFlow.protectionSummary, 'protected');
});

test('Chapter 4: unencrypted-transit gap fires on a real literal http:// destination', () => {
  const graph = _buildRealGraph(HTTP_INSECURE_SOURCE);
  const flow = graph.flows[0];
  assert.ok(flow, 'fixture assumption drifted: expected a real flow');
  const edge = graph.edges.find((e) => flow.edgeIds.includes(e.id));
  assert.equal(edge.protection.transit.verdict, 'unprotected', 'fixture assumption drifted: expected real unprotected transit evidence');
  const { record } = emitDecisionStory(graph, {});
  const ch4 = record.chapters[3];
  assert.match(ch4.markdown, /Flows with unencrypted transit \(1\):/);
});

test('Chapter 4: a real, unconfigured governance gap is disclosed in a table, escaped, never fabricated', () => {
  const graph = _buildRealGraphViaScan(PHI_TO_AI_SOURCE, { scanRoot: _mkScanRoot() });
  const { record } = emitDecisionStory(graph, {});
  const ch4 = record.chapters[3];
  assert.match(ch4.markdown, /Flows with governance fields requiring manual input \(\d+\):/);
  assert.match(ch4.markdown, /\| Data element \| Destination \| Missing fields \| Provided values \|/);
  assert.match(ch4.markdown, /purpose/);
});

test('Chapter 4: policyState !== permitted conflicts are disclosed with a plain-language label in board mode, raw enum in technical mode', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const board = emitDecisionStory(graph, { audienceMode: 'board' }).record.chapters[3];
  const technical = emitDecisionStory(graph, { audienceMode: 'technical' }).record.chapters[3];
  assert.match(board.markdown, /needs manual review|prohibited by policy|not yet evaluated against policy|conditionally permitted/);
  assert.doesNotMatch(board.markdown, /`not_evaluated`/);
  assert.match(technical.markdown, /`not_evaluated`/);
});

test('Chapter 5: the "no historical baseline" disclosure is always present and prominent, never a new/worsened-flow claim', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const { record } = emitDecisionStory(graph, {});
  const ch5 = record.chapters[4];
  assert.match(ch5.markdown, /No historical baseline is available in this milestone/);
  assert.match(ch5.markdown, /Data-Flow Time Machine/);
  assert.doesNotMatch(ch5.markdown, /\bnew flow\b/i);
  assert.doesNotMatch(ch5.markdown, /\bworsened\b/i);
});

test('Chapter 5: a real "prohibited" policy verdict surfaces as a decision needed now, and lands on record.decisions', () => {
  const perFile = { 'a.js': parseJsFile('a.js', `
    function track(req, analytics) {
      const email = req.body.email;
      analytics.track('signup', { email });
    }
  `) };
  const callGraph = buildCallGraph(perFile);
  // A policy present but with an empty allow list — deny-by-default,
  // real 'prohibited' verdict (policy-verdict.test.js's own G1/3 case).
  const { graph } = buildGraphWithCoverage(callGraph, {
    repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', privacySinkPolicy: { allow: [] },
  });
  const flow = graph.flows.find((f) => f.policyVerdict === 'prohibited');
  assert.ok(flow, 'fixture assumption drifted: expected a real prohibited flow');

  const { record } = emitDecisionStory(graph, {});
  const ch5 = record.chapters[4];
  assert.match(ch5.markdown, /Decisions needed now \(\d+\):/);
  assert.ok(record.decisions.length >= 1);
  const d = record.decisions.find((x) => x.flowId === flow.id);
  assert.ok(d, 'the real prohibited flow must appear in record.decisions');
  assert.equal(d.policyVerdict, 'prohibited');
});

test('Board mode caps Chapter 2\'s observation list at 7 items (FR-501\'s own "maximum of seven primary observations"), technical mode shows every item', () => {
  const lines = [];
  for (let i = 0; i < 10; i++) {
    lines.push(`logger${i}.info('processing payment', req.body.card_number_${i});`);
  }
  const source = `
    function handleCheckout(req, ${Array.from({ length: 10 }, (_, i) => `logger${i}`).join(', ')}) {
      ${lines.join('\n')}
    }
  `;
  const graph = _buildRealGraph(source);
  assert.ok(graph.flows.length >= 10, `fixture assumption drifted: expected >=10 real flows, got ${graph.flows.length}`);

  const board = emitDecisionStory(graph, { audienceMode: 'board' }).record.chapters[1];
  const technical = emitDecisionStory(graph, { audienceMode: 'technical' }).record.chapters[1];

  assert.ok(board.itemCount <= 7, `board mode must cap at 7 observations, got ${board.itemCount}`);
  assert.match(board.markdown, /capped at 7 primary observations/);
  assert.equal(technical.itemCount, graph.flows.length, 'technical mode must show every flow, no cap');
  assert.doesNotMatch(technical.markdown, /capped at/);
});

test('an empty graph (no flows) produces an honest "nothing to report" message in every flow-dependent chapter, never a crash', () => {
  const graph = _emptyGraph();
  assert.equal(graph.flows.length, 0, 'test setup must genuinely produce zero flows');

  const { record, markdown } = emitDecisionStory(graph, {});
  assert.doesNotThrow(() => validateDecisionStory(record));
  assert.equal(validateDecisionStory(record).valid, true);

  assert.match(record.chapters[1].markdown, /No flows were identified in this graph scope/);
  assert.match(record.chapters[2].markdown, /No flows in this graph scope reach an external or unresolved destination/);
  assert.match(record.chapters[3].markdown, /No control or governance gaps were identified/);
  assert.match(record.chapters[4].markdown, /No flows currently require a manual policy decision/);
  assert.equal(record.evidenceGrade, 'none');
  assert.deepEqual(record.decisions, []);
  assert.ok(markdown.length > 0);
});

// Final whole-branch review of export-privacy.js, BLOCKING-1 (fixed there):
// an unescaped "|" or embedded newline in an operator-supplied governance
// value corrupted a Markdown table's own column alignment and could inject
// arbitrary Markdown (a fake heading) into the document. Reproduced here,
// verbatim in spirit, against THIS file's own governance-gap table
// (Chapter 4) — the one place this module interpolates the same
// flow.governanceRefs operator prose DPIA/RoPA does.
test('Chapter 4: a governance value containing a literal "|" and an embedded newline does not corrupt the governance-gap table', () => {
  const scanRoot = _mkScanRoot();
  try {
    _writeGovernanceConfig(scanRoot, {
      byClass: {
        PHI: {
          purpose: 'Clinical summarization | for internal review',
          subject: 'Row A\n## INJECTED HEADING\nRow B',
        },
      },
    });
    const graph = _buildRealGraphViaScan(PHI_TO_AI_SOURCE, { scanRoot });
    assert.ok(graph.flows.length >= 1, 'fixture assumption drifted: expected at least one real PHI flow');

    const { record } = emitDecisionStory(graph, {});
    const ch4 = record.chapters[3];
    const lines = ch4.markdown.split('\n');
    const headerIdx = lines.findIndex((l) => l.startsWith('| Data element | Destination | Missing fields | Provided values |'));
    assert.ok(headerIdx >= 0, 'the governance-gap table header must be present');
    const headerCellCount = lines[headerIdx].split(' | ').length;
    let i = headerIdx + 2;
    let dataRowsChecked = 0;
    while (i < lines.length && lines[i].startsWith('|')) {
      const cellCount = lines[i].split(' | ').length;
      assert.equal(cellCount, headerCellCount, `row ${i} column count drifted — a "|"-containing value broke the table: ${JSON.stringify(lines[i])}`);
      dataRowsChecked++;
      i++;
    }
    assert.ok(dataRowsChecked > 0, 'test setup must produce at least one real data row');

    // The escaped pipe survives as literal text (never silently dropped),
    // and the embedded newline was collapsed rather than injecting a real
    // Markdown heading mid-table.
    assert.match(ch4.markdown, /Clinical summarization \\\| for internal review/);
    assert.doesNotMatch(ch4.markdown, /^## INJECTED HEADING$/m);
    assert.match(ch4.markdown, /Row A ## INJECTED HEADING Row B/);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('emitDecisionStory: opts.filter genuinely narrows the graph (via export-json.js\'s own _filterGraph) before ranking, but the digest always identifies the source graph', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  assert.ok(graph.flows.length >= 3, 'fixture assumption drifted');

  const unfiltered = emitDecisionStory(graph, {});
  const targetFlow = graph.flows[0];
  const filter = { nodeIds: [targetFlow.source, targetFlow.sink], edgeIds: [...targetFlow.edgeIds] };
  const filtered = emitDecisionStory(graph, { filter });

  assert.notEqual(filtered.markdown, unfiltered.markdown, 'filtered output must genuinely differ');
  // Mirrors export-json.js's own established rule: the digest always
  // identifies the SOURCE graph, never the filtered view.
  assert.equal(filtered.record.graphDigest, unfiltered.record.graphDigest);
  assert.equal(filtered.record.graphDigest, computeGraphDigest(graph));
  assert.deepEqual(filtered.record.scopeQuery, { filter });
});

// Final whole-branch review, BLOCKING-2 (fixed): Chapter 4 used to bucket
// EVERY non-'permitted' policyVerdict — including 'not_evaluated', the
// default with no privacy-policy.json on disk — under "policy conflict
// (not permitted)", an unsupported compliance claim (AC-25), and directly
// contradicting Chapter 5's own correct "no decision needed" treatment of
// the SAME not_evaluated flows.
test('Chapter 4: an unconfigured-policy (not_evaluated) flow is honestly labeled "not yet evaluated", never "policy conflict", and never contradicts Chapter 5', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const flow = graph.flows.find((f) => f.policyVerdict === 'not_evaluated');
  assert.ok(flow, 'fixture assumption drifted: expected a real not_evaluated flow (no policy configured)');

  const { record } = emitDecisionStory(graph, {});
  const ch4 = record.chapters[3];
  const ch5 = record.chapters[4];

  assert.match(ch4.markdown, /Flows not yet evaluated against policy \(no policy configured for this scan\)/);
  assert.doesNotMatch(ch4.markdown, /policy conflict/i);
  // Chapter 5 must not claim a decision is needed for this same flow.
  assert.equal(ch5.markdown.includes('Decisions needed now'), false, 'a not_evaluated-only graph must not claim any decision is needed in Chapter 5');
  assert.match(ch5.markdown, /No flows currently require a manual policy decision/);
});

test('Chapter 4: a real "prohibited" verdict is labeled "policy conflict", a real "manual_review_required" verdict is labeled "requiring manual policy review" — distinctly, never collapsed together', () => {
  const perFile = { 'a.js': parseJsFile('a.js', `
    function track(req, analytics) {
      const email = req.body.email;
      analytics.track('signup', { email });
    }
  `) };
  const callGraph = buildCallGraph(perFile);
  const { graph } = buildGraphWithCoverage(callGraph, {
    repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', privacySinkPolicy: { allow: [] },
  });
  const flow = graph.flows.find((f) => f.policyVerdict === 'prohibited');
  assert.ok(flow, 'fixture assumption drifted: expected a real prohibited flow');

  const { record } = emitDecisionStory(graph, {});
  const ch4 = record.chapters[3];
  assert.match(ch4.markdown, /Flows prohibited or conditionally permitted by policy/);
  assert.doesNotMatch(ch4.markdown, /Flows requiring manual policy review \(\d+\)/, 'no manual_review_required flow in this fixture — that section must not render');
});

// Final whole-branch review, RECOMMENDED-1 (fixed): --filter narrows every
// chapter's own flow content, but Chapter 1's coverage block read the
// UNFILTERED graph.coverage with no disclosure a filter was applied.
test('Chapter 1 discloses when a filter was applied, and stays silent about it when none was', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const targetFlow = graph.flows[0];
  const filter = { nodeIds: [targetFlow.source, targetFlow.sink], edgeIds: [...targetFlow.edgeIds] };

  const filtered = emitDecisionStory(graph, { filter });
  assert.match(filtered.record.chapters[0].markdown, /scoped to a filtered subset of the graph/);

  const unfiltered = emitDecisionStory(graph, {});
  assert.doesNotMatch(unfiltered.record.chapters[0].markdown, /scoped to a filtered subset of the graph/);
});

// Final whole-branch review, RECOMMENDED-4 (fixed): the PRD's own
// "transparent CONFIGURABLE factors" requirement was unreachable —
// rankFlows accepted opts.factorOrder, but emitDecisionStory never
// threaded it through, so nothing external could reach it.
test('emitDecisionStory: opts.factorOrder overrides the default ranking priority and genuinely changes flow order', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const defaultOrder = emitDecisionStory(graph, { audienceMode: 'technical' });
  const reversedOrder = emitDecisionStory(graph, { audienceMode: 'technical', factorOrder: [...RANKING_FACTORS].reverse() });
  assert.notEqual(defaultOrder.markdown, reversedOrder.markdown, 'a genuinely different factorOrder must change the rendered document');
});

test('emitDecisionStory: opts.generatedAt overrides graph.generatedAt; with neither, falls back to graph.generatedAt, never wall-clock', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const overridden = emitDecisionStory(graph, { generatedAt: '2020-01-01T00:00:00.000Z' });
  assert.equal(overridden.record.generatedAt, '2020-01-01T00:00:00.000Z');

  const fallback = emitDecisionStory(graph, {});
  assert.equal(fallback.record.generatedAt, graph.generatedAt);
});

test('emitDecisionStory is deterministic: two calls over the same graph and opts produce byte-identical output', () => {
  const graph = _buildRealGraph(MULTI_SINK_SOURCE);
  const a = emitDecisionStory(graph, { audienceMode: 'ciso' });
  const b = emitDecisionStory(graph, { audienceMode: 'ciso' });
  assert.deepEqual(a.record, b.record);
  assert.equal(a.markdown, b.markdown);
});

test('REAL CORPUS: sweeping bench/data-lineage/ fixtures never throws emitting the briefing, across every audience mode, and every record validates', async () => {
  const { buildFixtureGraph } = await import('../../../bench/data-lineage/runner.mjs');
  const FIXTURES_ROOT = path.join(__dirname, '../../../bench/data-lineage/fixtures');
  const fixtureIds = fs.readdirSync(FIXTURES_ROOT).filter((f) => fs.statSync(path.join(FIXTURES_ROOT, f)).isDirectory());
  assert.ok(fixtureIds.length > 0);

  let graphsChecked = 0;
  for (const fixtureId of fixtureIds) {
    const srcPath = path.join(FIXTURES_ROOT, fixtureId, 'source.js');
    if (!fs.existsSync(srcPath)) continue;
    const source = fs.readFileSync(srcPath, 'utf8');
    const graph = buildFixtureGraph(fixtureId, source);

    for (const audienceMode of AUDIENCE_MODES) {
      let result;
      assert.doesNotThrow(() => { result = emitDecisionStory(graph, { audienceMode }); }, `${fixtureId}/${audienceMode}: emitDecisionStory threw`);
      const { valid, errors } = validateDecisionStory(result.record);
      assert.equal(valid, true, `${fixtureId}/${audienceMode}: produced an invalid DecisionStory record: ${JSON.stringify(errors)}`);
    }
    graphsChecked++;
  }
  assert.ok(graphsChecked > 0, 'the sweep must exercise at least one real fixture, or this test is vacuous');
});
