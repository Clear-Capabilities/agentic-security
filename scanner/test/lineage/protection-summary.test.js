//
// protection-summary.test.js — Milestone 2, Sub-project I, increment 1.
//
// Proves `flow.protectionSummary` (PRD line 909: "the end-to-end summary
// may be protected/unprotected/mixed/unknown/not_assessed... must be
// derived from the individual edge verdicts, never stored as an
// unsupported independent claim") — previously a hardcoded 'not_assessed'
// literal at every flow's mint site, now computed via protection.js's
// aggregateVerdicts() over the flow's own edge's three dimensions
// (transit/atRest/handling), per
// docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-i1-plan.md.
//
// AC-12's own worked example ("one branch encrypts a field and another
// branch reaches the same store without encryption") is proven here as
// TWO SIBLING FLOWS, each correctly reading its own honest
// protectionSummary — this increment does not invent a cross-branch
// aggregate field; the per-flow honesty proven here is the real,
// achievable slice of AC-12's property (see the scoping/plan docs for
// the full reasoning on why a coarse-group aggregate is out of scope).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { scanTransitEvidence } from '../../src/lineage/transit-protection.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { FLOW_SUMMARY_VALUES } from '../../src/lineage/schema.js';
import { PROTECTION_VERDICTS } from '../../src/lineage/protection.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

function build(files, opts = {}) {
  const cg = irOf(files);
  const { graph } = buildGraphWithCoverage(cg, {
    repository: 'r', generatedAt: '2026-08-31T00:00:00.000Z',
    transitEvidenceByFile: scanTransitEvidence(files),
    ...opts,
  });
  const v = validateGraph(graph);
  assert.deepEqual(v.errors, []);
  assert.equal(v.valid, true);
  return graph;
}

test('I1/1: a real protected transit verdict flows into flow.protectionSummary', () => {
  const graph = build({
    'a.js': `
      function h(req) {
        const cardNumber = req.body.card_number;
        fetch("https://payments.example/charge", { method: 'POST', body: cardNumber });
      }
    `,
  });
  assert.equal(graph.flows.length, 1);
  assert.equal(graph.flows[0].protectionSummary, 'protected');
});

test('I1/2: a real unprotected transit verdict (http://) flows into flow.protectionSummary', () => {
  const graph = build({
    'a.js': `
      function h(req) {
        const cardNumber = req.body.card_number;
        fetch("http://payments.example/charge", { method: 'POST', body: cardNumber });
      }
    `,
  });
  assert.equal(graph.flows.length, 1);
  assert.equal(graph.flows[0].protectionSummary, 'unprotected');
});

test('I1/3: no evidence on any dimension — protectionSummary stays the honest not_assessed default', () => {
  const graph = build({
    'a.js': `
      function h(req, logger) {
        const cardNumber = req.body.card_number;
        logger.info('processing', cardNumber);
      }
    `,
  });
  assert.equal(graph.flows.length, 1);
  assert.equal(graph.flows[0].protectionSummary, 'not_assessed');
});

test('I1/4 (AC-12): two sibling flows to the same store, one encrypted one not — each flow honestly reports its OWN protectionSummary, never a shared false-positive', () => {
  const graph = build({
    'a.js': `
      function handleCheckout(req, db) {
        const cardNumber = req.body.card_number;
        const encryptedPan = crypto.createCipheriv('aes-256-gcm', key, iv).update(cardNumber);
        db.query('INSERT INTO cards_encrypted (pan) VALUES (?)', [encryptedPan]);
        db.query('INSERT INTO cards_raw (pan) VALUES (?)', [cardNumber]);
      }
    `,
  });
  const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  const storeFlows = graph.flows.filter((f) => nodesById.get(f.sink)?.kind === 'store');
  assert.equal(storeFlows.length, 2, 'sanity: two distinct store-bound flows must exist');
  const summaries = storeFlows.map((f) => f.protectionSummary);
  assert.ok(summaries.includes('protected'), 'the encrypted branch must read protected');
  assert.ok(summaries.includes('not_assessed'), 'the unencrypted branch must NOT read protected — a transform on one branch cannot make the sibling flow green (AC-12)');
});

test('I1/5: the three verdict values real producers can actually emit today are all valid FLOW_SUMMARY_VALUES members', () => {
  // NOT a claim that every PROTECTION_VERDICTS member is a valid
  // FLOW_SUMMARY_VALUES member — it is not: 'not_applicable' is a real
  // PROTECTION_VERDICTS value with no FLOW_SUMMARY_VALUES counterpart,
  // confirmed directly (this was this test's own first-draft assumption,
  // corrected after it failed against the real enums). No producer in
  // this codebase ever sets a dimension's verdict to 'not_applicable'
  // today (transit-protection.js and the inline atRest block only ever
  // emit 'protected'/'unprotected'; emptyProtection()'s own default is
  // 'not_assessed') — so aggregateVerdicts, fed only real dimension
  // verdicts, can never actually produce it. If a FUTURE analyzer ever
  // emits 'not_applicable' on a real edge, `flow.protectionSummary`
  // could fail validateGraph — a disclosed, currently-inert fragility,
  // named in the I1 code comment in graph-builder.js too, not silently
  // relied upon.
  for (const v of ['protected', 'unprotected', 'not_assessed']) {
    assert.ok(PROTECTION_VERDICTS.includes(v) && FLOW_SUMMARY_VALUES.includes(v));
  }
  const graph = build({
    'a.js': `
      function h(req) {
        const cardNumber = req.body.card_number;
        fetch("https://payments.example/charge", { method: 'POST', body: cardNumber });
      }
    `,
  });
  assert.ok(FLOW_SUMMARY_VALUES.includes(graph.flows[0].protectionSummary));
});
