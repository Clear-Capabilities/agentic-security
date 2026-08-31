// AC-01 proof (PRD §25: "Given req.body.card_number flows to a logger, a
// database column, and an external payment API, when the user selects PCI,
// then all three paths are highlighted and each sink shows its own
// handling, transit, or at-rest verdict") — one of Milestone 1's 4 exit-gate
// acceptance criteria (PRD §26, line 1796).
//
// Not authored as a bench/data-lineage/ corpus fixture: F1's `runner.mjs`
// scoring contract (docs/superpowers/plans/2026-08-31-data-flow-explorer-
// m1-subproject-f1.md §3) asserts exactly ONE sourceCategory/sinkCategory
// pair per fixture — it cannot express "one field reaches THREE distinct
// sinks in the same graph," which is AC-01's own defining shape. Extending
// that contract to a multi-sink form is real, undecided scope (its own
// design question — array-valued sinkCategory? a distinct assertion mode?)
// deliberately not improvised here; this file proves AC-01 directly against
// real `buildGraphWithCoverage` output instead, the same precedent AC-02's
// masked/raw distinction and AC-11's disconnected-node shape already
// established via direct unit tests (source-seeding.test.js's E2/6a/6b;
// graph-builder.js's own AC-11 header note) alongside their corpus fixtures.
//
// The per-sink "handling/transit/at-rest verdict" half of AC-01's own
// wording is Milestone 2's job (protection verdicts are unconditionally
// `not_assessed` in Milestone 1 — graph.limitations discloses this on every
// built graph) — this file proves the FLOW-MULTIPLICITY half only, which is
// everything Milestone 1's own exit gate can actually require.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { validateGraph } from '../../src/lineage/validate.js';

test('AC-01: req.body.card_number (PCI) reaches THREE distinct sinks — log, database, external-api — as three distinct, independently visible flows in one graph', () => {
  const source = `
    function handleCheckout(req, logger, db) {
      const cardNumber = req.body.card_number;
      logger.info('processing payment', cardNumber);
      const sql = \`SELECT * FROM cards WHERE number = '\${cardNumber}'\`;
      db.query(sql);
      fetch('https://payments.example/charge', { body: cardNumber });
    }
  `;
  const cg = buildCallGraph({ 'a.js': parseJsFile('a.js', source) });
  const { graph } = buildGraphWithCoverage(cg, { repository: 'ac01', generatedAt: '1970-01-01T00:00:00.000Z' });

  assert.deepEqual(validateGraph(graph).errors, [], 'AC-01 fixture must produce a schema-valid graph');

  const pciDataElements = graph.dataElements.filter((d) => (d.dataClasses ?? []).includes('PCI'));
  assert.ok(pciDataElements.length > 0, 'at least one dataElement must be classified PCI (card_number)');
  const pciIds = new Set(pciDataElements.map((d) => d.id));

  const pciFlows = graph.flows.filter((f) => f.dataElementIds.some((id) => pciIds.has(id)));
  assert.ok(pciFlows.length >= 3, `expected at least 3 PCI-carrying flows, found ${pciFlows.length}`);

  const sinkNodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  const reachedSinkCategories = new Set(
    pciFlows.map((f) => sinkNodesById.get(f.sink)?.subtype).filter(Boolean),
  );

  assert.ok(reachedSinkCategories.has('log'), `PCI must reach a 'log' sink — reached: ${[...reachedSinkCategories]}`);
  assert.ok(reachedSinkCategories.has('database'), `PCI must reach a 'database' sink — reached: ${[...reachedSinkCategories]}`);
  assert.ok(reachedSinkCategories.has('external-api'), `PCI must reach an 'external-api' sink — reached: ${[...reachedSinkCategories]}`);
  assert.equal(reachedSinkCategories.size, 3, 'exactly 3 distinct sink categories, matching AC-01\'s own worked example — not fewer (a missed sink) and not more (an unintended extra match)');

  // AC-01's own "each sink shows its own... verdict" clause — the Milestone
  // 2 half. Proven here as an honest ABSENCE, not asserted as a real
  // verdict: every flow must carry the disclosed not_assessed placeholder,
  // never a fabricated one.
  for (const f of pciFlows) {
    assert.equal(f.protectionSummary, 'not_assessed', 'protection verdicts are honestly not_assessed in Milestone 1 — never a guessed value');
  }
});
