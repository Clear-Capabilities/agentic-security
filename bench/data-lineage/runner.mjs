#!/usr/bin/env node
//
// bench/data-lineage/runner.mjs — Sub-project F, increment F1.
//
// Scores every fixture under bench/data-lineage/fixtures/ against its own
// expected.json, by building a real DataFlowGraph v1 document
// (buildGraphWithCoverage) from the fixture's source.js and checking that
// the graph correctly REPRESENTS the labeled flow — a shape-match, not the
// binary vulnerable/clean presence check bench/cve-replay/runner.mjs uses.
// See docs/superpowers/plans/2026-08-31-data-flow-explorer-m1-subproject-f-scoping.md
// §3 for why this corpus needs a different scorer, not a copy of cve-replay's.
//
// Milestone-2-deferred fields (expectedProtection) are recorded and printed,
// never asserted — graph.limitations already discloses that protection
// verdicts are not_assessed in Milestone 1; scoring them now would either
// always fail or force the corpus to lie about what's provable today.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseJsFile } from '../../scanner/src/ir/parser-js.js';
import { buildCallGraph } from '../../scanner/src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../scanner/src/lineage/coverage.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, 'fixtures');

/** Builds a deterministic DataFlowGraph v1 document from one fixture's source.js. */
export function buildFixtureGraph(fixtureId, sourceCode) {
  const perFile = { 'source.js': parseJsFile('source.js', sourceCode) };
  const callGraph = buildCallGraph(perFile);
  const { graph } = buildGraphWithCoverage(callGraph, {
    repository: fixtureId,
    generatedAt: '1970-01-01T00:00:00.000Z',
  });
  return graph;
}

/**
 * The shape-match scoring contract (scoping report §3). Never throws —
 * returns {pass, errors}, errors always populated when pass is false.
 */
export function scoreFixture(graph, expected) {
  const errors = [];
  const sourceNodes = graph.nodes.filter((n) => n.subtype === expected.sourceCategory);
  const sinkNodes = graph.nodes.filter((n) => n.subtype === expected.sinkCategory);
  if (sourceNodes.length === 0) errors.push(`no node with subtype '${expected.sourceCategory}' (source category)`);
  if (sinkNodes.length === 0) errors.push(`no node with subtype '${expected.sinkCategory}' (sink category)`);
  if (errors.length > 0) return { pass: false, errors };

  const sourceIds = new Set(sourceNodes.map((n) => n.id));
  const sinkIds = new Set(sinkNodes.map((n) => n.id));
  const dataElById = new Map(graph.dataElements.map((d) => [d.id, d]));
  const dataClasses = expected.dataClass ?? [];

  const matchingFlows = graph.flows.filter((f) =>
    sourceIds.has(f.source) && sinkIds.has(f.sink) &&
    f.dataElementIds.some((id) => {
      const de = dataElById.get(id);
      return de && (de.dataClasses ?? []).some((c) => dataClasses.includes(c));
    }));

  const expectConnected = expected.expectedConnected !== false; // default true

  if (!expectConnected) {
    if (matchingFlows.length > 0) {
      errors.push(`expected NO connecting flow (expectedConnected: false) but found ${matchingFlows.length}`);
    }
    // AC-11: a disconnected node must still be VISIBLE with a coverage
    // reason, never silently absent — assert this on every candidate sink
    // node (the one AC-11 actually cares about for this fixture shape).
    for (const n of sinkNodes) {
      if (!n.coverageReason) errors.push(`sink node ${n.id} (subtype ${n.subtype}) has no coverageReason — AC-11 requires a disconnected node to still disclose why`);
    }
    return { pass: errors.length === 0, errors };
  }

  if (matchingFlows.length === 0) {
    errors.push('expected a connecting flow (matching source/sink category AND a shared dataClass) but found none');
    return { pass: false, errors };
  }

  if (expected.expectedTransformKind) {
    const transformById = new Map(graph.transformations.map((t) => [t.id, t]));
    const hasKind = matchingFlows.some((f) =>
      f.transformationIds.some((tid) => transformById.get(tid)?.kind === expected.expectedTransformKind));
    if (!hasKind) errors.push(`expected a transformation of kind '${expected.expectedTransformKind}' on the matching flow, found none`);
  } else if (expected.expectedTransformKind === null) {
    const hasUntransformed = matchingFlows.some((f) => f.transformationIds.length === 0);
    if (!hasUntransformed) errors.push('expected an UNtransformed flow (expectedTransformKind: null) but every matching flow carries a transformation');
  }

  return { pass: errors.length === 0, errors };
}

function loadFixtures() {
  const ids = fs.readdirSync(FIXTURES_DIR).filter((f) => fs.statSync(path.join(FIXTURES_DIR, f)).isDirectory());
  return ids.sort().map((id) => {
    const dir = path.join(FIXTURES_DIR, id);
    const sourceFile = fs.readdirSync(dir).find((f) => f.startsWith('source.'));
    const source = fs.readFileSync(path.join(dir, sourceFile), 'utf8');
    const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
    return { id, source, expected, tier: expected.tier ?? 'regression' };
  });
}

async function main() {
  const args = process.argv.slice(2);
  const checkMode = args.includes('--check');

  let fixtures;
  try {
    fixtures = loadFixtures();
  } catch (e) {
    console.error(`bench/data-lineage: failed to load fixtures: ${e.message}`);
    process.exit(2);
  }
  if (fixtures.length === 0) {
    console.error('bench/data-lineage: no fixtures found under fixtures/ — nothing to check');
    process.exit(2);
  }

  let regressionFail = 0;
  let capabilityFail = 0;
  let pass = 0;

  for (const fx of fixtures) {
    let result;
    try {
      const graph = buildFixtureGraph(fx.id, fx.source);
      result = scoreFixture(graph, fx.expected);
    } catch (e) {
      result = { pass: false, errors: [`threw while building/scoring: ${e.message}`] };
    }
    if (result.pass) {
      pass++;
      console.log(`  ok  [${fx.tier}] ${fx.id}`);
    } else {
      if (fx.tier === 'regression') regressionFail++; else capabilityFail++;
      console.log(`FAIL  [${fx.tier}] ${fx.id}`);
      for (const err of result.errors) console.log(`        - ${err}`);
    }
  }

  console.log('');
  console.log(`bench/data-lineage: ${pass}/${fixtures.length} passed (${regressionFail} regression-tier failure(s), ${capabilityFail} capability-tier failure(s))`);

  if (checkMode && regressionFail > 0) {
    console.error(`bench/data-lineage: CHECK FAILED — ${regressionFail} regression-tier fixture(s) did not score correctly`);
    process.exit(1);
  }
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
