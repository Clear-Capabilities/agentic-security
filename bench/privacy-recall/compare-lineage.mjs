#!/usr/bin/env node
// Sub-project G, increment G1 (Data Flow Explorer PRD, Milestone 1 exit-gate
// closure plan) — measures, side by side, how the OLD privacy-taint engine
// (dataflow/privacy-taint.js, classifies by DECLARED VARIABLE NAME) and the
// NEW lineage engine (src/lineage/, classifies by the SOURCE EXPRESSION'S
// OWN field name) each score the same 4 real fixtures under
// bench/privacy-recall/fixtures/. This is a disclosed, deliberate asymmetry
// between the two engines, not a bug in either — see
// docs/lineage/PRIVACY_COMPARISON.md for the full write-up this script's
// numbers feed.
//
// Reuses measure() from ./measure.mjs verbatim for the old-engine
// (shallow/deep) counts — does not reimplement that logic. Adds
// measureLineage() for the new engine: parse -> call graph ->
// buildGraphWithCoverage -> count dataElements with a non-empty
// dataClasses array.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { measure } from './measure.mjs';
import { parseJsFile } from '../../scanner/src/ir/parser-js.js';
import { buildCallGraph } from '../../scanner/src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../scanner/src/lineage/coverage.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(HERE, 'fixtures');

function listFixtures() {
  return fs.readdirSync(FIXTURES_DIR, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

/**
 * Runs the new lineage engine over one fixture's app.js and counts
 * `graph.dataElements` entries with a non-empty `dataClasses` array — the
 * lineage engine's own "classified as sensitive" signal, analogous to but
 * NOT the same unit as the old engine's finding count (a dataElement is a
 * distinct field identity, not a reported finding — labeled accordingly in
 * the printed table, never conflated with `shallowCount`/`deepCount`).
 */
function measureLineageFixture(name) {
  const appFile = path.join(FIXTURES_DIR, name, 'app.js');
  const source = fs.readFileSync(appFile, 'utf8');
  const perFile = { 'app.js': parseJsFile('app.js', source) };
  const callGraph = buildCallGraph(perFile);
  const { graph } = buildGraphWithCoverage(callGraph, {
    repository: name,
    generatedAt: '1970-01-01T00:00:00.000Z',
  });
  const classified = graph.dataElements.filter((d) => (d.dataClasses ?? []).length > 0);
  return { lineageClassifiedCount: classified.length };
}

export function measureLineage() {
  const results = {};
  for (const name of listFixtures()) {
    results[name] = measureLineageFixture(name);
  }
  return results;
}

async function compare() {
  const [oldResults, lineageResults] = [await measure(), measureLineage()];
  const combined = {};
  for (const name of listFixtures()) {
    combined[name] = {
      shallowCount: oldResults[name].shallowCount,
      deepCount: oldResults[name].deepCount,
      lineageClassifiedCount: lineageResults[name].lineageClassifiedCount,
    };
  }
  return combined;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const jsonOut = process.argv.includes('--json');
  const results = await compare();
  if (jsonOut) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    console.log('fixture'.padEnd(24) + 'shallow'.padStart(10) + 'deep'.padStart(8) + 'lineage-classified'.padStart(22));
    for (const [name, r] of Object.entries(results)) {
      console.log(
        name.padEnd(24) +
        String(r.shallowCount).padStart(10) +
        String(r.deepCount).padStart(8) +
        String(r.lineageClassifiedCount).padStart(22),
      );
    }
  }
}
