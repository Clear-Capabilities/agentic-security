#!/usr/bin/env node
// Reads the real backend flagship fixture, validates it with the REAL
// validateGraph() (Node-side only — this script never ships to the
// browser), and writes a browser-importable ES module copy. Re-run this
// whenever scanner/src/lineage/fixtures/flagship-graph.json changes;
// test/fixture-module-parity.test.js enforces that the committed output
// stays in sync and stays valid.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const BACKEND_FIXTURE_PATH = path.join(REPO_ROOT, 'scanner', 'src', 'lineage', 'fixtures', 'flagship-graph.json');
const OUTPUT_PATH = path.join(HERE, '..', 'src', 'data', 'flagship-graph.js');
const VALIDATE_JS_PATH = path.join(REPO_ROOT, 'scanner', 'src', 'lineage', 'validate.js');

async function main() {
  const graph = JSON.parse(fs.readFileSync(BACKEND_FIXTURE_PATH, 'utf8'));

  const { validateGraph } = await import(VALIDATE_JS_PATH);
  const result = validateGraph(graph);
  if (!result.valid) {
    process.stderr.write(`generate-fixture-module.mjs: backend fixture failed validateGraph():\n${JSON.stringify(result.errors, null, 2)}\n`);
    process.exit(1);
  }

  const header = `// GENERATED FILE — do not edit by hand.\n// Source: scanner/src/lineage/fixtures/flagship-graph.json\n// Regenerate: node frontend/scripts/generate-fixture-module.mjs\n// This copy has been validated by the real validateGraph() at generation\n// time (see frontend/test/fixture-module-parity.test.js for the ongoing\n// proof) — the browser bundle itself never imports scanner/src/lineage/.\n\n`;
  const body = `export const FLAGSHIP_GRAPH = ${JSON.stringify(graph, null, 2)};\n`;

  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, header + body);
  process.stdout.write(`wrote ${OUTPUT_PATH} (${graph.nodes.length} nodes, ${graph.edges.length} edges, ${graph.flows.length} flows)\n`);
}

main();
