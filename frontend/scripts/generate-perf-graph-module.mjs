#!/usr/bin/env node
// Generates a browser-importable ES module from bench/data-lineage/perf's
// synthetic 5,000-node/10,000-edge graph (PRD Section 21's own reference
// scale), for M3-Perf's real-browser performance measurement only — NOT
// a fixture with any semantic meaning, and NEVER a substitute for the
// real flagship-graph.js (see frontend/scripts/generate-fixture-module.mjs
// for that). Validated with the REAL validateGraph() before writing,
// exactly like the real fixture generator.
//
// Output is git-ignored (frontend/src/data/perf-large-graph.js) — this is
// throwaway measurement infrastructure, not a committed artifact.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const GENERATOR_PATH = path.join(REPO_ROOT, 'bench', 'data-lineage', 'perf', 'generate-synthetic-graph.mjs');
const VALIDATE_JS_PATH = path.join(REPO_ROOT, 'scanner', 'src', 'lineage', 'validate.js');
const OUTPUT_PATH = path.join(HERE, '..', 'src', 'data', 'perf-large-graph.js');

async function main() {
  const { generateSyntheticGraph } = await import(GENERATOR_PATH);
  const graph = generateSyntheticGraph(5000, 10000);

  const { validateGraph } = await import(VALIDATE_JS_PATH);
  const result = validateGraph(graph);
  if (!result.valid) {
    process.stderr.write(`generate-perf-graph-module.mjs: synthetic graph failed validateGraph():\n${JSON.stringify(result.errors.slice(0, 10), null, 2)}\n`);
    process.exit(1);
  }

  const header = `// GENERATED FILE, git-ignored — do not edit by hand or commit.\n// Source: bench/data-lineage/perf/generate-synthetic-graph.mjs (5,000 nodes/10,000 edges, PRD Section 21's own reference scale)\n// Regenerate: node frontend/scripts/generate-perf-graph-module.mjs\n// M3-Perf measurement infrastructure only — never the real fixture.\n\n`;
  const body = `export const PERF_LARGE_GRAPH = ${JSON.stringify(graph)};\n`;

  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, header + body);
  process.stdout.write(`wrote ${OUTPUT_PATH} (${graph.nodes.length} nodes, ${graph.edges.length} edges, ${graph.flows.length} flows)\n`);
}

main();
