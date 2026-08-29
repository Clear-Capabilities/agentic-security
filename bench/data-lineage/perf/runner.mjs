//
// Contract-layer performance harness (PRD section 21's "Graph build
// overhead" and validation-cost concerns, scoped to what exists at
// Milestone 0: no render/query/layout timings yet, since there is no UI
// — Milestone 3 extends this file with those). Run:
//   node bench/data-lineage/perf/runner.mjs
// Prints timing; exits 0 always at this milestone (no baseline to gate
// against yet — a --check flag with a committed baseline lands once
// Milestone 3's UI timings make the PRD 21 targets checkable for real).

import { generateSyntheticGraph } from './generate-synthetic-graph.mjs';
import { validateGraph } from '../../../scanner/src/lineage/validate.js';

function timeIt(label, fn) {
  const start = process.hrtime.bigint();
  const result = fn();
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  console.log(`${label}: ${ms.toFixed(1)}ms`);
  return { result, ms };
}

function main() {
  const { result: graph, ms: genMs } = timeIt('generate 5000-node/10000-edge synthetic graph', () => generateSyntheticGraph(5000, 10000));
  console.log(`  nodes=${graph.nodes.length} edges=${graph.edges.length} flows=${graph.flows.length}`);

  const { result: validation, ms: valMs } = timeIt('validateGraph over the synthetic graph', () => validateGraph(graph));
  console.log(`  valid=${validation.valid} errorCount=${validation.errors.length}`);

  console.log('\nSummary:');
  console.log(`  generation: ${genMs.toFixed(1)}ms`);
  console.log(`  validation: ${valMs.toFixed(1)}ms`);
  console.log('\nNo baseline gate yet — this harness establishes the measurement point for Milestone 3 to extend with real render/query/layout timings against PRD section 21 targets.');
}

main();
