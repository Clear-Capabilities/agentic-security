//
// Contract-layer performance harness (PRD section 21's "Graph build
// overhead" and validation-cost concerns, scoped to what exists at
// Milestone 0/1: no render/query/layout timings yet, since there is no UI
// — Milestone 3 extends this file with those). Run:
//   node bench/data-lineage/perf/runner.mjs
// Prints timing; exits 0 always at this milestone (no baseline to gate
// against yet — a --check flag with a committed baseline lands once
// Milestone 3's UI timings make the PRD 21 targets checkable for real).
//
// Sub-project G, increment G2 (Data Flow Explorer PRD, Milestone 1
// exit-gate closure plan) added the second timed step below: a REAL scan
// (via runScan) over scanner/test/fixtures/vulnerable-js, with and without
// AGENTIC_SECURITY_LINEAGE_DEEP=1, to measure PRD §21's actual P0 target —
// "Graph build overhead: no more than 35% p50 over the equivalent deep
// scan" — which the synthetic-graph timings above never answered (they
// time a fixture-building helper and schema validation, never the real
// buildGraphWithCoverage engine on top of a real deep scan). Still no
// baseline gate — see the file's own posture note above, now covering
// both timed steps, not just the synthetic one.

import { generateSyntheticGraph } from './generate-synthetic-graph.mjs';
import { validateGraph } from '../../../scanner/src/lineage/validate.js';
import { disableStateWrites, purgeScanState } from '../../_lib/tree-integrity.mjs';
import { runScan } from '../../../scanner/src/runScan.js';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VULNERABLE_JS_FIXTURE = path.join(HERE, '../../../scanner/test/fixtures/vulnerable-js');

function timeIt(label, fn) {
  const start = process.hrtime.bigint();
  const result = fn();
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  console.log(`${label}: ${ms.toFixed(1)}ms`);
  return { result, ms };
}

async function timeItAsync(label, fn) {
  const start = process.hrtime.bigint();
  const result = await fn();
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  console.log(`${label}: ${ms.toFixed(1)}ms`);
  return { result, ms };
}

/**
 * Times a real scan over the vulnerable-js fixture with the given env vars
 * set. Mirrors bench/privacy-recall/measure.mjs's exact save/restore +
 * disableStateWrites()/purgeScanState() pattern so this harness never
 * pollutes or is polluted by real scan state.
 */
async function timedScan(label, envOverrides) {
  const saved = {};
  for (const key of Object.keys(envOverrides)) saved[key] = process.env[key];
  for (const [key, value] of Object.entries(envOverrides)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    purgeScanState(VULNERABLE_JS_FIXTURE);
    const { ms } = await timeItAsync(label, () => runScan(VULNERABLE_JS_FIXTURE, { network: false }));
    return ms;
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    purgeScanState(VULNERABLE_JS_FIXTURE);
  }
}

async function main() {
  const { result: graph, ms: genMs } = timeIt('generate 5000-node/10000-edge synthetic graph', () => generateSyntheticGraph(5000, 10000));
  console.log(`  nodes=${graph.nodes.length} edges=${graph.edges.length} flows=${graph.flows.length}`);

  const { result: validation, ms: valMs } = timeIt('validateGraph over the synthetic graph', () => validateGraph(graph));
  console.log(`  valid=${validation.valid} errorCount=${validation.errors.length}`);

  console.log('');
  await disableStateWrites();

  const baselineMs = await timedScan(
    'deep scan (AGENTIC_SECURITY_DEEP=1) over test/fixtures/vulnerable-js — baseline',
    { AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_LINEAGE_DEEP: undefined },
  );
  const withLineageMs = await timedScan(
    'deep scan + AGENTIC_SECURITY_LINEAGE_DEEP=1 over test/fixtures/vulnerable-js',
    { AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
  );
  const overheadPct = ((withLineageMs - baselineMs) / baselineMs) * 100;

  console.log('\nSummary:');
  console.log(`  generation: ${genMs.toFixed(1)}ms`);
  console.log(`  validation: ${valMs.toFixed(1)}ms`);
  console.log(`  deep scan baseline: ${baselineMs.toFixed(1)}ms`);
  console.log(`  deep scan + lineage: ${withLineageMs.toFixed(1)}ms`);
  console.log(`  lineage graph-build overhead: ${overheadPct.toFixed(1)}% (PRD section 21 P0 target: no more than 35% p50 over the equivalent deep scan)`);
  console.log('\nNo baseline gate yet — this harness establishes the measurement point for Milestone 3 to extend with real render/query/layout timings against PRD section 21 targets.');
}

main();
