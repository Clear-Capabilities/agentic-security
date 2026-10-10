#!/usr/bin/env node
// A local boundary-graph drift example (DOC-001.AC02): build the deployment boundary graph for two synthetic revisions of the same
// service and print what changed between them.
//
//   node scripts/graph-drift-example.mjs [--reverse]
//
// "Before" is the synthetic deployment with no ingress (scanner/test/fixtures/deployment-ablation/cases/k8s-ingress-vs-internal/
// non-exploitable) and "after" is the same service with a public ingress added (.../exploitable). With --reverse the two are
// swapped, so the same exposure is removed and the result reads as a reduction. Nothing is executed or contacted: the script
// reads the local manifests only (the `deployment-boundaries` feature is turned on in this one process, it is off by default).
//
// Exit: 0 the expected drift was reported / 1 it was not or a graph could not be built.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveAssuranceConfig } from '../scanner/src/posture/assurance/config.js';
import { runBoundaries } from '../scanner/src/lineage/deployment/boundaries-run.js';
import { diffBoundaryGraphs, explainDrift } from '../scanner/src/lineage/deployment/drift.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const cases = path.join(HERE, '..', 'scanner', 'test', 'fixtures', 'deployment-ablation', 'cases', 'k8s-ingress-vs-internal');
const reverse = process.argv.includes('--reverse');
const config = resolveAssuranceConfig({ env: {}, overrides: { features: { 'deployment-boundaries': true } } });

const build = (dir) => runBoundaries({ config, from: path.join(cases, dir), environment: 'prod', repository: null, revision: null });
const a = build(reverse ? 'exploitable' : 'non-exploitable');
const b = build(reverse ? 'non-exploitable' : 'exploitable');
for (const [label, r] of [['before', a], ['after', b]]) {
  if (r.status !== 'ok') { console.error(`${label}: graph not built (${r.status}): ${r.reason}`); process.exit(1); }
  console.log(`${label}: ${r.report.graph.nodeCount} node(s), ${r.report.graph.edgeCount} edge(s), digest ${r.report.graph.digest.slice(0, 12)}`);
}
const d = diffBoundaryGraphs(a.graph, b.graph);
if (!d.ok) { console.error(`diff refused: ${d.errors.map((e) => e.message).join('; ')}`); process.exit(1); }
for (const line of explainDrift(d.diff)) console.log(line);
const category = reverse ? 'exposure-reduced' : 'new-exposure';
process.exit(d.diff.changes.some((c) => c.category === category) ? 0 : 1);
