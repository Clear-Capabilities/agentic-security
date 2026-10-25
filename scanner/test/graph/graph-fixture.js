// Shared fixture for the graph view tests: one real build over the vulnerable-js
// project, exposing the producers' outputs unchanged.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProjectIR } from '../../src/ir/index.js';
import { buildSemanticGraph } from '../../src/ir/semantic-graph.js';
import { buildDataFlowGraph } from '../../src/lineage/graph-builder.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(here, '..', 'fixtures', 'vulnerable-js', 'app.js');

export function buildFixture(repository = 'vulnerable-js') {
  const ir = buildProjectIR({ 'app.js': fs.readFileSync(APP, 'utf8') });
  const built = buildDataFlowGraph(ir.callGraph, { repository, generatedAt: '2026-01-01T00:00:00.000Z' });
  const semantic = buildSemanticGraph(ir);
  return { ir, built, semantic, graph: built.graph, store: built.store, sites: built.sites, repository };
}
