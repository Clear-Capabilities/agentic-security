// Shared fixtures and builders for the deployment boundary graph suites
// (X-301 to X-304). Not a test file: nothing here asserts.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ingestDeploymentConfig } from '../../src/lineage/deployment/ingest.js';
import { buildBoundaryGraph, exportBoundaryGraph } from '../../src/lineage/deployment/boundary-graph.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const FIXTURES = path.join(HERE, 'fixtures');
export const REV_A = 'a'.repeat(40);
export const REV_B = 'b'.repeat(40);
export const REV_C = 'c'.repeat(40);

export function fx(rel) { return fs.readFileSync(path.join(FIXTURES, rel), 'utf8'); }

/** Ingest one fixture file and return the graph, failing loudly if ingest itself fails. */
export function ingestOne(rel, { environment = 'prod', repository = 'repo', revision = null, identities = {}, as = rel } = {}) {
  const r = ingestDeploymentConfig({ files: [{ path: as, text: fx(rel) }], environment, repository, revision, identities });
  if (r.status !== 'ok') throw new Error(`ingest failed for ${rel}: ${JSON.stringify(r.errors)}`);
  return r.graph;
}

export function ingestText(files, opts = {}) {
  const r = ingestDeploymentConfig({ files, environment: 'prod', repository: 'repo', ...opts });
  if (r.status !== 'ok') throw new Error(`ingest failed: ${JSON.stringify(r.errors)}`);
  return r.graph;
}

export function nodeByName(graph, name, kind) {
  return graph.nodes.find(n => n.name === name && (!kind || n.kind === kind));
}

export function edgesOf(graph, relation, { from, to, provenance } = {}) {
  const byId = new Map(graph.nodes.map(n => [n.id, n]));
  return graph.edges.filter(e => e.relation === relation
    && (!from || byId.get(e.from)?.name === from)
    && (!to || byId.get(e.to)?.name === to)
    && (!provenance || e.provenance === provenance));
}

/** Two repository graphs for the caller-to-callee fixture: checkout calls billing. */
export function crossRepoGraphs({ billingRevision = REV_B, checkoutRevision = REV_A, billingRepo = 'billing' } = {}) {
  const checkout = ingestOne('xrepo/checkout.yaml', { repository: 'checkout', revision: checkoutRevision });
  const billing = ingestOne('xrepo/billing.yaml', { repository: billingRepo, revision: billingRevision });
  return { checkout, billing };
}

export function standardDeclaration(over = {}) {
  return {
    caller: { repository: 'checkout', revision: REV_A, service: 'shop/web', environment: 'prod' },
    callee: { repository: 'billing', revision: REV_B, service: 'billing/billing-api', environment: 'prod', route: { host: 'billing.internal', path: '/charge' } },
    ...over,
  };
}

export function supplied(graphs) {
  return graphs.map(g => ({ repository: g.repository, text: exportBoundaryGraph(g) }));
}

/** A tiny hand-built graph with one of every node kind, for contract tests. */
export function oneOfEach() {
  const nodes = [
    { kind: 'repository', name: 'app-repo', repository: 'app-repo' },
    { kind: 'environment', name: 'prod' },
    { kind: 'tenant', name: 'acme', environment: 'prod' },
    { kind: 'route', name: 'gw:/pay', environment: 'prod', trustZone: 'public' },
    { kind: 'service', name: 'pay', environment: 'prod', trustZone: 'internal', repository: 'app-repo' },
    { kind: 'identity', name: 'pay-role', environment: 'prod', trustZone: 'internal' },
    { kind: 'resource', name: 'ledger-db', environment: 'prod', trustZone: 'internal' },
  ];
  return nodes;
}

export function src(file = 'x.yaml') {
  return { file, digest: `sha256:${'1'.repeat(64)}`, parser: 'test-parser', parserVersion: '1' };
}

export function buildOneOfEach() {
  const built = buildBoundaryGraph({ nodes: oneOfEach(), edges: [], sources: [] });
  if (!built.ok) throw new Error(JSON.stringify(built.errors));
  return built.graph;
}
