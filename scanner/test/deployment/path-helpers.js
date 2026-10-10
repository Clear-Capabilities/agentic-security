// Builders for the attack path, drift and presentation suites (X-305 to X-307). Not a test file: nothing here asserts.
//
// `graphOf` builds a validated boundary graph from small node and edge descriptions so each scenario states only the
// relationships it is about. Real adapter output is used where a fixture file exists; these builders cover what no adapter
// emits (an explicit network deny, a tenant transition, an observed edge).

import { buildBoundaryGraph, normalizeNode, nodeIdOf } from '../../src/lineage/deployment/boundary-graph.js';
import { buildVerificationRecord } from '../../src/posture/assurance/verification-record.js';
import { digestOf } from '../../src/posture/assurance/identity.js';

export const SRC = (file, text = file) => ({ file, digest: digestOf(text), parser: 'kubernetes-manifest', parserVersion: '1' });

export function node(kind, name, o = {}) {
  return {
    kind, name, environment: o.environment === undefined ? 'prod' : o.environment, tenant: o.tenant ?? null, repository: o.repository ?? null,
    trustZone: o.trustZone ?? 'internal', resolved: o.resolved !== false, unresolvedReason: o.resolved === false ? 'fixture' : null,
    attrs: {}, declaredBy: o.declaredBy ?? [],
  };
}

export function edge(relation, from, to, o = {}) {
  const effect = o.effect ?? 'none';
  return {
    relation, from: nodeIdOf(normalizeNode(from)), to: nodeIdOf(normalizeNode(to)),
    environment: from.environment === undefined ? 'prod' : from.environment, tenant: null,
    effect, provenance: o.provenance ?? 'static-config', confidence: o.confidence ?? 'high',
    pathState: o.pathState ?? (effect === 'deny' ? 'blocked' : 'possible'),
    observationInterval: o.observationInterval ?? null, completeness: o.completeness ?? null, sourceRevision: o.sourceRevision ?? null,
    source: o.source !== undefined ? o.source : ((o.provenance ?? 'static-config') === 'static-config' ? SRC('cfg/default.yaml') : null), discriminator: o.discriminator ?? null, crossRepo: null, attrs: o.attrs ?? {},
  };
}

export function graphOf({ nodes, edges, gaps = [], sources = [], repository = 'repo', revision = null }) {
  const r = buildBoundaryGraph({ repository, revision, nodes, edges, gaps, sources });
  if (!r.ok) throw new Error(`fixture graph invalid: ${JSON.stringify(r.errors)}`);
  return r.graph;
}

/** public route -> api service -> (identity) -> database resource, the base shape of the three removal scenarios. */
export function baseline(o = {}) {
  const route = node('route', 'edge/orders', { trustZone: 'public' });
  const api = node('service', 'shop/api', { tenant: o.apiTenant ?? null });
  const ledger = node('service', 'shop/ledger');
  const ident = node('identity', 'sa/ledger');
  const db = node('resource', 'db/ledger', { trustZone: 'privileged', tenant: o.dbTenant ?? null });
  const nodes = [route, api, ledger, ident, db];
  const edges = [
    edge('routes-to', route, api, o.routeSource ? { source: o.routeSource } : {}),
    edge('calls', api, ledger, o.callSource ? { source: o.callSource } : {}),
    edge('assumes', ledger, ident),
    edge('grants', ident, db, { effect: 'allow', attrs: { verbs: 'get' }, ...(o.grantSource ? { source: o.grantSource } : {}) }),
    ...(o.extraEdges ?? []),
  ];
  return { route, api, ledger, ident, db, nodes: [...nodes, ...(o.extraNodes ?? [])], edges };
}

export const FINDING = Object.freeze({
  id: 'F-1', severity: 'high', file: 'services/api/handler.js', line: 12, vuln: 'Command injection', cwe: 'CWE-78',
  family: 'injection', parser: 'SAST', stableId: 'stable-boundary-1', description: 'input reaches a shell', remediation: 'use an argument array',
});
export const BINDINGS = Object.freeze([{ pathPrefix: 'services/api/', service: 'shop/api' }]);
export const COMMIT = 'a1'.repeat(20);

const trusted = [{ id: 'oracle-observation', kind: 'trusted-runtime-proof', producer: 'trusted-runner', digest: digestOf('observed'), source: 'oracle:injection-execution@1' }];

/** A version-1 verification record for FINDING. `kind` picks what backs it. */
export function recordFor(kind, o = {}) {
  const common = {
    hypothesisId: o.hypothesisId ?? FINDING.stableId, commit: COMMIT, detectorOrigin: { detector: 'Command injection', family: 'injection', parser: 'SAST' },
    attempt: 1, reason: `fixture ${kind}`, scope: { description: 'fixture oracle scenario', platform: process.platform, backend: 'userspace' },
    preconditions: { valid: true }, repair: { status: 'none' },
  };
  if (kind === 'trusted') {
    return buildVerificationRecord({ ...common, oracle: { id: o.oracleId ?? 'injection-execution', kind: 'runtime-replay', version: '1' }, outcome: 'confirmed', evidence: trusted });
  }
  if (kind === 'model') {
    // a model's agreement, however repeated, is inference: it can never reach a runtime-confirmed level
    return buildVerificationRecord({
      ...common, oracle: { id: 'model-review', kind: 'model', version: '1' }, outcome: 'confirmed',
      evidence: [{ id: 'model-opinion', kind: 'inference', producer: 'model', digest: digestOf('opinion'), source: null }],
    });
  }
  if (kind === 'adjudicated') {
    // valid and confirmed, but by a person reading the code: adjudication is not a trusted runtime replay
    return buildVerificationRecord({
      ...common, oracle: { id: 'human-review', kind: 'human', version: '1' }, outcome: 'confirmed',
      evidence: [{ id: 'reviewer-note', kind: 'independent-adjudication', producer: 'human', digest: digestOf('note'), source: null }],
    });
  }
  if (kind === 'refuted') {
    return buildVerificationRecord({ ...common, oracle: { id: 'injection-execution', kind: 'runtime-replay', version: '1' }, outcome: 'refuted', evidence: trusted });
  }
  throw new Error(`unknown record kind ${kind}`);
}
