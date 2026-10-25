// DAG-08: the pure boundary-contract module (validation, digests, import boundary).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  BOUNDARY_CONTRACT_VERSION, createBoundaryContract, validateBoundaryContract, contractDigest, analyzeServiceBoundaries, EVIDENCE_KINDS,
} from '../../src/lineage/boundary-contract.js';

const base = () => createBoundaryContract({
  id: 'boundary:t', kind: 'http', channel: { route: 'POST /orders' }, schema: { name: 'Order', version: '1' },
  producer: { service: 'a', site: null }, consumer: { service: 'b', site: { file: 'b.js', function: 'h', param: 'req' } },
  fieldMappings: [{ from: 'customer_id', to: 'customerId' }], declaredBy: 'ops',
});

test('createBoundaryContract yields a valid, versioned, digest-carrying declaration', () => {
  const c = base();
  assert.equal(c.version, BOUNDARY_CONTRACT_VERSION);
  assert.equal(c.persistence, 'immediate');
  assert.deepEqual(c.evidence, { declared: true, observed: false });
  assert.equal(validateBoundaryContract(c).valid, true);
  assert.equal(c.configDigest, contractDigest(c));
});

test('the digest ignores declaration metadata and key order but not meaning', () => {
  const c = base();
  assert.equal(contractDigest({ ...c, declaredBy: 'someone else', rationale: 'x' }), c.configDigest);
  assert.equal(contractDigest({ ...c, fieldMappings: [{ to: 'customerId', from: 'customer_id' }] }), c.configDigest);
  assert.notEqual(contractDigest({ ...c, schema: { name: 'Order', version: '2' } }), c.configDigest);
  assert.notEqual(contractDigest({ ...c, channel: { route: 'GET /orders' } }), c.configDigest);
});

test('validation refuses an observed claim, an unknown kind, a missing consumer param and bad mappings', () => {
  const c = base();
  const bad = (over) => validateBoundaryContract({ ...c, ...over }).valid;
  assert.equal(bad({ evidence: { declared: true, observed: true } }), false);
  assert.equal(bad({ kind: 'rpc' }), false);
  assert.equal(bad({ consumer: { service: 'b', site: { file: 'b.js', function: 'h' } } }), false);
  assert.equal(bad({ fieldMappings: [{ from: 'x' }] }), false);
  assert.equal(bad({ provenance: 'guessed' }), false);
  assert.equal(bad({ id: 'nope' }), false);
  assert.equal(validateBoundaryContract(null).valid, false);
});

test('an acyclic service chain converges without being forced through a cycle path', () => {
  const mk = (id, f, t, m, p) => createBoundaryContract({ id, kind: 'queue', channel: { topic: id }, schema: { name: id, version: '1' }, producer: { service: f, site: null, ...(p || {}) }, consumer: { service: t, site: { file: 'x.js', function: 'g', param: 'p' } }, fieldMappings: m, declaredBy: 'ops' });
  const r = analyzeServiceBoundaries([mk('boundary:1', 'a', 'b', [{ from: 'x', to: 'y' }], { untrustedFields: ['x'] }), mk('boundary:2', 'b', 'c', [{ from: 'y', to: 'z' }])]);
  assert.deepEqual(r.cycles, []);
  assert.deepEqual(r.taintedFields.c, ['z']);
  assert.equal(r.converged, true);
  assert.equal(r.origins['c.z'].contractId, 'boundary:2');
});

test('evidence kinds are the five separately attributable kinds', () => {
  assert.deepEqual([...EVIDENCE_KINDS], ['foreign-graph-validation', 'digest-check', 'manual-assertion', 'code-mapping', 'observed-connection']);
});

test('the module is pure: only node:crypto, schema.js and graph/scc.js', () => {
  const src = readFileSync(fileURLToPath(new URL('../../src/lineage/boundary-contract.js', import.meta.url)), 'utf8');
  const specs = [...src.matchAll(/^import[^;]*?from\s+'([^']+)'/gm)].map((m) => m[1]).sort();
  assert.deepEqual(specs, ['../graph/scc.js', './schema.js', 'node:crypto']);
});
