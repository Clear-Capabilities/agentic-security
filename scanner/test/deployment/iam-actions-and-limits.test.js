// Threat-model PRD FR-03 (TM-03, TM-04): a deny blocks only the action, resource and condition it matches, and a path search says why
// it stopped. Policies go through the real IAM adapter and graph normalization; paths through the normal search.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIamPolicy } from '../../src/lineage/deployment/adapter-cloud.js';
import { computeAttackPaths, analyzeFindingBoundaries } from '../../src/lineage/deployment/attack-paths.js';
import { validateBoundaryContext } from '../../src/lineage/deployment/projection.js';
import { evaluateCondition, statementAttrs } from '../../src/lineage/deployment/iam-eval.js';
import { node, edge, graphOf, FINDING, BINDINGS } from './path-helpers.js';
import { digestOf } from '../../src/posture/assurance/identity.js';

const READ = { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::records/*' };
const ctx = { file: 'iam/app.json', identity: 'app', environment: 'prod', digest: digestOf('iam/app.json') };

/** public route -> shop/api -> assumes iam/app -> the policy's resources */
function graphWith(statements, { extraEdges = [], extraNodes = [], identity = 'app' } = {}) {
  const pol = parseIamPolicy(JSON.stringify({ Version: '2012-10-17', Statement: statements }), { ...ctx, identity });
  const route = node('route', 'edge/records', { trustZone: 'public' });
  const api = node('service', 'shop/api');
  const ident = node('identity', 'iam/app');
  return { g: graphOf({ nodes: [route, api, ident, ...pol.nodes, ...extraNodes], edges: [edge('routes-to', route, api), edge('assumes', api, ident), ...pol.edges, ...extraEdges], gaps: pol.gaps }), route, api, ident, gaps: pol.gaps };
}
const read = (g, o = {}) => computeAttackPaths(g, { action: 's3:GetObject', ...o });

test('AC-03A: allow-only and a disjoint delete deny leave the read possible; a matching explicit deny blocks and cites its rule', () => {
  assert.equal(read(graphWith([READ]).g).paths[0].state, 'possible');
  const disjoint = graphWith([READ, { Effect: 'Deny', Action: 's3:DeleteObject', Resource: '*' }]).g;
  const p = read(disjoint).paths[0];
  assert.equal(p.state, 'possible', 'TM-03: an unrelated delete deny no longer closes the read');
  assert.equal(p.blockers.length, 0);
  const legacy = computeAttackPaths(disjoint).paths[0];
  assert.equal(legacy.state, 'possible', 'with no requested action the granted action is still possible');
  assert.deepEqual(legacy.actionOutcomes, { 's3:GetObject': 'possible' });
  const matching = read(graphWith([READ, { Effect: 'Deny', Action: 's3:Get*', Resource: '*' }]).g).paths[0];
  assert.equal(matching.state, 'blocked');
  assert.equal(matching.blockers.length, 1); assert.equal(matching.blockers[0].action, 's3:GetObject'); assert.deepEqual(matching.blockers[0].matchedActions, ['s3:Get*']);
});

test('AC-03A: a supported condition that holds blocks, one that does not permits, and an unevaluated one leaves the read unresolved', () => {
  const cond = { Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::records/*', Condition: { Bool: { 'aws:SecureTransport': 'false' } } };
  const { g } = graphWith([READ, cond]);
  assert.equal(read(g, { context: { 'aws:SecureTransport': 'false' } }).paths[0].state, 'blocked', 'the condition holds');
  assert.equal(read(g, { context: { 'aws:SecureTransport': 'true' } }).paths[0].state, 'possible', 'the condition does not hold');
  const open = read(g).paths[0];
  assert.equal(open.state, 'unresolved', 'TM-03: an unevaluated predicate no longer blocks');
  assert.match(open.hops.find((h) => h.actions).actions[0].unresolvedBy[0], /does not supply aws:SecureTransport/);
  const odd = graphWith([READ, { ...cond, Condition: { IpAddress: { 'aws:SourceIp': '10.0.0.0/8' } } }]);
  assert.equal(read(odd.g, { context: { 'aws:SourceIp': '10.1.1.1' } }).paths[0].state, 'unresolved', 'an operator outside the subset is never decided');
  assert.ok(odd.gaps.some((x) => x.code === 'unsupported-syntax'), 'and the support limit is disclosed');
});

test('AC-03B: other identities, resources and tenants do not block; a network deny still does; results are deterministic', () => {
  const other = parseIamPolicy(JSON.stringify({ Statement: [{ Effect: 'Deny', Action: 's3:GetObject', Resource: '*' }] }), { ...ctx, file: 'iam/other.json', identity: 'other' });
  const a = graphWith([READ], { extraNodes: other.nodes, extraEdges: other.edges });
  assert.equal(read(a.g).paths[0].state, 'possible', 'a deny on another identity');
  assert.equal(read(graphWith([READ, { Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::audit/*' }]).g).paths[0].state, 'possible', 'a deny on another resource');
  const net = graphWith([READ]);
  const withNet = graphOf({ nodes: net.g.nodes, edges: [...net.g.edges, edge('network-denies', net.route, net.api, { effect: 'deny' })] });
  const blocked = read(withNet).paths[0];
  assert.equal(blocked.state, 'blocked'); assert.equal(blocked.blockers[0].relation, 'network-denies', 'network deny semantics are separate');
  const g = graphWith([READ, { Effect: 'Deny', Action: 's3:DeleteObject', Resource: '*' }]).g;
  assert.deepEqual(read(g), read(g), 'the same graph and query give the same result');
  assert.equal(graphWith([READ]).g.digest, graphWith([READ]).g.digest);
  assert.equal(computeAttackPaths(g).paths[0].id, read(g).paths[0].id, 'path identity does not depend on the query');
  assert.equal(read(g, { action: 's3:PutObject' }).paths.length, 0, 'an action nothing grants has no path');
});

test('AC-03C: a depth cutoff is reported; a terminal stop, a result cap and an expansion cap are each distinguishable', () => {
  const { g } = graphWith([READ]);
  const one = computeAttackPaths(g, { maxHops: 1 });
  assert.equal(one.paths.length, 0);
  assert.equal(one.truncated, true, 'TM-04: the legacy flag now says the search ended at a bound');
  assert.deepEqual(one.truncation.reasons, ['depth']); assert.ok(one.truncation.frontier.length > 0);
  const eight = computeAttackPaths(g, { maxHops: 8 });
  assert.equal(eight.paths.length, 1); assert.equal(eight.truncated, false); assert.deepEqual(eight.truncation.reasons, []);
  const exact = computeAttackPaths(g, { maxHops: 3 });
  assert.equal(exact.paths.length, 1); assert.deepEqual(exact.truncation.reasons, [], 'a bound reached on a node with nowhere left to go is not a cutoff');
  const two = graphWith([READ, { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::exports/*' }]).g;
  assert.deepEqual(computeAttackPaths(two, { maxPaths: 1 }).truncation.reasons, ['result-count']);
  assert.deepEqual(computeAttackPaths(two, { maxExpansions: 1 }).truncation.reasons, ['expansion']);
  assert.match(computeAttackPaths(g, { maxHops: 1 }).statement, /search stopped at a limit: depth/);
});

test('AC-03C: the finding context carries the truncation reasons, validates as 1.1.0, and never certifies absence after a cutoff', () => {
  const { g } = graphWith([READ]);
  const api = { ...node('service', 'shop/api') };
  void api;
  const r = analyzeFindingBoundaries({ graph: g, finding: FINDING, bindings: BINDINGS, maxHops: 1 });
  assert.equal(r.ok, true);
  assert.equal(r.context.schemaVersion, '1.1.0');
  assert.deepEqual(r.context.truncation.reasons, ['depth']);
  assert.ok(r.context.warnings.some((w) => /stopped at a limit \(depth\).*no listed absence is a proof of absence/.test(w)));
  assert.equal(validateBoundaryContext(r.context).ok, true, JSON.stringify(validateBoundaryContext(r.context).errors));
  const legacy = { ...r.context, schemaVersion: '1.0.0' };
  assert.equal(validateBoundaryContext(legacy).ok, false, 'a 1.0.0 context may not carry the 1.1.0 fields');
  const { truncation, action, ...old } = legacy; void truncation; void action;
  assert.equal(validateBoundaryContext(old).ok, true, 'a 1.0.0 context without them is still valid');
});

test('the condition subset is decided exactly and anything outside it is unknown', () => {
  const a = statementAttrs(['s3:GetObject'], { StringEquals: { 'aws:PrincipalTag/tenant': ['tenant-a', 'tenant-b'] } });
  assert.equal(evaluateCondition(a, { 'aws:PrincipalTag/tenant': 'tenant-b' }).result, 'true');
  assert.equal(evaluateCondition(a, { 'aws:PrincipalTag/tenant': 'tenant-c' }).result, 'false');
  assert.equal(evaluateCondition(statementAttrs(['x'], { StringNotEquals: { 'aws:SourceVpc': 'vpc-1' } }), { 'aws:SourceVpc': 'vpc-1' }).result, 'false');
  assert.equal(evaluateCondition(statementAttrs(['x'], { StringEquals: { 'aws:userid': '${aws:username}' } }), {}).result, 'unknown', 'a policy variable');
  assert.equal(statementAttrs(Array.from({ length: 40 }, (_, i) => `s3:Action${i}`), null).actionsComplete, false, 'a clipped action list is marked');
});
