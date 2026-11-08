// Threat-model PRD FR-04.1, FR-04.2 (TM-05): a proof promotes a deployed path only when it is the graph's revision and an issued,
// signed binding ties it to that exact path, claim, artifact, policy, environment, tenant, actor, route, action and oracle version.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { analyzeFindingBoundaries } from '../../src/lineage/deployment/attack-paths.js';
import { verifyProofBinding } from '../../src/lineage/deployment/proof-binding.js';
import { graphOf, baseline, FINDING, BINDINGS, recordFor, COMMIT, bindingFor, TRUST_ROOT } from './path-helpers.js';

const REV_B = 'b2'.repeat(20);
const graphAt = (revision) => { const b = baseline(); return graphOf({ nodes: b.nodes, edges: b.edges, revision }); };
const ctxFor = (graph, records, proofBindings = [], expect = {}) => analyzeFindingBoundaries({ graph, finding: FINDING, bindings: BINDINGS, records, proofBindings, trustRoot: TRUST_ROOT, expect }).context;
const labels = (ctx) => ctx.paths.map((p) => `${p.kind}:${p.exploitability.label}`).sort();

test('AC-04A: a valid trusted record from revision A leaves both paths of a revision B graph unpromoted, kept as history', () => {
  const rec = recordFor('trusted');           // made at COMMIT (revision A)
  const g = graphAt(REV_B);
  const unbound = ctxFor(g, [rec]);
  const paths = unbound.paths;
  const ctx = ctxFor(g, [rec], paths.map((p) => bindingFor(rec, g, p, p.kind)));
  assert.ok(ctx.paths.length >= 2 && ctx.paths.some((p) => p.kind === 'exposure') && ctx.paths.some((p) => p.kind === 'impact'));
  assert.ok(ctx.paths.every((p) => p.exploitability.label === 'not-established'), `TM-05: ${labels(ctx)}`);
  assert.equal(ctx.verification[0].applicable, false);
  assert.equal(ctx.verification[0].historical, true); assert.equal(ctx.verification[0].commit, COMMIT);
  assert.match(ctx.verification[0].reasons.join(' '), /not this graph's revision/);
});

test('AC-04A: at the same revision, each binding field that differs from the tested subject fails promotion on its own', () => {
  const rec = recordFor('trusted');
  const g = graphAt(COMMIT);
  const exposure = ctxFor(g, [rec]).paths.find((p) => p.kind === 'exposure');
  const promoted = (over, expect = {}) => ctxFor(g, [rec], [bindingFor(rec, g, exposure, 'exposure', over)], expect).paths.find((p) => p.id === exposure.id).exploitability;
  assert.equal(promoted({}).label, 'exploitable-confirmed', 'the positive control');
  const other = crypto.generateKeyPairSync('ed25519');
  const cases = [
    ['artifact', {}, { artifactDigest: 'sha256:other-artifact' }],
    ['environment', { environment: 'staging' }, {}],
    ['tenant', { tenant: 'globex' }, { tenant: 'acme' }],
    ['route', {}, { route: 'POST /admin' }],
    ['action', {}, { action: 'export' }],
    ['actor', {}, { actor: 'tenant-a-user' }],
    ['policy', { policyDigest: 'sha256:' + '0'.repeat(64) }, {}],
    ['scenario', { pathId: 'bpath:not-this-one' }, {}],
    ['oracle', { oracleVersion: '999' }, {}],
    ['issuer', { privateKey: other.privateKey.export({ type: 'pkcs8', format: 'pem' }) }, {}],
  ];
  for (const [name, over, expect] of cases) {
    const e = promoted(over, expect);
    assert.equal(e.label, 'not-established', name);
    assert.ok(e.componentProof.diagnostics.length >= 1, `${name}: a diagnostic says why`);
  }
});

test('AC-04B: a bound receipt promotes only its tested claim, and a component proof cannot promote a separate impact path', () => {
  const rec = recordFor('trusted');
  const g = graphAt(COMMIT);
  const paths = ctxFor(g, [rec]).paths;
  const exposure = paths.find((p) => p.kind === 'exposure');
  const ctx = ctxFor(g, [rec], [bindingFor(rec, g, exposure, 'exposure')]);
  for (const p of ctx.paths) assert.equal(p.exploitability.label, p.id === exposure.id ? 'exploitable-confirmed' : 'not-established', `${p.kind} ${p.id}`);
  const impact = paths.find((p) => p.kind === 'impact');
  const misclaimed = ctxFor(g, [rec], [bindingFor(rec, g, impact, 'exposure')]).paths.find((p) => p.id === impact.id).exploitability;
  assert.equal(misclaimed.label, 'not-established', 'an exposure claim does not promote an impact path');
  assert.equal(misclaimed.componentProof.code, 'context-mismatch');
});

test('AC-04B: malformed, tampered, expired, untrusted and replayed bindings have distinct diagnostics; a duplicate adds nothing', () => {
  const rec = recordFor('trusted');
  const g = graphAt(COMMIT);
  const exposure = ctxFor(g, [rec]).paths.find((p) => p.kind === 'exposure');
  const good = bindingFor(rec, g, exposure, 'exposure');
  const now = Date.parse('2026-11-08T12:00:00Z');
  assert.equal(verifyProofBinding(good, { trustRoot: TRUST_ROOT, now }).code, 'verified');
  assert.equal(verifyProofBinding({ ...good, extra: 1 }, { trustRoot: TRUST_ROOT, now }).code, 'malformed');
  assert.equal(verifyProofBinding({ ...good, schema: 'x' }, { trustRoot: TRUST_ROOT, now }).code, 'unsupported-version');
  assert.equal(verifyProofBinding({ ...good, effect: 'nothing' }, { trustRoot: TRUST_ROOT, now }).code, 'tampered');
  assert.equal(verifyProofBinding(bindingFor(rec, g, exposure, 'exposure', { expires: '2026-01-01T00:00:00Z' }), { trustRoot: TRUST_ROOT, now }).code, 'expired');
  assert.equal(verifyProofBinding(good, { trustRoot: {}, now }).code, 'untrusted-issuer', 'a digest alone is not authority');
  const { pathId, ...noPath } = good; void pathId;
  assert.equal(verifyProofBinding(noPath, { trustRoot: TRUST_ROOT, now }).code, 'missing-binding');
  const replay = ctxFor(graphAt(COMMIT), [rec], [bindingFor(rec, g, exposure, 'exposure', { policyDigest: graphAt(REV_B).digest })]).paths.find((p) => p.id === exposure.id).exploitability;
  assert.equal(replay.componentProof.code, 'context-mismatch', 'a binding issued for another context is a replay');
  const dup = ctxFor(g, [rec], [good, good, { ...good }]).paths.find((p) => p.id === exposure.id).exploitability;
  assert.equal(dup.label, 'exploitable-confirmed'); assert.equal(dup.bindingId.length, 16);
  const bad = ctxFor(g, [rec], [{ ...good, effect: 'x' }, { ...good, effect: 'x' }]).paths.find((p) => p.id === exposure.id).exploitability;
  assert.equal(bad.componentProof.diagnostics.length, 1, 'an exact duplicate is judged once');
});
