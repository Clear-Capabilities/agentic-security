// Epics H and G on the slice: the semantic mutation population judged by the real oracle and repair verifier, a status-only judge
// shown to miss a durable effect, the observation-to-regression workflow, and the isolated shadow comparison. H-AC01..H-AC04,
// G-AC01..G-AC03, G-AC05, G-AC06. Execution goes through the trust boundary; where this host cannot run it the tests say so and stop.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runMutationPopulation } from '../../src/posture/evaluation/semantic-mutations.js';
import { discrepancies, propose, regressionRecord, shadowCompare } from '../../src/contracts/runtime-feedback.js';
import { createInvariant } from '../../src/posture/invariants/schema.js';
import { verifyInvariant } from '../../src/posture/invariants/run.js';
import { emptyLedger, recordTransition } from '../../src/posture/invariants/lifecycle.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const F = path.join(HERE, '..', 'fixtures', 'contract-slice');
const vulnerable = fs.readFileSync(path.join(F, 'service.mjs'), 'utf8');
const patched = fs.readFileSync(path.join(HERE, '..', 'fixtures', 'contract-slice-patch', 'service.mjs'), 'utf8');
const contract = JSON.parse(fs.readFileSync(path.join(F, 'security', 'contracts', 'invoices-service', 'contract.json'), 'utf8'));
const inv = createInvariant(JSON.parse(fs.readFileSync(path.join(F, 'invariants', 'invoices-tenant-isolation.json'), 'utf8')));
const config = resolveAssuranceConfig({ env: {}, overrides: { features: { 'invariant-scenarios': true, 'verification-oracles': true, 'patch-negative-verification': true, 'invariant-repair': true } } });
const commit = contract.scope.repositories[0].revision;
const REVIEWER = { id: 'dana', kind: 'human' }; const POLICY = { id: 'p', reviewers: ['dana'] };
let ledger = recordTransition(emptyLedger(), { action: 'propose', invariant: inv, actor: { id: 'o', kind: 'code' }, reason: 'slice' }).ledger;
ledger = recordTransition(ledger, { action: 'approve', invariantId: inv.id, actor: REVIEWER, reason: 'slice' }, { policy: POLICY }).ledger;
const skip = sandboxAvailable() ? false : 'no confinement backend on this host';

test('H-AC01/H-AC02/H-AC03/H-AC04: every mutant is accounted for; the durable-state oracle kills the denial-after-write mutant the status-only judge misses; oracle rewrites are refused', { skip }, async () => {
  const rep = await runMutationPopulation({ invariant: inv, ledger, fixtureText: vulnerable, patchedText: patched, commit, config });
  const by = Object.fromEntries(rep.results.map((r) => [r.id, r.outcome]));
  assert.equal(by['remove-write-tenant-predicate'], 'killed');
  assert.equal(by['authorization-after-write'], 'killed', 'the business-state oracle sees the write behind the 404');
  assert.equal(by['status-only-judge'], 'survived', 'a status-only judge calls the same mutant safe');
  assert.equal(by['remove-read-tenant-predicate'], 'survived', 'a contract that forbids only writes does not see a cross-tenant read: reported, not removed');
  assert.equal(by['deny-everyone'], 'killed'); assert.equal(by['scope-by-principal-id'], 'killed');
  assert.equal(by['comment-only'], 'equivalent');
  assert.equal(by['forged-receipt'], 'killed'); assert.equal(by['altered-approval-identity'], 'killed'); assert.equal(by['patch-rewrites-oracle'], 'killed');
  assert.equal(rep.scheduled, rep.results.length);
  assert.equal(Object.values(rep.counts).reduce((a, b) => a + b, 0), rep.scheduled, 'no mutant is dropped');
  assert.ok(rep.killRate > 0 && rep.killRate < 1, 'survivors lower the rate; they are not removed');
});

test('G-AC01/G-AC02/G-AC03/G-AC06: an unmodeled observed path becomes a reviewable discrepancy and a PROPOSED revision; a modeled path with no traffic is not-observed, never safe; an unknown or wrong build is a limitation', () => {
  const lines = [
    { ts: '2026-11-22T10:00:00Z', environment: 'isolated-test', route: { method: 'PUT', path: '/invoices/77/memo' }, destination: { service: 'invoices' } },
    { ts: '2026-11-22T10:01:00Z', environment: 'isolated-test', route: { method: 'DELETE', path: '/invoices/77' }, destination: { service: 'invoices' }, authorization: 'Bearer not-kept' },
    { ts: '2026-11-22T10:02:00Z', environment: 'production', route: { method: 'DELETE', path: '/invoices/9' }, destination: { service: 'invoices' } },
  ].map((x) => JSON.stringify(x)).join('\n');
  const modeledRoutes = ['GET /invoices/:id', 'PUT /invoices/:id/memo', 'POST /invoices'];
  const d = discrepancies({ traceText: lines, environment: 'isolated-test', contract, modeledRoutes, now: '2026-11-22T12:00:00Z' });
  assert.equal(d.imported.rejected, 1, 'the other environment\'s line is rejected');
  const un = d.records.filter((r) => r.kind === 'unmodeled-path');
  assert.deepEqual(un.map((r) => r.route), ['DELETE /invoices/:id']);
  assert.equal(un[0].buildBinding, 'unknown'); assert.ok(un[0].limitations.some((l) => /cannot be tied/.test(l)));
  assert.deepEqual(d.records.filter((r) => r.kind === 'not-observed-in-window').map((r) => r.route).sort(), ['GET /invoices/:id', 'POST /invoices']);
  assert.ok(d.records.filter((r) => r.kind === 'not-observed-in-window').every((r) => /not evidence that the path is unreachable/.test(r.limitations[0])));
  const wrongBuild = discrepancies({ traceText: lines, environment: 'isolated-test', contract, modeledRoutes, build: { revision: 'f'.repeat(40) }, now: '2026-12-22T12:00:00Z' });
  const w = wrongBuild.records.find((r) => r.kind === 'unmodeled-path');
  assert.equal(w.buildBinding, 'mismatched'); assert.equal(w.stale, true);
  const p = propose(contract, un[0], { invariantId: 'TENANT-ISOLATION-001' });
  assert.equal(p.ok, true); assert.equal(p.contract.review.state, 'proposed'); assert.equal(p.contract.version, '1.1.0');
  assert.ok(p.contract.invariants[0].scope.routes.includes('DELETE /invoices/:id'));
  assert.equal(p.scenarioRequest.incomplete, true, 'the trace carries no request body; a synthetic reconstruction is required');
  const rec = regressionRecord({ discrepancy: un[0], proposalRef: p.contractRef, approval: { state: 'proposed' }, replay: null });
  assert.equal(rec.status, 'awaiting-approval'); assert.equal(rec.sealedEligible, false);
});

test('G-AC04/G-AC05: the shadow comparison replays one workload against separate baseline and patched runs; the correct patch passes, a patch that breaks the authorized workflow fails with both reports kept', { skip }, async () => {
  const run = (text) => verifyInvariant({ invariant: inv, fixture: { files: { 'service.mjs': text } }, commit, config, ledger });
  const base = await run(vulnerable);
  const good = shadowCompare({ baseline: base, patched: await run(patched) });
  assert.equal(good.status, 'pass'); assert.ok(good.fixedForbidden.length >= 1, 'the forbidden write the baseline reached is gone');
  const denyAll = patched.replace('export function setInvoiceMemo(db, principal, key, payload) {', 'export function setInvoiceMemo(db, principal, key, payload) {\n  return { status: 403 };');
  const bad = shadowCompare({ baseline: base, patched: await run(denyAll) });
  assert.equal(bad.status, 'fail'); assert.ok(bad.findings.some((f) => /authorized-workflow-regression/.test(f)));
  assert.equal(bad.baseline.completed, true); assert.equal(bad.patched.completed, true);
  assert.equal(shadowCompare({ baseline: { results: [] }, patched: base }).status, 'incomplete');
});
