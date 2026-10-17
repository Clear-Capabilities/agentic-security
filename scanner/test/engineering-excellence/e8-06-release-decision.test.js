// E8-06: the release decision is a function that blocks on the right things and cannot be turned green by relabelling a metric, dropping a gate or editing a flag.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { releaseDecision, gather, build } from '../../../scripts/engineering-excellence/final-report.mjs';
import { buildWaiver, signWaiver, evaluateWaiver } from '../../src/posture/assurance/waiver.js';
import { keyFingerprint } from '../../src/posture/evidence-bundle.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const tasks = [{ id: 'A-1', title: 'a', priority: 'P0' }, { id: 'A-2', title: 'b', priority: 'P1' }];
const green = () => ({ tasks, ledger: { 'A-1': { state: 'done' }, 'A-2': { state: 'pending' } }, exitGates: [{ epic: 'E0', status: 'met', evidence: ['x'], note: '' }, { epic: 'E3', status: 'partially_met', evidence: ['x'], note: 'one gap' }], unresolved: [{ id: 'U-1', title: 'open', blocksRelease: false }], gateRun: { verdict: 'PASSED' }, measurement: { measurementValid: true, releaseTrust: 'trusted' }, pathExists: () => true, evaluateWaiver });
const codes = (d) => d.blockers.map((b) => b.code);

test('WHEN NOTHING BLOCKS IT SAYS RELEASE READY, AND LISTS PARTIAL GATES AS CAVEATS RATHER THAN HIDING THEM', () => {
  const d = releaseDecision(green()); assert.equal(d.verdict, 'release_ready'); assert.deepEqual(d.blockers, []); assert.equal(d.caveats.length, 1); assert.match(d.caveats[0], /E3 exit gate partially met/);
});

test('EACH BLOCKING CONDITION BLOCKS ON ITS OWN, with its code', () => {
  const cases = [
    ['P0_TASK_INCOMPLETE', (g) => { g.ledger['A-1'] = { state: 'pending' }; }], ['TASK_FAILED_OR_BLOCKED', (g) => { g.ledger['A-2'] = { state: 'failed' }; }],
    ['GATE_NOT_PASSED', (g) => { g.gateRun = { verdict: 'FAILED' }; }], ['GATE_NOT_PASSED', (g) => { g.gateRun = null; }],
    ['MEASUREMENT_NOT_VALID', (g) => { g.measurement = { measurementValid: false, releaseTrust: 'trusted' }; }], ['MEASUREMENT_NOT_VALID', (g) => { g.measurement = { measurementValid: true, releaseTrust: 'untrusted' }; }],
    ['EXIT_GATE_NOT_MET', (g) => { g.exitGates[0] = { epic: 'E0', status: 'not_met', evidence: [], note: 'n' }; }], ['EXIT_GATE_NOT_MET', (g) => { g.exitGates[0] = { epic: 'E0', status: 'not_measured', evidence: [], note: 'n' }; }],
    ['UNRESOLVED_BLOCKER', (g) => { g.unresolved[0].blocksRelease = true; }],
  ];
  for (const [code, mutate] of cases) { const g = green(); mutate(g); const d = releaseDecision(g); assert.equal(d.verdict, 'release_blocked', code); assert.ok(codes(d).includes(code), code + ' ' + codes(d)); }
});

test('A METRIC CANNOT BE RELABELLED GREEN: an exit gate marked met with missing or absent evidence still blocks', () => {
  const g = green(); g.pathExists = (p) => p !== 'x'; assert.ok(codes(releaseDecision(g)).includes('EXIT_GATE_UNEVIDENCED'));
  const h = green(); h.exitGates[0] = { epic: 'E0', status: 'met', evidence: [], note: '' }; assert.ok(codes(releaseDecision(h)).includes('EXIT_GATE_UNEVIDENCED'), 'met with no evidence at all');
});

test('A BLOCKER CANNOT BE WAIVED BY A FLAG OR AN UNSIGNED OR EXPIRED WAIVER; ONLY A SIGNED, UNEXPIRED, JUSTIFIED WAIVER WITH A COMPENSATING CONTROL CLEARS THAT ITEM', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519'); const PRIV = privateKey.export({ type: 'pkcs8', format: 'pem' }); const PUB = publicKey.export({ type: 'spki', format: 'pem' });
  const mk = (over = {}) => buildWaiver({ tenant: 'tenant-1', environment: 'release', scope: { kind: 'rule', value: 'U-1' }, actor: { id: 'owner-1', role: 'maintainer' }, approvals: [{ id: 'approver-2', role: 'security' }], justification: 'the publish-time checks need network access that this environment lacks', compensatingControl: 'the checks are run by hand before the tag', createdAt: '2026-10-01T00:00:00Z', expiresAt: '2026-11-01T00:00:00Z', policyVersion: 1, ...over });
  const ctx = { now: Date.parse('2026-10-16T00:00:00Z'), tenant: 'tenant-1', environment: 'release', policy: { requireSignature: true }, trustedKeys: { [keyFingerprint(PUB)]: PUB } };
  const base = () => { const g = green(); g.unresolved[0].blocksRelease = true; g.waiverCtx = ctx; return g; };
  const flagOnly = base(); flagOnly.unresolved[0].waived = true; assert.equal(releaseDecision(flagOnly).verdict, 'release_blocked', 'a flag on the item changes nothing');
  const unsigned = base(); unsigned.waivers = [mk()]; assert.equal(releaseDecision(unsigned).verdict, 'release_blocked'); assert.match(releaseDecision(unsigned).blockers[0].message, /refused: .*unsigned/);
  const expired = base(); expired.waivers = [signWaiver(mk({ createdAt: '2026-08-01T00:00:00Z', expiresAt: '2026-09-01T00:00:00Z' }), PRIV)]; assert.match(releaseDecision(expired).blockers[0].message, /expired/);
  const otherScope = base(); otherScope.waivers = [signWaiver(mk({ scope: { kind: 'rule', value: 'U-9' } }), PRIV)]; assert.equal(releaseDecision(otherScope).verdict, 'release_blocked', 'a waiver for another item does not apply');
  const ok = base(); ok.waivers = [signWaiver(mk(), PRIV)]; const d = releaseDecision(ok); assert.equal(d.verdict, 'release_ready'); assert.match(d.caveats.join(' '), /U-1 waived by a signed waiver/);
});

test('THE RECORDED DECISION FOR THIS CHECKOUT IS RELEASE READY WITH CAVEATS, because the merge and release were authorised and done, no waiver exists, and the gaps are still listed', async () => {
  const g = await gather(); assert.deepEqual(g.waivers, []);
  const b = await build(); assert.equal(b.decision.verdict, 'release_ready'); assert.deepEqual(b.decision.blockers, [], 'no blocker stands');
  const resolved = g.list.filter((t) => t.id === 'E8-06'); assert.ok(resolved.length === 1);
  const caveats = b.decision.caveats.join(' '); assert.match(caveats, /E2 exit gate partially met/); assert.match(caveats, /E3 exit gate partially met/);
  const report = fs.readFileSync(path.join(ROOT, 'docs/engineering-excellence/FINAL_REPORT.md'), 'utf8'); assert.match(report, /RELEASE READY/); assert.match(report, /not a statement that the software is free of defects/);
});

test('THE E2 GATE IS ONLY PARTLY MET, AND THE ONE RECOVERY IS MEASURED: the evidence file shows a true positive gained, no false positive added, and the original behaviour for the other entries', () => {
  const gate = JSON.parse(fs.readFileSync(path.join(ROOT, 'scripts/engineering-excellence/data/exit-gates.json'), 'utf8')).gates.find((x) => x.epic === 'E2'); assert.equal(gate.status, 'partially_met');
  const ab = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs/engineering-excellence/data/u01-targeted-remeasurement.json'), 'utf8'));
  assert.deepEqual(ab.effectOnBaselineTotals, { localizedTruePositives: { before: 6, after: 7 }, localizedFalsePositives: { before: 13, after: 13 } });
  const won = ab.rows.filter((r) => r.now.tpLocal > r.baseline.tpLocal); assert.deepEqual(won.map((r) => r.id), ['GHSA-pmwx-rm49-xv39']);
  for (const r of ab.rows) { assert.ok(r.now.fpLocal <= r.baseline.fpLocal, r.id + ' gained no false positive'); assert.ok(r.now.tpLocal >= r.baseline.tpLocal, r.id + ' lost no true positive'); }
  assert.match(ab.caveat, /not a new baseline run/);
});
