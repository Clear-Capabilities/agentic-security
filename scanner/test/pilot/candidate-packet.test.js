// Threat-model PRD FR-10.3, FR-10.4, AC-10C and section 8 ("local, independent and staging verification kept separate"): candidate
// packets assembled from real runs of the pilot fixtures, the `release-package qualify` surface over them, evidence tiers that never
// stand in for each other, and decisions that an upgrade, a policy change or an expiry invalidates while a rollback is covered only by
// the earlier artifact's own decision.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { assemblePilotPacket } from '../fixtures/pilot/assemble-packet.mjs';
import { artifactDigest } from '../fixtures/pilot/records-service.mjs';
import { evaluateCandidate, signCandidatePacket, verifyCandidatePacket, revalidateDecision } from '../../src/posture/assurance/candidate-qualification.js';
import { cmdReleasePackage } from '../../src/posture/assurance/release-package-cli.js';
import { runQualification } from '../../../bench/threat-model-pilot/qualify.mjs';

const NOW = Date.parse('2026-11-08T12:00:00Z');
const keys = () => { const k = crypto.generateKeyPairSync('ed25519'); return { priv: k.privateKey.export({ type: 'pkcs8', format: 'pem' }), pub: k.publicKey.export({ type: 'spki', format: 'pem' }) }; };
let cached;
const packets = async () => (cached ??= await assemblePilotPacket({ now: NOW, scannerBundle: 'sha256:bundle' }));
const clone = (x) => JSON.parse(JSON.stringify(x));

test('the assembled pilot packets meet every local case, and what this host cannot run is recorded as blocked, never left out', async () => {
  const ps = await packets();
  assert.deepEqual(Object.keys(ps), ['records-service', 'export-chain', 'records-search'], 'one packet per deployment identity (FR-08.2)');
  for (const [id, p] of Object.entries(ps)) {
    const d = evaluateCandidate(p, { now: NOW });
    for (const c of d.cases.filter((x) => x.tier === 'local' && x.outcome !== 'blocked')) assert.equal(c.outcome, 'met', `${id} ${c.caseId}: ${c.reason}`);
    assert.equal(d.status, 'not-qualified', `${id}: no attested runner, scope or independent measurement, so no qualification`);
  }
  const rec = evaluateCandidate(ps['records-service'], { now: NOW });
  for (const id of ['PILOT-01', 'PILOT-02', 'PILOT-03', 'PILOT-04', 'PILOT-05', 'PILOT-06', 'PILOT-07', 'PILOT-08']) assert.ok(rec.cases.some((c) => c.caseId === id), id);
  for (const id of ['PILOT-09', 'PILOT-10', 'PILOT-11']) assert.equal(rec.cases.find((c) => c.caseId === id).outcome, 'blocked', id);
  assert.equal(rec.gates['G-03'].outcome, 'blocked', 'the critical pilot gate needs the independently held variant');
  for (const id of ['export-chain', 'records-search']) assert.equal(evaluateCandidate(ps[id], { now: NOW, requiredGates: ['G-03'] }).status, 'qualified', id);
  // sanitized: no credential, no protected marker, no raw log line in any packet
  const text = JSON.stringify(ps);
  assert.ok(!/token-tenant|not-a-valid-token|Bearer|MARKER-|request_id/.test(text), 'the packets carry observations and digests, not secrets or bodies');
});

test('evidence tiers are separate qualifications: local detection cases never satisfy a gate that requires staging evidence', async () => {
  const p = clone((await packets())['records-service']);
  p.cases = p.cases.filter((c) => c.caseId !== 'PILOT-10');
  assert.equal(evaluateCandidate(p, { now: NOW, requiredGates: ['G-05'] }).gates['G-05'].outcome, 'met', 'local evidence alone meets a gate with no tier requirement');
  const strict = evaluateCandidate(p, { now: NOW, requiredGates: ['G-05'], requiredTiers: { 'G-05': 'staging' } }).gates['G-05'];
  assert.equal(strict.outcome, 'unresolved');
  assert.match(strict.reasons.join(), /no staging evidence for this gate \(\d+ case\(s\) of another tier do not count\)/);
  const staged = { ...p, cases: [...p.cases, { ...p.cases.find((c) => c.caseId === 'PILOT-01-detect'), caseId: 'STAGE-01', tier: 'staging' }] };
  assert.equal(evaluateCandidate(staged, { now: NOW, requiredGates: ['G-05'], requiredTiers: { 'G-05': 'staging' } }).gates['G-05'].outcome, 'met', 'a staging case meets it');
  const odd = { ...p, cases: [{ ...p.cases[0], tier: 'production' }] };
  assert.match(evaluateCandidate(odd, { now: NOW }).cases[0].reason, /unknown evidence tier/);
  // a detection case that does not say whether the rule fired stays open
  const silent = { ...p, cases: [{ ...p.cases.find((c) => c.kind === 'detection'), observed: {} }] };
  assert.equal(evaluateCandidate(silent, { now: NOW }).cases[0].outcome, 'unresolved');
});

test('FR-10.4: an upgrade or policy change invalidates a decision, a rollback is covered only by the earlier artifact\'s own decision, and expiry ends it', async () => {
  const chain = clone((await packets())['export-chain']);
  const d = evaluateCandidate(chain, { now: NOW, requiredGates: ['G-03'] });
  assert.equal(d.status, 'qualified');
  const t = { artifactDigest: chain.target.artifactDigest, policyDigest: chain.target.policyDigest, scannerBundle: 'sha256:bundle' };
  assert.equal(revalidateDecision(d, t, { packet: chain, now: NOW }).valid, true);
  assert.match(revalidateDecision(d, { ...t, artifactDigest: 'sha256:upgraded' }).reason, /artifact differs/);
  assert.match(revalidateDecision(d, { ...t, policyDigest: 'sha256:other-policy' }).reason, /policy differs/);
  assert.match(revalidateDecision(d, { ...t, scannerBundle: 'sha256:newer-scanner' }).reason, /scanner bundle differs/);
  assert.match(revalidateDecision(d, t, { packet: { ...chain, cases: chain.cases.slice(1) }, now: NOW }).reason, /not the one the decision was computed from/);
  assert.match(revalidateDecision(d, t, { packet: chain, now: NOW + 30 * 24 * 3600 * 1000 }).reason, /expired/);
  // a rollback: the upgraded artifact's evidence does not qualify the earlier one, but the earlier one's own decision still does
  const upgraded = { ...chain, target: { ...chain.target, artifactDigest: 'sha256:v2' }, cases: chain.cases.map((c) => ({ ...c, artifactDigest: 'sha256:v2' })) };
  const dv2 = evaluateCandidate(upgraded, { now: NOW, requiredGates: ['G-03'] });
  assert.equal(dv2.status, 'qualified');
  assert.equal(revalidateDecision(dv2, t).valid, false, 'the v2 decision says nothing about the rolled-back v1');
  assert.equal(revalidateDecision(d, t, { packet: chain, now: NOW }).valid, true, 'v1 is covered by its own unexpired decision');
  assert.match(revalidateDecision(evaluateCandidate(chain, { now: NOW }), t).reason, /did not qualify/);
});

test('compatibility: a packet of another version is refused by name, and the signature covers the tier and every case', async () => {
  const { priv, pub } = keys();
  const signed = signCandidatePacket((await packets())['records-search'], priv);
  assert.equal(verifyCandidatePacket(signed, pub).ok, true);
  assert.equal(verifyCandidatePacket({ ...signed, version: 2 }, pub).code, 'UNSUPPORTED_VERSION');
  assert.equal(verifyCandidatePacket({ ...signed, version: 0 }, pub).code, 'UNSUPPORTED_VERSION');
  assert.equal(verifyCandidatePacket({ ...signed, schema: 'other' }, pub).code, 'FORMAT');
  const promoted = { ...signed, cases: signed.cases.map((c) => ({ ...c, tier: 'staging' })) };
  assert.equal(verifyCandidatePacket(promoted, pub).code, 'SIGNATURE', 'relabelling local evidence as staging breaks the signature');
});

test('release-package qualify: exit 0 only when qualified, 1 for not qualified or a bad packet, 2 for usage; it writes the decision once', async () => {
  const dir = mkTestTmp('qualify-cli-');
  const { priv, pub } = keys();
  fs.writeFileSync(path.join(dir, 'pub.pem'), pub);
  const ps = await packets();
  for (const id of Object.keys(ps)) fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(signCandidatePacket(ps[id], priv)));
  const run = async (argv) => {
    const out = []; const err = [];
    const _ = []; const flags = {};
    for (let i = 0; i < argv.length; i++) if (argv[i].startsWith('--')) { const k = argv[i].slice(2); flags[k] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true; } else _.push(argv[i]);
    const code = await cmdReleasePackage({ _, flags }, { out: (s) => out.push(s), err: (s) => err.push(s) });
    return { code, out: out.join('\n'), err: err.join('\n') };
  };
  const pk = path.join(dir, 'pub.pem');
  // the fixture cases expire a week after NOW, and the CLI judges against the real clock, so these packets are judged as of today
  let r = await run(['release-package', 'qualify', path.join(dir, 'export-chain.json'), '--public-key', pk, '--require-gate', 'G-03', '--output', path.join(dir, 'decision.json')]);
  if (Date.now() < NOW + 7 * 24 * 3600 * 1000) {
    assert.equal(r.code, 0, r.err || r.out); assert.match(r.out, /candidate QUALIFIED for export-chain/);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'decision.json'), 'utf8')).status, 'qualified');
  } else assert.equal(r.code, 1, 'expired evidence keeps the candidate open');
  r = await run(['release-package', 'qualify', path.join(dir, 'records-service.json'), '--public-key', pk, '--require-tier', 'G-05=staging']);
  assert.equal(r.code, 1); assert.match(r.out, /NOT QUALIFIED/); assert.match(r.out, /G-04 evidence and harness integrity: blocked/);
  r = await run(['release-package', 'qualify', path.join(dir, 'records-service.json'), '--public-key', pk, '--format', 'json']);
  assert.equal(JSON.parse(r.out).status, 'not-qualified');
  const tampered = JSON.parse(fs.readFileSync(path.join(dir, 'export-chain.json'), 'utf8')); tampered.cases[1].observed.forbiddenEffect = false; tampered.cases[0].observed.forbiddenEffect = true;
  tampered.target.service = 'renamed';
  fs.writeFileSync(path.join(dir, 'tampered.json'), JSON.stringify(tampered));
  r = await run(['release-package', 'qualify', path.join(dir, 'tampered.json'), '--public-key', pk]);
  assert.equal(r.code, 1); assert.match(r.err, /SIGNATURE/);
  assert.equal((await run(['release-package', 'qualify', path.join(dir, 'export-chain.json')])).code, 2, 'no key is a usage error');
  assert.equal((await run(['release-package', 'qualify', path.join(dir, 'export-chain.json'), '--public-key', pk, '--require-gate', 'G-99'])).code, 2);
  assert.equal((await run(['release-package', 'qualify', path.join(dir, 'export-chain.json'), '--public-key', pk, '--require-tier', 'G-05=prod'])).code, 2);
  assert.equal((await run(['release-package', 'qualify', path.join(dir, 'missing.json'), '--public-key', pk])).code, 2);
});

test('the bench runner writes signed packets and decisions that the qualify surface reads, and reports no local regression', async () => {
  const out = mkTestTmp('tm-pilot-');
  const r = await runQualification({ out, now: Date.now() });
  assert.deepEqual(r.regressions, []);
  for (const id of ['records-service', 'export-chain', 'records-search']) {
    const p = JSON.parse(fs.readFileSync(path.join(out, `${id}.packet.json`), 'utf8'));
    assert.equal(verifyCandidatePacket(p, fs.readFileSync(path.join(out, 'public.pem'), 'utf8')).ok, true, id);
    assert.equal(JSON.parse(fs.readFileSync(path.join(out, `${id}.decision.json`), 'utf8')).status, 'not-qualified', id);
  }
  assert.equal(r.results['records-service'].scope.artifactDigest, artifactDigest('fixed'));
  assert.equal(r.results['records-service'].gates['G-05'].outcome, 'blocked', 'the staging drill is a blocker, not a pass');
});
