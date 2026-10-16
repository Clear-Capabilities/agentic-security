// E7-03: a signed release assurance package that an independent offline verifier accepts when intact and rejects when tampered with, reordered, re-signed
// with a substituted key or stripped of mandatory evidence; integrity is kept apart from proof of exploitability.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { buildSamples } from '../../../scripts/engineering-excellence/lib/evidence-samples.mjs';
import { buildSnapshotRef } from '../../src/posture/assurance/evidence-registry.js';
import { MANDATORY_KINDS, buildReleasePackage, signReleasePackage, signedBytes } from '../../src/posture/assurance/release-package.js';
import { verifyReleasePackage, MINIMUM_KINDS } from '../../src/posture/assurance/release-package-verify.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const VERIFIER = path.join(ROOT, 'scripts', 'verify-release-package.mjs');
const { samples, finding } = await buildSamples();
const keys = () => { const k = crypto.generateKeyPairSync('ed25519'); return { priv: k.privateKey.export({ type: 'pkcs8', format: 'pem' }), pub: k.publicKey.export({ type: 'spki', format: 'pem' }) }; };
const K = keys(); const OTHER = keys();
const snap = buildSnapshotRef({ commit: 'a'.repeat(40), engineVersion: 'test' });
const completeHealth = { ...samples['scan-health'], status: 'complete', conditions: [] };
const unproven = { ...finding, proofTier: 'unproven' }; const proven = { ...finding, proofTier: 'execution-proven' };

function pkgBody({ health = completeHealth, f = unproven, extra = [], required = [], assertions, drop = [] } = {}) {
  let evidence = [
    { kind: 'scan-health', payload: health }, { kind: 'finding', payload: f },
    { kind: 'finding-evidence', payload: samples['finding-evidence'], restsOn: [1] },
    { kind: 'fix-verification', payload: samples['fix-verification'], restsOn: [1, 2] },
    { kind: 'sbom', payload: samples.sbom }, { kind: 'compliance-evidence', payload: samples['compliance-evidence'] }, ...extra,
  ];
  evidence = evidence.filter((e) => !drop.includes(e.kind));
  return buildReleasePackage({ snapshot: snap, evidence, requiredKinds: required, policyDecisions: [{ id: 'p1', outcome: 'allow', reason: 'test', policyVersion: '1' }], assertions: assertions || [{ id: 'a1', text: 'the scan finished', status: 'supported', evidence: [0] }, { id: 'a2', text: 'some files were not analysed', status: 'unknown', reason: 'not assessed', evidence: [] }] });
}
const signed = (o) => signReleasePackage(pkgBody(o), K.priv);
const verify = (p, key = K.pub, opts) => verifyReleasePackage(p, key, opts);
const codes = (r) => [...new Set(r.errors.map((e) => e.code))].sort();
const clone = (o) => JSON.parse(JSON.stringify(o));

test('an intact package verifies, with the offline verifier alone and from the command line', () => {
  const p = signed(); const r = verify(p);
  assert.deepEqual(r.errors, []); assert.equal(r.ok, true); assert.equal(r.completeness, 'complete');
  assert.equal(p.issuance.independentlyCertified, false, 'self-issued, and it says so inside the signed bytes');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-03-'));
  try {
    fs.writeFileSync(path.join(dir, 'p.json'), JSON.stringify(p)); fs.writeFileSync(path.join(dir, 'pub.pem'), K.pub); fs.writeFileSync(path.join(dir, 'other.pem'), OTHER.pub);
    const ok = spawnSync(process.execPath, [VERIFIER, path.join(dir, 'p.json'), '--public-key', path.join(dir, 'pub.pem')], { encoding: 'utf8' });
    assert.equal(ok.status, 0, ok.stderr); assert.match(ok.stdout, /release package verified: scan complete/);
    const bad = spawnSync(process.execPath, [VERIFIER, path.join(dir, 'p.json'), '--public-key', path.join(dir, 'other.pem')], { encoding: 'utf8' });
    assert.equal(bad.status, 1); assert.match(bad.stderr, /SIGNATURE/); assert.match(bad.stderr, /REJECTED/);
    assert.equal(spawnSync(process.execPath, [VERIFIER], { encoding: 'utf8' }).status, 2, 'missing arguments are an input error, not a verdict');
    assert.equal(spawnSync(process.execPath, [VERIFIER, path.join(dir, 'missing.json'), '--public-key', path.join(dir, 'pub.pem')], { encoding: 'utf8' }).status, 2);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the verifier is independent: it imports only Node built-ins, the command-line wrapper adds nothing but the file system, and the minimum it holds matches the producer\'s', () => {
  const importsOf = (file) => [...fs.readFileSync(file, 'utf8').matchAll(/^import .* from '([^']+)'/gm)].map((m) => m[1]).sort();
  assert.deepEqual(importsOf(path.join(ROOT, 'scanner', 'src', 'posture', 'assurance', 'release-package-verify.js')), ['node:crypto'], 'the verifier shares no code with the producer');
  assert.deepEqual(importsOf(VERIFIER), ['../scanner/src/posture/assurance/release-package-verify.js', 'node:fs', 'node:url']);
  assert.deepEqual([...MINIMUM_KINDS], [...MANDATORY_KINDS]);
});

test('TAMPERED FIELDS: a changed record, reference, snapshot, summary or statement is each caught', () => {
  const base = signed();
  const mut = (fn) => { const p = clone(base); fn(p); return verify(p); };
  assert.ok(codes(mut((p) => { p.evidence[1].payload.severity = 'low'; })).includes('SIGNATURE'));
  assert.ok(codes(mut((p) => { p.evidence[1].payload.severity = 'low'; })).includes('EVIDENCE'), 'and the record no longer matches its own reference');
  assert.ok(codes(mut((p) => { p.evidence[0].ref.payloadId = 'x'; })).includes('EVIDENCE'));
  assert.ok(codes(mut((p) => { p.snapshot.commit = 'b'.repeat(40); })).includes('SNAPSHOT'));
  assert.ok(codes(mut((p) => { p.snapshot.dirty = true; })).includes('SNAPSHOT'));
  assert.ok(codes(mut((p) => { p.assertions[0].text = 'everything is fine'; })).includes('SIGNATURE'));
  assert.ok(codes(mut((p) => { p.policy.decisions[0].outcome = 'deny'; })).includes('SIGNATURE'));
  assert.ok(codes(mut((p) => { p.completeness.verdict = 'incomplete'; })).includes('SIGNATURE'));
  assert.ok(codes(mut((p) => { p.proves = 'This package proves the product is secure.'; })).includes('SIGNATURE'));
  assert.ok(codes(mut((p) => { p.verdict = 'safe to deploy'; })).includes('FORMAT'), 'a key stapled on after signing is refused outright');
  assert.ok(codes(mut((p) => { p.schemaVersion = '2.0.0'; })).includes('FORMAT'));
  assert.ok(codes(mut((p) => { p.schema = 'x'; })).includes('FORMAT'));
  assert.equal(verify(null).ok, false);
});

test('REORDERING: swapping two records, or the stated order, is caught by the signature and by the dependency check', () => {
  const base = signed();
  const swapped = clone(base); [swapped.evidence[0], swapped.evidence[1]] = [swapped.evidence[1], swapped.evidence[0]];
  const r = verify(swapped); assert.ok(codes(r).includes('SIGNATURE')); assert.ok(codes(r).includes('LINEAGE'));
  const order = clone(base); order.lineageOrder = [...order.lineageOrder].reverse();
  assert.ok(codes(verify(order)).includes('SIGNATURE'));
  // the key holder signs a package whose list is out of dependency order: the signature is valid, the order is still refused
  const own = pkgBody(); own.evidence = [own.evidence[3], ...own.evidence.filter((_, i) => i !== 3)]; own.lineageOrder = own.evidence.map((e) => e.ref.digest);
  const resigned = signReleasePackage(own, K.priv);
  const rr = verify(resigned); assert.equal(rr.ok, false); assert.ok(codes(rr).includes('LINEAGE'), JSON.stringify(rr.errors));
  assert.ok(!codes(rr).includes('SIGNATURE'));
});

test('SIGNATURE SUBSTITUTION: another package\'s signature, another key, a swapped issuer and a missing signature are each rejected', () => {
  const a = signed(); const b = signed({ f: proven });
  const lifted = clone(a); lifted.signature = b.signature;
  assert.ok(codes(verify(lifted)).includes('SIGNATURE'), 'a valid signature from a different package does not verify');
  assert.ok(codes(verify(a, OTHER.pub)).includes('SIGNATURE'), 'the wrong public key');
  // an attacker edits the package, signs it with their own key, and names their own key
  const forged = clone(a); forged.evidence[1].payload.severity = 'info';
  const attacker = signReleasePackage((({ signature, issuance, ...rest }) => rest)(forged), OTHER.priv);
  assert.equal(verify(attacker, OTHER.pub).ok, false, 'it fails on the evidence digests even under its own key');
  const consistent = signReleasePackage(pkgBody(), OTHER.priv);
  assert.equal(verify(consistent, OTHER.pub).ok, true, 'a correctly built package verifies under the key that made it');
  const mism = verify(consistent, K.pub); assert.equal(mism.ok, false); assert.ok(codes(mism).includes('SIGNATURE'), 'but not under a key the verifier was not given');
  const swappedIssuer = clone(a); swappedIssuer.issuance.issuer.keyFingerprint = crypto.createHash('sha256').update(crypto.createPublicKey(OTHER.pub).export({ type: 'spki', format: 'der' })).digest('hex');
  assert.ok(codes(verify(swappedIssuer, OTHER.pub)).includes('SIGNATURE'), 'naming another key in the package does not make that key the signer');
  const unsigned = clone(a); delete unsigned.signature; assert.ok(codes(verify(unsigned)).includes('SIGNATURE'));
  assert.ok(codes(verify(a, null)).includes('SIGNATURE')); assert.ok(codes(verify(a, 'not a key')).includes('SIGNATURE'));
  const wrongAlg = clone(a); wrongAlg.signature.algorithm = 'rsa'; assert.ok(codes(verify(wrongAlg)).includes('SIGNATURE'));
  const certified = clone(a); certified.issuance.independentlyCertified = true; assert.ok(codes(verify(certified)).includes('SIGNATURE'));
});

test('MISSING MANDATORY EVIDENCE: a package without a scan health or without findings is refused even when properly signed, and its own list cannot lower the bar', () => {
  const noHealth = (() => { const b = buildReleasePackage({ snapshot: snap, evidence: [{ kind: 'finding', payload: unproven }, { kind: 'sbom', payload: samples.sbom }] }); return signReleasePackage(b, K.priv); })();
  const r = verify(noHealth); assert.equal(r.ok, false); assert.match(r.errors.map((e) => e.message).join(' '), /required evidence is missing: scan-health/);
  const noFinding = signReleasePackage(buildReleasePackage({ snapshot: snap, evidence: [{ kind: 'scan-health', payload: completeHealth }, { kind: 'sbom', payload: samples.sbom }] }), K.priv);
  assert.match(verify(noFinding).errors.map((e) => e.message).join(' '), /missing: finding/);
  // a package whose own list drops the minimum
  const lowered = pkgBody(); lowered.requiredKinds = []; const sl = signReleasePackage(lowered, K.priv);
  assert.match(verify(sl).errors.map((e) => e.message).join(' '), /does not declare "scan-health" as required/);
  // evidence removed AFTER signing
  const stripped = clone(signed()); stripped.evidence = stripped.evidence.filter((e) => e.ref.kind !== 'scan-health');
  const sr = verify(stripped); assert.equal(sr.ok, false); assert.ok(codes(sr).includes('SIGNATURE')); assert.ok(codes(sr).includes('MANDATORY'));
  // the caller's own requirement
  assert.equal(verify(signed(), K.pub, { require: ['provenance-evidence'] }).ok, false);
  assert.match(verify(signed(), K.pub, { require: ['provenance-evidence'] }).errors[0].message, /missing: provenance-evidence/);
  assert.equal(verify(signed({ required: ['sbom'] }), K.pub, { require: ['sbom'] }).ok, true);
  assert.throws(() => buildReleasePackage({ snapshot: snap, evidence: [] }), /at least one evidence/);
  assert.throws(() => buildReleasePackage({ snapshot: { ...snap, commit: 'b'.repeat(40) }, evidence: [{ kind: 'finding', payload: finding }] }), /snapshot reference/);
});

test('COMPLETENESS: a package cannot call an incomplete scan complete, even when the key holder signs it that way', () => {
  const honest = signed({ health: samples['scan-health'] });
  const real = samples['scan-health'].status;
  assert.equal(verify(honest).ok, true, 'a package over an incomplete scan is valid and says so'); assert.equal(honest.completeness.verdict, real === 'complete' ? 'complete' : 'incomplete');
  const incompleteHealth = { ...samples['scan-health'], status: 'partial', conditions: ['1 analyzer(s) threw on at least one file'] };
  const p = signed({ health: incompleteHealth });
  assert.equal(p.completeness.verdict, 'incomplete'); assert.equal(verify(p).ok, true); assert.deepEqual(p.completeness.conditions, incompleteHealth.conditions);
  const lie = pkgBody({ health: incompleteHealth }); lie.completeness.verdict = 'complete';
  const r = verify(signReleasePackage(lie, K.priv)); assert.equal(r.ok, false); assert.ok(codes(r).includes('COMPLETE')); assert.ok(!codes(r).includes('SIGNATURE'));
  const hide = pkgBody({ health: incompleteHealth }); hide.completeness.conditions = [];
  assert.ok(codes(verify(signReleasePackage(hide, K.priv))).includes('COMPLETE'));
  const wrongSource = pkgBody(); wrongSource.completeness.source = 'sha256:' + '0'.repeat(64);
  assert.ok(codes(verify(signReleasePackage(wrongSource, K.priv))).includes('COMPLETE'));
});

test('INTEGRITY IS NOT EXPLOITABILITY: each finding carries its proof tier, the summary cannot say more than the finding does', () => {
  const u = signed({ f: unproven }); const e = signed({ f: proven });
  assert.deepEqual(u.findings.map((f) => [f.integrity, f.proofTier, f.exploitabilityProven]), [['unmodified-since-signing', 'unproven', false]]);
  assert.deepEqual(e.findings.map((f) => [f.proofTier, f.exploitabilityProven]), [['execution-proven', true]]);
  assert.match(u.doesNotProve, /real or exploitable/); assert.match(u.proves, /Nothing in this package changed/);
  const lie = pkgBody({ f: unproven }); lie.findings[0].exploitabilityProven = true;
  const r = verify(signReleasePackage(lie, K.priv)); assert.equal(r.ok, false); assert.match(r.errors.map((x) => x.message).join(' '), /exploitability is stated as proven without an execution proof/);
  const lie2 = pkgBody({ f: unproven }); lie2.findings[0].proofTier = 'execution-proven';
  assert.match(verify(signReleasePackage(lie2, K.priv)).errors.map((x) => x.message).join(' '), /summary says proof tier "execution-proven" but the finding says "unproven"/);
  const hidden = pkgBody({ f: unproven }); hidden.findings = [];
  assert.match(verify(signReleasePackage(hidden, K.priv)).errors.map((x) => x.message).join(' '), /lists 0 findings but contains 1/);
});

test('ASSERTIONS and ROLES: statements cite records that are present, "supported" needs a citation, unknowns are carried, finding and control evidence are labelled', () => {
  const p = signed();
  assert.deepEqual(p.assertions.map((a) => [a.id, a.status]), [['a1', 'supported'], ['a2', 'unknown']]); assert.equal(p.assertions[1].reason, 'not assessed');
  const roles = Object.fromEntries(p.evidence.map((e) => [e.ref.kind, e.role]));
  assert.equal(roles.finding, 'finding'); assert.equal(roles['fix-verification'], 'finding'); assert.equal(roles['compliance-evidence'], 'control'); assert.equal(roles.sbom, 'inventory'); assert.equal(roles['scan-health'], 'completeness');
  const ghost = pkgBody(); ghost.assertions[0].evidence = ['sha256:' + '9'.repeat(64)];
  assert.match(verify(signReleasePackage(ghost, K.priv)).errors.map((x) => x.message).join(' '), /cites a record that is not in the package/);
  const empty = pkgBody({ assertions: [{ id: 'x', text: 'trust me', status: 'supported', evidence: [] }] });
  assert.match(verify(signReleasePackage(empty, K.priv)).errors.map((x) => x.message).join(' '), /"supported" but cites nothing/);
  assert.throws(() => pkgBody({ assertions: [{ id: 'x', text: 't', status: 'supported', evidence: [99] }] }), /does not exist/);
});

test('the package is deterministic and the signed bytes carry a domain label', () => {
  const a = pkgBody(); const b = pkgBody();
  assert.equal(JSON.stringify(a), JSON.stringify(b)); assert.match(signedBytes(a).toString('utf8'), /^agentic-security\/release-package@1\n\{/);
  const withSig = signReleasePackage(a, K.priv); assert.equal('signature' in JSON.parse(signedBytes(withSig).toString('utf8').slice(signedBytes(withSig).toString('utf8').indexOf('\n') + 1)), false, 'the package\'s own signature is never part of what it signs');
  assert.throws(() => buildReleasePackage({ snapshot: snap, evidence: [{ kind: 'finding', payload: finding, restsOn: [0] }] }), /rests on itself/);
  assert.throws(() => buildReleasePackage({ snapshot: snap, evidence: [{ kind: 'finding', payload: finding, restsOn: [5] }] }), /does not exist/);
});
