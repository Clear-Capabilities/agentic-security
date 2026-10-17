// E7-07: three perspectives from one evidence set: they agree on finding ids, status, evidence hash and confidence; the offline report renders safely.
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
import { buildReleasePackage, signReleasePackage } from '../../src/posture/assurance/release-package.js';
import { verifyReleasePackage } from '../../src/posture/assurance/release-package-verify.js';
import { buildCanonicalFindings, buildViews, renderHtml, renderText } from '../../src/report/perspectives.js';
import { rankFleetExposure } from '../../src/posture/fleet/exposure-ranking.js';

// Deep analysis is off under CI unless asked for (engine.js); these tests need the deep layer, so a hosted runner must not change what they measure.
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const BIN = path.join(ROOT, 'scanner', 'bin', 'agentic-security.js');
const { samples, finding } = await buildSamples();
const k = crypto.generateKeyPairSync('ed25519'); const priv = k.privateKey.export({ type: 'pkcs8', format: 'pem' }); const pub = k.publicKey.export({ type: 'spki', format: 'pem' });
const snap = buildSnapshotRef({ commit: 'a'.repeat(40), engineVersion: 'test' });
const health = { ...samples['scan-health'], status: 'complete', conditions: [] };

function makePackage({ findings = [finding], fixVerified = true, partial = false, extraAssertions = [] } = {}) {
  const evidence = [{ kind: 'scan-health', payload: partial ? { ...health, status: 'partial', conditions: ['1 analyzer(s) threw on at least one file'] } : health }];
  findings.forEach((f) => evidence.push({ kind: 'finding', payload: f }));
  const fv = { ...samples['fix-verification'], findingId: String(findings[0].id), findingStableId: findings[0].stableId, verifiedFull: fixVerified, fixCompleteness: fixVerified ? 'FULL' : 'unverified', degradedLegs: fixVerified ? [] : [{ leg: 'behaviorTests', reason: 'not run' }] };
  evidence.push({ kind: 'fix-verification', payload: fv, restsOn: [1] });
  return signReleasePackage(buildReleasePackage({ snapshot: snap, evidence, assertions: [{ id: 'a1', text: 'the scan finished', status: partial ? 'unknown' : 'supported', reason: partial ? 'an analyzer failed' : undefined, evidence: partial ? [] : [0] }, ...extraAssertions] }), priv);
}
const f1 = { ...finding, id: 'f-1', stableId: 'sf-aaaa1111', severity: 'high', proofTier: 'execution-proven', confidence: 0.9, description: 'User input reaches a shell.', remediation: 'Pass arguments as an array.' };
const f2 = { ...finding, id: 'f-2', stableId: 'sf-bbbb2222', severity: 'medium', proofTier: 'unproven', confidence: 0.4, description: 'Maybe.', remediation: 'Validate.' };

test('ONE LIST, THREE PROJECTIONS: every view names the same findings with the same id, status, evidence hash and confidence', () => {
  const pkg = makePackage({ findings: [f1, f2] });
  const v = buildViews(pkg, { verification: verifyReleasePackage(pkg, pub) });
  const canon = new Map(v.canonical.map((f) => [f.id, f]));
  assert.deepEqual(v.canonical.map((f) => f.id).sort(), ['sf-aaaa1111', 'sf-bbbb2222']);
  for (const [name, list] of [['developer', v.developer], ['ciso', v.ciso.findings], ['auditor', v.auditor.findings]]) {
    assert.deepEqual(list.map((f) => f.id).sort(), [...canon.keys()].sort(), `${name} lists the same findings`);
    for (const f of list) { const c = canon.get(f.id); assert.equal(f.evidenceHash, c.evidenceHash, `${name} ${f.id} evidence`); assert.equal(f.status, c.status, `${name} ${f.id} status`); assert.equal(f.confidence, c.confidence, `${name} ${f.id} confidence`); }
  }
  assert.match(v.canonical[0].evidenceHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(canon.get('sf-aaaa1111').confidence, 'high'); assert.equal(canon.get('sf-bbbb2222').confidence, 'low');
  // the evidence hash is the finding's reference in the package, the thing an auditor can check
  const ref = pkg.evidence.find((e) => e.ref.kind === 'finding' && e.ref.payloadId === 'sf-aaaa1111').ref.digest; assert.equal(canon.get('sf-aaaa1111').evidenceHash, ref);
});

test('DEVELOPER: where, why and how to fix, with the fix\'s verification state; a fix that did not pass its checks says which', () => {
  const ok = buildViews(makePackage({ findings: [f1], fixVerified: true })).developer[0];
  assert.deepEqual(ok.where, { file: finding.file, line: finding.line }); assert.equal(ok.why, 'User input reaches a shell.'); assert.equal(ok.how, 'Pass arguments as an array.'); assert.equal(ok.status, 'fix-verified'); assert.equal(ok.fix.verifiedFull, true);
  const bad = buildViews(makePackage({ findings: [f1], fixVerified: false })).developer[0];
  assert.equal(bad.status, 'fix-unverified'); assert.deepEqual(bad.fix.degradedLegs, ['behaviorTests']);
  const none = buildViews(buildReleasePackage({ snapshot: snap, evidence: [{ kind: 'scan-health', payload: health }, { kind: 'finding', payload: f1 }] })).developer[0];
  assert.equal(none.status, 'open'); assert.equal(none.fix, null);
});

test('CISO: what is proven, the change since the last release, risk and coverage', () => {
  const prev = makePackage({ findings: [f2, { ...f1, id: 'f-9', stableId: 'sf-gone9999' }] });
  const cur = makePackage({ findings: [f1, f2] });
  const v = buildViews(cur, { previous: prev, verification: verifyReleasePackage(cur, pub) });
  assert.deepEqual(v.ciso.proven, { executionProven: 1, taintProven: 0, unproven: 1, total: 2 });
  assert.deepEqual(v.ciso.changeSinceLast.new, ['sf-aaaa1111']); assert.deepEqual(v.ciso.changeSinceLast.resolved, ['sf-gone9999']);
  // the fix check in the previous release was for sf-bbbb2222 (the first finding of that package); this release's is for sf-aaaa1111
  assert.deepEqual(v.ciso.changeSinceLast.statusChanged, [{ id: 'sf-bbbb2222', from: 'fix-verified', to: 'open' }]); assert.equal(v.ciso.changeSinceLast.unchanged, 0);
  assert.deepEqual(v.ciso.scan, { verdict: 'complete', scanStatus: 'complete', conditions: [] }); assert.equal(v.ciso.verified, true);
  assert.equal(buildViews(cur).ciso.changeSinceLast, null, 'no previous release: no change is invented'); assert.equal(buildViews(cur).ciso.verified, null);
  const incomplete = buildViews(makePackage({ findings: [f1], partial: true }));
  assert.equal(incomplete.ciso.scan.verdict, 'incomplete'); assert.deepEqual(incomplete.ciso.scan.conditions, ['1 analyzer(s) threw on at least one file']);
  const ranking = rankFleetExposure({ graph: { nodes: [], edges: [] }, chains: [], findings: [{ id: 'sf-aaaa1111', repo: 'r', severity: 'high' }], now: 1 });
  assert.equal(buildViews(cur, { ranking }).ciso.findings.find((f) => f.id === 'sf-aaaa1111').priority, 'P3', 'a high finding with unknown exposure');
  assert.equal(buildViews(cur, { ranking }).ciso.risk.byPriority.P3, 1);
});

test('AUDITOR: each statement cites its evidence, each unknown says why, and the limits of the signature are stated', () => {
  const pkg = makePackage({ findings: [f1, f2], partial: true });
  const v = buildViews(pkg, { verification: verifyReleasePackage(pkg, pub) });
  assert.equal(v.auditor.issuer.independentlyCertified, false); assert.match(v.auditor.doesNotProve, /real or exploitable/);
  const a1 = v.auditor.assertions[0]; assert.equal(a1.status, 'unknown'); assert.equal(a1.reason, 'an analyzer failed');
  const reasons = v.auditor.unknowns.map((u) => u.about + ' | ' + u.reason);
  assert.ok(reasons.some((r) => /scan completeness \| 1 analyzer/.test(r)), reasons.join('\n')); assert.ok(reasons.some((r) => /exploitability of sf-bbbb2222 \| proof tier is unproven/.test(r)));
  assert.ok(!reasons.some((r) => /exploitability of sf-aaaa1111/.test(r)), 'an executed proof is not listed as unknown');
  assert.ok(v.auditor.unknowns.every((u) => u.reason.length > 5), 'every unknown has a reason');
  const bad = JSON.parse(JSON.stringify(pkg)); bad.evidence[1].payload.severity = 'low';
  const vb = buildViews(bad, { verification: verifyReleasePackage(bad, pub) }); assert.equal(vb.auditor.verification.ok, false); assert.ok(vb.auditor.verification.errors.some((e) => /SIGNATURE/.test(e)));
  assert.equal(buildViews(pkg).auditor.verification.ok, null, 'a view that did not verify says so');
});

test('OFFLINE REPORT: one self-contained page, no script, nothing loaded from elsewhere, every value escaped, data attributes agree with the views', () => {
  const evil = { ...f1, id: 'f-x', stableId: 'sf-evil0001', vuln: '<script>alert(1)</script>', description: '"><img src=x onerror=alert(1)>', remediation: "' onload='steal()", file: '<b>a</b>.js' };
  const pkg = makePackage({ findings: [evil, f2] });
  const views = buildViews(pkg, { verification: verifyReleasePackage(pkg, pub) });
  const html = renderHtml(views);
  assert.match(html, /^<!doctype html>/); assert.ok(!/<script/i.test(html), 'no script element');
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), 'hostile text is escaped'); assert.ok(!html.includes('<img'), 'no element built from repository text'); assert.ok(!html.includes('<b>a</b>'));
  assert.match(html, /Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"/);
  assert.ok(!/(?:src|href)=["']https?:/i.test(html) && !/@import|url\(/i.test(html), 'nothing is fetched from anywhere');
  const rows = [...html.matchAll(/<tr data-finding="([^"]+)" data-evidence="([^"]+)" data-status="([^"]+)" data-confidence="([^"]+)">/g)].map((m) => ({ id: m[1], evidence: m[2], status: m[3], confidence: m[4] }));
  const canon = new Map(views.canonical.map((f) => [f.id, f]));
  assert.ok(rows.length >= 3 * 2, `each finding appears in each of the three tables (${rows.length} rows)`);
  for (const r of rows) { const c = canon.get(r.id); assert.ok(c, r.id); assert.equal(r.evidence, c.evidenceHash); assert.equal(r.status, c.status); assert.equal(r.confidence, c.confidence); }
  // well-formed: every opened table/details/ul closes
  for (const t of ['table', 'details', 'ul', 'thead', 'tbody']) assert.equal((html.match(new RegExp(`<${t}[ >]`, 'g')) || []).length, (html.match(new RegExp(`</${t}>`, 'g')) || []).length, t);
  assert.match(html, /prefers-color-scheme: dark/); assert.match(html, /name="viewport"/);
  assert.match(renderHtml(buildViews(makePackage({ findings: [f1] })), { title: '<x>' }), /<title>&lt;x&gt;<\/title>/);
  assert.ok(renderHtml(buildViews(buildReleasePackage({ snapshot: snap, evidence: [{ kind: 'scan-health', payload: health }] }))).includes('No findings.'));
});

test('TEXT: the same facts as plain text, one view or all', () => {
  const v = buildViews(makePackage({ findings: [f1, f2] }));
  const all = renderText(v); assert.match(all, /DEVELOPER VIEW/); assert.match(all, /CISO VIEW/); assert.match(all, /AUDITOR VIEW/); assert.match(all, /sf-aaaa1111/);
  assert.ok(!/CISO VIEW/.test(renderText(v, 'developer'))); assert.match(renderText(v, 'ciso'), /proven: 1 executed, 0 taint path, 1 unproven, of 2/); assert.match(renderText(v, 'auditor'), /does not prove:/);
  assert.match(renderText(buildViews(makePackage({ findings: [f1], partial: true })), 'ciso'), /scan: incomplete/);
});

test('CLI: release-view prints each view as text, json or html, verifies when given the public key, and fails when the package does not verify', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-07-'));
  try {
    const pkg = makePackage({ findings: [f1, f2] }); const prev = makePackage({ findings: [f2] });
    fs.writeFileSync(path.join(dir, 'p.json'), JSON.stringify(pkg)); fs.writeFileSync(path.join(dir, 'prev.json'), JSON.stringify(prev)); fs.writeFileSync(path.join(dir, 'pub.pem'), pub);
    const run = (...a) => spawnSync(process.execPath, [BIN, 'release-view', path.join(dir, 'p.json'), ...a], { encoding: 'utf8', timeout: 60000 });
    const t = run('--public-key', path.join(dir, 'pub.pem'), '--previous', path.join(dir, 'prev.json')); assert.equal(t.status, 0, t.stderr);
    assert.match(t.stdout, /signature and contents verified/); assert.match(t.stdout, /since last release: 1 new, 0 resolved/);
    const j = JSON.parse(run('--view', 'ciso', '--format', 'json').stdout); assert.equal(j.proven.total, 2); assert.equal(j.verified, null);
    const h = run('--format', 'html', '--public-key', path.join(dir, 'pub.pem')); assert.equal(h.status, 0); assert.match(h.stdout, /<!doctype html>/); assert.match(h.stdout, /Verification: <span class="ok">passed/);
    const tampered = JSON.parse(JSON.stringify(pkg)); tampered.evidence[1].payload.severity = 'low'; fs.writeFileSync(path.join(dir, 't.json'), JSON.stringify(tampered));
    const bad = spawnSync(process.execPath, [BIN, 'release-view', path.join(dir, 't.json'), '--public-key', path.join(dir, 'pub.pem'), '--view', 'auditor'], { encoding: 'utf8' });
    assert.equal(bad.status, 1); assert.match(bad.stdout, /verification: FAILED/);
    assert.equal(spawnSync(process.execPath, [BIN, 'release-view'], { encoding: 'utf8' }).status, 2);
    assert.equal(run('--format', 'pdf').status, 2); assert.equal(spawnSync(process.execPath, [BIN, 'release-view', path.join(dir, 'missing.json')], { encoding: 'utf8' }).status, 2);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
