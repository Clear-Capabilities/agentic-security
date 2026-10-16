// E3-03: one verifier for every patch route. Identical patch and settings give the same canonical verdict whichever route asked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { cleanup } from './helpers.js';
import { runScan } from '../../src/runScan.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { createServer } from '../../src/mcp/server.js';
import { applyVerifiedFix } from '../../src/fix/apply-fix-service.js';
import { verifyPatch } from '../../src/fix/verify-patch.js';
import { validateFixVerificationRecord } from '../../src/fix/verification-record.js';

const VULN = "const { exec } = require('child_process');\nexports.ping = (req, cb) => exec('echo ' + req.query.host, (e, out) => cb(e, out));\n";
const GOOD = "const { execFile } = require('child_process');\nexports.ping = (req, cb) => execFile('echo', [String(req.query.host)], (e, out) => cb(e, out));\n";
const DENY = "exports.ping = (req, cb) => cb(new Error('forbidden'));\n";
const TEST = "const app = require('./app');\napp.ping({ query: { host: 'hello' } }, (e, out) => { if (e || !/hello/.test(out)) { console.error('ping broke'); process.exit(1); } });\n";

async function session({ withTests = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e3c-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'e3c', version: '1.0.0', ...(withTests ? { scripts: { test: 'node test.js' } } : {}) }));
  fs.writeFileSync(path.join(root, 'app.js'), VULN);
  if (withTests) fs.writeFileSync(path.join(root, 'test.js'), TEST);
  const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
  let scan;
  try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
  const finding = scan.findings.find((f) => /CWE-78/.test(f.cwe || ''));
  const state = path.join(root, '.agentic-security'); fs.mkdirSync(state, { recursive: true });
  const body = JSON.stringify(scan);
  fs.writeFileSync(path.join(state, 'last-scan.json'), body); fs.writeFileSync(path.join(state, 'last-scan.json.sig'), signLastScan(body));
  const handle = createServer({ sessionRoot: root }).handleRequest;
  const call = async (name, args) => { const r = await handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }); try { return JSON.parse(r.result.content[0].text); } catch { return { raw: r.result?.content?.[0]?.text, err: r.error }; } };
  return { root, finding, ref: { file: 'app.js', id: finding.id, stableId: finding.stableId, vuln: finding.vuln }, call };
}

const canon = (r) => ({ id: r.fixVerification.id, verifiedFull: r.verifiedFull, fixCompleteness: r.fixCompleteness, degradedLegs: r.degradedLegs });

test('the same patch gives the same record id, verdict and degraded legs through the service, verify_fix and apply_fix', async () => {
  const s = await session();
  try {
    const svc = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': GOOD }, dryRun: true });
    const mcpVerify = await s.call('verify_fix', { stable_id: s.finding.stableId, files: { 'app.js': GOOD } });
    const mcpApply = await s.call('apply_fix', { finding_id: s.finding.id, confirm: true, dry_run: true, patch: { 'app.js': GOOD } });
    for (const r of [svc, mcpVerify, mcpApply]) {
      assert.ok(r.fixVerification, 'every route returns the canonical record');
      const v = validateFixVerificationRecord(r.fixVerification);
      assert.equal(v.ok, true, JSON.stringify(v.errors));
    }
    assert.deepEqual(canon(mcpVerify), canon(svc));
    assert.deepEqual(canon(mcpApply), canon(svc));
    assert.notEqual(svc.fixVerification.route, mcpVerify.fixVerification.route, 'who asked is recorded, but is not part of the id');
    assert.ok(svc.degradedLegs.some((d) => /^behaviorTests: not_run/.test(d)), 'no test command: surfaced as degraded on every route');
    assert.equal(svc.verifiedFull, false);
  } finally { cleanup(s.root); }
});

test('the bad patch is judged the same everywhere too, and a different patch gives a different id', async () => {
  const s = await session();
  try {
    const a = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': GOOD }, dryRun: true });
    const b = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': DENY }, dryRun: true });
    assert.notEqual(a.fixVerification.id, b.fixVerification.id);
    const v = await s.call('verify_fix', { stable_id: s.finding.stableId, files: { 'app.js': DENY } });
    assert.equal(canon(v).id, canon(b).id);
  } finally { cleanup(s.root); }
});

test('tests run before the patch exists are surfaced as degraded on every route, not as a full verification', async () => {
  const s = await session({ withTests: true });
  try {
    const svc = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': DENY }, dryRun: true });
    const v = await s.call('verify_fix', { stable_id: s.finding.stableId, files: { 'app.js': DENY } });
    const ap = await s.call('apply_fix', { finding_id: s.finding.id, confirm: true, dry_run: true, patch: { 'app.js': DENY } });
    for (const r of [svc, v, ap]) {
      assert.equal(r.verifiedFull, false);
      assert.ok(r.degradedLegs.some((d) => /behaviorTests: not_run \(.*BEFORE the patch/.test(d)), JSON.stringify(r.degradedLegs));
    }
  } finally { cleanup(s.root); }
});

test('existing fields are unchanged: ok, verified, rescan and summary are still there beside the additive ones', async () => {
  const s = await session();
  try {
    const v = await s.call('verify_fix', { stable_id: s.finding.stableId, files: { 'app.js': GOOD } });
    for (const k of ['ok', 'rescan', 'lint', 'tests', 'summary', 'verificationRecord']) assert.ok(k in v, k);
    const dry = await s.call('apply_fix', { finding_id: s.finding.id, confirm: true, dry_run: true, patch: { 'app.js': GOOD } });
    for (const k of ['applied', 'dryRun', 'verified', 'files', 'summary']) assert.ok(k in dry, k);
    assert.equal(dry.verified, true);
  } finally { cleanup(s.root); }
});

test('the PoC rule is one rule: a stored PoC is used by every route only when the scan is signed', async () => {
  const s = await session();
  try {
    let seen = [];
    const fake = async (args) => { seen.push(!!args.poc); return { ok: true, rescan: { ok: true, reason: 'verified', introduced: [] }, lint: { runner: 'none', ok: true }, tests: { skipped: true, reason: 'none' }, poc: { status: 'not-requested' }, summary: 's' }; };
    const scan = JSON.parse(fs.readFileSync(path.join(s.root, '.agentic-security/last-scan.json'), 'utf8'));
    scan.findings.find((f) => f.stableId === s.finding.stableId).poc = { code: 'console.log(1)', kind: 'http' };
    const body = JSON.stringify(scan); const file = path.join(s.root, '.agentic-security/last-scan.json');
    fs.writeFileSync(file, body); fs.writeFileSync(file + '.sig', signLastScan(body));
    await verifyPatch({ scanRoot: s.root, finding: s.ref, files: { 'app.js': GOOD }, route: 'x', verify: fake });
    fs.writeFileSync(file, body + ' '); // signature no longer verifies
    await verifyPatch({ scanRoot: s.root, finding: s.ref, files: { 'app.js': GOOD }, route: 'x', verify: fake });
    assert.deepEqual(seen, [true, false]);
  } finally { cleanup(s.root); }
});

test('the env flag no longer swaps the verifier: with it set the result still carries the canonical record and the honesty leg', async () => {
  const s = await session();
  const saved = process.env.AGENTIC_SECURITY_FIX_RUN_TESTS; process.env.AGENTIC_SECURITY_FIX_RUN_TESTS = '1';
  try {
    const ap = await s.call('apply_fix', { finding_id: s.finding.id, confirm: true, dry_run: true, patch: { 'app.js': GOOD } });
    const svc = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': GOOD }, dryRun: true });
    assert.equal(ap.fixVerification.id, svc.fixVerification.id);
  } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_FIX_RUN_TESTS; else process.env.AGENTIC_SECURITY_FIX_RUN_TESTS = saved; cleanup(s.root); }
});
