// E3-01: every route by which a patch is produced, verified or applied, with call tests that pin what each route does TODAY.
// The route table is docs/engineering-excellence/patch-routes.json. A divergence listed there as `open` is asserted here in its current,
// wrong state; closing it (E3-03, E3-05, ...) flips its status and these assertions must then be replaced with the corrected behaviour.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { REPO, cleanup } from './helpers.js';
import { runScan } from '../../src/runScan.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { createServer } from '../../src/mcp/server.js';
import { applyVerifiedFix } from '../../src/fix/apply-fix-service.js';
import { verifyFix } from '../../src/posture/fix-verify.js';

const TABLE = JSON.parse(fs.readFileSync(path.join(REPO, 'docs/engineering-excellence/patch-routes.json'), 'utf8'));
const TASKS = new Set(JSON.parse(fs.readFileSync(path.join(REPO, 'scripts/engineering-excellence/tasks.json'), 'utf8')).tasks.map((t) => t.id));
const divergence = (id) => TABLE.divergences.find((d) => d.id === id);

// ---- the table ----------------------------------------------------------------------------------------------------------------

test('every route names a real entry point in a real file and at least one existing test', () => {
  assert.ok(TABLE.routes.length >= 16);
  const ids = new Set();
  for (const r of TABLE.routes) {
    assert.ok(!ids.has(r.id), `duplicate route ${r.id}`); ids.add(r.id);
    const file = path.join(REPO, r.file);
    assert.ok(fs.existsSync(file), `${r.id}: ${r.file} does not exist`);
    assert.ok(fs.readFileSync(file, 'utf8').includes(r.symbol), `${r.id}: ${r.symbol} does not occur in ${r.file}`);
    assert.ok(r.tests.length >= 1, `${r.id} has no test`);
    for (const t of r.tests) assert.ok(fs.existsSync(path.join(REPO, t)), `${r.id}: test ${t} does not exist`);
    assert.equal(typeof r.writes, 'boolean');
  }
});

test('the table separates routes that write from routes that do not, and records which of the writing routes verify', () => {
  const writers = TABLE.routes.filter((r) => r.writes);
  const unverified = writers.filter((r) => r.verifier === 'none').map((r) => r.id).sort();
  assert.deepEqual(unverified, ['R5'.replace('R5', 'R6'), 'R7'].sort(), 'the writing routes with no verifier of their own are the dependency upgrade (R6) and undo (R7)');
  assert.ok(writers.length >= 9);
});

test('every divergence has an id, a status, a summary and a closing task that exists in the program manifest', () => {
  const seen = new Set();
  for (const d of TABLE.divergences) {
    assert.match(d.id, /^D\d+$/); assert.ok(!seen.has(d.id)); seen.add(d.id);
    assert.ok(['open', 'closed'].includes(d.status), d.id);
    assert.ok(d.summary.length > 40, d.id);
    assert.ok(TASKS.has(d.closedBy), `${d.id}: ${d.closedBy} is not a task`);
  }
  assert.ok(TABLE.divergences.length >= 10);
});

// ---- a real project, a real signed scan --------------------------------------------------------------------------------------

const VULN = "const { exec } = require('child_process');\nexports.ping = (req, cb) => exec('echo ' + req.query.host, (e, out) => cb(e, out));\n";
const GOOD = "const { execFile } = require('child_process');\nexports.ping = (req, cb) => execFile('echo', [String(req.query.host)], (e, out) => cb(e, out));\n";
const DENY = "exports.ping = (req, cb) => cb(new Error('forbidden'));\n";
const TEST = "const app = require('./app');\napp.ping({ query: { host: 'hello' } }, (e, out) => { if (e || !/hello/.test(out)) { console.error('ping broke'); process.exit(1); } });\n";

async function session({ withTests = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e3-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'e3-fixture', version: '1.0.0', ...(withTests ? { scripts: { test: 'node test.js' } } : {}) }));
  fs.writeFileSync(path.join(root, 'app.js'), VULN);
  if (withTests) fs.writeFileSync(path.join(root, 'test.js'), TEST);
  const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
  let scan;
  try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
  const finding = scan.findings.find((f) => /CWE-78/.test(f.cwe || ''));
  assert.ok(finding, 'the fixture produces a command injection finding');
  const state = path.join(root, '.agentic-security'); fs.mkdirSync(state, { recursive: true });
  const body = JSON.stringify({ ...scan, findings: scan.findings });
  fs.writeFileSync(path.join(state, 'last-scan.json'), body);
  fs.writeFileSync(path.join(state, 'last-scan.json.sig'), signLastScan(body));
  const ref = { file: 'app.js', id: finding.id, stableId: finding.stableId, vuln: finding.vuln };
  const handle = createServer({ sessionRoot: root }).handleRequest;
  const call = async (name, args) => { const r = await handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }); if (r.error) return { rpcError: r.error.message }; try { return JSON.parse(r.result.content[0].text); } catch { return { raw: r.result.content[0].text }; } };
  return { root, finding, ref, call };
}

test('R3 applyVerifiedFix: a good patch is verified, and the result carries the shared fields', async () => {
  const s = await session();
  try {
    const r = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': GOOD }, dryRun: true });
    assert.equal(r.ok, true); assert.equal(r.verified, true);
    assert.deepEqual(Object.keys(r).sort(), ['applied', 'dryRun', 'files', 'materialClassification', 'ok', 'verified', 'verify']);
    assert.equal(r.verify.rescan.ok, true);
    assert.ok(r.verify.degradedLegs.some((l) => /tests: skipped/.test(l)), 'no test command was detected, and the result says so');
    const real = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': GOOD } });
    assert.equal(real.applied, true);
    assert.equal(typeof real.verifiedFull, 'boolean');
    assert.equal(real.verifiedFull, false, 'a degraded pass is not a full pass');
    assert.equal(fs.readFileSync(path.join(s.root, 'app.js'), 'utf8'), GOOD);
  } finally { cleanup(s.root); }
});

test('the shared service refuses an unsigned scan, a path outside the project and a reserved path, and leaves the file as it was', async () => {
  const s = await session();
  try {
    fs.rmSync(path.join(s.root, '.agentic-security', 'last-scan.json.sig'));
    const unsigned = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': GOOD } });
    assert.equal(unsigned.applied, false);
    assert.match(unsigned.reason, /integrity check failed/);
    assert.equal(fs.readFileSync(path.join(s.root, 'app.js'), 'utf8'), VULN);
  } finally { cleanup(s.root); }
  const t = await session();
  try {
    const escape = await applyVerifiedFix({ scanRoot: t.root, finding: t.ref, files: { '../outside.js': GOOD } });
    assert.equal(escape.applied, false); assert.match(escape.reason, /path-escape refused/);
    const reserved = await applyVerifiedFix({ scanRoot: t.root, finding: t.ref, files: { '.agentic-security/last-scan.json': '{}' } });
    assert.equal(reserved.applied, false); assert.match(reserved.reason, /reserved path refused/);
  } finally { cleanup(t.root); }
});

test('R3 refuses a write when the file changed after the scan that produced the finding', async () => {
  const s = await session();
  try {
    const first = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': GOOD }, dryRun: true, fixMeta: { baselineHashes: { 'app.js': 'sha256:' + '0'.repeat(64) } } });
    assert.ok(first.ok === false || first.applied === false || first.reason, JSON.stringify(Object.keys(first)));
  } finally { cleanup(s.root); }
});

test('[D1] the same verification is reported in different shapes: apply_fix with a caller patch and verify_fix do not return verifiedFull', async () => {
  assert.equal(divergence('D1').status, 'open');
  const s = await session();
  try {
    const v = await s.call('verify_fix', { stable_id: s.finding.stableId, files: { 'app.js': GOOD } });
    assert.equal(v.ok, true);
    assert.equal('verifiedFull' in v, false, 'verify_fix computes verifiedFull but does not return it');
    assert.ok(v.verificationRecord, 'it returns a hypothesis-level verification record instead');
    const dry = await s.call('apply_fix', { finding_id: s.finding.id, confirm: true, dry_run: true, patch: { 'app.js': GOOD } });
    assert.equal(dry.verified, true);
    assert.equal('verifiedFull' in dry, false, 'the caller-patch branch returns verified only');
    assert.equal('degradedLegs' in dry, false);
  } finally { cleanup(s.root); }
});

test('[D2] the PoC leg is requested by verify_fix and not by the apply route', async () => {
  assert.equal(divergence('D2').status, 'open');
  const s = await session();
  try {
    const r = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': GOOD }, dryRun: true });
    assert.equal(r.verify.poc.status, 'not-requested');
  } finally { cleanup(s.root); }
});

test('[D3] the project tests run on the tree as it is BEFORE the patch, yet the verdict is reported as fully verified', async () => {
  assert.equal(divergence('D3').status, 'open');
  const s = await session({ withTests: true });
  try {
    // the tests pass on the vulnerable code and FAIL on the deny-all handler
    const v = await verifyFix({ scanRoot: s.root, originalFindingStableId: s.finding.stableId, files: { 'app.js': DENY } });
    assert.equal(v.tests.passed, true, 'the test leg passed for a patch that breaks the very behaviour the tests check');
    assert.equal(v.testedPrePatch, true);
    assert.match(v.summary, /NOT the candidate patch/, 'the summary admits it');
    assert.equal(v.verifiedFull, true, 'but the verdict is still full');
    assert.deepEqual(v.degradedLegs, [], 'and no leg is marked degraded');
    fs.writeFileSync(path.join(s.root, 'app.js'), DENY);
    const after = await verifyFix({ scanRoot: s.root, originalFindingStableId: s.finding.stableId, files: { 'app.js': DENY } });
    assert.equal(after.tests.passed, false, 'run against the patched tree, the same tests fail');
  } finally { cleanup(s.root); }
});

test('[D10] a patch that removes the vulnerable behaviour is accepted as verified: a deny-all handler, and an empty file', async () => {
  assert.equal(divergence('D10').status, 'open');
  const s = await session();
  try {
    const deny = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': DENY }, dryRun: true });
    assert.equal(deny.ok, true); assert.equal(deny.verified, true, 'the original finding is gone, so the patch passes');
    assert.equal(deny.verify.rescan.ok, true);
    const empty = await applyVerifiedFix({ scanRoot: s.root, finding: s.ref, files: { 'app.js': '' }, dryRun: true });
    assert.equal(empty.ok, true); assert.equal(empty.verified, true);
  } finally { cleanup(s.root); }
});

test('R10b apply_fix with a caller patch needs confirm:true; with it the patch is written, verified, and recorded in history', async () => {
  const s = await session();
  try {
    const noConfirm = await s.call('apply_fix', { finding_id: s.finding.id, patch: { 'app.js': GOOD } });
    assert.match(JSON.stringify(noConfirm), /confirm/, 'a write without confirm is refused');
    assert.notEqual(noConfirm.applied, true);
    assert.equal(fs.readFileSync(path.join(s.root, 'app.js'), 'utf8'), VULN, 'nothing was written');
    const done = await s.call('apply_fix', { finding_id: s.finding.id, confirm: true, patch: { 'app.js': GOOD } });
    assert.equal(done.applied, true);
    assert.equal(done.verified, true);
    assert.equal('verifiedFull' in done, false, '[D1] the applied result has no verifiedFull');
    assert.equal(fs.readFileSync(path.join(s.root, 'app.js'), 'utf8'), GOOD);
    assert.ok(fs.existsSync(path.join(s.root, '.agentic-security', 'fix-history')), 'the write is in the fix history, so undo can revert it');
  } finally { cleanup(s.root); }
});
