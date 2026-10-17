// E3-05: a fix must keep the feature. The finding disappearing is not enough.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { cleanup } from './helpers.js';
import { runScan } from '../../src/runScan.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { checkFootprint, kindsOf } from '../../src/fix/footprint.js';
import { discoverTestCommand, runTestsOnPatchedCopy } from '../../src/fix/test-commands.js';
import { verifyPatch } from '../../src/fix/verify-patch.js';
import { applyVerifiedFix } from '../../src/fix/apply-fix-service.js';

const IDOR = "app.get('/doc/:id', (req, res) => {\n  const doc = db.docs.findOne({ id: req.params.id });\n  res.json(doc);\n});\n";
const IDOR_FIXED = "app.get('/doc/:id', (req, res) => {\n  const doc = db.docs.findOne({ id: req.params.id, owner: req.user.id });\n  if (!doc) return res.status(404).json({ error: 'not found' });\n  res.json(doc);\n});\n";
const IDOR_DENY_ALL = "app.get('/doc/:id', (req, res) => {\n  res.status(403).json({ error: 'forbidden' });\n});\n";
const SQLI = "exports.user = (db, req, res) => {\n  db.query(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\", (e, rows) => res.json(rows));\n};\n";
const SQLI_FIXED = "exports.user = (db, req, res) => {\n  db.query('SELECT * FROM users WHERE id = ?', [req.query.id], (e, rows) => res.json(rows));\n};\n";
const SQLI_DISABLED = "exports.user = (db, req, res) => {\n  res.status(501).send('not implemented');\n};\n";

test('the footprint check rejects a blanket-deny IDOR patch and a disable-the-feature SQL patch, and accepts the real fixes', () => {
  const idorDeny = checkFootprint({ before: { 'r.js': IDOR }, after: { 'r.js': IDOR_DENY_ALL }, cwe: 'CWE-639' });
  assert.equal(idorDeny.status, 'failed'); assert.match(idorDeny.reason, /removes functionality instead of fixing it/); assert.match(idorDeny.reason, /data-access/); assert.match(idorDeny.reason, /deny response/);
  const sqlDisabled = checkFootprint({ before: { 's.js': SQLI }, after: { 's.js': SQLI_DISABLED }, cwe: 'CWE-89' });
  assert.equal(sqlDisabled.status, 'failed'); assert.deepEqual(sqlDisabled.lost, ['data-access']);
  assert.equal(checkFootprint({ before: { 'r.js': IDOR }, after: { 'r.js': IDOR_FIXED }, cwe: 'CWE-639' }).status, 'passed');
  assert.equal(checkFootprint({ before: { 's.js': SQLI }, after: { 's.js': SQLI_FIXED }, cwe: 'CWE-89' }).status, 'passed');
});

test('an emptied file, a stripped-down file, and a commented-out body are all feature removal', () => {
  assert.equal(checkFootprint({ before: { 's.js': SQLI }, after: { 's.js': '' }, cwe: 'CWE-89' }).status, 'failed');
  assert.equal(checkFootprint({ before: { 's.js': SQLI }, after: { 's.js': '// removed\n' }, cwe: 'CWE-89' }).status, 'failed');
  const commented = "exports.user = (db, req, res) => {\n  // db.query(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\", cb);\n  res.json([]);\n};\n";
  assert.equal(checkFootprint({ before: { 's.js': SQLI }, after: { 's.js': commented }, cwe: 'CWE-89' }).status, 'failed', 'commented-out code does not count as performing the operation');
});

test('kinds are held to the weakness: a command-injection fix may drop a database read, an SQL fix may not drop the query', () => {
  const both = "exports.f = (db, req) => { db.query('SELECT 1'); require('child_process').exec('ls ' + req.q); };\n";
  const noDb = "exports.f = (db, req) => { require('child_process').execFile('ls', [req.q]); };\n";
  assert.equal(checkFootprint({ before: { 'a.js': both }, after: { 'a.js': noDb }, cwe: 'CWE-78' }).status, 'passed');
  assert.equal(checkFootprint({ before: { 'a.js': both }, after: { 'a.js': noDb }, cwe: 'CWE-89' }).status, 'failed');
  assert.deepEqual(kindsOf("fs.readFileSync(p); fetch(u);"), ['file-access', 'network-out']);
});

test('what cannot be observed is not_run, never passed; an intentional removal is surfaced for a person, never silently accepted', () => {
  const opaque = checkFootprint({ before: { 'a.js': 'const x = 1;\nmodule.exports = x;\n' }, after: { 'a.js': 'const x = 2;\n' }, cwe: 'CWE-798' });
  assert.equal(opaque.status, 'not_run'); assert.match(opaque.reason, /unobservable/);
  const intent = checkFootprint({ before: { 's.js': SQLI }, after: { 's.js': SQLI_DISABLED }, cwe: 'CWE-89', intentionalRemoval: { reason: 'the endpoint is being retired' } });
  assert.equal(intent.status, 'not_run'); assert.match(intent.reason, /a person must confirm/);
  assert.equal(checkFootprint({ before: { 's.js': SQLI }, after: { 's.js': SQLI_DISABLED }, cwe: 'CWE-89', intentionalRemoval: { reason: '  ' } }).status, 'failed', 'a blank reason is not a declaration');
  assert.equal(checkFootprint({ before: { }, after: { 'new.js': 'x' }, cwe: 'CWE-89' }).status, 'not_run');
});

// ---- tests on the patched copy ----------------------------------------------------------------------------------------------

function tiny({ failBefore = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e3e-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0', scripts: { test: 'node t.js' } }));
  fs.writeFileSync(path.join(root, 'lib.js'), "exports.f = () => 'ok';\n");
  fs.writeFileSync(path.join(root, 't.js'), `if (require('./lib').f() !== 'ok'${failBefore ? ' || true' : ''}) { console.error('broken'); process.exit(1); }\n`);
  return root;
}

test('tests run on a copy with the patch applied: a breaking patch fails, a harmless one passes, and the real tree is never written', () => {
  const root = tiny();
  try {
    const good = runTestsOnPatchedCopy({ scanRoot: root, files: { 'lib.js': "exports.f = () => 'ok'; // patched\n" } });
    assert.equal(good.status, 'passed'); assert.equal(good.onPatchedTree, true);
    const bad = runTestsOnPatchedCopy({ scanRoot: root, files: { 'lib.js': "exports.f = () => { throw new Error('forbidden'); };\n" } });
    assert.equal(bad.status, 'failed'); assert.equal(bad.preExistingFailure, false);
    assert.equal(fs.readFileSync(path.join(root, 'lib.js'), 'utf8'), "exports.f = () => 'ok';\n");
  } finally { cleanup(root); }
});

test('a suite that was already failing is attributed to the project, not to the patch', () => {
  const root = tiny();
  fs.writeFileSync(path.join(root, 't.js'), "process.exit(1);\n");
  try {
    const r = runTestsOnPatchedCopy({ scanRoot: root, files: { 'lib.js': "exports.f = () => 'ok';\n" } });
    assert.equal(r.status, 'failed'); assert.equal(r.preExistingFailure, true);
  } finally { cleanup(root); }
});

test('an explicit command wins over discovery, is an argv (no shell), and a patch path outside the copy is refused', () => {
  const root = tiny();
  try {
    const marker = path.join(os.tmpdir(), `ee-e3e-shell-${process.pid}`);
    const r = runTestsOnPatchedCopy({ scanRoot: root, files: {}, command: [process.execPath, '-e', `process.exit(require('fs').existsSync('lib.js') ? 0 : 3)`] });
    assert.equal(r.status, 'passed'); assert.equal(r.runner, 'explicit');
    const inj = runTestsOnPatchedCopy({ scanRoot: root, files: {}, command: ['echo', `x; touch ${marker}`] });
    assert.equal(fs.existsSync(marker), false, 'no shell interpreted the argument');
    assert.equal(inj.status, 'passed');
    const esc = runTestsOnPatchedCopy({ scanRoot: root, files: { '../escape.js': 'x' } });
    assert.equal(esc.skipped, true); assert.match(esc.reason, /escapes/);
    assert.equal(fs.existsSync(path.join(path.dirname(root), 'escape.js')), false);
  } finally { cleanup(root); }
});

test('runner discovery covers cargo, dotnet, maven, gradle and rspec as well as the existing ones; nothing found is null', () => {
  const yes = () => true;
  const mk = (files) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e3e-d-')); for (const f of files) fs.writeFileSync(path.join(d, f), ''); return d; };
  const cases = [[['Cargo.toml'], 'cargo'], [['app.csproj'], 'dotnet'], [['pom.xml'], 'maven'], [['build.gradle'], 'gradle'], [['.rspec', 'Gemfile'], 'rspec'], [['go.mod'], 'go']];
  for (const [files, kind] of cases) { const d = mk(files); try { assert.equal(discoverTestCommand(d, { available: yes })?.kind, kind, kind); } finally { cleanup(d); } }
  const empty = mk([]); try { assert.equal(discoverTestCommand(empty, { available: yes }), null); assert.equal(discoverTestCommand(mk(['Cargo.toml']), { available: () => false }), null, 'a tool that is not installed is not a runner'); } finally { cleanup(empty); }
});

// ---- end to end ------------------------------------------------------------------------------------------------------------

const CMD_VULN = "const { exec } = require('child_process');\nexports.ping = (req, cb) => exec('echo ' + req.query.host, (e, out) => cb(e, out));\n";
const CMD_GOOD = "const { execFile } = require('child_process');\nexports.ping = (req, cb) => execFile('echo', [String(req.query.host)], (e, out) => cb(e, out));\n";
const CMD_DENY = "exports.ping = (req, cb) => cb(new Error('forbidden'));\n";
const CMD_TEST = "const app = require('./app');\napp.ping({ query: { host: 'hello' } }, (e, out) => { if (e || !/hello/.test(out)) { console.error('ping broke'); process.exit(1); } });\n";

async function project({ tests }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e3e2-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0', ...(tests ? { scripts: { test: 'node test.js' } } : {}) }));
  fs.writeFileSync(path.join(root, 'app.js'), CMD_VULN);
  if (tests) fs.writeFileSync(path.join(root, 'test.js'), CMD_TEST);
  const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
  let scan; try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
  const finding = scan.findings.find((f) => /CWE-78/.test(f.cwe || ''));
  const state = path.join(root, '.agentic-security'); fs.mkdirSync(state, { recursive: true });
  const body = JSON.stringify(scan); fs.writeFileSync(path.join(state, 'last-scan.json'), body); fs.writeFileSync(path.join(state, 'last-scan.json.sig'), signLastScan(body));
  return { root, finding, ref: { file: 'app.js', id: finding.id, stableId: finding.stableId, vuln: finding.vuln } };
}

test('end to end: the blanket-deny patch is rejected even though the original finding disappeared; the real fix is fully verified', async () => {
  const p = await project({ tests: true });
  try {
    const deny = await verifyPatch({ scanRoot: p.root, finding: p.ref, files: { 'app.js': CMD_DENY }, route: 'test' });
    assert.equal(deny.verdict.rescan.ok, true, 'the scanner alone would accept it');
    assert.equal(deny.verdict.ok, false);
    assert.equal(deny.fixVerification.behaviorPreservation.status, 'failed');
    assert.equal(deny.fixVerification.behaviorTests.status, 'failed');
    assert.equal(deny.fixVerification.fixCompleteness, 'unverified');
    const good = await verifyPatch({ scanRoot: p.root, finding: p.ref, files: { 'app.js': CMD_GOOD }, route: 'test' });
    assert.equal(good.fixVerification.verifiedFull, true, JSON.stringify(good.fixVerification.degradedLegs));
    assert.equal(good.fixVerification.fixCompleteness, 'FULL');
    const applied = await applyVerifiedFix({ scanRoot: p.root, finding: p.ref, files: { 'app.js': CMD_DENY } });
    assert.equal(applied.applied, false); assert.equal(fs.readFileSync(path.join(p.root, 'app.js'), 'utf8'), CMD_VULN);
  } finally { cleanup(p.root); }
});

test('with no project tests the deny-all patch is still rejected by the footprint check, and a good fix is only a degraded pass', async () => {
  const p = await project({ tests: false });
  try {
    const deny = await verifyPatch({ scanRoot: p.root, finding: p.ref, files: { 'app.js': CMD_DENY }, route: 'test' });
    assert.equal(deny.verdict.ok, false);
    const good = await verifyPatch({ scanRoot: p.root, finding: p.ref, files: { 'app.js': CMD_GOOD }, route: 'test' });
    assert.equal(good.verdict.ok, true);
    assert.equal(good.fixVerification.verifiedFull, false);
    assert.ok(good.fixVerification.degradedLegs.some((d) => d.startsWith('behaviorTests: not_run')));
    assert.equal(good.fixVerification.fixCompleteness, 'MITIGATION');
  } finally { cleanup(p.root); }
});
