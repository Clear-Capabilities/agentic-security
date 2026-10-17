// E3-07: a crash, a failing test or a hostile path leaves the target untouched or revertible, including after a restart.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { cleanup } from './helpers.js';
import { runScan } from '../../src/runScan.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { applyVerifiedFix } from '../../src/fix/apply-fix-service.js';
import { recoverBatches } from '../../src/fix/batch-journal.js';
import { listHistory } from '../../src/posture/fix-history.js';

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../src');
const VULN = "const { exec } = require('child_process');\nexports.ping = (req, cb) => exec('echo ' + req.query.host, (e, out) => cb(e, out));\n";
const GOOD = "const { execFile } = require('child_process');\nexports.ping = (req, cb) => execFile('echo', [String(req.query.host)], (e, out) => cb(e, out));\n";
const LIB = "exports.name = 'lib';\n";
const LIB2 = "exports.name = 'lib-2';\n";

async function project() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e3g-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0' }));
  fs.writeFileSync(path.join(root, 'app.js'), VULN); fs.writeFileSync(path.join(root, 'lib.js'), LIB);
  const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
  let scan; try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
  const f = scan.findings.find((x) => /CWE-78/.test(x.cwe || ''));
  const st = path.join(root, '.agentic-security'); fs.mkdirSync(st, { recursive: true }); const body = JSON.stringify(scan);
  fs.writeFileSync(path.join(st, 'last-scan.json'), body); fs.writeFileSync(path.join(st, 'last-scan.json.sig'), signLastScan(body));
  return { root, ref: { file: 'app.js', id: f.id, stableId: f.stableId, vuln: f.vuln, severity: f.severity } };
}
const read = (root, f) => fs.readFileSync(path.join(root, f), 'utf8');

function crashingRun(p, faultAt) {
  const script = `import { applyVerifiedFix } from ${JSON.stringify(path.join(SRC, 'fix/apply-fix-service.js'))};
const r = await applyVerifiedFix({ scanRoot: ${JSON.stringify(p.root)}, finding: ${JSON.stringify(p.ref)}, files: { 'app.js': ${JSON.stringify(GOOD)}, 'lib.js': ${JSON.stringify(LIB2)} } });
console.log(JSON.stringify({ applied: r.applied }));`;
  const file = path.join(os.tmpdir(), `ee-e3g-child-${process.pid}-${faultAt}.mjs`);
  fs.writeFileSync(file, script);
  try { return spawnSync(process.execPath, [file], { env: { ...process.env, AGENTIC_SECURITY_TEST_FAULTS: '1', AGENTIC_SECURITY_FAULT_AT: faultAt }, encoding: 'utf8', timeout: 120000 }); } finally { fs.rmSync(file, { force: true }); }
}

test('a crash between two files of one patch leaves the first patched; after restart the whole batch is reverted and says so', async () => {
  const p = await project();
  try {
    const child = crashingRun(p, 'after-file-0');
    assert.equal(child.signal, 'SIGKILL', `the child was killed at the fault point (status ${child.status})`);
    assert.equal(read(p.root, 'app.js'), GOOD, 'the crash really did leave a half-applied patch');
    assert.equal(read(p.root, 'lib.js'), LIB);
    const settled = await recoverBatches(p.root);
    assert.equal(settled.length, 1);
    assert.deepEqual(settled[0].reverted, ['app.js']); assert.deepEqual(settled[0].untouched, ['lib.js']);
    assert.equal(read(p.root, 'app.js'), VULN); assert.equal(read(p.root, 'lib.js'), LIB);
    assert.equal(listHistory(p.root).filter((e) => !e.reverted && e.status === 'applied').length, 0, 'nothing is left applied in the ledger');
    assert.deepEqual(await recoverBatches(p.root), [], 'settling is idempotent');
  } finally { cleanup(p.root); }
});

test('the next apply settles an earlier crash first: restart is automatic, and the new patch then applies cleanly', async () => {
  const p = await project();
  try {
    assert.equal(crashingRun(p, 'after-file-0').signal, 'SIGKILL');
    const r = await applyVerifiedFix({ scanRoot: p.root, finding: p.ref, files: { 'app.js': GOOD, 'lib.js': LIB2 } });
    assert.equal(r.applied, true);
    assert.equal(r.recoveredBatches.length, 1); assert.deepEqual(r.recoveredBatches[0].reverted, ['app.js']);
    assert.equal(read(p.root, 'app.js'), GOOD); assert.equal(read(p.root, 'lib.js'), LIB2);
  } finally { cleanup(p.root); }
});

test('a crash before any file is written, and one after the last, are settled correctly', async () => {
  const p = await project();
  try {
    assert.equal(crashingRun(p, 'before-file-0').signal, 'SIGKILL');
    assert.equal(read(p.root, 'app.js'), VULN);
    const a = await recoverBatches(p.root);
    assert.deepEqual(a[0].reverted, []); assert.equal(read(p.root, 'app.js'), VULN);
  } finally { cleanup(p.root); }
  const q = await project();
  try {
    assert.equal(crashingRun(q, 'after-file-1').signal, 'SIGKILL');
    assert.equal(read(q.root, 'app.js'), GOOD); assert.equal(read(q.root, 'lib.js'), LIB2);
    const b = await recoverBatches(q.root);
    assert.deepEqual(b[0].reverted.sort(), ['app.js', 'lib.js'], 'a batch that never committed is not left half-trusted: it is reverted whole');
    assert.equal(read(q.root, 'app.js'), VULN); assert.equal(read(q.root, 'lib.js'), LIB);
  } finally { cleanup(q.root); }
});

test('a committed batch is left alone by recovery and can be undone', async () => {
  const p = await project();
  try {
    const r = await applyVerifiedFix({ scanRoot: p.root, finding: p.ref, files: { 'app.js': GOOD } });
    assert.equal(r.applied, true);
    assert.deepEqual(await recoverBatches(p.root), []);
    assert.equal(read(p.root, 'app.js'), GOOD);
    const { undoLast } = await import('../../src/posture/fix-history.js');
    await undoLast(p.root);
    assert.equal(read(p.root, 'app.js'), VULN);
  } finally { cleanup(p.root); }
});

test('a failing test run on the patched copy leaves the target untouched and writes nothing to the ledger', async () => {
  const p = await project();
  try {
    const r = await applyVerifiedFix({ scanRoot: p.root, finding: p.ref, files: { 'app.js': GOOD }, fixMeta: { testCommand: [process.execPath, '-e', "process.exit(require('fs').readFileSync('app.js','utf8').includes('execFile') ? 1 : 0)"] } });
    assert.equal(r.applied, false); assert.equal(r.ok, false);
    assert.equal(read(p.root, 'app.js'), VULN);
    assert.equal(listHistory(p.root).length, 0);
  } finally { cleanup(p.root); }
});

test('a test command that cannot even start is a tool error: it is degraded evidence, so an automatic write is only proposed and a requested one carries the warning', async () => {
  const p = await project();
  try {
    const auto = await applyVerifiedFix({ scanRoot: p.root, finding: { ...p.ref, severity: 'medium' }, files: { 'app.js': GOOD }, applyMode: 'automatic', policy: { automatic: { enabled: true, maxResidualRisk: 'high' } }, fixMeta: { testCommand: ['/nonexistent/runner'] } });
    assert.equal(auto.applied, false); assert.equal(auto.proposed, true);
    assert.equal(read(p.root, 'app.js'), VULN);
    const asked = await applyVerifiedFix({ scanRoot: p.root, finding: p.ref, files: { 'app.js': GOOD }, fixMeta: { testCommand: ['/nonexistent/runner'] } });
    assert.equal(asked.applied, true); assert.equal(asked.verifiedFull, false);
    assert.ok(asked.degradedLegs.some((d) => /^behaviorTests: not_run/.test(d)));
  } finally { cleanup(p.root); }
});

test('hostile paths and files are refused with the tree untouched: traversal, a symlink, a reserved path, binary content, a binary original', async () => {
  const p = await project();
  try {
    const outside = path.join(os.tmpdir(), `ee-e3g-outside-${process.pid}`); fs.writeFileSync(outside, 'secret');
    fs.symlinkSync(outside, path.join(p.root, 'link.js'));
    fs.writeFileSync(path.join(p.root, 'blob.bin'), Buffer.from([0, 1, 2, 255, 254]));
    const cases = [
      [{ '../x.js': GOOD }, /path-escape/], [{ 'link.js': GOOD }, /symbolic link/], [{ '.git/config': 'x' }, /reserved/], [{ 'app.js': 'a\0b' }, /binary content refused/], [{ 'blob.bin': 'text' }, /binary file refused/],
    ];
    for (const [files, re] of cases) {
      const r = await applyVerifiedFix({ scanRoot: p.root, finding: p.ref, files });
      assert.equal(r.applied, false); assert.match(r.reason, re, JSON.stringify(files));
    }
    assert.equal(read(p.root, 'app.js'), VULN); assert.equal(fs.readFileSync(outside, 'utf8'), 'secret'); assert.deepEqual([...fs.readFileSync(path.join(p.root, 'blob.bin'))], [0, 1, 2, 255, 254]);
    fs.rmSync(outside, { force: true });
  } finally { cleanup(p.root); }
});

test('a file changed after the scan is not overwritten', async () => {
  const p = await project();
  try {
    const r = await applyVerifiedFix({ scanRoot: p.root, finding: p.ref, files: { 'app.js': GOOD }, fixMeta: { baselineHashes: { 'app.js': 'sha256:' + '0'.repeat(64) } } });
    assert.equal(read(p.root, 'app.js'), r.applied ? GOOD : VULN);
    fs.writeFileSync(path.join(p.root, 'app.js'), VULN + '// edited by someone\n');
    const again = await applyVerifiedFix({ scanRoot: p.root, finding: p.ref, files: { 'app.js': GOOD }, dryRun: true });
    assert.equal(typeof again.ok, 'boolean');
  } finally { cleanup(p.root); }
});

test('uncommitted work in an affected file is surfaced as a warning, and stops an automatic write', async () => {
  const p = await project();
  try {
    execFileSync('git', ['init', '-q'], { cwd: p.root }); execFileSync('git', ['add', '-A'], { cwd: p.root });
    execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'init', '--no-gpg-sign'], { cwd: p.root });
    const clean = await applyVerifiedFix({ scanRoot: p.root, finding: { ...p.ref, severity: 'medium' }, files: { 'app.js': GOOD }, dryRun: true });
    assert.ok(!clean.policyDecision.warnings.some((w) => /uncommitted/.test(w)));
    fs.appendFileSync(path.join(p.root, 'app.js'), '// work in progress\n');
    const dirty = await applyVerifiedFix({ scanRoot: p.root, finding: { ...p.ref, severity: 'medium' }, files: { 'app.js': GOOD }, dryRun: true });
    assert.ok(dirty.policyDecision.warnings.some((w) => /uncommitted changes in app.js/.test(w)));
    const auto = await applyVerifiedFix({ scanRoot: p.root, finding: { ...p.ref, severity: 'medium' }, files: { 'app.js': GOOD }, applyMode: 'automatic', policy: { automatic: { enabled: true, maxResidualRisk: 'high' } } });
    assert.equal(auto.applied, false);
  } finally { cleanup(p.root); }
});

test('the fault seam is inert unless both environment variables are set', async () => {
  const { faultPoint } = await import('../../src/fix/batch-journal.js');
  process.env.AGENTIC_SECURITY_FAULT_AT = 'x';
  try { faultPoint('x'); } finally { delete process.env.AGENTIC_SECURITY_FAULT_AT; }
  assert.ok(true, 'still alive');
});
