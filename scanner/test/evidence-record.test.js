import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { runScan } from '../src/runScan.js';
import { toJSON } from '../src/report/index.js';
import { sourceState, invocationSummary, reconcileFindings } from '../src/pipeline/evidence-record.js';
import { mkTestTmp } from './helpers/tmp.js';

const APP = "const cp = require('child_process');\nmodule.exports = (r) => cp.exec('ls ' + r.query.d);\n";
const git = (d, ...a) => cp.spawnSync('git', ['-c', 'user.email=a@b.c', '-c', 'user.name=t', ...a], { cwd: d, encoding: 'utf8' });

function repo() {
  const d = mkTestTmp('agsec-evid-');
  fs.writeFileSync(path.join(d, 'package.json'), '{}');
  fs.writeFileSync(path.join(d, 'app.js'), APP);
  git(d, 'init', '-q'); git(d, 'add', '-A'); git(d, 'commit', '-q', '-m', 'init');
  return d;
}

test('scan record ties the run to a commit and names the dirty files with digests', async () => {
  const d = repo();
  const clean = sourceState(d);
  assert.equal(clean.vcs, 'git'); assert.equal(clean.dirty, false); assert.match(clean.commit, /^[0-9a-f]{40}$/);
  fs.writeFileSync(path.join(d, 'app.js'), APP + '// edit\n');
  fs.writeFileSync(path.join(d, 'new.js'), 'x\n');
  const dirty = sourceState(d);
  assert.equal(dirty.dirty, true);
  assert.deepEqual(dirty.dirtyFiles.map((f) => f.file).sort(), ['app.js', 'new.js']);
  assert.ok(dirty.dirtyFiles.every((f) => /^[0-9a-f]{64}$/.test(f.sha256)));
  const none = sourceState(mkTestTmp('agsec-evid-nogit-'));
  assert.equal(none.vcs, 'none');
});

test('a scan carries the scan record and each finding carries a record with source hash, span and disposition', async () => {
  const d = repo();
  const { scan, meta } = await runScan(d, { invocation: ['--format', 'json', '--api-key', 'sk-secret'] });
  const r = scan.scanRecord;
  assert.equal(r.schema, 'scan-record/1');
  assert.equal(r.source.commit, sourceState(d).commit);
  assert.ok(r.invocation.flags.includes('--format=json'));
  assert.ok(r.invocation.flags.includes('--api-key=<redacted>'));
  assert.doesNotMatch(JSON.stringify(r), /sk-secret/);
  const f = scan.findings.find((x) => x.file === 'app.js');
  assert.match(f.record.sourceHash, /^[0-9a-f]{64}$/);
  assert.ok(f.record.span.startLine >= 1);
  assert.equal(f.record.disposition, f.disposition);
  assert.equal(f.record.stableId, f.stableId);
  const json = toJSON(scan, meta);
  assert.equal(json.scanRecord.schema, 'scan-record/1');
  const jf = json.findings.find((x) => x.file === 'app.js');
  assert.ok(jf.record && jf.disposition);
});

test('the stable id survives a harmless line shift and the source hash changes', async () => {
  const d = repo();
  const a = (await runScan(d)).scan.findings.find((x) => x.file === 'app.js');
  fs.writeFileSync(path.join(d, 'app.js'), '\n\n// shifted\n' + APP);
  const b = (await runScan(d)).scan.findings.find((x) => x.file === 'app.js');
  assert.equal(a.stableId, b.stableId);
  assert.notEqual(a.record.sourceHash, b.record.sourceHash);
  assert.notEqual(a.line, b.line);
});

test('raw and displayed findings reconcile only when every difference is named', () => {
  assert.equal(reconcileFindings({ raw: 10, displayed: 6, hidden: { sca: 3, generated: 1 } }).ok, true);
  const bad = reconcileFindings({ raw: 10, displayed: 6, hidden: { sca: 3 } });
  assert.equal(bad.ok, false); assert.equal(bad.gap, 1);
  assert.deepEqual(invocationSummary(['scan', '.', '--token', 'abc', '--deep']), ['--token=<redacted>', '--deep']);
});
