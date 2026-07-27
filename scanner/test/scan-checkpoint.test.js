// R8 — scan checkpointing / resume.
//
// The load-bearing property: a RESUMED scan must produce the same finding set
// as an UNINTERRUPTED one. Everything else here is invalidation discipline —
// if anything that could change the answer changed, the checkpoint is thrown
// away and the scan starts clean.
//
// The interruption in test 1 is a real one: a child process is hard-exited
// (process.exit, no unwinding, no cleanup hooks) partway through the per-file
// loop, which is byte-equivalent to a SIGKILL as far as the checkpoint file is
// concerned because every record is fsync'd before the next file starts.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  openCheckpoint, recordFileDone, completedFiles, resumeFindings,
  closeCheckpoint, computeRunKey, checkpointPath,
} from '../src/posture/scan-checkpoint.js';
import { runScan } from '../src/runScan.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUN_SCAN_URL = new URL('../src/runScan.js', import.meta.url).href;

// ---------------------------------------------------------------- fixture ---

// Enough files that an abort-after-2 leaves real work behind, and enough
// variety that both the AST taint path (JS with req.query) and the regex path
// (python, java) are exercised — the per-file payload we persist has to survive
// a JSON round-trip for both.
const FIXTURE = {
  'src/a.js': `const express = require('express');
const app = express();
app.get('/a', (req, res) => {
  const q = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + q);
  res.send("<b>" + q + "</b>");
});
app.get('/a2', (req, res) => {
  const name = req.query.name;
  const safe = encodeURIComponent(name);
  const n = parseInt(req.query.n, 10);
  res.redirect("/next?name=" + safe + "&n=" + n);
});
module.exports = app;
`,
  'src/b.js': `const cp = require('child_process');
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false, secureProtocol: 'TLSv1_method' });
// Sample value taken from the docs, not a real credential:
const SAMPLE_AUTH_TOKEN = "Zm9vYmFyQmF6UXV4MTIzNDU2Nzg5MEFiQ2RFZg";
function run(req) {
  const name = req.body.name;
  cp.exec("ls " + name);
}
module.exports = { run };
`,
  'src/c.js': `const crypto = require('crypto');
// Synthetic credential. Deliberately NOT in any real vendor's key format —
// a fixture that matches one trips external secret scanners and blocks pushes.
const API_KEY = "NOTAREALKEY_9f2a7c4be1d8035a6b7c9e0f1a2b3c4d";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI7K7MDENGbPxRfiCYzEXAMPLEKEY";
const BUILD_HASH = "3f9a1c7e5b2d84069f1a3c5e7b9d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d";
function hash(p) { return crypto.createHash('md5').update(p).digest('hex'); }
function cmp(a, b) { return a == b; }
module.exports = { hash, cmp, API_KEY, AWS_SECRET_ACCESS_KEY, BUILD_HASH };
`,
  'src/d.py': `import os, subprocess, hashlib
def handler(request):
    cmd = request.args.get("cmd")
    os.system("echo " + cmd)
    subprocess.call("sh -c " + cmd, shell=True)
    return hashlib.md5(cmd.encode()).hexdigest()
`,
  'src/e.js': `const fs = require('fs');
function read(req, res) {
  const p = req.params.file;
  res.send(fs.readFileSync("/data/" + p));
}
module.exports = { read };
`,
  'src/f.js': `const jwt = require('jsonwebtoken');
function verify(t) { return jwt.verify(t, "hardcoded-secret-value-123456", { algorithms: ['none'] }); }
module.exports = { verify };
`,
};

function makeTree(label) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `r8-${label}-`));
  for (const [rel, body] of Object.entries(FIXTURE)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, body);
  }
  return root;
}

// Canonical, order-independent representation of everything the scan claims to
// have found. If resume loses (or invents) anything, this differs.
function canonical(scan) {
  const rows = (arr, fn) => (Array.isArray(arr) ? arr.map(fn).sort() : []);
  return {
    findings: rows(scan.findings, f => [f.id, f.severity, f.file, f.line, f.cwe, f.vuln].join('␟')),
    secrets: rows(scan.secrets, s => [s.file, s.line, s.type || s.vuln || ''].join('␟')),
    logicVulns: rows(scan.logicVulns, l => [l.file, l.line, l.vuln || l.type || ''].join('␟')),
    routes: rows(scan.routes, r => [r.method, r.path, r.file, r.line].join('␟')),
    sources: rows(scan.sources, s => [s.file, s.line, s.type || '', s.variable || ''].join('␟')),
    sinks: rows(scan.sinks, s => [s.file, s.line, s.type || '', s.variable || ''].join('␟')),
    sanitizers: rows(scan.sanitizers, s => [s.file, s.line, s.type || '', s.outputVar || ''].join('␟')),
    pfrFiles: Object.keys(scan.pfr || {}).sort(),
    pfrFindings: Object.entries(scan.pfr || {}).map(([f, v]) => `${f}:${(v.findings || []).length}:${(v.sources || []).length}:${(v.sinks || []).length}:${(v.sanitizers || []).length}`).sort(),
    suppressions: rows(scan.suppressions, s => [s.file, s.line, s.vuln, s.reason].join('␟')),
    ciphers: ((scan.ciphers || {}).atRest || []).length + ((scan.ciphers || {}).inTransit || []).length,
    filesScanned: scan.filesScanned,
  };
}

// The run key covers every AGENTIC_SECURITY_* switch, so the child must inherit
// this process's environment verbatim apart from the two resume controls (both
// of which are excluded from the key by design).
const BASE_ENV = { ...process.env };

// Run a scan in a child process that hard-exits after `abortAfter` files have
// been checkpointed. Returns the child's exit code.
function interruptedScan(root, abortAfter) {
  const src = `import { runScan } from ${JSON.stringify(RUN_SCAN_URL)};\n` +
              `await runScan(${JSON.stringify(root)}, {});\n`;
  const r = cp.spawnSync(process.execPath, ['--input-type=module', '-e', src], {
    env: {
      ...BASE_ENV,
      AGENTIC_SECURITY_RESUME: '1',
      AGENTIC_SECURITY_CHECKPOINT_ABORT_AFTER: String(abortAfter),
    },
    encoding: 'utf8',
    timeout: 180_000,
  });
  return r;
}

function withEnv(extra, fn) {
  const saved = {};
  for (const k of Object.keys(extra)) { saved[k] = process.env[k]; }
  for (const [k, v] of Object.entries(extra)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  return (async () => {
    try { return await fn(); }
    finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k]; else process.env[k] = v;
      }
    }
  })();
}

// ------------------------------------------------------- 1. the real thing ---

test('resumed scan produces an identical finding set to an uninterrupted scan', async () => {
  const treeA = makeTree('base');
  const treeB = makeTree('resume');

  // Uninterrupted: default behaviour, checkpointing off entirely.
  const { scan: baseline } = await withEnv({ AGENTIC_SECURITY_RESUME: undefined }, () => runScan(treeA, {}));

  // Interrupted: hard-exit after 4 files are checkpointed.
  const child = interruptedScan(treeB, 4);
  assert.equal(child.status, 137, `child should have hard-exited; stderr=${child.stderr}`);
  const ckptFile = checkpointPath(treeB);
  assert.ok(fs.existsSync(ckptFile), 'interrupted run must leave a checkpoint behind');

  // Which files will be REPLAYED rather than rescanned. Everything below is
  // asserted against this set, so the test cannot quietly degrade into
  // "the two boring files matched" if the fixture ever drifts.
  const replayed = new Set(
    fs.readFileSync(ckptFile, 'utf8').split('\n').slice(1).filter(Boolean)
      .map(l => JSON.parse(l).f));
  assert.equal(replayed.size, 4);

  // Every channel the per-file loop appends to must actually be exercised by a
  // file that gets replayed — otherwise dropping that channel on resume would
  // go unnoticed.
  const covered = (arr) => (arr || []).some(x => replayed.has(x.file));
  assert.ok(covered(baseline.findings), 'findings not covered by the replayed set');
  assert.ok(covered(baseline.logicVulns), 'logicVulns not covered by the replayed set');
  assert.ok(covered(baseline.secrets), 'secrets not covered by the replayed set');
  assert.ok(covered(baseline.routes), 'routes not covered by the replayed set');
  assert.ok(covered(baseline.sources), 'taint sources not covered by the replayed set');
  assert.ok(covered(baseline.sinks), 'taint sinks not covered by the replayed set');
  assert.ok(covered(baseline.sanitizers), 'sanitizers not covered by the replayed set');
  assert.ok(covered(baseline.suppressions), 'suppressions not covered by the replayed set');
  assert.ok(covered(baseline.ciphers.atRest), 'at-rest ciphers not covered by the replayed set');
  assert.ok(covered(baseline.ciphers.inTransit), 'in-transit ciphers not covered by the replayed set');

  // Resume.
  const { scan: resumed } = await withEnv({ AGENTIC_SECURITY_RESUME: '1' }, () => runScan(treeB, {}));

  assert.equal(resumed._scanMeta.checkpoint.resumed, 4,
    `expected 4 files replayed from the checkpoint, got ${resumed._scanMeta.checkpoint.resumed}`);
  assert.ok(resumed._scanMeta.checkpoint.resumed < resumed._scanMeta.checkpoint.total,
    'the resume must still have had work left to do');

  assert.deepEqual(canonical(resumed), canonical(baseline));

  // And a clean completion removes the checkpoint (test 5).
  assert.equal(fs.existsSync(ckptFile), false, 'clean completion must remove the checkpoint');

  // The next run therefore cannot resume stale state.
  const { scan: third } = await withEnv({ AGENTIC_SECURITY_RESUME: '1' }, () => runScan(treeB, {}));
  assert.equal(third._scanMeta.checkpoint.resumed, 0);
  assert.deepEqual(canonical(third), canonical(baseline));

  fs.rmSync(treeA, { recursive: true, force: true });
  fs.rmSync(treeB, { recursive: true, force: true });
});

// ------------------------------------------------- 2. content invalidation ---

test('changing a source file after the checkpoint discards it', async () => {
  const treeA = makeTree('changed-base');
  const treeB = makeTree('changed');

  const child = interruptedScan(treeB, 2);
  assert.equal(child.status, 137, child.stderr);
  assert.ok(fs.existsSync(checkpointPath(treeB)));

  // Mutate a source file — the file-set signature is content-hashed, so this
  // invalidates the whole checkpoint, not just that one entry.
  fs.appendFileSync(path.join(treeB, 'src/c.js'),
    `\nfunction alsoBad(req){ return eval(req.query.x); }\nmodule.exports.alsoBad = alsoBad;\n`);
  fs.appendFileSync(path.join(treeA, 'src/c.js'),
    `\nfunction alsoBad(req){ return eval(req.query.x); }\nmodule.exports.alsoBad = alsoBad;\n`);

  const { scan: resumed } = await withEnv({ AGENTIC_SECURITY_RESUME: '1' }, () => runScan(treeB, {}));
  assert.equal(resumed._scanMeta.checkpoint.resumed, 0, 'a changed source file must force a clean scan');

  const { scan: baseline } = await withEnv({ AGENTIC_SECURITY_RESUME: undefined }, () => runScan(treeA, {}));
  assert.deepEqual(canonical(resumed), canonical(baseline));

  fs.rmSync(treeA, { recursive: true, force: true });
  fs.rmSync(treeB, { recursive: true, force: true });
});

test('adding or removing a file discards the checkpoint', async () => {
  const tree = makeTree('fileset');
  const child = interruptedScan(tree, 2);
  assert.equal(child.status, 137, child.stderr);

  fs.writeFileSync(path.join(tree, 'src/g.js'), 'module.exports = 1;\n');
  const { scan } = await withEnv({ AGENTIC_SECURITY_RESUME: '1' }, () => runScan(tree, {}));
  assert.equal(scan._scanMeta.checkpoint.resumed, 0);

  fs.rmSync(tree, { recursive: true, force: true });
});

// ------------------------------------------------ 3. identity invalidation ---

test('changing the ruleset version discards the checkpoint end-to-end', async () => {
  const tree = makeTree('ruleset');
  const child = interruptedScan(tree, 2);
  assert.equal(child.status, 137, child.stderr);
  assert.ok(fs.existsSync(checkpointPath(tree)));

  // Pin a different ruleset version via the state file rather than the env var:
  // env vars are separately folded into the run key, so going through the file
  // is what actually proves the ruleset-version input is honoured.
  fs.writeFileSync(path.join(tree, '.agentic-security', 'ruleset-version.json'),
    JSON.stringify({ version: '99.99.99-not-the-one-that-wrote-it', pinned: true }));

  const { scan } = await withEnv({ AGENTIC_SECURITY_RESUME: '1' }, () => runScan(tree, {}));
  assert.equal(scan._scanMeta.checkpoint.resumed, 0, 'a different ruleset version must not resume');

  fs.rmSync(tree, { recursive: true, force: true });
});

test('engine version, ruleset version and bundle sha each change the run key', () => {
  const fileContents = { 'a.js': 'x', 'b.js': 'y' };
  const base = { engineVersion: '1.0.0', rulesetVersion: '1.0.0', bundleSha: 'aa', fileContents };
  const k = computeRunKey(base);
  assert.match(k, /^[0-9a-f]{64}$/);
  assert.notEqual(k, computeRunKey({ ...base, engineVersion: '1.0.1' }));
  assert.notEqual(k, computeRunKey({ ...base, rulesetVersion: '1.0.1' }));
  assert.notEqual(k, computeRunKey({ ...base, bundleSha: 'bb' }));
  assert.notEqual(k, computeRunKey({ ...base, fileContents: { 'a.js': 'x', 'b.js': 'z' } }));
  assert.notEqual(k, computeRunKey({ ...base, fileContents: { 'a.js': 'x' } }));
  assert.notEqual(k, computeRunKey({ ...base, fileContents: { 'a.js': 'x', 'b.js': 'y', 'c.js': '' } }));
  assert.notEqual(k, computeRunKey({ ...base, depFileContents: { 'package.json': '{}' } }));
  // Same inputs → same key (otherwise nothing would ever resume).
  assert.equal(k, computeRunKey({ ...base }));
});

test('a checkpoint written under one run key is not readable under another', () => {
  const tree = makeTree('runkey');
  const h1 = openCheckpoint(tree, { runKey: 'a'.repeat(64) });
  recordFileDone(h1, 'src/a.js', { findings: [{ id: 'x' }] });
  closeCheckpoint(h1, { complete: false });

  const h2 = openCheckpoint(tree, { runKey: 'b'.repeat(64) });
  assert.equal(completedFiles(h2).size, 0);
  assert.deepEqual(resumeFindings(h2), []);
  closeCheckpoint(h2, { complete: true });

  fs.rmSync(tree, { recursive: true, force: true });
});

// ------------------------------------------------------ 4. corrupt / torn ---

test('a corrupt header discards the whole checkpoint without throwing', () => {
  const tree = makeTree('corrupt-header');
  const key = 'c'.repeat(64);
  const h1 = openCheckpoint(tree, { runKey: key });
  recordFileDone(h1, 'src/a.js', { findings: [] });
  closeCheckpoint(h1, { complete: false });

  const file = checkpointPath(tree);
  fs.writeFileSync(file, '{not json at all\n{"f":"src/a.js"}\n');
  const h2 = openCheckpoint(tree, { runKey: key });
  assert.equal(completedFiles(h2).size, 0);
  assert.equal(h2.enabled, true, 'a discarded checkpoint should still be usable for new records');
  closeCheckpoint(h2, { complete: true });

  fs.rmSync(tree, { recursive: true, force: true });
});

test('a torn final record is dropped and the good prefix survives', () => {
  const tree = makeTree('torn');
  const key = 'd'.repeat(64);
  const h1 = openCheckpoint(tree, { runKey: key });
  recordFileDone(h1, 'src/a.js', { findings: [{ id: 'one' }] });
  recordFileDone(h1, 'src/b.js', { findings: [{ id: 'two' }] });
  closeCheckpoint(h1, { complete: false });

  // Simulate a process killed mid-write: chop the tail of the file.
  const file = checkpointPath(tree);
  const raw = fs.readFileSync(file);
  fs.writeFileSync(file, raw.subarray(0, raw.length - 12));

  const h2 = openCheckpoint(tree, { runKey: key });
  const done = completedFiles(h2);
  assert.equal(done.has('src/a.js'), true, 'the complete record must survive');
  assert.equal(done.has('src/b.js'), false, 'the torn record must be dropped');
  // Appending after recovery must still produce a readable file.
  recordFileDone(h2, 'src/b.js', { findings: [{ id: 'two' }] });
  closeCheckpoint(h2, { complete: false });
  const h3 = openCheckpoint(tree, { runKey: key });
  assert.deepEqual([...completedFiles(h3)].sort(), ['src/a.js', 'src/b.js']);
  assert.deepEqual(resumeFindings(h3).map(r => r.file), ['src/a.js', 'src/b.js']);
  closeCheckpoint(h3, { complete: true });

  fs.rmSync(tree, { recursive: true, force: true });
});

test('a checksum-tampered record is dropped', () => {
  const tree = makeTree('tamper');
  const key = 'e'.repeat(64);
  const h1 = openCheckpoint(tree, { runKey: key });
  recordFileDone(h1, 'src/a.js', { findings: [{ id: 'one' }] });
  recordFileDone(h1, 'src/b.js', { findings: [{ id: 'two' }] });
  closeCheckpoint(h1, { complete: false });

  const file = checkpointPath(tree);
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const rec = JSON.parse(lines[1]);
  rec.d = rec.d.replace('one', 'ONE');
  lines[1] = JSON.stringify(rec);
  fs.writeFileSync(file, lines.join('\n'));

  const h2 = openCheckpoint(tree, { runKey: key });
  assert.equal(completedFiles(h2).size, 0, 'a tampered record and everything after it must be dropped');
  closeCheckpoint(h2, { complete: true });

  fs.rmSync(tree, { recursive: true, force: true });
});

test('a corrupt checkpoint does not change the scan result', async () => {
  const treeA = makeTree('corrupt-base');
  const treeB = makeTree('corrupt-scan');

  const child = interruptedScan(treeB, 2);
  assert.equal(child.status, 137, child.stderr);
  const file = checkpointPath(treeB);
  const raw = fs.readFileSync(file);
  fs.writeFileSync(file, Buffer.concat([raw.subarray(0, Math.floor(raw.length / 2)), Buffer.from('  garbage')]));

  const { scan: resumed } = await withEnv({ AGENTIC_SECURITY_RESUME: '1' }, () => runScan(treeB, {}));
  const { scan: baseline } = await withEnv({ AGENTIC_SECURITY_RESUME: undefined }, () => runScan(treeA, {}));
  assert.deepEqual(canonical(resumed), canonical(baseline));

  fs.rmSync(treeA, { recursive: true, force: true });
  fs.rmSync(treeB, { recursive: true, force: true });
});

// ------------------------------------------------------------- 5. default ---

test('checkpointing is off by default and writes nothing', async () => {
  const tree = makeTree('default-off');
  const { scan } = await withEnv({ AGENTIC_SECURITY_RESUME: undefined }, () => runScan(tree, {}));
  assert.equal(scan._scanMeta.checkpoint.enabled, false);
  assert.equal(fs.existsSync(checkpointPath(tree)), false);
  fs.rmSync(tree, { recursive: true, force: true });
});

test('checkpoint helpers never throw on a disabled or bogus handle', () => {
  const h = openCheckpoint(null, {});
  assert.equal(h.enabled, false);
  assert.equal(recordFileDone(h, 'a.js', { findings: [] }), false);
  assert.equal(completedFiles(h).size, 0);
  assert.deepEqual(resumeFindings(h), []);
  assert.equal(closeCheckpoint(h, { complete: true }), false);
  assert.equal(recordFileDone(null, 'a.js', {}), false);
  assert.equal(completedFiles(null).size, 0);
  assert.deepEqual(resumeFindings(undefined), []);
  assert.equal(closeCheckpoint(undefined, { complete: true }), false);
});

test('values JSON cannot round-trip are refused rather than silently mangled', () => {
  const tree = makeTree('jsonsafe');
  const h = openCheckpoint(tree, { runKey: 'f'.repeat(64) });
  assert.equal(recordFileDone(h, 'a.js', { findings: [{ when: new Date() }] }), false);
  assert.equal(recordFileDone(h, 'b.js', { findings: [{ re: /x/ }] }), false);
  assert.equal(recordFileDone(h, 'c.js', { findings: [{ fn: () => 1 }] }), false);
  assert.equal(recordFileDone(h, 'd.js', { findings: [{ m: new Map() }] }), false);
  assert.equal(recordFileDone(h, 'e.js', { findings: [{ ok: 1, s: 'x', n: null, a: [1, 2] }] }), true);
  assert.deepEqual([...completedFiles(h)], ['e.js']);
  closeCheckpoint(h, { complete: true });
  fs.rmSync(tree, { recursive: true, force: true });
});

test('checkpoint state lives under .agentic-security/ in the scan root', () => {
  const p = checkpointPath('/some/root');
  assert.equal(p, path.join('/some/root', '.agentic-security', 'scan-checkpoint.jsonl'));
  assert.ok(!p.includes(HERE), 'must never be written into the scanner source tree');
});
