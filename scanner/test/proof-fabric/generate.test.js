// Reproducer generation from a finding's evidence (PRD 1): what it builds, what it refuses by name, and, with the sandbox,
// that a generated reproducer is confirmed on the vulnerable code and NOT on a mitigated twin by the unchanged proof machinery.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { generateReproducer } from '../../src/posture/proof-fabric/generate.js';
import { proveFinding } from '../../src/posture/proof-fabric/orchestrator.js';
import { validateReproducer } from '../../src/posture/proof-fabric/reproducer.js';
import { sandboxAvailable, detectBackend } from '../../src/sandbox/index.js';

const sandbox = sandboxAvailable() ? false : 'no confinement backend on this host';
function repo(files) {
  const dir = mkTestTmp('gen-repro-');
  for (const [f, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true }); fs.writeFileSync(path.join(dir, f), c); }
  return dir;
}
const F = (over = {}) => ({ id: 'F1', stableId: 'F1', cwe: 'CWE-78', file: 'app.js', line: 1, parser: 'IR-TAINT', ...over });
const prove = (finding, dir, reproducer) => proveFinding({ finding, reproducer, sourceRoot: dir, policy: { timeoutMs: 20000 } });

const SCRIPT_VULN = "import { execSync } from 'node:child_process';\nconst userInput = process.argv[2] || '';\ntry { execSync(`echo hello; ${userInput}`, { stdio: 'ignore' }); } catch { /* ignore */ }\n";
const SCRIPT_SAFE = "import { spawnSync } from 'node:child_process';\nconst userInput = process.argv[2] || '';\nspawnSync('echo', ['hello', userInput], { stdio: 'ignore', shell: false });\n";
const CJS_FN_VULN = "const { execSync } = require('child_process');\nfunction run(name) {\n  execSync('echo ' + name, { stdio: 'ignore' });\n}\nmodule.exports = { run };\n";
const CJS_FN_SAFE = "const { execFileSync } = require('child_process');\nfunction run(name) {\n  execFileSync('echo', [name], { stdio: 'ignore' });\n}\nmodule.exports = { run };\n";
const HANDLER_VULN = "const { exec } = require('child_process');\nfunction handler(req, res) {\n  exec('ping -c 1 ' + req.body.host, () => res.send('done'));\n}\nmodule.exports = handler;\n";
const HANDLER_SAFE = "const { execFile } = require('child_process');\nfunction handler(req, res) {\n  execFile('ping', ['-c', '1', req.body.host], () => res.send('done'));\n}\nmodule.exports = handler;\n";

test('script shape: a program that reads process.argv[2] is run with the payload', () => {
  const dir = repo({ 'app.mjs': SCRIPT_VULN });
  const r = generateReproducer({ finding: F({ file: 'app.mjs', line: 3 }), root: dir });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.basis.shape, 'script'); assert.equal(r.basis.class, 'command-injection');
  assert.deepEqual(validateReproducer(r.reproducer), []);
  assert.equal(r.reproducer.sources['target.mjs'], 'app.mjs');
  assert.deepEqual(r.reproducer.run, ['{{NODE}}', 'target.mjs', 'x; touch {{CANARY:command}}']);
  assert.equal(r.reproducer.oracle.type, 'command_execution');
});

test('function shape: the exported function is loaded and called, with the tainted parameter filled', () => {
  const dir = repo({ 'lib.js': CJS_FN_VULN });
  const r = generateReproducer({ finding: F({ file: 'lib.js', line: 3 }), root: dir });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.basis.shape, 'function'); assert.equal(r.basis.taintedParameter, 'name'); assert.match(r.basis.function, /^run\(name\)$/);
  assert.match(r.reproducer.files['harness.mjs'], /createRequire/); assert.match(r.reproducer.files['harness.mjs'], /mod\["run"\]/);
  assert.equal(r.reproducer.sources['target.cjs'], 'lib.js');
  const h = generateReproducer({ finding: F({ file: 'h.js', line: 3 }), root: repo({ 'h.js': HANDLER_VULN }) });
  assert.equal(h.ok, true, h.reason); assert.equal(h.basis.requestLike, true); assert.match(h.reproducer.files['harness.mjs'], /body: P, query: P, params: P/);
});

test('ES modules are loaded as modules; named, default and CommonJS exports are all found', () => {
  const esm = generateReproducer({ finding: F({ cwe: 'CWE-918', file: 'f.js', line: 2 }), root: repo({ 'f.js': "export async function download(url) {\n  return fetch(url);\n}\n" }) });
  assert.equal(esm.ok, true, esm.reason); assert.equal(esm.reproducer.sources['target.mjs'], 'f.js'); assert.match(esm.reproducer.files['harness.mjs'], /await import\('\.\/target\.mjs'\)/);
  assert.equal(esm.reproducer.network, 'callback'); assert.deepEqual(esm.reproducer.run.slice(-1), ['{{CALLBACK_URL}}']);
  const def = generateReproducer({ finding: F({ file: 'd.js', line: 2 }), root: repo({ 'd.js': "export default function (cmd) {\n  require('child_process').execSync(cmd);\n}\n" }) });
  assert.equal(def.ok, true, def.reason); assert.match(def.reproducer.files['harness.mjs'], /mod\.default \?\? mod/);
  const exp = generateReproducer({ finding: F({ file: 'e.js', line: 3 }), root: repo({ 'e.js': "const cp = require('child_process');\nexports.go = function go(c) {\n  cp.execSync(c);\n};\n" }) });
  assert.equal(exp.ok, true, exp.reason); assert.match(exp.reproducer.files['harness.mjs'], /mod\["go"\]/);
});

test('relative imports are mirrored into the workspace; anything else the sandbox cannot load is refused by name', () => {
  const ok = generateReproducer({ finding: F({ file: 'src/app.js', line: 3 }), root: repo({ 'src/app.js': "const lib = require('./lib');\nfunction run(c) {\n  require('child_process').execSync(c + lib.suffix);\n}\nmodule.exports = run;\n", 'src/lib.js': 'exports.suffix = "";\n' }) });
  assert.equal(ok.ok, true, ok.reason); assert.equal(ok.reproducer.sources['lib.js'], 'src/lib.js');
  const ext = generateReproducer({ finding: F({ file: 'h.js', line: 3 }), root: repo({ 'h.js': "const express = require('express');\nfunction h(req, res) {\n  require('child_process').exec(req.body.x);\n}\nmodule.exports = h;\n" }) });
  assert.equal(ext.ok, false); assert.match(ext.reason, /needs express/); assert.deepEqual(ext.missing, ['express']);
  const up = generateReproducer({ finding: F({ file: 'a/b.js', line: 3 }), root: repo({ 'a/b.js': "const u = require('../util');\nfunction r(c) {\n  require('child_process').execSync(c);\n}\nmodule.exports = r;\n", 'util.js': 'module.exports = 1;' }) });
  assert.equal(up.ok, false); assert.match(up.reason, /outside the flagged file's directory/);
  const missing = generateReproducer({ finding: F({ file: 'm.js', line: 3 }), root: repo({ 'm.js': "const u = require('./nope');\nfunction r(c) {\n  require('child_process').execSync(c);\n}\nmodule.exports = r;\n" }) });
  assert.equal(missing.ok, false); assert.match(missing.reason, /"\.\/nope" was not found/);
  const many = { 'm.js': `${Array.from({ length: 10 }, (_, i) => `require('./d${i}');`).join('\n')}\nfunction r(c) {\n  require('child_process').execSync(c);\n}\nmodule.exports = r;\n` };
  for (let i = 0; i < 10; i++) many[`d${i}.js`] = 'module.exports = 1;';
  const mr = generateReproducer({ finding: F({ file: 'm.js', line: 12 }), root: repo(many) });
  assert.equal(mr.ok, false); assert.match(mr.reason, /more than 8 repository files/);
});

test('a finding it cannot build a harness for is refused with the reason, and nothing is invented', () => {
  const dir = repo({ 'lib.js': CJS_FN_VULN, 'private.js': "function inner(c) {\n  require('child_process').execSync(c);\n}\n", 'noargs.js': "function r() {\n  require('child_process').execSync('ls');\n}\nmodule.exports = r;\n", 'top.js': "require('child_process').execSync('ls ' + process.env.X);\n", 'broken.js': 'function (', 'readonly.js': "const fs = require('fs');\nfunction r(name) {\n  return fs.readFileSync('/srv/' + name);\n}\nmodule.exports = r;\n", 'x.py': 'import os\n' });
  const cases = [
    [F({ cwe: 'CWE-89', file: 'lib.js', line: 3 }), /no payload and oracle exist for CWE-89/], [F({ cwe: undefined, file: 'lib.js', line: 3 }), /no payload and oracle/],
    [F({ file: 'x.rb', line: 1 }), /JavaScript, Python and Haskell only/], [F({ file: 'lib.js', line: undefined }), /no line number/], [F({ file: 'gone.js', line: 1 }), /missing, outside/],
    [F({ file: '../escape.js', line: 1 }), /missing, outside/], [F({ file: 'broken.js', line: 1 }), /could not be parsed/], [F({ file: 'private.js', line: 2 }), /not exported/],
    [F({ file: 'noargs.js', line: 2 }), /takes no parameters/], [F({ file: 'top.js', line: 1 }), /not inside a function/], [F({ cwe: 'CWE-22', file: 'readonly.js', line: 3 }), /only observe a write/],
  ];
  for (const [finding, re] of cases) { const r = generateReproducer({ finding, root: dir }); assert.equal(r.ok, false, JSON.stringify(finding)); assert.match(r.reason, re, JSON.stringify(finding)); assert.equal(r.reproducer, undefined); }
  assert.equal(generateReproducer({ finding: null, root: dir }).ok, false);
});

test('a symlink out of the repository is not followed', () => {
  const dir = repo({ 'real.js': CJS_FN_VULN });
  const outside = mkTestTmp('gen-out-'); fs.writeFileSync(path.join(outside, 'o.js'), CJS_FN_VULN);
  fs.symlinkSync(path.join(outside, 'o.js'), path.join(dir, 'link.js'));
  const r = generateReproducer({ finding: F({ file: 'link.js', line: 3 }), root: dir });
  assert.equal(r.ok, false); assert.match(r.reason, /missing, outside/);
});

test('a generated reproducer is CONFIRMED on the vulnerable code and NOT on the mitigated twin (script)', { skip: sandbox, timeout: 120000 }, async () => {
  const vdir = repo({ 'app.mjs': SCRIPT_VULN }); const sdir = repo({ 'app.mjs': SCRIPT_SAFE });
  const g = generateReproducer({ finding: F({ file: 'app.mjs', line: 3 }), root: vdir });
  const bad = await prove(F({ file: 'app.mjs', line: 3 }), vdir, g.reproducer);
  assert.equal(bad.state, 'EXPLOIT_CONFIRMED', `${bad.outcome}: ${bad.degradation}`);
  const good = await prove(F({ file: 'app.mjs', line: 3 }), sdir, g.reproducer);
  assert.notEqual(good.state, 'EXPLOIT_CONFIRMED');
});

test('a generated reproducer is confirmed on an exported function and on a request handler, and not on their mitigated twins', { skip: sandbox, timeout: 240000 }, async () => {
  for (const [vuln, safe, file, line] of [[CJS_FN_VULN, CJS_FN_SAFE, 'lib.js', 3], [HANDLER_VULN, HANDLER_SAFE, 'h.js', 3]]) {
    const vdir = repo({ [file]: vuln }); const sdir = repo({ [file]: safe });
    const g = generateReproducer({ finding: F({ file, line }), root: vdir });
    assert.equal(g.ok, true, g.reason);
    const bad = await prove(F({ file, line }), vdir, g.reproducer);
    assert.equal(bad.state, 'EXPLOIT_CONFIRMED', `${file}: ${bad.outcome}: ${bad.degradation}`);
    const good = await prove(F({ file, line }), sdir, g.reproducer);
    assert.notEqual(good.state, 'EXPLOIT_CONFIRMED', `${file}: the mitigated twin must not be confirmed`);
  }
});

test('path traversal (write) and SSRF are confirmed by execution too', { skip: sandbox, timeout: 240000 }, async () => {
  const wr = repo({ 'save.js': "const fs = require('fs');\nconst path = require('path');\nfunction save(name) {\n  const base = path.join(process.cwd(), 'public');\n  fs.mkdirSync(base, { recursive: true });\n  fs.writeFileSync(path.join(base, name), 'x');\n}\nmodule.exports = save;\n" });
  const g = generateReproducer({ finding: F({ cwe: 'CWE-22', file: 'save.js', line: 6 }), root: wr });
  assert.equal(g.ok, true, g.reason); assert.ok(g.basis.assumptions.some((a) => /one directory below/.test(a)));
  const r = await prove(F({ cwe: 'CWE-22', file: 'save.js', line: 6 }), wr, g.reproducer);
  assert.equal(r.state, 'EXPLOIT_CONFIRMED', `${r.outcome}: ${r.degradation}`);
  if (detectBackend() === 'userspace') {
    const dl = repo({ 'f.mjs': "export async function download(url) {\n  try { await fetch(url); } catch { /* the listener answers */ }\n}\n" });
    const gs = generateReproducer({ finding: F({ cwe: 'CWE-918', file: 'f.mjs', line: 2 }), root: dl });
    const rs = await prove(F({ cwe: 'CWE-918', file: 'f.mjs', line: 2 }), dl, gs.reproducer);
    assert.equal(rs.state, 'EXPLOIT_CONFIRMED', `${rs.outcome}: ${rs.degradation}`);
  }
});
