// E2-04: async, callbacks and framework propagation, from request ingress to a sensitive sink, each with a safe sibling.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { cleanup } from './helpers.js';
import { runScan } from '../../src/runScan.js';
import { buildProjectIR } from '../../src/ir/index.js';

// Deep analysis is off under CI unless asked for (engine.js); these tests need the deep layer, so a hosted runner must not change what they measure.
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

const H = "const { exec } = require('child_process');\nconst express = require('express');\nconst app = express();\n";
async function cmdi(src) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e2d-'));
  try {
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}'); fs.writeFileSync(path.join(root, 'app.js'), H + src);
    const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
    let scan; try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
    return scan.findings.some((f) => /CWE-78$/.test(f.cwe || '') && f.parser === 'IR-TAINT');
  } finally { cleanup(root); }
}
const route = (body, pre = '') => `${pre}app.get('/a', async (req, res) => {\n${body}\n});\n`;

const PAIRS = [
  ['an awaited value', route("  const c = await Promise.resolve(req.query.c);\n  exec('x ' + c);"), route("  const c = await Promise.resolve('ls');\n  exec('x ' + c);")],
  ['an awaited async helper (block body)', route("  const c = await get(req);\n  exec('x ' + c);", "async function get(req) { return req.query.c; }\n"), route("  const c = await get(req);\n  exec('x ' + c);", "async function get(req) { return 'ls'; }\n")],
  ['an awaited async helper (expression-bodied arrow)', route("  const c = await get(req);\n  exec('x ' + c);", "const get = async (req) => req.query.c;\n"), route("  const c = await get(req);\n  exec('x ' + c);", "const get = async (req) => 'ls';\n")],
  ['a synchronous expression-bodied arrow helper', route("  const c = get(req);\n  exec('x ' + c);", "const get = (req) => req.query.c;\n"), route("  const c = get(req);\n  exec('x ' + c);", "const get = (req) => 'ls';\n")],
  ['a promise .then callback', route("  fetchIt(req.query.c).then((c) => exec('x ' + c));"), route("  fetchIt('ls').then((c) => exec('x ' + c));")],
  ['a user-defined callback', route("  later(req.query.c, (c) => exec('x ' + c));", "function later(v, cb) { cb(v); }\n"), route("  later('ls', (c) => exec('x ' + c));", "function later(v, cb) { cb(v); }\n")],
  ['a callback given a clean value by its caller', route("  later(req.query.c, (c) => exec('x ' + c));", "function later(v, cb) { cb(v); }\n"), route("  later(req.query.c, (c) => exec('x ' + c));", "function later(v, cb) { cb('ls'); }\n")],
  ['a middleware that stores a field on the request', "app.use((req, res, next) => { req.cmd = req.query.c; next(); });\napp.get('/a', (req, res) => {\n  exec('x ' + req.cmd);\n});\n", "app.use((req, res, next) => { req.cmd = req.query.c; next(); });\napp.get('/a', (req, res) => {\n  exec('x ' + req.other);\n});\n"],
  ['a middleware that stores a nested field', "app.use((req, res, next) => { req.ctx = { cmd: req.query.c }; next(); });\napp.get('/a', (req, res) => {\n  exec('x ' + req.ctx.cmd);\n});\n", "app.use((req, res, next) => { req.ctx = { cmd: req.query.c, safe: 'ls' }; next(); });\napp.get('/a', (req, res) => {\n  exec('x ' + req.ctx.safe);\n});\n"],
  ['a named handler registered on the router', "function handler(req, res) { exec('x ' + req.query.c); }\napp.get('/a', handler);\n", "function handler(req, res) { exec('x ' + 'ls'); }\napp.get('/a', handler);\n"],
  ['a handler inside try/catch', route("  try { const c = await Promise.resolve(req.query.c); exec('x ' + c); } catch (e) { res.sendStatus(500); }"), route("  try { const c = await Promise.resolve('ls'); exec('x ' + c); } catch (e) { res.sendStatus(500); }")],
  ['a class method called from the handler', "class C { run(req) { exec('x ' + req.query.c); } }\nconst c = new C();\napp.get('/a', (req, res) => c.run(req));\n", "class C { run(req) { exec('x ' + 'ls'); } }\nconst c = new C();\napp.get('/a', (req, res) => c.run(req));\n"],
];
for (const [name, vuln, safe] of PAIRS) {
  test(`ingress to sink: ${name}: found, and the safe sibling is silent`, async () => {
    assert.equal(await cmdi(vuln), true, 'vulnerable form');
    assert.equal(await cmdi(safe), false, 'safe sibling');
  });
}

test('the callback of .catch receives an error, not the value: it is not tainted by the receiver', async () => {
  assert.equal(await cmdi(route("  fetchIt(req.query.c).catch((e) => exec('x ' + e));")), false);
});

test('an expression-bodied arrow now records its return; block bodies are unchanged', () => {
  const ir = buildProjectIR({ 'a.js': "const a = (x) => x + 1;\nconst b = (x) => { return x + 1; };\nconst c = (x) => { x + 1; };\nconst d = () => sink(1);\n" });
  const by = Object.fromEntries(ir.perFile['a.js'].functions.map((f) => [f.name, f]));
  assert.equal(by.a.returns.length, 1); assert.equal(by.b.returns.length, 1); assert.equal(by.c.returns.length, 0, 'a block body without return returns nothing');
  assert.equal(by.d.returns.length, 1);
  const calls = Object.values(by.d.cfg.nodes).map((n) => n.kind);
  assert.ok(calls.indexOf('call') < calls.indexOf('return'), 'the return follows the call it contains');
});

test('known gaps are stated as gaps, not hidden: Promise.all destructuring and EventEmitter hand-off are not followed', async () => {
  assert.equal(await cmdi(route("  const [c] = await Promise.all([Promise.resolve(req.query.c)]);\n  exec('x ' + c);")), false);
  assert.equal(await cmdi("const EventEmitter = require('events');\nconst bus = new EventEmitter();\nbus.on('cmd', (c) => exec('x ' + c));\napp.get('/a', (req, res) => { bus.emit('cmd', req.query.c); });\n"), false);
});

test('request-field propagation is same-file only: a field set in another file is not assumed', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e2d2-'));
  try {
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}');
    fs.writeFileSync(path.join(root, 'mw.js'), "module.exports = (req, res, next) => { req.cmd = req.query.c; next(); };\n");
    fs.writeFileSync(path.join(root, 'app.js'), H + "app.get('/a', (req, res) => {\n  exec('x ' + req.cmd);\n});\n");
    const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
    let scan; try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
    assert.equal(scan.findings.some((f) => /CWE-78$/.test(f.cwe || '') && f.parser === 'IR-TAINT'), false, 'documented limit: cross-file middleware chains need a router model');
  } finally { cleanup(root); }
});
