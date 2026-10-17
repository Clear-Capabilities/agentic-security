// E2-03: field-sensitive heap, aliases, collections and closures. Every positive has an adversarial negative; known gaps are asserted as gaps.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { cleanup } from './helpers.js';
import { runScan } from '../../src/runScan.js';
import { buildProjectIR } from '../../src/ir/index.js';
import { analysisLimits } from '../../src/dataflow/analysis-limits.js';
import { buildSemanticGraph, validateGraph } from '../../src/ir/semantic-graph.js';
import { hasTaintedDescendant, isCoveredBy } from '../../src/dataflow/access-paths.js';

// Deep analysis is off under CI unless asked for (engine.js); these tests need the deep layer, so a hosted runner must not change what they measure.
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

const H = "const { exec } = require('child_process');\nexports.h = (req, res) => {\n";
const T = '\n};\n';
async function cmdi(src, file = 'a.js') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e2c-'));
  try {
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}'); fs.writeFileSync(path.join(root, file), src);
    const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
    let scan; try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
    return scan.findings.some((f) => /CWE-78$/.test(f.cwe || '') && f.parser === 'IR-TAINT');
  } finally { cleanup(root); }
}

const POSITIVES = {
  'a field assigned after creation': "  const o = {};\n  o.cmd = req.query.c;\n  exec('x ' + o.cmd);",
  'a field of an object literal': "  const o = { cmd: req.query.c };\n  exec('x ' + o.cmd);",
  'a nested literal field': "  const o = { in: { cmd: req.query.c } };\n  exec('x ' + o.in.cmd);",
  'destructuring': "  const { c } = req.query;\n  exec('x ' + c);",
  'destructuring with a rename': "  const { c: cmd } = req.query;\n  exec('x ' + cmd);",
  'an alias of the object': "  const a = { cmd: req.query.c };\n  const b = a;\n  exec('x ' + b.cmd);",
  'the whole object read after one field is tainted': "  const o = { cmd: req.query.c, safe: 'ls' };\n  exec('x ' + JSON.stringify(o));",
  'a spread copy keeps a tainted field': "  const a = { cmd: req.query.c };\n  const b = { ...a };\n  exec('x ' + b.cmd);",
  'a spread of the request': "  const o = { ...req.query };\n  exec('x ' + o.c);",
  'an array push': "  const arr = [];\n  arr.push(req.query.c);\n  exec('x ' + arr[0]);",
  'an array literal element': "  const arr = [req.query.c, 'ls'];\n  exec('x ' + arr[0]);",
  'a whole array joined': "  const arr = ['a', req.query.c];\n  exec('x ' + arr.join(' '));",
  'a Map key set then get': "  const m = new Map();\n  m.set('k', req.query.c);\n  exec('x ' + m.get('k'));",
  'a Map key set then read with a variable key': "  const m = new Map();\n  m.set('k', req.query.c);\n  const key = 'k';\n  exec('x ' + m.get(key));",
  'a closure capturing a tainted variable': "  const c = req.query.c;\n  const f = () => exec('x ' + c);\n  f();",
  'a template literal over a field': "  const o = { c: req.query.c };\n  exec(`x ${o.c}`);",
  'a field passed through a parameter': "  const run = (o) => exec('x ' + o.cmd);\n  run({ cmd: req.query.c });",
};
const NEGATIVES = {
  'the sibling field of a literal': "  const o = { cmd: req.query.c, safe: 'ls' };\n  exec('x ' + o.safe);",
  'the sibling field of an assigned object': "  const o = {};\n  o.cmd = req.query.c;\n  o.safe = 'ls';\n  exec('x ' + o.safe);",
  'a field overwritten with a constant': "  const o = { cmd: req.query.c };\n  o.cmd = 'ls';\n  exec('x ' + o.cmd);",
  'the other destructured name': "  const { c, d } = { c: req.query.c, d: 'ls' };\n  exec('x ' + d);",
  'a different object with the same field name': "  const a = { cmd: req.query.c };\n  const b = { cmd: 'ls' };\n  exec('x ' + b.cmd);",
  'another array index': "  const arr = [req.query.c, 'ls'];\n  exec('x ' + arr[1]);",
  'another Map key': "  const m = new Map();\n  m.set('a', req.query.c);\n  m.set('b', 'ls');\n  exec('x ' + m.get('b'));",
  'a closure over a different variable': "  const c = req.query.c;\n  const d = 'ls';\n  const f = () => exec('x ' + d);\n  f();",
  'a variable reassigned to a constant': "  let c = req.query.c;\n  c = 'ls';\n  exec('x ' + c);",
  'a spread copy with the tainted field overridden': "  const a = { cmd: req.query.c };\n  const b = { ...a, cmd: 'ls' };\n  exec('x ' + b.cmd);",
  'a closure parameter shadowing the tainted name': "  const c = req.query.c;\n  const f = (c) => exec('x ' + c);\n  f('ls');",
};

for (const [name, body] of Object.entries(POSITIVES)) test(`found: ${name}`, async () => { assert.equal(await cmdi(H + body + T), true); });
for (const [name, body] of Object.entries(NEGATIVES)) test(`silent: ${name}`, async () => { assert.equal(await cmdi(H + body + T), false); });

test('known gaps are stated as gaps, not hidden: a closure RETURNED from a factory loses the captured taint', async () => {
  // Higher-order closure return is not modelled. If this starts passing the gap is closed and this test must move to POSITIVES.
  assert.equal(await cmdi(H + "  const mk = (v) => () => v;\n  const g = mk(req.query.c);\n  exec('x ' + g());" + T), false);
});

test('known gaps are stated as gaps, not hidden: a spread of a wholly tainted value cannot be overridden field by field', async () => {
  assert.equal(await cmdi(H + "  const b = { ...req.query, cmd: 'ls' };\n  exec('x ' + b.cmd);" + T), true, 'conservative: the unknown keys of the request are all tainted');
});

test('the field rules apply to JavaScript and TypeScript only; Python comprehensions and subscripts keep their whole-value rule', async () => {
  const py = "import subprocess\nfrom flask import request, Flask\napp = Flask(__name__)\n@app.route('/r')\ndef r():\n    hosts = [h for h in request.args.getlist('host')]\n    subprocess.run('ping ' + hosts[0], shell=True)\n    return 'ok'\n";
  assert.equal(await cmdi(py, 'app.py'), true);
});

test('access-path lattice: a descendant taints the whole read, a sibling does not, a prefix covers below', () => {
  const s = new Set(['o.cmd']);
  assert.equal(hasTaintedDescendant(s, 'o'), true);
  assert.equal(hasTaintedDescendant(s, 'o.safe'), false);
  assert.equal(hasTaintedDescendant(s, 'o.cmd'), false, 'strictly below');
  assert.equal(hasTaintedDescendant(s, 'oo'), false, 'a longer name is not a descendant');
  assert.equal(isCoveredBy(new Set(['o']), 'o.cmd'), true);
  assert.equal(isCoveredBy(s, 'o'), false);
  assert.equal(hasTaintedDescendant(null, 'o'), false);
});

test('the IR marks array literals that contain a spread, so index sensitivity is never applied to them', () => {
  const ir = buildProjectIR({ 'a.js': 'exports.h = (req) => { const a = [1, ...req.query.l, 2]; const b = [1, 2]; return [a, b]; };\n' });
  const nodes = Object.values(ir.perFile['a.js'].functions.find((f) => f.name === 'h').cfg.nodes).filter((n) => n.kind === 'assign');
  assert.deepEqual(nodes.find((n) => n.target === 'a').source.spreads, [1]);
  assert.equal('spreads' in nodes.find((n) => n.target === 'b').source, false, 'the shape is unchanged for ordinary arrays');
});

test('dynamic features the analysis cannot resolve are reported with where and what the engine did about it', () => {
  const ir = buildProjectIR({ 'a.js': "exports.h = (req, res, name) => {\n  const o = {};\n  const k = req.query.k;\n  o[k] = req.query.v;\n  const x = o[k];\n  eval('1+' + req.query.e);\n  const m = require(name);\n  Reflect.apply(fn, null, []);\n  o[name](1);\n  setTimeout('x()', 1);\n  Object.defineProperty(o, 'p', { get() { return 1; } });\n};\n" });
  const lim = analysisLimits(ir);
  const kinds = lim.map((l) => l.kind);
  for (const k of ['computed-write', 'computed-read', 'eval-like', 'dynamic-require', 'reflective-call', 'getter-or-proxy']) assert.ok(kinds.includes(k), k);
  for (const l of lim) { assert.ok(l.line >= 2 && l.line <= 11, `${l.kind} line ${l.line}`); assert.ok(l.effect.length > 30); assert.equal(l.file, 'a.js'); assert.equal(l.function, 'h'); }
  assert.deepEqual(analysisLimits(buildProjectIR({ 'b.js': 'exports.f = (x) => x + 1;\n' })), [], 'clean code reports nothing');
  assert.deepEqual(analysisLimits(ir), lim, 'stable');
});

test('the semantic graph carries the dynamic features and still validates', () => {
  const ir = buildProjectIR({ 'a.js': "exports.h = (req, res, name) => {\n  const o = {};\n  o[name] = req.query.v;\n  eval(req.query.e);\n};\n" });
  const g = buildSemanticGraph(ir);
  assert.equal(validateGraph(g).ok, true);
  assert.deepEqual(g.dynamicFeatures.map((d) => d.kind).sort(), ['computed-write', 'eval-like']);
  assert.ok(g.dynamicFeatures.every((d) => g.symbols.some((s) => s.id === d.symbol && s.name === 'h')));
});
