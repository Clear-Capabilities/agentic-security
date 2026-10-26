// DAG-05: the cross-scan IR cache (dataflow/ir-cache.js). A restored file must equal a fresh parse in everything
// but the node-id names, every id must be unique across the process, and anything the cache cannot prove it
// restores exactly must be parsed again rather than served.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildProjectIR } from '../src/ir/index.js';
import { parseJsFile } from '../src/ir/parser-js.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';
import { openIrCache, _internals } from '../src/dataflow/ir-cache.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(HERE, '..', 'src');

const SAMPLE = {
  'app.js': [
    "const cp = require('child_process');",
    'const pattern = /^[a-z]+\\d*$/gi;',
    'function run(req, res) {',
    '  const v = req.query.cmd;',
    '  if (pattern.test(v)) { cp.exec(v); }',
    '  return v.replace(/x+/g, "y");',
    '}',
    'class Box { set(v) { this.v = v; } get() { return this.v; } }',
    'module.exports = { run, Box };',
  ].join('\n'),
  'view.jsx': 'export function View(props) { return <div className="a" onClick={() => props.go(1)}>{props.label}</div>; }\n',
  'typed.ts': 'export function add(a: number, b: number): number { const c: number = a + b; return c; }\ninterface Shape { w: number }\n',
  'odd.js': 'const big = 10n; const s = "n1"; function g(x) { return x ?? big; }\n',
};

const ROOTS = [];
after(() => { for (const r of ROOTS) fs.rmSync(r, { recursive: true, force: true }); });

function tempRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ir-cache-test-'));
  ROOTS.push(root);
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"t","version":"1.0.0"}');
  return root;
}

function realFiles(dir, limit) {
  const out = {};
  for (const n of fs.readdirSync(dir).filter((f) => f.endsWith('.js')).sort().slice(0, limit)) out[`src/${path.basename(dir)}/${n}`] = fs.readFileSync(path.join(dir, n), 'utf8');
  return out;
}

const allIds = (perFile) => Object.values(perFile).flatMap((ir) => ir.functions.flatMap((fn) => Object.keys(fn.cfg.nodes)));

test('a restored IR equals a fresh parse except for the node-id names (sample, real sources, regex literals)', () => {
  const files = { ...SAMPLE, ...realFiles(path.join(SRC, 'sast'), 25), ...realFiles(path.join(SRC, 'dataflow'), 12) };
  const root = tempRoot();
  const first = openIrCache(root);
  const cold = buildProjectIR(files, { irCache: first });
  assert.ok(first.stats().stored > 20, `stored ${first.stats().stored}`);
  const second = openIrCache(root);
  const warm = buildProjectIR(files, { irCache: second });
  assert.equal(second.stats().rejected, 0);
  assert.ok(second.stats().hits >= first.stats().stored, 'every stored file is read back');
  const fresh = buildProjectIR(files);
  for (const f of Object.keys(fresh.perFile)) {
    assert.equal(_internals.canonical(warm.perFile[f]), _internals.canonical(fresh.perFile[f]), `${f} differs from a fresh parse`);
    assert.equal(_internals.canonical(cold.perFile[f]), _internals.canonical(fresh.perFile[f]), `${f} (stored run) differs`);
  }
  // the call graph built over restored IR is the same graph
  assert.deepEqual([...warm.callGraph.functions.keys()].sort(), [...fresh.callGraph.functions.keys()].sort());
  assert.equal(JSON.stringify(warm.callGraph.edges.map((e) => [e.caller, e.callee, e.calleeName])), JSON.stringify(fresh.callGraph.edges.map((e) => [e.caller, e.callee, e.calleeName])));
  // a regular expression stays a RegExp, not the `{}` JSON would make of it
  const lit = [];
  const seek = (v) => { if (v instanceof RegExp) lit.push(v); else if (v && typeof v === 'object') for (const x of Object.values(v)) seek(x); };
  seek(warm.perFile['app.js']);
  assert.ok(lit.length >= 2 && lit.every((r) => r instanceof RegExp), 'regex literals are restored as RegExp');
  assert.ok(lit.some((r) => r.flags === 'gi' && r.source.includes('[a-z]')));
});

test('restored node ids are unique across the process and keep the file\'s relative order', () => {
  const root = tempRoot();
  buildProjectIR(SAMPLE, { irCache: openIrCache(root) });
  const warmA = buildProjectIR(SAMPLE, { irCache: openIrCache(root) });
  const warmB = buildProjectIR(SAMPLE, { irCache: openIrCache(root) });
  const fresh = buildProjectIR(SAMPLE);
  const ids = [...allIds(warmA.perFile), ...allIds(warmB.perFile), ...allIds(fresh.perFile)];
  assert.equal(new Set(ids).size, ids.length, 'no id is used twice');
  // every reference inside a restored function names a node of that function (the relative order is
  // compared with a fresh parse by the previous test)
  for (const fn of warmA.perFile['app.js'].functions) {
    for (const node of Object.values(fn.cfg.nodes)) {
      assert.ok(node.succ.every((s) => s in fn.cfg.nodes) && node.pred.every((p) => p in fn.cfg.nodes), 'edges stay inside the function');
    }
    assert.ok(fn.cfg.entry in fn.cfg.nodes && fn.cfg.exit in fn.cfg.nodes);
    assert.ok(fn.returns.every((r) => r in fn.cfg.nodes));
    assert.ok(fn.calls.every((c) => c.site in fn.cfg.nodes));
    for (const list of Object.values(fn.writes)) assert.ok(list.every((w) => w.node in fn.cfg.nodes));
  }
});

test('a changed file is a miss; an unchanged file is a hit; the key covers the path', () => {
  const root = tempRoot();
  const seed = openIrCache(root);
  buildProjectIR({ 'a.js': 'function f(x) { return x + 1; }\n' }, { irCache: seed });
  const hit = openIrCache(root);
  buildProjectIR({ 'a.js': 'function f(x) { return x + 1; }\n' }, { irCache: hit });
  assert.equal(hit.stats().hits, 1);
  const edited = openIrCache(root);
  const ir = buildProjectIR({ 'a.js': 'function f(x) { return x + 2; }\n' }, { irCache: edited });
  assert.equal(edited.stats().hits, 0);
  assert.equal(edited.stats().misses, 1);
  assert.ok(JSON.stringify(ir.perFile['a.js']).includes('"value":2'), 'the edited text was parsed');
  const moved = openIrCache(root);
  buildProjectIR({ 'b.js': 'function f(x) { return x + 2; }\n' }, { irCache: moved });
  assert.equal(moved.stats().hits, 0, 'the same text under another path is not served from a.js\'s record');
});

test('a corrupt, truncated, hand-edited or foreign record is parsed again, never served or thrown', () => {
  const files = { 'a.js': 'function f(x) { const y = x + 1; return y; }\n', 'b.js': 'function g(z) { return z; }\n' };
  const root = tempRoot();
  const seed = openIrCache(root);
  buildProjectIR(files, { irCache: seed });
  const recs = fs.readdirSync(seed.dir).filter((n) => n.endsWith('.ir.json')).map((n) => path.join(seed.dir, n));
  assert.equal(recs.length, 2);
  const original = recs.map((r) => fs.readFileSync(r, 'utf8'));
  const damage = [
    (t) => t.slice(0, Math.floor(t.length / 2)), // truncated
    (t) => t.replace('"kind":"return"', '"kind":"throw"'), // payload edited, header digest stale
    (t) => `${t.slice(0, t.indexOf('\n'))}\n{"functions":[]}`, // payload swapped
    () => 'not a record', // foreign
    (t) => t.replace(/^\{"format":"ir-cache\/1"/, '{"format":"ir-cache/0"'), // other format
  ];
  const fresh = buildProjectIR(files);
  for (const d of damage) {
    recs.forEach((r, i) => fs.writeFileSync(r, d(original[i])));
    const c = openIrCache(root);
    const ir = buildProjectIR(files, { irCache: c });
    for (const f of Object.keys(files)) assert.equal(_internals.canonical(ir.perFile[f]), _internals.canonical(fresh.perFile[f]), `${f} after damage`);
    assert.equal(c.stats().hits, 0, 'a damaged record is not a hit');
  }
});

test('an IR that does not survive JSON exactly is not cached', () => {
  const root = tempRoot();
  const c = openIrCache(root);
  const base = parseJsFile('x.js', 'function f(a) { return a; }\n');
  const clone = () => JSON.parse(JSON.stringify(base));
  const withUndefined = clone(); withUndefined.functions[0].extra = undefined;
  const withBigInt = clone(); withBigInt.functions[0].extra = 10n;
  const withNaN = clone(); withNaN.functions[0].extra = NaN;
  const withMap = clone(); withMap.functions[0].extra = new Map([[1, 2]]);
  const withHole = clone(); withHole.functions[0].extra = [1, , 3]; // eslint-disable-line no-sparse-arrays
  const unknownId = clone(); unknownId.functions[0].meta = { ref: Object.keys(unknownId.functions[0].cfg.nodes)[0] };
  for (const [name, ir] of Object.entries({ withUndefined, withBigInt, withNaN, withMap, withHole, unknownId })) {
    assert.equal(c.store('x.js', 'function f(a) { return a; }\n', ir), false, name);
  }
  assert.equal(c.stats().stored, 0);
  assert.equal(c.stats().skipped, 6);
  // the clean one is stored
  assert.equal(c.store('x.js', 'function f(a) { return a; }\n', clone()), true);
});

test('with state writes off nothing is written, and an existing cache is still read', () => {
  const root = tempRoot();
  const off = openIrCache(root, { write: false });
  buildProjectIR(SAMPLE, { irCache: off });
  assert.equal(off.stats().stored, 0);
  assert.equal(fs.existsSync(off.dir), false, 'no directory is created');
  buildProjectIR(SAMPLE, { irCache: openIrCache(root) });
  const readOnly = openIrCache(root, { write: false });
  buildProjectIR(SAMPLE, { irCache: readOnly });
  assert.ok(readOnly.stats().hits >= 3);
  const noRead = openIrCache(root, { read: false, write: false });
  buildProjectIR(SAMPLE, { irCache: noRead });
  assert.equal(noRead.stats().hits, 0);
});

test('deep analysis over restored IR gives the findings it gives over a fresh parse', () => {
  const vuln = {
    'server.js': [
      "const cp = require('child_process');",
      "const db = require('./db');",
      'function helper(v) { return v; }',
      'function handler(req, res) { const id = helper(req.query.id); db.query("SELECT * FROM t WHERE a = " + id); cp.exec(req.query.cmd); res.send(req.query.name); }',
      'module.exports = { handler };',
    ].join('\n'),
    'db.js': 'module.exports = { query(sql) { return sql; } };\n',
  };
  const norm = (list) => list.map((f) => JSON.stringify({ file: f.file, line: f.line, vuln: f.vuln, cwe: f.cwe, sink: f.sink && f.sink.label })).sort();
  const root = tempRoot();
  const coldIr = buildProjectIR(vuln);
  const cold = runDeepAnalysis(coldIr.perFile, coldIr.callGraph, { scanRoot: root, fileContents: vuln });
  buildProjectIR(vuln, { irCache: openIrCache(root) });
  const warmIr = buildProjectIR(vuln, { irCache: openIrCache(root) });
  const warm = runDeepAnalysis(warmIr.perFile, warmIr.callGraph, { scanRoot: root, fileContents: vuln });
  assert.ok(cold.length >= 2, `the fixture produces findings (${cold.length})`);
  assert.deepEqual(norm(warm), norm(cold));
});
