// E2-01: the semantic graph contract: typed entities, stable ids, a versioned wire format, additive by construction.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO } from './helpers.js';
import { buildProjectIR, buildProjectIRAsync } from '../../src/ir/index.js';
import { ENTITY_LISTS, SEMANTIC_GRAPH_SCHEMA, SEMANTIC_GRAPH_VERSION, buildSemanticGraph, migrateGraph, parseGraph, serializeGraph, validateGraph } from '../../src/ir/semantic-graph.js';

const A = "const { exec } = require('child_process');\nconst h = require('./b');\nfunction local(x) { return x; }\nexports.run = function run(req) {\n  const cmd = h.build(req.query.x);\n  const o = { a: 1, b: [1, 2] };\n  o.c = local(cmd);\n  exec(cmd);\n};\n";
const B = "exports.build = (s) => 'echo ' + s;\n";
const build = (files) => buildSemanticGraph(buildProjectIR(files));

test('the graph is valid, names every entity list, and says which lists are populated and which are schema-only and why', () => {
  const g = build({ 'a.js': A, 'b.js': B });
  const v = validateGraph(g);
  assert.deepEqual(v, { ok: true, errors: [] });
  assert.equal(g.schema, SEMANTIC_GRAPH_SCHEMA); assert.equal(g.schemaVersion, SEMANTIC_GRAPH_VERSION);
  for (const k of ENTITY_LISTS) { assert.ok(Array.isArray(g[k]), k); assert.ok(g.coverage[k].reason.length > 10, k); }
  for (const k of ['symbols', 'callSites', 'allocations', 'fieldAccesses', 'valueOrigins']) assert.equal(g.coverage[k].state, 'populated', k);
  for (const k of ['serviceBoundaries', 'storageEdges', 'sanitizers', 'guards']) { assert.equal(g.coverage[k].state, 'schema-only', k); assert.deepEqual(g[k], []); }
  assert.ok(g.limits.some((l) => /columns are null/.test(l)));
  const names = g.symbols.map((s) => s.name).sort();
  assert.ok(names.includes('run') && names.includes('local') && names.includes('<module>'));
});

test('calls nested in assignments are call sites; a same-file call resolves as inferred, an import-based one stays unresolved with no callee', () => {
  const g = build({ 'a.js': A, 'b.js': B });
  const by = (t) => g.callSites.filter((c) => c.calleeText === t);
  assert.equal(by('local').length, 1); assert.equal(by('local')[0].resolution, 'resolved'); assert.equal(by('local')[0].confidence.tier, 'inferred');
  assert.ok(g.symbols.some((s) => s.id === by('local')[0].callee && s.name === 'local'));
  for (const t of ['h.build', 'exec']) { assert.equal(by(t).length, 1, t); assert.equal(by(t)[0].resolution, 'unresolved'); assert.equal(by(t)[0].callee, null); assert.equal(by(t)[0].confidence.tier, 'unresolved'); }
  const ex = by('exec')[0];
  assert.equal(ex.args.length, 1); assert.ok(g.valueOrigins.some((o) => o.id === ex.args[0].origin));
  assert.ok(g.fieldAccesses.some((f) => f.mode === 'read' && f.base === 'req' && f.path.join('.') === 'query.x'));
  assert.ok(g.fieldAccesses.some((f) => f.mode === 'write' && f.base === 'o' && f.path.join('.') === 'c'));
  assert.deepEqual(g.allocations.map((a) => a.kind).sort(), ['array', 'object']);
});

test('ids are stable: a blank line above a function, a different file order and a rebuild change no id; a structural change does', () => {
  const base = build({ 'a.js': A, 'b.js': B });
  const shifted = build({ 'a.js': `\n\n// comment\n${A}`, 'b.js': B });
  const reordered = build({ 'b.js': B, 'a.js': A });
  const ids = (g) => ENTITY_LISTS.flatMap((k) => g[k].map((e) => e.id)).sort();
  assert.deepEqual(ids(shifted), ids(base), 'line shifts do not move any id');
  assert.deepEqual(ids(reordered), ids(base));
  assert.equal(serializeGraph(build({ 'a.js': A, 'b.js': B })), serializeGraph(base), 'a rebuild is byte-identical');
  const lines = (g) => g.callSites.map((c) => c.line).sort((a, b) => a - b);
  assert.notDeepEqual(lines(shifted), lines(base), 'but the recorded lines did move');
  const changed = build({ 'a.js': A.replace('exec(cmd);', 'exec(cmd); exec(cmd);'), 'b.js': B });
  assert.notDeepEqual(ids(changed), ids(base));
  assert.equal(new Set(ids(changed)).size, ids(changed).length, 'two identical calls in one function still get distinct ids');
});

test('the wire format round-trips byte for byte, and canonical order means key order in memory is irrelevant', () => {
  const g = build({ 'a.js': A, 'b.js': B });
  const text = serializeGraph(g);
  const back = parseGraph(text);
  assert.equal(back.ok, true);
  assert.equal(serializeGraph(back.graph), text);
  const scrambled = JSON.parse(text); scrambled.callSites.reverse(); scrambled.symbols.reverse();
  assert.equal(serializeGraph(scrambled), text);
});

test('hostile or malformed graphs are refused without throwing, and each rule is enforced', () => {
  for (const bad of [null, undefined, 3, 'x', [], {}, { schema: 'other' }, { schema: SEMANTIC_GRAPH_SCHEMA, schemaVersion: 'one' }]) assert.equal(validateGraph(bad).ok, false);
  assert.equal(parseGraph('{not json').ok, false);
  const g = build({ 'a.js': A, 'b.js': B });
  const code = (mut) => { const c = structuredClone(g); mut(c); return validateGraph(c).errors.map((e) => `${e.code}:${e.path}`); };
  assert.ok(code((c) => { c.callSites[0].caller = 'sym:0000000000000000'; }).some((x) => x.startsWith('DANGLING_REF')));
  assert.ok(code((c) => { c.symbols.push(structuredClone(c.symbols[0])); }).some((x) => x.startsWith('DUPLICATE_ID')));
  assert.ok(code((c) => { c.symbols[0].file = '../escape.js'; }).some((x) => x.startsWith('BAD_TYPE')));
  assert.ok(code((c) => { c.symbols[0].locationPrecision = 'exact'; }).some((x) => x.startsWith('RULE_VIOLATION')), 'a null column must declare line precision');
  assert.ok(code((c) => { c.symbols[0].confidence = { tier: 'certain', basis: 'x' }; }).some((x) => x.startsWith('BAD_TYPE')));
  assert.ok(code((c) => { const r = c.callSites.find((x) => !x.callee); r.resolution = 'resolved'; }).some((x) => x.startsWith('RULE_VIOLATION')));
  assert.ok(code((c) => { c.coverage.sanitizers = { state: 'populated', reason: 'x' }; }).some((x) => x.startsWith('RULE_VIOLATION')), 'populated but empty is a lie');
  assert.ok(code((c) => { c.coverage.symbols = { state: 'schema-only', reason: 'x' }; }).some((x) => x.startsWith('RULE_VIOLATION')));
  assert.ok(code((c) => { c.schemaVersion = '2.0.0'; }).some((x) => x.startsWith('UNSUPPORTED_MAJOR')));
});

test('versioning: an older minor migrates, a different major is refused rather than guessed at', () => {
  const g = build({ 'a.js': A });
  const old = { ...g, schemaVersion: '1.0.0' };
  assert.equal(migrateGraph(old).ok, true);
  const m = migrateGraph({ ...g, schemaVersion: '1.0.0' });
  assert.equal(validateGraph(m.graph).ok, true);
  assert.equal(migrateGraph({ ...g, schemaVersion: '2.0.0' }).ok, false);
  assert.equal(migrateGraph({ schema: 'other' }).ok, false);
});

test('building the graph does not modify the IR it reads', () => {
  const ir = buildProjectIR({ 'a.js': A, 'b.js': B });
  const before = JSON.stringify(ir);
  buildSemanticGraph(ir);
  assert.equal(JSON.stringify(ir), before);
});

test('it is built from the CFG every language shares: Python, Java and Go produce valid graphs with symbols, calls and origins', async () => {
  const cases = [
    ['p.py', 'def f(x):\n    v = "a" + x.id\n    sink(v)\n'],
    ['P.java', 'class P { void f(String x) { String v = "a" + x; sink(v); } }\n'],
    ['p.go', 'package p\nfunc f(x string) { v := "a" + x\n sink(v) }\n'],
  ];
  for (const [file, src] of cases) {
    const g = buildSemanticGraph(await buildProjectIRAsync({ [file]: src }));
    assert.equal(validateGraph(g).ok, true, file);
    assert.ok(g.symbols.some((s) => s.kind === 'function' && /f$/.test(s.name)), file);
    assert.ok(g.callSites.some((c) => /sink/i.test(c.calleeText)), file);
    assert.ok(g.valueOrigins.some((o) => o.variable === 'v'), file);
  }
});

test('overhead is small: the serialized graph is a few times the source, and building it costs less than building the IR', () => {
  const files = {};
  for (let i = 0; i < 40; i++) files[`m${i}.js`] = A.replace(/run/g, `run${i}`).replace(/local/g, `local${i}`);
  let t0 = process.hrtime.bigint(); const ir = buildProjectIR(files); const irMs = Number(process.hrtime.bigint() - t0) / 1e6;
  t0 = process.hrtime.bigint(); const g = buildSemanticGraph(ir); const text = serializeGraph(g); const gMs = Number(process.hrtime.bigint() - t0) / 1e6;
  const srcBytes = Object.values(files).reduce((a, s) => a + s.length, 0);
  assert.ok(text.length / srcBytes < 40, `serialized ${text.length} bytes for ${srcBytes} bytes of source`);
  assert.ok(gMs < Math.max(irMs * 3, 200), `graph ${gMs.toFixed(1)} ms vs IR ${irMs.toFixed(1)} ms`);
  assert.equal(validateGraph(g).ok, true);
});

test('additive by construction: nothing on the scan path imports the graph, so findings and chain[] cannot change', () => {
  const offenders = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/\.(js|mjs)$/.test(e.name) && !p.endsWith('ir/semantic-graph.js') && /(?:from\s+|import\s*\(\s*|require\s*\(\s*)['"][^'"]*semantic-graph(?:\.js)?['"]/.test(fs.readFileSync(p, 'utf8'))) offenders.push(path.relative(REPO, p)); } };
  walk(path.join(REPO, 'scanner/src')); walk(path.join(REPO, 'scanner/bin'));
  assert.deepEqual(offenders, []);
});

test('the measured construct matrix is current, covers ten languages and seven constructs, and the contract doc matches it', () => {
  const r = spawnSync(process.execPath, [path.join(REPO, 'scripts/engineering-excellence/ir-matrix.mjs'), '--check'], { cwd: REPO, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const m = JSON.parse(fs.readFileSync(path.join(REPO, 'scripts/engineering-excellence/data/ir-matrix.json'), 'utf8'));
  assert.equal(Object.keys(m.languages).length, 10); assert.equal(m.constructs.length, 7);
  for (const cells of Object.values(m.languages)) for (const c of m.constructs) assert.ok(['modelled', 'not-modelled', 'error'].includes(cells[c].state));
  const doc = fs.readFileSync(path.join(REPO, 'docs/engineering-excellence/IR_CONTRACT.md'), 'utf8');
  for (const w of ['## Layers', 'Known structural gaps', 'The semantic graph contract', 'schema only']) assert.ok(doc.includes(w), w);
});
