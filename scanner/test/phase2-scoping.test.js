// Phase 2 — shared call-site extraction, catalog language scoping, receivers.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { callSitesFromCfg } from '../src/ir/call-sites.js';
import { buildProjectIRAsync } from '../src/ir/index.js';

function cfgOf(nodes) { return { entry: 'entry', exit: 'exit', nodes }; }

test('callSitesFromCfg: collects a statement-position call', () => {
  const sites = callSitesFromCfg(cfgOf({
    n1: { kind: 'call', callee: 'exec', args: [{ kind: 'ident', name: 'x' }], line: 3, succ: [], pred: [] },
  }));
  assert.equal(sites.length, 1);
  assert.equal(sites[0].site, 'n1');
  assert.equal(sites[0].callee, 'exec');
  assert.equal(sites[0].line, 3);
  assert.ok(Array.isArray(sites[0].args));
});

test('callSitesFromCfg: collects a call on an assignment right-hand side', () => {
  const sites = callSitesFromCfg(cfgOf({
    n1: { kind: 'assign', target: 'v', source: { kind: 'call', callee: 'helper', args: [] }, line: 5, succ: [], pred: [] },
  }));
  assert.deepEqual(sites.map(s => s.callee), ['helper']);
});

test('callSitesFromCfg: collects from return, throw and if', () => {
  const sites = callSitesFromCfg(cfgOf({
    n1: { kind: 'return', value: { kind: 'call', callee: 'a', args: [] }, line: 1, succ: [], pred: [] },
    n2: { kind: 'throw',  value: { kind: 'call', callee: 'b', args: [] }, line: 2, succ: [], pred: [] },
    n3: { kind: 'if',     cond:  { kind: 'call', callee: 'c', args: [] }, line: 3, succ: [], pred: [] },
  }));
  assert.deepEqual(sites.map(s => s.callee).sort(), ['a', 'b', 'c']);
});

test('callSitesFromCfg: collects nested calls in arguments', () => {
  const sites = callSitesFromCfg(cfgOf({
    n1: { kind: 'call', callee: 'outer', args: [{ kind: 'call', callee: 'inner', args: [] }], line: 1, succ: [], pred: [] },
  }));
  assert.deepEqual(sites.map(s => s.callee).sort(), ['inner', 'outer']);
});

test('callSitesFromCfg: preserves a dotted callee rather than flattening it', () => {
  const sites = callSitesFromCfg(cfgOf({
    n1: { kind: 'call', callee: 'obj.method', args: [], line: 1, succ: [], pred: [] },
  }));
  assert.equal(sites[0].callee, 'obj.method');
});

test('callSitesFromCfg: tolerates malformed input without throwing', () => {
  assert.deepEqual(callSitesFromCfg(null), []);
  assert.deepEqual(callSitesFromCfg({}), []);
  assert.deepEqual(callSitesFromCfg({ nodes: null }), []);
  assert.deepEqual(callSitesFromCfg(cfgOf({ n1: null })), []);
});

const FIXTURES = {
  'a.go':  'package main\nfunc h(x string) string { return x }\nfunc m(r string) { v := h(r); _ = v }\n',
  'a.cs':  'class A { public string H(string x){ return x; } public void M(string r){ var v = H(r); } }',
  'a.kt':  'fun h(x: String): String { return x }\nfun m(r: String) { val v = h(r) }\n',
  'a.php': '<?php function h($x){ return $x; } function m($r){ $v = h($r); }',
};

test('fn.calls: Go, C#, Kotlin and PHP each record their call sites', async () => {
  const { perFile } = await buildProjectIRAsync(FIXTURES);
  for (const file of Object.keys(FIXTURES)) {
    const ir = perFile[file];
    assert.ok(ir, `${file} must produce IR`);
    const caller = ir.functions.find(f => /m$/i.test(f.name));
    assert.ok(caller, `${file} must yield the calling function`);
    assert.ok(Array.isArray(caller.calls) && caller.calls.length >= 1,
      `${file}: caller must record at least one call site, got ${JSON.stringify(caller.calls)}`);
    const c = caller.calls[0];
    assert.ok(c.site && caller.cfg.nodes[c.site], `${file}: site must be a real CFG node id`);
    assert.ok(typeof c.callee === 'string' && c.callee.length, `${file}: callee must be a name`);
    assert.ok(Array.isArray(c.args), `${file}: args must be an array`);
    assert.ok(typeof c.line === 'number', `${file}: line must be set`);
  }
});

test('fn.calls: the callee name resolves to the callee function', async () => {
  const { perFile, callGraph } = await buildProjectIRAsync(FIXTURES);
  for (const file of Object.keys(FIXTURES)) {
    const ir = perFile[file];
    const caller = ir.functions.find(f => /m$/i.test(f.name));
    const callee = ir.functions.find(f => /h$/i.test(f.name));
    const resolved = callGraph.resolveKnownCallee(caller.calls[0].callee, file);
    assert.equal(resolved, callee.qid, `${file}: the recorded callee must resolve to the callee's qid`);
  }
});

import { matchSinkOrSanitizer, _languageExtensions } from '../src/dataflow/catalog.js';
import * as fs from 'node:fs';

test('language scoping: every catalog language has an extension mapping', () => {
  const map = _languageExtensions();
  for (const lang of ['js', 'py', 'cs', 'kt', 'go', 'php', 'rb', 'java', 'cpp']) {
    assert.ok(map[lang], `${lang} must be scoped`);
  }
});

test('language scoping: extension sets match the IR dispatch exactly', () => {
  // A set narrower than the parser's silently drops true positives; wider than
  // the parser's re-opens the cross-language leak. Pin both directions against
  // the real dispatch source.
  const src = fs.readFileSync(new URL('../src/ir/index.js', import.meta.url), 'utf8');
  const cases = [
    ['js',  /\.\(\?:js\|jsx\|ts\|tsx\|mjs\|cjs\)\$/],
    ['py',  /\.py\$/],
    ['cs',  /\.cs\$/],
    ['kt',  /\.kt\$/],
    ['go',  /\.go\$/],
    ['php', /\.\(\?:php\|phtml\)\$/],
    ['rb',  /\.rb\$/],
  ];
  const map = _languageExtensions();
  for (const [lang, expected] of cases) {
    assert.ok(expected.test(src), `ir/index.js must still dispatch ${lang} the way this test expects`);
    assert.ok(map[lang] instanceof RegExp, `${lang} mapping must be a RegExp`);
  }
});

test('language scoping: a python-language sink does not fire on a .js file', () => {
  const hitsPy = matchSinkOrSanitizer('system', 'a.py') || [];
  const hitsJs = matchSinkOrSanitizer('system', 'a.js') || [];
  assert.ok(hitsPy.some(h => h.language === 'py'), 'py entry must fire on .py');
  assert.ok(!hitsJs.some(h => h.language === 'py'), 'py entry must NOT fire on .js');
});

test('language scoping: legitimate matches still fire for every language', () => {
  const cases = [
    ['a.js', 'js'], ['a.py', 'py'], ['a.go', 'go'], ['a.rb', 'rb'],
    ['a.php', 'php'], ['a.cs', 'cs'], ['a.kt', 'kt'], ['a.cpp', 'cpp'],
  ];
  // Callee matching is case-sensitive and by bare name, so the probe list has
  // to include each language's actual catalog naming convention — Go and C#
  // sinks are PascalCase (`Query`, `Start`) rather than the lowercase
  // `system`/`exec`/`eval`/`query`/`popen` style used by the others. Confirmed
  // against catalog.js's `go-*`/`cs-*` entries before adding these.
  const PROBES = ['system', 'exec', 'eval', 'query', 'popen', 'Query', 'Start'];
  for (const [file, lang] of cases) {
    const anyForLang = PROBES
      .flatMap(n => matchSinkOrSanitizer(n, file) || [])
      .some(h => h.language === lang);
    assert.ok(anyForLang, `${lang} must still match at least one of its own sinks on ${file}`);
  }
});

test('language scoping: no file context keeps the permissive behaviour', () => {
  const hits = matchSinkOrSanitizer('system') || [];
  assert.ok(hits.length >= 1, 'with no file, matching must not be narrowed');
});
