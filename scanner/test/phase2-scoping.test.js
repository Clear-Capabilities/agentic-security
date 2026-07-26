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

import { matchSinkOrSanitizer, matchSource, _languageExtensions } from '../src/dataflow/catalog.js';
import * as fs from 'node:fs';

test('language scoping: every catalog language has an extension mapping', () => {
  const map = _languageExtensions();
  for (const lang of ['js', 'py', 'cs', 'kt', 'go', 'php', 'rb', 'java', 'cpp']) {
    assert.ok(map[lang], `${lang} must be scoped`);
  }
});

test('language scoping: extension sets match the IR dispatch exactly', () => {
  // A set narrower than the parser's silently drops true positives; wider than
  // the parser's re-opens the cross-language leak. This must actually COMPARE
  // catalog.js's mapping against ir/index.js's dispatch source, not merely
  // confirm each regex literal appears somewhere in the file text (an earlier
  // version of this test did exactly that, and would have stayed green even
  // if _LANG_EXT.js were narrowed to /\.js$/ — a silent-recall-loss test that
  // could never fail). For each language, `expected` is the exact literal
  // ir/index.js dispatches on; check 1 pins that literal is still present in
  // ir/index.js's source (so a change there forces this test to be revisited)
  // and check 2 compares catalog.js's actual mapping against that SAME
  // literal by regex `.source`, so a narrowed or widened `_LANG_EXT` entry
  // fails here even though check 1 alone would not have caught it.
  const irSrc = fs.readFileSync(new URL('../src/ir/index.js', import.meta.url), 'utf8');
  const cppSrc = fs.readFileSync(new URL('../src/ir/parser-cpp.js', import.meta.url), 'utf8');
  const cases = [
    ['js',   /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i],
    ['py',   /\.py$/i],
    ['cs',   /\.cs$/i],
    ['kt',   /\.kt$/i],
    ['go',   /\.go$/i],
    ['php',  /\.(?:php|phtml)$/i],
    ['rb',   /\.rb$/i],
    ['java', /\.java$/i],
  ];
  const map = _languageExtensions();
  for (const [lang, expected] of cases) {
    // Escape the regex source for literal embedding into a source-text search.
    const literalSrc = expected.source.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const literalRe = new RegExp(literalSrc);
    assert.ok(literalRe.test(irSrc), `ir/index.js must still dispatch ${lang} via ${expected}`);
    assert.ok(map[lang] instanceof RegExp, `${lang} mapping must be a RegExp`);
    assert.equal(map[lang].source, expected.source,
      `catalog.js's ${lang} extension set (${map[lang]}) must equal ir/index.js's dispatch regex (${expected}) — narrower silently drops true positives, wider re-opens the cross-language leak`);
  }
  // cpp delegates to cppExtRe() rather than a literal, so pin that the literal
  // it returns is still the one parser-cpp.js defines, and that catalog.js's
  // cpp mapping is that exact same object/value (not a re-declared copy that
  // could drift).
  const cppExpected = /\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i;
  const cppLiteralSrc = cppExpected.source.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  assert.ok(new RegExp(cppLiteralSrc).test(cppSrc), 'parser-cpp.js must still define CPP_EXT_RE the way this test expects');
  assert.ok(/cppExtRe\(\)/.test(irSrc), 'ir/index.js must still delegate cpp dispatch to cppExtRe()');
  assert.equal(map.cpp.source, cppExpected.source, "catalog.js's cpp extension set must equal parser-cpp.js's cppExtRe()");
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

// py-flask-args-get regression guard (review follow-up): a first cut of this
// catalog entry only covered request.args/form/values.get() — restoring less
// of the pre-Phase-2 cross-language-leak recall than it should have, since
// request.headers/.cookies/.json/.data are ALSO already-catalogued member
// sources (py-flask-request-headers/cookies/json/data) but their .get() chain
// silently produced zero findings. Covers every shape the widened receiver
// alternation is meant to restore, plus the two guards `receiverBase` adds:
// language scoping (must not fire cross-language) and the unrelated-local
// false positive `receiverBase` was added to close.
test('language scoping: py request.<prop>.get() call-shaped source fires for every catalogued property', () => {
  for (const prop of ['args', 'form', 'values', 'headers', 'cookies', 'json', 'data']) {
    const expr = {
      kind: 'call',
      callee: { kind: 'member', prop: 'get', object: { kind: 'member', prop, object: { kind: 'ident', name: 'request' } } },
      args: [],
    };
    const s = matchSource(expr, 'app.py');
    assert.ok(s && s.id === 'py-flask-args-get', `request.${prop}.get() must match the py-flask-args-get source, got ${JSON.stringify(s)}`);
  }
});

test('language scoping: py request.<prop>.get() does not fire on a .js file', () => {
  const expr = {
    kind: 'call',
    callee: { kind: 'member', prop: 'get', object: { kind: 'member', prop: 'headers', object: { kind: 'ident', name: 'request' } } },
    args: [],
  };
  assert.equal(matchSource(expr, 'app.js'), null, 'a py-only source must not fire on a .js file');
});

test('language scoping: an unrelated local .get() call is not treated as a request source', () => {
  // args = parse(); args.get("cmd") — `args` matches `receiver` on its own,
  // but there is no request/req in the chain, so `receiverBase` must reject
  // it. Guards against the Minor the review flagged: receiver alone matches
  // ANY segment, so a same-named unrelated local was a false positive before
  // receiverBase existed.
  const expr = {
    kind: 'call',
    callee: { kind: 'member', prop: 'get', object: { kind: 'ident', name: 'args' } },
    args: [],
  };
  assert.equal(matchSource(expr, 'app.py'), null, 'a bare, non-request .get() call must not match py-flask-args-get');
});
