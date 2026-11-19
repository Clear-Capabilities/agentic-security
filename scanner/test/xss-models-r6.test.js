// Cross-site scripting models, round six (the XSS block of
// src/dataflow/catalog-framework-models.js plus the IR and engine support it
// needed). Every model family has a vulnerable file that must produce an
// IR-TAINT CWE-79 finding and a clean twin (escaped output, a JSON or
// plain-text response, a literal-only template) that must be silent or
// labelled sanitized. The fixtures are synthetic and written from the
// framework APIs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { mkTestTmp } from './helpers/tmp.js';
import { parseCSharpFile, parsePhpFile, buildProjectIRAsync } from '../src/ir/index.js';
import { matchSinkOrSanitizer } from '../src/dataflow/catalog.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, 'fixtures');

const FIXTURES = ['r6-xss-js', 'r6-xss-py', 'r6-xss-rb', 'r6-xss-php', 'r6-xss-go', 'r6-xss-jvm', 'r6-xss-cs'];

async function taintByFile(dir) {
  const tmp = mkTestTmp('as-r6-xss-');
  fs.cpSync(dir, tmp, { recursive: true });
  const { scan } = await runScan(tmp, { deep: true, deepInCi: true });
  const byFile = new Map();
  for (const f of (scan.findings || []).filter((x) => x.parser === 'IR-TAINT')) {
    const base = path.basename(f.file || '');
    if (!byFile.has(base)) byFile.set(base, []);
    byFile.get(base).push(f);
  }
  return byFile;
}

const show = (fs_) => (fs_ || []).map((f) => `${f.cwe}@${f.line}${f.sanitized ? '(sanitized)' : ''}`).join(', ') || '(none)';

for (const fixture of FIXTURES) {
  test(`${fixture}: every vulnerable file fires with CWE-79`, async () => {
    const dir = path.join(FIX, fixture, 'vulnerable');
    const byFile = await taintByFile(dir);
    for (const file of fs.readdirSync(dir)) {
      const got = byFile.get(file) || [];
      assert.ok(got.some((f) => f.cwe === 'CWE-79' && !f.sanitized), `${fixture}/vulnerable/${file}: expected CWE-79, got ${show(got)}`);
    }
  });

  test(`${fixture}: every clean file is silent or labelled sanitized`, async () => {
    const dir = path.join(FIX, fixture, 'clean');
    const byFile = await taintByFile(dir);
    for (const file of fs.readdirSync(dir)) {
      const live = (byFile.get(file) || []).filter((f) => !f.sanitized);
      assert.equal(live.length, 0, `${fixture}/clean/${file}: expected no unsanitized finding, got ${show(byFile.get(file))}`);
    }
  });

  test(`${fixture}: every vulnerable file has a clean twin`, () => {
    assert.deepEqual(fs.readdirSync(path.join(FIX, fixture, 'clean')).sort(), fs.readdirSync(path.join(FIX, fixture, 'vulnerable')).sort());
  });
}

// ── IR support the models needed ─────────────────────────────────────────

const callsOf = (fn) => Object.values(fn.cfg.nodes).filter((n) => n.kind === 'call');

test('PHP: print(...) and echo(...) lower their parenthesised expression (it lowered to unknown)', () => {
  const ir = parsePhpFile('a.php', '<?php\n$t = $_GET["t"];\nprint("<h2>" . $t . "</h2>");\necho ($t) . "x";\n');
  const echoes = callsOf(ir.functions[0]).filter((n) => n.callee === '__php_echo__');
  assert.equal(echoes.length, 2);
  assert.notEqual(echoes[0].args[0].kind, 'unknown');
  assert.notEqual(echoes[1].args[0].kind, 'unknown', 'a leading group that does not wrap the whole expression is kept as written');
});

test('C#: an awaited statement call and an indexer assignment are lowered (both were dropped)', () => {
  const ir = parseCSharpFile('A.cs', [
    'public class A {',
    '  public async Task M(string t) {',
    '    await Response.WriteAsync("<p>" + t + "</p>");',
    '    ViewData["Title"] = Html.Raw(t);',
    '  }',
    '}',
  ].join('\n'));
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  assert.ok(nodes.some((n) => n.kind === 'call' && n.callee === 'Response.WriteAsync'));
  const ix = nodes.find((n) => n.kind === 'assign' && n.target === 'ViewData');
  assert.ok(ix, 'the indexer write is an assignment to its container');
  assert.equal(ix.source.weakUpdate, true, 'a weak update: the container keeps the taint it held');
  assert.equal(ix.source.left.name, 'ViewData');
  assert.equal(ix.source.right.callee, 'Html.Raw');
});

test('Python: returns of an @app.route view are marked; @app.get (FastAPI spelling) and plain functions are not', async () => {
  const { perFile } = await buildProjectIRAsync({ 'a.py': [
    'from flask import Flask',
    'app = Flask(__name__)',
    '@app.route("/a")',
    'def a():',
    '    return "<p>x</p>"',
    '@app.get("/b")',
    'def b():',
    '    return "<p>x</p>"',
    'def c():',
    '    return "<p>x</p>"',
  ].join('\n') });
  const marked = (n) => Object.values(perFile['a.py'].functions.find((f) => f.name === n).cfg.nodes).some((x) => x.kind === 'return' && x.routeReturn);
  assert.equal(marked('a'), true);
  assert.equal(marked('b'), false);
  assert.equal(marked('c'), false);
});

test('Java: returns of a Spring String handler are marked only when the String is the response body', async () => {
  const src = [
    'import org.springframework.stereotype.Controller;',
    '@Controller',
    'public class A {',
    '  @GetMapping("/v") public String view(String m) { return "home"; }',
    '  @GetMapping("/b") @ResponseBody public String body(String m) { return "<p>" + m; }',
    '  @GetMapping(value = "/j", produces = "application/json") @ResponseBody public String json(String m) { return m; }',
    '  @ResponseBody public String notMapped(String m) { return m; }',
    '}',
  ].join('\n');
  const { perFile } = await buildProjectIRAsync({ 'A.java': src });
  const marked = (n) => Object.values(perFile['A.java'].functions.find((f) => f.name === `A.${n}`).cfg.nodes).some((x) => x.kind === 'return' && x.routeReturn);
  assert.equal(marked('view'), false, 'a @Controller String without @ResponseBody is a view name');
  assert.equal(marked('body'), true);
  assert.equal(marked('json'), false, 'produces = application/json');
  assert.equal(marked('notMapped'), false);
});

// ── Catalog scoping ──────────────────────────────────────────────────────

test('catalog: the round-six sinks and sanitizers are scoped by receiver', () => {
  const member = (o, p) => ({ kind: 'member', object: typeof o === 'string' ? { kind: 'ident', name: o } : o, prop: p });
  const call = (callee) => ({ kind: 'call', callee, args: [] });
  const ids = (callee, file) => (matchSinkOrSanitizer(callee, file) || []).map((e) => e.id);
  assert.ok(ids(member(call({ kind: 'ident', name: '$' }), 'append'), 'a.js').includes('js-jquery-insert-append'));
  assert.ok(ids(member('$list', 'append'), 'a.js').includes('js-jquery-insert-append'), 'a $-prefixed jQuery object');
  assert.ok(!ids(member('form', 'append'), 'a.js').includes('js-jquery-insert-append'), 'FormData.append is not an HTML insertion');
  assert.ok(!ids(member('el', 'append'), 'a.js').includes('js-jquery-insert-append'), 'Element.append inserts text');
  assert.ok(ids(member('c', 'html'), 'a.js').includes('js-hono-html'));
  assert.ok(ids(member('reply', 'send'), 'a.js').includes('js-fastify-reply-send-html'));
  assert.ok(!ids(member('socket', 'send'), 'a.js').includes('js-fastify-reply-send-html'));
  assert.ok(ids(member(member('HtmlEncoder', 'Default'), 'Encode'), 'A.cs').includes('cs-htmlencoder-encode'));
  assert.ok(!ids(member(member('UrlEncoder', 'Default'), 'Encode'), 'A.cs').includes('cs-htmlencoder-encode'), 'URL encoding is not HTML escaping');
  assert.ok(ids('fmt.Fprintf', 'a.go').includes('go-fmt-fprintf-markup'));
  assert.ok(!ids('log.Fprintf', 'a.go').includes('go-fmt-fprintf-markup'));
});

test('catalog: mark_safe is not an XSS sanitizer (it marks a string as safe and escapes nothing)', () => {
  const san = (matchSinkOrSanitizer('mark_safe', 'a.py') || []).filter((e) => e.kind === 'sanitizer');
  assert.deepEqual(san.map((e) => e.id), []);
  assert.ok((matchSinkOrSanitizer('mark_safe', 'a.py') || []).some((e) => e.kind === 'sink' && e.vuln.cwe === 'CWE-79'));
});
