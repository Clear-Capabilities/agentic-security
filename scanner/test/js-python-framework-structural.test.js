// JS/TS + Python framework structural detectors — PRD Tier 1 (JS/Python recall).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanJsFrameworkStructural as js } from '../src/sast/js-framework-structural.js';
import { scanPythonStructural as py } from '../src/sast/python-structural.js';

const has = (f, cwe) => f.some(x => x.cwe === cwe);
const none = (f, cwe) => f.filter(x => x.cwe === cwe).length === 0;

test('JS SQLi — db.query with concat/template, not parameterized', () => {
  assert.ok(has(js('a.ts', 'this.conn.query("SELECT * FROM u WHERE name=\'" + name + "\'")'), 'CWE-89'));
  assert.ok(has(js('a.js', 'c.query(`SELECT * FROM u WHERE id=${id}`)'), 'CWE-89'));
  assert.ok(none(js('a.js', "c.query('SELECT * FROM u WHERE name=?', [name])"), 'CWE-89'));
});

test('Koa path traversal (koa-send) + Koa reflected XSS (ctx.body), escape clears XSS', () => {
  assert.ok(has(js('a.js', 'await send(ctx, ctx.query.f, { root: "/var/data" })'), 'CWE-22'));
  assert.ok(has(js('a.js', "ctx.body = '<h1>Hi ' + ctx.query.name + '</h1>'"), 'CWE-79'));
  assert.ok(none(js('a.js', "ctx.body = '<h1>Hi ' + escape(ctx.query.name) + '</h1>'"), 'CWE-79'));
});

test('NestJS SSRF — http.get with a non-literal URL', () => {
  assert.ok(has(js('p.ts', 'return this.http.get(url).toPromise()'), 'CWE-918'));
});

test('Prototype pollution — deep-merge of user input, cleared by a key filter', () => {
  assert.ok(has(js('m.js', 'deepMerge(result, req.body)'), 'CWE-1321'));
  assert.ok(none(js('m.js', "const FORBIDDEN_KEYS = new Set(['__proto__']);\nif (FORBIDDEN_KEYS.has(key)) continue;\ndeepMerge(result, req.body)"), 'CWE-1321'));
});

test('Flask render_template_string built from input is XSS; Jinja {{ }} is safe', () => {
  assert.ok(has(py('app.py', "return render_template_string('<h1>Hi ' + name + '</h1>')"), 'CWE-79'));
  assert.ok(none(py('app.py', "return render_template_string('<h1>Hi {{ name }}</h1>', name=name)"), 'CWE-79'));
});

test('Django raw()/extra() + cursor.execute with concat = SQLi; ORM/params clean', () => {
  assert.ok(has(py('v.py', 'User.objects.raw("SELECT id FROM auth_user ORDER BY " + col)'), 'CWE-89'));
  assert.ok(has(py('v.py', 'cur.execute("SELECT * FROM u WHERE n=" + name)'), 'CWE-89'));
  assert.ok(none(py('v.py', 'User.objects.all().order_by(col)'), 'CWE-89'));
  assert.ok(none(py('v.py', 'cur.execute("SELECT * FROM u WHERE id = %s", [uid])'), 'CWE-89'));
});

test('no false positives on clean JS / Python', () => {
  assert.deepEqual(js('ok.js', 'function add(a, b){ return a + b; }'), []);
  assert.deepEqual(py('ok.py', 'def add(a, b):\n    return a + b'), []);
});
