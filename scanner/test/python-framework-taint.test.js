// Python taint through framework shapes: a FastAPI dependency (`Depends(fn)`) binds the parameter to the dependency's return and
// fills the dependency's own parameters from the request; a Django view's URL captures come from urls.py; a `with X() as c` client
// is typed; a call chained on a sink call (`cur.execute(q).fetchall()`, `requests.get(u).json()`) still has its sink site; an
// awaited call is a call. Each positive case has a refusing twin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIRAsync, probePythonAvailable } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';

async function hits(files, cwe) {
  const ir = await buildProjectIRAsync(files);
  const r = runDeepAnalysis(ir.perFile, ir.callGraph, { fileContents: files });
  return [...new Set((Array.isArray(r) ? r : (r.findings || [])).filter((f) => f.cwe === cwe).map((f) => `${f.file}:${f.line}`))];
}
const py = probePythonAvailable ? probePythonAvailable() : true;
const SQL = (v) => `db.execute("SELECT * FROM t WHERE n = '" + ${v} + "'")`;
const FA = (body) => ({ 'app.py': `from fastapi import FastAPI, Depends\napp = FastAPI()\n${body}` });
const FL = (imports, body) => ({ 'app.py': `from flask import Flask, request\n${imports}\napp = Flask(__name__)\n@app.get("/r")\ndef r():\n    u = request.args.get("u")\n${body}` });

test('FastAPI: a parameter bound by Depends(fn) carries the return of fn, whose own text parameter is request input', { skip: !py }, async () => {
  assert.deepEqual(await hits(FA(`def get_name(name: str):\n    return name\n@app.get("/r")\ndef r(name: str = Depends(get_name)):\n    ${SQL('name')}\n`), 'CWE-89'), ['app.py:7']);
  // the dependency is a plain function with no route decorator; it is request-filled only because something depends on it
  assert.deepEqual(await hits(FA(`def get_name(name: str):\n    return name\ndef r(name):\n    ${SQL('name')}\n`), 'CWE-89'), []);
});
test('REFUSES: a dependency returning a clean object, and one whose parameter is an int', { skip: !py }, async () => {
  assert.deepEqual(await hits(FA(`def get_db():\n    return make_session()\n@app.get("/r")\ndef r(db = Depends(get_db)):\n    db.execute("SELECT 1")\n`), 'CWE-89'), []);
  assert.deepEqual(await hits(FA(`def get_page(page: int = 1):\n    return page\n@app.get("/r")\ndef r(p: int = Depends(get_page)):\n    db.execute("SELECT * FROM t LIMIT " + str(p))\n`), 'CWE-89'), []);
});
test('Django: the text captures of a path()/re_path() route mark the view\'s parameters; numeric converters and unrouted helpers do not', { skip: !py }, async () => {
  const V = `from django.http import HttpResponse\ndef v(request, name):\n    return HttpResponse(open("/d/" + name).read())\ndef w(request, pk):\n    return HttpResponse(open("/d/" + str(pk)).read())\n`;
  assert.deepEqual(await hits({ 'app/urls.py': `from django.urls import path\nfrom . import views\nurlpatterns = [path("x/<str:name>/", views.v)]\n`, 'app/views.py': V }, 'CWE-22'), ['app/views.py:3']);
  assert.deepEqual(await hits({ 'app/urls.py': `from django.urls import path\nfrom . import views\nurlpatterns = [path("x/<name>/", views.v)]\n`, 'app/views.py': V }, 'CWE-22'), ['app/views.py:3']);
  assert.deepEqual(await hits({ 'app/urls.py': `from django.urls import re_path\nfrom .views import v\nurlpatterns = [re_path(r"^x/(?P<name>\\w+)/$", v)]\n`, 'app/views.py': V }, 'CWE-22'), ['app/views.py:3']);
  assert.deepEqual(await hits({ 'app/urls.py': `from django.urls import path\nfrom . import views\nurlpatterns = [path("x/<int:pk>/", views.w)]\n`, 'app/views.py': V }, 'CWE-22'), []);
  assert.deepEqual(await hits({ 'app/urls.py': `from django.urls import path\nfrom . import views\nurlpatterns = [path("x/", views.other)]\n`, 'app/views.py': V }, 'CWE-22'), []);
  // the module beside the urls file wins over a same-named module elsewhere
  assert.deepEqual(await hits({ 'app/urls.py': `from django.urls import path\nfrom . import views\nurlpatterns = [path("x/<name>/", views.v)]\n`, 'app/views.py': V, 'other/views.py': V }, 'CWE-22'), ['app/views.py:3']);
  const ir = await buildProjectIRAsync({ 'app/urls.py': `from django.urls import path, re_path\nfrom . import views\nurlpatterns = [path("a/<slug:s>/<int:n>/", views.v), re_path(r"^b/(?P<id>\\d+)/(?P<word>\\w+)/$", views.w)]\n` });
  assert.deepEqual(ir.perFile['app/urls.py'].urlCaptures.map((c) => [c.view, c.module, c.params]), [['v', 'views', ['s']], ['w', 'views', ['word']]]);
});
test('a with-statement client is typed, so receiverTypeIn confirms the sink on a short name', { skip: !py }, async () => {
  assert.deepEqual(await hits(FL('import httpx', `    with httpx.Client() as c:\n        return c.get(u)\n`), 'CWE-918'), ['app.py:8']);
  assert.deepEqual(await hits(FL('import httpx', `    with httpx.Client() as c:\n        return c.get("https://fixed.example/")\n`), 'CWE-918'), []);
});
test('a sink call keeps its site under a chained call or member read, in a return, an assignment and a statement', { skip: !py }, async () => {
  assert.deepEqual(await hits(FL('import requests', `    return requests.get(u).json()\n`), 'CWE-918'), ['app.py:7']);
  assert.deepEqual(await hits(FL('import requests', `    return requests.get(u).text\n`), 'CWE-918'), ['app.py:7']);
  assert.deepEqual(await hits(FL('import sqlite3', `    cur = sqlite3.connect("x").cursor()\n    rows = cur.execute("SELECT * FROM t WHERE n = '" + u + "'").fetchall()\n`), 'CWE-89'), ['app.py:8']);
  assert.deepEqual(await hits(FL('import subprocess', `    subprocess.Popen("ping " + u, shell=True).communicate()\n`), 'CWE-78'), ['app.py:7']);
  // a member CHAIN is not a call chain: obj.exec.run(x) names no exec() call
  assert.deepEqual(await hits(FL('', `    obj.exec.run(u)\n`), 'CWE-94'), []);
  assert.deepEqual(await hits(FL('import requests', `    return requests.get("https://fixed.example/").json()[u]\n`), 'CWE-918'), []);
  const ir = await buildProjectIRAsync({ 'c.py': `def f(cur, q):\n    return cur.execute(q).fetchall()\n` });
  const ret = Object.values(ir.perFile['c.py'].functions[0].cfg.nodes).find((n) => n.kind === 'return');
  assert.equal(ret.value.callee, 'cur.execute.fetchall');
  assert.deepEqual(ret.value.innerCalls.map((c) => [c.callee, c.args.length]), [['cur.execute', 1]]);
});
test('an awaited call is a call: asyncio.create_subprocess_shell is a command sink, the exec form is not', { skip: !py }, async () => {
  assert.deepEqual(await hits(FL('import asyncio', `    await asyncio.create_subprocess_shell("ping " + u)\n`), 'CWE-78'), ['app.py:7']);
  assert.deepEqual(await hits(FL('import asyncio', `    await asyncio.create_subprocess_exec("ping", u)\n`), 'CWE-78'), []);
});
test('Template(source) compiles request text; string.Template and a literal template with request context do not', { skip: !py }, async () => {
  assert.deepEqual(await hits(FL('from jinja2 import Template', `    return Template(u).render()\n`), 'CWE-1336'), ['app.py:7']);
  assert.deepEqual(await hits(FL('import jinja2', `    return jinja2.Template(u).render()\n`), 'CWE-1336'), ['app.py:7']);
  assert.deepEqual(await hits(FL('import string', `    return string.Template(u).substitute(a=1)\n`), 'CWE-1336'), []);
  assert.deepEqual(await hits(FL('from jinja2 import Template', `    return Template("Hello {{ name }}").render(name=u)\n`), 'CWE-1336'), []);
});
