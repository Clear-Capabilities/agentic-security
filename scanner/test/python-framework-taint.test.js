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

// The second half of the round: class-based views, task dispatch, GraphQL resolvers, gRPC servicers, comprehension and lambda bodies,
// a return-type-hinted factory and an element read of a call result.
const SH = (imports, body) => ({ 'app.py': `from flask import Flask, request\nimport os\n${imports}\napp = Flask(__name__)\n@app.get("/r")\ndef r():\n    n = request.args.get("n")\n${body}` });
test('Django class-based views: a method parameter after (self, request) and self.kwargs are URL captures; a plain class is not a view', { skip: !py }, async () => {
  assert.deepEqual(await hits({ 'views.py': `from django.views import View\nclass V(View):\n    def get(self, request, name):\n        return HttpResponse(open("/d/" + name).read())\n` }, 'CWE-22'), ['views.py:4']);
  assert.deepEqual(await hits({ 'views.py': `from rest_framework.views import APIView\nclass V(APIView):\n    def get(self, request, *args, **kwargs):\n        return HttpResponse(open("/d/" + self.kwargs["name"]).read())\n` }, 'CWE-22'), ['views.py:4']);
  assert.deepEqual(await hits({ 'views.py': `class Helper:\n    def get(self, request, name):\n        return open("/d/" + name).read()\n    def other(self):\n        return open("/d/" + self.kwargs["x"]).read()\n` }, 'CWE-22'), []);
});
test('task dispatch: task.delay(x), task.apply_async(args=[x]) and queue.enqueue(fn, x) run the function with x; a task with no producer in the scan is not a source by itself', { skip: !py }, async () => {
  // the argument is whatever the producer enqueued: without a producer the task states nothing (the real sets showed bare task-argument
  // sources landing on administrator configuration)
  assert.deepEqual(await hits({ 'tasks.py': `from celery import shared_task\nimport os\n@shared_task\ndef ping(host):\n    os.system("ping " + host)\n` }, 'CWE-78'), []);
  assert.deepEqual(await hits(SH('', `    ping.delay(n)\ndef ping(host):\n    os.system("ping " + host)\n`), 'CWE-78'), ['app.py:10']);
  assert.deepEqual(await hits(SH('', `    ping.apply_async(args=[n])\ndef ping(host):\n    os.system("ping " + host)\n`), 'CWE-78'), ['app.py:10']);
  assert.deepEqual(await hits(SH('from rq import Queue\nq = Queue()', `    job = q.enqueue(ping, n, job_timeout=30)\ndef ping(host):\n    os.system("ping " + host)\n`), 'CWE-78'), ['app.py:11']);
  assert.deepEqual(await hits(SH('', `    ping.delay("localhost")\ndef ping(host):\n    os.system("ping " + host)\n`), 'CWE-78'), []);
  const ir = await buildProjectIRAsync({ 't.py': `def r(n):\n    ping.delay(n)\n    q.enqueue(ping, n, job_timeout=30)\n` });
  const calls = Object.values(ir.perFile['t.py'].functions[0].cfg.nodes).filter((x) => x.kind === 'call').map((x) => [x.callee, x.args.length, x.dispatch || null]);
  assert.deepEqual(calls, [['ping.delay', 1, null], ['ping', 1, 'delay'], ['q.enqueue', 3, null], ['ping', 1, 'enqueue']]);
});
test('GraphQL and gRPC: graphene resolve_x arguments after info, strawberry field arguments, and a servicer method\'s request are input', { skip: !py }, async () => {
  assert.deepEqual(await hits({ 'schema.py': `import graphene\nclass Q(graphene.ObjectType):\n    def resolve_user(self, info, name):\n        return db.execute("SELECT * FROM u WHERE n = '" + name + "'")\n` }, 'CWE-89'), ['schema.py:4']);
  assert.deepEqual(await hits({ 'schema.py': `import strawberry\n@strawberry.type\nclass Query:\n    @strawberry.field\n    def user(self, name: str) -> str:\n        return db.execute("SELECT * FROM u WHERE n = '" + name + "'")\n` }, 'CWE-89'), ['schema.py:6']);
  assert.deepEqual(await hits({ 'server.py': `import os\nimport svc_pb2_grpc\nclass Servicer(svc_pb2_grpc.PingServicer):\n    def Ping(self, request, context):\n        os.system("ping " + request.host)\n` }, 'CWE-78'), ['server.py:5']);
  // not a resolver (no info parameter), not a servicer
  assert.deepEqual(await hits({ 'schema.py': `class Q:\n    def resolve_user(self, name):\n        return db.execute("SELECT * FROM u WHERE n = '" + name + "'")\n` }, 'CWE-89'), []);
  assert.deepEqual(await hits({ 'server.py': `import os\nclass Handler:\n    def Ping(self, request, context):\n        os.system("ping " + request.host)\n` }, 'CWE-78'), []);
});
test('comprehension and lambda bodies are analysed, a return-type hint types a factory\'s result, and an element of a tainted split is tainted', { skip: !py }, async () => {
  assert.deepEqual(await hits(SH('', `    [os.system("ping " + h) for h in n.split(",")]\n`), 'CWE-78'), ['app.py:8']);
  assert.deepEqual(await hits(SH('', `    outs = [os.popen("ping " + h).read() for h in n.split(",")]\n`), 'CWE-78'), ['app.py:8']);
  assert.deepEqual(await hits(SH('', `    f = lambda h: os.system("ping " + h)\n    f(n)\n`), 'CWE-78'), ['app.py:8']);
  assert.deepEqual(await hits(SH('', `    f = lambda h: os.system("ping " + h)\n    f("localhost")\n`), 'CWE-78'), []);
  assert.deepEqual(await hits(SH('', `    h = n.split(",")[0]\n    os.system("ping " + h)\n`), 'CWE-78'), ['app.py:9']);
  assert.deepEqual(await hits({ 'app.py': `from flask import Flask, request\napp = Flask(__name__)\nfrom svc import Service, make\n@app.get("/r")\ndef r():\n    n = request.args.get("n")\n    s = make()\n    s.update(n)\n`, 'svc.py': `import sqlite3\nclass Service:\n    def update(self, name):\n        cur = sqlite3.connect("d").cursor()\n        cur.execute("SELECT * FROM t WHERE n = '" + name + "'")\ndef make() -> Service:\n    return Service()\n` }, 'CWE-89'), ['svc.py:5']);
  const ir = await buildProjectIRAsync({ 'svc.py': `class Service:\n    pass\ndef make() -> Service:\n    return Service()\n` });
  assert.equal(ir.perFile['svc.py'].functions.find((f) => f.name === 'make').returnType, 'Service');
});
