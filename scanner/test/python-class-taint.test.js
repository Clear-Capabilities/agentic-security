// Python taint through classes: a method called on an instance (constructed locally, at module level, held in a
// field, typed by a hint), `self.method(...)` resolved to the function's own class or an ancestor, and the receiver
// parameter skipped when arguments are mapped. Each positive case has a refusing twin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIRAsync } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';
import { probePythonAvailable } from '../src/ir/index.js';

const SQL = `cur.execute("SELECT * FROM t WHERE n = '" + name + "'")`;
const SERVICE = `import sqlite3\nclass Service:\n    def update(self, name):\n        cur = sqlite3.connect("d").cursor()\n        ${SQL}\n        return 1\n`;
async function sqli(files) {
  const ir = await buildProjectIRAsync(files);
  const r = runDeepAnalysis(ir.perFile, ir.callGraph, { fileContents: files });
  return [...new Set((Array.isArray(r) ? r : (r.findings || [])).filter((f) => f.cwe === 'CWE-89').map((f) => `${f.file}:${f.line}`))];
}
const py = probePythonAvailable ? probePythonAvailable() : true;
const view = (body) => `from flask import request\nfrom service import Service\n@app.route("/x")\ndef x():\n    name = request.args.get("name")\n${body}`;

test('a request value reaches the sink through a locally constructed instance', { skip: !py }, async () => {
  assert.deepEqual(await sqli({ 'views.py': view('    s = Service()\n    return s.update(name)\n'), 'service.py': SERVICE }), ['service.py:5']);
});
test('... through an inline construction and through a module-level instance', { skip: !py }, async () => {
  assert.deepEqual(await sqli({ 'views.py': view('    return Service().update(name)\n'), 'service.py': SERVICE }), ['service.py:5']);
  assert.deepEqual(await sqli({ 'views.py': `from flask import request\nfrom service import Service\nsvc = Service()\n@app.route("/x")\ndef x():\n    name = request.args.get("name")\n    return svc.update(name)\n`, 'service.py': SERVICE }), ['service.py:5']);
});
test('... through a field set in __init__, a field from a typed constructor parameter, and a class attribute', { skip: !py }, async () => {
  const ctl = (init) => `from flask import request\nfrom service import Service\nclass Ctl:\n${init}    def post(self):\n        name = request.args.get("name")\n        return self.svc.update(name)\n`;
  assert.deepEqual(await sqli({ 'views.py': ctl('    def __init__(self):\n        self.svc = Service()\n'), 'service.py': SERVICE }), ['service.py:5']);
  assert.deepEqual(await sqli({ 'views.py': ctl('    def __init__(self, svc: Service):\n        self.svc = svc\n'), 'service.py': SERVICE }), ['service.py:5']);
  assert.deepEqual(await sqli({ 'views.py': ctl('    svc = Service()\n'), 'service.py': SERVICE }), ['service.py:5']);
});
test('... through a parameter with a type hint', { skip: !py }, async () => {
  assert.deepEqual(await sqli({ 'views.py': `from flask import request\nfrom service import Service\ndef run(svc: Service):\n    name = request.args.get("name")\n    return svc.update(name)\n`, 'service.py': SERVICE }), ['service.py:5']);
});
test('self.helper(name) resolves to the own class, and to an ancestor', { skip: !py }, async () => {
  const own = `from flask import request\nimport sqlite3\nclass Ctl:\n    def helper(self, name):\n        cur = sqlite3.connect("d").cursor()\n        ${SQL}\n    def post(self):\n        name = request.args.get("name")\n        return self.helper(name)\n`;
  const inherited = `from flask import request\nimport sqlite3\nclass Base:\n    def helper(self, name):\n        cur = sqlite3.connect("d").cursor()\n        ${SQL}\nclass Ctl(Base):\n    def post(self):\n        name = request.args.get("name")\n        return self.helper(name)\n`;
  assert.deepEqual(await sqli({ 'views.py': own }), ['views.py:6']);
  assert.deepEqual(await sqli({ 'views.py': inherited }), ['views.py:6']);
});
test('REFUSES: another class\'s same-named method, a library class, a shadowing local, and a clean argument position', { skip: !py }, async () => {
  const other = `from flask import request\nimport sqlite3\nclass Other:\n    def helper(self, name):\n        cur = sqlite3.connect("d").cursor()\n        ${SQL}\nclass Ctl:\n    def helper(self, name):\n        return 1\n    def post(self):\n        name = request.args.get("name")\n        return self.helper(name)\n`;
  assert.deepEqual(await sqli({ 'views.py': other }), [], 'two classes defining helper never cross');
  assert.deepEqual(await sqli({ 'views.py': view('    f = Foo()\n    return f.update(name)\n').replace('from service import Service', 'from lib import Foo') }), [], 'a library class resolves to nothing');
  assert.deepEqual(await sqli({ 'views.py': `from flask import request\nfrom service import Service\nsvc = Service()\n@app.route("/x")\ndef x():\n    name = request.args.get("name")\n    svc = other()\n    return svc.update(name)\n`, 'service.py': SERVICE }), [], 'a local shadows the module instance');
  const clean = `from flask import request\nimport sqlite3\nclass Service:\n    def update(self, name, note):\n        cur = sqlite3.connect("d").cursor()\n        ${SQL}\nclass Ctl:\n    def post(self):\n        note = request.args.get("n")\n        s = Service()\n        return s.update("fixed", note)\n`;
  assert.deepEqual(await sqli({ 'views.py': clean }), [], 'self is not an argument slot: the tainted second argument maps to the second parameter, which is not the sink');
});
test('the IR states the facts: class records with field types, class-qualified method ids, parameter types, constructed locals', { skip: !py }, async () => {
  const ir = await buildProjectIRAsync({ 'v.py': `class Service:\n    pass\nclass Ctl:\n    def __init__(self, other: Service):\n        self.svc = Service()\n        self.other = other\n    def post(self, q: "Service"):\n        s = Service()\n        return s\n` });
  const pf = ir.perFile['v.py'];
  assert.deepEqual(pf.classes.map((c) => c.name), ['Service', 'Ctl']);
  assert.deepEqual(pf.classes[1].fieldTypes, { svc: 'Service', other: 'Service' });
  const post = pf.functions.find((f) => f.name === 'post');
  assert.match(post.qid, /^v\.py::Ctl::post@/);
  assert.equal(post.className, 'Ctl');
  assert.deepEqual(post.paramTypes, { q: 'Service' });
  assert.ok(Object.values(post.cfg.nodes).some((n) => n.kind === 'assign' && n.target === 's' && n.declaredType === 'Service'));
});
