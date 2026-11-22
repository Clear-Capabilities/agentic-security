// The 0.220.0 round beyond framework shapes: module resolution (tsconfig paths and baseUrl, Python source roots and submodule imports),
// route-module and h3 sources, an allowlist ternary, field paths for an object passed as a variable, element reads of a call result,
// Ruby keyword arguments as records with a string-only sink, and the cross-layer check that drops a structural SQL finding at a call
// the taint engine found clean. Each positive case has a refusing twin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { buildProjectIRAsync } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';
import { buildModuleIndex } from '../src/ir/module-resolver.js';
import { mkTestTmp } from './helpers/tmp.js';

async function hits(files, cwe) {
  const ir = await buildProjectIRAsync(files);
  const r = runDeepAnalysis(ir.perFile, ir.callGraph, { fileContents: files });
  return [...new Set((Array.isArray(r) ? r : (r.findings || [])).filter((f) => f.cwe === cwe).map((f) => `${f.file}:${f.line}`))];
}
const SVC_TS = `export function find(name: string) { db.query("SELECT * FROM t WHERE n = '" + name + "'"); }\n`;
const SVC_PY = `def find(name):\n    db.execute("SELECT * FROM t WHERE n = '" + name + "'")\n`;

test('tsconfig paths and baseUrl resolve a non-relative import; an alias no pattern names stays unresolved', async () => {
  const idx = buildModuleIndex({ 'tsconfig.json': `{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"], "~/*": ["./*"] } } }`, 'src/lib/svc.ts': SVC_TS, 'lib/x.ts': 'export const x = 1;\n', 'src/app/r.ts': 'import { find } from "@/lib/svc";\n' }, {});
  assert.equal(idx.resolveSpecifier('src/app/r.ts', '@/lib/svc', 'js').file, 'src/lib/svc.ts');
  assert.equal(idx.resolveSpecifier('src/app/r.ts', '~/lib/x', 'js').file, 'lib/x.ts');
  assert.equal(idx.resolveSpecifier('src/app/r.ts', '@/lib/missing', 'js').kind, 'unresolved');
  assert.equal(idx.resolveSpecifier('src/app/r.ts', '#lib/svc', 'js').kind, 'unresolved');
  assert.equal(idx.resolveSpecifier('src/app/r.ts', 'express', 'js').kind, 'external');
  const base = buildModuleIndex({ 'tsconfig.json': `{ "compilerOptions": { "baseUrl": "src" } }`, 'src/lib/svc.ts': SVC_TS }, {});
  assert.equal(base.resolveSpecifier('src/app/r.ts', 'lib/svc', 'js').file, 'src/lib/svc.ts');
  // a comment and a trailing comma in the tsconfig are read past
  const lenient = buildModuleIndex({ 'tsconfig.json': `{\n  // aliases\n  "compilerOptions": { "paths": { "@/*": ["src/*"], }, },\n}`, 'src/a.ts': 'export const a = 1;\n' }, {});
  assert.equal(lenient.resolveSpecifier('src/b.ts', '@/a', 'js').file, 'src/a.ts');
  assert.deepEqual(await hits({ 'tsconfig.json': `{ "compilerOptions": { "baseUrl": "src" } }`, 'src/lib/svc.ts': SVC_TS, 'src/app/route.ts': `import express from "express";\nimport { find } from "lib/svc";\nconst app = express();\napp.get("/r", (req, res) => { find(req.query.n as string); res.end(); });\n` }, 'CWE-89'), ['src/lib/svc.ts:1']);
});
test('Python absolute imports resolve from the repository root, a src/ layout and the importer\'s package parents; a from-import binds a submodule', async () => {
  const idx = buildModuleIndex({ 'src/app/__init__.py': '', 'src/app/svc.py': SVC_PY, 'src/app/web/views.py': 'from app.svc import find\n', 'pkg/__init__.py': '', 'pkg/mod.py': 'def g():\n    pass\n', 'pkg/use.py': 'from . import mod\n' }, {});
  assert.equal(idx.resolveSpecifier('src/app/web/views.py', 'app.svc', 'py').file, 'src/app/svc.py');
  assert.equal(idx.resolveSpecifier('src/app/web/views.py', 'app', 'py').file, 'src/app/__init__.py');
  assert.equal(idx.resolveSpecifier('src/app/web/views.py', 'requests', 'py').kind, 'external');
  assert.equal(idx.resolveSpecifier('pkg/use.py', '.mod', 'py').file, 'pkg/mod.py');
  assert.deepEqual(await hits({ 'app/svc.py': SVC_PY, 'app/views.py': `from flask import request\nfrom . import svc\n@app.get("/r")\ndef r():\n    svc.find(request.args.get("n"))\n` }, 'CWE-89'), ['app/svc.py:2']);
  assert.deepEqual(await hits({ 'src/app/__init__.py': '', 'src/app/svc.py': SVC_PY, 'src/app/views.py': `from flask import request\nfrom app.svc import find\n@app.get("/r")\ndef r():\n    find(request.args.get("n"))\n` }, 'CWE-89'), ['src/app/svc.py:2']);
});
test('route modules: Remix loader params and action formData, SvelteKit load params and +server event.url, h3 getQuery/readBody; a non-route export is not marked', async () => {
  assert.deepEqual(await hits({ 'app/routes/f.$name.tsx': `import fs from "fs";\nexport async function loader({ params }) {\n  return fs.readFileSync("/d/" + params.name, "utf8");\n}\n` }, 'CWE-22'), ['app/routes/f.$name.tsx:3']);
  assert.deepEqual(await hits({ 'app/routes/run.tsx': `import { exec } from "child_process";\nexport async function action({ request }) {\n  const fd = await request.formData();\n  exec("ping " + fd.get("host"));\n}\n` }, 'CWE-78'), ['app/routes/run.tsx:4']);
  assert.deepEqual(await hits({ 'src/routes/f/[name]/+page.server.ts': `import fs from "fs";\nexport async function load({ params }) {\n  return { text: fs.readFileSync("/d/" + params.name, "utf8") };\n}\n` }, 'CWE-22'), ['src/routes/f/[name]/+page.server.ts:3']);
  assert.deepEqual(await hits({ 'src/routes/api/r/+server.ts': `import { exec } from "child_process";\nexport async function GET(event) {\n  exec("ping " + event.url.searchParams.get("h"));\n  return new Response("ok");\n}\n` }, 'CWE-78'), ['src/routes/api/r/+server.ts:3']);
  assert.deepEqual(await hits({ 'server/api/r.ts': `import { exec } from "child_process";\nexport default defineEventHandler(async (event) => {\n  const q = getQuery(event);\n  exec("ping " + q.h);\n});\n` }, 'CWE-78'), ['server/api/r.ts:4']);
  assert.deepEqual(await hits({ 'server/api/r.post.ts': `export default defineEventHandler(async (event) => {\n  const body = await readBody(event);\n  return prisma.$queryRawUnsafe("SELECT * FROM t WHERE n = '" + body.n + "'");\n});\n` }, 'CWE-89'), ['server/api/r.post.ts:3']);
  // a helper exported from a routes file is not a loader; a load() outside a +page/+layout file is not SvelteKit's
  assert.deepEqual(await hits({ 'app/routes/f.tsx': `import fs from "fs";\nexport async function helper({ params }) {\n  return fs.readFileSync("/d/" + params.name, "utf8");\n}\n` }, 'CWE-22'), []);
  assert.deepEqual(await hits({ 'src/lib/data.ts': `import fs from "fs";\nexport async function load({ params }) {\n  return fs.readFileSync("/d/" + params.name, "utf8");\n}\n` }, 'CWE-22'), []);
});
test('an allowlist ternary carries only the fallback: a value chosen from a constant collection is not tainted; a non-constant collection still is', async () => {
  const Q = (choice) => ({ 'a.js': `const COLS = ['name', 'age'];\nconst SET = new Set(['a', 'b']);\napp.get('/u', (req, res) => { const c = ${choice}; db.query('SELECT ' + c + ' FROM users'); res.send('ok'); });\n` });
  assert.deepEqual(await hits(Q(`COLS.includes(req.query.c) ? req.query.c : 'name'`), 'CWE-89'), []);
  assert.deepEqual(await hits(Q(`!COLS.includes(req.query.c) ? 'name' : req.query.c`), 'CWE-89'), []);
  assert.deepEqual(await hits(Q(`COLS.indexOf(req.query.c) !== -1 ? req.query.c : 'name'`), 'CWE-89'), []);
  assert.deepEqual(await hits(Q(`SET.has(req.query.c) ? req.query.c : 'a'`), 'CWE-89'), []);
  assert.deepEqual(await hits(Q(`['x', 'y'].includes(req.query.c) ? req.query.c : 'x'`), 'CWE-89'), []);
  assert.deepEqual(await hits(Q(`req.query.ok ? req.query.c : 'name'`), 'CWE-89'), ['a.js:3']);
  assert.deepEqual(await hits({ 'a.js': `app.get('/u', (req, res) => { const cols = req.query.cols.split(','); const c = cols.includes(req.query.c) ? req.query.c : 'name'; db.query('SELECT ' + c + ' FROM users'); res.send('ok'); });\n` }, 'CWE-89'), ['a.js:1']);
});
test('an object passed as a variable enters the callee by its tainted fields; an element read of a tainted call result is tainted', async () => {
  const REC = `import express from "express";\nfunction rec({ root, decision }) { db.query("SELECT * FROM t WHERE n = '" + root + "'"); }\nexport function h(req, res) { BODY }\n`;
  assert.deepEqual(await hits({ 'a.js': REC.replace('BODY', `const o = { root: 'fixed', decision: req.query.d }; rec(o);`) }, 'CWE-89'), []);
  assert.deepEqual(await hits({ 'a.js': REC.replace('BODY', `const o = { root: 'fixed', decision: 1 }; o.root = req.query.p; rec(o);`) }, 'CWE-89'), ['a.js:2']);
  assert.deepEqual(await hits({ 'a.js': REC.replace('BODY', `const o = req.body; rec(o);`) }, 'CWE-89'), ['a.js:2']);
  assert.deepEqual(await hits({ 'a.js': `const { exec } = require("child_process");\napp.get("/r", (req, res) => { const h = req.query.n.split(",")[0]; exec("ping " + h); });\n` }, 'CWE-78'), ['a.js:2']);
  assert.deepEqual(await hits({ 'a.js': `const { exec } = require("child_process");\napp.get("/r", (req, res) => { const h = "a,b".split(",")[0]; exec("ping " + h); });\n` }, 'CWE-78'), []);
});
test('Ruby: a keyword argument is a one-key record, so where(id: params[:id]) is the parameterised form and where("id = " + x) is not; a nested sink inside the record still fires', async () => {
  const RB = (body) => ({ 'a.rb': `class UsersController < ApplicationController\n  def show\n    ${body}\n  end\nend\n` });
  assert.deepEqual(await hits(RB(`User.where(id: params[:id])`), 'CWE-89'), []);
  assert.deepEqual(await hits(RB(`User.where("id = " + params[:id])`), 'CWE-89'), ['a.rb:3']);
  assert.deepEqual(await hits(RB(`render plain: File.read("/var/data/" + params[:file])`), 'CWE-22'), ['a.rb:3']);
});
test('cross-layer: a structural JS SQL finding is dropped at a call the taint engine examined and found clean, kept where the engine did not look', async () => {
  const { runScan } = await import('../src/runScan.js');
  const scan = async (prefix, code) => {
    const dir = mkdtempSync(join(mkTestTmp(prefix), 'p-'));
    mkdirSync(dirname(join(dir, 'a.js')), { recursive: true }); writeFileSync(join(dir, 'a.js'), code);
    const { scan } = await runScan(dir, { deep: true, deepInCi: true });
    return scan.findings.filter((f) => f.cwe === 'CWE-89').map((f) => f.parser);
  };
  // clean at the examined site: no finding of either layer
  assert.deepEqual(await scan('xl-clean', `const COLS = ['name', 'age'];\napp.get('/u', (req, res) => { const c = COLS.includes(req.query.c) ? req.query.c : 'name'; db.query('SELECT ' + c + ' FROM users'); res.send('ok'); });\n`), []);
  // tainted: the taint finding is the one kept (the structural duplicate dedupes against it)
  const tainted = await scan('xl-tainted', `app.get('/u', (req, res) => { db.query('SELECT ' + req.query.c + ' FROM users'); res.send('ok'); });\n`);
  assert.ok(tainted.includes('IR-TAINT'), JSON.stringify(tainted));
  // a constant-only concatenation: the structural rule itself reads it as constant
  assert.deepEqual(await scan('xl-const', `const TABLE = 'users';\napp.get('/u', (req, res) => { db.query('SELECT * FROM ' + TABLE + ' WHERE active = 1'); res.send('ok'); });\n`), []);
});

// What the first reading of the real-code sets (bench/dag/dev-realcode) changed: every case below is a class found there, with its positive twin.
test('operator-only origins: a path or command whose every recorded origin is the command line or the environment is not reported, even through a helper; request origin and unattributed flows are', async () => {
  assert.deepEqual(await hits({ 'r1.py': `import argparse\ndef read_lock(path):\n    with open(path) as f:\n        return f.read()\ndef main():\n    p = argparse.ArgumentParser()\n    p.add_argument("--lock")\n    a = p.parse_args()\n    read_lock(a.lock)\n` }, 'CWE-22'), []);
  assert.deepEqual(await hits({ 'r2.py': `import os, sys\nos.system("ping " + sys.argv[1])\n` }, 'CWE-78'), []);
  assert.deepEqual(await hits({ 'r3.py': `from flask import Flask, request\napp = Flask(__name__)\ndef read_it(path):\n    with open(path) as f:\n        return f.read()\n@app.get("/r")\ndef r():\n    return read_it("/d/" + request.args.get("p"))\n` }, 'CWE-22'), ['r3.py:4']);
  // a container flow carries no origin record: kept (the gate drops only on positive operator evidence)
  assert.deepEqual(await hits({ 'r4.py': `import os\nfrom flask import request\ndef handler():\n    items = []\n    items.append(request.args['cmd'])\n    os.system(items[0])\n` }, 'CWE-78'), ['r4.py:6']);
});
test('statement builders are not SQL text: select()/delete() constructs, directly or through a variable, do not fire the execute sinks; SQL text does', async () => {
  assert.deepEqual(await hits({ 's1.py': `from flask import Flask, request\nfrom sqlalchemy import select, delete\napp = Flask(__name__)\n@app.get("/r")\ndef r():\n    u = request.args.get("u")\n    db.session.execute(select(Item).where(Item.name == u))\n    stmt = delete(Item).where(Item.name == u)\n    db.session.execute(stmt)\n` }, 'CWE-89'), []);
  assert.deepEqual(await hits({ 's2.py': `from flask import Flask, request\napp = Flask(__name__)\n@app.get("/r")\ndef r():\n    u = request.args.get("u")\n    q = "SELECT * FROM t WHERE n = '" + u + "'"\n    db.session.execute(q)\n` }, 'CWE-89'), ['s2.py:7']);
  // SQLModel's session.exec is not the exec builtin; sqlparse.parse is not an XML parser; an ORM session's delete is not an HTTP DELETE
  assert.deepEqual(await hits({ 's3.py': `from flask import Flask, request\nfrom sqlmodel import select\nimport sqlparse\napp = Flask(__name__)\n@app.get("/r")\ndef r():\n    u = request.args.get("u")\n    rows = session.exec(select(Item).where(Item.name == u)).all()\n    sqlparse.parse(u)\n    item = Item.query.get(u)\n    db.session.delete(item)\n` }, 'CWE-95'), []);
  assert.deepEqual(await hits({ 's4.py': `from flask import Flask, request\nimport sqlparse\napp = Flask(__name__)\n@app.get("/r")\ndef r():\n    u = request.args.get("u")\n    sqlparse.parse(u)\n` }, 'CWE-611'), []);
  assert.deepEqual(await hits({ 's5.py': `from flask import Flask, request\napp = Flask(__name__)\n@app.get("/r")\ndef r():\n    u = request.args.get("u")\n    item = Item.query.get(u)\n    db.session.delete(item)\n` }, 'CWE-918'), []);
  assert.deepEqual(await hits({ 's6.py': `from flask import Flask, request\nfrom lxml import etree\napp = Flask(__name__)\n@app.get("/r")\ndef r():\n    etree.parse(request.args.get("u"))\n` }, 'CWE-611'), ['s6.py:6']);
});
test('SSRF needs the host: a literal scheme and host or a same-origin path prefix is not SSRF; a protocol-relative prefix, a bare value and a tainted host are', async () => {
  assert.deepEqual(await hits({ 'u1.ts': `export async function h(req, res) { const r = await fetch("/api/items/" + req.query.id); res.end(await r.text()); }\n` }, 'CWE-918'), []);
  assert.deepEqual(await hits({ 'u2.ts': `export async function h(req, res) { const r = await fetch(\`https://api.example.com/v1/\${req.query.id}\`); res.end(await r.text()); }\n` }, 'CWE-918'), []);
  assert.deepEqual(await hits({ 'u3.ts': `export async function h(req, res) { const r = await fetch("//" + req.query.host + "/x"); res.end(await r.text()); }\n` }, 'CWE-918'), ['u3.ts:1']);
  assert.deepEqual(await hits({ 'u4.ts': `export async function h(req, res) { const r = await fetch(req.query.url as string); res.end(await r.text()); }\n` }, 'CWE-918'), ['u4.ts:1']);
  assert.deepEqual(await hits({ 'u5.ts': `export async function h(req, res) { const r = await fetch(\`https://\${req.query.host}/v1\`); res.end(await r.text()); }\n` }, 'CWE-918'), ['u5.ts:1']);
  // an environment-configured base URL is the operator's
  assert.deepEqual(await hits({ 'u6.ts': `export async function h(req, res) { const base = process.env.API_URL; const r = await fetch(base + "/items"); res.end(await r.text()); }\n` }, 'CWE-918'), []);
  // the template's literal chunks are in the IR, in source order
  const ir = await buildProjectIRAsync({ 'u7.js': 'function f(a, b) { return `https://h/${a}/x/${b}`; }\n' });
  const ret = Object.values(ir.perFile['u7.js'].functions.find((x) => x.name === 'f').cfg.nodes).find((n) => n.kind === 'return');
  assert.deepEqual(ret.value.parts.map((p) => (p.kind === 'literal' ? p.value : p.name)), ['https://h/', 'a', '/x/', 'b']);
});
test('a RegExp bound in this function is a RegExp here even when another function binds the same name to something else; a service method named execute is not a database', async () => {
  assert.deepEqual(await hits({ 'x1.ts': `export const other = (text: string) => { const separator = text.indexOf("&"); return separator; };\nexport const hasMore = (text: string, max: number): boolean => {\n  const separator = /[ ,]/g;\n  let n = 0;\n  while (separator.exec(text) !== null) { if (++n >= max) return true; }\n  return false;\n};\nexport function h(req, res) { hasMore(req.query.t, 3); }\n` }, 'CWE-78'), []);
  assert.deepEqual(await hits({ 'x2.ts': `import express from "express";\nconst app = express();\napp.post("/r", async (req, res) => { const out = await this.createOneQueryRunnerService.execute({ data: req.body }); res.json(out); });\n` }, 'CWE-89'), []);
  assert.deepEqual(await hits({ 'x3.ts': `import express from "express";\nimport { db } from "./db";\nconst app = express();\napp.get("/r", async (req, res) => { res.json(await db.execute("SELECT * FROM t WHERE n = '" + req.query.n + "'")); });\n` }, 'CWE-89'), ['x3.ts:4']);
});
