// The 0.221.0 round: what the real-code development sets' false positives taught the engine. Each mechanism is pinned with a
// positive case (the finding goes) and a refusing twin (the finding stays): an allowlist membership guard with an early exit,
// a URL-safety predicate on a multi-line condition, a keyword passed through a splatted local dict, a response whose content type
// is not markup, an escaped regular-expression pattern, an object's own `eval` method, a bound `raw(text, bindings)`, Django's
// `format_html` as an escaper, framework URL builders at a redirect, a `return` that no longer flows into the next statement, the
// browser-module scope, and the multi-line guard head in the text-layer dominance check.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIRAsync } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';
import { isBrowserModule, dropBrowserModuleServerFindings } from '../src/dataflow/browser-module.js';
import { guardDominatesSink } from '../src/dataflow/guard-dominance.js';

async function deep(files) {
  const ir = await buildProjectIRAsync(files);
  const r = runDeepAnalysis(ir.perFile, ir.callGraph, { fileContents: files });
  return Array.isArray(r) ? r : (r.findings || []);
}
async function hits(files, cwe) {
  return [...new Set((await deep(files)).filter((f) => f.cwe === cwe).map((f) => `${f.file}:${f.line}`))];
}

const EXPRESS_HEAD = `import fs from 'node:fs';\nimport path from 'node:path';\nimport express from 'express';\nconst NAMES = ['data.json', 'messages.json'];\nconst app = express();\n`;

test('an allowlist membership guard narrows: the early-exit form and the guarded block; a check whose failing branch continues keeps the finding', async () => {
  const exit = EXPRESS_HEAD + `app.get('/x', (req, res, next) => {\n  const name = req.query.f;\n  if (!NAMES.includes(name)) { next(); return; }\n  res.end(fs.readFileSync(path.join('/data', name)));\n});\n`;
  const block = EXPRESS_HEAD + `app.get('/z', (req, res) => {\n  const name = req.query.f;\n  if (NAMES.includes(name)) { res.end(fs.readFileSync(path.join('/data', name))); }\n});\n`;
  const merge = EXPRESS_HEAD + `app.get('/y', (req, res) => {\n  const name = req.query.f;\n  if (!NAMES.includes(name)) { console.log('nope'); }\n  res.end(fs.readFileSync(path.join('/data', name)));\n});\n`;
  const open = EXPRESS_HEAD + `app.get('/w', (req, res, next) => {\n  const name = req.query.f;\n  if (!req.app.locals.names.includes(name)) { next(); return; }\n  res.end(fs.readFileSync(path.join('/data', name)));\n});\n`;
  assert.deepEqual(await hits({ 'a.ts': exit }, 'CWE-22'), []);
  assert.deepEqual(await hits({ 'a.ts': block }, 'CWE-22'), []);
  assert.deepEqual(await hits({ 'a.ts': merge }, 'CWE-22'), ['a.ts:9']);
  assert.deepEqual(await hits({ 'a.ts': open }, 'CWE-22'), ['a.ts:9'], 'a collection that is not closed proves nothing');
});

test('a return no longer flows into the statement after its block', async () => {
  const ir = await buildProjectIRAsync({ 'r.js': `function f(a) {\n  if (!a) { return 1; }\n  g(a);\n}\n` });
  const fn = ir.perFile.get ? ir.perFile.get('r.js').functions.find((x) => x.name === 'f') : ir.perFile['r.js'].functions.find((x) => x.name === 'f');
  const ret = Object.values(fn.cfg.nodes).find((n) => n.kind === 'return');
  assert.deepEqual(ret.succ, [fn.cfg.exit]);
});

test('Django: a URL-safety predicate on a multi-line condition narrows the redirect; the unguarded redirect and the negated early exit are both read', async () => {
  const guarded = `from django.shortcuts import redirect\nfrom django.utils.http import url_has_allowed_host_and_scheme\n\ndef done(request):\n    nxt = request.GET.get('next')\n    if nxt and url_has_allowed_host_and_scheme(\n        nxt,\n        allowed_hosts={request.get_host()},\n    ):\n        return redirect(nxt)\n    return redirect('/')\n`;
  const early = `from django.shortcuts import redirect\nfrom django.utils.http import url_has_allowed_host_and_scheme\n\ndef done(request):\n    nxt = request.GET.get('next')\n    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts=None):\n        return redirect('/')\n    return redirect(nxt)\n`;
  const bare = `from django.shortcuts import redirect\n\ndef done(request):\n    nxt = request.GET.get('next')\n    return redirect(nxt)\n`;
  assert.deepEqual(await hits({ 'v.py': guarded }, 'CWE-601'), []);
  assert.deepEqual(await hits({ 'v.py': early }, 'CWE-601'), []);
  assert.deepEqual(await hits({ 'v.py': bare }, 'CWE-601'), ['v.py:5']);
});

test('a URL the framework builds is not a redirect target: url_for, reverse, get_login_url, a model\'s get_absolute_url; a variable bound to one too', async () => {
  const built = `from flask import redirect, request, url_for\nfrom flask_login import login_url as get_login_url\n\ndef a():\n    return redirect(url_for('login', next=request.args.get('next')))\n\ndef b():\n    target = get_login_url(next=request.url)\n    return redirect(target)\n\ndef c(obj):\n    return redirect(obj.get_absolute_url())\n\ndef d():\n    return redirect(request.args.get('next'))\n`;
  assert.deepEqual(await hits({ 'r.py': built }, 'CWE-601'), ['r.py:15']);
});

test('a keyword passed through a splatted local dict is read: shell False is not a shell, shell True is, an updated dict is not enumerable', async () => {
  const py = `import sys\nfrom subprocess import Popen, PIPE\n\ndef quiet():\n    command = sys.argv[1:]\n    kwargs = dict()\n    kwargs['close_fds'] = False\n    kwargs['shell'] = False\n    return Popen(command, stdout=PIPE, **kwargs)\n\ndef loud():\n    command = sys.argv[1]\n    kwargs = {}\n    kwargs['shell'] = True\n    return Popen(command, stdout=PIPE, **kwargs)\n\ndef unknown(extra):\n    command = sys.argv[1]\n    kwargs = {}\n    kwargs.update(extra)\n    return Popen(command, stdout=PIPE, **kwargs)\n\ndef literal():\n    command = sys.argv[1]\n    kwargs = {'shell': True}\n    return Popen(command, **kwargs)\n`;
  assert.deepEqual((await hits({ 'p.py': py }, 'CWE-78')).sort(), ['p.py:15', 'p.py:21', 'p.py:26']);
});

test('a response whose content type the function set to JSON is not an HTML document; a markup type or no type keeps the finding', async () => {
  const head = `import express from 'express';\nconst app = express();\n`;
  const json = head + `app.get('/a', (req, res) => {\n  const body = render(req.params.lang);\n  res.setHeader('Content-Type', 'application/json');\n  res.send(body);\n});\n`;
  const alias = head + `app.get('/b', (req, res) => {\n  res.type('json').send(req.query.q);\n});\n`;
  const html = head + `app.get('/c', (req, res) => {\n  res.setHeader('Content-Type', 'text/html');\n  res.send(req.query.q);\n});\n`;
  const none = head + `app.get('/d', (req, res) => {\n  res.send(req.query.q);\n});\n`;
  assert.deepEqual(await hits({ 'a.ts': json }, 'CWE-79'), []);
  assert.deepEqual(await hits({ 'a.ts': alias }, 'CWE-79'), []);
  assert.deepEqual(await hits({ 'a.ts': html }, 'CWE-79'), ['a.ts:5']);
  assert.deepEqual(await hits({ 'a.ts': none }, 'CWE-79'), ['a.ts:4']);
});

test('a pattern whose metacharacters were escaped cannot backtrack; the unescaped pattern is reported', async () => {
  const head = `import express from 'express';\nconst app = express();\n`;
  const escaped = head + `app.get('/a', (req, res) => {\n  const tag = req.query.tag;\n  const re = new RegExp(tag.replace(/[.*+?^\${}()|[\\]\\\\]/g, '\\\\$&'), 'g');\n  res.json({ ok: re.test('x') });\n});\n`;
  const helper = head + `import escapeStringRegexp from 'escape-string-regexp';\napp.get('/b', (req, res) => {\n  const re = new RegExp(escapeStringRegexp(req.query.tag));\n  res.json({ ok: re.test('x') });\n});\n`;
  const raw = head + `app.get('/c', (req, res) => {\n  const re = new RegExp(req.query.tag, 'g');\n  res.json({ ok: re.test('x') });\n});\n`;
  assert.deepEqual(await hits({ 'a.ts': escaped }, 'CWE-1333'), []);
  assert.deepEqual(await hits({ 'a.ts': helper }, 'CWE-1333'), []);
  assert.deepEqual(await hits({ 'a.ts': raw }, 'CWE-1333'), ['a.ts:4']);
});

test('an object\'s own eval method is not JavaScript\'s eval; the bare global and window.eval are', async () => {
  const head = `import express from 'express';\nimport { createClient } from 'redis';\nconst app = express();\nconst redis = createClient();\n`;
  const method = head + `app.get('/a', async (req, res) => {\n  res.json(await redis.eval(req.query.script, { keys: [] }));\n});\n`;
  const bare = head + `app.get('/b', (req, res) => {\n  res.json(eval(req.query.script));\n});\n`;
  const win = head + `app.get('/c', (req, res) => {\n  res.json(globalThis.eval(req.query.script));\n});\n`;
  assert.deepEqual(await hits({ 'a.ts': method }, 'CWE-95'), []);
  assert.deepEqual(await hits({ 'a.ts': bare }, 'CWE-95'), ['a.ts:6']);
  assert.deepEqual(await hits({ 'a.ts': win }, 'CWE-95'), ['a.ts:6']);
});

test('raw(text, bindings) with a closed text binds its values; a text built from the value is reported', async () => {
  const head = `import express from 'express';\nimport knex from 'knex';\nconst app = express();\nconst db = knex({});\n`;
  const bound = head + `app.get('/a', async (req, res) => {\n  const q = db.raw('select * from t where id = ?', [req.query.id]);\n  res.json(await db.query(q));\n});\n`;
  const text = head + `app.get('/b', async (req, res) => {\n  const q = db.raw('select * from t where id = ' + req.query.id, []);\n  res.json(await db.query(q));\n});\n`;
  assert.deepEqual(await hits({ 'a.ts': bound }, 'CWE-89'), []);
  assert.deepEqual((await hits({ 'a.ts': text }, 'CWE-89')).sort(), ['a.ts:6', 'a.ts:7'], 'the raw call with the tainted text is itself the injection site, and the query that runs it is too');
});

test('Django format_html is recorded as an escaper on the path to mark_safe', async () => {
  const py = `from django.utils.html import format_html, mark_safe\n\ndef cell(request):\n    name = request.GET.get('name')\n    return mark_safe(format_html('<b>{}</b>', name))\n`;
  const f = (await deep({ 't.py': py })).filter((x) => x.cwe === 'CWE-79');
  assert.ok(f.length >= 1, 'the mark_safe site is still a finding for the gate to label');
  assert.ok(f.every((x) => (x._sanitizersOnPath || []).includes('format_html')), 'format_html is on the path');
});

test('browser modules: the directive, or a client library with a hook; a server import decides against', () => {
  assert.equal(isBrowserModule(`"use client";\nimport { useSearchParams } from "next/navigation";\nexport const useX = () => fetch(useSearchParams().get('u'));\n`), true);
  assert.equal(isBrowserModule(`import { useState } from 'react';\nexport function C() { const [u] = useState(''); return fetch(u); }\n`), true);
  assert.equal(isBrowserModule(`import React from 'react';\nexport default async function Page({ params }) { return fetch(params.u); }\n`), false, 'a server component imports react too');
  assert.equal(isBrowserModule(`"use client";\nimport fs from 'node:fs';\n`), false, 'a Node built-in is a server');
  assert.equal(isBrowserModule(`import express from 'express';\n`), false);
  const fc = { 'c.tsx': `"use client";\nimport { useState } from 'react';\n`, 's.ts': `import express from 'express';\n`, 'h.ts': `export const get = (p) => fetch(p);\n` };
  const findings = [
    { id: '1', file: 'c.tsx', cwe: 'CWE-918' }, { id: '2', file: 'c.tsx', cwe: 'CWE-79' }, { id: '3', file: 's.ts', cwe: 'CWE-918' },
    { id: '4', file: 'c.tsx -> h.ts', cwe: 'CWE-918' }, { id: '5', file: 's.ts -> h.ts', cwe: 'CWE-918' },
  ];
  const dropped = [];
  const kept = dropBrowserModuleServerFindings(findings, fc, (f) => dropped.push(f.id));
  assert.deepEqual(kept.map((f) => f.id), ['2', '3', '5']);
  assert.deepEqual(dropped, ['1', '4']);
});

test('text-layer dominance: a guard head that spans several lines still encloses the sink in its block', () => {
  const lines = `def done(request):\n    nxt = request.GET.get('next')\n    if nxt and url_has_allowed_host_and_scheme(\n        nxt,\n        allowed_hosts={request.get_host()},\n    ):\n        return redirect(nxt)\n    return redirect('/')\n`.split('\n');
  assert.equal(guardDominatesSink({ lines, guardIdx: 2, sinkIdx: 6, file: 'v.py' }).reason, 'sink-inside-guarded-branch');
  const after = `def done(request):\n    nxt = request.GET.get('next')\n    if nxt and url_has_allowed_host_and_scheme(\n        nxt,\n        allowed_hosts={request.get_host()},\n    ):\n        log(nxt)\n    return redirect(nxt)\n`.split('\n');
  assert.equal(guardDominatesSink({ lines: after, guardIdx: 2, sinkIdx: 7, file: 'v.py' }).dominates, false, 'a body that does not exit protects nothing after the block');
});
