#!/usr/bin/env node
// Measured maturity audit of Deterministic Context Intelligence (E4-01).
//   node scripts/engineering-excellence/dci-audit.mjs            write data/dci-maturity.json and docs/engineering-excellence/DCI_MATURITY.md
//   node scripts/engineering-excellence/dci-audit.mjs --check    fail when the committed audit no longer matches a fresh measurement
//
// For each language a small project with the SAME security shape is built (an unguarded route, an authenticated route, a role-guarded route, an
// owner-scoped route and a tenant-scoped route) and run through the real `buildContext`. A cell says whether DCI saw the entry point and the
// control that the route was written to carry. The workflow, state-transition and transaction-integrity dimensions are asked in the same way
// with a probe each; where no deterministic extractor exists the cell is `absent`, and the question packs for them are reported separately as
// model-assisted, which is a different thing.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildContext } from '../../scanner/src/context-intelligence/build.js';
import { normalizeConfig } from '../../scanner/src/context-intelligence/config.js';
import { capabilityMatrix } from '../../scanner/src/context-intelligence/capabilities.js';
import { disableStateWrites } from '../../bench/_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../..');
const DATA = path.join(HERE, 'data/dci-maturity.json');
const DOC = path.join(REPO, 'docs/engineering-excellence/DCI_MATURITY.md');

// route label substring -> the control kind the route was written to carry
export const DIMENSIONS = ['entry-point', 'sensitive-operation', 'authentication', 'authorization-role', 'ownership', 'tenant-scope'];

export const FIXTURES = {
  javascript: { file: 'app.js', routes: { '/open': null, '/auth': 'authentication', '/role': 'authorization-role', '/own': 'ownership', '/tenant': 'tenant-scope' }, src: `const express = require('express');
const app = express();
function requireUser(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }
function requireRole(r) { return (req, res, next) => { if (req.user.role !== r) return res.sendStatus(403); next(); }; }
app.get('/open/:id', async (req, res) => { res.json(await db.docs.findOne({ id: req.params.id })); });
app.get('/auth/:id', requireUser, async (req, res) => { res.json(await db.docs.findOne({ id: req.params.id })); });
app.get('/role/:id', requireRole('admin'), async (req, res) => { res.json(await db.docs.findOne({ id: req.params.id })); });
app.get('/own/:id', requireUser, async (req, res) => { res.json(await db.docs.findOne({ id: req.params.id, ownerId: req.user.id })); });
app.get('/tenant/:id', requireUser, async (req, res) => { res.json(await db.docs.findOne({ id: req.params.id, tenantId: req.user.tenantId })); });
` },
  typescript: { file: 'app.ts', routes: { '/open': null, '/auth': 'authentication', '/role': 'authorization-role', '/own': 'ownership', '/tenant': 'tenant-scope' }, src: `import express, { Request, Response, NextFunction } from 'express';
const app = express();
function requireUser(req: any, res: Response, next: NextFunction) { if (!req.user) return res.sendStatus(401); next(); }
function requireRole(r: string) { return (req: any, res: Response, next: NextFunction) => { if (req.user.role !== r) return res.sendStatus(403); next(); }; }
app.get('/open/:id', async (req: Request, res: Response) => { res.json(await db.docs.findOne({ id: req.params.id })); });
app.get('/auth/:id', requireUser, async (req: any, res: Response) => { res.json(await db.docs.findOne({ id: req.params.id })); });
app.get('/role/:id', requireRole('admin'), async (req: any, res: Response) => { res.json(await db.docs.findOne({ id: req.params.id })); });
app.get('/own/:id', requireUser, async (req: any, res: Response) => { res.json(await db.docs.findOne({ id: req.params.id, ownerId: req.user.id })); });
app.get('/tenant/:id', requireUser, async (req: any, res: Response) => { res.json(await db.docs.findOne({ id: req.params.id, tenantId: req.user.tenantId })); });
` },
  'python-flask': { file: 'app.py', routes: { '/open': null, '/auth': 'authentication', '/role': 'authorization-role', '/own': 'ownership', '/tenant': 'tenant-scope' }, src: `from flask import Flask
app = Flask(__name__)
@app.route('/open/<id>')
def open_doc(id):
    return db.docs.find_one({'id': id})
@app.route('/auth/<id>')
@login_required
def auth_doc(id):
    return db.docs.find_one({'id': id})
@app.route('/role/<id>')
@roles_required('admin')
def role_doc(id):
    return db.docs.find_one({'id': id})
@app.route('/own/<id>')
@login_required
def own_doc(id):
    return db.docs.find_one({'id': id, 'owner_id': current_user.id})
@app.route('/tenant/<id>')
@login_required
def tenant_doc(id):
    return db.docs.find_one({'id': id, 'tenant_id': current_user.tenant_id})
` },
  'python-fastapi': { file: 'main.py', routes: { '/open': null, '/auth': 'authentication', '/role': 'authorization-role', '/own': 'ownership', '/tenant': 'tenant-scope' }, src: `from fastapi import FastAPI, Depends
app = FastAPI()
@app.get('/open/{id}')
async def open_doc(id: str):
    return await db.docs.find_one({'id': id})
@app.get('/auth/{id}')
async def auth_doc(id: str, user=Depends(get_current_user)):
    return await db.docs.find_one({'id': id})
@app.get('/role/{id}')
async def role_doc(id: str, user=Depends(require_admin)):
    return await db.docs.find_one({'id': id})
@app.get('/own/{id}')
async def own_doc(id: str, user=Depends(get_current_user)):
    return await db.docs.find_one({'id': id, 'owner_id': user.id})
@app.get('/tenant/{id}')
async def tenant_doc(id: str, user=Depends(get_current_user)):
    return await db.docs.find_one({'id': id, 'tenant_id': user.tenant_id})
` },
  'java-spring': { file: 'DocController.java', routes: { '/open': null, '/auth': 'authentication', '/role': 'authorization-role', '/own': 'ownership', '/tenant': 'tenant-scope' }, src: `@RestController
class DocController {
  @GetMapping("/open/{id}")
  Doc open(@PathVariable String id) { return repo.findById(id); }
  @GetMapping("/auth/{id}")
  @Authenticated
  Doc auth(@PathVariable String id) { return repo.findById(id); }
  @GetMapping("/role/{id}")
  @PreAuthorize("hasRole('ADMIN')")
  Doc role(@PathVariable String id) { return repo.findById(id); }
  @GetMapping("/own/{id}")
  Doc own(@PathVariable String id, Principal p) { return repo.findByIdAndOwnerId(id, p.getName()); }
  @GetMapping("/tenant/{id}")
  Doc tenant(@PathVariable String id, Principal p) { return repo.findByIdAndTenantId(id, tenantOf(p)); }
}
` },
  go: { file: 'main.go', routes: { '/open': null, '/auth': 'authentication', '/role': 'authorization-role', '/own': 'ownership', '/tenant': 'tenant-scope' }, src: `package main
func main() {
  http.HandleFunc("/open", func(w http.ResponseWriter, r *http.Request) { db.QueryRow("SELECT * FROM docs WHERE id = $1", r.URL.Query().Get("id")) })
  http.HandleFunc("/auth", requireUser(func(w http.ResponseWriter, r *http.Request) { db.QueryRow("SELECT * FROM docs WHERE id = $1", r.URL.Query().Get("id")) }))
  http.HandleFunc("/role", requireRole("admin", func(w http.ResponseWriter, r *http.Request) { db.QueryRow("SELECT * FROM docs WHERE id = $1", r.URL.Query().Get("id")) }))
  http.HandleFunc("/own", requireUser(func(w http.ResponseWriter, r *http.Request) { db.QueryRow("SELECT * FROM docs WHERE id = $1 AND owner_id = $2", r.URL.Query().Get("id"), userID(r)) }))
  http.HandleFunc("/tenant", requireUser(func(w http.ResponseWriter, r *http.Request) { db.QueryRow("SELECT * FROM docs WHERE id = $1 AND tenant_id = $2", r.URL.Query().Get("id"), tenantID(r)) }))
}
` },
  'csharp-aspnet': { file: 'DocController.cs', routes: { '/open': null, '/auth': 'authentication', '/role': 'authorization-role', '/own': 'ownership', '/tenant': 'tenant-scope' }, src: `public class DocController : Controller {
  [HttpGet("open/{id}")] public Doc Open(string id) => db.Docs.Find(id);
  [Authorize] [HttpGet("auth/{id}")] public Doc Auth(string id) => db.Docs.Find(id);
  [Authorize(Roles = "Admin")] [HttpGet("role/{id}")] public Doc Role(string id) => db.Docs.Find(id);
  [Authorize] [HttpGet("own/{id}")] public Doc Own(string id) => db.Docs.FirstOrDefault(d => d.Id == id && d.OwnerId == User.Identity.Name);
  [Authorize] [HttpGet("tenant/{id}")] public Doc Tenant(string id) => db.Docs.FirstOrDefault(d => d.Id == id && d.TenantId == CurrentTenant());
}
` },
  'ruby-rails': { file: 'docs_controller.rb', routes: { '/open': null, '/auth': 'authentication', '/role': 'authorization-role', '/own': 'ownership', '/tenant': 'tenant-scope' }, src: `class DocsController < ApplicationController
  def open; render json: Doc.find(params[:id]); end
  before_action :authenticate_user!, only: [:auth, :role, :own, :tenant]
  def auth; render json: Doc.find(params[:id]); end
  def role; authorize! :manage, Doc; render json: Doc.find(params[:id]); end
  def own; render json: current_user.docs.find(params[:id]); end
  def tenant; render json: Doc.where(tenant_id: current_user.tenant_id).find(params[:id]); end
end
` },
  'php-laravel': { file: 'routes/web.php', routes: { '/open': null, '/auth': 'authentication', '/role': 'authorization-role', '/own': 'ownership', '/tenant': 'tenant-scope' }, src: `<?php
Route::get('/open/{id}', function ($id) { return Doc::find($id); });
Route::get('/auth/{id}', function ($id) { return Doc::find($id); })->middleware('auth');
Route::get('/role/{id}', function ($id) { return Doc::find($id); })->middleware('role:admin');
Route::get('/own/{id}', function ($id) { return Doc::where('id', $id)->where('owner_id', auth()->id())->first(); })->middleware('auth');
Route::get('/tenant/{id}', function ($id) { return Doc::where('id', $id)->where('tenant_id', auth()->user()->tenant_id)->first(); })->middleware('auth');
` },
};

// dimensions with no deterministic extractor are asked with one probe each; a fact in the bundle would make the cell `detected`
export const ABSENT_PROBES = {
  'workflow-state-check': { file: 'app.js', src: "const app = require('express')();\napp.post('/ship', async (req, res) => {\n  const order = await db.orders.findOne({ id: req.body.id });\n  if (order.status !== 'paid') return res.sendStatus(409);\n  await db.orders.updateOne({ id: order.id }, { status: 'shipped' });\n  res.sendStatus(200);\n});\n", kinds: ['workflow', 'state-transition', 'state', 'status-check'] },
  'transaction-integrity': { file: 'app.js', src: "const app = require('express')();\napp.post('/pay', async (req, res) => {\n  await db.transaction(async (t) => {\n    await t.query('UPDATE accounts SET balance = balance - 5 WHERE id = $1', [1]);\n    await t.query('UPDATE accounts SET balance = balance + 5 WHERE id = $1', [2]);\n  });\n  res.sendStatus(200);\n});\n", kinds: ['transaction', 'transaction-integrity', 'atomicity'] },
};

async function build(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dci-audit-'));
  try {
    for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true }); fs.writeFileSync(path.join(root, f), t); }
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}');
    const r = await buildContext(root, { config: normalizeConfig({}).config });
    return r;
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

export async function measure() {
  await disableStateWrites();
  const out = { schema: 'agentic-security/dci-maturity', version: 1, dimensions: DIMENSIONS, languages: {}, absent: {}, questionPacks: [] };
  for (const [lang, fx] of Object.entries(FIXTURES)) {
    const r = await build({ [fx.file]: fx.src });
    const cells = Object.fromEntries(DIMENSIONS.map((d) => [d, 'not-detected']));
    const detail = {};
    if (r.ok) {
      const byRoute = {};
      for (const b of r.bundles) {
        const label = String(b.entrypoint.label || '');
        const key = Object.keys(fx.routes).find((k) => label.includes(k));
        if (!key) continue;
        const protection = Object.fromEntries(Object.entries(b.manifest?.protection || {}).map(([k, v]) => [k, v.state]));
        const kinds = new Set((b.reach?.facts || []).map((f) => f.category === 'sensitive' ? `sensitive:${f.kind}` : f.kind));
        // the protection verdict is the manifest's own conclusion about a dimension: a `present` state counts as the control being seen
        for (const [dim, st] of Object.entries(protection)) if (st === 'present') kinds.add(dim);
        byRoute[key] = { disposition: b.entrypoint.disposition, integrity: b.manifest?.context?.integrity ?? null, kinds: [...kinds].sort(), protection };
      }
      detail.routes = byRoute;
      if (Object.keys(byRoute).length) cells['entry-point'] = Object.keys(byRoute).length === Object.keys(fx.routes).length ? 'detected' : 'partial';
      if (Object.values(byRoute).some((x) => x.kinds.some((k) => k.startsWith('sensitive:')))) cells['sensitive-operation'] = 'detected';
      for (const [route, want] of Object.entries(fx.routes)) { if (!want) continue; cells[want] = byRoute[route]?.kinds.includes(want) ? 'detected' : 'not-detected'; }
      // a control reported on the open route is a false positive: record it
      const open = byRoute['/open'];
      detail.controlsOnUnguardedRoute = open ? open.kinds.filter((k) => !k.startsWith('sensitive:')) : [];
    } else detail.failure = r.reason;
    out.languages[lang] = { cells, detail };
  }
  for (const [name, p] of Object.entries(ABSENT_PROBES)) {
    const r = await build({ [p.file]: p.src });
    const kinds = r.ok ? [...new Set(r.bundles.flatMap((b) => (b.reach?.facts || []).map((f) => f.kind)))].sort() : [];
    const hit = kinds.filter((k) => p.kinds.includes(k));
    out.absent[name] = { state: hit.length ? 'detected' : 'absent', factKindsSeen: kinds, lookedFor: p.kinds };
  }
  out.questionPacks = capabilityMatrix().filter((c) => /^review:/.test(c.kind)).map((c) => ({ pack: c.kind.replace('review: ', ''), status: c.status, evidenceFiles: c.evidence }));
  out.buildCapabilities = capabilityMatrix().filter((c) => !/^review:/.test(c.kind)).map((c) => ({ language: c.language, kind: c.kind, status: c.status }));
  return out;
}

function render(m) {
  const L = [];
  L.push('# Deterministic Context Intelligence: maturity audit (E4-01)', '', 'Generated by `node scripts/engineering-excellence/dci-audit.mjs`. Every cell is measured by running the real `buildContext` over a small project with the same security shape in each language (an unguarded route, an authenticated route, a role-guarded route, an owner-scoped route, a tenant-scoped route). `detected` means DCI saw the entry point, or the control the route was written to carry. `not-detected` is not a statement about the framework; it is a statement about this extractor and this fixture.', '');
  L.push('## Per language', '', `| Language | ${m.dimensions.join(' | ')} |`, `|---|${m.dimensions.map(() => '---').join('|')}|`);
  for (const [lang, v] of Object.entries(m.languages)) L.push(`| ${lang} | ${m.dimensions.map((d) => v.cells[d]).join(' | ')} |`);
  const cells = Object.values(m.languages).flatMap((v) => Object.values(v.cells));
  L.push('', `${cells.filter((c) => c === 'detected').length} of ${cells.length} cells detected, ${cells.filter((c) => c === 'partial').length} partial, ${cells.filter((c) => c === 'not-detected').length} not detected.`, '');
  const fp = Object.entries(m.languages).filter(([, v]) => (v.detail.controlsOnUnguardedRoute || []).length);
  L.push(fp.length ? `Controls reported on the UNGUARDED route (false positives): ${fp.map(([l, v]) => `${l}: ${v.detail.controlsOnUnguardedRoute.join(', ')}`).join('; ')}.` : 'No control was reported on the unguarded route in any language.', '');
  L.push('## Dimensions with no deterministic extractor', '', '| Dimension | State | Fact kinds DCI produced for the probe |', '|---|---|---|');
  for (const [k, v] of Object.entries(m.absent)) L.push(`| ${k} | ${v.state} | ${v.factKindsSeen.join(', ') || 'none'} |`);
  L.push('', 'Workflow ordering, state transitions and transaction integrity exist only as model-assisted question packs (`transaction-integrity`, `business-invariant`, `cross-route-consistency` below). DCI packs the code and its security-relevant facts; it does not itself decide a workflow or atomicity property, and there is no deterministic check to fall back on when no model is configured.', '');
  L.push('## Model-assisted question packs', '', '| Pack | Status | Evidence |', '|---|---|---|');
  for (const q of m.questionPacks) L.push(`| ${q.pack} | ${q.status} | ${q.evidenceFiles.join(', ')} |`);
  L.push('', 'Status `experimental` means the mechanics are tested with a fake provider. No accuracy has been measured on real applications (E4-06).', '');
  L.push('## Build capability (from `capabilities.js`)', '', '| Language | Kind | Status |', '|---|---|---|');
  for (const c of m.buildCapabilities) L.push(`| ${c.language} | ${c.kind} | ${c.status} |`);
  L.push('', '## Limitations', '', '- One small fixture per language: absence here is not absence in a real framework variant.', '- `detected` for a control means the extractor reported that control kind on that route; it does not say the control is effective.', '- Confidence and limitation per claim are carried in each bundle manifest at run time; this audit is the static view of the same facts.', '');
  return L.join('\n');
}

async function main() {
  const m = await measure();
  if (process.argv.includes('--check')) {
    const stored = JSON.parse(fs.readFileSync(DATA, 'utf8'));
    const diff = [];
    for (const [l, v] of Object.entries(m.languages)) for (const d of DIMENSIONS) if (stored.languages?.[l]?.cells?.[d] !== v.cells[d]) diff.push(`${l}/${d}: ${stored.languages?.[l]?.cells?.[d]} -> ${v.cells[d]}`);
    for (const [k, v] of Object.entries(m.absent)) if (stored.absent?.[k]?.state !== v.state) diff.push(`${k}: ${stored.absent?.[k]?.state} -> ${v.state}`);
    if (diff.length) { console.error(`the DCI audit changed:\n${diff.join('\n')}`); process.exit(1); }
    if (fs.readFileSync(DOC, 'utf8') !== render(m)) { console.error('DCI_MATURITY.md is stale'); process.exit(1); }
    console.log('DCI audit matches'); return;
  }
  fs.writeFileSync(DATA, JSON.stringify(m, null, 2) + '\n');
  fs.writeFileSync(DOC, render(m));
  const cells = Object.values(m.languages).flatMap((v) => Object.values(v.cells));
  console.log(`wrote audit: ${cells.filter((c) => c === 'detected').length}/${cells.length} cells detected`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((e) => { console.error(e); process.exit(2); });
