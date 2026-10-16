// E4-06: authorization and business-logic cases for the deterministic context analysis, across two web stacks (Express, Flask).
//
// LABELS ARE WRITTEN FROM THE CODE'S MEANING, BEFORE ANY RUN. Each route is `vulnerable` (the control is missing or applied after the operation) or `safe`.
// WHO LABELLED: the author of this file, not an independent reviewer, and none of the cases is taken from an upstream advisory. The cases are written in the
// shape of common application code (a notes API, an invoice API, an admin API), but they are SYNTHETIC. This corpus therefore does NOT satisfy the PRD's
// "independent reviewer or upstream advisory" labelling requirement, and its numbers must not be quoted as accuracy on real applications. See DCI_REAL_APP.md.
//
// `nonObvious: true` marks a safe route that LOOKS unprotected (the control is applied somewhere a simple scan does not look) or a vulnerable route that looks
// protected (a control for a different resource). Every case has a vulnerable/fixed pair or a safe counterexample so precision is measured, not assumed.
const JS_HEAD = "const express = require('express');\nconst app = express();\nfunction requireUser(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }\nfunction requireRole(role) { return (req, res, next) => { if (!req.user || req.user.role !== role) return res.sendStatus(403); next(); }; }\n";
const PY_HEAD = "from flask import Flask, request, jsonify, abort\nfrom flask_login import login_required, current_user\nfrom functools import wraps\napp = Flask(__name__)\ndef roles_required(role):\n    def deco(f):\n        @wraps(f)\n        def w(*a, **k):\n            if current_user.role != role:\n                abort(403)\n            return f(*a, **k)\n        return w\n    return deco\n";

export const POLICIES = {
  authentication: (g) => ({ id: 'AUTH-1', title: 'Requires a signed-in user', rule: 'requires', appliesTo: { routes: [g] }, requires: ['authentication'], severity: 'high' }),
  role: (g) => ({ id: 'ROLE-1', title: 'Requires the admin role', rule: 'requires', appliesTo: { routes: [g] }, requires: ['authorization-role'], severity: 'high' }),
  ownership: (g) => ({ id: 'OWN-1', title: 'Owner scoped', rule: 'requires', appliesTo: { routes: [g] }, requires: ['ownership'], severity: 'high' }),
  tenant: (g) => ({ id: 'TEN-1', title: 'Tenant scoped', rule: 'requires', appliesTo: { routes: [g] }, requires: ['tenant-scope'], severity: 'high' }),
};

export const CASES = [
  // ---- missing middleware (authentication)
  { id: 'js-mw-1', stack: 'express', family: 'missing-middleware', control: 'authentication', glob: '/account/**', ext: 'js',
    files: { 'app.js': JS_HEAD + "app.get('/account/:id', requireUser, async (req, res) => { res.json(await db.accounts.findOne({ id: req.params.id })); });\napp.delete('/account/:id', async (req, res) => { await db.accounts.deleteOne({ id: req.params.id }); res.sendStatus(204); });\n" },
    routes: { 'GET /account/:id': 'safe', 'DELETE /account/:id': 'vulnerable' }, why: 'the delete route has no authentication middleware' },
  { id: 'js-mw-2', stack: 'express', family: 'missing-middleware', control: 'authentication', glob: '/account/**', ext: 'js',
    files: { 'app.js': JS_HEAD + "app.get('/account/:id', requireUser, async (req, res) => { res.json(await db.accounts.findOne({ id: req.params.id })); });\napp.delete('/account/:id', requireUser, async (req, res) => { await db.accounts.deleteOne({ id: req.params.id }); res.sendStatus(204); });\n" },
    routes: { 'GET /account/:id': 'safe', 'DELETE /account/:id': 'safe' }, why: 'fixed twin of js-mw-1' },
  { id: 'js-mw-3', stack: 'express', family: 'missing-middleware', control: 'authentication', glob: '/account/**', ext: 'js', nonObvious: true,
    files: { 'app.js': JS_HEAD + "app.use('/account', requireUser);\napp.get('/account/:id', async (req, res) => { res.json(await db.accounts.findOne({ id: req.params.id })); });\napp.delete('/account/:id', async (req, res) => { await db.accounts.deleteOne({ id: req.params.id }); res.sendStatus(204); });\n" },
    routes: { 'GET /account/:id': 'safe', 'DELETE /account/:id': 'safe' }, why: 'authentication is applied once for the whole prefix before the routes, so the routes carry no per-route middleware but are protected' },
  { id: 'js-mw-4', stack: 'express', family: 'missing-middleware', control: 'authentication', glob: '/account/**', ext: 'js', nonObvious: true,
    files: { 'app.js': JS_HEAD + "app.get('/account/:id', async (req, res) => { res.json(await db.accounts.findOne({ id: req.params.id })); });\napp.use('/account', requireUser);\n" },
    routes: { 'GET /account/:id': 'vulnerable' }, why: 'the authentication middleware is registered AFTER the route, so it never runs for it' },
  { id: 'js-mw-5', stack: 'express', family: 'missing-middleware', control: 'authentication', glob: '/api/**', ext: 'js', nonObvious: true,
    files: { 'app.js': JS_HEAD + "const router = express.Router();\nrouter.use(requireUser);\nrouter.get('/orders/:id', async (req, res) => { res.json(await db.orders.findOne({ id: req.params.id })); });\napp.use('/api', router);\napp.get('/api/health', (req, res) => res.json({ ok: true }));\n" },
    routes: { 'GET /api/orders/:id': 'safe', 'GET /api/health': 'safe' }, why: 'router-level authentication; the health route is public by design and carries no data' },

  // ---- ownership (direct)
  { id: 'js-own-1', stack: 'express', family: 'ownership', control: 'ownership', glob: '/notes/**', ext: 'js',
    files: { 'app.js': JS_HEAD + "app.get('/notes/:id', requireUser, async (req, res) => { const n = await db.notes.findOne({ id: req.params.id, ownerId: req.user.id }); if (!n) return res.sendStatus(404); res.json(n); });\napp.put('/notes/:id', requireUser, async (req, res) => { await db.notes.updateOne({ id: req.params.id }, { $set: req.body }); res.sendStatus(204); });\napp.delete('/notes/:id', requireUser, async (req, res) => { await db.notes.deleteOne({ id: req.params.id }); res.sendStatus(204); });\n" },
    routes: { 'GET /notes/:id': 'safe', 'PUT /notes/:id': 'vulnerable', 'DELETE /notes/:id': 'vulnerable' }, why: 'read is scoped to the owner, update and delete are not' },
  { id: 'js-own-2', stack: 'express', family: 'ownership', control: 'ownership', glob: '/notes/**', ext: 'js',
    files: { 'app.js': JS_HEAD + "app.get('/notes/:id', requireUser, async (req, res) => { const n = await db.notes.findOne({ id: req.params.id, ownerId: req.user.id }); if (!n) return res.sendStatus(404); res.json(n); });\napp.put('/notes/:id', requireUser, async (req, res) => { await db.notes.updateOne({ id: req.params.id, ownerId: req.user.id }, { $set: req.body }); res.sendStatus(204); });\napp.delete('/notes/:id', requireUser, async (req, res) => { await db.notes.deleteOne({ id: req.params.id, ownerId: req.user.id }); res.sendStatus(204); });\n" },
    routes: { 'GET /notes/:id': 'safe', 'PUT /notes/:id': 'safe', 'DELETE /notes/:id': 'safe' }, why: 'fixed twin of js-own-1' },
  { id: 'js-own-3', stack: 'express', family: 'ownership', control: 'ownership', glob: '/notes/**', ext: 'js', nonObvious: true,
    files: { 'app.js': JS_HEAD + "app.put('/notes/:id', requireUser, async (req, res) => {\n  const n = await db.notes.findOne({ id: req.params.id });\n  if (!n) return res.sendStatus(404);\n  if (n.ownerId !== req.user.id) return res.sendStatus(403);\n  await db.notes.updateOne({ id: n.id }, { $set: req.body });\n  res.sendStatus(204);\n});\n" },
    routes: { 'PUT /notes/:id': 'safe' }, why: 'the record is loaded unscoped, then the owner is checked and the request refused BEFORE the write: a check in code, not in the query' },
  { id: 'js-own-4', stack: 'express', family: 'ownership', control: 'ownership', glob: '/notes/**', ext: 'js', nonObvious: true,
    files: { 'app.js': JS_HEAD + "app.put('/notes/:id', requireUser, async (req, res) => {\n  const n = await db.notes.findOne({ id: req.params.id });\n  if (!n) return res.sendStatus(404);\n  await db.notes.updateOne({ id: n.id }, { $set: req.body });\n  if (n.ownerId !== req.user.id) return res.sendStatus(403);\n  res.sendStatus(204);\n});\n" },
    routes: { 'PUT /notes/:id': 'vulnerable' }, why: 'the owner check runs AFTER the write; the update has already happened when the 403 is sent' },
  { id: 'js-own-5', stack: 'express', family: 'ownership', control: 'ownership', glob: '/notes/**', ext: 'js', nonObvious: true,
    files: { 'app.js': JS_HEAD + "app.get('/notes/:id', requireUser, async (req, res) => { const n = await db.notes.findOne({ id: req.params.id, ownerId: req.user.id }); res.json(n); });\napp.get('/notes/:id/comments', requireUser, async (req, res) => { res.json(await db.comments.find({ noteId: req.params.id })); });\n" },
    routes: { 'GET /notes/:id': 'safe', 'GET /notes/:id/comments': 'vulnerable' }, why: 'the note is owner scoped but its comments are fetched by note id alone: a control for a different resource' },

  // ---- indirect ownership (through a parent record)
  { id: 'js-ind-1', stack: 'express', family: 'indirect-ownership', control: 'ownership', glob: '/tasks/**', ext: 'js', nonObvious: true,
    files: { 'app.js': JS_HEAD + "app.delete('/tasks/:id', requireUser, async (req, res) => {\n  const t = await db.tasks.findOne({ id: req.params.id });\n  const p = await db.projects.findOne({ id: t.projectId });\n  if (p.ownerId !== req.user.id) return res.sendStatus(403);\n  await db.tasks.deleteOne({ id: t.id });\n  res.sendStatus(204);\n});\n" },
    routes: { 'DELETE /tasks/:id': 'safe' }, why: 'ownership is established through the parent project before the delete' },
  { id: 'js-ind-2', stack: 'express', family: 'indirect-ownership', control: 'ownership', glob: '/tasks/**', ext: 'js', nonObvious: true,
    files: { 'app.js': JS_HEAD + "app.delete('/tasks/:id', requireUser, async (req, res) => {\n  const t = await db.tasks.findOne({ id: req.params.id });\n  await db.tasks.deleteOne({ id: t.id });\n  res.sendStatus(204);\n});\n" },
    routes: { 'DELETE /tasks/:id': 'vulnerable' }, why: 'vulnerable twin of js-ind-1: any signed-in user can delete any task' },

  // ---- multi-tenant joins
  { id: 'js-ten-1', stack: 'express', family: 'multi-tenant', control: 'tenant-scope', glob: '/invoices/**', ext: 'js',
    files: { 'app.js': JS_HEAD + "app.get('/invoices/:id', requireUser, async (req, res) => { res.json(await db.invoices.findOne({ id: req.params.id, tenantId: req.user.tenantId })); });\napp.get('/invoices/:id/lines', requireUser, async (req, res) => { res.json(await db.lines.find({ invoiceId: req.params.id })); });\n" },
    routes: { 'GET /invoices/:id': 'safe', 'GET /invoices/:id/lines': 'vulnerable' }, why: 'the invoice is tenant scoped, its lines are fetched without the tenant' },
  { id: 'js-ten-2', stack: 'express', family: 'multi-tenant', control: 'tenant-scope', glob: '/invoices/**', ext: 'js',
    files: { 'app.js': JS_HEAD + "app.get('/invoices/:id', requireUser, async (req, res) => { res.json(await db.invoices.findOne({ id: req.params.id, tenantId: req.user.tenantId })); });\napp.get('/invoices/:id/lines', requireUser, async (req, res) => { res.json(await db.lines.find({ invoiceId: req.params.id, tenantId: req.user.tenantId })); });\n" },
    routes: { 'GET /invoices/:id': 'safe', 'GET /invoices/:id/lines': 'safe' }, why: 'fixed twin of js-ten-1' },

  // ---- role / function-level authorization
  { id: 'js-role-1', stack: 'express', family: 'function-level-authorization', control: 'authorization-role', glob: '/admin/**', ext: 'js',
    files: { 'app.js': JS_HEAD + "app.get('/admin/users', requireUser, requireRole('admin'), async (req, res) => { res.json(await db.users.find({})); });\napp.delete('/admin/users/:id', requireUser, async (req, res) => { await db.users.deleteOne({ id: req.params.id }); res.sendStatus(204); });\n" },
    routes: { 'GET /admin/users': 'safe', 'DELETE /admin/users/:id': 'vulnerable' }, why: 'signed in is not enough to delete users: the role check is missing on one admin route' },
  { id: 'js-role-2', stack: 'express', family: 'function-level-authorization', control: 'authorization-role', glob: '/admin/**', ext: 'js',
    files: { 'app.js': JS_HEAD + "app.get('/admin/users', requireUser, requireRole('admin'), async (req, res) => { res.json(await db.users.find({})); });\napp.delete('/admin/users/:id', requireUser, requireRole('admin'), async (req, res) => { await db.users.deleteOne({ id: req.params.id }); res.sendStatus(204); });\n" },
    routes: { 'GET /admin/users': 'safe', 'DELETE /admin/users/:id': 'safe' }, why: 'fixed twin of js-role-1' },

  // ---- Flask
  { id: 'py-mw-1', stack: 'flask', family: 'missing-middleware', control: 'authentication', glob: '/account/**', ext: 'py',
    files: { 'app.py': PY_HEAD + "@app.route('/account/<int:id>')\n@login_required\ndef get_account(id):\n    return jsonify(Account.query.get(id).to_dict())\n\n@app.route('/account/<int:id>', methods=['DELETE'])\ndef delete_account(id):\n    Account.query.filter_by(id=id).delete()\n    return '', 204\n" },
    routes: { 'GET /account/<int:id>': 'safe', 'DELETE /account/<int:id>': 'vulnerable' }, why: 'the delete view has no login_required' },
  { id: 'py-mw-2', stack: 'flask', family: 'missing-middleware', control: 'authentication', glob: '/account/**', ext: 'py',
    files: { 'app.py': PY_HEAD + "@app.route('/account/<int:id>')\n@login_required\ndef get_account(id):\n    return jsonify(Account.query.get(id).to_dict())\n\n@app.route('/account/<int:id>', methods=['DELETE'])\n@login_required\ndef delete_account(id):\n    Account.query.filter_by(id=id).delete()\n    return '', 204\n" },
    routes: { 'GET /account/<int:id>': 'safe', 'DELETE /account/<int:id>': 'safe' }, why: 'fixed twin of py-mw-1' },
  { id: 'py-role-1', stack: 'flask', family: 'function-level-authorization', control: 'authorization-role', glob: '/admin/**', ext: 'py',
    files: { 'app.py': PY_HEAD + "@app.route('/admin/users')\n@login_required\n@roles_required('admin')\ndef list_users():\n    return jsonify([u.to_dict() for u in User.query.all()])\n\n@app.route('/admin/users/<int:id>', methods=['DELETE'])\n@login_required\ndef delete_user(id):\n    User.query.filter_by(id=id).delete()\n    return '', 204\n" },
    routes: { 'GET /admin/users': 'safe', 'DELETE /admin/users/<int:id>': 'vulnerable' }, why: 'delete lacks the role check' },
  { id: 'py-own-1', stack: 'flask', family: 'ownership', control: 'ownership', glob: '/notes/**', ext: 'py',
    files: { 'app.py': PY_HEAD + "@app.route('/notes/<int:id>')\n@login_required\ndef get_note(id):\n    return jsonify(Note.query.filter_by(id=id, owner_id=current_user.id).first_or_404().to_dict())\n\n@app.route('/notes/<int:id>', methods=['PUT'])\n@login_required\ndef put_note(id):\n    n = Note.query.get(id)\n    n.body = request.json['body']\n    return '', 204\n" },
    routes: { 'GET /notes/<int:id>': 'safe', 'PUT /notes/<int:id>': 'vulnerable' }, why: 'read is owner scoped, update loads by id alone' },
  { id: 'py-own-2', stack: 'flask', family: 'ownership', control: 'ownership', glob: '/notes/**', ext: 'py',
    files: { 'app.py': PY_HEAD + "@app.route('/notes/<int:id>')\n@login_required\ndef get_note(id):\n    return jsonify(Note.query.filter_by(id=id, owner_id=current_user.id).first_or_404().to_dict())\n\n@app.route('/notes/<int:id>', methods=['PUT'])\n@login_required\ndef put_note(id):\n    n = Note.query.filter_by(id=id, owner_id=current_user.id).first_or_404()\n    n.body = request.json['body']\n    return '', 204\n" },
    routes: { 'GET /notes/<int:id>': 'safe', 'PUT /notes/<int:id>': 'safe' }, why: 'fixed twin of py-own-1' },
];

// Families the PRD names that this analysis cannot represent deterministically. They are listed so the limit is visible, and are not scored.
export const NOT_REPRESENTABLE = [
  { family: 'state-machine-bypass', reason: 'the context analysis has no extractor for workflow order or state transitions (the E4-01 audit marks workflow-state-check absent); a case could only be answered by a model-assisted pack, which has no measured accuracy' },
  { family: 'race-toctou', reason: 'a check-then-act race is a property of interleavings, not of one handler\'s text; no deterministic fact or invariant expresses it' },
];
