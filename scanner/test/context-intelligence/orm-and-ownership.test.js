// Two corrections to the deterministic context analysis, each pinned in both directions.
//
// 1. A Flask route's data operation goes through the ORM (`Model.query.filter_by(...).delete()`, `db.session.add(x)`), which names no
//    database receiver the call-name rule knew, so a route that deletes a row read as touching nothing sensitive and could not be judged.
// 2. For ownership, the order that matters is the check before the first WRITE. Loading the record by id, refusing unless the principal
//    owns it and only then writing is the ordinary safe shape; it used to be reported as missing ownership because the load came first.
//    The excuse is narrow: a write before the check, or a read returned with no check anywhere, is still reported.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreCase } from '../../../bench/dci-real-app/runner.mjs';

const PY_HEAD = 'from flask import Flask, request, jsonify, abort\nfrom flask_login import login_required, current_user\nfrom functools import wraps\napp = Flask(__name__)\n\n';
const JS_HEAD = "const express = require('express');\nconst app = express();\nfunction requireUser(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }\n";
const outcome = async (c) => (await scoreCase({ id: 't', stack: 'express', family: 'x', glob: '/**', ext: 'js', ...c })).rows.map((r) => r.outcome);

test('ORM: a Flask delete with no login is a true positive and the same delete behind login_required is a true negative', async () => {
  const route = (guard) => PY_HEAD + `@app.route('/account/<int:id>', methods=['DELETE'])\n${guard}def delete_account(id):\n    Account.query.filter_by(id=id).delete()\n    return '', 204\n`;
  const base = { stack: 'flask', ext: 'py', control: 'authentication', glob: '/account/**', routes: { 'DELETE /account/<int:id>': 'vulnerable' } };
  assert.deepEqual(await outcome({ ...base, files: { 'app.py': route('') } }), ['tp']);
  assert.deepEqual(await outcome({ ...base, routes: { 'DELETE /account/<int:id>': 'safe' }, files: { 'app.py': route('@login_required\n') } }), ['tn']);
});

test('ORM: a session write is a write, and a handler that touches no data is still not applicable', async () => {
  const base = { stack: 'flask', ext: 'py', control: 'authentication', glob: '/x/**' };
  const writes = PY_HEAD + "@app.route('/x/<int:id>', methods=['POST'])\ndef add(id):\n    db.session.add(Item(id=id))\n    db.session.commit()\n    return '', 201\n";
  assert.deepEqual(await outcome({ ...base, files: { 'app.py': writes }, routes: { 'POST /x/<int:id>': 'vulnerable' } }), ['tp']);
  const none = PY_HEAD + "@app.route('/x/ping')\ndef ping():\n    return 'pong'\n";
  assert.deepEqual(await outcome({ ...base, files: { 'app.py': none }, routes: { 'GET /x/ping': 'safe' } }), ['unresolved'], 'nothing to protect is not a pass');
});

test('ORM ownership: a query scoped to the principal is satisfied and the same query unscoped is violated', async () => {
  const route = (scope) => PY_HEAD + `@app.route('/notes/<int:id>', methods=['PUT'])\n@login_required\ndef edit(id):\n    n = Note.query.filter_by(id=id${scope}).first_or_404()\n    n.body = request.json['body']\n    return jsonify(n.to_dict())\n`;
  const base = { stack: 'flask', ext: 'py', control: 'ownership', glob: '/notes/**' };
  assert.deepEqual(await outcome({ ...base, files: { 'app.py': route(', owner_id=current_user.id') }, routes: { 'PUT /notes/<int:id>': 'safe' } }), ['tn']);
  assert.deepEqual(await outcome({ ...base, files: { 'app.py': route('') }, routes: { 'PUT /notes/<int:id>': 'vulnerable' } }), ['tp']);
});

const own = (body, label) => ({ control: 'ownership', glob: '/notes/**', files: { 'app.js': JS_HEAD + `app.put('/notes/:id', requireUser, async (req, res) => {\n${body}\n});\n` }, routes: { 'PUT /notes/:id': label } });

test('ownership order: load, check, then write is satisfied', async () => {
  assert.deepEqual(await outcome(own("  const n = await db.notes.findOne({ id: req.params.id });\n  if (n.ownerId !== req.user.id) return res.sendStatus(403);\n  await db.notes.updateOne({ id: n.id }, { $set: req.body });\n  res.sendStatus(204);", 'safe')), ['tn']);
});

test('ownership order: a write before the check is still violated', async () => {
  assert.deepEqual(await outcome(own("  const n = await db.notes.findOne({ id: req.params.id });\n  await db.notes.updateOne({ id: n.id }, { $set: req.body });\n  if (n.ownerId !== req.user.id) return res.sendStatus(403);\n  res.sendStatus(204);", 'vulnerable')), ['tp']);
});

test('ownership order: a write with no check anywhere is still violated, and so is a read returned with none', async () => {
  assert.deepEqual(await outcome(own("  await db.notes.updateOne({ id: req.params.id }, { $set: req.body });\n  res.sendStatus(204);", 'vulnerable')), ['tp']);
  const read = { control: 'ownership', glob: '/notes/**', files: { 'app.js': JS_HEAD + "app.get('/notes/:id', requireUser, async (req, res) => {\n  res.json(await db.notes.findOne({ id: req.params.id }));\n});\n" }, routes: { 'GET /notes/:id': 'vulnerable' } };
  assert.deepEqual(await outcome(read), ['tp']);
});
