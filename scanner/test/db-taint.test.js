// v0.70 #10 — database-aware (ORM round-trip) taint tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanDbTaint } from '../src/sast/db-taint.js';

test('Sequelize Model.create with user input + later read fires stored-XSS', () => {
  const out = scanDbTaint('app.js', `
const express = require('express');
const app = express();
app.post('/u', (req, res) => {
  User.create({ bio: req.body.bio });
});
app.get('/u/:id', async (req, res) => {
  const u = await User.findOne({ where: { id: req.params.id }});
  res.send('<p>' + u.bio + '</p>');
});
`);
  assert.ok(out.length >= 1, 'expected stored-XSS finding');
  assert.equal(out[0].cwe, 'CWE-79');
  assert.equal(out[0].family, 'stored-xss');
  assert.match(out[0].vuln, /User\.bio/);
});

test('Prisma create with req.body fires when field is later rendered', () => {
  const out = scanDbTaint('app.js', `
const express = require('express');
const app = express();
app.post('/u', async (req, res) => {
  await prisma.user.create({ data: { bio: req.body.bio } });
});
app.get('/u', async (req, res) => {
  const u = await prisma.user.findFirst({}).bio;
  res.send(u);
});
`);
  assert.ok(out.length >= 1, 'expected stored-XSS finding via Prisma');
});

test('Django ORM Model.objects.create + later render fires', () => {
  const out = scanDbTaint('app.py', `
from django.shortcuts import render
from django.http import HttpResponse
def submit(request):
    Article.objects.create(body=request.POST['body'])
def show(request, pk):
    a = Article.objects.get(pk=pk).body
    return HttpResponse(a)
`);
  assert.ok(out.length >= 1, 'expected stored-XSS finding via Django ORM');
});

test('write WITHOUT a user source does NOT fire', () => {
  const out = scanDbTaint('app.js', `
app.post('/u', async (req, res) => {
  User.create({ bio: 'a constant value' });
});
app.get('/u', async (req, res) => {
  const u = await User.findOne({});
  res.send(u.bio);
});
`);
  // Const body → not user-derived → no finding.
  assert.equal(out.length, 0, 'constant write must not fire stored-XSS');
});

test('write with user source but NO render sink does NOT fire', () => {
  const out = scanDbTaint('app.js', `
app.post('/u', async (req, res) => {
  User.create({ bio: req.body.bio });
  res.status(204).end();
});
`);
  // No read site → no chain → no finding.
  assert.equal(out.length, 0);
});

test('different field names: write to bio, read displayName, no finding', () => {
  const out = scanDbTaint('app.js', `
app.post('/u', async (req, res) => {
  User.create({ bio: req.body.bio });
});
app.get('/u', async (req, res) => {
  const u = await User.findOne({});
  res.send(u.displayName);
});
`);
  assert.equal(out.length, 0, 'field-name mismatch should not fire');
});

test('the finding includes a 2-step trace pointing at write + read lines', () => {
  const out = scanDbTaint('app.js', `
app.post('/u', async (req, res) => {
  User.create({ bio: req.body.bio });
});
app.get('/u', async (req, res) => {
  const u = await User.findOne({});
  res.send(u.bio);
});
`);
  assert.ok(out[0].trace);
  assert.equal(out[0].trace.length, 2);
  assert.equal(out[0].trace[0].kind, 'db-write');
  assert.equal(out[0].trace[1].kind, 'db-read');
});

test('files without ORM patterns return empty', () => {
  const out = scanDbTaint('app.js', `
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('hello'));
`);
  assert.equal(out.length, 0);
});
