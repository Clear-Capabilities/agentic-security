// A taint finding must say where its data came from. Sources the engine records are keyed by the variable a source call was assigned to, so a
// value DERIVED from one (`b = 'ls ' + a`), a value that crossed a call (`run(b)`) and a value returned from a function used to reach the sink
// with an empty evidence chain. These tests pin the origin for each shape, in a language other than Haskell (the engine change is language
// neutral), and pin that a clean value still has none.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { runScan } from '../src/runScan.js';
import { mkTestTmp } from './helpers/tmp.js';

async function scan(files) {
  const dir = mkTestTmp('src-attr-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true, deepInCi: true });
  return [...(r.scan.findings || [])].filter((f) => f.parser === 'IR-TAINT');
}
const byLine = (fs, line) => fs.filter((f) => f.line === line);
const lineOf = (text, needle) => text.split('\n').findIndex((l) => l.includes(needle)) + 1;

const APP = `const express = require('express');
const { exec } = require('child_process');
const app = express();

function run(cmd) {
  exec(cmd);
}

function build(extra) {
  return 'make ' + extra;
}

app.get('/direct', (req, res) => {
  const a = req.query.cmd;
  exec(a);
  res.send('ok');
});

app.get('/derived', (req, res) => {
  const a = req.query.cmd;
  const b = 'ls ' + a;
  exec(b);
  res.send('ok');
});

app.get('/hop', (req, res) => {
  const a = req.query.cmd;
  const b = 'ls ' + a;
  run(b);
  res.send('ok');
});

app.get('/returned', (req, res) => {
  const a = req.query.target;
  const full = build(a);
  exec(full);
  res.send('ok');
});

app.get('/clean', (req, res) => {
  const b = 'ls ' + 'static';
  exec(b);
  res.send('ok');
});

app.listen(3000);
`;

test('a finding names the request value it came from whether the sink sees it directly, after a derivation, after a call, or after a return', async () => {
  const fs = await scan({ 'app.js': APP });
  const direct = byLine(fs, lineOf(APP, 'exec(a);'));
  const derived = byLine(fs, lineOf(APP, 'exec(b);'));
  const hop = byLine(fs, lineOf(APP, 'exec(cmd);'));
  const returned = byLine(fs, lineOf(APP, 'exec(full);'));
  assert.equal(direct.length, 1);
  assert.equal(derived.length, 1, JSON.stringify(fs.map((f) => [f.line, f.source && f.source.label])));
  assert.equal(returned.length, 1);
  assert.ok(hop.length >= 1);
  for (const f of [...direct, ...derived, ...hop, ...returned]) {
    // the first hop is the request read itself, or the return of a function whose own origin is in `sourceRoots`
    const named = (f.source && /req\.query/.test(f.source.label)) || (f.sourceRoots || []).some((r) => /req\.query/.test(r.label));
    assert.ok(named, `line ${f.line}: ${JSON.stringify(f.source)} roots ${JSON.stringify(f.sourceRoots)}`);
    assert.ok(Array.isArray(f.chain) && f.chain.length >= 2, `line ${f.line} has an evidence chain`);
  }
  for (const f of [...direct, ...derived, ...hop]) assert.ok(/req\.query/.test(f.source.label), `line ${f.line}: the first hop is the request read`);
});

test('a clean derived value has no finding and so no invented origin', async () => {
  const fs = await scan({ 'app.js': APP });
  assert.equal(fs.filter((f) => f.line > lineOf(APP, "app.get('/clean'")).length, 0);
});
