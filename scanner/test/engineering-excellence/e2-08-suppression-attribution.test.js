// E2-08: the miss-forensics no longer blames a miss on an unrelated dropped candidate. On the baseline run, six misses were attributed to a filter or guard
// whose ledger entry recorded neither a family nor a CWE: a too-short secret candidate beside an authorization bug, a header write beside a CSRF fix. Matching
// by location alone made the drop look like the cause. Guard recognition itself is untouched; the real scan keeps its guarded negative controls silent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyMiss } from '../../src/posture/evaluation/why-missed.js';
import { runFullScan } from '../../src/engine.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';

setStateWritesEnabled(false);
const policy = { lineWindow: 3 };
const label = { id: 'dlab:1', targetId: 't1', language: 'javascript', family: 'ssrf', cwe: 'CWE-918', location: { file: 'app.js', startLine: 10, endLine: 10 } };
const diag = (suppressions) => ({ suppressions, stageEvidence: { dedupe: [], guard: [] }, sources: [], sinks: [], ir: { files: { 'app.js': { lowered: true, functions: [{ line: 1, name: 'h' }] } }, parseFailures: { count: 0, byLanguage: {}, firstError: null } } });
const classify = (suppressions) => classifyMiss({ label, outcome: { status: 'completed', findings: [] }, diagnostics: diag(suppressions), policy });
const drop = (over) => ({ id: null, file: 'app.js', line: 10, reason: 'value-too-short', ...over });

test('A DROP WITH A MATCHING FAMILY OR CWE IS THE CAUSE, AND THE TRACE NAMES THE DECISION RULE', () => {
  const f = classify([drop({ family: 'ssrf', reason: 'guard-recognized:ssrf-host-guard:dominates@8' })]);
  assert.equal(f.stage, 'filters'); assert.equal(f.reason, 'guard-recognized:ssrf-host-guard'); assert.equal(f.evidence.ledger.identity, 'family');
  const c = classify([drop({ cwe: 'CWE-918', reason: 'sanitized:empty-args' })]); assert.equal(c.stage, 'filters'); assert.equal(c.evidence.ledger.identity, 'cwe'); assert.equal(c.reason, 'sanitized:empty-args');
});

test('A DROP THAT RECORDS NO FAMILY AND NO CWE IS NOT BLAMED: a coincidence of location is not a cause, and the miss is explained by the stage that really failed', () => {
  const r = classify([drop({ reason: 'value-too-short' }), drop({ reason: 'entropy-filter:length<12', line: 11 })]);
  assert.notEqual(r.stage, 'filters'); assert.notEqual(r.stage, 'suppression'); assert.equal(r.stage, 'source-modelling');
});

test('A DROP OF ANOTHER FAMILY OR FAR AWAY IS STILL NOT THE CAUSE', () => {
  assert.notEqual(classify([drop({ family: 'xss', cwe: 'CWE-79' })]).stage, 'filters');
  assert.notEqual(classify([drop({ family: 'ssrf', line: 90 })]).stage, 'filters');
});

test('GUARD RECOGNITION IS NOT TURNED OFF: a host allow-list guard keeps the guarded twin silent while the unguarded twin is still reported', async () => {
  const scan = async (code) => (await runFullScan({ fileContents: { 'app.js': code }, scanRoot: null, deep: true })).findings.filter((f) => f.file === 'app.js' && /SSRF/i.test(f.vuln));
  const vuln = "const express = require('express'); const app = express();\napp.get('/f', async (req, res) => { const r = await fetch(req.query.u); res.send(await r.text()); });\n";
  const guarded = "const express = require('express'); const app = express();\nconst ALLOWED = new Set(['api.example.com']);\napp.get('/f', async (req, res) => {\n  const u = new URL(req.query.u);\n  if (!ALLOWED.has(u.hostname)) return res.status(400).end();\n  const r = await fetch(u); res.send(await r.text());\n});\n";
  assert.ok((await scan(vuln)).length >= 1, 'the unguarded twin is reported');
  const g = await scan(guarded); assert.ok(g.length === 0 || g.every((f) => f.sanitized === true || f.suppressed), 'the guarded twin is silent or marked guarded: ' + JSON.stringify(g.map((f) => f.vuln)));
});
