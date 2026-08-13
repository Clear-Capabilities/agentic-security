// Covers PRD R6, R10, R11 (docs/DETECTION_GAP_REMEDIATION_PRD.md, Theme B+D).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { buildProjectIR } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-rcvr-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('CHA is threaded onto callContext during a real deep scan (no throw, scan completes)', () => {
  const fileContents = {
    'app.js': `
class UserRepo {
  save(x) { return x; }
}
const repo = new UserRepo();
repo.save(1);
`,
  };
  const { perFile, callGraph } = buildProjectIR(fileContents);
  // Must not throw — this is the smoke test that CHA wiring didn't break
  // the ordinary per-file analysis loop.
  assert.doesNotThrow(() => runDeepAnalysis(perFile, callGraph, { fileContents }));
});

import { matchSinkOrSanitizer } from '../src/dataflow/catalog.js';

test('R6 unit: matchSinkOrSanitizer suppresses a bare-name SQL sink on a non-DB receiver type', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'cache' }, prop: 'query' };
  // No receiverType passed (today's behavior) — still matches, unconstrained.
  const unconstrained = matchSinkOrSanitizer(calleeExpr, 'a.js');
  assert.ok(unconstrained && unconstrained.some(h => h.id === 'js-sql-query'),
    'sanity: js-sql-query must still match with no receiverType arg (backward compat)');
  // A confidently-resolved, non-DB receiver type suppresses the SQL sink.
  const suppressed = matchSinkOrSanitizer(calleeExpr, 'a.js', 'CacheClient');
  assert.ok(!suppressed || !suppressed.some(h => h.id === 'js-sql-query'),
    'js-sql-query must NOT match cache.query() once the receiver is confidently typed as non-DB');
});

test('R6 unit: matchSinkOrSanitizer still fires a genuine db.query() with a DB-shaped receiver type', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'db' }, prop: 'query' };
  const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', 'db');
  assert.ok(hits && hits.some(h => h.id === 'js-sql-query'),
    'js-sql-query must still fire when the receiver type IS in the allow-list');
});

test('R6 unit: unknown receiver type (null) stays permissive — unknown != clean', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'x' }, prop: 'query' };
  const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', null);
  assert.ok(hits && hits.some(h => h.id === 'js-sql-query'),
    'an unresolved (null) receiver type must never suppress a match — only a confident mismatch may');
});

test('R6 end-to-end: unknown/unmatched receiver type still allows match (conservative)', async () => {
  // When CHA returns null or cannot infer receiver type, the finding is
  // allowed through (Unknown ≠ clean). This test ensures we stay permissive.
  const dir = mkTmp('r6-e2e', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/', (req, res) => {
  const x = require('./untyped');
  x.query(req.query.q);
});
`,
    'untyped.js': `
module.exports = { query(s) { return s; } };
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const sqlFindings = (scan.findings || []).filter(f => /sql/i.test(f.vuln || ''));
  // Even though `x` is untyped/unknown, the finding should still fire
  // (conservative: null receiverType never suppresses).
  assert.ok(sqlFindings.length > 0,
    'x.query(tainted) with unknown receiver type should still be flagged (Unknown ≠ clean)');
  fs.rmSync(dir, { recursive: true, force: true });
});
