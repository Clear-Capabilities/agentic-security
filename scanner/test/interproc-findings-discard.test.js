// Stage 3 correctness audit (detection depth): interprocedural findings
// computed under a non-empty (tainted-arg) context were silently discarded.
//
// Five of six `SummaryCache.compute()` call sites in engine.js built an
// `inner`/`ctx` context, ran `analyzeFunction` against it (which correctly
// populates `inner._findings` when the callee's body contains a real sink),
// and then hardcoded `findings: []` on the RETURNED/cached summary object —
// `inner._findings` was read by nobody. The sixth (the higher-order
// callback path) already merged correctly, proving the fix pattern existed
// — it just wasn't applied everywhere.
//
// The k=2 pass (probes every function with >=1 param, entry = ALL its own
// params tainted) is the sharpest edge: for a caller whose real call site
// computes the exact same entry state (e.g. a single-param helper called
// with a tainted argument — entryStateFromCall produces {'id'}, identical
// to the k=2 probe's `new Set(fn.params)` for a one-param function), the
// k=2 pass runs FIRST, computes the real finding, throws it away, and
// caches a finding-less summary — so the real call site's own
// `summaryCache.get()` gets a cache HIT and never calls `compute()` (the
// one place that DOES merge findings back) at all.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-interdisc-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('a single-param helper called with a tainted argument fires, even though the k=2 pass eagerly (and discardingly) probes the exact same entry state first', async () => {
  const dir = mkTmp('plaincall', {
    'app.js': `
const db = require('./db');
const express = require('express');
const app = express();
function leak(id) { db.query('SELECT * FROM t WHERE id=' + id); }
app.get('/run', (req, res) => {
  const uid = req.query.id;
  leak(uid);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const sqlFindings = irFindings.filter(f => /sql/i.test(f.vuln || ''));
  assert.ok(sqlFindings.length >= 1,
    `expected the SQL injection inside leak(id) to fire via the plain-call-site interprocedural path, got IR-TAINT findings: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('the same helper, called with an assign-from-call site instead of a bare call, also fires', async () => {
  const dir = mkTmp('assigncall', {
    'app.js': `
const db = require('./db');
const express = require('express');
const app = express();
function buildQuery(id) { return 'SELECT * FROM t WHERE id=' + id; }
app.get('/run', (req, res) => {
  const uid = req.query.id;
  const sql = buildQuery(uid);
  db.query(sql);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const sqlFindings = irFindings.filter(f => /sql/i.test(f.vuln || ''));
  assert.ok(sqlFindings.length >= 1,
    `expected the SQL injection at db.query(sql) to fire, got IR-TAINT findings: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});
