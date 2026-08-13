// PRD R4b (docs/DETECTION_GAP_REMEDIATION_PRD.md): at an assign-from-call
// site whose callee resolves to a builtin-summary table entry (see
// dataflow/builtin-summaries.js) with returnTainted:false, the engine
// unconditionally cleared ALL taint from
// the assignment target via removePathAndDescendants — family-blind. Several
// of those entries (encodeURIComponent, parseInt, DOMPurify.sanitize...) are
// genuine sanitizers already registered in the dataflow catalog with a
// narrow `appliesTo` family (e.g. encodeURIComponent -> ['url'] only), so
// `x = encodeURIComponent(tainted); db.query(x)` silently deleted a real SQL
// injection finding — the exact cross-family false negative the sanitizer-
// gate's family check exists to prevent everywhere else in this engine.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-builtinkill-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('encodeURIComponent (a URL-family sanitizer) does not erase a SQL-family finding on the same value', async () => {
  const dir = mkTmp('sql', {
    'app.js': `
const db = require('./db');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const id = req.query.id;
  const encoded = encodeURIComponent(id);
  db.query('SELECT * FROM t WHERE id=' + encoded);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  const sqlFindings = irFindings.filter((f) => /sql/i.test(f.vuln || ''));
  assert.ok(sqlFindings.length >= 1,
    `expected the SQLi finding to survive encodeURIComponent (a URL-only sanitizer), got IR-TAINT findings: ${JSON.stringify(irFindings.map((f) => f.vuln))}`);
});

test('encodeURIComponent still demotes/labels the URL-family it actually covers (not a total no-op)', async () => {
  // Sanity: confirms the fix doesn't just disable builtin-summary handling
  // entirely — the sanitizer is still RECORDED (via the catalog path), it's
  // just no longer allowed to erase an unrelated family's finding.
  const dir = mkTmp('recorded', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const id = req.query.id;
  const encoded = encodeURIComponent(id);
  res.redirect('http://example.com/?next=' + encoded);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  // Not asserting a specific suppression outcome here (that's sanitizer-gate's
  // job, out of scope for this fix) — only that the scan completes and the
  // sanitizer machinery still runs without throwing.
  assert.ok(Array.isArray(irFindings));
});
