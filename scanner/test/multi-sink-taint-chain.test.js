// SARD_80_F1 W4.J22/J23 — the MULTI-SINK aggregate ("one source reaches N
// sinks") previously ALWAYS pushed a brand new finding hardcoding
// cwe:'CWE-20' with no `family`, regardless of what the grouped sinks
// actually were. When every sink shares one real family/CWE, that new
// finding duplicated a per-sink finding already in the result set at the
// identical (file, line, family, cwe) — a scored phantom fp with no new
// information. Fixed: the homogeneous case attaches chain metadata onto the
// existing per-sink findings instead of pushing a duplicate; only a
// genuinely mixed-CWE chain (a real, distinct "multiple vulnerability
// classes from one source" finding) still gets its own standalone finding.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runFullScan } from '../src/engine.js';

test('homogeneous multi-sink chain: no duplicate MULTI-SINK finding, metadata attached instead', async () => {
  const src = `
const express = require('express');
const app = express();
app.get('/x', (req, res) => {
  const q = req.query.q;
  db.query("SELECT * FROM t WHERE a='" + q + "'");
  db.query("SELECT * FROM u WHERE b='" + q + "'");
});
`;
  const res = await runFullScan({ fileContents: { 'app.js': src }, scanRoot: '/tmp/agentic-security-multi-sink-homogeneous', deep: true });
  const findings = res.findings || [];
  const multi = findings.filter((f) => f.parser === 'MULTI-SINK');
  assert.equal(multi.length, 0);
  const sqli = findings.filter((f) => f.family === 'sql-injection');
  assert.equal(sqli.length, 2);
  for (const f of sqli) {
    assert.ok(f.multiSinkChain);
    assert.equal(f.multiSinkChain.sinkCount, 2);
    assert.equal(f.multiSinkChain.sinks.length, 2);
  }
});

test('mixed-CWE chain: still gets its own standalone MULTI-SINK finding with the generic tag', async () => {
  const src = `
const express = require('express');
const app = express();
app.get('/x', (req, res) => {
  const q = req.query.q;
  db.query("SELECT * FROM t WHERE a='" + q + "'");
  res.send("<div>" + q + "</div>");
});
`;
  const res = await runFullScan({ fileContents: { 'app.js': src }, scanRoot: '/tmp/agentic-security-multi-sink-mixed', deep: true });
  const findings = res.findings || [];
  const multi = findings.filter((f) => f.parser === 'MULTI-SINK');
  assert.equal(multi.length, 1);
  assert.equal(multi[0].family, 'multi-sink-taint-chain');
  assert.equal(multi[0].cwe, 'CWE-20');
});
