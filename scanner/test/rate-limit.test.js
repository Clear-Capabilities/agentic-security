// rate-limit.js had zero test coverage since it was written, which is exactly
// how it went unnoticed that both findings.push() blocks set `title` but
// never `vuln` — engine.js's _shouldKeep drops any SAST finding with no
// `vuln` field (required per scanner/src/sast/CLAUDE.md), so every finding
// this detector ever produced was silently discarded downstream, project-wide,
// regardless of how many auth/AI/payment/contact endpoints actually lacked
// rate limiting. Found while root-causing an independent-population false
// negative (GHSA-r745-8hwv-h473) whose labelled CWE was different (CWE-639
// IDOR) — the rate-limit finding just happened to land on the same line and
// was suppressed the same silent way, which is what surfaced the bug.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { scanRateLimit } from '../src/sast/rate-limit.js';
import { runScan } from '../src/runScan.js';
import { normalizeFindings } from '../src/report/index.js';

test('an auth endpoint with no rate-limit guard produces a finding with a real vuln field', () => {
  const content = [
    "const router = require('express').Router();",
    "router.post('/login', (req, res) => { /* ... */ });",
  ].join('\n');
  const findings = scanRateLimit('routes/auth.js', content);
  assert.equal(findings.length, 1);
  assert.equal(typeof findings[0].vuln, 'string');
  assert.ok(findings[0].vuln.length > 0, 'vuln must be a non-empty string, not just title');
  assert.equal(findings[0].vuln, findings[0].title);
  assert.equal(findings[0].cwe, 'CWE-307');
});

test('a rate-limited auth endpoint produces no finding (positive control)', () => {
  const content = [
    "const rateLimit = require('express-rate-limit');",
    "const router = require('express').Router();",
    "router.post('/login', rateLimit({ windowMs: 900000, max: 5 }), (req, res) => {});",
  ].join('\n');
  assert.deepEqual(scanRateLimit('routes/auth.js', content), []);
});

test('the finding survives engine.js\'s _shouldKeep filter end-to-end (the actual bug)', async () => {
  // Regression for the real defect: scanRateLimit() alone having a `vuln`
  // field is necessary but not sufficient — the bug only ever manifested
  // through the full scan pipeline, so this proves the finding reaches
  // scan.findings, not just the module's own return value.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ratelimit-e2e-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
    fs.writeFileSync(
      path.join(dir, 'routes.js'),
      [
        "const router = require('express').Router();",
        "router.post('/api/login', (req, res) => { res.send('ok'); });",
        'module.exports = router;',
      ].join('\n')
    );
    const { scan } = await runScan(dir);
    const findings = normalizeFindings(scan) || [];
    const rateLimitFindings = findings.filter(f => String(f.id || '').startsWith('rate-limit:'));
    assert.ok(
      rateLimitFindings.length > 0,
      `expected at least one rate-limit finding to survive to scan.findings, got 0 of ${findings.length} total findings`
    );
    assert.ok(rateLimitFindings.every(f => typeof f.vuln === 'string' && f.vuln.length > 0));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
