// Stage 6 correctness audit — src/lsp/server.js.
//
// Three findings, all reproduced against the real module:
//   1. findingToDiagnostic read `f.remediation` directly, but raw
//      scan.findings entries (what this consumes, pre-normalizeFindings)
//      come from two conventions — most posture/*.js and newer sast/*.js
//      modules set `remediation`, while ~127 of engine.js's own detectors
//      set a `fix` STRING field instead. The remediation text silently
//      dropped for every fix-string detector's diagnostic.
//   2. scanFile only ever read scan.findings (SAST channel) — scan.secrets
//      and scan.logicVulns are separate arrays on the raw runScan() result,
//      so a saved file with a hardcoded credential got a clean problem
//      pane, no diagnostic at all.
//   3. Unlike the MCP surface, nothing here ever applied redactFinding —
//      fixed together with #2 so merging in the secrets/logicVulns channels
//      (which is exactly where raw secret material shows up in `snippet`)
//      didn't open a new leak the moment it happened.
//
// The scanFile-based tests run it in a real child process (see
// helpers/lsp-scan-file.mjs) rather than in-process: scanFile()'s internal
// send() writes real LSP protocol frames to process.stdout, and
// monkey-patching that away in-process was found to interfere with
// node:test's own stdout-based reporting (sibling tests silently vanished
// from the run summary).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { _internals } from '../src/lsp/server.js';

const { findingToDiagnostic } = _internals;
const HELPER = fileURLToPath(new URL('./helpers/lsp-scan-file.mjs', import.meta.url));

test('findingToDiagnostic prefers a fix-string detector\'s remediation, not just the `remediation` field', () => {
  const f = { vuln: 'AWS Access Key ID', severity: 'critical', file: 'a.js', line: 1, fix: 'Remove the hardcoded credential; use environment variables.' };
  const diag = findingToDiagnostic(f);
  assert.match(diag.message, /Remove the hardcoded credential/, 'a fix-string detector\'s remediation must not be silently dropped');
});

test('findingToDiagnostic still renders a `remediation`-field finding (existing convention, unchanged)', () => {
  const f = { vuln: 'Missing auth', severity: 'high', file: 'a.js', line: 1, remediation: 'Add an auth middleware check.' };
  const diag = findingToDiagnostic(f);
  assert.match(diag.message, /Add an auth middleware check/);
});

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-lsp-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

function scanFileInChild(dir, absFilePath) {
  // scanFile() writes real LSP protocol frames to the CHILD's stdout — the
  // helper reports its result over stderr instead, a channel scanFile
  // never touches, so the two never collide.
  const r = spawnSync('node', [HELPER, dir, absFilePath], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`lsp-scan-file helper failed: ${r.stderr}`);
  return JSON.parse(r.stderr);
}

test('scanFile surfaces a hardcoded secret (scan.secrets channel), not just SAST findings', () => {
  const SECRET = 'AKIAABCDEFGHIJKLMNOP';
  const dir = mkTmp('secret', { 'app.js': `const AWS_KEY = "${SECRET}";\n` });
  try {
    const diags = scanFileInChild(dir, path.join(dir, 'app.js'));
    assert.ok(diags.length >= 1, 'expected at least one diagnostic for a hardcoded AWS key');
    // Redaction: the raw secret value must never reach the stored finding.
    for (const f of diags) {
      assert.ok(!JSON.stringify(f).includes(SECRET), 'raw secret leaked into an LSP diagnostic');
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('scanFile diagnostics are redacted — a committed .env secret does not appear raw', () => {
  const SECRET = 'SuperSecretPass123';
  const dir = mkTmp('dotenv', { '.env': `DB_PASSWORD=${SECRET}\n` });
  try {
    const diags = scanFileInChild(dir, path.join(dir, '.env'));
    assert.ok(diags.length >= 1, 'expected a committed-.env diagnostic');
    for (const f of diags) {
      assert.ok(!JSON.stringify(f).includes(SECRET), 'raw .env secret leaked into an LSP diagnostic');
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// PRD R1 (docs/DETECTION_GAP_REMEDIATION_PRD.md): scanFile called runScan()
// with no `deep` option, so every on-save LSP diagnostic pass was
// regex/AST-only — blind to a bug whose source and sink are connected only
// through a call within the same saved file. NOT changing runScan()'s
// global default or the CI override — scoped to this call site only, same
// as the analogous scan_diff (MCP) fix.
test('scanFile runs the interprocedural taint engine, not just regex/AST (deep mode reaches on-save diagnostics)', () => {
  const dir = mkTmp('deep', {
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
  try {
    // _diagnosticsByUri stores the raw finding objects (pre-
    // findingToDiagnostic conversion), so assert on `.vuln`, not `.message`.
    const diags = scanFileInChild(dir, path.join(dir, 'app.js'));
    assert.ok(diags.some((d) => d.vuln === 'SQL Injection (db.query)'),
      `expected the deep-engine-only "SQL Injection (db.query)" finding, got vulns: ${JSON.stringify(diags.map((d) => d.vuln))}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
