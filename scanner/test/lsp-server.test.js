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

// Final whole-branch review — I4. The four state-dir.test.js tests exercise
// safeWriteState's underlying `category` primitive directly, but nothing
// drove a real on-save scan through THIS server and inspected what it wrote.
// server.js now creates `.agentic-security/provenance/cache/*.json` on every
// save (M2 §2.4's deliberate exceptCategories:['provenance-cache'] carve-out
// in the withStateWritesDisabled wrapper above) — a disclosed change from
// before, when the LSP wrote zero state files. This asserts the carve-out
// stays exactly as narrow as documented: real provenance cache writes land,
// and nothing else (dpia.md, ropa.md, lifecycle.json, …) leaks through.
function listFilesRecursive(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFilesRecursive(full));
    else out.push(full);
  }
  return out;
}

test('a real on-save scan writes ONLY .agentic-security/provenance/cache/ — no dpia.md, ropa.md, lifecycle.json, or other state', () => {
  const dir = mkTmp('write-scope', {
    'app.js': `
const db = require('./db');
function run(id) { db.query('SELECT * FROM t WHERE id=' + id); }
`,
  });
  try {
    const git = (gitArgs) => {
      const r = spawnSync('git', gitArgs, { cwd: dir, encoding: 'utf8' });
      assert.equal(r.status, 0, `git ${gitArgs.join(' ')} failed: ${r.stderr}`);
    };
    git(['init']);
    git(['config', 'user.email', 'lsp-write-scope@example.com']);
    git(['config', 'user.name', 'LSP Write Scope Test']);
    git(['add', '-A']);
    git(['commit', '-m', 'initial commit']);

    scanFileInChild(dir, path.join(dir, 'app.js'));

    const stateDir = path.join(dir, '.agentic-security');
    const written = listFilesRecursive(stateDir).map((f) => path.relative(stateDir, f));

    // Non-vacuous guard: if nothing were written at all (e.g. the
    // provenance-cache carve-out silently stopped firing), the loop below
    // would pass over an empty list and this test would prove nothing.
    assert.ok(written.length > 0, 'on-save scan wrote nothing under .agentic-security/ — the write-scope check would be vacuous');

    for (const f of written) {
      assert.ok(
        f.startsWith(`provenance${path.sep}cache${path.sep}`),
        `on-save scan wrote outside provenance/cache/: ${f}`,
      );
    }

    // Known-dangerous specific paths must not exist, even if the prefix
    // check above were ever loosened.
    for (const dangerous of ['dpia.md', 'ropa.md', path.join('provenance', 'lifecycle.json'), 'privacy-framework.json', 'threat-model.json']) {
      assert.ok(!fs.existsSync(path.join(stateDir, dangerous)), `on-save scan wrote ${dangerous}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Final whole-branch review — I8. Same Critical defect Task 17 fixed in
// bin/agentic-security.js, still present here: `import.meta.url ===
// file://${process.argv[1]}` is FALSE when the script is invoked through a
// symlink, because Node resolves import.meta.url to the realpath while
// process.argv[1] stays the symlink path as invoked. `agentic-security-lsp` is
// one of this package's published `bin` entries, and npm/npx install every bin
// entry as a symlink, so an editor launching the server through
// `node_modules/.bin/agentic-security-lsp` would have got a process that exits
// immediately with nothing on stdout or stderr.
//
// Tested through a GENUINE symlink (not a renamed copy — a copy has its own
// realpath and would pass under the broken guard too), driven by a real LSP
// `initialize` request over the stdio framing the server actually speaks.
test('LSP entry point starts the server when invoked through a symlink', () => {
  const realScript = fileURLToPath(new URL('../src/lsp/server.js', import.meta.url));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-lsp-symlink-'));
  const linkPath = path.join(dir, 'agentic-security-lsp-link.js');
  try {
    fs.symlinkSync(realScript, linkPath);
    const req = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { rootUri: null } });
    const frame = `Content-Length: ${Buffer.byteLength(req, 'utf8')}\r\n\r\n${req}`;
    const r = spawnSync(process.execPath, [linkPath], { input: frame, encoding: 'utf8', timeout: 60000 });
    assert.match(r.stdout, /Content-Length: \d+/,
      `symlinked LSP invocation produced no protocol output (status=${r.status}, stderr=${r.stderr})`);
    assert.match(r.stdout, /capabilities/,
      `symlinked LSP invocation did not answer initialize; stdout=${JSON.stringify(r.stdout)}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
