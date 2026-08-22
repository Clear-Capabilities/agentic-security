// PRD F11.3 — incremental mode must not change the ANSWER, only the cost.
//
// `AGENTIC_SECURITY_INCREMENTAL=1` reuses taint summaries from a prior scan, and
// it is ON BY DEFAULT for diff-scoped runs (`--pr`, `--changed-since`) — which
// is the PR-review path, i.e. the one where a missed finding is most expensive.
//
// A cache that returns a stale summary does not crash. It quietly answers a
// question about the code as it used to be, and the scan still succeeds, still
// prints, still exits 0. That is the same silent-wrong-answer shape as the
// rate-limit detector discarding all its findings: nothing fails, the number is
// just wrong.
//
// So the property is parity: for the same tree, an incremental scan and a cold
// scan must agree on the finding set. Speed is not asserted here — a correct
// slow answer is fine, a fast wrong one is not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function fixture() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'incr-parity-'));
  fs.writeFileSync(path.join(d, 'package.json'), '{"name":"p","version":"1.0.0"}');
  fs.writeFileSync(path.join(d, 'app.js'), [
    "const { exec } = require('child_process');",
    "const express = require('express');",
    'const app = express();',
    "app.get('/ping', (req, res) => {",
    '  exec(`ping -c 1 ${req.query.host}`, (e, out) => res.send(out));',
    '});',
    "app.get('/read', (req, res) => {",
    "  const fs2 = require('fs');",
    '  res.send(fs2.readFileSync(req.query.file, "utf8"));',
    '});',
    'module.exports = app;',
  ].join('\n'));
  return d;
}

/** Stable, comparable shape — ordering and volatile fields excluded. */
const key = (f) => `${f.file}:${f.line}:${f.vuln}:${f.cwe}`;
const setOf = (scan) => [
  ...(scan.findings || []), ...(scan.logicVulns || []),
].map(key).sort();

async function scanWith(dir, incremental) {
  const prev = process.env.AGENTIC_SECURITY_INCREMENTAL;
  if (incremental) process.env.AGENTIC_SECURITY_INCREMENTAL = '1';
  else delete process.env.AGENTIC_SECURITY_INCREMENTAL;
  try {
    // Fresh module registry per scan so a cache cannot leak across the
    // comparison in-process and manufacture the agreement being tested.
    const { runScan } = await import(`../src/runScan.js?incr=${incremental ? 1 : 0}-${Date.now()}`);
    const { scan } = await runScan(dir);
    return setOf(scan);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_INCREMENTAL;
    else process.env.AGENTIC_SECURITY_INCREMENTAL = prev;
  }
}

test('an incremental scan agrees with a cold scan on the same tree', async () => {
  const dir = fixture();
  try {
    const cold = await scanWith(dir, false);
    assert.ok(cold.length > 0, 'the fixture must produce findings or the comparison is vacuous');

    // First incremental run populates the cache; the second is the one that can
    // actually serve a reused summary. Both must match the cold answer — testing
    // only the first would never exercise the reuse path at all.
    const warmup = await scanWith(dir, true);
    const reused = await scanWith(dir, true);

    assert.deepEqual(warmup, cold, 'incremental (cold cache) diverged from a full scan');
    assert.deepEqual(reused, cold, 'incremental (REUSED summaries) diverged from a full scan');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a changed file is re-analysed, not served from a stale summary', async () => {
  // The failure mode that matters: the cache answers about the code as it WAS.
  // Scan, then remove the vulnerability, then scan again with the cache warm.
  // The finding must disappear.
  const dir = fixture();
  try {
    const before = await scanWith(dir, true);
    assert.ok(before.some((k) => /Command|Injection/i.test(k)), 'fixture must start with a command-injection finding');

    fs.writeFileSync(path.join(dir, 'app.js'), [
      "const express = require('express');",
      'const app = express();',
      "app.get('/ping', (req, res) => res.send('pong'));",
      'module.exports = app;',
    ].join('\n'));

    const after = await scanWith(dir, true);
    assert.ok(
      !after.some((k) => /Command|Injection/i.test(k)),
      'a stale summary reported a vulnerability that no longer exists in the file',
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a newly-introduced vulnerability is seen with the cache warm', async () => {
  // The other direction, and the more dangerous one: a warm cache must not hide
  // a NEW finding. On the --pr path this is exactly the review that matters.
  const dir = fixture();
  try {
    fs.writeFileSync(path.join(dir, 'app.js'), [
      "const express = require('express');",
      'const app = express();',
      "app.get('/ok', (req, res) => res.send('ok'));",
      'module.exports = app;',
    ].join('\n'));
    const clean = await scanWith(dir, true);

    fs.writeFileSync(path.join(dir, 'app.js'), [
      "const { exec } = require('child_process');",
      "const express = require('express');",
      'const app = express();',
      "app.get('/ping', (req, res) => {",
      '  exec(`ping -c 1 ${req.query.host}`, (e, out) => res.send(out));',
      '});',
      'module.exports = app;',
    ].join('\n'));
    const dirty = await scanWith(dir, true);

    assert.ok(dirty.length > clean.length, 'a warm cache hid a newly-introduced vulnerability');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
