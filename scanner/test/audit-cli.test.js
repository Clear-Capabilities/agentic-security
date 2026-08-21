// Transcript-review CLI tests (eval-post recommendation #6).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { auditCall } from '../src/mcp/audit.js';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN = path.resolve(__dirname, '..', 'bin', 'agentic-security-audit.js');

function mkLog(entries) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-cli-'));
  // audit.js refuses to write the log unless the session root has a project
  // marker (package.json / .git / etc). Drop a stub so the CLI tests see it.
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"audit-cli-test"}');
  for (const e of entries) auditCall({ sessionRoot: root, ...e });
  return root;
}

// Budget for one CLI invocation. Deliberately generous, and here is the
// measurement behind it: `bin/agentic-security-audit.js` takes ~2.7 s to start
// and run on an IDLE machine. The previous budget was 4 s — a 1.5x margin — and
// `npm test` runs many test files CONCURRENTLY, so under ordinary suite load
// these spawns routinely exceeded it.
//
// The failure mode is what makes this worth fixing rather than retrying: it
// surfaces as `status: null` with an empty stderr on a DIFFERENT test each run,
// which reads as a real assertion failure and is not reproducible in isolation
// (verified: three consecutive clean runs of this file alone). It blocked a
// release push on 2026-08-21, on a commit whose entire diff was 8 lines of JSON
// in a release-gate data file that cannot affect subprocess timing.
//
// 30 s is ~11x the idle cost — enough headroom for a loaded machine, still
// bounded so a genuinely hung CLI fails the suite instead of stalling it.
const CLI_TIMEOUT_MS = 30_000;

function run(args, root) {
  return cp.spawnSync('node', [BIN, ...args, '--root', root], { encoding: 'utf8', timeout: CLI_TIMEOUT_MS });
}

test('review prints filtered entries', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: { files: ['a.js'] }, outcome: 'ok' },
    { tool: 'apply_fix', args: { finding_id: 'f1' }, outcome: 'rejected', reason: 'no-confirm' },
    { tool: 'apply_fix', args: { finding_id: 'f2', confirm: true }, outcome: 'ok' },
  ]);
  const r = run(['review', '--last', '1h', '--n', '10'], root);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /scan_diff/);
  assert.match(r.stdout, /apply_fix/);
  assert.match(r.stdout, /\[REJ\]/);
});

test('review filters by tool', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: { files: ['a.js'] }, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
  ]);
  const r = run(['review', '--tool', 'apply_fix', '--last', '1h'], root);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /apply_fix/);
  assert.ok(!/scan_diff/.test(r.stdout));
});

test('review filters by outcome', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: {}, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'rejected', reason: 'r' },
  ]);
  const r = run(['review', '--outcome', 'rejected', '--last', '1h'], root);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /apply_fix/);
  assert.ok(!/\[ OK\].*scan_diff/.test(r.stdout));
});

test('metrics aggregates by tool', () => {
  const root = mkLog([
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'rejected', reason: 'r' },
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
    { tool: 'scan_diff', args: {}, outcome: 'ok' },
  ]);
  const r = run(['metrics', '--last', '1h', '--json'], root);
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.equal(out.byTool.apply_fix.total, 3);
  assert.equal(out.byTool.apply_fix.ok, 2);
  assert.equal(out.byTool.apply_fix.rejected, 1);
});

test('verify reports OK on a clean chain', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: {}, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
  ]);
  const r = run(['verify'], root);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Audit chain verified: 2 entries/);
});

test('verify fails on tampered chain', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: {}, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
  ]);
  // Tamper: rewrite the second line's prev hash to a wrong value.
  const fp = path.join(root, '.agentic-security', 'mcp-audit.log');
  const lines = fs.readFileSync(fp, 'utf8').split('\n').filter(Boolean);
  const e1 = JSON.parse(lines[1]);
  e1.prev = '0000000000000000000000000000000000000000000000000000000000000000';
  lines[1] = JSON.stringify(e1);
  fs.writeFileSync(fp, lines.join('\n') + '\n');
  const r = run(['verify'], root);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Audit chain BROKEN/);
});

test('review on empty log prints "No entries match"', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-empty-'));
  const r = run(['review'], root);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /No entries match/);
});

// ─── harness-anatomy #9: by-session metrics ─────────────────────────────────

test('metrics --by-session groups entries with the same sessionId', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: {}, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
    { tool: 'query_taint', args: {}, outcome: 'ok' },
  ]);
  const r = run(['metrics', '--by-session', '--last', '1h', '--json'], root);
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  // All entries share the same in-process sessionId.
  assert.equal(out.totalSessions, 1);
  assert.equal(out.sessions[0].total, 3);
});

test('metrics --by-session flags outliers above threshold', () => {
  // 25 calls of the same tool in the same session → outlier at threshold=10.
  const entries = [];
  for (let i = 0; i < 25; i++) entries.push({ tool: 'apply_fix', args: {}, outcome: 'ok' });
  const root = mkLog(entries);
  const r = run(['metrics', '--by-session', '--outlier-threshold', '10', '--last', '1h', '--json'], root);
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.equal(out.sessions[0].outlier, true);
  assert.equal(out.sessions[0].maxToolCount, 25);
});

test('metrics --by-session handles legacy entries without sessionId', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-legacy-'));
  const stateDir = path.join(root, '.agentic-security');
  fs.mkdirSync(stateDir, { recursive: true });
  // Hand-craft a pre-instrumentation entry (no sessionId field). The bucket
  // should be labelled "pre-instrumented" so legacy logs still aggregate.
  const entry = { ts: new Date().toISOString(), tool: 'scan_diff', outcome: 'ok', args: '{}', prev: 'GENESIS' };
  fs.writeFileSync(path.join(stateDir, 'mcp-audit.log'), JSON.stringify(entry) + '\n');
  const r = run(['metrics', '--by-session', '--last', '1h', '--json'], root);
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.equal(out.sessions[0].sessionId, 'pre-instrumented');
});
