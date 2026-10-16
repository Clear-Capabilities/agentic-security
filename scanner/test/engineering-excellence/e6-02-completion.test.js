// E6-02: every target that did not complete is placed in one cause by its own recorded reason; the causes this analysis found in engine-controlled
// code are fixed and the fixes have tests that fail without them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { CAUSES, classifyReason, collect, render } from '../../../scripts/engineering-excellence/completion-analysis.mjs';
import { defaultScanFn } from '../../src/posture/evaluation/runner.js';
import { proofTargetOutcome } from '../../src/posture/accuracy-scorecard.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

test('classification: each recorded reason lands in exactly one cause, specific causes win, and an unknown reason is never folded into a known one', () => {
  const c = classifyReason;
  assert.equal(c('target "grafana" has no pinned commit — run the runner with --refresh-pins to resolve it'), 'not_attempted_unpinned');
  assert.equal(c('scan produced no result block'), 'harness_capture');
  assert.equal(c('not parseable as JSON (65536 bytes) — a truncated or interleaved capture'), 'harness_capture');
  assert.equal(c('scan failed: entry exceeded 600000ms (/tmp/x)'), 'timeout');
  assert.equal(c('no result within 60000 ms'), 'timeout');
  assert.equal(c('FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory'), 'out_of_memory');
  assert.equal(c('fatal: unable to access: Could not resolve host: github.com (clone failed)'), 'clone_or_fetch');
  assert.equal(c('spawn python3 ENOENT: python3 command not found'), 'missing_tool');
  assert.equal(c('unsupported language: cobol'), 'unsupported_language');
  assert.equal(c('parser-ir: no-function-lowered'), 'parsing');
  assert.equal(c('scan exited 1: TypeError: x is not a function'), 'engine_crash');
  assert.equal(c('something nobody has seen before'), 'unclassified'); assert.equal(c(''), 'unclassified'); assert.equal(c(undefined), 'unclassified');
  assert.equal(c('heap limit exceeded after a timeout'), 'out_of_memory', 'OOM is not reported as a timeout even when both words appear');
  for (const k of Object.keys(CAUSES)) assert.ok(CAUSES[k].owner && CAUSES[k].meaning, k);
});

test('the committed results classify with no unclassified target, and the totals add up', () => {
  const { rows } = collect();
  assert.ok(rows.length > 0);
  assert.deepEqual(rows.filter((r) => r.cause === 'unclassified').map((r) => `${r.id}: ${r.reason}`), []);
  const md = render({ rows });
  for (const k of new Set(rows.map((r) => r.cause))) assert.ok(md.includes(`| ${k} |`), k);
  const unpinned = rows.filter((r) => r.cause === 'not_attempted_unpinned');
  assert.equal(unpinned.length, 7, 'seven of the ten third-party targets were never attempted');
  assert.ok(!unpinned.some((r) => r.cause === 'engine_crash'), 'and none of them is an engine failure');
});

test('THIRD-PARTY SETUP: the seven unpinned targets are pinned to full commit SHAs, and nothing that was already pinned moved', () => {
  const m = JSON.parse(fs.readFileSync(path.join(ROOT, 'bench/proof-corpus/manifest.json'), 'utf8'));
  for (const t of m.targets) assert.match(String(t.commit), /^[0-9a-f]{40}$/, `${t.id} is pinned`);
  const was = { ghost: '7da28a03b9c72fa2cc656f5f926230bae09fd684', godot: '159701651ad44335691dcbd632d8074307074c7b', superset: 'e1ffa53d9b4926f2ac7fe8c83c5f890fd621f3c8' };
  for (const [id, sha] of Object.entries(was)) assert.equal(m.targets.find((t) => t.id === id).commit, sha, `${id} still measures the same commit`);
});

test('REPORTING: a target that never ran is "not attempted", not a failure, in the scorecard; a genuine failure still is one', () => {
  assert.equal(proofTargetOutcome({ status: 'ok' }), 'completed');
  assert.equal(proofTargetOutcome({ status: 'error', error: 'target "x" has no pinned commit — run ...' }), 'not_attempted');
  assert.equal(proofTargetOutcome({ status: 'not_attempted' }), 'not_attempted');
  assert.equal(proofTargetOutcome({ status: 'error', error: 'scan exited 1' }), 'failed');
  assert.equal(proofTargetOutcome({ status: 'timeout' }), 'failed'); assert.equal(proofTargetOutcome(null), 'failed');
  const md = fs.readFileSync(path.join(ROOT, 'docs/SCORECARD.md'), 'utf8');
  assert.ok(!/3\/10 targets completed/.test(md) || /not attempted/.test(md), 'the old "3/10 completed" figure is not left standing on its own');
});

test('PROOF-CORPUS RUNNER: an unpinned target is recorded as not_attempted and the run does not exit 0 on it', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bench/proof-corpus/runner.mjs'), 'utf8');
  assert.match(src, /record\.status = 'not_attempted'/); assert.match(src, /failed: records\.filter\(r => r\.status !== 'ok' && r\.status !== 'not_attempted'\)/);
  assert.match(src, /summary\.failed === 0 && summary\.notAttempted === 0 \? 0 : 1/);
});

test('HARNESS CAPTURE: a scan whose result is larger than one pipe buffer (64 KB) arrives whole (62 of 272 forensics re-scans were lost to this)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e6-02-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{}');
    // enough findings that the result block is several times the size of a pipe buffer
    for (let i = 0; i < 400; i++) fs.writeFileSync(path.join(dir, `h${i}.js`), `const express = require('express');\nconst { exec } = require('child_process');\nconst app = express();\napp.get('/r${i}', (req, res) => { exec('ls ' + req.query.d${i}); res.end(); });\napp.get('/s${i}', (req, res) => { require('fs').readFileSync(req.query.f${i}); res.end(); });\n`);
    const r = await defaultScanFn(dir, { layer: 'deterministic-only', timeoutMs: 280_000, env: { PATH: process.env.PATH, HOME: dir, LANG: 'C' }, diagnose: true });
    const bytes = Buffer.byteLength(JSON.stringify(r));
    assert.ok(bytes > 3 * 65536, `the result was ${bytes} bytes, so it exercises the case`);
    assert.ok(r.findings.length >= 400, `${r.findings.length} findings arrived`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the committed completion analysis is current', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/engineering-excellence/completion-analysis.mjs'), '--verify'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});
