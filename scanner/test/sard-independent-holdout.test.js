// SARD_AGENTIC_SECURITY_PRD.md adversarial-premortem remediation, Round 4
// F14 — the external-holdout generalization gate's fail-closed branch was
// structurally unreachable: every existing curated app (dvwa, juice-shop,
// nodegoat, pygoat, railsgoat) carries `provenance:
// bootstrap-from-engine-output-*` in its own expected.json, so none of them
// can serve as a genuinely independent held-out check — the ground truth
// was seeded from a past scanner run, not built from the code itself.
//
// This tests the mechanism that makes a NEW, genuinely independent holdout
// app possible: `bench-realworld.js`'s `ensureClone` now accepts a `local`
// path (repo-root-relative) instead of `repo`/`sha`, skipping the git clone
// entirely for an app committed directly in this repo
// (bench/holdout-independent/tinymart/, wired into manifest.json's
// `tinymart` entry). The full end-to-end proof that the gate now genuinely
// fires on a real regression — not just that this mechanism resolves a
// path — was done manually this session (seed a baseline, temporarily
// remove tinymart's SQL injection, confirm `holdout-check.mjs
// --check-baseline` exits 1 naming tinymart, revert, confirm it exits 0
// again) and is recorded in bench/sard/IMPLEMENTATION_STATUS.md; that full
// cycle is too slow (multiple ~1-3 minute real scans) to re-run as part of
// the fast unit-test suite, so this file covers the FAST, always-run parts:
// the path-resolution mechanism itself never attempting a clone, and the
// committed fixture's own ground truth being well-formed and internally
// consistent.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureClone } from './benchmark/realworld/bench-realworld.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, '..', '..');

test('ensureClone: a `local` path resolves directly, repo-root-relative, without ever attempting a git clone', async () => {
  const resolved = await ensureClone('tinymart', undefined, undefined, 'bench/holdout-independent/tinymart');
  assert.equal(resolved, path.join(REPO_ROOT, 'bench', 'holdout-independent', 'tinymart'));
  assert.ok(fs.existsSync(path.join(resolved, 'server.js')), 'the resolved path should point at the real, committed fixture');
});

test('ensureClone: a `local` path is used even when repo/sha are also (nonsensically) provided — local always wins, never silently falls through to a clone attempt', async () => {
  // If `local` were ignored whenever `repo` happened to be truthy, this
  // call would attempt `git clone ... not-a-real-repo ...` and either hang
  // on a bogus network call or throw — neither is acceptable for what
  // should be a pure, instant path resolution.
  const resolved = await ensureClone('tinymart', 'https://example.invalid/not-a-real-repo.git', 'deadbeef', 'bench/holdout-independent/tinymart');
  assert.equal(resolved, path.join(REPO_ROOT, 'bench', 'holdout-independent', 'tinymart'));
});

test('manifest.json: the tinymart entry uses `local`, not `repo`/`sha`, and points at the real committed fixture directory', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'benchmark', 'realworld', 'manifest.json'), 'utf8'));
  const app = manifest.apps.tinymart;
  assert.ok(app, 'expected a tinymart entry in manifest.json');
  assert.equal(typeof app.local, 'string');
  assert.equal(app.repo, undefined, 'tinymart must never be cloned — repo must be absent');
  assert.equal(app.sha, undefined, 'tinymart must never be cloned — sha must be absent');
  assert.ok(fs.existsSync(path.join(REPO_ROOT, app.local)), `manifest's local path must resolve to a real directory: ${app.local}`);
});

test('expected/tinymart.json: ground truth is genuinely independent (provenance is NOT bootstrap-from-engine-output, requiresReAudit is false) — unlike every other curated app', () => {
  const expectedPath = path.join(__dirname, 'benchmark', 'realworld', 'expected', 'tinymart.json');
  const doc = JSON.parse(fs.readFileSync(expectedPath, 'utf8'));
  assert.equal(doc.requiresReAudit, false);
  assert.doesNotMatch(doc.provenance || '', /bootstrap-from-engine-output/,
    'tinymart\'s whole reason for existing is a ground truth NOT seeded from a past scanner run');
  assert.ok(Array.isArray(doc.expected) && doc.expected.length > 0);
  for (const entry of doc.expected) {
    assert.equal(typeof entry.file, 'string');
    assert.equal(typeof entry.line, 'number');
    assert.equal(typeof entry.family, 'string');
    assert.equal(typeof entry.cwe, 'string');
    // Every referenced file must actually exist in the fixture, and the
    // referenced line must be within the file's real line count — a stale
    // or fabricated ground-truth entry is worse than a missing one.
    const filePath = path.join(REPO_ROOT, 'bench', 'holdout-independent', 'tinymart', entry.file);
    assert.ok(fs.existsSync(filePath), `expected.json references a file that doesn't exist: ${entry.file}`);
    const lineCount = fs.readFileSync(filePath, 'utf8').split('\n').length;
    assert.ok(entry.line >= 1 && entry.line <= lineCount,
      `${entry.file}:${entry.line} is out of range (file has ${lineCount} lines)`);
  }
});

test('holdout-check.mjs: HOLDOUT_APPS includes tinymart alongside the pre-existing bootstrapped apps', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'bench', 'sard', 'scripts', 'holdout-check.mjs'), 'utf8');
  const m = src.match(/const HOLDOUT_APPS = (\[[^\]]+\]);/);
  assert.ok(m, 'expected a HOLDOUT_APPS array literal');
  const apps = JSON.parse(m[1].replace(/'/g, '"'));
  assert.ok(apps.includes('tinymart'), `expected tinymart in HOLDOUT_APPS, got: ${JSON.stringify(apps)}`);
});
