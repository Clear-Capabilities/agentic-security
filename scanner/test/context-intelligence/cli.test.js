import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tempProject, cleanup } from './helpers.js';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../bin/agentic-security.js');
function cli(args, env = {}) {
  const clean = { ...process.env };
  for (const k of Object.keys(clean)) if (/^AGENTIC_SECURITY_(LLM|EGRESS)/.test(k)) delete clean[k];
  const r = spawnSync(process.execPath, [BIN, 'context', ...args], { encoding: 'utf8', env: { ...clean, ...env }, timeout: 60000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test('context with no subcommand prints usage and exits 0; unknown subcommand exits 1', () => {
  assert.equal(cli([]).code, 0);
  assert.match(cli([]).out, /Usage: agentic-security context/);
  assert.equal(cli(['frobnicate']).code, 1);
});

test('build writes inspectable bundles; inspect and verify agree; tampering fails verify', () => {
  const dir = tempProject('js-app');
  try {
    const b = cli(['build', '--root', dir, '--format', 'json']);
    assert.equal(b.code, 0, b.err);
    const j = JSON.parse(b.out);
    assert.equal(j.summary.entrypointsFound, 7);
    assert.equal(j.persisted.ok, true);
    const i = cli(['inspect', '--root', dir, '--route', '/docs/:id/archive', '--format', 'json']);
    assert.equal(i.code, 0, i.err);
    assert.ok(JSON.parse(i.out));
    assert.equal(cli(['verify', '--root', dir]).code, 0);
    const bundles = path.join(dir, '.agentic-security', 'context-intelligence', 'bundles');
    const h = fs.readdirSync(bundles)[0];
    fs.appendFileSync(path.join(bundles, h, 'context-1.txt'), 'tampered');
    assert.notEqual(cli(['verify', '--root', dir]).code, 0);
  } finally { cleanup(dir); }
});

test('review without a configured model skips every job: missing coverage is reported and --strict fails', () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    const r = cli(['review', '--root', dir, '--format', 'json', '--strict']);
    assert.equal(r.code, 3, r.out + r.err);
    const j = JSON.parse(r.out);
    assert.equal(j.coverage.succeeded, 0);
    assert.ok(j.coverage.missingCoverage > 0);
    assert.equal(j.findings.length, 0);
    assert.equal(cli(['review', '--root', dir, '--provider', 'other']).code, 1);
    assert.equal(cli(['review', '--root', dir, '--question', 'nope']).code, 1);
  } finally { cleanup(dir); }
});

test('review --dry-run plans without calling anything', () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    const d = cli(['review', '--root', dir, '--dry-run', '--format', 'json']);
    assert.equal(d.code, 0, d.err);
    assert.equal(JSON.parse(d.out).dryRun, true);
  } finally { cleanup(dir); }
});

test('build refuses to write state into a directory with no project marker', () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    fs.rmSync(path.join(dir, 'package.json'));
    const b = cli(['build', '--root', dir, '--format', 'json']);
    const j = JSON.parse(b.out);
    assert.equal(j.persisted.ok, false);
    assert.equal(fs.existsSync(path.join(dir, '.agentic-security')), false);
  } finally { cleanup(dir); }
});

test('eval runs the bundled synthetic suite and exits 0', () => {
  const r = cli(['eval', '--suite', 'fixtures', '--baseline', 'deterministic,dci', '--format', 'json']);
  assert.equal(r.code, 0, r.err);
  assert.equal(JSON.parse(r.out).synthetic, true);
});

test('the built distributable runs the documented commands (not just the source imports)', { skip: !fs.existsSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/agentic-security.mjs')) && 'dist bundle not built' }, () => {
  const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/agentic-security.mjs');
  const dir = tempProject('js-app');
  try {
    const run = (...a) => spawnSync(process.execPath, [dist, 'context', ...a], { encoding: 'utf8', timeout: 60000 });
    const b = run('build', '--root', dir, '--format', 'json');
    assert.equal(b.status, 0, b.stderr);
    assert.equal(JSON.parse(b.stdout).summary.entrypointsFound, 7);
    assert.equal(run('verify', '--root', dir).status, 0);
    assert.equal(run('inspect', '--root', dir, '--route', '/admin/purge', '--format', 'json').status, 0);
    assert.equal(run('status', '--root', dir).status, 0);
  } finally { cleanup(dir); }
});
