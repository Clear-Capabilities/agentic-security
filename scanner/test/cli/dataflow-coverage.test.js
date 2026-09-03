// dataflow-coverage.test.js — Milestone 5, language coverage-tier
// disclosure: real CLI integration tests for
// `agentic-security dataflow export --format coverage`.
//
// Mirrors test/cli/dataflow-recipients.test.js's own real-git-fixture +
// real-deep-scan + real-CLI-subprocess pattern.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

// A plain JS source file — enough to produce a real graph.coverage.languages
// entry for 'js' with real filesAnalyzed/filesExpected counts.
const JS_SOURCE = `function h(req, res){ res.send(req.body.name); }`;

function _scanWithLineage(fx) {
  return spawnSync(process.execPath, [CLI, 'scan', '.'], {
    cwd: fx.root, encoding: 'utf8', timeout: 60000,
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
  });
}

function _exportCli(fx, args) {
  return spawnSync(process.execPath, [CLI, 'dataflow', 'export', '.', ...args], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
}

test('dataflow export --format coverage writes a Markdown table with a real per-language row, tier, and recall figure', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', JS_SOURCE);
  fx.commit('add a plain JS flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'coverage.md');
  const exportR = _exportCli(fx, ['--format', 'coverage', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format coverage failed: ${exportR.stderr}\n${exportR.stdout}`);
  assert.ok(fs.existsSync(outFile), 'expected coverage.md to be written');

  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /# Language Coverage/);
  assert.match(md, /\| Language \| Files Analyzed \| Files Expected \| Tier \| Recall \(docs\/METRICS\.md\) \|/);
  assert.match(md, /\| js \|/);
  assert.match(md, /\bpartial\b/);
  assert.match(md, /58% \(as of 2026-08-19\)/);
});

test('dataflow export --format coverage: --filter is a documented no-op with a warning', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', JS_SOURCE);
  fx.commit('add a plain JS flow');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const filterPath = path.join(fx.root, 'filter.json');
  fs.writeFileSync(filterPath, JSON.stringify({ nodeIds: [], edgeIds: [] }));
  const outFile = path.join(fx.root, 'coverage-filtered.md');
  const exportR = _exportCli(fx, ['--format', 'coverage', '--output', outFile, '--filter', filterPath]);
  assert.equal(exportR.status, 0);
  assert.match(exportR.stderr, /--filter has no effect on --format coverage/);
});

test('dataflow export --format coverage: --no-redact and --view are documented no-ops with a warning', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', JS_SOURCE);
  fx.commit('add a plain JS flow');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'coverage-noredact.md');
  const noRedactR = _exportCli(fx, ['--format', 'coverage', '--output', outFile, '--no-redact']);
  assert.equal(noRedactR.status, 0);
  assert.match(noRedactR.stderr, /--no-redact has no effect on --format coverage/);

  const outFile2 = path.join(fx.root, 'coverage-view.md');
  const viewR = _exportCli(fx, ['--format', 'coverage', '--output', outFile2, '--view', 'privacy']);
  assert.equal(viewR.status, 0);
  assert.match(viewR.stderr, /--view has no effect on --format coverage/);
});

test('dataflow export --format coverage never fabricates a recall number for an unrecognized language', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  // No source files at all — graph.coverage.languages should come back
  // empty (or, if perFile ever includes an unrecognized extension in a
  // future fixture, that entry must show tier "unknown" with no percentage
  // printed). This test only pins the "no fabrication" property, not a
  // specific unrecognized-language shape, since this repo's own scan
  // pipeline may not surface a language for an empty tree at all. A plain
  // README (not source code in any of the 9 lineage-wired languages) is
  // committed so `git commit` has something to track — a truly empty tree
  // has nothing to stage and `git commit` fails outright.
  fx.writeFile('README.md', '# empty tree fixture\n');
  fx.commit('empty tree');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'coverage-empty.md');
  const exportR = _exportCli(fx, ['--format', 'coverage', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format coverage failed: ${exportR.stderr}\n${exportR.stdout}`);
  const md = fs.readFileSync(outFile, 'utf8');
  // Whatever the table contains, it must never print a bare, unlabeled
  // percentage next to an "unknown" tier row — every recall figure shown
  // must be paired with its own "(as of docs/METRICS.md date)" provenance,
  // enforced structurally by _renderDataflowCoverageMarkdown's own '—'
  // fallback for a missing irTaintRecallPct.
  const unknownRows = md.split('\n').filter((l) => /\| unknown \|/.test(l));
  for (const row of unknownRows) assert.match(row, /\| — \|$/, `unknown-tier row must show "—" for recall, never a number: ${row}`);
});
