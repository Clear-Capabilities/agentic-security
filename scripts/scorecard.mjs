#!/usr/bin/env node
// Accuracy scorecard driver (roadmap R3) — `npm run scorecard`.
//
// This is the impure half of the scorecard. It performs the runs, then hands
// the raw results to `scanner/src/posture/accuracy-scorecard.js`, which does
// all aggregation and rendering as pure functions (that split is what makes
// the figures unit-testable against a hand-computed fixture — see
// scanner/test/accuracy-scorecard.test.js).
//
// Every rate in the emitted document comes from a run this script just
// performed:
//   · the full CVE-replay corpus, via `bench/cve-replay/runner.mjs --json`
//   · the self-scan precision harness, via `bench/self-scan/measure.mjs --json`
// Two committed files are ALSO read (`corpus-baseline.json`,
// `proof-corpus/results/summary.json`) but only for context, are labelled as
// committed artifacts in the output with their own generatedAt/commit, and no
// rate is ever derived from them.
//
// Outputs: docs/SCORECARD.md and docs/scorecard.json.
//
// Determinism: the only part of the output permitted to vary between two runs
// on an unchanged tree is the generated-timestamp. Verify with:
//   npm run scorecard && cp docs/SCORECARD.md /tmp/a.md && npm run scorecard
//   diff <(grep -v 'Generated (UTC)' /tmp/a.md) \
//        <(grep -v 'Generated (UTC)' docs/SCORECARD.md)

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  buildScorecard,
  renderScorecardMarkdown,
} from '../scanner/src/posture/accuracy-scorecard.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

function runJson(scriptRelPath, args, label) {
  const script = path.join(REPO, scriptRelPath);
  const r = cp.spawnSync(process.execPath, [script, ...args], {
    cwd: REPO, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env },
  });
  if (r.status !== 0) {
    process.stderr.write(`✗ ${label} exited ${r.status}\n${(r.stderr || '').slice(-4000)}\n`);
    process.exit(1);
  }
  try {
    return JSON.parse(r.stdout);
  } catch (e) {
    process.stderr.write(`✗ ${label} produced unparseable JSON: ${e.message}\n`);
    process.exit(1);
  }
}

// Read-or-null. Deliberately a single read inside try/catch rather than an
// existsSync-then-read: the check-then-use form is a TOCTOU pattern this
// project's own engine flags, and the self-scan precision harness would
// correctly report it on this file.
function readJsonIfPresent(rel) {
  try { return JSON.parse(fs.readFileSync(path.join(REPO, rel), 'utf8')); } catch { return null; }
}

function git(args) {
  const r = cp.spawnSync('git', args, { cwd: REPO, encoding: 'utf8' });
  return r.status === 0 ? (r.stdout || '').trim() : null;
}

async function main() {
  process.stderr.write('· running the CVE-replay corpus (all tiers)…\n');
  const corpus = runJson('bench/cve-replay/runner.mjs', ['--json'], 'corpus runner');

  process.stderr.write('· running the self-scan precision harness…\n');
  const selfScan = runJson('bench/self-scan/measure.mjs', ['--json'], 'self-scan');

  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8'));
  let bundleSha256 = 'unbuilt';
  try {
    const raw = fs.readFileSync(path.join(REPO, 'scanner', 'dist', 'agentic-security.mjs.sha256'), 'utf8');
    bundleSha256 = raw.trim().split(/\s+/)[0] || 'unbuilt';
  } catch { /* bundle not built — recorded as 'unbuilt', never fabricated */ }

  const model = buildScorecard({
    provenance: {
      engineVersion: pkg.version,
      bundleSha256,
      commit: git(['rev-parse', 'HEAD']) || 'unknown',
      // "Clean" is evaluated with the two artifacts this command itself writes
      // excluded — a scorecard can never be clean with respect to its own
      // output. Everything else being uncommitted is disclosed in the document,
      // because then the recorded commit does not describe what was measured.
      worktreeClean: git(['status', '--porcelain', '--',
        ':(exclude)docs/SCORECARD.md', ':(exclude)docs/scorecard.json']) === '',
      nodeVersion: process.version,
      generatedAt: new Date().toISOString(),
    },
    corpusDetail: corpus.detail || [],
    selfScan,
    committed: {
      corpusBaseline: readJsonIfPresent('bench/cve-replay/corpus-baseline.json'),
      proofCorpus: readJsonIfPresent('bench/proof-corpus/results/summary.json'),
      // The independent-population result is READ from a committed file rather
      // than re-run: scoring 110 upstream packages takes ~32 minutes, far too
      // long to sit inside `npm run scorecard`.
      //
      // It is read here at all because the section reporting it used to be
      // HAND-WRITTEN into docs/SCORECARD.md — an auto-generated file. Every
      // regeneration silently deleted it, and in between, the document kept
      // publishing a recall figure (45.0%, n=40) that had already been
      // withdrawn. A number nobody regenerates is a number nobody corrects.
      independent: readJsonIfPresent('bench/independent/RESULT.json'),
    },
  });

  const md = renderScorecardMarkdown(model);
  fs.writeFileSync(path.join(REPO, 'docs', 'SCORECARD.md'), md);
  fs.writeFileSync(path.join(REPO, 'docs', 'scorecard.json'), JSON.stringify(model, null, 2) + '\n');

  const c = model.corpus;
  process.stderr.write(
    `✓ docs/SCORECARD.md + docs/scorecard.json written\n` +
    `  detection (pre/):      ${c.overall.detection.n}/${c.overall.detection.d}\n` +
    `  correct silence (post/): ${c.overall.silence.n}/${c.overall.silence.d}\n`);
  if (c.notScored.length) {
    process.stderr.write(`  ! ${c.notScored.length} entry/entries could not be scored (disclosed in the document, excluded from every denominator):\n`);
    for (const n of c.notScored) process.stderr.write(`    · ${n.cve}: ${n.status}${n.error ? ' — ' + n.error : ''}\n`);
  }
  if (!model.provenance.worktreeClean) {
    process.stderr.write('  ! worktree is dirty — the recorded commit does not fully describe what was measured\n');
  }
}

main().catch(e => { process.stderr.write(`fatal: ${e && e.stack}\n`); process.exit(2); });
