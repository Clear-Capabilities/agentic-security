#!/usr/bin/env node
// Proof-corpus bench runner.
//
// Clones pinned commits of third-party repositories into an out-of-tree cache,
// scans each with the committed bundle, and assembles an aggregate results
// record. Raw findings are never written to a committed path — see
// docs/PROOF_CORPUS_PRD.md §9.1 for why that boundary is enforced here rather
// than left to discipline.
//
// Usage:
//   node bench/proof-corpus/runner.mjs [options]
//     --only a,b        run just these target ids
//     --refresh-pins    resolve each target's ref to a SHA and rewrite the manifest
//     --no-determinism  skip the second scan used for the byte-identical check
//     --out <dir>       results directory (default bench/proof-corpus/results)

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { ensureClone, resolveRef, repoDir } from './lib/clone.mjs';
import { detectLicence } from './lib/licence.mjs';
import { readIrStats, coverageSummary } from './lib/irstats.mjs';
import { verifyBundle, runRepoScan } from './lib/scan.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST = path.join(HERE, 'manifest.json');

function parseArgs(argv) {
  const out = { only: null, refreshPins: false, determinism: true, outDir: path.join(HERE, 'results') };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--only') out.only = String(argv[++i] || '').split(',').filter(Boolean);
    else if (a === '--refresh-pins') out.refreshPins = true;
    else if (a === '--no-determinism') out.determinism = false;
    else if (a === '--out') out.outDir = path.resolve(String(argv[++i] || ''));
  }
  return out;
}

function loadManifest() {
  return JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
}

function refreshPins(manifest, targets) {
  for (const t of targets) {
    process.stdout.write(`  resolving ${t.id} @ ${t.ref} ... `);
    const sha = resolveRef(t.url, t.ref);
    t.commit = sha;
    process.stdout.write(`${sha}\n`);
  }
  fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  process.stdout.write(`manifest updated: ${MANIFEST}\n`);
}

function sha256File(file) {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  } catch {
    return null;
  }
}

async function runTarget(t, opts) {
  const record = {
    id: t.id, url: t.url, commit: t.commit, tier: t.tier,
    status: 'pending', scope: t.scope, timeBudgetS: t.timeBudgetS,
  };

  const rawDir = path.join(opts.outDir, 'raw', t.id);
  fs.mkdirSync(rawDir, { recursive: true });

  try {
    const { dir, cached } = ensureClone(t);
    record.cached = cached;

    const lic = detectLicence(dir);
    record.licence = lic;

    const statsPath = path.join(rawDir, 'ir-stats.json');
    const sarifA = path.join(rawDir, 'run-a.sarif');
    const scanDir = Array.isArray(t.scope) && t.scope.length
      ? path.join(dir, t.scope[0])
      : dir;
    record.scannedPath = path.relative(dir, scanDir) || '.';

    const a = await runRepoScan({
      dir: scanDir, statsPath, sarifPath: sarifA, timeoutMs: t.timeBudgetS * 1000,
    });
    record.scan = {
      exitCode: a.exitCode, wallMs: a.wallMs, timedOut: a.timedOut, peakRssKb: a.peakRssKb,
    };

    if (a.timedOut) {
      record.status = 'timeout';
      record.error = `exceeded time budget of ${t.timeBudgetS}s`;
      return record;
    }

    record.coverage = coverageSummary(readIrStats(statsPath));

    if (opts.determinism) {
      const sarifB = path.join(rawDir, 'run-b.sarif');
      const b = await runRepoScan({
        dir: scanDir, sarifPath: sarifB, timeoutMs: t.timeBudgetS * 1000,
      });
      const ha = sha256File(sarifA);
      const hb = sha256File(sarifB);
      record.determinism = {
        checked: true,
        identical: ha !== null && ha === hb,
        secondRunWallMs: b.wallMs,
      };
    } else {
      record.determinism = { checked: false, identical: null };
    }

    record.status = 'ok';
  } catch (err) {
    record.status = 'error';
    record.error = String(err && err.message);
  }
  return record;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const manifest = loadManifest();
  let targets = manifest.targets;
  if (opts.only) {
    const want = new Set(opts.only);
    targets = targets.filter(t => want.has(t.id));
    const missing = opts.only.filter(id => !manifest.targets.some(t => t.id === id));
    if (missing.length) {
      process.stderr.write(`unknown target id(s): ${missing.join(', ')}\n`);
      return 4;
    }
  }

  if (opts.refreshPins) {
    process.stdout.write('refreshing pins:\n');
    refreshPins(manifest, targets);
    return 0;
  }

  const bundle = verifyBundle();
  if (!bundle.ok) {
    process.stderr.write(`bundle check failed: ${bundle.reason}\n`);
    return 5;
  }

  fs.mkdirSync(opts.outDir, { recursive: true });
  const records = [];
  for (const t of targets) {
    process.stdout.write(`\n=== ${t.id} ===\n`);
    const rec = await runTarget(t, opts);
    records.push(rec);
    const cov = rec.coverage ? rec.coverage.totals.pct : null;
    process.stdout.write(
      `  status=${rec.status} exit=${rec.scan ? rec.scan.exitCode : 'n/a'} ` +
      `wall=${rec.scan ? Math.round(rec.scan.wallMs / 1000) : 'n/a'}s ` +
      `coverage=${cov === null ? 'n/a' : cov + '%'} ` +
      `licence=${rec.licence ? rec.licence.spdx : 'n/a'}\n`,
    );
  }

  const summary = {
    bundleSha: bundle.sha,
    targetCount: records.length,
    ok: records.filter(r => r.status === 'ok').length,
    failed: records.filter(r => r.status !== 'ok').length,
    targets: records,
  };
  const summaryPath = path.join(opts.outDir, 'summary.json');
  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2) + '\n', 'utf8');
  process.stdout.write(`\nsummary: ${summaryPath}\n`);
  process.stdout.write(`ok=${summary.ok} failed=${summary.failed}\n`);

  return summary.failed === 0 ? 0 : 1;
}

main().then(c => process.exit(c)).catch(err => {
  process.stderr.write(`fatal: ${err && err.stack}\n`);
  process.exit(2);
});
