#!/usr/bin/env node
// Proof-corpus bench runner.
//
// Clones pinned commits of third-party repositories into an out-of-tree cache,
// scans each with the committed bundle, and assembles an aggregate results
// record.
//
// DISCLOSURE BOUNDARY, enforced in code rather than left to discipline: raw
// findings are never written to a committed path. They describe possible
// weaknesses in third-party code at public commits, and publishing them from
// here would be disclosing someone else's vulnerabilities on their behalf.
// Only aggregate counts are committed; everything per-finding stays in the
// gitignored results/raw/.
//
// Usage:
//   node bench/proof-corpus/runner.mjs [options]
//     --only a,b        run just these target ids
//     --refresh-pins    resolve each target's ref to a SHA and rewrite the manifest
//     --no-determinism  skip the second scan used for the byte-identical check
//     --out <dir>       where summary.json is written (default bench/proof-corpus/results).
//                       Raw artifacts (findings, SARIF, ir-stats.json — up to 200 real
//                       third-party source paths) are ALWAYS written under the fixed
//                       bench/proof-corpus/results/raw/ regardless of --out, because that
//                       is the only path .gitignore covers. --out never relocates raw
//                       artifacts — see the disclosure boundary above.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { ensureClone, resolveRef, repoDir } from './lib/clone.mjs';
import { detectLicence } from './lib/licence.mjs';
import { readIrStats, coverageSummary } from './lib/irstats.mjs';
import { verifyBundle, runRepoScan } from './lib/scan.mjs';

import { disableStateWrites } from '../_lib/tree-integrity.mjs';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST = path.join(HERE, 'manifest.json');
// Fixed regardless of --out: this is the only path bench/proof-corpus/.gitignore
// covers. Raw artifacts carry real third-party source paths and must never be
// stageable in git — see the disclosure boundary at the top of this file.
const RAW_DIR = path.join(HERE, 'results', 'raw');

export function parseArgs(argv) {
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

// Exported so tests can assert containment without spawning the CLI: the raw
// artifact directory for a target id is always under the fixed RAW_DIR,
// independent of whatever --out resolved to.
export function rawDirFor(targetId) {
  return path.join(RAW_DIR, targetId);
}

export { RAW_DIR };

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

// Hash AND validate a captured SARIF.
//
// Hashing alone is not a gate. Godot's two captures were both exactly 65,536
// bytes (one OS pipe buffer) and both ended mid-token, so comparing their
// digests compared two identical truncated prefixes and reported
// `identical: true` — a check that could not fail. The capture bug is fixed
// in lib/scan.mjs, and this refuses to report determinism from any file that
// does not parse as a SARIF document with a `runs[]` array, so a future
// truncation surfaces as a failure instead of a pass.
export function sarifDigest(file) {
  let buf;
  try {
    buf = fs.readFileSync(file);
  } catch (e) {
    return { ok: false, reason: `unreadable: ${(e && e.code) || String(e && e.message)}`, sha: null, bytes: 0, results: null };
  }
  const sha = crypto.createHash('sha256').update(buf).digest('hex');
  let doc;
  try {
    doc = JSON.parse(buf.toString('utf8'));
  } catch {
    return {
      ok: false,
      reason: `not parseable as JSON (${buf.length} bytes) — a truncated or interleaved capture`,
      sha, bytes: buf.length, results: null,
    };
  }
  if (!doc || !Array.isArray(doc.runs) || doc.runs.length === 0) {
    return { ok: false, reason: 'parsed as JSON but has no SARIF runs[]', sha, bytes: buf.length, results: null };
  }
  const results = doc.runs.reduce((n, r) => n + ((r && Array.isArray(r.results) && r.results.length) || 0), 0);
  return { ok: true, reason: null, sha, bytes: buf.length, results };
}

// A target's declared `scope` can list several first-party subtrees (e.g.
// Godot's core/modules/scene/servers/editor). The scanner CLI takes a single
// root directory, so scanning "just scope[0]" silently narrows the measured
// scope to one subtree while the manifest and scorecard keep claiming all of
// them — scanning a subset while the manifest and scorecard keep claiming the
// whole scope is the single most dishonest thing this bench could do, because
// the shortfall is invisible in every number it publishes. Instead, materialize
// every scope entry
// as a top-level sibling under one staging root (via a real recursive copy,
// not a symlink — readTree() walks with followSymbolicLinks:false) so a
// single scan pass covers the full declared scope, sees cross-directory calls
// for the call graph, and excludes everything NOT listed (thirdparty/, tests/,
// platform/, etc.) simply by never being copied in.
function materializeScope(dir, scope, stagingDir) {
  fs.rmSync(stagingDir, { recursive: true, force: true });
  fs.mkdirSync(stagingDir, { recursive: true });
  const missing = [];
  for (const entry of scope) {
    const src = path.join(dir, entry);
    if (!fs.existsSync(src)) { missing.push(entry); continue; }
    fs.cpSync(src, path.join(stagingDir, entry), { recursive: true });
  }
  return { stagingDir, missing };
}

async function runTarget(t, opts) {
  const record = {
    id: t.id, url: t.url, commit: t.commit, tier: t.tier,
    status: 'pending', scope: t.scope, timeBudgetS: t.timeBudgetS,
  };

  const rawDir = path.join(RAW_DIR, t.id);
  fs.mkdirSync(rawDir, { recursive: true });

  try {
    const { dir, cached } = ensureClone(t);
    record.cached = cached;

    const lic = detectLicence(dir);
    record.licence = lic;

    const statsPath = path.join(rawDir, 'ir-stats.json');
    const sarifA = path.join(rawDir, 'run-a.sarif');
    let scanDir;
    if (Array.isArray(t.scope) && t.scope.length > 1) {
      const stagingDir = path.join(rawDir, 'scope-root');
      const { missing } = materializeScope(dir, t.scope, stagingDir);
      if (missing.length) {
        record.status = 'error';
        record.error = `scope entries missing from checkout: ${missing.join(', ')}`;
        return record;
      }
      scanDir = stagingDir;
      record.scannedPath = t.scope.join(', ');
    } else if (Array.isArray(t.scope) && t.scope.length === 1) {
      scanDir = path.join(dir, t.scope[0]);
      record.scannedPath = t.scope[0];
    } else {
      scanDir = dir;
      record.scannedPath = '.';
    }

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
      const da = sarifDigest(sarifA);
      const db = sarifDigest(sarifB);
      // `identical` requires BOTH captures to be valid whole SARIF documents.
      // A truncated capture can never report determinism again.
      record.determinism = {
        checked: true,
        valid: da.ok && db.ok,
        invalidReason: da.ok ? (db.ok ? null : `run-b: ${db.reason}`) : `run-a: ${da.reason}`,
        identical: da.ok && db.ok && da.sha === db.sha,
        bytes: { runA: da.bytes, runB: db.bytes },
        results: da.ok ? da.results : null,
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
  // STATE_SEAM_COMPLETION_PRD M3 — a benchmark must not mutate what it measures.
  // Every runner disables state writing; runners with a well-defined corpus
  // directory additionally assert byte-identity (see bench/cve-replay/runner.mjs).
  await disableStateWrites();
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

// Guarded so importing this module (e.g. from a test that only wants
// parseArgs/rawDirFor) never triggers a real bench run as a side effect.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(c => process.exit(c)).catch(err => {
    process.stderr.write(`fatal: ${err && err.stack}\n`);
    process.exit(2);
  });
}
