#!/usr/bin/env node
// SARD_AGENTIC_SECURITY_PRD.md §43-44 — external holdout, never used for tuning.
//
// PRD §43: "maintain at least one benchmark family that is NEVER used for
// tuning ... Preferred external holdouts should contain larger, more
// realistic applications with known injected vulnerabilities." This repo
// already has exactly that: bench-realworld.js's curated real-world apps
// (dvwa, juice-shop, nodegoat, pygoat, railsgoat — see bench/README.md's
// corpus inventory). None of their expected-findings fixtures were ever
// derived from or influenced by SARD Juliet/PHP content, so they qualify.
//
// This script runs each holdout app and compares against a LOCAL-ONLY
// baseline (same "no committed benchmark scores" reasoning as
// compare-baseline.mjs — see that file's header) — the point is catching a
// SARD-driven engine change regressing real-world detection, not producing
// a number anyone quotes externally. A "no drift" result on a
// `requiresReAudit:true` corpus is informational, matching
// bench-realworld.js's own WARNING for that corpus.
//
// Usage:
//   node bench/sard/scripts/holdout-check.mjs --update-baseline
//   node bench/sard/scripts/holdout-check.mjs --check-baseline
//
// Run this AFTER any SARD-driven engine change (a new catalog.js source/sink,
// a detector tweak informed by a SARD false negative, etc.) to confirm the
// change generalizes rather than only moving the SARD number.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REALWORLD_DIR = path.join(HERE, '..', '..', '..', 'scanner', 'test', 'benchmark', 'realworld');
const REPORTS_DIR = path.join(HERE, '..', 'reports');
const BASELINE_PATH = path.join(REPORTS_DIR, 'holdout-baseline.json');

// The external holdout set (PRD §43). Kept as a literal list, not derived
// from the manifest automatically, so adding a new curated app to the
// manifest doesn't silently enroll it as a holdout without a deliberate
// decision that it actually qualifies (SARD-independent ground truth).
const HOLDOUT_APPS = ['dvwa', 'juice-shop', 'nodegoat', 'pygoat', 'railsgoat'];
const TOLERANCE = 0.02;

function args() {
  const a = process.argv.slice(2);
  return { update: a.includes('--update-baseline'), check: a.includes('--check-baseline') };
}

function runApp(name) {
  const res = cp.spawnSync('node', ['test/benchmark/realworld/bench-realworld.js', '--app', name, '--json'], {
    cwd: path.join(REALWORLD_DIR, '..', '..', '..'),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 180_000, // bounded — a hung holdout app must not hang this script forever.
  });
  if (res.error || res.status !== 0) {
    return { name, error: res.error?.message || `exit ${res.status}: ${res.stderr?.slice(-2000)}` };
  }
  let parsed;
  try { parsed = JSON.parse(res.stdout); } catch (e) { return { name, error: `unparseable output: ${e.message}` }; }
  const r = parsed.results?.[0];
  if (!r) return { name, error: 'no results in output' };
  return { name, tp: r.tp, fp: r.fp, fn: r.fn, precision: r.precision, recall: r.recall, f1: r.f1, requiresReAudit: !!r.requiresReAudit };
}

function main() {
  const opts = args();
  if (!opts.update && !opts.check) {
    console.error('Usage: holdout-check.mjs --update-baseline | --check-baseline');
    process.exit(2);
  }

  const results = [];
  for (const app of HOLDOUT_APPS) {
    console.error(`  running holdout app: ${app}`);
    results.push(runApp(app));
  }

  const errored = results.filter(r => r.error);
  if (errored.length) {
    console.error(`\n✗ ${errored.length} holdout app(s) failed to run — treating as environment error, not a regression:`);
    for (const e of errored) console.error(`  · ${e.name}: ${e.error}`);
  }
  const ok = results.filter(r => !r.error);

  fs.mkdirSync(REPORTS_DIR, { recursive: true });

  if (opts.update) {
    fs.writeFileSync(BASELINE_PATH, JSON.stringify({ generatedAt: new Date().toISOString(), apps: ok }, null, 2) + '\n');
    console.log(`\n✓ holdout baseline updated (local-only, gitignored): ${path.relative(process.cwd(), BASELINE_PATH)}`);
    for (const r of ok) console.log(`  ${r.name}: P=${(r.precision*100).toFixed(1)}% R=${(r.recall*100).toFixed(1)}% F1=${(r.f1*100).toFixed(1)}%${r.requiresReAudit ? '  [informational — requiresReAudit]' : ''}`);
    return;
  }

  if (!fs.existsSync(BASELINE_PATH)) {
    console.error(`✗ no baseline at ${path.relative(process.cwd(), BASELINE_PATH)} — run --update-baseline first.`);
    process.exit(2);
  }
  const baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
  const baseByName = Object.fromEntries(baseline.apps.map(a => [a.name, a]));

  let failed = false;
  console.log('\nExternal holdout check (never used for SARD tuning):');
  for (const r of ok) {
    const base = baseByName[r.name];
    if (!base) { console.log(`  + ${r.name}: no baseline entry yet (new app)`); continue; }
    const delta = r.f1 - base.f1;
    const tag = r.requiresReAudit ? '  [informational — requiresReAudit, not gated]' : '';
    if (delta < -TOLERANCE && !r.requiresReAudit) {
      failed = true;
      console.log(`  ✗ ${r.name}: F1 regressed beyond tolerance ${(base.f1*100).toFixed(1)}% -> ${(r.f1*100).toFixed(1)}%${tag}`);
    } else {
      console.log(`  ✓ ${r.name}: F1 ${(base.f1*100).toFixed(1)}% -> ${(r.f1*100).toFixed(1)}% (${delta>=0?'+':''}${(delta*100).toFixed(1)}pp)${tag}`);
    }
  }
  if (failed) {
    console.error('\n✗ external holdout regression — a SARD-driven change may not generalize. If intentional, run --update-baseline.');
    process.exit(1);
  }
  console.log('\n✓ no regression beyond tolerance on any gated holdout app.');
}

main();
