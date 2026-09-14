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
import { adaptiveTolerance } from './compare-baseline.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REALWORLD_DIR = path.join(HERE, '..', '..', '..', 'scanner', 'test', 'benchmark', 'realworld');
const REPORTS_DIR = path.join(HERE, '..', 'reports');
const BASELINE_PATH = path.join(REPORTS_DIR, 'holdout-baseline.json');
const AUDIT_LOG_PATH = path.join(REPORTS_DIR, 'holdout-baseline-update-log.jsonl');

// The external holdout set (PRD §43). Kept as a literal list, not derived
// from the manifest automatically, so adding a new curated app to the
// manifest doesn't silently enroll it as a holdout without a deliberate
// decision that it actually qualifies (SARD-independent ground truth).
//
// `tinymart` (added: SARD_AGENTIC_SECURITY_PRD.md adversarial-premortem
// remediation, F14) is the first — and, as of this writing, only — entry
// here whose `requiresReAudit` is genuinely `false`: every other app's
// ground truth carries `provenance: bootstrap-from-engine-output-*` (seeded
// from a past scanner run, not built independently), which is exactly why
// this gate's fail-closed branch could never fire against real data before
// now. tinymart's 6-entry ground truth was hand-authored from its own
// source, before the scanner was ever run against it — see
// bench/holdout-independent/README.md and expected/tinymart.json's own
// `_doc` for the full independence account.
const HOLDOUT_APPS = ['dvwa', 'juice-shop', 'nodegoat', 'pygoat', 'railsgoat', 'tinymart'];
const TOLERANCE = 0.02;
// tinymart's ground truth has only 6 entries — on a set that small, a
// single line moving in or out of the matched set swings F1 by double-digit
// percentage points, which a flat 2pp tolerance would misreport as a
// "regression" on ordinary, expected small-sample noise. Reuses the SAME
// `adaptiveTolerance` compare-baseline.mjs's own regression gate uses
// (Round 1 F4 / Round 2 F8) rather than inventing a second, drifting
// tolerance policy for the identical problem.
function toleranceFor(support) {
  return adaptiveTolerance(TOLERANCE, support);
}

export function args() {
  const a = process.argv.slice(2);
  const reasonIdx = a.indexOf('--reason');
  return {
    update: a.includes('--update-baseline'),
    check: a.includes('--check-baseline'),
    reason: reasonIdx !== -1 ? a[reasonIdx + 1] : null,
  };
}

// Same reasoning and same shape as compare-baseline.mjs's appendAuditLog —
// see that function's comment for why this is a local, gitignored trail
// rather than a committed one. This holdout gate is arguably the more
// important of the two to have SOME trail on, since it's the one check the
// PRD explicitly calls out as "never used for tuning" — silently rewriting
// its baseline defeats that guarantee just as surely as tuning against it.
function appendAuditLog(reason, before, after) {
  fs.mkdirSync(path.dirname(AUDIT_LOG_PATH), { recursive: true });
  const beforeByName = Object.fromEntries((before?.apps || []).map(a => [a.name, a]));
  const entry = {
    timestamp: new Date().toISOString(),
    reason,
    apps: after.map(a => ({ name: a.name, f1Before: beforeByName[a.name]?.f1 ?? null, f1After: a.f1 })),
  };
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(entry) + '\n');
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
    if (!opts.reason || !opts.reason.trim()) {
      console.error('✗ --update-baseline requires --reason "<why this new number is a legitimate baseline>".');
      process.exit(2);
    }
    const before = fs.existsSync(BASELINE_PATH) ? JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8')) : null;
    fs.writeFileSync(BASELINE_PATH, JSON.stringify({ generatedAt: new Date().toISOString(), apps: ok }, null, 2) + '\n');
    appendAuditLog(opts.reason, before, ok);
    console.log(`\n✓ holdout baseline updated (local-only, gitignored): ${path.relative(process.cwd(), BASELINE_PATH)}`);
    console.log(`  reason: ${opts.reason}`);
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
    const support = (base.tp || 0) + (base.fn || 0);
    const tolerance = toleranceFor(support);
    const tag = r.requiresReAudit ? '  [informational — requiresReAudit, not gated]' : '';
    if (delta < -tolerance && !r.requiresReAudit) {
      failed = true;
      console.log(`  ✗ ${r.name}: F1 regressed beyond tolerance (${(tolerance*100).toFixed(2)}pp, support=${support}) ${(base.f1*100).toFixed(1)}% -> ${(r.f1*100).toFixed(1)}%${tag}`);
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

if (import.meta.url === `file://${process.argv[1]}`) main();
