#!/usr/bin/env node
// PRD Epic 5 — the fleet CLI.
//
// Everything runs here, on the operator's machine. No server, no account, no
// hosting: the rollup is a static file generated from local artifacts. That
// constraint is the product's identity (PRD §2.2, §10), and a fleet command is
// exactly where it would erode.
//
// Usage:
//   node scripts/fleet.mjs --repos <file|dir> [options]
//
//   --repos <path>     A file listing one repo path per line, OR a directory
//                      whose immediate subdirectories are each a repo.
//   --concurrency <n>  Parallel repos (default 4, capped at 32).
//   --state <path>     Checkpoint file (default .agentic-security/fleet-state.json
//                      in the CWD — deliberately OUTSIDE the scanned repos).
//   --previous <path>  A prior --json output, to compute what is new since then.
//   --json <path>      Write the full result set.
//   --html <path>      Write the offline rollup page.
//   --no-resume        Rescan repos the checkpoint says are done.
//   --fail-on <sev>    Exit 1 if any repo has a finding at or above this severity.
//
// Exit codes: 0 clean, 1 --fail-on threshold met, 2 usage/IO error.
// A repo that FAILED to scan always contributes to a non-zero exit — an
// unscanned repo is unknown, not clean.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

const { runFleet, renderFleetHtml, renderFleetSummary } =
  await import(path.join(REPO, 'scanner', 'src', 'posture', 'fleet.js'));
const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));

// STATE_SEAM_COMPLETION_PRD M3 — placed immediately after the runScan import,
// BEFORE anything can scan. Inserting it after the last top-level statement
// (the first attempt) put it after the scan in attest-fixture.mjs, so the
// fixture was still littered. Placement, not presence, is what matters.
const { disableStateWrites } = await import('../bench/_lib/tree-integrity.mjs');
await disableStateWrites();

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')
    ? process.argv[i + 1] : fallback;
}
const has = (name) => process.argv.includes(`--${name}`);

const reposArg = arg('repos');
if (!reposArg) {
  process.stderr.write('usage: fleet.mjs --repos <file|dir> [--concurrency n] [--json out] [--html out]\n');
  process.exit(2);
}

// Resolve the repo list. A listing file and a parent directory are the two
// shapes people actually have; a GitHub org enumeration would require network
// and credentials, so it is left to the caller to produce a list.
let repos = [];
try {
  // Attempt the directory read FIRST and let it fail, rather than stat-then-use.
  // The check-then-use form is CWE-367 (TOCTOU) and this project's own engine
  // flags it — it did, on this file. `withFileTypes` also removes the per-entry
  // stat, so there is exactly one syscall per decision.
  let entries = null;
  try { entries = fs.readdirSync(reposArg, { withFileTypes: true }); } catch { entries = null; }
  if (entries) {
    repos = entries.filter(e => e.isDirectory()).map(e => path.join(reposArg, e.name));
  } else {
    repos = fs.readFileSync(reposArg, 'utf8').split('\n')
      .map(l => l.replace(/#.*$/, '').trim()).filter(Boolean);
  }
} catch (e) {
  process.stderr.write(`could not read --repos ${reposArg}: ${e.message}\n`);
  process.exit(2);
}
if (!repos.length) {
  process.stderr.write(`no repositories found via --repos ${reposArg}\n`);
  process.exit(2);
}

let previous = null;
const prevPath = arg('previous');
if (prevPath) {
  try { previous = JSON.parse(fs.readFileSync(prevPath, 'utf8')); }
  catch (e) {
    // Refused rather than ignored: silently dropping the baseline would report
    // every existing finding as new, which is the opposite of useful.
    process.stderr.write(`could not read --previous ${prevPath}: ${e.message}\n`);
    process.exit(2);
  }
}

const stateFile = path.resolve(arg('state', path.join(process.cwd(), '.agentic-security', 'fleet-state.json')));
const concurrency = Number(arg('concurrency', '4')) || 4;

process.stderr.write(`fleet: ${repos.length} repo(s), concurrency ${concurrency}\n`);

const res = await runFleet({
  repos, concurrency, stateFile, runScan, previous,
  resume: !has('no-resume'),
  onProgress: (e) => process.stderr.write(
    e.ok ? `  ok    ${e.repo} — ${e.total} finding(s)\n` : `  FAIL  ${e.repo} — ${e.error}\n`),
});

if (!res.ok) { process.stderr.write(`fleet failed: ${res.reason}\n`); process.exit(2); }

process.stdout.write('\n' + (renderFleetSummary(res.rollup) || '') + '\n');

const jsonOut = arg('json');
if (jsonOut) {
  fs.mkdirSync(path.dirname(path.resolve(jsonOut)), { recursive: true });
  fs.writeFileSync(jsonOut, JSON.stringify({ rollup: res.rollup, results: res.results }, null, 2));
  process.stderr.write(`wrote ${jsonOut}\n`);
}
const htmlOut = arg('html');
if (htmlOut) {
  fs.mkdirSync(path.dirname(path.resolve(htmlOut)), { recursive: true });
  fs.writeFileSync(htmlOut, renderFleetHtml(res.rollup, res.results));
  process.stderr.write(`wrote ${htmlOut}\n`);
}

// A repo that could not be scanned is unknown, not clean — it must never exit 0
// silently, or a broken fleet run reads as a passing one.
if (res.rollup.failed > 0) {
  process.stderr.write(`\n${res.rollup.failed} repo(s) failed to scan — their findings are UNKNOWN, not zero.\n`);
  process.exit(1);
}

const failOn = (arg('fail-on') || '').toLowerCase();

if (failOn) {
  const order = ['info', 'low', 'medium', 'high', 'critical'];
  const idx = order.indexOf(failOn);
  if (idx === -1) { process.stderr.write(`unknown --fail-on severity: ${failOn}\n`); process.exit(2); }
  const hit = order.slice(idx).reduce((n, s) => n + (res.rollup.bySeverity[s] || 0), 0);
  if (hit > 0) {
    process.stderr.write(`\n${hit} finding(s) at or above ${failOn} — failing per --fail-on.\n`);
    process.exit(1);
  }
}
process.exit(0);
