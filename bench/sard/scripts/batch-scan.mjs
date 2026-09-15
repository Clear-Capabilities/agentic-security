#!/usr/bin/env node
// PRD W0.3 (SARD_80_F1_EXECUTION_PRD.md) — batch corpus scanning per CWE
// directory, so no single scan approaches the deep engine's global timeout
// budget (AGENTIC_SECURITY_DEEP_TIMEOUT_MS, default 300s). Confirmed this
// session: even after W0.4 cut the Java dev-split scan surface from 112 to
// 18 CWE directories, a single --deep run still hit the budget (530.7s
// elapsed, 300s budget) and correctly reported truncated:true.
//
// Runs bench-realworld.js once per CWE the app's gold set covers, using its
// OWN --cwe flag (which already scopes both GT construction and the scan
// surface to exactly that one directory — see that flag's header comment in
// bench-realworld.js). Each batch is a small fraction of the corpus, so it
// comfortably fits inside the deep budget even where the whole surface does
// not. Collects every batch's single-CWE result and aggregates them into ONE
// combined result object with the SAME SHAPE bench-realworld.js itself
// produces, so it slots into the identical `| macro-score.mjs` pipeline
// unchanged. This also makes a full run agree with the `--cwe` smoke subset
// by construction — the smoke subset is a strict prefix of these same
// batches, run the same way.
//
// No answer-key signals: this is pure orchestration over bench-realworld.js
// and its own existing --cwe/--list-cwes machinery. It reads no comment,
// filename, or bench-shape heuristic that bench-realworld.js itself doesn't
// already read for the exact same purpose.
//
// Usage:
//   node batch-scan.mjs --app sard-juliet-java-strict --blind \
//     --scramble-identifiers --deep --split dev --json \
//     | node macro-score.mjs
//
// Any flag bench-realworld.js accepts (other than --app, --json, --cwe,
// --list-cwes, which this script owns) is forwarded verbatim to every child.

import * as fsSync from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REALWORLD = path.join(HERE, '..', '..', '..', 'scanner', 'test', 'benchmark', 'realworld', 'bench-realworld.js');

const argv = process.argv.slice(2);
function flag(name) { return argv.includes(name); }
function value(name) { const i = argv.indexOf(name); return i !== -1 ? argv[i + 1] : null; }

const APP = value('--app');
const JSON_OUT = flag('--json');
const ALLOW_TRUNCATION = flag('--allow-truncation');

if (!APP) {
  console.error('Usage: batch-scan.mjs --app <name> [--blind] [--scramble-identifiers] [--deep] [--split train|dev|test] [--json] [--allow-truncation]');
  process.exit(2);
}

// Forwarded verbatim to every child (both the --list-cwes discovery call and
// each per-CWE batch) — everything the caller passed except --app and this
// script's own --json (every child always runs --json so its output is
// parseable; a human-readable summary, if requested, is this script's job).
const passthrough = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--app') { i++; continue; }
  if (a === '--json') continue;
  passthrough.push(a);
}

// Mirrors bench-realworld.js's own runOneIsolated(): stdout goes straight to
// a file, not a pipe — a single CWE's JSON is small, but the discipline
// (never trust a default pipe buffer with benchmark JSON) is cheap to keep
// uniform across both scripts.
function runChild(args) {
  const outPath = path.join(os.tmpdir(), `batch-scan-${process.pid}-${Math.random().toString(36).slice(2)}.json`);
  const fd = fsSync.openSync(outPath, 'w');
  try {
    const r = cp.spawnSync(process.execPath, [REALWORLD, ...args], { stdio: ['ignore', fd, 'pipe'], encoding: 'utf8', maxBuffer: 1024 * 1024 * 200 });
    if (r.stderr) process.stderr.write(r.stderr);
    if (r.status !== 0 || r.signal) return { error: `exited ${r.status} signal ${r.signal}`, raw: null };
    return { error: null, raw: fsSync.readFileSync(outPath, 'utf8') };
  } finally {
    try { fsSync.closeSync(fd); } catch { /* already closed */ }
    try { fsSync.unlinkSync(outPath); } catch { /* best effort */ }
  }
}

function main() {
  console.error(`  batch-scan: discovering CWEs covered by ${APP}'s gold set (--list-cwes, no scan)...`);
  const listRes = runChild(['--app', APP, ...passthrough, '--list-cwes']);
  if (listRes.error) { console.error(`✗ --list-cwes failed: ${listRes.error}`); process.exit(1); }
  let cwes, expectedTotal;
  try { ({ cwes, expectedTotal } = JSON.parse(listRes.raw)); }
  catch (e) { console.error(`✗ --list-cwes produced unparseable output: ${e.message}`); process.exit(1); }
  if (!cwes.length) { console.error(`✗ ${APP}: gold set covers zero CWEs — nothing to batch`); process.exit(1); }
  console.error(`  batch-scan: ${cwes.length} CWE(s) to scan one at a time (gold covers ${expectedTotal} expected entries total): ${cwes.join(',')}`);

  const batches = [];
  let failedBatches = 0;
  for (const cwe of cwes) {
    console.error(`  batch-scan: scanning CWE-${cwe} (${batches.length + failedBatches + 1}/${cwes.length})...`);
    const t0 = Date.now();
    // --allow-truncation on the CHILD: a batch that itself truncates should
    // still report its (honest, truncated) numbers so the aggregate below
    // can see them — the FAIL-CLOSED decision belongs to whoever owns the
    // final combined result (this script), not to an individual batch. Same
    // principle bench-realworld.js's own AGENTIC_SECURITY_BENCH_CHILD guard
    // uses for isolated per-app children.
    const res = runChild(['--app', APP, ...passthrough, '--cwe', cwe, '--json', '--allow-truncation']);
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    if (res.error) { console.error(`  ✗ CWE-${cwe} batch failed: ${res.error} (${elapsed}s)`); failedBatches++; continue; }
    let doc;
    try { doc = JSON.parse(res.raw); }
    catch (e) { console.error(`  ✗ CWE-${cwe} batch produced unparseable JSON: ${e.message}`); failedBatches++; continue; }
    const r = doc.results && doc.results[0];
    if (!r) { console.error(`  ✗ CWE-${cwe} batch produced no result`); failedBatches++; continue; }
    console.error(`    CWE-${cwe}: tp=${r.tp} fp=${r.fp} fn=${r.fn} (${elapsed}s${r.truncated ? ', TRUNCATED' : ''})`);
    batches.push(r);
  }

  // Aggregate every batch's single-CWE result into ONE combined result with
  // the same shape bench-realworld.js's own runOne() produces, so it is
  // indistinguishable from a single-shot result to every downstream
  // consumer (macro-score.mjs, the ledger, the dashboard).
  const combined = {
    name: APP, language: batches[0]?.language || null,
    tp: 0, fp: 0, fn: 0, scanned: 0, expectedTotal: 0,
    scannedFiles: 0, expectedFiles: 0, elapsedSec: 0, peakRssMb: 0,
    perCwe: {}, tps: [], fps: [], fns: [],
    truncated: failedBatches > 0,
    truncationDetail: { filesTimedOut: 0, filesSkipped: 0, filesDenseSkipped: 0, deepBudgetExceeded: false, fnLimitExceeded: false, failedBatches },
  };
  for (const r of batches) {
    combined.tp += r.tp || 0; combined.fp += r.fp || 0; combined.fn += r.fn || 0;
    combined.scanned += r.scanned || 0; combined.expectedTotal += r.expectedTotal || 0;
    combined.scannedFiles += r.scannedFiles || 0; combined.expectedFiles += r.expectedFiles || 0;
    combined.elapsedSec += r.elapsedSec || 0;
    combined.peakRssMb = Math.max(combined.peakRssMb, r.peakRssMb || 0);
    // SUM per-CWE counters, never overwrite: bench-realworld.js bumps an FP
    // row under the FINDING'S OWN claimed CWE (reportedCwe), not the CWE
    // directory being scanned — so a batch scoped to CWE-643 can still
    // contribute FP counts under CWE-79/CWE-918/etc "spillover" keys, and
    // more than one batch can legitimately touch the SAME spillover key.
    // `Object.assign` would silently drop every batch's contribution but the
    // last for any key two batches share — found by comparing a batch's own
    // logged tp/fp/fn against its perCwe breakdown during W0.3 verification.
    for (const [cwe, c] of Object.entries(r.perCwe || {})) {
      const acc = combined.perCwe[cwe] || (combined.perCwe[cwe] = { tp: 0, fp: 0, fn: 0 });
      acc.tp += c.tp || 0; acc.fp += c.fp || 0; acc.fn += c.fn || 0;
    }
    combined.tps.push(...(r.tps || []));
    combined.fps.push(...(r.fps || []));
    combined.fns.push(...(r.fns || []));
    if (r.truncated) {
      combined.truncated = true;
      const d = r.truncationDetail || {};
      combined.truncationDetail.filesTimedOut += d.filesTimedOut || 0;
      combined.truncationDetail.filesSkipped += d.filesSkipped || 0;
      combined.truncationDetail.filesDenseSkipped += d.filesDenseSkipped || 0;
      combined.truncationDetail.deepBudgetExceeded = combined.truncationDetail.deepBudgetExceeded || !!d.deepBudgetExceeded;
      combined.truncationDetail.fnLimitExceeded = combined.truncationDetail.fnLimitExceeded || !!d.fnLimitExceeded;
    }
  }
  combined.precision = (combined.tp + combined.fp) === 0 ? 1 : combined.tp / (combined.tp + combined.fp);
  combined.recall = (combined.tp + combined.fn) === 0 ? 1 : combined.tp / (combined.tp + combined.fn);
  combined.f1 = (combined.precision + combined.recall) === 0 ? 0 : (2 * combined.precision * combined.recall) / (combined.precision + combined.recall);
  combined.elapsedSec = Math.round(combined.elapsedSec * 10) / 10;

  if (JSON_OUT) {
    console.log(JSON.stringify({ results: [combined] }));
  } else {
    console.log(`\n${APP}: TP=${combined.tp} FP=${combined.fp} FN=${combined.fn}  P=${(combined.precision * 100).toFixed(1)}%  R=${(combined.recall * 100).toFixed(1)}%  F1=${(combined.f1 * 100).toFixed(1)}%  (${batches.length}/${cwes.length} batches ok, ${combined.elapsedSec}s total across batches)`);
  }

  if (combined.truncated && !ALLOW_TRUNCATION) {
    console.error(`\n✗ batch-scan: at least one CWE batch truncated or failed (${failedBatches} failed outright) — refusing to report this as a valid measurement. Pass --allow-truncation to accept anyway.`);
    process.exitCode = 1;
  }
}

main();
