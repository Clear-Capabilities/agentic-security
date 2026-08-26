// FR-906 (assurance-hardening PRD) — peak memory usage, tracked and gated.
//
// Mirrors bench/ttff/runner.mjs's design deliberately — same target (this
// repo's own scanner/src/posture, ~290 modules, always present, no network),
// same wide-tolerance regression-factor gate shape, same
// baseline/history/--check/--update-baseline CLI surface. Two proven metrics
// over the same measurement, not two different designs to maintain.
//
// WHAT IS ACTUALLY MEASURED
// -------------------------
// Peak resident set size (RSS) of THIS process, sampled every 50ms on a
// timer while `runScan()` runs. Node is single-threaded: a sampling timer
// only fires between chunks of synchronous work, so a peak reached entirely
// within one long synchronous stretch with no I/O yield in between could be
// under-measured. Stated rather than hidden — this is a drift tripwire, the
// same honesty bench/self-scan's own README gives its own "not a precision
// figure" limitation. It is not a substitute for a real profiler when
// chasing a specific leak.
//
// WHY THE TOLERANCE IS WIDE
// -------------------------
// Same reasoning as bench/ttff/runner.mjs: RSS is noisy across machines (GC
// timing, allocator behaviour, other processes' memory pressure), so a tight
// threshold fails on noise and a gate that cries wolf gets disabled. This
// fails only on a LARGE regression and records the raw number every run so a
// slow drift is still visible in history.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');
const BASELINE = path.join(HERE, 'BASELINE.json');
const HISTORY = path.join(HERE, 'history.jsonl');

// Same target bench/ttff uses — one representative, always-present, no
// network measurement surface for both benches rather than two.
const TARGET = path.join(REPO, 'scanner', 'src', 'posture');

const REGRESSION_FACTOR = 1.6;
const SAMPLE_INTERVAL_MS = 50;

async function measure() {
  // MANDATORY for any bench runner scanning this repo's own source — see
  // bench/ttff/runner.mjs's identical comment; the tree-integrity guard
  // caught that runner's first CI run writing .agentic-security/ into the
  // very tree other gates baseline against.
  const { disableStateWrites } = await import(path.join(REPO, 'bench', '_lib', 'tree-integrity.mjs'));
  await disableStateWrites();
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));

  let peakRss = process.memoryUsage().rss;
  const timer = setInterval(() => {
    const rss = process.memoryUsage().rss;
    if (rss > peakRss) peakRss = rss;
  }, SAMPLE_INTERVAL_MS);
  timer.unref?.();

  let scan;
  try {
    ({ scan } = await runScan(TARGET));
  } finally {
    clearInterval(timer);
  }
  // One last sample — the peak could land after the final timer tick but
  // before runScan actually resolved.
  const finalRss = process.memoryUsage().rss;
  if (finalRss > peakRss) peakRss = finalRss;

  const findings = (scan.findings || []).length + (scan.logicVulns || []).length;
  return { peakRssMb: Math.round(peakRss / (1024 * 1024)), findings, filesScanned: scan.filesScanned || null };
}

const isCheck = process.argv.includes('--check');
const isUpdate = process.argv.includes('--update-baseline');

const run = await measure();
const record = { ...run, at: new Date().toISOString() };
try { fs.appendFileSync(HISTORY, JSON.stringify(record) + '\n'); } catch { /* history is best-effort */ }

if (isUpdate) {
  fs.writeFileSync(BASELINE, JSON.stringify({
    schema: 'memory/v1',
    note: 'Peak RSS of this process while scanning scanner/src/posture, sampled every 50ms. A drift tripwire, not a precision instrument — see this file\'s own header.',
    target: 'scanner/src/posture',
    regressionFactor: REGRESSION_FACTOR,
    ...run,
    recordedAt: record.at,
  }, null, 1) + '\n');
  console.log(`✓ baseline written — ${run.peakRssMb} MB peak RSS, ${run.findings} findings over ${run.filesScanned} files`);
  process.exit(0);
}

console.log(`peak memory: ${run.peakRssMb} MB RSS (${run.findings} findings, ${run.filesScanned} files)`);

if (!isCheck) process.exit(0);

// Read-first, not existsSync()-then-readFileSync() — the file can vanish
// between those two calls (this session's own D-0012 discipline; this
// same pattern was caught in bench/ttff/runner.mjs, this file's own model,
// and fixed there too).
let baseRaw;
try {
  baseRaw = fs.readFileSync(BASELINE, 'utf8');
} catch {
  console.error('✗ no baseline — run `npm run bench:memory:update-baseline`. An unmeasurable gate is a failure, not a skip.');
  process.exit(1);
}
const base = JSON.parse(baseRaw);
const limit = Math.round(base.peakRssMb * REGRESSION_FACTOR);

if (run.findings !== base.findings) {
  console.log(`  note: findings moved ${base.findings} → ${run.findings} (not a memory signal, not gated)`);
}

if (run.peakRssMb > limit) {
  console.error(`✗ peak memory regressed: ${run.peakRssMb} MB vs baseline ${base.peakRssMb} MB (limit ${limit} MB, ${REGRESSION_FACTOR}×)`);
  console.error('  If this is an accepted cost, re-baseline deliberately and say why in the commit.');
  process.exit(1);
}
console.log(`✓ within budget — ${run.peakRssMb} MB vs baseline ${base.peakRssMb} MB (limit ${limit} MB)`);
