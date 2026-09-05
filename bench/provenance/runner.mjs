// M2 §2.4 — Finding Provenance overhead, measured and gated.
//
// WHAT IS MEASURED
// -----------------
// Wall-clock and peak-RSS for a scan WITH provenance annotation enabled vs.
// the SAME scan with provenance disabled (--no-provenance equivalent, via
// the AGENTIC_SECURITY_NO_PROVENANCE env var — the same lever the CLI's own
// --no-provenance flag uses), on a synthetic git history built fresh each
// iteration so the disk cache starts empty for the COLD arm (the worst case
// a first-time scan on a real repo actually pays). A second, WARM arm then
// re-runs the with-provenance scan against the SAME fixture (same HEAD, same
// files) so the on-disk provenance cache (posture/provenance/cache.js) is hit
// instead of recomputed — FR-PROV-029 requires both cold and warm numbers be
// published, and until this revision only cold (and only a single sample of
// it) ever was.
//
// WHY STATE WRITES ARE NOT DISABLED HERE (unlike ttff/memory/self-scan)
// -----------------------------------------------------------------------
// Those benches scan THIS repository's own tracked source (or a committed
// corpus) and must never let the engine write into the tree being measured —
// see bench/_lib/tree-integrity.mjs's header for the two real incidents that
// module exists to prevent. This bench's "corpus" is different in kind: a
// git fixture built fresh in a private os.tmpdir() directory
// (build-git-fixture.js's createGitFixture()) that exists ONLY for one
// iteration and is fs.rmSync'd by fx.cleanup() before the next one starts —
// nothing here is tracked, committed, or reused across a run. Leaving state
// writes on is what makes the WARM arm possible at all (the provenance cache
// lives under `.agentic-security/provenance-cache/` inside scanRoot and is
// itself gated on state writes being enabled — see cache.js's own header) and
// is also more representative of what a real scan actually costs: a real
// invocation writes last-scan.json and the provenance cache too.
//
// WHY N REPEATED ITERATIONS, NOT ONE SAMPLE
// -------------------------------------------
// A single wall-clock sample is not a p95 (second Finding Provenance audit,
// verbatim). `posture/fix-metrics.js` already established this project's
// precedent for repeated-duration statistics on a real (if different)
// measurement: nearest-rank percentiles (an observed duration, never an
// interpolated one that no run actually took) and a `reliable` flag gated on
// n >= RELIABLE_N = 10. Reused verbatim here rather than inventing a second
// convention — N itself is doubled to 20 for percentile resolution, see the
// `const N` comment below for the measured reason. This bench builds its own
// fixture (45 git commits) per iteration and runs 3 scans (without-provenance
// baseline, cold with-provenance, warm with-provenance); at N=20 total wall
// time is still tens of seconds, which is why this is wired into
// `provenance-gate` in scripts/release-check.mjs (`slow: true`) and
// deliberately NOT into the pre-push gate's tighter ~3 min budget — see root
// CLAUDE.md's "Pre-push gate" cost budget.
//
// WHY A RATIO, NOT A PERCENTAGE
// -------------------------------
// This runner reports overhead as a RATIO (withMs / withoutMs), not a
// percentage. On this tiny synthetic fixture the without-provenance arm is
// dominated by near-floor fixed costs (tens of milliseconds), so a modest,
// roughly constant amount of git-walking work can balloon into a
// large-looking ratio purely because the denominator is small — that is a
// property of THIS fixture's size, not evidence about real-world overhead at
// FR-PROV-029's intended scale (a realistic repo where the baseline scan
// itself runs seconds to minutes). Read this number as a REGRESSION signal
// against ITS OWN prior baseline, never as a literal FR-PROV-029 percentage
// claim on its own — see task-6-report.md for the honest translation to the
// PRD's literal ≤30%/≤20% targets.
//
// GATING PHILOSOPHY (matches bench/ttff/runner.mjs)
// ----------------------------------------------------
// Fails only on a LARGE regression (a wide multiplicative factor) of the p95
// ratio, because wall-clock on a shared machine is noisy even across 10
// samples. Records the raw p95s every run so a slow drift is visible in
// history even when it never trips the gate.
//
// WARM MEMORY OVERHEAD IS RECORDED BUT NOT GATED (Task 8 fix)
// -------------------------------------------------------------
// The Task 6 review found this dimension's gate could not actually fail: at
// the previous baseline (p95 1.19x) the additive-margin limit was 7.90x, so a
// genuine 3-4x regression sailed through — and repeated real measurements
// during this fix swung the ratio itself from 1.1x to 4.96x run-to-run on an
// UNCHANGED engine, purely from noise. The root cause is structural, not a
// badly-chosen constant: the warm arm's own scan is tens of milliseconds, so
// its rssDeltaBytes denominator (the without-provenance arm) is frequently at
// or near the sampler's floor, and a ratio of two near-floor numbers is not a
// stable signal at this fixture's size. `warm.ms`/`warm.rssDeltaBytes` (the
// absolute distributions, not the ratio) are still recorded in
// history.jsonl/BASELINE.json every run — the number is not hidden, it is
// just honestly excluded from `checkDim`, which is a `gatedDimensions: false`
// flag away from being re-enabled if a larger fixture ever makes it stable
// enough to gate for real. See scripts/pre-push-gate.mjs / release-check.mjs
// for the exact declared coverage this note is describing.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');
const BASELINE = path.join(HERE, 'BASELINE.json');
const HISTORY = path.join(HERE, 'history.jsonl');

// Fails only above this multiple of the baseline OVERHEAD RATIO (not the raw
// ms) — see the note above on why wall-clock alone is too noisy to gate
// tightly. A ratio-of-a-ratio tolerance is wide on purpose.
const REGRESSION_FACTOR = 1.6;

// Repeated-measurement sample size and reliability threshold — same values
// and same rationale as posture/fix-metrics.js's RELIABLE_N (see that
// module's header). Kept as a literal here rather than importing fix-metrics
// itself: that module's constant is scoped to the fix-verification-duration
// distribution it owns, and this bench has no other dependency on it.
// N=20, not RELIABLE_N=10: with exactly 10 samples, nearest-rank p95 is
// `ceil(0.95*10)=10` — i.e. the SAME as max(), which makes the reported
// "p95" maximally sensitive to a single noisy outlier iteration (measured
// directly: this bench's cold memory-overhead ratio swung from ~15x to
// 32x+ across otherwise-identical repeated runs at N=10, purely because a
// single one-of-ten iteration was itself an outlier). Doubling to N=20
// makes p95 the 19th-of-20 value instead of the top one, giving the
// percentile actual room to differ from the single worst sample, at the
// cost of roughly 2x this bench's own wall time (still tens of seconds).
//
// N=20 -> 60 (v0.147.4): cold.memOverheadRatio's denominator is the
// without-provenance arm's own RSS delta (measure()'s `if
// (without.rssDeltaBytes > 0)` guard skips the ratio entirely when it
// isn't), and that arm is ~40-60ms — short enough that the SAMPLE_INTERVAL_MS
// peak-RSS poller can genuinely observe zero net growth for it, especially
// on a host with different GC pacing. BASELINE.json's own recorded
// memOverheadRatio.n is 19/20 (one dropped iteration) on whatever machine
// captured it — expected and already within RELIABLE_N's margin. GitHub
// Actions' shared runners drop far more: two consecutive real hosted release
// runs (v0.147.3, v0.147.4) measured only 7/20 and 8/20 usable — a ~35-40%
// survival rate, nowhere near enough headroom over RELIABLE_N=10 at N=20.
// 60 gives an expected ~21-24 usable samples at that same survival rate,
// comfortably clearing 10 with real margin even on a bad draw, at the cost
// of roughly another 2x this bench's wall time on top of the first doubling.
const N = 60;
const RELIABLE_N = 10;
// Finer than bench/memory/runner.mjs's 50ms (same technique, same
// rationale) because the warm arm's own scans are themselves only tens of
// ms — at 50ms a whole warm scan could complete between two timer ticks and
// report a peak no higher than its own starting RSS, undersampling exactly
// the arm this bench most wants a real reading from.
const SAMPLE_INTERVAL_MS = 10;

async function buildFixture() {
  const { createGitFixture } = await import(path.join(REPO, 'scanner', 'test', 'helpers', 'build-git-fixture.js'));
  const fx = createGitFixture();
  // 15 files, each with a small linear history (3 commits: safe -> vulnerable
  // -> touched-again), so provenance has real candidate-commit walks to do —
  // an empty or single-commit fixture would measure nothing.
  for (let i = 0; i < 15; i++) {
    const rel = `file${i}.js`;
    fx.writeFile(rel, 'function h(req){ return safe(req); }\n');
    fx.commit(`add ${rel}`);
    fx.writeFile(rel, `function h(req){ eval(req.body.x${i}); }\n`);
    fx.commit(`introduce eval in ${rel}`);
    fx.writeFile(rel, `function h(req){ eval(req.body.x${i}); } // reviewed\n`);
    fx.commit(`touch ${rel} again`);
  }
  return fx;
}

// One scan against an ALREADY-BUILT fixture — deliberately does not build or
// clean up the fixture itself, so the caller can run this twice against the
// SAME fixture (cold then warm) and have the second call's provenance-cache
// reads actually land on what the first call wrote.
async function scanOnce({ provenance, fx }) {
  // runScan() does NOT forward a `provenance` option to runFullScan — verified
  // by reading runScan.js: its runFullScan() call passes only
  // {fileContents, depFileContents, scanRoot, resume, deep, deepInCi,
  // completeScan}. The real on/off lever the CLI itself uses is the
  // AGENTIC_SECURITY_NO_PROVENANCE env var (engine.js reads it directly to
  // set provenanceCtx.disabled, which short-circuits annotateGitProvenance
  // to a fast stampAll(NOT_AVAILABLE) — the detector pipeline still runs
  // identically either way, isolating exactly the annotator's git-walking
  // cost as "overhead", which is the FR-PROV-029 question). Using this env
  // var (not a fabricated runScan option) means the benchmark measures the
  // real CLI code path, not a synthetic one.
  const prior = process.env.AGENTIC_SECURITY_NO_PROVENANCE;
  if (provenance) delete process.env.AGENTIC_SECURITY_NO_PROVENANCE;
  else process.env.AGENTIC_SECURITY_NO_PROVENANCE = '1';
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
  // Peak RSS sampled during the call, same technique as bench/memory/runner.mjs
  // (its own header explains why: a naive before/after heapUsed delta — what
  // this runner used to do — is dominated by GC timing noise and, per the
  // second Finding Provenance audit, was never even computed for the
  // without-provenance side to make a ratio from at all). Three scans
  // (without/cold/warm) run in this ONE process, so raw peak RSS accumulates
  // across them — what is comparable across arms is the DELTA above this
  // call's own starting RSS, not the raw peak.
  const rssBefore = process.memoryUsage().rss;
  let peakRss = rssBefore;
  const timer = setInterval(() => {
    const rss = process.memoryUsage().rss;
    if (rss > peakRss) peakRss = rss;
  }, SAMPLE_INTERVAL_MS);
  timer.unref?.();
  try {
    const t0 = process.hrtime.bigint();
    const { scan } = await runScan(fx.root, {});
    const t1 = process.hrtime.bigint();
    const rssAfter = process.memoryUsage().rss;
    if (rssAfter > peakRss) peakRss = rssAfter;
    return {
      ms: Number(t1 - t0) / 1e6,
      rssDeltaBytes: Math.max(0, peakRss - rssBefore),
      findings: (scan.findings || []).length,
    };
  } finally {
    clearInterval(timer);
    if (prior === undefined) delete process.env.AGENTIC_SECURITY_NO_PROVENANCE;
    else process.env.AGENTIC_SECURITY_NO_PROVENANCE = prior;
  }
}

// One full iteration: a fresh fixture, a without-provenance baseline scan
// (the ratio denominator — provenance is fully bypassed for this arm, so
// there is no cache for it to hit either way), a cold with-provenance scan
// (empty provenance cache — the fixture was just built), and a warm
// with-provenance scan (same fixture, same HEAD, so every cache key
// makeCacheKey() derives matches what the cold pass just wrote).
async function measureIteration() {
  const fx = await buildFixture();
  try {
    const without = await scanOnce({ provenance: false, fx });
    const cold = await scanOnce({ provenance: true, fx });
    const warm = await scanOnce({ provenance: true, fx });
    return { without, cold, warm };
  } finally {
    fx.cleanup();
  }
}

// Nearest-rank percentile over an ascending array — same formula as
// posture/fix-metrics.js's `_pct`: nearest-rank, not interpolated, because
// these are observed durations/bytes and an interpolated p95 would report a
// value no run actually produced.
function pct(sorted, p) {
  if (!sorted.length) return null;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))];
}

function dist(values) {
  const v = values.filter((x) => typeof x === 'number' && Number.isFinite(x) && x >= 0).sort((a, b) => a - b);
  if (!v.length) return { n: 0, min: null, p50: null, p95: null, max: null, mean: null, reliable: false };
  const sum = v.reduce((a, b) => a + b, 0);
  return {
    n: v.length,
    min: v[0],
    p50: pct(v, 50),
    p95: pct(v, 95),
    max: v[v.length - 1],
    mean: sum / v.length,
    reliable: v.length >= RELIABLE_N,
  };
}

function round2(x) { return x == null ? null : Math.round(x * 100) / 100; }
function roundDist(d) {
  return { n: d.n, min: round2(d.min), p50: round2(d.p50), p95: round2(d.p95), max: round2(d.max), mean: round2(d.mean), reliable: d.reliable };
}

async function measure() {
  const samples = { without: { ms: [], rss: [] }, cold: { ms: [], rss: [], timeRatio: [], memRatio: [] }, warm: { ms: [], rss: [], timeRatio: [], memRatio: [] } };
  let findings = null;
  for (let i = 0; i < N; i++) {
    const { without, cold, warm } = await measureIteration();
    findings = cold.findings;
    samples.without.ms.push(without.ms);
    samples.without.rss.push(without.rssDeltaBytes);
    samples.cold.ms.push(cold.ms);
    samples.cold.rss.push(cold.rssDeltaBytes);
    samples.warm.ms.push(warm.ms);
    samples.warm.rss.push(warm.rssDeltaBytes);
    // Per-iteration ratio (not ratio-of-aggregates) so the cold/warm pass and
    // the without-provenance pass that same iteration's ratio is built from
    // share the SAME fixture instance and the same moment on the host —
    // pairing this way cancels a good deal of shared machine noise (thermal
    // state, other processes) that an aggregate-of-aggregates ratio would not.
    if (without.ms > 0) {
      samples.cold.timeRatio.push(cold.ms / without.ms);
      samples.warm.timeRatio.push(warm.ms / without.ms);
    }
    if (without.rssDeltaBytes > 0) {
      samples.cold.memRatio.push(cold.rssDeltaBytes / without.rssDeltaBytes);
      samples.warm.memRatio.push(warm.rssDeltaBytes / without.rssDeltaBytes);
    }
  }
  return {
    n: N,
    findings,
    without: { ms: dist(samples.without.ms), rssDeltaBytes: dist(samples.without.rss) },
    cold: {
      ms: dist(samples.cold.ms),
      rssDeltaBytes: dist(samples.cold.rss),
      timeOverheadRatio: dist(samples.cold.timeRatio),
      memOverheadRatio: dist(samples.cold.memRatio),
    },
    warm: {
      ms: dist(samples.warm.ms),
      rssDeltaBytes: dist(samples.warm.rss),
      timeOverheadRatio: dist(samples.warm.timeRatio),
      memOverheadRatio: dist(samples.warm.memRatio),
    },
  };
}

function roundRun(run) {
  return {
    n: run.n,
    findings: run.findings,
    without: { ms: roundDist(run.without.ms), rssDeltaBytes: roundDist(run.without.rssDeltaBytes) },
    cold: {
      ms: roundDist(run.cold.ms),
      rssDeltaBytes: roundDist(run.cold.rssDeltaBytes),
      timeOverheadRatio: roundDist(run.cold.timeOverheadRatio),
      memOverheadRatio: roundDist(run.cold.memOverheadRatio),
    },
    warm: {
      ms: roundDist(run.warm.ms),
      rssDeltaBytes: roundDist(run.warm.rssDeltaBytes),
      timeOverheadRatio: roundDist(run.warm.timeOverheadRatio),
      memOverheadRatio: roundDist(run.warm.memOverheadRatio),
    },
  };
}

const isCheck = process.argv.includes('--check');
const isUpdate = process.argv.includes('--update-baseline');

const rawRun = await measure();
const run = roundRun(rawRun);
const record = { ...run, at: new Date().toISOString() };
try { fs.appendFileSync(HISTORY, JSON.stringify(record) + '\n'); } catch { /* history is best-effort */ }

function summaryLine(label, d) {
  return `${label}: p50 ${d.timeOverheadRatio.p50}x / p95 ${d.timeOverheadRatio.p95}x time` +
    ` (${d.ms.p50}ms with, ${run.without.ms.p50}ms without), ` +
    `mem p50 ${d.memOverheadRatio.p50}x / p95 ${d.memOverheadRatio.p95}x`;
}

if (isUpdate) {
  fs.writeFileSync(BASELINE, JSON.stringify({
    schema: 'provenance/v3',
    note: 'Wall-clock and peak-RSS overhead of provenance annotation vs. a provenance-disabled scan, on a ' +
      'synthetic 15-file/3-commit-each git fixture. cold = fresh provenance cache; warm = second with-provenance ' +
      'pass against the same fixture/HEAD, so the on-disk provenance cache is hit. Each dimension is a ' +
      `distribution over n=${N} iterations (nearest-rank percentiles, matching posture/fix-metrics.js's ` +
      'convention); the gated number is the p95 of the per-iteration ratio, not a single sample. GATED: ' +
      'cold.timeOverheadRatio, warm.timeOverheadRatio, cold.memOverheadRatio, each at a plain ' +
      `${REGRESSION_FACTOR}x-of-baseline-p95 limit (no additive margin — Task 8 removed it once repeated real ` +
      'runs showed cold memory ratio holds within ~12% of its own baseline, so a pure multiplicative factor is ' +
      'already wide enough to avoid noise-only failures while still catching a genuine ~2x regression). NOT ' +
      'GATED: warm.memOverheadRatio — still measured and recorded every run, but its own run-to-run noise ' +
      '(observed 0x-5x+ on an unchanged engine, because the warm arm\'s scan is tens of ms and its ratio ' +
      'denominator sits at or near the sampler\'s floor) makes it unfalsifiable at this fixture size; a gate ' +
      'that cannot fail advertises coverage it does not have, so it is honestly excluded instead of padded ' +
      'with a margin wide enough to never trip. Every checkDim\'d dimension also requires `reliable: true` ' +
      `(n >= ${RELIABLE_N}) — an unreliable sample size fails the gate rather than silently comparing too few ` +
      'points. See runner.mjs for the full reasoning (Task 6 review; Task 8 fix).',
    regressionFactor: REGRESSION_FACTOR,
    ...run,
    recordedAt: record.at,
  }, null, 1) + '\n');
  console.log(`✓ baseline written — ${summaryLine('cold', run.cold)}`);
  console.log(`               and — ${summaryLine('warm', run.warm)}`);
  process.exit(0);
}

console.log(`provenance overhead (n=${run.n}, ${run.findings} findings):`);
console.log(`  ${summaryLine('cold', run.cold)}`);
console.log(`  ${summaryLine('warm', run.warm)}`);

if (!isCheck) process.exit(0);

let baseRaw;
try {
  baseRaw = fs.readFileSync(BASELINE, 'utf8');
} catch {
  console.error('✗ no baseline — run `npm run bench:provenance:update-baseline`. An unmeasurable gate is a failure, not a skip.');
  process.exit(1);
}
const base = JSON.parse(baseRaw);
if (base.schema !== 'provenance/v3') {
  console.error(`✗ baseline schema is ${JSON.stringify(base.schema)}, expected 'provenance/v3' — ` +
    're-baseline with `npm run bench:provenance:update-baseline` after the schema change (Task 8: ' +
    'warm memory overhead is no longer gated, and cold memory overhead dropped its additive margin — ' +
    'see this file\'s header).');
  process.exit(1);
}

// Task 8 fix #2 (Task 6 review, second finding): `checkDim` used to only
// treat n=0 (p95 === null) as unscoreable. The memory-ratio arrays are
// conditionally populated (`if (without.rssDeltaBytes > 0)` above), so their
// `n` could fall below RELIABLE_N without any signal — the gate would
// silently compare single samples while claiming the same coverage as a
// dimension backed by all N=20 iterations. `dist()` already computes
// `reliable` (n >= RELIABLE_N, same convention as posture/fix-metrics.js);
// this is now actually consulted.
let failed = false;
function checkDim(label, runDist, baseDist) {
  if (!runDist.reliable) {
    console.error(`✗ ${label}: only ${runDist.n}/${N} iterations produced a usable sample ` +
      `(need >= ${RELIABLE_N}) — an unreliable sample size is a failure, not a pass.`);
    failed = true;
    return;
  }
  if (runDist.p95 == null || baseDist.p95 == null) {
    console.error(`✗ ${label} p95 could not be computed (a divide-by-near-zero denominator) — treat as a failure, not a pass.`);
    failed = true;
    return;
  }
  const limit = Math.round((baseDist.p95 * REGRESSION_FACTOR) * 100) / 100;
  if (runDist.p95 > limit) {
    console.error(`✗ ${label} regressed: p95 ${runDist.p95}x vs baseline p95 ${baseDist.p95}x (limit ${limit}x, ${REGRESSION_FACTOR}×)`);
    console.error('  If this is an accepted cost, re-baseline deliberately and say why in the commit.');
    failed = true;
  } else {
    console.log(`✓ ${label} within budget — p95 ${runDist.p95}x vs baseline p95 ${baseDist.p95}x (limit ${limit}x)`);
  }
}

checkDim('cold time overhead', run.cold.timeOverheadRatio, base.cold.timeOverheadRatio);
checkDim('warm time overhead', run.warm.timeOverheadRatio, base.warm.timeOverheadRatio);
checkDim('cold memory overhead', run.cold.memOverheadRatio, base.cold.memOverheadRatio);
// warm memory overhead is DELIBERATELY NOT GATED — see the "WARM MEMORY
// OVERHEAD IS RECORDED BUT NOT GATED" note at the top of this file. It is
// still measured and appended to history.jsonl/BASELINE.json every run.
console.log(`  (warm memory overhead: p95 ${run.warm.memOverheadRatio.p95 == null ? 'n/a' : run.warm.memOverheadRatio.p95 + 'x'} ` +
  `recorded, NOT gated — ratio is unfalsifiable at this fixture size, see runner.mjs header)`);

if (failed) process.exit(1);
