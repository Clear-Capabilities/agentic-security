// M2 §2.4 — Finding Provenance overhead, measured and gated.
//
// WHAT IS MEASURED
// -----------------
// Wall-clock and peak memory for a scan WITH provenance annotation enabled
// vs. the SAME scan with provenance disabled (--no-provenance equivalent,
// via the AGENTIC_SECURITY_NO_PROVENANCE env var — the same lever the CLI's
// own --no-provenance flag uses), on a synthetic git history built
// fresh each run so the disk cache starts empty (cold — the worst case a
// first-time scan on a real repo actually pays).
//
// WHY A SYNTHETIC HISTORY, NOT THIS REPO'S OWN
// ----------------------------------------------
// This repo's own history is enormous and its shape (10000+ commits) is not
// representative of what a typical scanned project looks like, and re-scanning
// it makes the benchmark itself slow to run in CI. A small, deliberately-sized
// synthetic history (build-git-fixture.js, already used by the provenance unit
// tests) gives a fixture whose finding count and candidate-commit depth are
// both known and stable across runs.
//
// GATING PHILOSOPHY (matches bench/ttff/runner.mjs)
// ----------------------------------------------------
// Fails only on a LARGE regression (a wide multiplicative factor), because
// wall-clock on a shared machine is noisy. Records the raw ratio every run so
// a slow drift is visible in history even when it never trips the gate.
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

async function measureOnce({ provenance }) {
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
  const fx = await buildFixture();
  try {
    const t0 = process.hrtime.bigint();
    const memBefore = process.memoryUsage().heapUsed;
    const { scan } = await runScan(fx.root, {});
    const memAfter = process.memoryUsage().heapUsed;
    const t1 = process.hrtime.bigint();
    return {
      ms: Number(t1 - t0) / 1e6,
      heapDeltaBytes: Math.max(0, memAfter - memBefore),
      findings: (scan.findings || []).length,
    };
  } finally {
    fx.cleanup();
    if (prior === undefined) delete process.env.AGENTIC_SECURITY_NO_PROVENANCE;
    else process.env.AGENTIC_SECURITY_NO_PROVENANCE = prior;
  }
}

async function measure() {
  const { disableStateWrites } = await import(path.join(REPO, 'bench', '_lib', 'tree-integrity.mjs'));
  await disableStateWrites();
  const withProvenance = await measureOnce({ provenance: true });
  const withoutProvenance = await measureOnce({ provenance: false });
  const overheadRatio = withoutProvenance.ms > 0 ? withProvenance.ms / withoutProvenance.ms : null;
  return {
    withProvenanceMs: Math.round(withProvenance.ms),
    withoutProvenanceMs: Math.round(withoutProvenance.ms),
    overheadRatio: overheadRatio != null ? Math.round(overheadRatio * 100) / 100 : null,
    withProvenanceHeapDeltaBytes: withProvenance.heapDeltaBytes,
    findings: withProvenance.findings,
  };
}

const isCheck = process.argv.includes('--check');
const isUpdate = process.argv.includes('--update-baseline');

const run = await measure();
const record = { ...run, at: new Date().toISOString() };
try { fs.appendFileSync(HISTORY, JSON.stringify(record) + '\n'); } catch { /* history is best-effort */ }

if (isUpdate) {
  fs.writeFileSync(BASELINE, JSON.stringify({
    schema: 'provenance/v1',
    note: 'Wall-clock overhead of provenance annotation vs. a provenance-disabled scan, on a synthetic 15-file/3-commit-each git fixture, cold cache. See runner.mjs header for why the number is a RATIO, not an absolute FR-PROV-029 percentage claim.',
    regressionFactor: REGRESSION_FACTOR,
    ...run,
    recordedAt: record.at,
  }, null, 1) + '\n');
  console.log(`✓ baseline written — overhead ratio ${run.overheadRatio}x (${run.withProvenanceMs}ms vs ${run.withoutProvenanceMs}ms)`);
  process.exit(0);
}

console.log(`provenance overhead: ${run.overheadRatio}x (${run.withProvenanceMs}ms with, ${run.withoutProvenanceMs}ms without, ${run.findings} findings)`);

if (!isCheck) process.exit(0);

let baseRaw;
try {
  baseRaw = fs.readFileSync(BASELINE, 'utf8');
} catch {
  console.error('✗ no baseline — run `npm run bench:provenance:update-baseline`. An unmeasurable gate is a failure, not a skip.');
  process.exit(1);
}
const base = JSON.parse(baseRaw);
if (run.overheadRatio == null || base.overheadRatio == null) {
  console.error('✗ overheadRatio could not be computed (a divide-by-near-zero denominator) — treat as a failure, not a pass.');
  process.exit(1);
}
const limit = Math.round(base.overheadRatio * REGRESSION_FACTOR * 100) / 100;

if (run.overheadRatio > limit) {
  console.error(`✗ provenance overhead regressed: ${run.overheadRatio}x vs baseline ${base.overheadRatio}x (limit ${limit}x, ${REGRESSION_FACTOR}×)`);
  console.error('  If this is an accepted cost, re-baseline deliberately and say why in the commit.');
  process.exit(1);
}
console.log(`✓ within budget — ${run.overheadRatio}x vs baseline ${base.overheadRatio}x (limit ${limit}x)`);
