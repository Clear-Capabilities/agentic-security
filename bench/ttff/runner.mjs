// PRD F11.2 — time-to-first-finding, tracked and gated.
//
// WHY THIS METRIC
// ---------------
// The ICP is vibecoder-first (docs/POSITIONING.md). For that user the binding
// constraint is how long until the FIRST useful result, not aggregate F1. A
// scanner that is 3 points more accurate and twice as slow is worse for them.
//
// WHAT IS ACTUALLY MEASURED
// -------------------------
// This engine is batch, not streaming: findings are returned when the scan
// completes, so time-to-FIRST-finding equals time-to-ALL-findings today. That is
// stated rather than hidden, because the metric name promises something a
// streaming engine would deliver differently. If streaming ever lands, this
// runner measures the real thing without changing its name.
//
// COLD CACHE, on purpose. A warm OSV/KEV cache and warm module resolution hide
// exactly the latency a first-time user experiences.
//
// WHY THE TOLERANCE IS WIDE
// -------------------------
// Wall-clock on a developer laptop or a shared CI runner is noisy: other
// processes, thermal state and disk cache all move it by tens of percent. A
// tight threshold would fail on noise, and a gate that cries wolf gets disabled
// — which is worse than no gate. So this fails only on a LARGE regression, and
// records the raw number every run so a slow drift is still visible in history.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');
const BASELINE = path.join(HERE, 'BASELINE.json');
const HISTORY = path.join(HERE, 'history.jsonl');

// The target is this repo's own scanner/src: ~290 modules, real code, always
// present, and no network needed to obtain it.
const TARGET = path.join(REPO, 'scanner', 'src', 'posture');

// Fails only above this multiple of the baseline. See the note above.
const REGRESSION_FACTOR = 1.6;

async function measure() {
  // MANDATORY for any bench runner: a scan writes .agentic-security/ into the
  // tree it scanned. For this bench the target is scanner/src/posture — this
  // repo's OWN source — so a stray state dir would land in the working tree and
  // pollute the very self-scan baseline other gates depend on. The tree-integrity
  // guard exists precisely for this and caught this runner on its first CI run.
  const { disableStateWrites } = await import(path.join(REPO, 'bench', '_lib', 'tree-integrity.mjs'));
  await disableStateWrites();
  // Cold cache: a fresh module registry per run is the closest we get without
  // spawning, and the state dir is not reused.
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
  const t0 = process.hrtime.bigint();
  const { scan } = await runScan(TARGET);
  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  const findings = (scan.findings || []).length + (scan.logicVulns || []).length;
  return { ms: Math.round(ms), findings, filesScanned: scan.filesScanned || null };
}

const isCheck = process.argv.includes('--check');
const isUpdate = process.argv.includes('--update-baseline');

const run = await measure();
// Timestamp is stamped AFTER measuring so it never influences the measurement,
// and the history line is appended on every run — including a failing one, so a
// regression leaves a trace rather than only an exit code.
const record = { ...run, at: new Date().toISOString() };
try { fs.appendFileSync(HISTORY, JSON.stringify(record) + '\n'); } catch { /* history is best-effort */ }

if (isUpdate) {
  fs.writeFileSync(BASELINE, JSON.stringify({
    schema: 'ttff/v1',
    note: 'Time-to-first-finding on a cold cache. This engine is batch, so this equals time-to-all-findings today.',
    target: 'scanner/src/posture',
    regressionFactor: REGRESSION_FACTOR,
    ...run,
    recordedAt: record.at,
  }, null, 1) + '\n');
  console.log(`✓ baseline written — ${run.ms} ms, ${run.findings} findings over ${run.filesScanned} files`);
  process.exit(0);
}

console.log(`time-to-first-finding: ${run.ms} ms (${run.findings} findings, ${run.filesScanned} files)`);

if (!isCheck) process.exit(0);

// Read-first, not existsSync()-then-readFileSync() — the file can vanish
// between those two calls (this session's own D-0012 discipline).
let baseRaw;
try {
  baseRaw = fs.readFileSync(BASELINE, 'utf8');
} catch {
  console.error('✗ no baseline — run `npm run bench:ttff:update-baseline`. An unmeasurable gate is a failure, not a skip.');
  process.exit(1);
}
const base = JSON.parse(baseRaw);
const limit = Math.round(base.ms * REGRESSION_FACTOR);

// A finding-count change is reported but does NOT fail: this gate is about
// latency. Coupling it to detection would make every legitimate rule addition
// look like a performance regression.
if (run.findings !== base.findings) {
  console.log(`  note: findings moved ${base.findings} → ${run.findings} (not a latency signal, not gated)`);
}

if (run.ms > limit) {
  console.error(`✗ time-to-first-finding regressed: ${run.ms} ms vs baseline ${base.ms} ms (limit ${limit} ms, ${REGRESSION_FACTOR}×)`);
  console.error('  If this is an accepted cost, re-baseline deliberately and say why in the commit.');
  process.exit(1);
}
console.log(`✓ within budget — ${run.ms} ms vs baseline ${base.ms} ms (limit ${limit} ms)`);
