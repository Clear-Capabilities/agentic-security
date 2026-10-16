#!/usr/bin/env node
// A fresh, checkpointed measurement of the current engine on the independent population (E1-04).
//   node independent-baseline.mjs --plan  [--per-language 30] [--splits dev,validation] [--chunk 20]
//   node independent-baseline.mjs --run   [--run <id>] [--per-language 30] [--chunk 20] [--chunk-timeout-min 90]
//   node independent-baseline.mjs --merge --run <id>
//   node independent-baseline.mjs --status --run <id>
//
// HOW IT STAYS HONEST
//   * The engine measured is the committed HEAD, checked out into a throwaway worktree, so editing the working tree while it runs cannot
//     change what is measured and the tree is clean by construction. The identity (commit, bundle digest, config, corpus digest, toolchain)
//     is written next to the result; a measurement that is not valid says so and why.
//   * Only the development and validation splits are selected. The sealed split is not reachable from here.
//   * Work is cut into chunks, each run in its own process under a wall-clock limit. A chunk that wedges or times out is recorded and the
//     run moves on; its entries are reported as unaccounted, never as misses. A finished chunk is never repeated on resume.
//   * The result is computed by scorer.mjs from the chunk rows: three definitions kept apart, complete denominator accounting, intervals
//     that resample whole repositories, and `insufficient_population` below the declared minimum.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { atomicWriteJson, nowIso } from '../loop-engineering/lib/util.mjs';
import { runBounded } from '../loop-engineering/lib/proc.mjs';
import { REPO_ROOT } from './lib/model.mjs';
import { measurementIdentity, digestOfFiles } from './lib/measurement-identity.mjs';
import { withCleanWorktree } from './lib/clean-worktree.mjs';

const readJson = (p, fb = null) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return fb; } };
const sha = (s) => createHash('sha256').update(s).digest('hex');
export const RUNS_DIR = (root) => join(root, 'bench', 'independent', 'runs');
export const CONFIG_DEEP = Object.freeze({ deep: true, llm: 'none', note: 'the CLI default outside CI; no model endpoint, so deterministic and offline apart from the fetch' });

async function imp(root, rel) { return import(`file://${join(root, rel)}`); }

/** Choose the entries and write the plan. Deterministic: the same splits file and parameters give the same selection and the same run id. */
export async function planRun(root, { perLanguage = 30, splitNames = ['dev', 'validation'], chunk = 20 } = {}) {
  const splitsMod = await imp(root, 'bench/independent/splits.mjs');
  const manifest = readJson(join(root, 'bench/independent/manifest.json'));
  const splits = splitsMod.loadSplits(join(root, 'bench/independent/splits.json'));
  if (!splits) throw new Error('bench/independent/splits.json is missing; build the frozen splits first (E1-02)');
  const sel = splitsMod.stratifiedSample(manifest.entries, splits, { perLanguage, splitNames });
  const head = measurementIdentity(root, { corpus: { id: 'independent-selection', files: ['bench/independent/manifest.json', 'bench/independent/splits.json'] } });
  const runId = sha(JSON.stringify({ commit: head.sourceCommit, ids: sel.ids, config: CONFIG_DEEP, chunk })).slice(0, 12);
  const dir = join(RUNS_DIR(root), runId);
  mkdirSync(join(dir, 'chunks'), { recursive: true }); mkdirSync(join(dir, 'logs'), { recursive: true });
  const selection = { schema: 'agentic-security/independent-selection@1', ...sel, splitsProtocolHash: splits.protocolHash, manifestSha256: digestOfFiles(root, ['bench/independent/manifest.json']) };
  atomicWriteJson(join(dir, 'selection.json'), selection);
  const chunks = [];
  for (let offset = 0; offset < sel.ids.length; offset += chunk) chunks.push({ index: chunks.length, offset, limit: Math.min(chunk, sel.ids.length - offset) });
  const plan = { schema: 'agentic-security/independent-run-plan@1', runId, plannedAt: nowIso(), config: CONFIG_DEEP, chunkSize: chunk, chunks, selection: { entries: sel.ids.length, counts: sel.counts, splitNames, perLanguage }, plannedAtCommit: head.sourceCommit };
  if (!existsSync(join(dir, 'plan.json'))) atomicWriteJson(join(dir, 'plan.json'), plan);
  return { runId, dir, plan: readJson(join(dir, 'plan.json')), selection };
}

const chunkFile = (dir, offset) => join(dir, 'chunks', `RESULT-chunk-deep-${String(offset).padStart(5, '0')}.json`);
const chunkOk = (dir, c) => { const j = readJson(chunkFile(dir, c.offset)); return !!(j && Array.isArray(j.perEntry)); };

/**
 * Run every chunk that has no result yet. `exec(argv, {cwd, wallMs, logPath})` defaults to the supervised runner and is injectable for tests.
 * Returns the progress record. A failed or timed-out chunk is recorded and skipped; `--run <id>` resumes and retries it once more.
 */
export async function runChunks(root, runId, { chunkTimeoutMs = 90 * 60 * 1000, materialiseTimeoutMs = 40 * 60 * 1000, exec = null, measureRoot = null, onChunk = () => {} } = {}) {
  const dir = join(RUNS_DIR(root), runId);
  const plan = readJson(join(dir, 'plan.json'));
  if (!plan) throw new Error(`no plan for run ${runId}`);
  const progressPath = join(dir, 'progress.json');
  const progress = readJson(progressPath, { schema: 'agentic-security/independent-run-progress@1', runId, chunks: {} });
  const run = exec || (async (argv, o) => {
    const r = await runBounded({ argv, cwd: o.cwd, wallMs: o.wallMs, logPath: o.logPath, redactLog: true, label: `independent:${runId}`, runId: `ee-ind-${runId}`, env: { ...process.env, AGENTIC_SECURITY_BENCH_PROGRESS: '1' } });
    return { outcome: r.outcome, exitCode: r.exitCode, durationMs: r.durationMs };
  });
  const body = async (measureDir) => {
    for (const c of plan.chunks) {
      if (chunkOk(dir, c)) { progress.chunks[c.index] = { ...(progress.chunks[c.index] || {}), state: 'done', offset: c.offset, limit: c.limit }; continue; }
      const rec = { state: 'running', offset: c.offset, limit: c.limit, startedAt: nowIso(), attempts: (progress.chunks[c.index]?.attempts || 0) + 1 };
      progress.chunks[c.index] = rec; atomicWriteJson(progressPath, progress);
      const selArg = `--selection=${join(dir, 'selection.json')}`;
      const mat = await run([process.execPath, 'bench/independent/materialise-cli.mjs', selArg, `--offset=${c.offset}`, `--limit=${c.limit}`], { cwd: measureDir, wallMs: materialiseTimeoutMs, logPath: join(dir, 'logs', `chunk-${String(c.index).padStart(3, '0')}-materialise.log`) });
      rec.materialise = mat;
      const sc = await run([process.execPath, 'bench/independent/runner.mjs', '--deep', '--json', selArg, `--offset=${c.offset}`, `--limit=${c.limit}`, `--out-dir=${join(dir, 'chunks')}`], { cwd: measureDir, wallMs: chunkTimeoutMs, logPath: join(dir, 'logs', `chunk-${String(c.index).padStart(3, '0')}-score.log`) });
      rec.score = sc;
      rec.endedAt = nowIso();
      rec.state = chunkOk(dir, c) ? 'done' : (sc.outcome === 'timeout-wall' ? 'timed_out' : 'failed');
      progress.chunks[c.index] = rec; atomicWriteJson(progressPath, progress);
      onChunk(c, rec);
    }
  };
  if (measureRoot) await body(measureRoot);
  else {
    mkdirSync(join(root, 'bench', 'independent', 'cache'), { recursive: true });
    await withCleanWorktree(root, async ({ dir: wt, commit, linked }) => {
      progress.measuredIn = { detachedWorktreeOf: commit, linkedFromSourceCheckout: linked };
      progress.identity = measurementIdentity(wt, { corpus: { id: 'independent-selection', files: ['bench/independent/manifest.json', 'bench/independent/splits.json'] } });
      atomicWriteJson(progressPath, progress);
      await body(wt);
    }, { link: ['scanner/node_modules', 'scanner/vendor', 'bench/independent/cache'] });
  }
  atomicWriteJson(progressPath, progress);
  return progress;
}

/** Merge finished chunks into RESULT.json using the scorer. Every entry of the selection is accounted for, scored or not. */
export async function mergeRun(root, runId) {
  const dir = join(RUNS_DIR(root), runId);
  const plan = readJson(join(dir, 'plan.json'));
  const selection = readJson(join(dir, 'selection.json'));
  const progress = readJson(join(dir, 'progress.json'), {});
  const scorer = await imp(root, 'bench/independent/scorer.mjs');
  const splitsMod = await imp(root, 'bench/independent/splits.mjs');
  const manifest = readJson(join(root, 'bench/independent/manifest.json'));
  const want = new Set(selection.ids);
  const entries = manifest.entries.filter((e) => want.has(e.id));
  const rows = []; const unscored = []; const missingChunks = []; let engineVersion = null; const seen = new Set();
  for (const c of plan.chunks) {
    const j = readJson(chunkFile(dir, c.offset));
    if (!j) { missingChunks.push({ index: c.index, state: progress.chunks?.[c.index]?.state || 'not_run' }); continue; }
    engineVersion = engineVersion || j.engineVersion;
    for (const r of j.perEntry) if (!seen.has(r.id)) { seen.add(r.id); rows.push(r); }
    for (const u of j.population.unscored || []) if (!seen.has(typeof u === 'string' ? u : u.id)) { const o = typeof u === 'string' ? { id: u, reason: 'unscored' } : u; seen.add(o.id); unscored.push(o); }
  }
  const splits = splitsMod.loadSplits(join(root, 'bench/independent/splits.json'));
  const scoring = scorer.scorePopulation({ rows, unscored, manifestEntries: entries, splits, protocolHash: splits ? splits.protocolHash : undefined });
  const result = {
    schema: 'agentic-security/independent-run-result@1',
    runId, mergedAt: nowIso(), engineVersion, configuration: plan.config,
    identity: progress.identity || null,
    measuredIn: progress.measuredIn || null,
    population: { role: 'independent population, development and validation splits only', selection: plan.selection, manifestSha256: selection.manifestSha256 || null, splitsProtocolHash: selection.splitsProtocolHash || null, entriesInSelection: entries.length, sealedSplitTouched: false },
    chunks: { planned: plan.chunks.length, missing: missingChunks },
    coverage: { scored: rows.length, unscored: unscored.length, unaccounted: scoring.denominators.unaccounted },
    scoring, headline: scorer.headline(scoring),
    perEntry: rows, unscored,
    historicalNote: 'Archived results for older engines (bench/independent/RESULT.json, engine 0.141.0) are not comparable with this run: different engine, different population selection, different scoring definitions.',
  };
  atomicWriteJson(join(dir, 'RESULT.json'), result);
  return result;
}

export function statusOf(root, runId) {
  const dir = join(RUNS_DIR(root), runId);
  const plan = readJson(join(dir, 'plan.json')); const progress = readJson(join(dir, 'progress.json'), { chunks: {} });
  if (!plan) return null;
  const done = plan.chunks.filter((c) => chunkOk(dir, c)).length;
  return { runId, chunksPlanned: plan.chunks.length, chunksDone: done, failed: Object.values(progress.chunks).filter((c) => c.state === 'failed' || c.state === 'timed_out').length, entries: plan.selection.entries };
}

const arg = (a, k, d = null) => { const i = a.indexOf(k); return i >= 0 ? a[i + 1] : d; };
if (import.meta.url === `file://${process.argv[1]}`) {
  const a = process.argv.slice(2);
  const root = a.includes('--root') ? resolve(arg(a, '--root')) : REPO_ROOT;
  (async () => {
    if (a.includes('--plan')) { const p = await planRun(root, { perLanguage: Number(arg(a, '--per-language', 30)), chunk: Number(arg(a, '--chunk', 20)) }); console.log(`run ${p.runId}: ${p.plan.selection.entries} entries in ${p.plan.chunks.length} chunks; ${JSON.stringify(p.plan.selection.counts)}`); return 0; }
    if (a.includes('--status')) { console.log(JSON.stringify(statusOf(root, arg(a, '--run')), null, 2)); return 0; }
    if (a.includes('--merge')) { const r = await mergeRun(root, arg(a, '--run')); console.log(JSON.stringify({ coverage: r.coverage, headline: r.headline }, null, 2)); return 0; }
    if (a.includes('--run')) {
      let id = arg(a, '--run');
      if (!id || id.startsWith('--')) { id = (await planRun(root, { perLanguage: Number(arg(a, '--per-language', 30)), chunk: Number(arg(a, '--chunk', 20)) })).runId; }
      const progress = await runChunks(root, id, { chunkTimeoutMs: Number(arg(a, '--chunk-timeout-min', 90)) * 60000, onChunk: (c, r) => console.log(`chunk ${c.index} ${r.state} (${c.offset}+${c.limit})`) });
      const merged = await mergeRun(root, id);
      console.log(`run ${id}: ${merged.coverage.scored} scored, ${merged.coverage.unscored} unscored, ${merged.coverage.unaccounted} unaccounted; chunks missing: ${merged.chunks.missing.length}`);
      void progress;
      return merged.chunks.missing.length ? 1 : 0;
    }
    console.error('usage: independent-baseline.mjs --plan | --run [id] | --merge --run id | --status --run id');
    return 2;
  })().then((c) => process.exit(c)).catch((e) => { console.error(`independent-baseline failed: ${e.stack || e.message}`); process.exit(2); });
}
void dirname; void readdirSync;
