//
// Durable, bounded review queue.
//
// Every job ends in exactly one terminal state, with a reason, and the run reports both how many jobs were ELIGIBLE and
// how many were ATTEMPTED, so a run that stopped early can never read as a clean one:
//
//   succeeded          a verified answer was obtained
//   partial            the job ran but the answer was declined (bad citation, malformed, context unavailable)
//   failed             the model call failed and retries were exhausted or the failure is not retryable
//   timed_out          the job-level deadline passed
//   skipped_by_policy  egress policy, redaction, a size limit or an exhausted budget stopped it BEFORE any call
//   cancelled          the run was cancelled before the job finished
//
// Nothing here talks to a provider: the invoker comes from `review.resolveInvoker`, which goes through the governed
// discovery caller. Local-only policy therefore holds by construction, and there is no fallback to a different provider.
//
// Bounds are absolute: jobs, concurrency, model calls (retries count), tokens per job, estimated dollars (only when a
// price is supplied), and wall time. No unbounded queue growth, no infinite retry.
import { hashOf, canonicalJson, sha256 } from './canonical.js';
import { packRef, REVIEW_SCHEMA_VERSION } from './prompts/packs.js';
import { runReviewOnce, verifyReview } from './review.js';
import { readStoreJson, writeStoreJson, writeStoreFile } from './store.js';

export const TERMINAL_STATES = Object.freeze(['succeeded', 'partial', 'failed', 'timed_out', 'skipped_by_policy', 'cancelled']);
export const QUEUE_SCHEMA_VERSION = 'review-queue/1';
export const HARD_LIMITS = Object.freeze({ maxJobs: 20000, maxConcurrency: 16, maxCalls: 5000, maxRetries: 3, maxWallSeconds: 86400 });
const MAX_GROUP = 6;

/** Group entry points that operate on the same kind of object (the static segment before the last path parameter). */
export function resourceKeyOf(pathTemplate) {
  const segs = String(pathTemplate || '').split('/').filter(Boolean);
  let lastParam = -1;
  segs.forEach((s, i) => { if (/^[:{<]/.test(s) || /[}>]$/.test(s)) lastParam = i; });
  for (let i = lastParam - 1; i >= 0; i--) if (!/^[:{<]/.test(segs[i])) return segs[i];
  return null;
}

export function jobKeyOf({ entrypointIds, contextHashes, packageIndex, pack, model }) {
  return hashOf({
    schema: REVIEW_SCHEMA_VERSION,
    entrypoints: entrypointIds,
    contexts: contextHashes,
    packageIndex,
    pack: packRef(pack),
    model: { provider: model.provider || null, model: model.model || null },
    settings: {},
  });
}

/**
 * Plan jobs. `bundles` are build results (`{entrypoint, manifest}`). Excluded entry points get no job; they are counted
 * by the caller from the entry-point dispositions.
 */
export function planJobs({ bundles, packs, model, maxJobs = HARD_LIMITS.maxJobs }) {
  const live = bundles.filter(b => b.manifest);
  const jobs = [];
  for (const pack of packs) {
    if (pack.multiBundle) {
      const groups = new Map();
      for (const b of live) {
        if (b.manifest.context.integrity === 'unavailable') continue;
        const k = resourceKeyOf(b.entrypoint.pathTemplate);
        if (!k) continue;
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k).push(b);
      }
      for (const [k, members] of [...groups.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
        if (members.length < 2) continue;
        const sorted = members.sort((a, b) => (a.entrypoint.id < b.entrypoint.id ? -1 : 1));
        const used = sorted.slice(0, MAX_GROUP);
        jobs.push({
          key: jobKeyOf({ entrypointIds: used.map(m => m.entrypoint.id), contextHashes: used.map(m => m.manifest.contextHash), packageIndex: 1, pack, model }),
          packId: pack.id, packRef: packRef(pack), label: `${pack.id}: ${k} (${used.length} routes)`, entrypointIds: used.map(m => m.entrypoint.id),
          contextHashes: used.map(m => m.manifest.contextHash), packageIndexes: used.map(() => 1), groupTruncated: sorted.length > used.length ? sorted.length - used.length : 0,
        });
      }
    } else {
      for (const b of live) {
        for (const pk of b.manifest.context.packages.length ? b.manifest.context.packages : [{ index: 1 }]) {
          jobs.push({
            key: jobKeyOf({ entrypointIds: [b.entrypoint.id], contextHashes: [b.manifest.contextHash], packageIndex: pk.index, pack, model }),
            packId: pack.id, packRef: packRef(pack), label: `${pack.id}: ${b.entrypoint.label}${b.manifest.context.packages.length > 1 ? ` [package ${pk.index}/${pk.total}]` : ''}`,
            entrypointIds: [b.entrypoint.id], contextHashes: [b.manifest.contextHash], packageIndexes: [pk.index], groupTruncated: 0,
          });
        }
      }
    }
  }
  jobs.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const dropped = Math.max(0, jobs.length - maxJobs);
  return { jobs: jobs.slice(0, maxJobs), droppedByJobLimit: dropped };
}

// ---- queue state ----------------------------------------------------------------------------------------------

export function runIdOf(jobs, limits) { return hashOf({ jobs: jobs.map(j => j.key), limits: { calls: limits.maxCalls } }).slice(0, 24); }

function sealState(state) {
  const body = { ...state };
  delete body.stateHash;
  return { ...body, stateHash: sha256(canonicalJson(body)) };
}

function loadState(root, runId) {
  const r = readStoreJson(root, `queues/${runId}.json`);
  if (!r.ok) return { ok: false, corrupt: r.code === 'corrupt-json' };
  const { stateHash, ...body } = r.value;
  if (r.value.schemaVersion !== QUEUE_SCHEMA_VERSION || sha256(canonicalJson(body)) !== stateHash) return { ok: false, corrupt: true };
  return { ok: true, state: r.value };
}

function reviewPath(key) { return `reviews/${key}.json`; }

/** A stored review is reusable only if it still verifies as a review of exactly this job. */
function loadCachedReview(root, job) {
  const r = readStoreJson(root, reviewPath(job.key));
  if (!r.ok) return null;
  const v = r.value;
  if (!v || v.jobKey !== job.key || !v.review || v.review.schemaVersion !== REVIEW_SCHEMA_VERSION) return null;
  if (sha256(canonicalJson(v.review)) !== v.reviewHash) return null;
  return v;
}

// ---- run --------------------------------------------------------------------------------------------------------

const defaultSleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * Run a planned job list.
 *   ctx.root, ctx.loadJob(job) -> { pack, entrypoints, manifests, packageTexts } | { error }
 *   ctx.fileContents, ctx.invoker ({ok,invoke}|{ok:false,reason,denied}), ctx.model
 *   ctx.limits { concurrency, maxCalls, maxWallSeconds, maxTokensPerJob, maxRetries, jobTimeoutMs, maxCostUsd, costPerCallUsd }
 *   ctx.signal (AbortSignal), ctx.sleep, ctx.random, ctx.now  -- injected so tests are deterministic
 *   ctx.retryFailed (re-run jobs that ended failed/timed_out), ctx.onEvent
 */
export async function runQueue(jobs, ctx) {
  const now = ctx.now || (() => Date.now());
  const sleep = ctx.sleep || defaultSleep;
  const random = ctx.random || Math.random;
  const emit = typeof ctx.onEvent === 'function' ? ctx.onEvent : () => {};
  const L = {
    concurrency: Math.min(HARD_LIMITS.maxConcurrency, Math.max(1, ctx.limits.concurrency || 1)),
    maxCalls: Math.min(HARD_LIMITS.maxCalls, Math.max(1, ctx.limits.maxCalls || 100)),
    maxWallMs: Math.min(HARD_LIMITS.maxWallSeconds, Math.max(1, ctx.limits.maxWallSeconds || 900)) * 1000,
    maxTokensPerJob: ctx.limits.maxTokensPerJob || 40000,
    maxRetries: Math.min(HARD_LIMITS.maxRetries, Math.max(0, ctx.limits.maxRetries ?? 3)),
    jobTimeoutMs: ctx.limits.jobTimeoutMs || 120000,
    maxCostUsd: Number.isFinite(ctx.limits.maxCostUsd) ? ctx.limits.maxCostUsd : null,
    costPerCallUsd: Number.isFinite(ctx.limits.costPerCallUsd) ? ctx.limits.costPerCallUsd : null,
  };
  const runId = runIdOf(jobs, L);
  const started = now();
  const loaded = loadState(ctx.root, runId);
  const prior = loaded.ok ? loaded.state.jobs : {};
  const state = { schemaVersion: QUEUE_SCHEMA_VERSION, runId, jobs: {} };
  const results = new Map();
  let calls = 0;
  let estCost = 0;
  let cooldownUntil = 0;
  let budgetStop = null;
  let persistChain = Promise.resolve();
  const persist = () => {
    persistChain = persistChain.then(() => { writeStoreJson(ctx.root, `queues/${runId}.json`, sealState(state)); });
    return persistChain;
  };

  const settle = async (job, outcome) => {
    state.jobs[job.key] = { state: outcome.state, reason: outcome.reason || null, attempts: outcome.attempts || 0, label: job.label };
    results.set(job.key, { job, ...outcome });
    if (outcome.review) {
      const reviewRecord = { schemaVersion: 'review-result/1', jobKey: job.key, questionPack: job.packRef, entrypointIds: job.entrypointIds, contextHashes: job.contextHashes, state: outcome.state, review: outcome.review, reviewHash: sha256(canonicalJson(outcome.review)) };
      writeStoreJson(ctx.root, reviewPath(job.key), reviewRecord);
    }
    await persist();
    emit({ event: 'job', key: job.key, state: outcome.state, reason: outcome.reason || null });
  };

  // classify jobs: cached / settled-before / to run
  const todo = [];
  for (const job of jobs) {
    const p = prior[job.key];
    const cached = loadCachedReview(ctx.root, job);
    if (cached && cached.state === 'succeeded') {
      results.set(job.key, { job, state: 'succeeded', reason: null, review: cached.review, cached: true, attempts: 0 });
      state.jobs[job.key] = { state: 'succeeded', reason: null, attempts: 0, label: job.label, cached: true };
      continue;
    }
    // A policy skip, a cancellation and an interrupted job say nothing about the model, so they are always re-evaluated:
    // the policy or the endpoint may be different now. Answers (even declined ones) and real failures are kept so a
    // resume does not pay twice, unless the operator asks to retry them.
    const resettable = !p || p.state === 'skipped_by_policy' || p.state === 'cancelled' || p.state === 'running' || p.state === 'pending' || (ctx.retryFailed && (p.state === 'failed' || p.state === 'timed_out'));
    if (!resettable && ['partial', 'failed', 'timed_out', 'succeeded'].includes(p.state)) {
      state.jobs[job.key] = { ...p, resumed: true };
      results.set(job.key, { job, state: p.state, reason: p.reason, attempts: p.attempts, resumed: true, review: cached ? cached.review : undefined });
      continue;
    }
    state.jobs[job.key] = { state: 'pending', reason: null, attempts: 0, label: job.label };
    todo.push(job);
  }
  await persist();

  const gate = async () => { const wait = cooldownUntil - now(); if (wait > 0) await sleep(wait); };

  const budgetReason = () => {
    if (ctx.signal && ctx.signal.aborted) return 'cancelled';
    if (now() - started >= L.maxWallMs) return 'budget-exhausted:wall-time';
    if (calls >= L.maxCalls) return 'budget-exhausted:max-calls';
    if (L.maxCostUsd !== null && L.costPerCallUsd !== null && estCost + L.costPerCallUsd > L.maxCostUsd) return 'budget-exhausted:max-cost';
    return null;
  };

  const runOne = async (job) => {
    const stop = budgetReason();
    if (stop) { return settle(job, stop === 'cancelled' ? { state: 'cancelled', reason: 'run cancelled before this job started' } : { state: 'skipped_by_policy', reason: stop }); }
    if (!ctx.invoker || !ctx.invoker.ok) return settle(job, { state: 'skipped_by_policy', reason: (ctx.invoker && ctx.invoker.reason) || 'no model endpoint is configured' });

    const loadedJob = ctx.loadJob(job);
    if (loadedJob.error) return settle(job, { state: 'failed', reason: loadedJob.error, attempts: 0 });

    let attempts = 0;
    for (;;) {
      const s2 = budgetReason();
      if (s2) return settle(job, s2 === 'cancelled' ? { state: 'cancelled', reason: 'run cancelled', attempts } : { state: 'skipped_by_policy', reason: s2, attempts });
      await gate();
      attempts++;
      calls++;
      if (L.costPerCallUsd !== null) estCost += L.costPerCallUsd;
      state.jobs[job.key] = { state: 'running', reason: null, attempts, label: job.label };
      const out = await runReviewOnce({
        pack: loadedJob.pack, entrypoints: loadedJob.entrypoints, manifests: loadedJob.manifests, packageIndexes: job.packageIndexes, packageTexts: loadedJob.packageTexts,
        fileContents: ctx.fileContents, scanRoot: ctx.root, invoker: ctx.invoker, model: ctx.model, limits: { maxTokensPerJob: L.maxTokensPerJob, jobTimeoutMs: L.jobTimeoutMs },
      });
      if (out.state === 'skipped_by_policy') calls--; // nothing was sent
      if (out.state === 'failed' && out.retryable && attempts <= L.maxRetries) {
        // exponential backoff with jitter; the shared cooldown slows every worker, which is what a 429 storm needs
        const backoff = Math.min(30000, 500 * 2 ** (attempts - 1)) + Math.floor(random() * 250);
        cooldownUntil = Math.max(cooldownUntil, now() + backoff);
        emit({ event: 'retry', key: job.key, attempt: attempts, backoffMs: backoff, reason: out.reason });
        continue;
      }
      return settle(job, { ...out, attempts });
    }
  };

  let next = 0;
  const worker = async () => {
    for (;;) {
      const idx = next++;
      if (idx >= todo.length) return;
      try { await runOne(todo[idx]); } catch (err) { await settle(todo[idx], { state: 'failed', reason: `internal error: ${String((err && err.message) || err).slice(0, 120)}` }); }
    }
  };
  const poolSize = Math.min(L.concurrency, Math.max(1, todo.length));
  await Promise.all(Array.from({ length: poolSize }, worker));
  await persistChain;

  // anything still pending/running was never finished: it is cancelled, not clean
  for (const job of todo) {
    const s = state.jobs[job.key];
    if (s && (s.state === 'pending' || s.state === 'running')) await settle(job, { state: 'cancelled', reason: 'run ended before this job finished', attempts: s.attempts });
  }
  budgetStop = budgetReason();
  return { runId, results, coverage: coverageOf(jobs, results, { calls, estCost: L.costPerCallUsd !== null ? estCost : null, costBasis: L.costPerCallUsd !== null ? 'estimate: operator-supplied per-call price' : 'unknown: no price supplied, dollar cap not enforceable', limits: L, wallMs: now() - started, budgetStop, queueStateCorrupt: loaded.corrupt === true }) };
}

export function coverageOf(jobs, results, extra = {}) {
  const c = { eligible: jobs.length, attempted: 0, succeeded: 0, partial: 0, failed: 0, timed_out: 0, skipped_by_policy: 0, cancelled: 0, cached: 0, resumed: 0, modelCalls: extra.calls || 0, estimatedCostUsd: extra.estCost ?? null, costBasis: extra.costBasis || null, wallMs: extra.wallMs || 0, budgetStop: extra.budgetStop || null, queueStateCorrupt: !!extra.queueStateCorrupt, reasons: {} };
  for (const job of jobs) {
    const r = results.get(job.key);
    if (!r) { c.cancelled++; continue; }
    c[r.state] = (c[r.state] || 0) + 1;
    if (r.cached) c.cached++;
    if (r.resumed) c.resumed++;
    if (r.state !== 'skipped_by_policy' && r.state !== 'cancelled') c.attempted++;
    if (r.reason) c.reasons[r.reason] = (c.reasons[r.reason] || 0) + 1;
  }
  // only a succeeded job with a conclusion is a reviewed route; everything else is missing coverage, never a clean pass
  c.reviewed = c.succeeded;
  c.missingCoverage = c.eligible - c.succeeded;
  return c;
}

// ---- offline batch: export a request file, import a result file --------------------------------------------------

export function batchIdOf(jobs) { return hashOf(jobs.map(j => j.key)).slice(0, 24); }

/**
 * Write a provider-agnostic batch: a request file (one JSON line per job, with the redacted prompt) and a manifest that
 * binds every request to its job key, context hash and prompt hash. No provider API is called: uploading the file and
 * downloading results is the operator's step, and the contract of any particular provider's batch API is NOT assumed.
 */
export function exportBatch(root, jobs, loadJob, ctx) {
  const { buildReviewPrompt, redactPackageText, checkEgressForFiles } = ctx.review;
  const lines = [];
  const entries = [];
  const skipped = [];
  for (const job of jobs) {
    const lj = loadJob(job);
    if (lj.error) { skipped.push({ key: job.key, reason: lj.error }); continue; }
    const files = [...new Set(lj.manifests.flatMap((m, i) => (m.context.packages.find(p => p.index === job.packageIndexes[i]) || { segments: [] }).segments.map(s => s.file)))];
    const eg = checkEgressForFiles(files, { scanRoot: root, model: ctx.model });
    if (!eg.allowed) { skipped.push({ key: job.key, reason: `egress policy denied ${eg.file}: ${eg.reason}` }); continue; }
    const red = lj.packageTexts.map(t => redactPackageText(t, { scanRoot: root }));
    const bad = red.find(r => !r.ok);
    if (bad) { skipped.push({ key: job.key, reason: `redaction refused: ${bad.reason}` }); continue; }
    const { prompt, promptHash } = buildReviewPrompt({ pack: lj.pack, entrypoints: lj.entrypoints, packageTexts: red.map(r => r.text), contextHash: lj.manifests[0].contextHash });
    lines.push(JSON.stringify({ custom_id: job.key, prompt }));
    entries.push({ key: job.key, packRef: job.packRef, entrypointIds: job.entrypointIds, contextHashes: job.contextHashes, packageIndexes: job.packageIndexes, promptHash });
  }
  const batchId = batchIdOf(jobs);
  const manifest = { schemaVersion: 'review-batch/1', batchId, jobs: entries, skipped, note: 'Provider batch upload and download are performed by the operator. Results are imported with `context review --import-batch`.' };
  const w1 = writeStoreFile(root, `batches/${batchId}/requests.jsonl`, lines.join('\n') + (lines.length ? '\n' : ''));
  if (!w1.ok) return w1;
  const w2 = writeStoreJson(root, `batches/${batchId}/manifest.json`, manifest);
  if (!w2.ok) return w2;
  return { ok: true, batchId, requests: entries.length, skipped, requestsFile: w1.path };
}

/**
 * Import results for a batch. Each result line is `{ custom_id, response }` where `response` is the model text.
 * A result is REJECTED when it names an unknown job, repeats a job already settled (first wins), or was produced for a
 * context that is no longer the current one (stale or out-of-order). Import is idempotent.
 */
export function importBatch(root, batchId, resultsText, ctx) {
  const m = readStoreJson(root, `batches/${batchId}/manifest.json`);
  if (!m.ok) return { ok: false, reason: `batch manifest ${m.code}` };
  const byKey = new Map(m.value.jobs.map(j => [j.key, j]));
  const seen = new Set();
  const report = { accepted: 0, declined: 0, rejected: [], duplicates: 0 };
  for (const lineRaw of String(resultsText).split('\n')) {
    const line = lineRaw.trim();
    if (!line) continue;
    let rec;
    try { rec = JSON.parse(line); } catch { report.rejected.push({ reason: 'not-json' }); continue; }
    const key = rec && rec.custom_id;
    const entry = byKey.get(key);
    if (!entry) { report.rejected.push({ key: key || null, reason: 'unknown-job' }); continue; }
    const settled = loadCachedReview(root, { key });
    if (seen.has(key) || (settled && settled.state === 'succeeded')) { report.duplicates++; continue; }
    seen.add(key);
    const job = ctx.jobs.find(j => j.key === key);
    if (!job) { report.rejected.push({ key, reason: 'job-not-in-current-plan' }); continue; }
    const lj = ctx.loadJob(job);
    if (lj.error) { report.rejected.push({ key, reason: lj.error }); continue; }
    if (lj.manifests.some((mm, i) => mm.contextHash !== entry.contextHashes[i])) { report.rejected.push({ key, reason: 'stale-context' }); continue; }
    const promptHash = entry.promptHash;
    const review = verifyReview({ raw: typeof rec.response === 'string' ? rec.response : '', pack: lj.pack, entrypoints: lj.entrypoints, manifests: lj.manifests, packageIndexes: job.packageIndexes, fileContents: ctx.fileContents, promptHash });
    const state = review.status === 'completed' ? 'succeeded' : 'partial';
    const record = { schemaVersion: 'review-result/1', jobKey: key, questionPack: job.packRef, entrypointIds: job.entrypointIds, contextHashes: job.contextHashes, state, review, reviewHash: sha256(canonicalJson(review)), via: 'batch-import' };
    writeStoreJson(root, reviewPath(key), record);
    if (state === 'succeeded') report.accepted++; else report.declined++;
  }
  return { ok: true, ...report };
}

