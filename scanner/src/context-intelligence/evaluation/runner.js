//
// Runs the frozen synthetic suite through the compared systems and tallies per-case outcomes.
//
// Systems (each answers one question per case variant: "is a defect reported at the labeled sink?"):
//   deterministic  the default scanner (`runScan`) with state writes disabled; no model, no spend
//   hunt           the existing discovery pipeline (partition, lens hunters, confirm, panel, judge)
//   dci            DCI bundles + governed review + verified citations -> candidates (model hypotheses, pre-confirmation)
//   dci-compiler   dci with imported compiler metadata; BLOCKED unless the case ships a `hie-export.json`
// Both model-backed systems get the SAME injected reader, so the only thing that differs is the text put in front of it.
//
// The reader here is the scripted one, so every number is a statement about the machinery on synthetic cases.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../../runScan.js';
import { withStateWritesDisabled } from '../../posture/state-dir.js';
import { buildProjectIR } from '../../ir/index.js';
import { runDiscovery } from '../../discovery/index.js';
import { makeTaintProbe } from '../../discovery/index.js';
import { buildContext } from '../build.js';
import { loadConfig } from '../config.js';
import { planJobs, runQueue } from '../queue.js';
import { packById } from '../prompts/packs.js';
import { describeModel } from '../review.js';
import { reviewsToCandidates, adjudicate } from '../candidates.js';
import { scriptedReader } from './scripted-reader.js';
import { readSnapshot } from '../files.js';

export const SYSTEMS = Object.freeze(['deterministic', 'hunt', 'dci', 'dci-compiler']);
export const LINE_TOLERANCE = 5;

/** Line (1-based) of the first line containing `contains`, or null. */
export function locate(text, contains) {
  const lines = String(text).split('\n');
  for (let i = 0; i < lines.length; i++) if (lines[i].includes(contains)) return i + 1;
  return null;
}

function copyTree(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, e.name); const d = path.join(dest, e.name);
    if (e.isDirectory()) copyTree(s, d); else if (e.isFile()) fs.copyFileSync(s, d);
  }
}

function recorder(inner) {
  const prompts = [];
  const fn = async (prompt) => { prompts.push(prompt); return inner(prompt); };
  fn.tokenizerName = inner.tokenizerName;
  return { invoke: fn, prompts };
}

function hit(found, sink) {
  return found.some(f => f.file === sink.file && Number.isInteger(f.line) && Math.abs(f.line - sink.line) <= LINE_TOLERANCE);
}

async function runDeterministic(dir, sink) {
  const { scan } = await withStateWritesDisabled(() => runScan(dir, { deep: true, deepInCi: true }));
  const findings = [...(scan.findings || []), ...(scan.logicVulns || [])].filter(f => f && f.severity !== 'info');
  return { flagged: hit(findings, sink), calls: 0, promptChars: 0, detail: { findings: findings.length }, prompts: [] };
}

async function runHuntSystem(dir, sink, reader) {
  const snap = await readSnapshot(dir, { maxFiles: 2000 });
  const fileContents = snap.fileContents;
  const ir = buildProjectIR(fileContents);
  const rec = recorder(reader);
  const res = await withStateWritesDisabled(() => runDiscovery({ perFileIR: ir.perFile, callGraph: ir.callGraph, fileContents }, { llmInvoke: rec.invoke, lenses: ['authz', 'business-logic'], maxAreas: 8 }));
  const reported = [...res.fresh, ...res.duplicates];
  const found = reported.map(f => ({ file: f.file, line: f.line }));
  return { flagged: hit(found, sink), calls: rec.prompts.length, promptChars: rec.prompts.reduce((n, p) => n + p.length, 0), detail: { reported: reported.length, areas: res.focusAreas.length }, prompts: rec.prompts };
}

async function runDciSystem(dir, sink, reader, { packIds, withCompiler }) {
  const { config } = loadConfig(dir);
  if (withCompiler) config.semanticMetadata = { mode: 'import', haskellHieDir: '.' };
  const built = await buildContext(dir, { config });
  if (!built.ok) return { flagged: false, calls: 0, promptChars: 0, detail: { buildFailed: built.reason }, prompts: [] };
  const packs = packIds.map(packById).filter(Boolean);
  const model = describeModel();
  const { jobs } = planJobs({ bundles: built.bundles, packs, model });
  const byEp = new Map(built.bundles.map(b => [b.entrypoint.id, b]));
  const packMap = new Map(packs.map(p => [p.id, p]));
  const loadJob = (job) => {
    const bundles = job.entrypointIds.map(id => byEp.get(id));
    if (bundles.some(b => !b || !b.manifest)) return { error: 'no bundle' };
    return { pack: packMap.get(job.packId), entrypoints: bundles.map(b => b.entrypoint), manifests: bundles.map(b => b.manifest), packageTexts: bundles.map((b, i) => (b.pack.packages.find(p => p.index === job.packageIndexes[i]) || b.pack.packages[0]).text) };
  };
  const rec = recorder(reader);
  const result = await runQueue(jobs, { root: built.root, fileContents: built.fileContents, model, invoker: { ok: true, invoke: rec.invoke }, loadJob, retryFailed: false, limits: { concurrency: 1, maxCalls: 500, maxWallSeconds: 300, maxTokensPerJob: 40000, maxRetries: 0, jobTimeoutMs: 30000, maxCostUsd: null, costPerCallUsd: null } });
  const records = [];
  for (const [, res] of result.results) {
    if (res.state === 'succeeded' && res.review) { const lj = loadJob(res.job); if (!lj.error) records.push({ review: res.review, entrypoints: lj.entrypoints.map(e => ({ id: e.id, label: e.label })), pack: lj.pack }); }
  }
  const candidates = reviewsToCandidates(records);
  const adj = await adjudicate(candidates, { taintProbe: makeTaintProbe(built.ir.perFile, built.ir.callGraph), scanRoot: built.root });
  const found = candidates.map(c => ({ file: c.file, line: c.line }));
  const tiers = {};
  for (const f of adj.findings) { const t = (f.discovery && f.discovery.confirmation && f.discovery.confirmation.tier) || 'unknown'; tiers[t] = (tiers[t] || 0) + 1; }
  return {
    flagged: hit(found, sink), calls: rec.prompts.length, promptChars: rec.prompts.reduce((n, p) => n + p.length, 0),
    detail: { jobs: jobs.length, candidates: candidates.length, coverage: { eligible: result.coverage.eligible, succeeded: result.coverage.succeeded, missing: result.coverage.missingCoverage }, confirmationTiers: tiers, bundles: { complete: built.summary.complete, partial: built.summary.partialBundles, unavailable: built.summary.unavailable } },
    prompts: rec.prompts,
  };
}

/**
 * Run one system over one case variant in a throwaway copy. Never touches the source fixture.
 * Returns { flagged, calls, promptChars, detail, prompts, status } where status is 'ok' or 'blocked'/'error'.
 */
export async function runCase({ system, caseDef, variant, suiteDir, variantName = 'dci' }) {
  const v = caseDef.variants[variant.key];
  const srcDir = path.join(suiteDir, 'corpus', caseDef.id, variant.key);
  if (system === 'dci-compiler' && !fs.existsSync(path.join(srcDir, 'hie-export.json'))) {
    return { status: 'blocked', reason: 'no compiler metadata export is shipped for this case (the exporter needs a build toolchain and is not run by DCI)', flagged: null, calls: 0, promptChars: 0, detail: {}, prompts: [] };
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dci-eval-'));
  try {
    copyTree(srcDir, tmp);
    const sinkText = fs.readFileSync(path.join(tmp, v.sink.file), 'utf8');
    const line = locate(sinkText, v.sink.contains);
    if (line === null) return { status: 'error', reason: `sink text not found in ${v.sink.file}`, flagged: null, calls: 0, promptChars: 0, detail: {}, prompts: [] };
    const sink = { file: v.sink.file, line };
    const reader = scriptedReader();
    let r;
    if (system === 'deterministic') r = await runDeterministic(tmp, sink);
    else if (system === 'hunt') r = await runHuntSystem(tmp, sink, reader);
    else if (system === 'dci' || system === 'dci-compiler') {
      const packIds = variantName === 'dci-all-packs' ? ['authz-idor', 'authz-function', 'transaction-integrity'] : [caseDef.pack];
      r = await runDciSystem(tmp, sink, reader, { packIds, withCompiler: system === 'dci-compiler' });
    } else return { status: 'error', reason: `unknown system ${system}`, flagged: null, calls: 0, promptChars: 0, detail: {}, prompts: [] };
    return { status: 'ok', sink, ...r };
  } catch (e) {
    return { status: 'error', reason: String(e && e.message || e).slice(0, 200), flagged: null, calls: 0, promptChars: 0, detail: {}, prompts: [] };
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}
