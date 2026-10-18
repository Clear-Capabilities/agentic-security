// The Eval Lab run (PRD 6): arms x repeats x tasks x dataset entries, with the leakage controls in front and the scores behind.
//
//   prepare   materialize each entry's workspace, neutralize it, audit it (custody) -> staged dir, or quarantined and excluded
//   execute   one attempt per (arm, repeat, task, entry), bounded concurrency, per-attempt timeout, cancellable
//   score     detection, falsification, exploit proof and remediation, each recomputed from what the lab itself observed
//
// Mechanical evidence decides (the shared engineering contract): an arm's claim that its PoC works or its patch holds is never
// taken. The lab executes the arm's reproducer in the proof fabric and replays the original exploit against the arm's patch.
// An attempt that does not complete is recorded as such and never dropped, so a model cannot improve its score by failing.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { digestOf } from '../../assurance/identity.js';
import { protectedTermsFrom } from '../custody.js';
import { superviseSpawn } from '../../../sandbox/supervise.js';
import { scrubEnv } from '../../../sandbox/trust-domains.js';
import { proveFinding } from '../../proof-fabric/orchestrator.js';
import { verifyFixWithProof } from '../../proof-fabric/fix-proof.js';
import { validateReproducer } from '../../proof-fabric/reproducer.js';
import { materializeEntry } from './materialize.js';
import { stageNeutralized } from './neutralize.js';
import { validateArm, runArmTask, TASKS } from './arms.js';
import { resolveInside, normalizeCwe } from './dataset.js';
import { scoreDetect, scoreFalsify, scoreExploit, scorePatch, scoreEconomics } from './score.js';

export const RUN_SCHEMA = 'agentic-security/eval-lab-run';
const RUN_VERSION = 1;
export const DEFAULT_REPEATS = 3;
const require = createRequire(import.meta.url);

const hasTarget = (e) => !!(e.kind === 'vulnerable' ? e.expectedSpan : e.lookalikeSpan);
const targetOf = (e) => (e.kind === 'vulnerable' ? { span: e.expectedSpan, cwe: normalizeCwe(e.cwe) } : { span: e.lookalikeSpan, cwe: normalizeCwe(e.resemblesCwe ?? e.cwe) });

function machineProfile() {
  const cpus = os.cpus();
  return { platform: os.platform(), arch: os.arch(), cpus: cpus.length, cpuModel: cpus[0]?.model ?? null, memoryGb: Math.round(os.totalmem() / 2 ** 30), node: process.version };
}
function scannerIdentity() {
  let version = null; let commit = null;
  try { version = require('../../../../package.json').version; } catch { /* bundled: unknown */ }
  try {
    const r = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: path.dirname(new URL(import.meta.url).pathname), encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
    if (r.status === 0) commit = r.stdout.trim() || null;
  } catch { /* not a checkout */ }
  return { version, commit };
}

async function pool(jobs, limit, run, signal) {
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, jobs.length || 1)) }, async () => {
    while (next < jobs.length && !signal?.aborted) { const j = jobs[next++]; await run(j); }
  });
  await Promise.all(workers);
}

/** Stage every entry's workspace. Returns the prepared map and the leakage-audit record for the run. */
export function prepareWorkspaces({ manifest, baseDir, workRoot }) {
  const policy = manifest.dataset.leakagePolicy;
  const terms = protectedTermsFrom({ advisoryText: policy.protectedTerms ?? [] });
  const prepared = new Map(); const quarantined = []; const failed = [];
  let filesAudited = 0;
  for (const e of manifest.entries) {
    const raw = path.join(workRoot, `raw-${prepared.size + quarantined.length + failed.length}`);
    const m = materializeEntry(e, { baseDir, destDir: raw });
    if (!m.ok) { failed.push({ entryId: e.id, reason: m.reason }); fs.rmSync(raw, { recursive: true, force: true }); continue; }
    const dest = path.join(workRoot, `w${prepared.size + quarantined.length + failed.length}`);
    const s = stageNeutralized({ srcDir: raw, destDir: dest, policy, terms });
    fs.rmSync(raw, { recursive: true, force: true });
    filesAudited += s.audit.scannedFiles;
    if (!s.ok) { quarantined.push({ entryId: e.id, leaks: s.leaks.slice(0, 5).map((l) => ({ kind: l.kind, file: l.file ?? null })) }); continue; }
    prepared.set(e.id, { dir: dest, fileMap: s.fileMap });
  }
  const status = failed.length || quarantined.length ? (prepared.size ? 'entries-excluded' : 'no-entries-usable') : 'clean';
  return { prepared, terms, audit: { status, mode: 'enforce', stripComments: !!policy.stripComments, renameFiles: !!policy.renameFiles, entries: manifest.entries.length, usable: prepared.size, quarantined, unavailable: failed, filesAudited, termCount: terms.length, scope: 'workspace contents and every request the lab sends an arm; an arm\'s own internal prompts are not visible to the lab' } };
}

async function testsPass({ argv, dir, files, timeoutMs, signal }) {
  if (!argv) return null;
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), 'eval-test-'));
  try {
    fs.cpSync(dir, copy, { recursive: true, dereference: false });
    for (const [rel, content] of Object.entries(files)) {
      const t = path.resolve(copy, rel);
      if (!t.startsWith(copy + path.sep)) return null;
      fs.mkdirSync(path.dirname(t), { recursive: true }); fs.writeFileSync(t, content);
    }
    const r = await superviseSpawn(argv[0], argv.slice(1), { cwd: copy, env: scrubEnv(process.env), timeoutMs, signal });
    if (r.spawnError || r.timedOut || r.cancelled) return null;
    return r.exitCode === 0;
  } finally { fs.rmSync(copy, { recursive: true, force: true }); }
}

/**
 * @param {object} o
 * @param {{manifest: object, baseDir: string, hash: string}} o.dataset
 * @param {object[]} o.arms
 * @param {string[]} [o.tasks]
 * @param {number} [o.repeats]
 */
export async function runEval({ dataset, arms, tasks = ['detect'], repeats = DEFAULT_REPEATS, concurrency = 2, timeoutMs = 120_000, budgetUsd = null, scanRoot = process.cwd(), signal, onProgress = () => {}, deps = {} } = {}) {
  const now = deps.now ?? Date.now;
  const startedAt = new Date(now()).toISOString();
  const errors = [];
  if (!Array.isArray(arms) || !arms.length) errors.push('at least one arm is required');
  const ids = new Set();
  for (const a of arms ?? []) { const v = validateArm(a); if (!v.ok) errors.push(`arm ${a?.id ?? '?'}: ${v.errors.join('; ')}`); if (ids.has(a?.id)) errors.push(`arm id ${a.id} is duplicated`); ids.add(a?.id); }
  if (!tasks.length || !tasks.every((t) => TASKS.includes(t))) errors.push(`tasks must be some of ${TASKS.join(', ')}`);
  if (!(Number.isInteger(repeats) && repeats >= 1 && repeats <= 50)) errors.push('repeats must be an integer from 1 to 50');
  if (errors.length) return { ok: false, errors };

  const { manifest, baseDir } = dataset;
  const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'eval-lab-'));
  try {
    const prep = prepareWorkspaces({ manifest, baseDir, workRoot });
    const entriesById = new Map(manifest.entries.map((e) => [e.id, e]));
    const usable = manifest.entries.filter((e) => prep.prepared.has(e.id));
    const attempts = [];
    const spend = { usd: 0 };
    const armPlans = arms.map((a) => ({ arm: a, repeats: a.kind === 'deterministic' ? 1 : repeats, tasks: tasks.filter((t) => a.tasks.includes(t)) }));
    const jobs = [];
    for (const plan of armPlans) for (let r = 0; r < plan.repeats; r++) for (const t of plan.tasks) {
      for (const e of usable) {
        if (t !== 'detect' && !hasTarget(e)) continue;
        if (t === 'patch' && !(e.kind === 'vulnerable' && e.reproducer)) continue;
        jobs.push({ arm: plan.arm, repeat: r, task: t, entry: e });
      }
    }
    let completedJobs = 0;
    const armLimit = new Map();
    const take = async (arm) => { const cap = arm.maxConcurrency ?? (arm.kind === 'model' ? 1 : concurrency); const st = armLimit.get(arm.id) ?? { n: 0, q: [] }; armLimit.set(arm.id, st); if (st.n >= cap) await new Promise((res) => st.q.push(res)); st.n++; };
    const give = (arm) => { const st = armLimit.get(arm.id); st.n--; st.q.shift()?.(); };

    await pool(jobs, concurrency, async (job) => {
      const { arm, task, entry } = job;
      const rec = { armId: arm.id, repeat: job.repeat, task, entryId: entry.id, entryKind: entry.kind };
      if (budgetUsd != null && spend.usd >= budgetUsd) { attempts.push({ ...rec, status: 'skipped-budget', reason: `the ${budgetUsd} USD budget was reached`, usage: { usd: null, latencyMs: 0 } }); return; }
      await take(arm);
      try {
        const ws = prep.prepared.get(entry.id);
        const t = targetOf(entry);
        const mappedFile = t.span ? (ws.fileMap[t.span.file] ?? t.span.file) : null;
        const base = { language: manifest.dataset.language, workspace: ws.dir };
        let request = { schema: 'agentic-security/eval-request', task, ...base };
        if (task === 'falsify') request = { ...request, candidates: [{ id: 'c1', file: mappedFile, line: t.span.startLine, cwe: t.cwe }] };
        if (task === 'exploit' || task === 'patch') request = { ...request, target: { file: mappedFile, line: t.span.startLine, endLine: t.span.endLine, cwe: t.cwe } };
        const res = await (deps.runArmTask ?? runArmTask)({ arm, task, request, workspaceDir: ws.dir, terms: prep.terms, scanRoot, signal, timeoutMs, egress: deps.egress, scanFn: deps.scanFn });
        if (res.usage?.usd != null) spend.usd += res.usage.usd;
        const out = { ...rec, status: res.status, reason: res.reason ?? null, usage: res.usage };
        if (res.status === 'completed') {
          if (task === 'detect') out.output = { findings: res.output.findings.slice(0, 200) };
          if (task === 'falsify') out.output = { verdict: res.output.verdicts?.c1 ?? 'uncertain' };
          if (task === 'exploit') {
            const rp = res.output.reproducer;
            const valid = rp && validateReproducer(rp).length === 0;
            out.proof = { reproducerProvided: !!rp, reproducerValid: !!valid, executed: false, state: null, successes: null, runs: null };
            if (valid) {
              const proved = await (deps.proveFn ?? proveFinding)({ finding: { id: `eval-${entry.id}`, stableId: `eval-${entry.id}`, parser: 'IR-TAINT' }, reproducer: { ...rp, findingId: `eval-${entry.id}` }, sourceRoot: ws.dir, policy: { timeoutMs: Math.min(timeoutMs, 60_000) }, signal });
              const ran = proved.attempts && proved.attempts.run > 0 && proved.environment?.mode !== 'unavailable';
              out.proof = { ...out.proof, executed: !!ran, state: proved.state, successes: proved.attempts?.successes ?? null, runs: proved.attempts?.run ?? null, degraded: (proved.degradation ?? []).slice(0, 5) };
            }
          }
          if (task === 'patch') {
            const files = res.output.files;
            const rpFile = resolveInside(baseDir, entry.reproducer);
            out.patch = { applicable: true, patchProvided: !!files && Object.keys(files).length > 0, exploitBlocked: null, testsPass: null, completeness: null, state: null, bytes: files ? Object.values(files).reduce((s, v) => s + v.length, 0) : 0, digest: files ? digestOf(files) : null };
            if (out.patch.patchProvided && rpFile) {
              let rp = JSON.parse(fs.readFileSync(rpFile, 'utf8'));
              if (rp.sources) rp = { ...rp, sources: Object.fromEntries(Object.entries(rp.sources).map(([d, s]) => [d, ws.fileMap[s] ?? s])) };
              const fp = await (deps.verifyPatchFn ?? verifyFixWithProof)({ finding: { id: `eval-${entry.id}`, stableId: `eval-${entry.id}` }, reproducer: { ...rp, findingId: `eval-${entry.id}` }, files, scanRoot: ws.dir, policy: { timeoutMs: Math.min(timeoutMs, 60_000) }, staticVerification: null, signal });
              const pre = fp.legs?.prePatch?.state === 'EXPLOIT_CONFIRMED';
              const post = fp.legs?.postPatch;
              out.patch.state = fp.state; out.patch.completeness = fp.completeness ?? null;
              out.patch.exploitBlocked = pre && post && post.attempts > 0 && post.completed === post.attempts ? post.exploitSucceeded === 0 : null;
              out.patch.testsPass = await testsPass({ argv: entry.test ?? manifest.dataset.test ?? null, dir: ws.dir, files, timeoutMs: Math.min(timeoutMs, 120_000), signal });
            }
          }
        }
        attempts.push(out);
      } finally { give(arm); completedJobs++; onProgress({ done: completedJobs, total: jobs.length }); }
    }, signal);

    // ---- scoring: per arm, per repeat, per task
    const mapFileFor = (entryId, f) => prep.prepared.get(entryId)?.fileMap[f] ?? f;
    const results = [];
    for (const plan of armPlans) {
      for (let r = 0; r < plan.repeats; r++) {
        const mine = attempts.filter((a) => a.armId === plan.arm.id && a.repeat === r);
        const scores = {};
        for (const t of plan.tasks) {
          const ta = mine.filter((a) => a.task === t);
          if (t === 'detect') scores.detect = scoreDetect({ entries: usable, attempts: new Map(ta.map((a) => [a.entryId, a])), mapFile: mapFileFor, targetCwes: manifest.dataset.cwe });
          if (t === 'falsify') {
            const truth = new Map(); const verdicts = new Map();
            for (const a of ta) { const e = entriesById.get(a.entryId); truth.set(a.entryId, e.kind === 'vulnerable' ? 'vulnerable' : 'not-vulnerable'); verdicts.set(a.entryId, a.status === 'completed' ? a.output?.verdict ?? 'uncertain' : null); }
            scores.falsify = scoreFalsify({ truth, verdicts });
          }
          if (t === 'exploit') scores.exploit = scoreExploit({ proofs: ta.map((a) => ({ entryKind: a.entryKind, reproducerValid: !!a.proof?.reproducerValid, executed: !!a.proof?.executed, state: a.proof?.state ?? null, successes: a.proof?.successes ?? null, runs: a.proof?.runs ?? null })) });
          if (t === 'patch') scores.patch = scorePatch({ patches: ta.map((a) => a.patch ?? { applicable: true, patchProvided: false, exploitBlocked: null, testsPass: null, completeness: null }) });
        }
        results.push({ armId: plan.arm.id, repeat: r, scores, economics: scoreEconomics(mine) });
      }
    }
    const finishedAt = new Date(now()).toISOString();
    const config = { tasks, repeats, concurrency, timeoutMs, budgetUsd, lineTolerance: 3 };
    const armsRecord = arms.map((a) => ({ id: a.id, kind: a.kind, tasks: a.tasks, model: a.model ? { id: a.model.id, provider: a.model.provider, local: a.model.local, version: a.model.version ?? null } : null, adapter: a.adapter.type, repeats: armPlans.find((p) => p.arm.id === a.id).repeats, configDigest: digestOf({ ...a, adapter: { ...a.adapter } }) }));
    const run = {
      schema: RUN_SCHEMA, version: RUN_VERSION,
      runId: `elab-${digestOf({ d: dataset.hash, a: armsRecord, config, startedAt }).slice(-14)}`,
      startedAt, finishedAt, scanner: scannerIdentity(), machine: machineProfile(),
      dataset: { id: manifest.dataset.id, version: manifest.dataset.version, hash: dataset.hash, split: manifest.dataset.split, language: manifest.dataset.language, license: manifest.dataset.license, entries: manifest.entries.length },
      config, arms: armsRecord, leakageAudit: prep.audit, attempts, results,
      complete: jobs.length === attempts.length && !attempts.some((a) => a.status === 'skipped-budget') && prep.audit.status === 'clean',
      incompleteReasons: [
        ...(prep.audit.status !== 'clean' ? [`leakage audit: ${prep.audit.status} (${prep.audit.quarantined.length} quarantined, ${prep.audit.unavailable.length} unavailable)`] : []),
        ...(attempts.some((a) => a.status === 'skipped-budget') ? ['budget reached; later attempts were skipped'] : []),
        ...(signal?.aborted ? ['cancelled'] : []),
      ],
      spendUsdMeasured: spend.usd,
    };
    run.digest = digestOf({ ...run, digest: undefined });
    return { ok: true, run };
  } finally { fs.rmSync(workRoot, { recursive: true, force: true }); }
}
