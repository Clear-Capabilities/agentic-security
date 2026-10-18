// CLI for the Eval Lab and the model router: `eval run|compare|report|list`, `models benchmark`, `models route explain`.
// Non-interactive (nothing reads stdin), bounded (every attempt has a timeout, the run is cancellable with SIGINT), and local:
// the lab itself makes no network call. A model arm that is not local needs `--allow-external`, and even then the egress policy
// is consulted for it before it runs.
//
// Exit codes: 0 done, 1 done but incomplete or no recommendation, 4 usage or precondition.
import fs from 'node:fs';
import path from 'node:path';
import { load as loadYaml } from '../../../util/yaml.js';
import { loadDatasetFile } from './dataset.js';
import { runEval, DEFAULT_REPEATS } from './run.js';
import { validateArm, TASKS } from './arms.js';
import { summarizeRun, renderReport, REPORT_FORMATS, PRIMARY } from './report.js';
import { saveRun, loadRun, listRuns, saveScoreboard, loadScoreboard } from './store.js';
import { scoreboardFromRun, mergeScoreboard } from './scoreboard.js';
import { routeTask, explainRoute, ROUTER_TASKS, ROUTER_POLICIES } from '../../routing/policy-router.js';

const MAX_ARMS_BYTES = 1024 * 1024;

function readArms(file) {
  let doc;
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_ARMS_BYTES) return { ok: false, errors: [`${file} is not a regular file under ${MAX_ARMS_BYTES} bytes`] };
    const text = fs.readFileSync(file, 'utf8');
    doc = /\.json$/i.test(file) ? JSON.parse(text) : loadYaml(text);
  } catch (e) { return { ok: false, errors: [`cannot read ${file}: ${String(e.message).split('\n')[0]}`] }; }
  const arms = Array.isArray(doc) ? doc : doc?.arms;
  if (!Array.isArray(arms) || !arms.length) return { ok: false, errors: ['the arms file needs a list of arms (or { "arms": [...] })'] };
  const errors = arms.flatMap((a, i) => { const v = validateArm(a); return v.ok ? [] : v.errors.map((e) => `arms[${i}]: ${e}`); });
  return errors.length ? { ok: false, errors } : { ok: true, arms };
}

const usageRun = () => { console.error('usage: eval run --dataset <file> --arms <file> [--tasks detect,falsify,exploit,patch] [--repeats N] [--concurrency N] [--timeout S] [--budget USD] [--allow-external]\n       eval report <run-id> [--format md|json|csv|html|chart] [--out <file>]\n       eval compare <run-id> [<other-run-id>]\n       eval list'); return 4; };

async function doRun(args, root, { updateScoreboard }) {
  const f = args.flags;
  if (!f.dataset || !f.arms) return usageRun();
  const ds = loadDatasetFile(path.resolve(String(f.dataset)));
  if (!ds.ok) { console.error(`Invalid dataset:\n  ${ds.errors.join('\n  ')}`); return 4; }
  const ar = readArms(path.resolve(String(f.arms)));
  if (!ar.ok) { console.error(`Invalid arms:\n  ${ar.errors.join('\n  ')}`); return 4; }
  const external = ar.arms.filter((a) => a.kind === 'model' && a.model.local === false);
  if (external.length && !f['allow-external']) { console.error(`These arms send source code to a non-local model: ${external.map((a) => a.id).join(', ')}. Pass --allow-external to run them; the egress policy is still consulted for each.`); return 4; }
  const tasks = f.tasks ? String(f.tasks).split(',').map((s) => s.trim()).filter(Boolean) : ['detect'];
  if (!tasks.every((t) => TASKS.includes(t))) { console.error(`--tasks must be some of ${TASKS.join(', ')}`); return 4; }
  const num = (v, name, lo, hi) => { if (v === undefined) return undefined; const n = Number(v); if (!Number.isFinite(n) || n < lo || n > hi) { console.error(`--${name} must be a number from ${lo} to ${hi}`); return null; } return n; };
  const repeats = num(f.repeats, 'repeats', 1, 50); const concurrency = num(f.concurrency, 'concurrency', 1, 32); const timeoutS = num(f.timeout, 'timeout', 1, 3600); const budget = num(f.budget, 'budget', 0, 1e6);
  if (repeats === null || concurrency === null || timeoutS === null || budget === null) return 4;
  const ac = new AbortController(); const onSig = () => ac.abort(); process.once('SIGINT', onSig);
  let res;
  try {
    res = await runEval({ dataset: ds, arms: ar.arms, tasks, repeats: repeats ?? DEFAULT_REPEATS, concurrency: concurrency ?? 2, timeoutMs: (timeoutS ?? 120) * 1000, budgetUsd: budget ?? null, scanRoot: root, signal: ac.signal });
  } finally { process.off('SIGINT', onSig); }
  if (!res.ok) { console.error(`Cannot run:\n  ${res.errors.join('\n  ')}`); return 4; }
  const run = res.run;
  const saved = saveRun(root, run);
  let sbNote = '';
  if (updateScoreboard) {
    const cur = loadScoreboard(root);
    if (cur.tampered) sbNote = 'The existing scoreboard failed its integrity check and was not updated; remove it to start again.';
    else { const w = saveScoreboard(root, mergeScoreboard(cur.doc, scoreboardFromRun(run, ar.arms))); sbNote = w.ok ? 'Scoreboard updated.' : `Scoreboard not stored: ${w.reason}`; }
  }
  const rep = summarizeRun(run);
  if (f.json) console.log(JSON.stringify({ runId: run.runId, stored: saved.ok ? saved.file : null, complete: run.complete, report: rep }, null, 2));
  else { console.log(renderReport(rep, 'md')); console.log(saved.ok ? `Run stored: ${run.runId}` : `(run not stored: ${saved.reason})`); if (sbNote) console.log(sbNote); }
  return run.complete ? 0 : 1;
}

export async function cmdEval(args, root) {
  const sub = args._[1];
  if (sub === 'run') return doRun(args, root, { updateScoreboard: false });
  if (sub === 'list') {
    const runs = listRuns(root);
    if (args.flags.json) { console.log(JSON.stringify(runs, null, 2)); return 0; }
    if (!runs.length) console.log('No eval runs yet. Start one with: eval run --dataset <file> --arms <file>');
    for (const r of runs) console.log(`${r.runId}  ${r.startedAt}  ${r.dataset}  arms: ${r.arms.join(', ')}${r.tampered ? '  (FAILED INTEGRITY CHECK)' : ''}`);
    return 0;
  }
  if (sub === 'report' || sub === 'compare') {
    const id = String(args._[2] ?? '');
    if (!id) return usageRun();
    const a = loadRun(root, id);
    if (a.missing) { console.error(`No run ${id}. List runs with: eval list`); return 4; }
    if (a.tampered) { console.error(`Run ${id} failed its integrity check and is not used.`); return 1; }
    if (sub === 'report') {
      const format = String(args.flags.format ?? 'md');
      if (!REPORT_FORMATS.includes(format)) { console.error(`--format must be one of ${REPORT_FORMATS.join(', ')}`); return 4; }
      const text = renderReport(summarizeRun(a.doc), format);
      if (args.flags.out) { fs.writeFileSync(path.resolve(String(args.flags.out)), text); console.log(`Wrote ${format} report to ${path.resolve(String(args.flags.out))}`); } else process.stdout.write(text);
      return 0;
    }
    const other = args._[3] ? loadRun(root, String(args._[3])) : null;
    if (other && (other.missing || other.tampered)) { console.error(`Run ${args._[3]} is ${other.missing ? 'missing' : 'not intact'}.`); return other.missing ? 4 : 1; }
    return compare(a.doc, other?.doc ?? null, !!args.flags['allow-different-datasets'], !!args.flags.json);
  }
  return usageRun();
}

function compare(a, b, allowDiff, json) {
  const ra = summarizeRun(a);
  if (!b) {
    const rows = ra.arms.map((arm) => ({ arm: arm.id, kind: arm.kind, runs: arm.runs, ...Object.fromEntries(Object.entries(arm.primary).map(([t, s]) => [`${t}:${PRIMARY[t]}`, s?.mean ?? null])), usdPerRun: arm.economics.usd.mean, medianLatencyMs: arm.economics.latencyMedianMs.mean, representative: Object.values(arm.primary).every((s) => s?.representative) }));
    if (json) console.log(JSON.stringify({ runId: a.runId, rows }, null, 2)); else console.log(renderReport(ra, 'md'));
    return 0;
  }
  if (a.dataset.hash !== b.dataset.hash && !allowDiff) { console.error(`These runs used different datasets (${a.dataset.id} ${String(a.dataset.hash).slice(-8)} vs ${b.dataset.id} ${String(b.dataset.hash).slice(-8)}); a comparison would not mean anything. Pass --allow-different-datasets to see the numbers anyway.`); return 1; }
  const rb = summarizeRun(b);
  const out = [];
  for (const arm of ra.arms) {
    const other = rb.arms.find((x) => x.id === arm.id);
    if (!other) continue;
    for (const [t, s] of Object.entries(arm.primary)) { const o = other.primary[t]; if (s?.mean == null || o?.mean == null) continue; out.push({ arm: arm.id, task: t, metric: PRIMARY[t], a: s.mean, b: o.mean, delta: o.mean - s.mean, representative: !!(s.representative && o.representative) }); }
  }
  if (json) console.log(JSON.stringify({ a: a.runId, b: b.runId, sameDataset: a.dataset.hash === b.dataset.hash, rows: out }, null, 2));
  else { console.log(`${a.runId} -> ${b.runId}${a.dataset.hash === b.dataset.hash ? '' : '  (DIFFERENT DATASETS)'}`); for (const r of out) console.log(`  ${r.arm} ${r.task}/${r.metric}: ${(r.a * 100).toFixed(1)}% -> ${(r.b * 100).toFixed(1)}% (${r.delta >= 0 ? '+' : ''}${(r.delta * 100).toFixed(1)} points)${r.representative ? '' : '  not representative'}`); if (!out.length) console.log('  no arm appears in both runs'); }
  return 0;
}

export async function cmdModelsLab(args, root) {
  const sub = args._[1];
  if (sub === 'benchmark') return doRun(args, root, { updateScoreboard: true });
  if (sub === 'route') {
    if (args._[2] !== 'explain') { console.error(`usage: models route explain <${Object.keys(ROUTER_TASKS).join('|')}> [--policy ${ROUTER_POLICIES.join('|')}] [--threshold 0.8] [--tolerance 0.02] [--dataset-hash <hash>]`); return 4; }
    const task = String(args._[3] ?? '');
    if (!task) { console.error(`models route explain needs a task: ${Object.keys(ROUTER_TASKS).join(', ')}`); return 4; }
    const sb = loadScoreboard(root);
    if (sb.tampered) { console.error('The scoreboard failed its integrity check and is not used for routing. Remove .agentic-security/eval-lab/scoreboard.json and re-run: models benchmark'); return 1; }
    const n = (v) => (v === undefined ? undefined : Number(v));
    const r = routeTask({ task, policy: args.flags.policy ? String(args.flags.policy) : 'balanced', scoreboard: sb.doc, qualityThreshold: n(args.flags.threshold) ?? null, ...(args.flags.tolerance !== undefined ? { tolerance: n(args.flags.tolerance) } : {}), ...(args.flags['min-runs'] !== undefined ? { minRuns: n(args.flags['min-runs']) } : {}), datasetHash: args.flags['dataset-hash'] ? String(args.flags['dataset-hash']) : null, scanRoot: root });
    if (args.flags.json) console.log(JSON.stringify(r, null, 2)); else console.log(explainRoute(r));
    return r.ok ? 0 : (r.blocked === 'unknown-task' || r.blocked === 'invalid-policy' ? 4 : 1);
  }
  return null;
}
