#!/usr/bin/env node
// bench/dag: real-code validation and measurement for the graph / taint / DAG
// workstream (PRD sections 8.3 and 8.4).
//
//   node bench/dag/run.mjs                 full run (about 10 minutes; see README section in summary.md)
//   node bench/dag/run.mjs --quick         quick tier only (about 1 minute)
//   node bench/dag/run.mjs --check         compare deterministic results to baseline.json (EQUALITY)
//   node bench/dag/run.mjs --update-baseline
//   flags: --reps=N  --only=<substring of unit id>  --synthetic-max=N  --no-write  --out=<dir>
//
// EQUALITY SEMANTICS (same stance as bench/layer-recall): --check fails on a
// regression AND on an unrecorded improvement. A floor-only gate is silent when
// the engine gets better, which is how published tables go stale. Timing and
// memory are measured and reported but are NEVER part of the equality check:
// they vary by host. The check compares only deterministic facts: per-label
// outcomes, per-unit counts, completion statuses, mutant verdicts, incremental
// unit counts, and synthetic graph digests and SCC properties.
//
// Each unit runs in its own child process so peak RSS is attributable and a
// crash or timeout in one unit cannot take the run down.
//
// NOT wired into the pre-push gate (by instruction); run it deliberately.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { acquire, CACHE } from './acquire.mjs';
import { FAMILIES } from './synthetic/generate.mjs';
import { isHeldOut, outcome, scoreSiteLabel, scoreFlowLabel, aggregate } from './lib/labels.mjs';
import { renderSummary } from './lib/summary.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const BASELINE = path.join(HERE, 'baseline.json');
const UNIT_TIMEOUT_MS = Number(process.env.AGENTIC_SECURITY_BENCH_ENTRY_TIMEOUT_MS) || 20 * 60 * 1000;

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
if (flag('--help') || flag('-h')) {
  console.log('usage: node bench/dag/run.mjs [--quick] [--check | --update-baseline] [--reps=N] [--only=<unit substring>] [--synthetic-max=N] [--no-write] [--out=<dir>]');
  process.exit(0);
}
const opt = (n, d) => { const a = argv.find((x) => x.startsWith(`${n}=`)); return a ? a.slice(n.length + 1) : d; };

// ---------------------------------------------------------------- child mode
if (flag('--child')) {
  const spec = JSON.parse(Buffer.from(opt('--spec', ''), 'base64').toString('utf8'));
  let result;
  try {
    if (spec.kind === 'scan') result = await (await import('./lib/scan-unit.mjs')).runUnit(spec);
    else if (spec.kind === 'incremental') result = await (await import('./lib/incremental.mjs')).incrementalProbe(spec);
    else if (spec.kind === 'synthetic') result = (await import('./synthetic/measure.mjs')).measureSynthetic(spec);
    else throw new Error(`unknown child kind ${spec.kind}`);
  } catch (e) {
    result = { id: spec.id, status: 'error', error: String((e && e.message) || e) };
  }
  process.stdout.write(`\n@@RESULT@@${JSON.stringify(result)}\n`);
  process.exit(0);
}

// -------------------------------------------------------------- parent mode
const QUICK = flag('--quick');
const CHECK = flag('--check');
const UPDATE = flag('--update-baseline');
const REPS = Math.max(1, Number(opt('--reps', '1')) || 1);
const ONLY = opt('--only', null);
const NO_WRITE = flag('--no-write');
const memGb = os.totalmem() / 2 ** 30;
const SYN_MAX = Number(opt('--synthetic-max', memGb >= 8 ? 1000000 : 100000));
const SYN_SIZES = (QUICK ? [1000, 10000] : [1000, 10000, 100000, 1000000]).filter((n) => n <= SYN_MAX);
const SYN_SEED = 20261025;

const manifest = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));
const realLabels = JSON.parse(fs.readFileSync(path.join(HERE, 'labels', 'real.json'), 'utf8')).labels;
const fixtureLabelsDoc = JSON.parse(fs.readFileSync(path.join(HERE, 'labels', 'multiservice.json'), 'utf8'));
const mutantsDoc = JSON.parse(fs.readFileSync(path.join(HERE, 'fixtures', 'mutants.json'), 'utf8'));
const FIXTURE_SRC = path.join(HERE, 'fixtures', 'multiservice', 'src');

const t0 = Date.now();
const log = (m) => process.stderr.write(`[dag ${String(Math.round((Date.now() - t0) / 1000)).padStart(4)}s] ${m}\n`);

function runChild(spec, extraNodeArgs = []) {
  const r = spawnSync(process.execPath, [...extraNodeArgs, fileURLToPath(import.meta.url), '--child', `--spec=${Buffer.from(JSON.stringify(spec)).toString('base64')}`], {
    encoding: 'utf8', timeout: UNIT_TIMEOUT_MS, maxBuffer: 256 * 1024 * 1024, env: { ...process.env },
  });
  if (r.error && r.error.code === 'ETIMEDOUT') return { id: spec.id, status: 'timeout', timeoutMs: UNIT_TIMEOUT_MS };
  const m = /@@RESULT@@(.*)\n/.exec(r.stdout || '');
  if (!m) return { id: spec.id, status: 'error', error: `child exited ${r.status}: ${(r.stderr || '').slice(-300)}` };
  return JSON.parse(m[1]);
}

function sh(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: REPO, encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

const pct = (arr, p) => {
  if (!arr.length) return null;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)];
};

// ----------------------------------------------------------- unit planning
const projects = new Map(manifest.projects.map((p) => [p.id, p]));
const acquired = new Map();
function ensureProject(id) {
  if (acquired.has(id)) return acquired.get(id);
  const p = projects.get(id);
  const r = acquire(p);
  acquired.set(id, r);
  if (!r.ok) log(`project ${id} unresolved: ${r.reason}`);
  return r;
}

const realUnits = [];
for (const p of manifest.projects) {
  for (const root of p.scanRoots) {
    if (QUICK && root.tier !== 'quick') continue;
    const id = `${p.id}/${root.path}`;
    if (ONLY && !id.includes(ONLY)) continue;
    realUnits.push({ id, project: p.id, language: p.language, root: root.path });
  }
}

// ------------------------------------------------------------------- run
const results = { real: {}, fixture: null, mutants: {}, incremental: {}, synthetic: {} };

for (const u of realUnits) {
  const pr = ensureProject(u.project);
  if (!pr.ok) { results.real[u.id] = { id: u.id, status: 'unresolved', reason: pr.reason, language: u.language }; continue; }
  const dir = path.join(CACHE, u.project, u.root);
  const samples = [];
  let last = null;
  for (let i = 0; i < REPS; i++) {
    log(`scan ${u.id} (${i + 1}/${REPS})`);
    last = runChild({ kind: 'scan', id: u.id, dir, prefix: u.root });
    samples.push(last);
    if (last.status !== 'ok') break;
  }
  results.real[u.id] = { ...last, language: u.language, project: u.project, msSamples: samples.filter((s) => s.status === 'ok').map((s) => s.ms), peakRssMb: Math.max(...samples.map((s) => s.peakRssMb || 0)) };
}

const wantFixture = !ONLY || 'fixture'.includes(ONLY) || ONLY.startsWith('fixture') || ONLY.startsWith('mutant');
if (wantFixture) {
  log('scan fixture/multiservice');
  results.fixture = runChild({ kind: 'scan', id: 'fixture/multiservice', dir: FIXTURE_SRC, prefix: '' });
  for (const m of mutantsDoc.mutants) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dag-mut-'));
    try {
      fs.cpSync(FIXTURE_SRC, tmp, { recursive: true });
      const fp = path.join(tmp, m.file);
      const src = fs.readFileSync(fp, 'utf8');
      if (!src.includes(m.find)) { results.mutants[m.id] = { id: m.id, status: 'invalid-mutant', reason: 'find string not present in fixture' }; continue; }
      fs.writeFileSync(fp, src.replace(m.find, () => m.replace));
      log(`scan mutant ${m.id}`);
      results.mutants[m.id] = { ...runChild({ kind: 'scan', id: `mutant/${m.id}`, dir: tmp, prefix: '' }), def: m };
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
}

const incTargets = [{ id: 'fixture', dir: FIXTURE_SRC, prefix: '' }];
if (!QUICK && acquire(projects.get('fastify')).ok) incTargets.push({ id: 'fastify/examples', dir: path.join(CACHE, 'fastify', 'examples'), prefix: 'examples' });
for (const t of incTargets) {
  if (ONLY && !`incremental/${t.id}`.includes(ONLY)) continue;
  log(`incremental ${t.id}`);
  results.incremental[t.id] = runChild({ kind: 'incremental', id: t.id, dir: t.dir, prefix: t.prefix });
}

for (const family of FAMILIES) {
  for (const n of SYN_SIZES) {
    const id = `${family}/${n}`;
    if (ONLY && !`synthetic/${id}`.includes(ONLY)) continue;
    log(`synthetic ${id}`);
    results.synthetic[id] = runChild({ kind: 'synthetic', family, n, seed: SYN_SEED }, ['--max-old-space-size=8192']);
  }
}

// ----------------------------------------------------------- evidence replay
function findWitnessBundle() {
  const hits = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/^witness-bundle\.[cm]?js$/.test(e.name)) hits.push(path.relative(REPO, p)); } };
  walk(path.join(REPO, 'scanner', 'src'));
  return hits;
}
const wb = findWitnessBundle();
const evidenceReplay = wb.length === 0
  ? { status: 'skipped', reason: 'scanner/src has no witness-bundle module; there is no evidence bundle to replay' }
  : { status: 'skipped', reason: `witness-bundle module present (${wb.join(', ')}) but bench/dag has no replay adapter yet; refusing to report a replay rate it did not measure` };

// -------------------------------------------------------------- scoring
const labelRows = [];
const realFindings = {};
for (const [id, r] of Object.entries(results.real)) {
  if (r.status !== 'ok') continue;
  (realFindings[r.project] ||= []).push(...r.findings);
}
const projectsRun = new Set(Object.values(results.real).filter((r) => r.status === 'ok').map((r) => r.project));
const rootsRun = (projectId) => Object.values(results.real).filter((r) => r.status === 'ok' && r.project === projectId).map((r) => r.id.split('/').slice(1).join('/'));
for (const l of realLabels) {
  if (!projectsRun.has(l.project)) continue;
  // A label is scored only when the scan root containing its file ran.
  const covered = rootsRun(l.project).some((root) => l.file === root || l.file.startsWith(`${root}/`));
  if (!covered) continue;
  const s = scoreSiteLabel(l, realFindings[l.project] || [], 0);
  labelRows.push({ id: l.id, project: l.project, language: l.language, class: l.class, verdict: l.verdict, outcome: outcome(l.verdict, s.reported), fileLevel: s.fileLevel, heldOut: isHeldOut(l.id) });
}

const fixtureRows = [];
if (results.fixture && results.fixture.status === 'ok') {
  for (const l of fixtureLabelsDoc.labels) {
    if (l.type === 'flow') {
      const s = scoreFlowLabel(l, (results.fixture.graph && results.fixture.graph.flows) || []);
      fixtureRows.push({ id: l.id, type: 'flow', verdict: l.verdict, outcome: outcome(l.verdict, s.reported), sinkMatch: s.sinkMatch, construct: l.construct });
    } else {
      const s = scoreSiteLabel(l, results.fixture.findings, fixtureLabelsDoc.siteTolerance);
      fixtureRows.push({ id: l.id, type: 'site', verdict: l.verdict, outcome: outcome(l.verdict, s.reported), construct: l.construct });
    }
  }
}

const mutantRows = [];
function reported(runResult, spec, kind) {
  if (!runResult || runResult.status !== 'ok') return null;
  if (kind === 'site') return scoreSiteLabel({ ...spec, verdict: 'positive' }, runResult.findings, fixtureLabelsDoc.siteTolerance).reported;
  return scoreFlowLabel(spec, (runResult.graph && runResult.graph.flows) || []).reported;
}
for (const m of mutantsDoc.mutants) {
  const r = results.mutants[m.id];
  if (!r || r.status !== 'ok') { mutantRows.push({ id: m.id, kind: m.kind, status: r ? r.status : 'not-run' }); continue; }
  const kind = m.site ? 'site' : 'flow';
  const spec = m.site || m.flow;
  const before = reported(results.fixture, spec, kind);
  const after = reported(r, spec, kind);
  const expected = m.expectAfter === 'reported';
  mutantRows.push({ id: m.id, kind: m.kind, status: 'ok', baseReported: before, afterReported: after, expectedReported: expected, correct: after === expected, flipped: before !== after, flipExpected: before !== expected });
}

// ------------------------------------------------------- per-language stats
const languages = {};
for (const lang of ['js', 'haskell', 'nix']) {
  const units = Object.values(results.real).filter((r) => r.language === lang);
  const ok = units.filter((r) => r.status === 'ok');
  if (!units.length) continue;
  const rows = labelRows.filter((r) => r.language === lang);
  const withGraph = ok.filter((r) => r.graph);
  const times = ok.flatMap((r) => r.msSamples);
  const callSites = withGraph.reduce((a, r) => a + (r.graph.callStatementSites || 0), 0);
  const trunc = withGraph.reduce((a, r) => a + (r.graph.truncatedQueries || 0), 0);
  languages[lang] = {
    units: units.length, unitsOk: ok.length, unitsNotOk: units.length - ok.length,
    unitsWithGraph: withGraph.length,
    unitsGraphComplete: withGraph.filter((r) => r.graph.completion.status === 'complete').length,
    completionRate: withGraph.length ? Math.round((withGraph.filter((r) => r.graph.completion.status === 'complete').length / withGraph.length) * 10000) / 10000 : null,
    truncatedQueries: trunc, queryDenominator: callSites,
    truncatedQueryRate: callSites ? Math.round((trunc / callSites) * 10000) / 10000 : null,
    timeMs: { samples: times.length, p50: pct(times, 50), p95: pct(times, 95), max: times.length ? Math.max(...times) : null },
    peakRssMb: ok.length ? Math.max(...ok.map((r) => r.peakRssMb)) : null,
    labels: aggregate(rows),
    labelsHeldOut: aggregate(rows.filter((r) => r.heldOut)),
    labelsDevelopment: aggregate(rows.filter((r) => !r.heldOut)),
    labelsLineOnly: aggregate(rows.map((r) => (r.fileLevel ? { ...r, outcome: outcome(r.verdict, false), fileLevel: false } : r))),
    files: ok.reduce((a, r) => a + (r.files || 0), 0),
    findings: ok.reduce((a, r) => a + r.findings.length, 0),
  };
}

// ------------------------------------------------- deterministic projection
const det = { schema: 1, units: {}, labels: {}, fixture: {}, mutants: {}, incremental: {}, synthetic: {}, evidenceReplay: evidenceReplay.status };
for (const [id, r] of Object.entries(results.real)) {
  det.units[id] = r.status !== 'ok' ? { status: r.status } : {
    status: 'ok', files: r.files, findings: r.findings.length,
    lineageFailure: r.lineage ? r.lineage.failure : null,
    graph: r.graph ? { status: r.graph.completion.status, nodes: r.graph.nodes, edges: r.graph.edges, flows: r.graph.flowCount, callStatementSites: r.graph.callStatementSites, connectedSinkSites: r.graph.connectedSinkSites, truncatedQueries: r.graph.truncatedQueries, pathsEnumerated: r.graph.pathsEnumerated } : null,
  };
}
if (results.fixture) det.units['fixture/multiservice'] = results.fixture.status !== 'ok' ? { status: results.fixture.status } : { status: 'ok', files: results.fixture.files, findings: results.fixture.findings.length, graph: results.fixture.graph ? { status: results.fixture.graph.completion.status, nodes: results.fixture.graph.nodes, edges: results.fixture.graph.edges, flows: results.fixture.graph.flowCount, truncatedQueries: results.fixture.graph.truncatedQueries } : null };
for (const r of labelRows) det.labels[r.id] = r.outcome;
for (const r of fixtureRows) det.fixture[r.id] = r.type === 'flow' ? `${r.outcome}${r.outcome === 'TP' ? (r.sinkMatch ? '+sink' : '-sink') : ''}` : r.outcome;
for (const r of mutantRows.filter((x) => x.status !== 'not-run')) det.mutants[r.id] = r.status === 'ok' ? { base: r.baseReported, after: r.afterReported, correct: r.correct } : { status: r.status };
for (const [id, r] of Object.entries(results.incremental)) det.incremental[id] = r.status !== 'ok' ? { status: r.status } : { summaryUnits: r.summaryUnits, restorable: r.restorableEmptyEntryUnits, changedFiles: r.changedFiles, changedUnits: r.changedUnits, reused: r.reusedUnits, invalidated: r.invalidatedUnits, parityEqual: r.parity.equal };
for (const [id, r] of Object.entries(results.synthetic)) det.synthetic[id] = r.status === 'error' || r.status === 'timeout' ? { status: r.status } : { digest: r.digest, observed: r.observed, matchesExpected: r.matchesExpected, verifyScc: r.verifyScc };

// ------------------------------------------------------------------- output
const commit = sh('git', ['rev-parse', 'HEAD']) || 'unknown';
const dirty = (sh('git', ['status', '--porcelain']) || '').length > 0;
const env = { node: process.version, platform: `${process.platform}-${process.arch}`, cpus: os.cpus().length, memGb: Math.round(memGb), mode: QUICK ? 'quick' : 'full', reps: REPS, syntheticMaxNodes: SYN_MAX };
const out = {
  schema: 1, commit, worktreeDirty: dirty, generatedAt: new Date().toISOString(), wallClockSeconds: Math.round((Date.now() - t0) / 1000), env,
  manifestPins: manifest.projects.map((p) => ({ id: p.id, commit: p.commit, resolved: !!(acquired.get(p.id) || {}).ok })),
  languages, units: results.real, fixture: results.fixture && { ...results.fixture, findings: undefined, flowsRecorded: results.fixture.graph && results.fixture.graph.flows.length },
  labelRows, fixtureRows, mutantRows, incremental: results.incremental, synthetic: results.synthetic, evidenceReplay, deterministic: det,
};

if (!CHECK && !NO_WRITE) {
  const dir = opt('--out', path.join(HERE, 'results', commit.slice(0, 12)));
  fs.mkdirSync(dir, { recursive: true });
  const slim = JSON.parse(JSON.stringify(out, (k, v) => (k === 'findings' ? undefined : v)));
  fs.writeFileSync(path.join(dir, QUICK ? 'results.quick.json' : 'results.json'), JSON.stringify(slim, null, 1) + '\n');
  fs.writeFileSync(path.join(dir, QUICK ? 'summary.quick.md' : 'summary.md'), renderSummary(out, manifest, { realLabels, fixtureLabelsDoc }));
  log(`wrote ${path.relative(REPO, dir)}`);
}

// ------------------------------------------------------------ baseline check
function diffObj(a, b, p, acc, { subsetOfBase }) {
  if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
    for (const k of Object.keys(a)) {
      if (!(k in b)) acc.push(`${p}${k}: present now, absent in baseline (unrecorded)`); else diffObj(a[k], b[k], `${p}${k}.`, acc, { subsetOfBase: false });
    }
    if (!subsetOfBase) for (const k of Object.keys(b)) if (!(k in a)) acc.push(`${p}${k}: in baseline, absent now`);
    return;
  }
  if (JSON.stringify(a) !== JSON.stringify(b)) acc.push(`${p.replace(/\.$/, '')}: now ${JSON.stringify(a)}, baseline ${JSON.stringify(b)}`);
}

if (UPDATE) {
  if (QUICK || ONLY) { console.error('refusing to write a baseline from a partial run (--quick/--only)'); process.exit(2); }
  if (Object.values(results.real).some((r) => r.status !== 'ok')) { console.error('refusing to baseline a run with non-ok units'); process.exit(2); }
  fs.writeFileSync(BASELINE, JSON.stringify({ note: 'Deterministic facts only. Regenerate with: node bench/dag/run.mjs --update-baseline. Timing and memory are never stored here.', recordedAtCommit: commit, deterministic: det }, null, 1) + '\n');
  console.log(`baseline written (${Object.keys(det.units).length} units, ${Object.keys(det.labels).length} labels)`);
  process.exit(0);
}

if (CHECK) {
  if (!fs.existsSync(BASELINE)) { console.error('FAIL: no baseline.json; run --update-baseline from a full run'); process.exit(1); }
  const base = JSON.parse(fs.readFileSync(BASELINE, 'utf8')).deterministic;
  const diffs = [];
  const partial = QUICK || !!ONLY;
  for (const sec of ['units', 'labels', 'fixture', 'mutants', 'incremental', 'synthetic']) diffObj(det[sec], base[sec] || {}, `${sec}.`, diffs, { subsetOfBase: partial });
  if (det.evidenceReplay !== base.evidenceReplay) diffs.push(`evidenceReplay: now ${det.evidenceReplay}, baseline ${base.evidenceReplay}`);
  const bad = Object.values(results.real).filter((r) => r.status !== 'ok');
  if (bad.length) diffs.push(`non-ok units: ${bad.map((r) => `${r.id}=${r.status}`).join(', ')}`);
  if (diffs.length) {
    console.error(`bench:dag:check FAILED (${diffs.length} difference${diffs.length === 1 ? '' : 's'}). Equality semantics: an unrecorded improvement fails too.`);
    for (const d of diffs.slice(0, 60)) console.error(`  ${d}`);
    if (diffs.length > 60) console.error(`  ... ${diffs.length - 60} more`);
    console.error('If the change is intended, re-baseline deliberately: node bench/dag/run.mjs --update-baseline');
    process.exit(1);
  }
  console.log(`bench:dag:check OK (${partial ? 'partial' : 'full'} run matches baseline exactly)`);
  process.exit(0);
}

console.log(`done: ${out.wallClockSeconds}s, ${labelRows.length} real labels scored, ${mutantRows.length} mutants, ${Object.keys(results.synthetic).length} synthetic graphs`);
