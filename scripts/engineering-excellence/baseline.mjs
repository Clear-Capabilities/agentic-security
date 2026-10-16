#!/usr/bin/env node
// Factual baseline (E0-02): the identity of this checkout and the results of the existing gates, as measured now.
//   node baseline.mjs                    identity and corpus identifiers only (fast, no gates)
//   node baseline.mjs --run-gates [--only id,id] [--timeout-ms N]   also run the existing offline gates, bounded, with logs
//   node baseline.mjs --render           write docs/engineering-excellence/baseline.json and BASELINE.md from the recorded results
// Nothing is invented: a gate that was not run is `not_run`, one that cannot run is `blocked` with the reason, and the independent
// population is `unmeasured` until a fresh run on this engine exists. Historical figures are labelled historical and carry their engine
// version; they are never presented as the current engine's.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { atomicWriteFile, atomicWriteJson, nowIso } from '../loop-engineering/lib/util.mjs';
import { runBounded } from '../loop-engineering/lib/proc.mjs';
import { REPO_ROOT } from './lib/model.mjs';
import { digestOfFiles, digestOfTree, measurementIdentity } from './lib/measurement-identity.mjs';

const DATA = (root) => join(root, 'scripts', 'engineering-excellence', 'data');
const RESULTS = (root) => join(DATA(root), 'baseline.results.json');
const OUT = (root) => join(root, 'docs', 'engineering-excellence');
const readJson = (p, fb = null) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return fb; } };

// Existing offline gates, run exactly as the repository defines them. `cwd` is relative to the repository root.
export const GATES = Object.freeze([
  { id: 'cve-replay', label: 'Curated CVE replay regression net', argv: ['npm', 'run', 'bench:cve-replay:check'], cwd: 'scanner', kind: 'regression', timeoutMs: 20 * 60 * 1000 },
  { id: 'mutation', label: 'Metamorphic and adversarial mutation gate', argv: ['npm', 'run', 'bench:mutation:check'], cwd: 'scanner', kind: 'regression', timeoutMs: 10 * 60 * 1000 },
  { id: 'protection-verdict', label: 'Protection verdict gate', argv: ['npm', 'run', 'bench:protection-verdict:check'], cwd: 'scanner', kind: 'regression', timeoutMs: 10 * 60 * 1000 },
  { id: 'layer-recall', label: 'Per-layer recall (curated corpus)', argv: ['npm', 'run', 'bench:layer-recall:check'], cwd: 'scanner', kind: 'regression', timeoutMs: 20 * 60 * 1000 },
  { id: 'provenance-accuracy', label: 'Finding provenance accuracy', argv: ['npm', 'run', 'bench:provenance-accuracy:check'], cwd: 'scanner', kind: 'regression', timeoutMs: 10 * 60 * 1000 },
  { id: 'self-scan', label: 'Self-scan precision baseline', argv: ['npm', 'run', 'bench:self-scan:check'], cwd: 'scanner', kind: 'regression', timeoutMs: 30 * 60 * 1000 },
  { id: 'independent-gate', label: 'Independent-population floor check (reads archived results; does not re-measure)', argv: ['npm', 'run', 'bench:independent:gate:check'], cwd: 'scanner', kind: 'archived-floor', timeoutMs: 10 * 60 * 1000 },
]);

function loadResults(root) { return readJson(RESULTS(root), { schemaVersion: 1, gates: {} }); }

function tail(text, n = 14) { return String(text || '').split('\n').filter((l) => l.trim()).slice(-n).join('\n'); }

export async function runGate(root, gate, { timeoutMs } = {}) {
  const logAbs = join(root, 'scripts', 'engineering-excellence', 'logs', 'E0-02', `${gate.id}.log`);
  mkdirSync(dirname(logAbs), { recursive: true });
  rmSync(logAbs, { force: true }); // a re-run replaces its log: the log and the recorded hash describe one run
  const id = measurementIdentity(root, { corpus: null });
  const res = await runBounded({ argv: gate.argv, cwd: join(root, gate.cwd), wallMs: timeoutMs || gate.timeoutMs, logPath: logAbs, redactLog: true, label: `baseline:${gate.id}`, runId: 'ee-baseline' });
  let status = 'failed';
  if (res.outcome === 'spawn-failed') status = 'blocked';
  else if (res.outcome === 'timeout-wall' || res.outcome === 'timeout-idle') status = 'blocked';
  else if (res.outcome === 'exited' && res.exitCode === 0) status = 'passed';
  return {
    id: gate.id, label: gate.label, kind: gate.kind, command: gate.argv.join(' '), cwd: gate.cwd,
    status, outcome: res.outcome, exitCode: res.exitCode, durationMs: res.durationMs, peakRssKb: res.peakRssKb || null,
    reason: status === 'blocked' ? (res.reason || res.outcome) : null,
    summaryTail: tail(`${res.stdoutTail}\n${res.stderrTail}`),
    log: relative(root, logAbs), logSha256: createHash('sha256').update(readFileSync(logAbs)).digest('hex'),
    ranAt: res.endedAt, sourceCommit: id.sourceCommit, measurementValid: id.measurementValid, invalidReasons: id.invalidReasons,
  };
}

export async function runGates(root, { only = null, timeoutMs, onResult = () => {} } = {}) {
  const store = loadResults(root);
  for (const gate of GATES) {
    if (only && !only.includes(gate.id)) continue;
    const r = await runGate(root, gate, { timeoutMs });
    store.gates[gate.id] = r;
    onResult(r);
    atomicWriteJson(RESULTS(root), store); // checkpoint per gate: an interrupted run resumes with --only
  }
  return store;
}

function corpora(root) {
  const m = (rel) => readJson(join(root, rel), null);
  const cve = m('bench/cve-replay/manifest.json');
  const cveBase = m('bench/cve-replay/corpus-baseline.json');
  const indep = m('bench/independent/manifest.json');
  const gate = m('bench/independent/gate-baseline.json');
  const countOf = (x) => (Array.isArray(x) ? x.length : Array.isArray(x?.entries) ? x.entries.length : x && typeof x === 'object' ? Object.keys(x).length : null);
  return {
    cveReplay: { role: 'curated regression net (not an accuracy measurement)', manifest: 'bench/cve-replay/manifest.json', entries: countOf(cve), manifestSha256: digestOfFiles(root, ['bench/cve-replay/manifest.json']), baselineSha256: digestOfFiles(root, ['bench/cve-replay/corpus-baseline.json']), baselineEntries: countOf(cveBase?.entries ?? cveBase) },
    independent: { role: 'independent population (advisory-labelled upstream code)', manifest: 'bench/independent/manifest.json', entries: countOf(indep), manifestSha256: digestOfFiles(root, ['bench/independent/manifest.json']), materialised: existsSync(join(root, 'bench/independent/RESULT.json')) },
    independentArchived: gate ? { engineVersion: gate.engineVersion, measuredAt: gate.measuredAt, overall: gate.overall, label: 'HISTORICAL: this is the archived result of an older engine, not a measurement of the current one' } : null,
    mutation: digestOfTree(root, 'bench/mutation'),
    sard: existsSync(join(root, 'bench/sard')) ? digestOfTree(root, 'bench/sard') : null,
  };
}

export function buildBaseline(root = REPO_ROOT) {
  const results = loadResults(root);
  const identity = measurementIdentity(root, { corpus: { id: 'engineering-excellence-baseline', files: ['bench/cve-replay/manifest.json', 'bench/independent/manifest.json'] } });
  const gates = GATES.map((g) => results.gates[g.id] || { id: g.id, label: g.label, kind: g.kind, command: g.argv.join(' '), cwd: g.cwd, status: 'not_run', reason: 'the baseline gate run has not been performed' });
  const indep = corpora(root);
  const scorecard = readJson(join(root, 'docs/scorecard.json'), null);
  return {
    schemaVersion: 1,
    generatedAt: nowIso(),
    identity,
    gates,
    corpora: indep,
    independentAccuracy: {
      status: 'unmeasured',
      reason: 'No fresh run of the independent population on this engine exists. The only independent numbers in the repository are archived results for an older engine; they are shown separately and are not the current engine.',
      engineVersion: identity.sourceCommit ? readJson(join(root, 'scanner/package.json'), {}).version : null,
      archived: indep.independentArchived,
    },
    scorecardOnDisk: scorecard ? { engineVersion: scorecard.engineVersion || null, keys: Object.keys(scorecard).slice(0, 12) } : null,
    notes: [
      'A gate with status `passed` here only says the existing gate exits 0 on this checkout. The curated regression net sits at its ceiling by construction and is not an accuracy measurement.',
      'Bookkeeping files the program rewrites (status.json, events.jsonl, docs/engineering-excellence) are not counted as a dirty source tree; they are counted in `bookkeepingPathsIgnored`.',
    ],
  };
}

export function renderMarkdown(b) {
  const i = b.identity;
  const L = [];
  L.push('# Baseline', '');
  L.push('> Generated by `node scripts/engineering-excellence/baseline.mjs --render` from recorded gate runs. Gate results come from `scripts/engineering-excellence/data/baseline.results.json`; each row names its log.', '');
  L.push('## Identity', '');
  L.push(`- Commit: \`${i.sourceCommit}\` on \`${i.sourceBranch}\``);
  L.push(`- Source tree: ${i.sourceTreeClean ? 'clean' : `**dirty** (${i.dirtyPaths.length} path(s): ${i.dirtyPaths.slice(0, 6).map((p) => `\`${p}\``).join(', ')}${i.dirtyPaths.length > 6 ? ', ...' : ''})`}; ${i.bookkeepingPathsIgnored} program bookkeeping path(s) not counted`);
  L.push(`- Release trust: **${i.releaseTrust}**${i.invalidReasons.length ? ` (${i.invalidReasons.join(', ')})` : ''}`);
  L.push(`- Bundle: \`${i.bundleSha256}\` (sidecar ${i.bundleSidecarSha256 === i.bundleSha256 ? 'matches' : 'DOES NOT MATCH'})`);
  L.push(`- Lockfile: \`${i.lockfileSha256}\``);
  L.push(`- Config digest: \`${i.configSha256}\`; model endpoint: ${i.config.modelEndpointMode}; knobs set: ${Object.keys(i.config.knobs).length ? Object.keys(i.config.knobs).join(', ') : 'none'}`);
  L.push(`- Toolchain: node ${i.toolchain.node}, npm ${i.toolchain.npm}, git ${i.toolchain.git}, python3 ${i.toolchain.python3 || 'not found'}, java ${i.toolchain.java || 'not found'}, go ${i.toolchain.go || 'not found'}, ghc ${i.toolchain.ghc || 'not found'}`);
  L.push(`- Host: ${i.toolchain.os}, ${i.toolchain.cpus} CPUs, ${i.toolchain.memoryGb} GB`, '');
  L.push('## Existing gates on this checkout', '', '| Gate | Kind | Status | Exit | Duration | Command | Log |', '|---|---|---|---|---|---|---|');
  for (const g of b.gates) L.push(`| ${g.label} | ${g.kind} | **${g.status}**${g.reason ? ` (${g.reason})` : ''} | ${g.exitCode ?? ''} | ${g.durationMs != null ? `${(g.durationMs / 1000).toFixed(1)} s` : ''} | \`${g.command}\` | ${g.log ? `\`${g.log}\`` : ''} |`);
  L.push('', 'Gate `passed` means the existing gate exits 0 on this checkout. For the curated regression net that is a ceiling by construction, not an accuracy figure.', '');
  L.push('## Independent accuracy', '', `Status: **${b.independentAccuracy.status}**. ${b.independentAccuracy.reason}`, '');
  if (b.independentAccuracy.archived) {
    const a = b.independentAccuracy.archived;
    L.push(`Archived, for the record only (${a.label}):`, '', `- engine ${a.engineVersion}, measured ${a.measuredAt}: precision ${(a.overall.precision * 100).toFixed(1)}%, recall ${(a.overall.recall * 100).toFixed(1)}%, F1 ${(a.overall.f1 * 100).toFixed(1)}%`, '');
  }
  L.push('## Corpora', '', '| Corpus | Role | Entries | Manifest digest |', '|---|---|---|---|');
  L.push(`| cve-replay | ${b.corpora.cveReplay.role} | ${b.corpora.cveReplay.entries} | \`${b.corpora.cveReplay.manifestSha256.slice(0, 16)}\` |`);
  L.push(`| independent | ${b.corpora.independent.role} | ${b.corpora.independent.entries} | \`${b.corpora.independent.manifestSha256.slice(0, 16)}\` (materialised locally: ${b.corpora.independent.materialised ? 'yes' : 'no'}) |`, '');
  L.push('## Notes', '', ...b.notes.map((n) => `- ${n}`), '');
  return L.join('\n');
}

export function render(root = REPO_ROOT) {
  const b = buildBaseline(root);
  mkdirSync(OUT(root), { recursive: true });
  atomicWriteJson(join(OUT(root), 'baseline.json'), b);
  atomicWriteFile(join(OUT(root), 'BASELINE.md'), renderMarkdown(b) + '\n', 0o644);
  return b;
}

const arg = (a, k) => { const i = a.indexOf(k); return i >= 0 ? a[i + 1] : null; };
if (import.meta.url === `file://${process.argv[1]}`) {
  const a = process.argv.slice(2);
  const root = a.includes('--root') ? resolve(arg(a, '--root')) : REPO_ROOT;
  (async () => {
    if (a.includes('--run-gates')) {
      const only = arg(a, '--only');
      const store = await runGates(root, { only: only ? only.split(',') : null, timeoutMs: Number(arg(a, '--timeout-ms')) || undefined, onResult: (r) => console.log(`${r.id}: ${r.status} (exit ${r.exitCode}, ${(r.durationMs / 1000).toFixed(1)} s)`) });
      return Object.values(store.gates).some((g) => g.status === 'blocked') ? 1 : 0;
    }
    if (a.includes('--render')) { const b = render(root); console.log(`baseline: identity ${b.identity.releaseTrust}; gates ${b.gates.map((g) => `${g.id}=${g.status}`).join(', ')}; independent accuracy ${b.independentAccuracy.status}`); return 0; }
    console.log(JSON.stringify(measurementIdentity(root), null, 2));
    return 0;
  })().then((c) => process.exit(c)).catch((e) => { console.error(`baseline failed: ${e.message}`); process.exit(2); });
}
