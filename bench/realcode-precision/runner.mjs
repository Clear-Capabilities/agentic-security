// Real-code precision for Python and TypeScript, as a GATE (the Haskell gate's sibling, bench/haskell-precision). Records what the engine
// reports at every hand-labelled site of bench/dag/dev-realcode and compares for EQUALITY: a regression fails, and so does an improvement
// nobody recorded.
//
// What it checks, cheapest first, for each set that has labels:
//   1. the label and sample files are the ones the baseline was recorded against (their digests),
//   2. the stored measurement (measurements/<set>.json: for each labelled site, whether the engine reported it and at what severity)
//      recomputes to exactly the committed aggregates in baseline.json (a hand edit of either file fails here),
//   3. LIVE, when every pinned clone of the set exists (or --live): the default scan of the projects reports exactly what the stored
//      measurement says, site by site. Skipped, and said so, when a clone is absent (a hosted runner has none).
//
// usage: node bench/realcode-precision/runner.mjs --check [--live|--no-live] [--json]
//        node bench/realcode-precision/runner.mjs --update-baseline [--results=<dir with <set>/<id>.json>]
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { wilson } from '../_lib/wilson.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const SETS_DIR = path.join(REPO, 'bench', 'dag', 'dev-realcode');
const argv = process.argv.slice(2);
const flag = (n) => argv.includes(`--${n}`);
const opt = (n, d = null) => { const i = argv.indexOf(`--${n}`); return i >= 0 && argv[i + 1] ? argv[i + 1] : (argv.find((a) => a.startsWith(`--${n}=`)) || '').slice(n.length + 3) || d; };
const sha = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const SETS = ['python', 'typescript'].filter((s) => fs.existsSync(path.join(SETS_DIR, `labels-${s}.json`)));
import { stratumOf } from '../dag/dev-realcode/lib.mjs';

function labelsOf(set) { return JSON.parse(fs.readFileSync(path.join(SETS_DIR, `labels-${set}.json`), 'utf8')).labels; }
function digests(set) { return { labels: sha(path.join(SETS_DIR, `labels-${set}.json`)), sample: sha(path.join(SETS_DIR, `sample-${set}.json`)) }; }
function measure(set, resultsDir) {
  // per labelled site: reported (non-info) at the same project/file/line/stratum, and the severity reported
  const now = new Map();
  const dir = path.join(resultsDir, set);
  for (const f of fs.readdirSync(dir).sort()) {
    if (!f.endsWith('.json')) continue;
    const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    for (const r of j.findings) if (r.severity !== 'info') now.set(`${j.id}:${r.file}:${r.line}:${stratumOf(r.vuln, r.cwe)}`, r);
  }
  const sites = {};
  for (const [k, l] of Object.entries(labelsOf(set))) { const r = now.get(l.key); sites[k] = { label: l.label, half: l.half, reported: !!r, severity: r ? r.severity : null }; }
  return { set, sites };
}
function aggregate(m) {
  const out = {};
  for (const half of ['tuning', 'verification', 'all']) {
    let tp = 0, fp = 0, tpLabelled = 0, labelled = 0;
    for (const s of Object.values(m.sites)) { if (half !== 'all' && s.half !== half) continue; labelled++; if (s.label === 'TP') tpLabelled++; if (s.reported) { if (s.label === 'TP') tp++; else fp++; } }
    const flagged = tp + fp; const w = wilson(tp, flagged);
    out[half] = { labelled, tpLabelled, flagged, tp, fp, precision: flagged ? +(tp / flagged).toFixed(4) : null, wilson95: w ? w.map((x) => +x.toFixed(4)) : null };
  }
  return out;
}
function scanLive(set, outDir) {
  const r = spawnSync(process.execPath, [path.join(SETS_DIR, 'scan-all.mjs'), `--set=${set}`, `--out=${outDir}`], { cwd: REPO, encoding: 'utf8', timeout: 3600000, env: { ...process.env, AGENTIC_SECURITY_NO_STATE: '1' } });
  if (r.status !== 0) throw new Error(`scan-all failed for ${set}: ${(r.stderr || r.stdout || '').slice(0, 400)}`);
}
const clonesPresent = (set) => JSON.parse(fs.readFileSync(path.join(SETS_DIR, `manifest-${set}.json`), 'utf8')).projects.every((p) => fs.existsSync(path.join(SETS_DIR, '.cache', p.id, '.git')));

const baselinePath = path.join(HERE, 'baseline.json');
const asJson = flag('json');
const report = { ok: true, sets: {}, notes: [] };
if (!SETS.length) { console.log('realcode precision: no labelled set yet (bench/dag/dev-realcode/labels-<set>.json); nothing to check'); process.exit(0); }

if (flag('update-baseline')) {
  const resultsDir = opt('results') ? path.resolve(opt('results')) : fs.mkdtempSync(path.join(os.tmpdir(), 'realcode-'));
  const baseline = { recordedAt: new Date().toISOString().slice(0, 10), sets: {} };
  for (const set of SETS) {
    if (!opt('results')) { if (!clonesPresent(set)) throw new Error(`pinned clones for ${set} are absent; run bench/dag/dev-realcode/acquire.mjs --set=${set}`); scanLive(set, resultsDir); }
    const m = measure(set, resultsDir);
    fs.writeFileSync(path.join(HERE, 'measurements', `${set}.json`), JSON.stringify(m, null, 1) + '\n');
    baseline.sets[set] = { digests: digests(set), aggregates: aggregate(m) };
  }
  fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2) + '\n');
  console.log(`baseline written: ${path.relative(REPO, baselinePath)} (${SETS.join(', ')})`);
  process.exit(0);
}

if (!fs.existsSync(baselinePath)) { console.log('✗ realcode precision: baseline.json not recorded; run --update-baseline'); process.exit(1); }
const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
let liveDir = null;
for (const set of SETS) {
  const b = baseline.sets[set];
  const r = { ok: true, problems: [] };
  if (!b) { r.ok = false; r.problems.push('no baseline for this set'); report.sets[set] = r; continue; }
  const d = digests(set);
  if (d.labels !== b.digests.labels) r.problems.push('labels file changed since the baseline was recorded');
  if (d.sample !== b.digests.sample) r.problems.push('sample file changed since the baseline was recorded');
  const stored = JSON.parse(fs.readFileSync(path.join(HERE, 'measurements', `${set}.json`), 'utf8'));
  const agg = aggregate(stored);
  if (JSON.stringify(agg) !== JSON.stringify(b.aggregates)) r.problems.push('stored measurement does not recompute to the recorded aggregates');
  for (const [k, s] of Object.entries(stored.sites)) if (s.label === 'TP' && s.reported && s.severity === 'info') r.problems.push(`${k}: a true positive lowered to info`);
  const live = flag('live') || (!flag('no-live') && clonesPresent(set));
  if (live) {
    liveDir = liveDir || fs.mkdtempSync(path.join(os.tmpdir(), 'realcode-live-'));
    try {
      scanLive(set, liveDir);
      const m = measure(set, liveDir);
      for (const [k, s] of Object.entries(m.sites)) {
        const o = stored.sites[k];
        if (!o) { r.problems.push(`${k}: not in the stored measurement`); continue; }
        if (o.reported !== s.reported || (o.reported && o.severity !== s.severity)) r.problems.push(`${k}: stored ${o.reported ? o.severity : 'not reported'}, live ${s.reported ? s.severity : 'not reported'}`);
      }
      r.live = 'ran';
    } catch (e) { r.problems.push(`live scan failed: ${e.message}`); }
  } else { r.live = 'skipped (pinned clones not present; the stored-measurement checks above still ran)'; }
  r.aggregates = agg;
  r.ok = r.problems.length === 0;
  report.sets[set] = r;
  if (!r.ok) report.ok = false;
}
if (asJson) console.log(JSON.stringify(report, null, 1));
else {
  for (const [set, r] of Object.entries(report.sets)) {
    const a = r.aggregates && r.aggregates.all;
    console.log(`${set}: ${a ? `${a.tp}/${a.flagged} labelled sites flagged are true positives (${a.precision == null ? 'n/a' : (100 * a.precision).toFixed(1) + '%'}), tuning ${r.aggregates.tuning.tp}/${r.aggregates.tuning.flagged}, verification ${r.aggregates.verification.tp}/${r.aggregates.verification.flagged}` : ''}; live: ${r.live || 'n/a'}`);
    for (const p of r.problems) console.log(`  ✗ ${p}`);
  }
  console.log(report.ok ? 'PASS' : 'FAIL');
}
process.exit(report.ok ? 0 : 1);
