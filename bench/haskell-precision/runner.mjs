// Haskell real-code precision, as a GATE. A precision regression on real Haskell was invisible: nothing in any script, CI job or release check ran the
// real-code sets, which is how the layer-recall table went stale before. This gate records what the engine does at every hand-labelled site of the
// development and fresh real-code sets (bench/dag/dev-haskell) and compares for EQUALITY: a regression fails, and so does an improvement nobody
// recorded (the lesson bench/layer-recall already paid for: a floor that is silent on a rise leaves the published table stale).
//
// What it checks, cheapest first:
//   1. the label files are the ones the baseline was recorded against (their digests),
//   2. the stored measurement (measurements/development.json: for each labelled site, what the engine reported there) recomputes to exactly the
//      committed aggregates in baseline.json (a hand edit of either file fails here),
//   3. LIVE, when the pinned clones exist (or --live): the real default scan of the 14 projects reports exactly what the stored measurement says,
//      site by site (severity, reachability status, lowering). Skipped, and said so, when the clones are absent (a hosted runner has none): the stored
//      checks above still run there,
//   4. invariants that hold whatever the baseline says: no site labelled a TRUE POSITIVE may sit in `unreachable-in-project`,
//   5. the sealed independent set, if a baseline for it has been recorded (see below).
//
// The SEALED independent set (bench/dag/independent-haskell) is never scanned here. It is spent once per release by running its own run.mjs deliberately
// and logging that in its USE-LOG.md. This gate only reads the committed result of that run: the labels digest must be valid, results.json must carry
// that digest, and its aggregate must equal the recorded sealed baseline. `--update-sealed-baseline` records it; `--require-sealed` (the release check)
// fails while none is recorded. Until then the default check prints that the sealed baseline is not recorded and does not touch its files at all.
//
// usage: node bench/haskell-precision/runner.mjs --check [--live|--no-live] [--require-sealed] [--json]
//        node bench/haskell-precision/runner.mjs --update-baseline [--dev-results <dir> --fresh-results <dir>]
//        node bench/haskell-precision/runner.mjs --update-sealed-baseline
// test hooks: --labels-dir <dir> (default bench/dag/dev-haskell), --data-dir <dir> (default bench/haskell-precision), --sealed-dir <dir>,
//             --dev-results <dir> / --fresh-results <dir> (scan-all output to use instead of scanning)
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { wilson } from '../_lib/wilson.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const argv = process.argv.slice(2);
const flag = (n) => argv.includes(`--${n}`);
const opt = (n, d = null) => { const i = argv.indexOf(`--${n}`); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };
const LABELS = path.resolve(opt('labels-dir', path.join(REPO, 'bench', 'dag', 'dev-haskell')));
const DATA = path.resolve(opt('data-dir', HERE));
const SEALED = path.resolve(opt('sealed-dir', path.join(REPO, 'bench', 'dag', 'independent-haskell')));
const BASELINE = path.join(DATA, 'baseline.json');
const MEASUREMENT = path.join(DATA, 'measurements', 'development.json');
const json = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const sha = (v) => crypto.createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(v)).digest('hex');
const stratumOf = (v) => (/^Path Traversal/.test(v) ? 'path-traversal' : String(v).replace(/^Unsafe boundary: .*/, 'unsafe-boundary'));
const STATUSES = ['entrypoint-reachable', 'external-api', 'unknown', 'unreachable-in-project', 'no-verdict'];

// ── labels ───────────────────────────────────────────────────────────────────
function loadLabels() {
  const dev = json(path.join(LABELS, 'labels.json')).labels;
  const rem = json(path.join(LABELS, 'labels-remainder.json')).labels;
  const fresh = json(path.join(LABELS, 'fresh-labels.json')).labels;
  const sets = { 'development-tuning': [], 'development-verification': [], 'development-remainder': [], fresh: [] };
  for (const l of Object.values(dev)) sets[l.half === 'tuning' ? 'development-tuning' : 'development-verification'].push({ key: `${l.project}:${l.file}:${l.line}:${stratumOf(l.vuln)}`, label: l.label });
  for (const [k, l] of Object.entries(rem)) sets['development-remainder'].push({ key: k, label: l.label });
  for (const [k, l] of Object.entries(fresh)) sets.fresh.push({ key: k, label: l.label });
  for (const v of Object.values(sets)) v.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  // the label files are digested as the sets they define, not by file bytes, so reformatting does not matter and a changed verdict does
  const digests = Object.fromEntries(Object.entries(sets).map(([k, v]) => [k, sha(v.map((x) => [x.key, x.label]))]));
  return { sets, digests };
}

// ── what the engine reported at each labelled site ───────────────────────────
// scan-all.mjs writes <dir>/<project>.json with { id, haskell: [rows] }; a row carries severity, reachability {status} and originalSeverity.
function loadResults(dir) {
  const rows = new Map();
  const census = {};
  for (const f of fs.readdirSync(dir).sort()) {
    if (!f.endsWith('.json')) continue;
    const j = json(path.join(dir, f));
    const c = (census[j.id] = { rows: 0, flagged: 0, loweredToInfo: 0, byStatus: {} });
    for (const r of j.haskell) {
      const k = `${j.id}:${r.file}:${r.line}:${stratumOf(r.vuln)}`;
      if (!rows.has(k)) rows.set(k, []);
      const st = r.reachability && r.reachability.status ? r.reachability.status : null;
      rows.get(k).push([r.severity, st, r.originalSeverity || null, r.parser || null]);
      c.rows++;
      if (r.severity === 'info') c.loweredToInfo++; else c.flagged++;
      const sk = st || 'no-verdict';
      c.byStatus[sk] = (c.byStatus[sk] || 0) + 1;
    }
  }
  return { rows, census };
}
// the stored measurement keeps only labelled sites: { set: { key: [[severity, status, originalSeverity, parser], ...] } }
function measurementOf(sets, dev, fresh) {
  const sites = {};
  for (const [name, items] of Object.entries(sets)) {
    sites[name] = {};
    const rows = name === 'fresh' ? fresh.rows : dev.rows;
    for (const { key } of items) if (rows.has(key)) sites[name][key] = rows.get(key).map((r) => r.slice()).sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
  }
  // every project's whole report, not only the labelled sites: a new flagged site anywhere (an unlabelled false positive) changes the census
  return { sites, census: { dev: dev.census, fresh: fresh.census } };
}
const statusOfSite = (rows) => {
  if (!rows || !rows.length) return null;
  const withV = rows.filter((r) => r[1]);
  if (!withV.length) return 'no-verdict';
  const order = ['entrypoint-reachable', 'external-api', 'unknown', 'unreachable-in-project'];
  return withV.map((r) => r[1]).sort((a, b) => order.indexOf(a) - order.indexOf(b))[0];
};
function aggregate(sets, measurement) {
  const out = {};
  for (const [name, items] of Object.entries(sets)) {
    const a = { labelled: items.length, reported: 0, notReported: 0, flagged: 0, loweredToInfo: 0, tp: 0, fp: 0, tpNotFlagged: 0, byStatus: Object.fromEntries(STATUSES.map((s) => [s, { TP: 0, FP: 0 }])) };
    for (const { key, label } of items) {
      const rows = measurement.sites[name][key];
      if (!rows) { a.notReported++; if (label === 'TP') a.tpNotFlagged++; continue; }
      a.reported++;
      const flagged = rows.some((r) => r[0] !== 'info');
      if (flagged) { a.flagged++; a[label === 'TP' ? 'tp' : 'fp']++; } else { a.loweredToInfo++; if (label === 'TP') a.tpNotFlagged++; }
      a.byStatus[statusOfSite(rows)][label === 'TP' ? 'TP' : 'FP']++;
    }
    a.precision = a.flagged ? +(a.tp / a.flagged).toFixed(4) : null;
    const ci = wilson(a.tp, a.flagged);
    a.wilson95 = ci ? ci.map((x) => +x.toFixed(4)) : null;
    out[name] = a;
  }
  out.census = measurement.census;
  return out;
}
const unreachableTps = (sets, measurement) => {
  const bad = [];
  for (const [name, items] of Object.entries(sets)) for (const { key, label } of items) if (label === 'TP' && statusOfSite(measurement.sites[name][key]) === 'unreachable-in-project') bad.push(`${name}: ${key}`);
  return bad;
};

// ── the live scan ────────────────────────────────────────────────────────────
function clonesPresent() {
  const missing = [];
  for (const [mf, set] of [['manifest.json', 'dev'], ['manifest-fresh.json', 'fresh']]) {
    let m; try { m = json(path.join(LABELS, mf)); } catch { missing.push(`${mf} unreadable`); continue; }
    for (const p of m.projects) if (!fs.existsSync(path.join(LABELS, '.cache', p.id, '.git'))) missing.push(`${set}/${p.id}`);
  }
  return missing;
}
function scanLive() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-precision-'));
  const dirs = {};
  for (const set of ['dev', 'fresh']) {
    dirs[set] = path.join(tmp, set);
    const r = spawnSync(process.execPath, [path.join(LABELS, 'scan-all.mjs'), ...(set === 'fresh' ? ['--set=fresh'] : []), `--out=${dirs[set]}`], { encoding: 'utf8', maxBuffer: 1 << 28, env: process.env });
    if (r.status !== 0 || /\[exit [1-9]/.test(r.stdout || '')) throw new Error(`the ${set} scan failed:\n${(r.stdout || '').slice(-600)}${(r.stderr || '').slice(-600)}`);
  }
  return dirs;
}
const resultsDirs = () => {
  const dev = opt('dev-results'); const fresh = opt('fresh-results');
  if (dev || fresh) { if (!dev || !fresh) throw new Error('--dev-results and --fresh-results go together'); return { dev: path.resolve(dev), fresh: path.resolve(fresh) }; }
  return null;
};

// ── sealed set (committed result only; never scanned here) ───────────────────
function sealedNow() {
  const labels = json(path.join(SEALED, 'labels.json'));
  const results = json(path.join(SEALED, 'results.json'));
  const all = results.all && results.all['all haskell projects'];
  return { labelsDigest: labels.labelsDigest, resultsDigest: results.labelsDigest, scannerVersion: results.scannerVersion, all: all ? { flagged: all.flagged, tp: all.tp, fp: all.fp, ambiguous: all.ambiguous, unlabeled: all.unlabeled, precision: all.precision } : null };
}

// ── commands ─────────────────────────────────────────────────────────────────
const fail = (msgs, code = 1) => { for (const m of [].concat(msgs)) console.error(m); process.exit(code); };
const engineVersion = () => { try { return json(path.join(REPO, 'scanner', 'package.json')).version; } catch { return null; } };

function updateBaseline() {
  const { sets, digests } = loadLabels();
  let dirs = resultsDirs();
  if (!dirs) {
    const missing = clonesPresent();
    if (missing.length) fail([`cannot measure: pinned clones missing (${missing.join(', ')}). Fetch them with \`node bench/dag/dev-haskell/acquire.mjs\` and \`node bench/dag/dev-haskell/acquire.mjs --set=fresh\`.`], 1);
    dirs = scanLive();
  }
  const measurement = measurementOf(sets, loadResults(dirs.dev), loadResults(dirs.fresh));
  const bad = unreachableTps(sets, measurement);
  if (bad.length) fail([`refusing to record: ${bad.length} site(s) labelled TRUE POSITIVE are in unreachable-in-project (the mechanism is wrong, not the label):`, ...bad.map((b) => `  ${b}`)]);
  const prior = fs.existsSync(BASELINE) ? json(BASELINE) : {};
  fs.mkdirSync(path.dirname(MEASUREMENT), { recursive: true });
  fs.writeFileSync(MEASUREMENT, JSON.stringify({ schema: 'agentic-security/haskell-precision-measurement@1', measurement }, null, 1) + '\n');
  fs.writeFileSync(BASELINE, JSON.stringify({
    schema: 'agentic-security/haskell-precision-baseline@1',
    comparison: 'equality: a regression fails, and so does an improvement that was not recorded here',
    engineVersion: engineVersion(), labelsDigests: digests, aggregates: aggregate(sets, measurement), sealed: prior.sealed || null,
  }, null, 1) + '\n');
  console.log(`recorded ${Object.values(sets).reduce((n, v) => n + v.length, 0)} labelled sites -> ${path.relative(process.cwd(), BASELINE)}, ${path.relative(process.cwd(), MEASUREMENT)}`);
  for (const [k, a] of Object.entries(aggregate(sets, measurement)).filter(([k]) => k !== 'census')) console.log(`  ${k.padEnd(26)} flagged ${a.flagged} (tp ${a.tp}, fp ${a.fp}), reported ${a.reported}/${a.labelled}, lowered ${a.loweredToInfo}`);
}

function updateSealed() {
  if (!fs.existsSync(BASELINE)) fail('record the development baseline first: --update-baseline');
  const s = sealedNow();
  if (s.labelsDigest !== s.resultsDigest) fail(`results.json was produced against labels with digest ${s.resultsDigest}, but labels.json has ${s.labelsDigest}: run the sealed set's run.mjs --check (once, logged in USE-LOG.md) and try again.`);
  if (!s.all) fail('results.json has no overall aggregate');
  const b = json(BASELINE);
  b.sealed = s;
  fs.writeFileSync(BASELINE, JSON.stringify(b, null, 1) + '\n');
  console.log(`recorded the sealed baseline: ${s.all.tp}/${s.all.tp + s.all.fp} decided sites true positive (scanner ${s.scannerVersion})`);
}

function check() {
  const errors = []; const notes = [];
  if (!fs.existsSync(BASELINE) || !fs.existsSync(MEASUREMENT)) fail(['FAIL: no recorded baseline (baseline.json and measurements/development.json). A gate with nothing recorded checks nothing.', 'Record one deliberately: node bench/haskell-precision/runner.mjs --update-baseline']);
  const base = json(BASELINE);
  const stored = json(MEASUREMENT).measurement;
  const { sets, digests } = loadLabels();

  // 1. labels
  for (const k of new Set([...Object.keys(digests), ...Object.keys(base.labelsDigests || {})])) if (digests[k] !== (base.labelsDigests || {})[k]) errors.push(`labels changed for "${k}" since the baseline was recorded (${(base.labelsDigests || {})[k] || 'none'} -> ${digests[k] || 'none'}). Labels are the answer key: change them only deliberately, then re-record.`);

  // 2. stored measurement vs committed aggregates (equality)
  const fromStored = aggregate(sets, stored);
  if (JSON.stringify(fromStored) !== JSON.stringify(base.aggregates)) {
    for (const k of Object.keys(fromStored)) if (JSON.stringify(fromStored[k]) !== JSON.stringify((base.aggregates || {})[k])) errors.push(`baseline.json disagrees with the stored measurement for "${k}": recorded ${JSON.stringify((base.aggregates || {})[k])} but the stored sites give ${JSON.stringify(fromStored[k])}.`);
  }

  // 4. invariant, on the stored measurement
  for (const b of unreachableTps(sets, stored)) errors.push(`a site labelled TRUE POSITIVE is in unreachable-in-project: ${b}`);

  // 3. live
  const wantLive = flag('live'); const noLive = flag('no-live');
  const injected = resultsDirs();
  const missing = injected ? [] : clonesPresent();
  let live = 'skipped';
  if (!noLive && (injected || !missing.length)) {
    let dirs = injected;
    try { dirs = dirs || scanLive(); } catch (e) { errors.push(`live scan failed: ${e.message}`); }
    if (dirs) {
      const now = measurementOf(sets, loadResults(dirs.dev), loadResults(dirs.fresh));
      for (const b of unreachableTps(sets, now)) errors.push(`LIVE: a site labelled TRUE POSITIVE is in unreachable-in-project: ${b}`);
      const diffs = [];
      for (const name of Object.keys(sets)) {
        const keys = new Set([...Object.keys(stored.sites[name] || {}), ...Object.keys(now.sites[name])]);
        for (const k of [...keys].sort()) {
          const a = JSON.stringify((stored.sites[name] || {})[k] || null); const b = JSON.stringify(now.sites[name][k] || null);
          if (a !== b) diffs.push(`${name} ${k}\n      recorded ${a}\n      now      ${b}`);
        }
      }
      for (const set of ['dev', 'fresh']) {
        for (const p of new Set([...Object.keys(stored.census[set] || {}), ...Object.keys(now.census[set] || {})])) {
          const a = JSON.stringify((stored.census[set] || {})[p] || null); const b = JSON.stringify((now.census[set] || {})[p] || null);
          if (a !== b) diffs.push(`${set}/${p} (whole report, labelled or not)\n      recorded ${a}\n      now      ${b}`);
        }
      }
      if (diffs.length) errors.push(`LIVE: the engine's report differs from the recorded measurement at ${diffs.length} place(s). A regression and an unrecorded improvement are both failures; if the change is deliberate and reviewed, re-record with --update-baseline.\n    ${diffs.slice(0, 12).join('\n    ')}${diffs.length > 12 ? `\n    ... ${diffs.length - 12} more` : ''}`);
      live = diffs.length ? 'differs' : 'matches';
    }
  } else if (!noLive) {
    notes.push(`live: skipped (pinned clones not present: ${missing.slice(0, 4).join(', ')}${missing.length > 4 ? ', ...' : ''}); the stored-measurement checks above still ran. Fetch them with node bench/dag/dev-haskell/acquire.mjs [--set=fresh].`);
    if (wantLive) errors.push('--live was requested but the pinned clones are not present');
  }

  // 5. sealed
  let sealedState = 'not recorded';
  if (base.sealed) {
    try {
      const s = sealedNow();
      if (JSON.stringify(s) !== JSON.stringify(base.sealed)) errors.push(`SEALED: the committed result of the sealed set differs from its recorded baseline: recorded ${JSON.stringify(base.sealed)}, now ${JSON.stringify(s)}. It was re-run or edited; log the use in its USE-LOG.md and re-record with --update-sealed-baseline.`);
      else if (s.labelsDigest !== s.resultsDigest) errors.push('SEALED: results.json was produced against different labels than labels.json holds');
      else sealedState = 'matches the recorded baseline';
    } catch (e) { errors.push(`SEALED: ${e.message}`); }
  } else if (flag('require-sealed')) errors.push('SEALED: no baseline is recorded for the sealed independent set, and this check requires one. Run its run.mjs --check ONCE (logged in bench/dag/independent-haskell/USE-LOG.md), then record it with --update-sealed-baseline.');
  else notes.push('sealed: no baseline recorded yet (the sealed independent set is spent once per release; the release check requires it). Its files were not read.');

  const report = { live, sealed: sealedState, sets: Object.fromEntries(Object.entries(fromStored).filter(([k]) => k !== 'census').map(([k, a]) => [k, { flagged: a.flagged, tp: a.tp, fp: a.fp, precision: a.precision, unreachableInProject: a.byStatus['unreachable-in-project'].TP + a.byStatus['unreachable-in-project'].FP }])), errors, notes };
  if (flag('json')) console.log(JSON.stringify(report, null, 1));
  else {
    console.log('Haskell real-code precision gate (equality against the recorded baseline)');
    for (const [k, a] of Object.entries(report.sets)) console.log(`  ${k.padEnd(26)} ${a.tp}/${a.flagged} flagged are true positives${a.precision == null ? '' : ` (${(100 * a.precision).toFixed(1)}%)`}, ${a.unreachableInProject} in unreachable-in-project`);
    console.log(`  stored measurement: consistent with baseline.json; live: ${live}; sealed: ${sealedState}`);
    for (const n of notes) console.log(`  note: ${n}`);
  }
  if (errors.length) { for (const e of errors) console.error(`FAIL: ${e}`); process.exit(1); }
  if (!flag('json')) console.log('PASS');
}

try {
  if (flag('update-baseline')) updateBaseline();
  else if (flag('update-sealed-baseline')) updateSealed();
  else if (flag('check')) check();
  else fail('usage: runner.mjs --check [--live|--no-live] [--require-sealed] [--json] | --update-baseline [--dev-results <dir> --fresh-results <dir>] | --update-sealed-baseline', 2);
} catch (e) { fail(`FAIL: ${e && e.message ? e.message : e}`, 1); }
