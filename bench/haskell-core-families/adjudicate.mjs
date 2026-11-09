// Two-reviewer adjudication and the holdout freeze for the Haskell core-family benchmark (PRD FR 04, "Benchmark design").
//
// Reviewers label cases WITHOUT seeing the scanner's verdict. Each reviewer file declares that (`blind: true`); a file without it is
// refused, not trusted. A case enters the manifest only when at least two reviewers labelled it and every one of them agrees on
// vulnerable or safe. A disagreement or an `unsure` label is UNRESOLVED: it is listed, counted, and never added, so an unresolved label
// can never stand in as a benign control. An `author-seed` origin is refused: the author of the scanner is not an independent labeller.
//
// The freeze records digests of the manifest and of the scoring definitions (runner.mjs). The runner refuses to score the holdout split
// when no freeze exists or when either digest has changed since, and every holdout run is appended to holdout-uses.jsonl, so repeated
// use of the holdout is visible rather than silent.
//
// reviewer file (reviews/<name>.json):
//   { "reviewer": "name", "blind": true, "labels": [ { "file": "cases/sql/X.hs", "family": "sql", "group": "sql-7", "split": "dev",
//     "origin": "published-fix:<ref>", "label": "vulnerable" | "safe" | "unsure" } ] }
//
// usage: node bench/haskell-core-families/adjudicate.mjs [--reviews <dir>] [--write]   adjudicate; --write adds agreed cases
//        node bench/haskell-core-families/adjudicate.mjs --freeze                       freeze the manifest and definitions
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FREEZE_FILE = path.join(HERE, 'FROZEN.json');
export const HOLDOUT_USES = path.join(HERE, 'holdout-uses.jsonl');
const LABELS = new Set(['vulnerable', 'safe', 'unsure']);
const SPLITS = new Set(['dev', 'holdout']);

const sha = (text) => crypto.createHash('sha256').update(text).digest('hex');

/** Validate one reviewer file. Returns { ok, reason }. */
export function validateReview(r) {
  if (!r || typeof r !== 'object') return { ok: false, reason: 'not an object' };
  if (!r.reviewer) return { ok: false, reason: 'names no reviewer' };
  if (r.blind !== true) return { ok: false, reason: `${r.reviewer}: does not declare blind: true (labels must be made without the scanner's verdict)` };
  if (!Array.isArray(r.labels) || !r.labels.length) return { ok: false, reason: `${r.reviewer}: no labels` };
  for (const l of r.labels) {
    if (!l.file || !l.family || !l.group || !SPLITS.has(l.split) || !LABELS.has(l.label) || !l.origin) return { ok: false, reason: `${r.reviewer}: incomplete label for ${l.file || '?'}` };
    if (l.origin === 'author-seed') return { ok: false, reason: `${r.reviewer}: ${l.file} has origin author-seed, which is not independent` };
  }
  return { ok: true, reason: null };
}

/**
 * Adjudicate labels from several reviewers.
 * @returns {{agreed:object[], unresolved:object[], perCase:object[], agreement:{cases:number, agreed:number, rate:number|null, kappa:number|null}}}
 */
export function adjudicate(reviews) {
  const byFile = new Map();
  for (const r of reviews) for (const l of r.labels) {
    if (!byFile.has(l.file)) byFile.set(l.file, []);
    byFile.get(l.file).push({ ...l, reviewer: r.reviewer });
  }
  const agreed = []; const unresolved = []; const perCase = [];
  const pairs = [];
  for (const [file, ls] of [...byFile].sort()) {
    const reviewers = [...new Set(ls.map((l) => l.reviewer))];
    const labels = ls.map((l) => l.label);
    const meta = ['family', 'group', 'split', 'origin'].filter((k) => new Set(ls.map((l) => l[k])).size > 1);
    let why = null;
    if (reviewers.length < 2) why = 'fewer than two reviewers';
    else if (meta.length) why = `reviewers disagree on ${meta.join(', ')}`;
    else if (labels.includes('unsure')) why = 'a reviewer is unsure';
    else if (new Set(labels).size > 1) why = 'reviewers disagree on the label';
    if (reviewers.length >= 2) pairs.push(labels);
    const rec = { file, reviewers, labels, resolved: !why, reason: why };
    perCase.push(rec);
    if (why) unresolved.push(rec);
    else agreed.push({ family: ls[0].family, label: labels[0], group: ls[0].group, split: ls[0].split, origin: ls[0].origin, file, cwe: null, adjudication: { reviewers, agreement: 'unanimous' } });
  }
  return { agreed, unresolved, perCase, agreement: agreementStats(pairs) };
}

// Observed agreement and Cohen's kappa over the first two labels of each multiply-labelled case (`unsure` is its own category).
function agreementStats(pairs) {
  const two = pairs.filter((p) => p.length >= 2).map((p) => [p[0], p[1]]);
  if (!two.length) return { cases: 0, agreed: 0, rate: null, kappa: null };
  const agree = two.filter(([a, b]) => a === b).length;
  const po = agree / two.length;
  let pe = 0;
  for (const c of LABELS) pe += (two.filter(([a]) => a === c).length / two.length) * (two.filter(([, b]) => b === c).length / two.length);
  return { cases: two.length, agreed: agree, rate: po, kappa: pe === 1 ? null : (po - pe) / (1 - pe) };
}

/** Add agreed cases to a manifest. A file already present is not added twice; a vulnerable case and its fixed pair must share a split. */
export function mergeIntoManifest(manifest, agreed) {
  const have = new Set(manifest.cases.map((c) => c.file));
  const added = agreed.filter((c) => !have.has(c.file));
  const cases = [...manifest.cases, ...added];
  const splitOf = new Map();
  for (const c of cases) {
    if (splitOf.has(c.group) && splitOf.get(c.group) !== c.split) throw new Error(`group ${c.group} spans two splits: a case and its fixed counterpart must share one`);
    splitOf.set(c.group, c.split);
  }
  return { manifest: { ...manifest, cases }, added: added.length };
}

/** The digests a freeze records: the manifest and the scoring definitions. */
export function freezeDigests({ manifestText, runnerText }) {
  return { manifest: sha(manifestText), definitions: sha(runnerText) };
}

/** Why scoring the holdout must be refused, or null. */
export function holdoutRefusal(freeze, current) {
  if (!freeze) return 'the benchmark is not frozen: run adjudicate.mjs --freeze before scoring the holdout';
  if (freeze.manifest !== current.manifest) return 'the manifest changed after the freeze: the holdout is no longer the one that was frozen';
  if (freeze.definitions !== current.definitions) return 'the scoring definitions (runner.mjs) changed after the freeze';
  return null;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const opt = (n, d = null) => { const i = argv.indexOf(`--${n}`); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };
  const manifestPath = path.join(HERE, 'manifest.json');
  if (argv.includes('--freeze')) {
    const d = freezeDigests({ manifestText: fs.readFileSync(manifestPath, 'utf8'), runnerText: fs.readFileSync(path.join(HERE, 'runner.mjs'), 'utf8') });
    fs.writeFileSync(FREEZE_FILE, JSON.stringify({ schema: 'haskell-core-families-freeze/1', frozenAt: new Date().toISOString(), ...d }, null, 1) + '\n');
    console.log(`frozen: manifest ${d.manifest.slice(0, 12)}, definitions ${d.definitions.slice(0, 12)}`);
    process.exit(0);
  }
  const dir = path.resolve(opt('reviews', path.join(HERE, 'reviews')));
  if (!fs.existsSync(dir)) { console.error(`no reviewer directory at ${dir}: each reviewer writes reviews/<name>.json (see the header of this file)`); process.exit(2); }
  const reviews = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
  for (const r of reviews) { const v = validateReview(r); if (!v.ok) { console.error(`refused: ${v.reason}`); process.exit(2); } }
  const res = adjudicate(reviews);
  const a = res.agreement;
  console.log(`reviewers: ${reviews.length}; cases labelled: ${res.perCase.length}; agreed: ${res.agreed.length}; unresolved: ${res.unresolved.length}`);
  console.log(`agreement on ${a.cases} double-labelled case(s): ${a.rate == null ? 'n/a' : `${(a.rate * 100).toFixed(1)}%`}, Cohen's kappa ${a.kappa == null ? 'n/a' : a.kappa.toFixed(2)}`);
  for (const u of res.unresolved) console.log(`  unresolved ${u.file}: ${u.reason} (${u.labels.join(' / ')})`);
  if (argv.includes('--write')) {
    if (fs.existsSync(FREEZE_FILE)) { console.error('refused: the benchmark is frozen; adding cases after a freeze changes the holdout. Remove FROZEN.json deliberately, add, then freeze again'); process.exit(2); }
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const m = mergeIntoManifest(manifest, res.agreed);
    fs.writeFileSync(manifestPath, JSON.stringify(m.manifest, null, 1) + '\n');
    console.log(`added ${m.added} case(s) to manifest.json`);
  }
}
