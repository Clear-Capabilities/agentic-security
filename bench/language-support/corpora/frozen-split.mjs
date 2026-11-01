// Shared body of the frozen, measurement-only Haskell splits (unseen-v4, unseen-v5, ...): parse the authoring files, build the
// scanned sources and labels, record and verify the digests, load a split with its digest checked, and turn a measure.mjs result
// into the baseline markdown. Each split directory keeps a two-line build.mjs and summarize.mjs over this file, so the rules a
// split was frozen under are the same code for every split and a new split cannot drift from the layout the harness loads.
//
// A split is MEASUREMENT ONLY until its USE-LOG records a use that turned it into a development set; the role lives in the
// split's manifest.json (`role`, `developmentSince`) and measure.mjs records it with every result.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

export const CWE = { 'sql-injection': 'CWE-89', 'command-injection': 'CWE-78', 'path-traversal': 'CWE-22', ssrf: 'CWE-918', 'html-injection': 'CWE-79',
  'weak-password-hash': 'CWE-916', 'weak-randomness': 'CWE-338', 'resource-limits': 'CWE-770', 'parser-safety': 'CWE-248',
  'sensitive-logging': 'CWE-532', 'route-authentication': 'CWE-306', 'object-authorization': 'CWE-639', 'session-cookie': 'CWE-1004' };

export const PER_FAMILY = 3;

/** The forms as written: `@@@ family | label | path` headers, one ` --@@` marker line per form (stripped from the source). */
export function parseForms(dir) {
  const forms = [];
  const authoring = path.join(dir, 'authoring');
  for (const f of fs.readdirSync(authoring).filter((x) => x.endsWith('.txt')).sort()) {
    const parts = fs.readFileSync(path.join(authoring, f), 'utf8').split(/^@@@ /m).slice(1);
    for (const part of parts) {
      const nl = part.indexOf('\n');
      const [family, label, file] = part.slice(0, nl).split('|').map((s) => s.trim());
      const lines = part.slice(nl + 1).replace(/\n+$/, '').split('\n');
      const marked = lines.map((l, i) => (/\s*--@@\s*$/.test(l) ? i + 1 : 0)).filter(Boolean);
      if (marked.length !== 1) throw new Error(`${family}/${label}/${file}: expected exactly one marker, found ${marked.length}`);
      const text = lines.map((l) => l.replace(/\s*--@@\s*$/, '')).join('\n') + '\n';
      if (!CWE[family]) throw new Error(`unknown family ${family}`);
      if (!['vulnerable', 'safe'].includes(label)) throw new Error(`${family}/${file}: label must be vulnerable or safe, got ${label}`);
      forms.push({ family, label, file, text, markedLine: marked[0] });
    }
  }
  return forms;
}

/** Cases and sources for one split, in canonical order. `split` names the split, `idPrefix` its id prefix (`hs-v5-`). */
export function build({ dir, split, idPrefix }) {
  const forms = parseForms(dir);
  const counts = {};
  for (const f of forms) { const k = `${f.family}|${f.label}`; counts[k] = (counts[k] || 0) + 1; }
  for (const fam of Object.keys(CWE)) for (const lab of ['vulnerable', 'safe']) if (counts[`${fam}|${lab}`] !== PER_FAMILY) throw new Error(`${fam} ${lab}: ${counts[`${fam}|${lab}`] || 0} forms, need ${PER_FAMILY}`);
  // A path may repeat across forms (unseen-v4 does): each case is scanned alone under its own opaque id directory.
  const idx = {}; const cases = []; const sources = {};
  const tag = split.replace(/^unseen-/, '');
  for (const f of forms) {
    const k = `${f.family}|${f.label}`; const j = (idx[k] = (idx[k] ?? -1) + 1);
    const id = idPrefix + sha(`${split}|${f.family}|${f.label}|${j}`).slice(0, 10);
    const c = { ecosystem: 'haskell', family: f.family, label: f.label, group: `haskell|${f.family}|${f.label}|${tag}s${j}`, split, nearMiss: null,
      shape: `${tag}s${j}`, labelledBy: 'author, from the intended semantics of the form, before any engine run', j, id, path: f.file, cwe: CWE[f.family],
      [f.label === 'vulnerable' ? 'flawLine' : 'safeSinkLine']: f.markedLine, fingerprint: sha(f.text) };
    cases.push(c); sources[id] = { path: f.file, text: f.text };
  }
  cases.sort((a, b) => a.id.localeCompare(b.id));
  return { cases, sources };
}

export function rollup(cases, sources) {
  const per = cases.map((c) => `${c.id}:${sha(sources[c.id].text)}`).join('\n');
  return { sourcesSha256: sha(per), labelsSha256: sha(JSON.stringify(cases)) };
}

/** The cases of a frozen split, refusing to load when the sources or labels on disk differ from the frozen manifest. */
export function loadFrozen({ dir, split }) {
  const read = (p) => fs.readFileSync(p, 'utf8');
  const cases = JSON.parse(read(path.join(dir, 'labels.json')));
  const m = JSON.parse(read(path.join(dir, 'manifest.json')));
  const per = [...cases].sort((a, b) => a.id.localeCompare(b.id)).map((c) => `${c.id}:${sha(read(path.join(dir, 'sources', 'haskell', c.id, c.path)))}`).join('\n');
  if (sha(per) !== m.sourcesSha256 || sha(JSON.stringify(cases)) !== m.labelsSha256) throw new Error(`${split} digest mismatch: the frozen split was modified after freezing (see ${path.join(dir, 'USE-LOG.md')})`);
  return cases;
}

/** `node build.mjs` writes and freezes a split (refusing when a manifest exists); `--verify` recomputes the digests. */
export function buildCli({ dir, split, idPrefix }) {
  const { cases, sources } = build({ dir, split, idPrefix });
  const roll = rollup(cases, sources);
  const manifestPath = path.join(dir, 'manifest.json');
  if (process.argv.includes('--verify')) {
    const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const disk = {}; for (const c of cases) disk[c.id] = { text: fs.readFileSync(path.join(dir, 'sources', 'haskell', c.id, c.path), 'utf8') };
    const onDisk = rollup(JSON.parse(fs.readFileSync(path.join(dir, 'labels.json'), 'utf8')), disk);
    const ok = onDisk.sourcesSha256 === m.sourcesSha256 && onDisk.labelsSha256 === m.labelsSha256 && roll.sourcesSha256 === m.sourcesSha256;
    console.log(ok ? `${split} digest OK` : `${split} DIGEST MISMATCH`, JSON.stringify({ recorded: m, disk: onDisk }));
    process.exit(ok ? 0 : 1);
  }
  if (fs.existsSync(manifestPath)) { console.error('manifest.json exists: the split is frozen. Use --verify.'); process.exit(1); }
  for (const c of cases) { const p = path.join(dir, 'sources', 'haskell', c.id, c.path); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, sources[c.id].text); }
  fs.writeFileSync(path.join(dir, 'labels.json'), JSON.stringify(cases, null, 1) + '\n');
  fs.writeFileSync(manifestPath, JSON.stringify({ split, frozenOn: new Date().toISOString().slice(0, 10), cases: cases.length, perFamily: PER_FAMILY, role: 'generalisation', developmentSince: null,
    ...roll, note: 'sourcesSha256 = sha256 over "id:sha256(source)" lines in id order; labelsSha256 = sha256 of the exact JSON array of cases (canonical build order); role is generalisation until USE-LOG.md records a use that changed the engine' }, null, 1) + '\n');
  console.log(cases.length, 'cases', JSON.stringify(roll));
}

/** The baseline markdown for a measure.mjs result of one split (per family and overall, Wilson 95% intervals). */
export function summarize(r, { split, wilson }) {
  const d = r.ecosystems.haskell.detection;
  const fam = {};
  for (const layer of ['sast', 'taint']) for (const [k, v] of Object.entries(d.layers[layer].families)) fam[k] = { layer, ...v };
  const pct = (x) => (x === null || x === undefined ? 'n/a' : (100 * x).toFixed(1) + '%');
  const ci = (k, n) => { const w = wilson(k, n); return w ? `${pct(w[0])} to ${pct(w[1])}` : 'n/a'; };
  const rowOf = (name, layer, t) => {
    const p = t.tp + t.fp, rr = t.tp + t.fn, f1 = p && rr && t.tp ? 2 * (t.tp / p) * (t.tp / rr) / ((t.tp / p) + (t.tp / rr)) : (p && rr ? 0 : null);
    return `| ${name} | ${layer} | ${t.tp} | ${t.fp} | ${t.fn} | ${t.tn ?? ''} | ${p ? pct(t.tp / p) : 'n/a'} (${p ? ci(t.tp, p) : 'n/a'}) | ${rr ? pct(t.tp / rr) : 'n/a'} (${rr ? ci(t.tp, rr) : 'n/a'}) | ${f1 === null ? 'n/a' : pct(f1)} |`;
  };
  const perFamilyCases = d.perFamilyCases;
  const rows = Object.keys(perFamilyCases).sort().map((k) => {
    const f = fam[k] || { layer: '?', tp: 0, fp: 0, fn: perFamilyCases[k].vulnerable };
    return rowOf(k, f.layer, { tp: f.tp, fp: f.fp, fn: f.fn, tn: perFamilyCases[k].safe - f.fp });
  });
  const sum = (layers) => layers.reduce((a, l) => ({ tp: a.tp + d.layers[l].tp, fp: a.fp + d.layers[l].fp, fn: a.fn + d.layers[l].fn, tn: a.tn + d.layers[l].tn }), { tp: 0, fp: 0, fn: 0, tn: 0 });
  const role = r.splitRole === 'development' ? `DEVELOPMENT set since ${r.developmentSince || 'an unrecorded date'}: its failures were read to change the engine, so this is a regression result, not a generalisation measure.` : 'MEASUREMENT ONLY. Measured once, before any change to the engine by whoever follows. Never tune against this split; see the split\'s README.md and USE-LOG.md.';
  return `# ${split} ${r.splitRole === 'development' ? 'measurement' : 'baseline'} (Haskell)

${role}

- Measured: ${r.measuredAt}; command: \`node bench/language-support/measure.mjs --split ${split} --eco haskell --suites detection --out bench/language-support/results/${split}-baseline.json\`
- Split: ${d.cases} cases (13 families, ${PER_FAMILY} vulnerable and ${PER_FAMILY} safe forms each; ${d.unknownOutcomes.total} unknown). Digest: see corpora/${split}/manifest.json (sourcesSha256, labelsSha256).
- Scoring: the existing harness (family-scoped; a finding of another family in a case is not this family's false positive; line numbers are not scored, the finding only has to be of the right CWE in the right file).
- Intervals: Wilson 95%, precision over TP+FP and recall over TP+FN, with small denominators (${PER_FAMILY} vulnerable and ${PER_FAMILY} safe forms per family). Read the intervals, not the point values; a per-family row is ${2 * PER_FAMILY} cases.

## Overall (all 13 families)

| scope | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
${rowOf('all', 'sast + taint', sum(['sast', 'taint']))}
${rowOf('pattern layer families (8)', 'sast', sum(['sast']))}
${rowOf('taint families (5)', 'taint', sum(['taint']))}

## Per family

| family | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
${rows.join('\n')}

Strict (cross-family findings counted as false positives): sast precision ${pct(d.layers.sast.strict.precision)}, taint precision ${pct(d.layers.taint.strict.precision)}.

## Caveats

- ${d.cases} forms by one author. Shapes are the author's idea of how real programs write these forms; they are not scraped from real projects.
- Forms were not compiled (library packages not installed here), so a form could contain a type error; the harness reads source text only.
- The harness does not score the flaw line (tolerance is unlimited), so a right-CWE finding on the wrong line in the file still counts as a TP; the author-labelled line is recorded in labels.json (flawLine / safeSinkLine) for a stricter later reading.
- A safe form here means the specific flaw is absent as the author reasoned it; a form can be safe for that family and still carry another weakness.
`;
}

/** `node summarize.mjs <result.json> <out.md>` for one split. */
export async function summarizeCli({ split }) {
  const { wilson } = await import('../../dag/independent-haskell/lib.mjs');
  const [, , inFile, outFile] = process.argv;
  const md = summarize(JSON.parse(fs.readFileSync(inFile, 'utf8')), { split, wilson });
  fs.writeFileSync(outFile, md);
  console.log(md);
}
