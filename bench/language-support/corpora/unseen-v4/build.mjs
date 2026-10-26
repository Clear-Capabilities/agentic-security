// Builds sources/, labels.json and manifest.json of the unseen-v4 split from authoring/*.txt.
// MEASUREMENT ONLY. See README.md. Usage: node build.mjs          (writes; refuses if a manifest already exists)
//                                          node build.mjs --verify (recomputes and compares against manifest.json)
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const CWE = { 'sql-injection': 'CWE-89', 'command-injection': 'CWE-78', 'path-traversal': 'CWE-22', ssrf: 'CWE-918', 'html-injection': 'CWE-79',
  'weak-password-hash': 'CWE-916', 'weak-randomness': 'CWE-338', 'resource-limits': 'CWE-770', 'parser-safety': 'CWE-248',
  'sensitive-logging': 'CWE-532', 'route-authentication': 'CWE-306', 'object-authorization': 'CWE-639', 'session-cookie': 'CWE-1004' };

export function parseForms() {
  const forms = [];
  const dir = path.join(HERE, 'authoring');
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.txt')).sort()) {
    const parts = fs.readFileSync(path.join(dir, f), 'utf8').split(/^@@@ /m).slice(1);
    for (const part of parts) {
      const nl = part.indexOf('\n');
      const [family, label, file] = part.slice(0, nl).split('|').map((s) => s.trim());
      const lines = part.slice(nl + 1).replace(/\n+$/, '').split('\n');
      const marked = lines.map((l, i) => (/\s*--@@\s*$/.test(l) ? i + 1 : 0)).filter(Boolean);
      if (marked.length !== 1) throw new Error(`${family}/${label}/${file}: expected exactly one marker, found ${marked.length}`);
      const text = lines.map((l) => l.replace(/\s*--@@\s*$/, '')).join('\n') + '\n';
      if (!CWE[family]) throw new Error(`unknown family ${family}`);
      forms.push({ family, label, file, text, markedLine: marked[0] });
    }
  }
  return forms;
}

export function build() {
  const forms = parseForms();
  const counts = {};
  for (const f of forms) { const k = `${f.family}|${f.label}`; counts[k] = (counts[k] || 0) + 1; }
  for (const fam of Object.keys(CWE)) for (const lab of ['vulnerable', 'safe']) if (counts[`${fam}|${lab}`] !== 3) throw new Error(`${fam} ${lab}: ${counts[`${fam}|${lab}`]} forms, need 3`);
  const idx = {}; const cases = []; const sources = {};
  for (const f of forms) {
    const k = `${f.family}|${f.label}`; const j = (idx[k] = (idx[k] ?? -1) + 1);
    const id = 'hs-v4-' + sha(`unseen-v4|${f.family}|${f.label}|${j}`).slice(0, 10);
    const c = { ecosystem: 'haskell', family: f.family, label: f.label, group: `haskell|${f.family}|${f.label}|v4s${j}`, split: 'unseen-v4', nearMiss: null,
      shape: `v4s${j}`, labelledBy: 'author, from the intended semantics of the form, before any engine run', j, id, path: f.file, cwe: CWE[f.family],
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

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { cases, sources } = build();
  const roll = rollup(cases, sources);
  const manifestPath = path.join(HERE, 'manifest.json');
  if (process.argv.includes('--verify')) {
    const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const disk = {}; for (const c of cases) disk[c.id] = { text: fs.readFileSync(path.join(HERE, 'sources', 'haskell', c.id, c.path), 'utf8') };
    const onDisk = rollup(JSON.parse(fs.readFileSync(path.join(HERE, 'labels.json'), 'utf8')), disk);
    const ok = onDisk.sourcesSha256 === m.sourcesSha256 && onDisk.labelsSha256 === m.labelsSha256 && roll.sourcesSha256 === m.sourcesSha256;
    console.log(ok ? 'unseen-v4 digest OK' : 'unseen-v4 DIGEST MISMATCH', JSON.stringify({ recorded: m, disk: onDisk }));
    process.exit(ok ? 0 : 1);
  }
  if (fs.existsSync(manifestPath)) { console.error('manifest.json exists: the split is frozen. Use --verify.'); process.exit(1); }
  for (const c of cases) { const p = path.join(HERE, 'sources', 'haskell', c.id, c.path); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, sources[c.id].text); }
  fs.writeFileSync(path.join(HERE, 'labels.json'), JSON.stringify(cases, null, 1) + '\n');
  fs.writeFileSync(manifestPath, JSON.stringify({ split: 'unseen-v4', frozenOn: new Date().toISOString().slice(0, 10), cases: cases.length,
    perFamily: 3, ...roll, note: 'sourcesSha256 = sha256 over "id:sha256(source)" lines in id order; labelsSha256 = sha256 of the exact JSON array of cases (canonical build order)' }, null, 1) + '\n');
  console.log(cases.length, 'cases', JSON.stringify(roll));
}
