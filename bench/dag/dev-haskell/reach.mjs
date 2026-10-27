// Diagnostic: for each sampled IR-TAINT finding, which function holds the sink and is that function's name used
// elsewhere in the project text? (Class evidence for the 'nothing in the project reaches it' entry-point rule.)
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
const H = path.dirname(fileURLToPath(import.meta.url));
const s = JSON.parse(fs.readFileSync(path.join(H, 'sample.json'), 'utf8')).sample;
const lab = JSON.parse(fs.readFileSync(path.join(H, 'labels.json'), 'utf8')).labels;
const dir = path.join(H, '.cache', '_runs', 'diag');
const d = {};
for (const f of fs.readdirSync(dir)) { const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); for (const r of j.haskell) d[`${j.id}:${r.file}:${r.line}:${r.id}`] = r; }
const walk = (p, out = []) => { for (const e of fs.readdirSync(p, { withFileTypes: true })) { if (e.name === '.git') continue; const q = path.join(p, e.name); if (e.isDirectory()) walk(q, out); else if (/\.hs$/.test(e.name)) out.push(q); } return out; };
const texts = {};
for (const r of s) {
  if (r.parser !== 'IR-TAINT') continue;
  const x = d[r.key]; if (!x || !x.extra) continue;
  const q = x.extra._funcQid || ''; const m = /::([\w.']+)@\d+$/.exec(q); const fn = m ? m[1].split('.').pop() : '?';
  const root = path.join(H, '.cache', r.project);
  texts[r.project] = texts[r.project] || walk(root).map((f) => fs.readFileSync(f, 'utf8'));
  const re = new RegExp(`(?<![\\w'])${fn.replace(/[$]/g, '\\$')}(?![\\w'])`, 'g');
  let n = 0; for (const t of texts[r.project]) n += (t.match(re) || []).length;
  console.log(`${String(s.indexOf(r)).padStart(3)} ${lab[r.key].label} ${r.project.padEnd(14)} fn=${fn.padEnd(28)} uses=${n} src=${(x.origin && x.origin.label || 'none').slice(0, 40)}`);
}
