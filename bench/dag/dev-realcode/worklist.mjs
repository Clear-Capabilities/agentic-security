// Prints each sampled site of a set with the finding's facts and the surrounding code, for labelling by reading.
// usage: node bench/dag/dev-realcode/worklist.mjs --set=python|typescript [--from=N] [--to=N] [--context=8]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (n) => { const a = process.argv.find((x) => x.startsWith(`--${n}=`)); return a ? a.slice(n.length + 3) : null; };
const set = arg('set') || 'python';
const from = Number(arg('from') || 0), to = Number(arg('to') || 1e9), ctx = Number(arg('context') || 8);
const sample = JSON.parse(fs.readFileSync(path.join(HERE, `sample-${set}.json`), 'utf8')).sample;
const results = {};
for (const s of sample.slice(from, to + 1)) {
  if (!results[s.project]) results[s.project] = JSON.parse(fs.readFileSync(path.join(HERE, 'results', set, `${s.project}.json`), 'utf8')).findings;
  const f = results[s.project].find((r) => r.file === s.file && r.line === s.line && r.id === s.id) || {};
  let src = []; try { src = fs.readFileSync(path.join(HERE, '.cache', s.project, s.file), 'utf8').split('\n'); } catch (e) { console.log(`\n#${s.index} [${s.half}] ${s.project} ${s.file}:${s.line}  (file unreadable: ${e.code})`); continue; }
  const lo = Math.max(1, (s.line || 1) - ctx), hi = Math.min(src.length, (s.line || 1) + ctx);
  console.log(`\n#${s.index} [${s.half}] ${s.project} ${s.file}:${s.line}  ${s.vuln} (${s.cwe}, ${s.parser}, ${s.severity})`);
  if (f.origin) console.log(`   origin: ${JSON.stringify(f.origin).slice(0, 220)}`);
  if (f.sourceRoots) console.log(`   roots: ${JSON.stringify(f.sourceRoots).slice(0, 220)}`);
  if (f.description) console.log(`   desc: ${f.description.slice(0, 200)}`);
  for (let i = lo; i <= hi; i++) console.log(`${i === s.line ? '>>' : '  '} ${String(i).padStart(5)} ${src[i - 1].slice(0, 180)}`);
}
