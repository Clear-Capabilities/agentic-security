// Diagnostic: builds the Haskell IR of one dev project and reports, for the named functions, whether the call graph reaches them.
// usage: node bench/dag/dev-haskell/irdebug.mjs <project> <fn> [<fn>...]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildHaskellIR } from '../../../scanner/src/language/haskell-ir.js';

const H = path.dirname(fileURLToPath(import.meta.url));
const [, , project, ...names] = process.argv;
const root = path.join(H, '.cache', project);
const files = {};
const walk = (p) => { for (const e of fs.readdirSync(p, { withFileTypes: true })) { if (e.name === '.git' || e.name === 'dist-newstyle') continue; const q = path.join(p, e.name); if (e.isDirectory()) walk(q); else if (/\.hs$/.test(e.name)) files[path.relative(root, q)] = fs.readFileSync(q, 'utf8'); } };
walk(root);
const ir = buildHaskellIR(files);
const { callGraph } = ir;
const byName = new Map();
for (const fn of callGraph.functions.values()) { const n = fn.name.split('.').pop(); if (!byName.has(n)) byName.set(n, []); byName.get(n).push(fn); }
const into = new Map();
for (const e of callGraph.edges) if (e.callee) { if (!into.has(e.callee)) into.set(e.callee, []); into.get(e.callee).push(e); }
for (const n of names) {
  for (const fn of byName.get(n) || []) {
    const inc = into.get(fn.qid) || [];
    const ann = fn.paramAnnotations ? JSON.stringify(fn.paramAnnotations) : 'none';
    console.log(`${fn.qid}: incoming=${inc.length} [${inc.slice(0, 3).map((e) => `${e.status}/${e.kind}:${e.caller.split('::')[1]}`).join('; ')}] annotations=${ann}`);
  }
  const unresolved = callGraph.edges.filter((e) => !e.callee && e.calleeName && String(e.calleeName).split('.').pop() === n);
  if (unresolved.length) console.log(`  unresolved edges naming ${n}: ${unresolved.length} e.g. ${unresolved[0].status} ${unresolved[0].reason || ''} in ${unresolved[0].caller}`);
}
if (names.includes('--refs')) {
  for (const fn of callGraph.functions.values()) for (const r of (fn.hs && fn.hs.refs) || []) if (r.via === 'ambiguous-import') console.log('ref', fn.qid, '->', r.target);
}
