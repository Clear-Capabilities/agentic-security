// Builds the labelling worklist of the FRESH set: every site flagged (non-info) after the fixes (the census), plus every site the original engine
// flagged that the engine no longer flags (what the fixes removed or lowered), so a lost true positive would be seen. Writes fresh-worklist.json.
// Sites are keyed project:file:line:stratum. usage: node bench/dag/dev-haskell/fresh-worklist.mjs
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const stratumOf = (v) => (/^Path Traversal/.test(v) ? 'path-traversal' : v.replace(/^Unsafe boundary: .*/, 'unsafe-boundary'));
const load = (d) => {
  const out = new Map();
  for (const f of fs.readdirSync(path.join(HERE, d)).sort()) {
    if (!f.endsWith('.json')) continue;
    const j = JSON.parse(fs.readFileSync(path.join(HERE, d, f), 'utf8'));
    for (const r of j.haskell) out.set(`${j.id}:${r.file}:${r.line}:${stratumOf(r.vuln)}`, { project: j.id, ...r });
  }
  return out;
};
const before = load('results-fresh-before');
const after = load('results-fresh-after');
const items = [];
for (const [k, r] of after) if (r.severity !== 'info') items.push({ key: k, kind: 'flagged-after', project: r.project, file: r.file, line: r.line, vuln: r.vuln, severity: r.severity, parser: r.parser, trust: r.trust && r.trust.verdict });
for (const [k, r] of before) {
  const a = after.get(k);
  if (r.severity !== 'info' && (!a || a.severity === 'info')) items.push({ key: k, kind: a ? 'lowered' : 'gone', project: r.project, file: r.file, line: r.line, vuln: r.vuln, severity: r.severity, parser: r.parser, trust: a && a.trust && a.trust.verdict });
}
fs.writeFileSync(path.join(HERE, 'fresh-worklist.json'), JSON.stringify({ beforeFlagged: [...before.values()].filter((r) => r.severity !== 'info').length, afterFlagged: [...after.values()].filter((r) => r.severity !== 'info').length, items }, null, 1));
const c = {};
for (const i of items) { const k = `${i.kind} ${i.parser}`; c[k] = (c[k] || 0) + 1; }
console.log(`before ${[...before.values()].filter((r) => r.severity !== 'info').length} flagged, after ${[...after.values()].filter((r) => r.severity !== 'info').length}; worklist ${items.length}`, c);
