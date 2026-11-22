// Default scan (deep mode on, as the CLI does outside CI; no lineage graph; state writes off) of one pinned project of a set, keeping the
// findings located in the set's language files. Writes <out>/<set>/<id>.json.
// usage: node bench/dag/dev-realcode/scan.mjs <set> <id> [--out=<dir>] [--engine=<dir containing src/runScan.js>]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { disableStateWrites } from '../../_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const [set, id] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const arg = (n) => { const a = process.argv.find((x) => x.startsWith(`--${n}=`)); return a ? a.slice(n.length + 3) : null; };
const OUT = path.join(arg('out') || path.join(HERE, 'results'), set);
const ENGINE = arg('engine') ? path.resolve(arg('engine')) : path.join(HERE, '..', '..', '..', 'scanner');
export const LANG_FILES = { python: /\.py$/i, typescript: /\.(?:[cm]?[jt]sx?)$/i };
const dir = path.join(HERE, '.cache', id);
await disableStateWrites();
process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;
const { runScan } = await import(pathToFileURL(path.join(ENGINE, 'src', 'runScan.js')).href);
const t0 = Date.now();
const { scan } = await runScan(dir);
const rows = [];
for (const f of scan.findings) {
  let file = f.file || '';
  if (path.isAbsolute(file)) file = path.relative(dir, file);
  if (!LANG_FILES[set].test(file)) continue;
  rows.push({
    id: f.id, stableId: f.stableId, file, line: Number.isInteger(f.line) ? f.line : null, severity: f.severity, vuln: f.vuln, cwe: f.cwe,
    parser: f.parser, family: f.family, confidence: f.confidence, description: (f.description || '').slice(0, 300),
    origin: f.source || f.taintSource || null, sourceRoots: f.sourceRoots || null, reachability: f.reachability || null, originalSeverity: f.originalSeverity || null,
    proof: f.proof && f.proof.verdict ? f.proof.verdict : null, sanitized: !!(f._sanitizersOnPath && f._sanitizersOnPath.length),
  });
}
rows.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : (a.line || 0) - (b.line || 0) || (a.id < b.id ? -1 : 1)));
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, `${id}.json`), JSON.stringify({ set, id, ms: Date.now() - t0, totalFindings: scan.findings.length, findings: rows }, null, 1));
console.log(`${set}/${id}: ${rows.length} findings in ${set} files of ${scan.findings.length} (${Date.now() - t0} ms)`);
