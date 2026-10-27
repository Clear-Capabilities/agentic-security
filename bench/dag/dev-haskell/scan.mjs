// Default scan (deep mode on, as the CLI does outside CI; no lineage graph, no state writes) of one
// project in bench/dag/dev-haskell/.cache. Writes the Haskell source findings to <out>/<id>.json.
// usage: node bench/dag/dev-haskell/scan.mjs <id> [--out=<dir>] [--engine=<dir containing src/runScan.js>]
// --engine lets the same scan run against an unmodified copy of the engine (for before/after comparisons).
import * as fs from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { disableStateWrites } from '../../_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const id = process.argv[2];
const arg = (n) => { const a = process.argv.find((x) => x.startsWith(`--${n}=`)); return a ? a.slice(n.length + 3) : null; };
const OUT = arg('out') || path.join(HERE, 'results');
const ENGINE = arg('engine') ? path.resolve(arg('engine')) : path.join(HERE, '..', '..', '..', 'scanner');
const dir = path.join(HERE, '.cache', id);
await disableStateWrites();
process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;
const { runScan } = await import(pathToFileURL(path.join(ENGINE, 'src', 'runScan.js')).href);
const t0 = Date.now();
const { scan } = await runScan(dir);
const HS = /\.(hs|lhs|hsc|hs-boot)$/i;
const rows = [];
for (const f of scan.findings) {
  let file = f.file || '';
  if (path.isAbsolute(file)) file = path.relative(dir, file);
  if (!HS.test(file)) continue;
  rows.push({
    id: f.id, stableId: f.stableId, file, line: Number.isInteger(f.line) ? f.line : null, severity: f.severity, vuln: f.vuln, cwe: f.cwe,
    parser: f.parser, family: f.family, rule: f.rule || f.ruleId || null, confidence: f.confidence, description: (f.description || '').slice(0, 300),
    origin: f.source || f.taintSource || null, trust: f.trustBoundary || null, reachability: f.reachability || null, originalSeverity: f.originalSeverity || null, sinkInfo: f.sink || null, extra: process.env.DEV_HS_RAW ? f : undefined,
  });
}
rows.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : (a.line || 0) - (b.line || 0) || (a.id < b.id ? -1 : 1)));
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, `${id}.json`), JSON.stringify({ id, ms: Date.now() - t0, totalFindings: scan.findings.length, haskell: rows }, null, 1));
console.log(`${id}: ${rows.length} haskell findings of ${scan.findings.length} (${Date.now() - t0} ms)`);
