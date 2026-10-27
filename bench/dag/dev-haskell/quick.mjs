// Scans a directory with the default (deep) scan and prints its Haskell findings compactly.
// usage: node bench/dag/dev-haskell/quick.mjs <dir> [--engine=<dir containing src/runScan.js>] [--all]
import * as path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { disableStateWrites } from '../../_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (n) => { const a = process.argv.find((x) => x.startsWith(`--${n}=`)); return a ? a.slice(n.length + 3) : null; };
const ENGINE = arg('engine') ? path.resolve(arg('engine')) : path.join(HERE, '..', '..', '..', 'scanner');
await disableStateWrites();
process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;
const { runScan } = await import(pathToFileURL(path.join(ENGINE, 'src', 'runScan.js')).href);
const dir = path.resolve(process.argv[2]);
const { scan } = await runScan(dir);
for (const f of scan.findings) {
  if (!/\.(hs|lhs)$/.test(f.file || '')) continue;
  const src = f.source && f.source.label ? ` <- ${f.source.label}` : '';
  const roots = Array.isArray(f.sourceRoots) ? ` roots=[${f.sourceRoots.map((r) => `${r.label}/${r.provenance}`).join(', ')}]` : '';
  const tier = f.trustBoundary ? ` trust=${f.trustBoundary.verdict}` : '';
  console.log(`${f.file}:${f.line} [${f.severity}] ${f.parser} ${f.vuln}${src}${roots}${tier}`);
}
