// Scans every acquired discovery project (deep mode, as the CLI does by default outside CI; no state writes) and writes the findings located
// in Haskell files to results/<id>.json, then prints the flagged (non-info) census and compares it with labels.json: a flagged site with no
// label is printed as NEW (read it, label it, and record the addition in USE-LOG.md). usage: node bench/dag/discovery-haskell/scan.mjs [--only=a,b]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../../scanner/src/runScan.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const only = (process.argv.find((a) => a.startsWith('--only=')) || '').slice(7).split(',').filter(Boolean);
process.env.AGENTIC_SECURITY_DEEP = '1';
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
process.env.AGENTIC_SECURITY_BLIND_BENCH = '1';
process.env.AGENTIC_SECURITY_NO_STATE_WRITES = '1';
const manifest = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));
const labels = JSON.parse(fs.readFileSync(path.join(HERE, 'labels.json'), 'utf8')).labels;
const stratumOf = (v) => (/^Path Traversal/.test(v) ? 'path-traversal' : /^Route .* not declared/.test(v) ? 'api-contract' : v.replace(/^Unsafe boundary: .*/, 'unsafe-boundary'));
fs.mkdirSync(path.join(HERE, 'results'), { recursive: true });
let unlabelled = 0;
for (const p of manifest.projects) {
  if (only.length && !only.includes(p.id)) continue;
  const dir = path.join(HERE, '.cache', p.id);
  if (!fs.existsSync(dir)) { console.log(`missing ${p.id}: run acquire.mjs`); continue; }
  const t0 = Date.now();
  const { scan } = await runScan(dir);
  const rows = (scan.findings || []).filter((f) => /\.l?hs$/.test(f.file || '')).map((f) => ({
    file: f.file, line: f.line, severity: f.severity, cwe: f.cwe, vuln: f.vuln, parser: f.parser,
    trust: f.trustBoundary && f.trustBoundary.verdict, reach: f.reachability && f.reachability.status,
    guard: f.guardNote && f.guardNote.kind, proof: f.proof && f.proof.verdict, provenance: f.sourceProvenance,
  }));
  fs.writeFileSync(path.join(HERE, 'results', `${p.id}.json`), JSON.stringify({ id: p.id, commit: p.commit, rows }, null, 1) + '\n');
  const flagged = rows.filter((r) => r.severity !== 'info');
  console.log(`== ${p.id}: ${rows.length} haskell findings, ${flagged.length} flagged (${Date.now() - t0} ms)`);
  for (const r of flagged) {
    const k = `${p.id}:${r.file}:${r.line}:${stratumOf(r.vuln)}`;
    const l = labels[k];
    if (!l) unlabelled++;
    console.log(`  ${l ? l.label.padEnd(9) : 'NEW      '} ${r.severity}\t${r.cwe}\t${r.file}:${r.line}\t${r.vuln}`);
  }
}
if (unlabelled) console.log(`\n${unlabelled} flagged site(s) have no label.`);
