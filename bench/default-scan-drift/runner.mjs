// Default-scan drift gate.
//
// WHY: a release said "a default scan's output is unchanged" while new detectors, new precision rules and a line backfill
// changed what a default scan reports (the 0.186.0 line backfill made twice as many findings carry a line, which also doubled the
// git-blame work and was only caught by the speed gate). A change to default output is allowed, but it must be deliberate and
// visible. This scans a fixed set of committed fixtures with the default settings and compares every finding to a committed
// baseline. Any added, removed or changed finding fails the check and prints the difference; re-baselining is an explicit act
// (`--update-baseline`) that belongs in the same commit as a changelog entry naming the rule that moved.
//
//   node bench/default-scan-drift/runner.mjs --check            fail on any difference
//   node bench/default-scan-drift/runner.mjs --update-baseline  write the baseline
//   node bench/default-scan-drift/runner.mjs --print            print the records as JSON (used to compare two checkouts)
//
// DRIFT_REPO=<path> imports the scanner from another checkout (to compare two releases); it is never set by the gate.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');
const SCANNER_REPO = process.env.DRIFT_REPO ? path.resolve(process.env.DRIFT_REPO) : REPO;
const BASELINE = path.join(HERE, 'BASELINE.json');

// Fixed inputs: committed fixtures only, chosen to cover the detectors and annotators that decide default output.
const ROOTS = [
  'scanner/test/fixtures/vulnerable-js',
  'scanner/test/fixtures/clean-js',
  'scanner/test/fixtures/code-injection-coercion',
  'scanner/test/fixtures/business-logic',
  'scanner/test/fixtures/csrf-routes',
  'scanner/test/fixtures/cookie-cors',
  'bench/dag/fixtures/callreturn',
  'bench/dag/fixtures/multiservice',
];

export async function collect() {
  const { disableStateWrites } = await import(path.join(REPO, 'bench', '_lib', 'tree-integrity.mjs'));
  await disableStateWrites();
  process.env.AGENTIC_SECURITY_NO_PROVENANCE = '1';
  process.env.AGENTIC_SECURITY_OFFLINE = '1';
  const { runScan } = await import(path.join(SCANNER_REPO, 'scanner', 'src', 'runScan.js'));
  const records = [];
  for (const rel of ROOTS) {
    const root = path.join(REPO, rel);
    if (!fs.existsSync(root)) { records.push({ root: rel, missing: true }); continue; }
    const { scan } = await runScan(root, { deterministic: true });
    for (const f of [...(scan.findings || []), ...(scan.logicVulns || [])]) {
      records.push({
        root: rel,
        file: String(f.file || '').replace(root, '').replace(/^\/+/, ''),
        line: Number.isInteger(f.line) ? f.line : null,
        vuln: f.vuln || null,
        severity: f.severity || null,
        family: f.family || null,
        parser: f.parser || null,
      });
    }
  }
  records.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return records;
}

const key = (r) => JSON.stringify(r);
export function diff(base, now) {
  const count = (arr) => { const m = new Map(); for (const r of arr) m.set(key(r), (m.get(key(r)) || 0) + 1); return m; };
  const a = count(base), b = count(now);
  const added = [], removed = [];
  for (const [k, n] of b) if (n > (a.get(k) || 0)) added.push(JSON.parse(k));
  for (const [k, n] of a) if (n > (b.get(k) || 0)) removed.push(JSON.parse(k));
  return { added, removed };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const records = await collect();
  if (process.argv.includes('--print')) { console.log(JSON.stringify(records)); process.exit(0); }
  if (process.argv.includes('--update-baseline')) {
    fs.writeFileSync(BASELINE, JSON.stringify({
      schema: 'default-scan-drift/v1',
      note: 'Findings of a default scan over fixed committed fixtures. Change this file only with a changelog entry that names the rule that moved.',
      roots: ROOTS,
      total: records.length,
      records,
    }, null, 1) + '\n');
    console.log(`baseline written: ${records.length} findings over ${ROOTS.length} roots`);
    process.exit(0);
  }
  let base;
  try { base = JSON.parse(fs.readFileSync(BASELINE, 'utf8')); } catch {
    console.error('no baseline: run with --update-baseline. An unmeasurable gate is a failure, not a skip.');
    process.exit(1);
  }
  const { added, removed } = diff(base.records, records);
  if (!added.length && !removed.length) { console.log(`default-scan drift: none (${records.length} findings over ${ROOTS.length} roots)`); process.exit(0); }
  const show = (r) => `${r.root}  ${r.file}:${r.line ?? '-'}  ${r.vuln}  [${r.severity}/${r.family}/${r.parser}]`;
  console.error(`default-scan drift: ${added.length} added, ${removed.length} removed.`);
  for (const r of added.slice(0, 40)) console.error(`  + ${show(r)}`);
  for (const r of removed.slice(0, 40)) console.error(`  - ${show(r)}`);
  console.error('A change to default output must be deliberate: name the rule in the changelog, then re-run with --update-baseline.');
  process.exit(1);
}
