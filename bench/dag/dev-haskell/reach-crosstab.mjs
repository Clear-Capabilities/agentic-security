// The gate on the project-reachability mechanism (plan section H), run on DEVELOPMENT data only: cross-tabulate `finding.reachability.status` against the
// hand labels of the development set (labels.json + labels-remainder.json) and the fresh set (fresh-labels.json). If a single site labelled a TRUE POSITIVE
// lands in `unreachable-in-project`, the mechanism is wrong (its reasoning, not the label) and it does not ship: exit 1.
//
// Reads scan results written by `scan-all.mjs` (rows carry `reachability` and `originalSeverity`). A labelled site that no longer appears in the results is
// counted as `not-reported`; one reported without a verdict (a rule finding, or a function the IR has no record of) as `no-verdict`.
// usage: node bench/dag/dev-haskell/reach-crosstab.mjs <dev results dir> <fresh results dir> [--write <out.json>]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const H = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const wi = process.argv.indexOf('--write');
const outFile = wi >= 0 ? process.argv[wi + 1] : null;
if (outFile && args.includes(outFile)) args.splice(args.indexOf(outFile), 1);
const [devDir, freshDir] = args.map((d) => path.resolve(d));
if (!devDir || !freshDir) { console.error('usage: reach-crosstab.mjs <dev results dir> <fresh results dir> [--write <out.json>]'); process.exit(2); }

const stratumOf = (v) => (/^Path Traversal/.test(v) ? 'path-traversal' : v.replace(/^Unsafe boundary: .*/, 'unsafe-boundary'));
const load = (dir) => {
  const out = new Map();
  for (const f of fs.readdirSync(dir).sort()) {
    if (!f.endsWith('.json')) continue;
    const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    for (const r of j.haskell) { const k = `${j.id}:${r.file}:${r.line}:${stratumOf(r.vuln)}`; if (!out.has(k)) out.set(k, []); out.get(k).push(r); }
  }
  return out;
};
const dev = load(devDir);
const fresh = load(freshDir);

const devLabels = JSON.parse(fs.readFileSync(path.join(H, 'labels.json'), 'utf8')).labels;
const remainder = JSON.parse(fs.readFileSync(path.join(H, 'labels-remainder.json'), 'utf8')).labels;
const freshLabels = JSON.parse(fs.readFileSync(path.join(H, 'fresh-labels.json'), 'utf8')).labels;

const sets = { 'development, tuning half': [], 'development, verification half': [], 'development, remainder': [], fresh: [] };
for (const l of Object.values(devLabels)) sets[l.half === 'tuning' ? 'development, tuning half' : 'development, verification half'].push([`${l.project}:${l.file}:${l.line}:${stratumOf(l.vuln)}`, l.label, dev]);
for (const [k, l] of Object.entries(remainder)) sets['development, remainder'].push([k, l.label, dev]);
for (const [k, l] of Object.entries(freshLabels)) sets.fresh.push([k, l.label, fresh]);

const statusOf = (rows) => {
  if (!rows || !rows.length) return 'not-reported';
  const withV = rows.filter((r) => r.reachability && r.reachability.status);
  if (!withV.length) return 'no-verdict';
  // a site with several findings is in the bucket of the most exposed one (a flagged finding outranks one already lowered)
  const order = ['entrypoint-reachable', 'external-api', 'unknown', 'unreachable-in-project'];
  return withV.map((r) => r.reachability.status).sort((a, b) => order.indexOf(a) - order.indexOf(b))[0];
};
const STATUSES = ['entrypoint-reachable', 'external-api', 'unknown', 'unreachable-in-project', 'no-verdict', 'not-reported'];
const result = { devDir: path.basename(devDir), freshDir: path.basename(freshDir), sets: {}, total: {}, unreachableSites: [], tpInUnreachable: [] };
const grand = Object.fromEntries(STATUSES.map((s) => [s, { TP: 0, FP: 0 }]));
for (const [name, items] of Object.entries(sets)) {
  const t = Object.fromEntries(STATUSES.map((s) => [s, { TP: 0, FP: 0 }]));
  for (const [key, label, map] of items) {
    const rows = map.get(key);
    const st = statusOf(rows);
    t[st][label === 'TP' ? 'TP' : 'FP']++;
    grand[st][label === 'TP' ? 'TP' : 'FP']++;
    if (st === 'unreachable-in-project') {
      const row = rows.find((r) => r.reachability && r.reachability.status === 'unreachable-in-project');
      const site = { set: name, site: key, label, severity: row.severity, originalSeverity: row.originalSeverity || null, premise: row.reachability.premise, trust: row.trust && row.trust.verdict };
      result.unreachableSites.push(site);
      if (label === 'TP') result.tpInUnreachable.push(site);
    }
  }
  result.sets[name] = t;
}
result.total = grand;

const pad = (s, n) => String(s).padEnd(n);
console.log(`label x reachability.status   (development results: ${result.devDir}; fresh results: ${result.freshDir})`);
for (const [name, t] of [...Object.entries(result.sets), ['ALL LABELLED SITES', grand]]) {
  console.log(`\n${name}`);
  console.log(`  ${pad('status', 24)} ${pad('TP', 5)} ${pad('FP', 5)}`);
  for (const s of STATUSES) if (t[s].TP || t[s].FP) console.log(`  ${pad(s, 24)} ${pad(t[s].TP, 5)} ${pad(t[s].FP, 5)}`);
}
console.log(`\nunreachable-in-project sites: ${result.unreachableSites.length}`);
for (const s of result.unreachableSites) console.log(`  [${s.label}] ${s.site}  severity ${s.originalSeverity || s.severity} -> ${s.severity}  premise ${s.premise}  trust ${s.trust}`);
if (outFile) { fs.writeFileSync(path.resolve(outFile), JSON.stringify(result, null, 1) + '\n'); console.log(`\nwrote ${outFile}`); }
if (result.tpInUnreachable.length) {
  console.log(`\nFAIL: ${result.tpInUnreachable.length} site(s) labelled TRUE POSITIVE are in unreachable-in-project. The mechanism is wrong and does not ship.`);
  process.exit(1);
}
console.log('\nPASS: no site labelled a true positive is in unreachable-in-project.');
