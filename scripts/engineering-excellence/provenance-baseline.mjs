#!/usr/bin/env node
// Attribution coverage baseline (E7-02): scans a directory of this repository with provenance on and a generous time budget, and reports how many findings
// were attributed to a commit, how many could not be (and why), and how many were never eligible, against the 95% aspirational target of eligible findings.
// The generous budget is deliberate: with the default 60 seconds the result depends on how busy the machine is, which is a property of the run, not of the
// attribution. Writes docs/engineering-excellence/data/provenance-coverage.json.
//
//   node scripts/engineering-excellence/provenance-baseline.mjs [--dir scanner/src] [--deep] [--budget-min 20]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; };
const dir = path.resolve(ROOT, opt('--dir', 'scanner/src')); const deep = argv.includes('--deep'); const budgetMin = Number(opt('--budget-min', '20'));
process.env.AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS = String(budgetMin * 60_000); process.env.AGENTIC_SECURITY_OFFLINE = '1';
const { runScan } = await import(path.join(ROOT, 'scanner', 'src', 'runScan.js'));
const { setStateWritesEnabled } = await import(path.join(ROOT, 'scanner', 'src', 'posture', 'state-dir.js'));
const { attributionCoverage } = await import(path.join(ROOT, 'scanner', 'src', 'posture', 'provenance', 'coverage.js'));
setStateWritesEnabled(false);
const t0 = performance.now();
const { scan } = await runScan(dir, { deep });
const wallMs = Math.round(performance.now() - t0);
const all = [...(scan.findings || []), ...(scan.secrets || []), ...((scan.supplyChain || []).filter((s) => s.type === 'vulnerable_dep' && s.isDirect))];
const cov = attributionCoverage(all, { root: dir, readHeader: (f) => { try { return fs.readFileSync(path.join(dir, f), 'utf8').slice(0, 400); } catch { return null; } } });
const reasons = {};
for (const p of cov.perFinding) if (p.category.startsWith('eligible:')) { const k = `${p.category} | ${String(p.reason).slice(0, 120)}`; reasons[k] = (reasons[k] || 0) + 1; }
const out = {
  schema: 'agentic-security/provenance-coverage@1', scanned: path.relative(ROOT, dir), deepAnalysis: deep, budgetMinutes: budgetMin, wallMs,
  hardware: { os: `${os.platform()} ${os.release()} ${os.arch()}`, cpus: os.cpus().length, loadAverage1m: Number(os.loadavg()[0].toFixed(2)) },
  commit: (() => { try { return fs.readFileSync(path.join(ROOT, '.git'), 'utf8').length ? null : null; } catch { return null; } })(),
  total: cov.total, categories: cov.categories, attributed: cov.attributed, ineligible: cov.ineligible, eligible: cov.eligible, eligibleUnattributed: cov.eligibleUnattributed,
  overallRate: cov.overallRate, eligibleRate: cov.eligibleRate, target: cov.target, targetStatus: cov.targetStatus,
  unattributedReasons: Object.entries(reasons).sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ reason: k, findings: n })),
};
delete out.commit;
fs.mkdirSync(path.join(ROOT, 'docs', 'engineering-excellence', 'data'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'docs', 'engineering-excellence', 'data', deep ? 'provenance-coverage-deep.json' : 'provenance-coverage.json'), JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify(out, null, 2));
