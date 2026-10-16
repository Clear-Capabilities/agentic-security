#!/usr/bin/env node
// Measures what blaming each file once (instead of once per asked-about line) does to provenance resolution (E7-02): how many `git` processes a scan
// starts, how long the provenance stage takes, and what the attribution statuses are, on the same findings with the file-level cache on and off. The
// provenance time budget is set large so the budget does not decide the outcome; the budget exhaustion this relieves is shown by the process counts and
// the times. Writes docs/engineering-excellence/data/provenance-blame.json.
//
//   node scripts/engineering-excellence/provenance-measure.mjs [--dir scanner/src/sast] [--runs 3]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import cp from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; };
const target = path.resolve(ROOT, opt('--dir', 'scanner/src/sast')); const runs = Number(opt('--runs', '3'));
const counts = {};
const wrap = (name) => { const o = cp[name]; cp[name] = function (file, args) { if (file === 'git' && Array.isArray(args)) { const sub = args.find((a) => !a.startsWith('-') && !/^core\./.test(a) && a !== '/dev/null' && !a.includes('=')) || 'git'; counts[sub] = (counts[sub] || 0) + 1; } return o.apply(this, arguments); }; };
wrap('execFileSync'); wrap('spawnSync'); syncBuiltinESMExports();
const { runScan } = await import(path.join(ROOT, 'scanner', 'src', 'runScan.js'));
const { setStateWritesEnabled } = await import(path.join(ROOT, 'scanner', 'src', 'posture', 'state-dir.js'));
const { clearBlameCache } = await import(path.join(ROOT, 'scanner', 'src', 'posture', 'provenance', 'git-evidence.js'));
setStateWritesEnabled(false);
process.env.AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS = '1200000'; process.env.AGENTIC_SECURITY_OFFLINE = '1';

async function once(cache) {
  if (cache) delete process.env.AGENTIC_SECURITY_NO_BLAME_CACHE; else process.env.AGENTIC_SECURITY_NO_BLAME_CACHE = '1';
  clearBlameCache(); for (const k of Object.keys(counts)) delete counts[k];
  const t0 = performance.now();
  const { scan } = await runScan(target, { deep: false });
  const ms = performance.now() - t0;
  const all = [...(scan.findings || []), ...(scan.secrets || [])];
  const status = {}; for (const f of all) { const s = f.findingProvenance && f.findingProvenance.status || 'none'; status[s] = (status[s] || 0) + 1; }
  const stage = ((scan.telemetry && scan.telemetry.stages) || []).find((x) => x.name === 'annotator:annotateGitProvenance');
  return { wallMs: Math.round(ms), provenanceStageMs: stage ? Math.round(stage.ms) : null, findings: all.length, status, gitProcesses: { ...counts }, gitTotal: Object.values(counts).reduce((a, b) => a + b, 0) };
}
await once(true);
const on = []; const off = [];
for (let i = 0; i < runs; i++) { off.push(await once(false)); on.push(await once(true)); }
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const same = JSON.stringify(on.map((r) => r.status)) === JSON.stringify(off.map((r) => r.status));
const out = {
  schema: 'agentic-security/provenance-blame-measurement@1', target: path.relative(ROOT, target), runsPerArm: runs, hardware: { os: `${os.platform()} ${os.release()} ${os.arch()}`, cpus: os.cpus().length, loadAverage1m: os.loadavg()[0] },
  cacheOff: { gitProcessesMedian: med(off.map((r) => r.gitTotal)), blameProcesses: off[0].gitProcesses.blame || 0, provenanceStageMsMedian: med(off.map((r) => r.provenanceStageMs ?? 0)), statuses: off[off.length - 1].status, findings: off[0].findings },
  cacheOn: { gitProcessesMedian: med(on.map((r) => r.gitTotal)), blameProcesses: on[0].gitProcesses.blame || 0, provenanceStageMsMedian: med(on.map((r) => r.provenanceStageMs ?? 0)), statuses: on[on.length - 1].status, findings: on[0].findings },
  statusesIdentical: same,
  note: 'budget set to 20 minutes so it does not decide the result; machine was shared with other work, see loadAverage1m',
};
out.blameProcessReductionPct = out.cacheOff.blameProcesses ? Number((100 * (1 - out.cacheOn.blameProcesses / out.cacheOff.blameProcesses)).toFixed(1)) : null;
out.provenanceStageReductionPct = out.cacheOff.provenanceStageMsMedian ? Number((100 * (1 - out.cacheOn.provenanceStageMsMedian / out.cacheOff.provenanceStageMsMedian)).toFixed(1)) : null;
fs.mkdirSync(path.join(ROOT, 'docs', 'engineering-excellence', 'data'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'docs', 'engineering-excellence', 'data', 'provenance-blame.json'), JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify(out, null, 2));
process.exit(same ? 0 : 1);
