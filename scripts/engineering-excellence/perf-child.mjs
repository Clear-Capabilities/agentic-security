// One cold measured scan in a fresh process (E6-08): prints a single JSON line with wall time, CPU time, peak RSS, finding count and scan health.
//   node perf-child.mjs <dir> <deep:0|1>
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const source = path.resolve(process.argv[2]); const deep = process.argv[3] === '1';
// scan a COPY: a scan with a scan root writes its state next to the code, and a fixture directory must not be left with a prior scan in it
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-perf-')); fs.cpSync(source, dir, { recursive: true, filter: (p) => !/(^|\/)(\.git|node_modules|\.agentic-security)(\/|$)/.test(p) });
process.on('exit', () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } });
const { runFullScan } = await import(path.join(ROOT, 'scanner', 'src', 'engine.js'));
const { setStateWritesEnabled } = await import(path.join(ROOT, 'scanner', 'src', 'posture', 'state-dir.js'));
setStateWritesEnabled(false);
const files = {};
(function walk(p, rel) {
  for (const e of fs.readdirSync(p, { withFileTypes: true })) {
    if (['node_modules', '.git', 'dist', '.agentic-security'].includes(e.name)) continue;
    const r = path.join(rel, e.name);
    if (e.isDirectory()) walk(path.join(p, e.name), r);
    else if (/\.(js|mjs|ts|tsx|jsx|py|java|go|rb|php|cs)$/.test(e.name) && fs.statSync(path.join(p, e.name)).size < 500_000) files[r] = fs.readFileSync(path.join(p, e.name), 'utf8');
  }
})(dir, '');
const cpu0 = process.cpuUsage(); const t0 = performance.now();
const scan = await runFullScan({ fileContents: files, scanRoot: dir, deep });
const wallMs = performance.now() - t0; const cpu = process.cpuUsage(cpu0);
const ru = process.resourceUsage();
process.stdout.write(JSON.stringify({ files: Object.keys(files).length, wallMs: Math.round(wallMs), cpuMs: Math.round((cpu.user + cpu.system) / 1000), maxRssMb: Math.round(ru.maxRSS / 1024), findings: scan.findings.length, health: scan.scanHealth ? scan.scanHealth.status : 'unknown', conditions: scan.scanHealth ? scan.scanHealth.conditions : [] }) + '\n');
