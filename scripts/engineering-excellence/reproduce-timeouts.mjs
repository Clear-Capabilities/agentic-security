#!/usr/bin/env node
// Re-run the entries of a baseline run that timed out, one at a time, with the same scan function and settings, but a longer limit (E6-02), and record how
// long each takes. An entry that finishes was slow, not stuck; one that does not is a real engine problem. The result is NOT merged into the baseline: the
// baseline keeps its own denominators.
//
//   node scripts/engineering-excellence/reproduce-timeouts.mjs --run <runId> [--limit-min 60]   (writes docs/engineering-excellence/data/timeout-reproduction.json)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; };
const runId = opt('--run', null); const limitMin = Number(opt('--limit-min', '60'));
if (!runId) { console.error('usage: reproduce-timeouts --run <runId> [--limit-min N]'); process.exit(2); }
const { defaultScanFn } = await import(path.join(ROOT, 'scanner', 'src', 'posture', 'evaluation', 'runner.js'));
const { engineEnvironment } = await import(path.join(ROOT, 'scanner', 'src', 'posture', 'evaluation', 'custody.js'));
const result = JSON.parse(fs.readFileSync(path.join(ROOT, 'bench', 'independent', 'runs', runId, 'RESULT.json'), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'bench', 'independent', 'manifest.json'), 'utf8'));
const entries = manifest.entries || manifest;
const timedOut = (result.unscored || []).filter((u) => /exceeded \d+ms/.test(u.reason || ''));
const rows = [];
for (const u of timedOut) {
  const e = entries.find((x) => x.id === u.id);
  const variant = /\/post\)?$/.test(u.reason || '') ? 'post' : 'pre';
  const src = path.join(ROOT, 'bench', 'independent', 'cache', u.id, variant);
  const row = { id: u.id, repo: e && e.repo, language: e && e.language, variant, files: null, loadAverage1m: os.loadavg()[0] };
  if (!fs.existsSync(src)) { rows.push({ ...row, outcome: 'unavailable', detail: 'the tree is not materialised' }); continue; }
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-timeout-'));
  try {
    const copy = path.join(work, 'tree');
    fs.cpSync(src, copy, { recursive: true, filter: (p) => !/(^|\/)(\.git|\.agentic-security)(\/|$)/.test(p) });
    let n = 0; (function walk(d) { for (const x of fs.readdirSync(d, { withFileTypes: true })) { if (x.isDirectory()) walk(path.join(d, x.name)); else n++; } })(copy); row.files = n;
    const env = engineEnvironment({ PATH: process.env.PATH, LANG: 'C', HOME: work });
    const t0 = performance.now();
    try { const r = await defaultScanFn(copy, { layer: 'deep-taint', timeoutMs: limitMin * 60_000, env }); rows.push({ ...row, outcome: 'completed', seconds: Math.round((performance.now() - t0) / 1000), findings: (r.findings || []).length }); }
    catch (err) { rows.push({ ...row, outcome: String(err.code || 'error').toLowerCase(), seconds: Math.round((performance.now() - t0) / 1000), detail: String(err.message).slice(0, 200) }); }
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
  console.log(JSON.stringify(rows[rows.length - 1]));
}
const out = { schema: 'agentic-security/timeout-reproduction@1', runId, baselineLimitSeconds: 600, retryLimitMinutes: limitMin, hardware: { os: `${os.platform()} ${os.release()} ${os.arch()}`, cpus: os.cpus().length, memoryGb: Math.round(os.totalmem() / 2 ** 30) }, note: 'run one at a time; other work was using the machine, see loadAverage1m per row', rows };
fs.mkdirSync(path.join(ROOT, 'docs', 'engineering-excellence', 'data'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'docs', 'engineering-excellence', 'data', 'timeout-reproduction.json'), JSON.stringify(out, null, 2) + '\n');
