#!/usr/bin/env node
// Validator outcome history — used for confidence calibration.
// Persists to .agentic-security/validator-history.json as a list of:
//   {ts, id, vuln, cwe, family, verdict, proven, finalOutcome}
// where finalOutcome ∈ {'TP_PROVEN','TP_CONFIRMED','PROBABLE_FP','INDETERMINATE','REFUSED'}.
//
// Usage:
//   history.js append <verdict-json>   → append a record
//   history.js summary                 → print per-family accuracy
//   history.js clear                   → wipe history

import * as fs from 'node:fs';
import * as path from 'node:path';

const HIST = path.join(process.cwd(), '.agentic-security', 'validator-history.json');

function load() {
  if (!fs.existsSync(HIST)) return [];
  try { return JSON.parse(fs.readFileSync(HIST, 'utf8')); } catch { return []; }
}
function save(rows) {
  fs.mkdirSync(path.dirname(HIST), { recursive: true });
  fs.writeFileSync(HIST, JSON.stringify(rows, null, 2));
}

function append(verdictJson) {
  const v = JSON.parse(verdictJson);
  const rows = load();
  rows.push({
    ts: new Date().toISOString(),
    id: v.id || null,
    vuln: v.vuln || null,
    cwe: v.cwe || null,
    family: v.family || null,
    verdict: v.verdict,
    proven: !!v.proven,
    durationMs: v.durationMs || null,
  });
  save(rows);
  process.stdout.write(`appended (n=${rows.length})\n`);
}

function summary() {
  const rows = load();
  if (!rows.length) { process.stdout.write('No history yet.\n'); return; }
  const byFamily = new Map();
  for (const r of rows) {
    const fam = r.family || 'unknown';
    const b = byFamily.get(fam) || { total: 0, proven: 0, fp: 0, indet: 0, refused: 0 };
    b.total++;
    if (r.verdict === 'TP_PROVEN') b.proven++;
    else if (r.verdict?.startsWith('PROBABLE_FP')) b.fp++;
    else if (r.verdict?.startsWith('REFUSED')) b.refused++;
    else b.indet++;
    byFamily.set(fam, b);
  }
  process.stdout.write(`Validator track record across your project (${rows.length} runs):\n\n`);
  process.stdout.write(`  ${'family'.padEnd(28)} N   proven  FP   indet  refused  accuracy\n`);
  for (const [fam, b] of [...byFamily].sort((a, b) => b[1].total - a[1].total)) {
    const acc = b.total ? ((b.proven + b.fp) / b.total * 100).toFixed(0) : '—';
    process.stdout.write(
      `  ${fam.padEnd(28)} ${String(b.total).padEnd(3)} ${String(b.proven).padEnd(7)} ${String(b.fp).padEnd(4)} ${String(b.indet).padEnd(6)} ${String(b.refused).padEnd(8)} ${acc}%\n`
    );
  }
  // Overall
  const total = rows.length;
  const decisive = rows.filter(r => r.verdict === 'TP_PROVEN' || r.verdict?.startsWith('PROBABLE_FP')).length;
  process.stdout.write(`\nDecisive verdicts (TP_PROVEN or PROBABLE_FP): ${decisive}/${total} = ${(decisive/total*100).toFixed(0)}%\n`);
}

function clear() {
  if (fs.existsSync(HIST)) fs.unlinkSync(HIST);
  process.stdout.write('cleared\n');
}

const [, , cmd, arg] = process.argv;
if (cmd === 'append' && arg) append(arg);
else if (cmd === 'summary') summary();
else if (cmd === 'clear') clear();
else { console.error('Usage: history.js append <json> | summary | clear'); process.exit(2); }
