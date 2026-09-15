#!/usr/bin/env node
// Status checker for SARD_80_F1_EXECUTION_PRD.md's execution ledger
// (bench/sard/EXECUTION_STATUS.md). Parses the ledger's own status tables —
// never re-derives "done" from source code existing, since that is exactly
// the mistake the ledger's own header rule exists to prevent. This script
// reports what the ledger CLAIMS; it does not re-verify the claims itself
// (the ledger's own inline command+output next to each VERIFIED line is the
// verification — this script is a summary view over it).
//
// Usage:
//   node bench/sard/scripts/execution-status.mjs           # human-readable
//   node bench/sard/scripts/execution-status.mjs --json     # machine-readable

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LEDGER = path.join(__dirname, '..', 'EXECUTION_STATUS.md');

const STATUSES = ['NOT_STARTED', 'IN_PROGRESS', 'BLOCKED', 'IMPLEMENTED_UNVERIFIED', 'VERIFIED'];
const WEIGHT = { NOT_STARTED: 0, BLOCKED: 0, IN_PROGRESS: 0.4, IMPLEMENTED_UNVERIFIED: 0.6, VERIFIED: 1 };

function parseLedger(text) {
  const lines = text.split('\n');
  const workstreams = [];
  let current = null;
  let inMilestones = false;
  const milestones = [];

  for (const line of lines) {
    const wsHeader = line.match(/^## (W\d+[A-Za-z]?) — (.+)$/);
    if (wsHeader) {
      current = { id: wsHeader[1], name: wsHeader[2].trim(), tasks: [], acceptance: null, acceptanceStatus: null };
      workstreams.push(current);
      inMilestones = false;
      continue;
    }
    if (/^## Milestone gates/.test(line)) { inMilestones = true; current = null; continue; }
    if (/^## Baseline/.test(line) || /^## Session log/.test(line)) { inMilestones = false; current = null; continue; }

    if (current) {
      const taskRow = line.match(/^\|\s*(W\d+[A-Za-z0-9.]*)\s*\|\s*(.+?)\s*\|\s*(NOT_STARTED|IN_PROGRESS|BLOCKED|IMPLEMENTED_UNVERIFIED|VERIFIED)\s*\|$/);
      if (taskRow) {
        current.tasks.push({ id: taskRow[1], name: taskRow[2], status: taskRow[3] });
        continue;
      }
      const acc = line.match(/^\*\*.*acceptance:\*\*\s*(.+?)\s*Status:\s*(NOT_STARTED|IN_PROGRESS|BLOCKED|IMPLEMENTED_UNVERIFIED|VERIFIED)\.?\s*$/i);
      if (acc) {
        current.acceptance = acc[1];
        current.acceptanceStatus = acc[2];
      }
    }
    if (inMilestones) {
      const mRow = line.match(/^\|\s*(M\d+)\s*\([^)]*\)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(NOT_STARTED|IN_PROGRESS|BLOCKED|IMPLEMENTED_UNVERIFIED|VERIFIED)\s*\|$/);
      if (mRow) {
        milestones.push({ id: mRow[1], java: mRow[2], csharp: mRow[3], php: mRow[4], status: mRow[5] });
      }
    }
  }
  return { workstreams, milestones };
}

function pct(tasks) {
  if (!tasks.length) return 0;
  const sum = tasks.reduce((a, t) => a + (WEIGHT[t.status] ?? 0), 0);
  return Math.round((sum / tasks.length) * 100);
}

function bar(p, width = 20) {
  const filled = Math.round((p / 100) * width);
  return '[' + '#'.repeat(filled) + '-'.repeat(width - filled) + `] ${p}%`;
}

function main() {
  if (!fs.existsSync(LEDGER)) {
    console.error(`Ledger not found at ${LEDGER}`);
    process.exit(1);
  }
  const text = fs.readFileSync(LEDGER, 'utf8');
  const { workstreams, milestones } = parseLedger(text);
  const asJson = process.argv.includes('--json');

  const overallTasks = workstreams.flatMap((w) => w.tasks);
  const overallPct = pct(overallTasks);

  if (asJson) {
    console.log(JSON.stringify({
      generatedAt: new Date().toISOString(),
      overallPct,
      workstreams: workstreams.map((w) => ({
        id: w.id, name: w.name, pct: pct(w.tasks), tasks: w.tasks,
        acceptance: w.acceptance, acceptanceStatus: w.acceptanceStatus,
      })),
      milestones,
    }, null, 2));
    return;
  }

  console.log(`SARD 80% F1 Execution PRD — status (${new Date().toISOString()})\n`);
  console.log(`Overall  ${bar(overallPct)}  (${overallTasks.length} tasks across ${workstreams.length} workstreams)\n`);

  for (const w of workstreams) {
    const p = pct(w.tasks);
    console.log(`${w.id} ${w.name}`);
    console.log(`  ${bar(p)}`);
    for (const t of w.tasks) {
      const mark = t.status === 'VERIFIED' ? '✓' : t.status === 'IN_PROGRESS' ? '~' : t.status === 'BLOCKED' ? '!' : t.status === 'IMPLEMENTED_UNVERIFIED' ? '?' : ' ';
      console.log(`    [${mark}] ${t.id}: ${t.name} — ${t.status}`);
    }
    if (w.acceptanceStatus) {
      console.log(`  Acceptance: ${w.acceptanceStatus}`);
    }
    console.log('');
  }

  console.log('Milestone gates (TEST split, run once each):');
  for (const m of milestones) {
    console.log(`  ${m.id}: Java${m.java} C#${m.csharp} PHP${m.php} — ${m.status}`);
  }
}

main();
