#!/usr/bin/env node
// PreToolUse hook: when Claude is about to edit a file, inject the file's
// relevant SECURITY CONTEXT into the next-turn prompt — recent findings, the
// most-recent /fix on that file, and any pending fix-plans. The goal is to
// stop Claude from re-introducing a vulnerability it (or a teammate) just
// fixed.
//
// The hook reads .agentic-security/{last-scan.json,fix-history/log.json,fix-plans/}
// and emits a JSON object with `additionalContext` per the Claude Code
// PreToolUse spec. The harness merges that into the model's context for the
// edit turn.
//
// Output budget: cap at ~30 lines of context per edit to avoid prompt bloat.
'use strict';
const fs = require('fs');
const path = require('path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
  });
}

function readJSON(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}

function relativizeToCwd(p) {
  if (!p) return p;
  try {
    const rel = path.relative(cwd, path.resolve(p));
    return rel.startsWith('..') ? p : rel;
  } catch { return p; }
}

function findingsForFile(scan, relFile) {
  if (!scan || !Array.isArray(scan.findings)) return [];
  return scan.findings.filter(f => f.file === relFile);
}

function recentFixHistory(relFile) {
  const log = readJSON(path.join(stateDir, 'fix-history', 'log.json'));
  if (!Array.isArray(log)) return [];
  // Most-recent first; only this file; only the last 14 days.
  const cutoff = Date.now() - 14 * 86400_000;
  return log
    .filter(e => e && e.file === relFile && !e.reverted)
    .filter(e => {
      try { return new Date(e.appliedAt).getTime() >= cutoff; } catch { return true; }
    })
    .slice(-5)
    .reverse();
}

function pendingFixPlans(relFile) {
  const dir = path.join(stateDir, 'fix-plans');
  if (!fs.existsSync(dir)) return [];
  try {
    return fs.readdirSync(dir)
      .filter(n => /\.md$/.test(n))
      .map(n => path.join(dir, n))
      .filter(fp => {
        try { return fs.readFileSync(fp, 'utf8').includes(relFile); } catch { return false; }
      })
      .slice(0, 3);
  } catch { return []; }
}

// Build the file-context block for a PreToolUse payload, or null when there's
// nothing to inject. Importable so the single PreToolUse dispatcher (#24) can
// run it in-process. stdout of this string is appended to the model's context.
function buildContextOutput(payload) {
  // tool_input shape varies: Edit/Write have file_path; MultiEdit has it too.
  const filePath = payload?.tool_input?.file_path || payload?.tool_input?.path || null;
  if (!filePath) return null;
  const rel = relativizeToCwd(filePath);

  const scan = readJSON(path.join(stateDir, 'last-scan.json'));
  const findings = findingsForFile(scan, rel);
  const fixes = recentFixHistory(rel);
  const plans = pendingFixPlans(rel);

  if (findings.length === 0 && fixes.length === 0 && plans.length === 0) return null;

  const lines = [];
  lines.push(`agentic-security context for ${rel}:`);
  if (findings.length) {
    const top = findings.slice(0, 6).map(f =>
      `  · [${(f.severity || '?').toUpperCase()}] ${f.vuln || 'finding'} @ line ${f.line || '?'}` +
      (f.stableId ? ` (id ${f.stableId.slice(0, 8)})` : '')
    );
    lines.push(`  ${findings.length} open finding(s):`);
    lines.push(...top);
    if (findings.length > 6) lines.push(`  · ... and ${findings.length - 6} more`);
  }
  if (fixes.length) {
    lines.push(`  Recent /fix history (don't re-introduce these vulns):`);
    for (const e of fixes) {
      const when = (e.appliedAt || '').slice(0, 10);
      lines.push(`  · ${when}: ${e.vuln || e.findingId || '(unnamed)'}`);
    }
  }
  if (plans.length) {
    lines.push(`  Pending fix-plan(s) for this file:`);
    for (const p of plans) lines.push(`  · ${path.basename(p)}`);
  }
  // Truncate to budget.
  return lines.slice(0, 30).join('\n');
}

if (require.main === module) {
  (async () => {
    const payload = await readStdinJSON();
    const out = buildContextOutput(payload);
    if (out) process.stdout.write(out + '\n');
    process.exit(0);
  })().catch(() => process.exit(0));
}

module.exports = { buildContextOutput };
