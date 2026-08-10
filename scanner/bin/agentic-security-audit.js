#!/usr/bin/env node
// Transcript-review CLI for the MCP audit log (eval-post recommendation #6).
//
// Quote we're implementing:
//   "When a task fails, the transcript tells you whether the agent made a
//    genuine mistake or whether your graders rejected a valid solution.
//    As a rule, we do not take eval scores at face value until someone digs
//    into the details of the eval and reads some transcripts."
//
// Subcommands:
//   review    print a sampled set of entries from .agentic-security/mcp-audit.log
//   metrics   aggregate outcomes by tool over the last N days
//   verify    verify the hash chain on the local audit log
//
// Usage:
//   agentic-security-audit review                       # last 24h, 20 entries
//   agentic-security-audit review --last 7d --n 50
//   agentic-security-audit review --tool apply_fix --outcome rejected
//   agentic-security-audit metrics --last 30d
//   agentic-security-audit verify
'use strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyAuditLog } from '../src/mcp/audit.js';

import { statePath } from '../src/posture/state-dir.js';
function args() {
  const a = process.argv.slice(2);
  const sub = a[0] || 'review';
  const out = { sub, last: '24h', n: 20, tool: null, outcome: null, root: process.cwd(), json: false, bySession: false, outlierThreshold: 20 };
  for (let i = 1; i < a.length; i++) {
    if (a[i] === '--last') out.last = a[++i];
    else if (a[i] === '--n') out.n = parseInt(a[++i], 10);
    else if (a[i] === '--tool') out.tool = a[++i];
    else if (a[i] === '--outcome') out.outcome = a[++i];
    else if (a[i] === '--root') out.root = a[++i];
    else if (a[i] === '--json') out.json = true;
    else if (a[i] === '--by-session') out.bySession = true;
    else if (a[i] === '--outlier-threshold') out.outlierThreshold = parseInt(a[++i], 10);
  }
  return out;
}

function _parseDuration(s) {
  const m = /^(\d+)([smhdw])$/.exec(String(s || ''));
  if (!m) return 24 * 3600 * 1000;
  const n = parseInt(m[1], 10);
  const u = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000, w: 7 * 86_400_000 }[m[2]];
  return n * u;
}

function _logPath(root) { return statePath(root, 'mcp-audit.log'); }

function _readEntries(root) {
  const fp = _logPath(root);
  if (!fs.existsSync(fp)) return [];
  const lines = fs.readFileSync(fp, 'utf8').split('\n').filter(Boolean);
  const out = [];
  for (const line of lines) {
    try { out.push(JSON.parse(line)); } catch { /* skip malformed line */ }
  }
  return out;
}

function _filterEntries(entries, opts) {
  const cutoff = Date.now() - _parseDuration(opts.last);
  return entries.filter(e => {
    const t = Date.parse(e.ts || '');
    if (Number.isFinite(t) && t < cutoff) return false;
    if (opts.tool && e.tool !== opts.tool) return false;
    if (opts.outcome && e.outcome !== opts.outcome) return false;
    return true;
  });
}

function _sample(arr, n) {
  if (arr.length <= n) return arr;
  // Reservoir-style: keep first N, then replace at decreasing probability so
  // the sample stays uniform across the source distribution. Deterministic
  // seed = first entry's ts so a repeated run on the same data sees the same
  // sample. (Operators want reproducible spot-checks.)
  const out = arr.slice(0, n);
  let seed = (arr[0]?.ts || '').length * 9301 + 49297;
  function rand() { seed = (seed * 9301 + 49297) % 233280; return seed / 233280; }
  for (let i = n; i < arr.length; i++) {
    const j = Math.floor(rand() * (i + 1));
    if (j < n) out[j] = arr[i];
  }
  return out;
}

function reviewCmd(opts) {
  const entries = _filterEntries(_readEntries(opts.root), opts);
  if (entries.length === 0) {
    if (opts.json) { console.log('[]'); return; }
    console.log(`No entries match (root=${opts.root}, last=${opts.last}${opts.tool ? ', tool=' + opts.tool : ''}${opts.outcome ? ', outcome=' + opts.outcome : ''}).`);
    return;
  }
  const sample = _sample(entries, opts.n);
  if (opts.json) { console.log(JSON.stringify({ totalMatching: entries.length, sampled: sample.length, entries: sample }, null, 2)); return; }
  console.log('');
  console.log(`Audit transcript — root=${opts.root}, last=${opts.last}, matching=${entries.length}, sampled=${sample.length}`);
  if (opts.tool || opts.outcome) console.log(`  filters: ${[opts.tool ? `tool=${opts.tool}` : null, opts.outcome ? `outcome=${opts.outcome}` : null].filter(Boolean).join(', ')}`);
  console.log('');
  for (const e of sample) {
    const tag = e.outcome === 'ok' ? 'OK' : e.outcome === 'rejected' ? 'REJ' : e.outcome === 'error' ? 'ERR' : '???';
    const reasonStr = e.reason ? ` (${e.reason})` : '';
    console.log(`  [${tag.padStart(3)}] ${e.ts}  ${String(e.tool).padEnd(20)}${reasonStr}`);
    if (e.args) {
      const argStr = String(e.args).length > 200 ? String(e.args).slice(0, 200) + '…' : e.args;
      console.log(`         args: ${argStr}`);
    }
  }
  console.log('');
}

function metricsCmd(opts) {
  const entries = _filterEntries(_readEntries(opts.root), opts);
  if (opts.bySession) return _metricsBySession(entries, opts);
  const byTool = {};
  for (const e of entries) {
    if (!byTool[e.tool]) byTool[e.tool] = { ok: 0, rejected: 0, error: 0, total: 0 };
    byTool[e.tool].total++;
    byTool[e.tool][e.outcome] = (byTool[e.tool][e.outcome] || 0) + 1;
  }
  if (opts.json) { console.log(JSON.stringify({ last: opts.last, totalEntries: entries.length, byTool }, null, 2)); return; }
  console.log('');
  console.log(`Audit metrics — root=${opts.root}, last=${opts.last}, total=${entries.length}`);
  console.log('');
  console.log(`  ${'tool'.padEnd(22)} ${'ok'.padStart(6)} ${'rej'.padStart(6)} ${'err'.padStart(6)} ${'total'.padStart(6)}  rejRate`);
  for (const [tool, c] of Object.entries(byTool)) {
    const rejRate = c.total > 0 ? (c.rejected || 0) / c.total : 0;
    console.log(`  ${tool.padEnd(22)} ${String(c.ok || 0).padStart(6)} ${String(c.rejected || 0).padStart(6)} ${String(c.error || 0).padStart(6)} ${String(c.total).padStart(6)}  ${(rejRate * 100).toFixed(1)}%`);
  }
  console.log('');
}

// Per-session aggregation (harness-anatomy #9). Groups entries by sessionId
// (stamped on each audit entry at `auditCall` time). Flags sessions where any
// single tool was called > opts.outlierThreshold times — the "agent went into
// a tool loop and burned the budget" failure mode.
function _metricsBySession(entries, opts) {
  const bySession = {};
  for (const e of entries) {
    const sid = e.sessionId || 'pre-instrumented';   // entries from before #9
    if (!bySession[sid]) bySession[sid] = { total: 0, byTool: {}, firstTs: e.ts, lastTs: e.ts };
    const s = bySession[sid];
    s.total++;
    s.lastTs = e.ts;
    if (!s.byTool[e.tool]) s.byTool[e.tool] = 0;
    s.byTool[e.tool]++;
  }
  const sessions = Object.entries(bySession).map(([id, s]) => {
    const maxToolCount = Math.max(...Object.values(s.byTool));
    const dominantTool = Object.entries(s.byTool).sort((a, b) => b[1] - a[1])[0]?.[0];
    return {
      sessionId: id, total: s.total,
      firstTs: s.firstTs, lastTs: s.lastTs,
      byTool: s.byTool, dominantTool, maxToolCount,
      outlier: maxToolCount >= opts.outlierThreshold,
    };
  }).sort((a, b) => b.total - a.total);
  if (opts.json) {
    console.log(JSON.stringify({
      last: opts.last, outlierThreshold: opts.outlierThreshold,
      totalSessions: sessions.length, sessions,
    }, null, 2));
    return;
  }
  console.log('');
  console.log(`Audit metrics — by session, root=${opts.root}, last=${opts.last}, threshold=${opts.outlierThreshold} calls/tool`);
  console.log(`  ${sessions.length} session(s); ${sessions.filter(s => s.outlier).length} flagged as outliers`);
  console.log('');
  console.log(`  ${'sessionId'.padEnd(20)} ${'total'.padStart(6)} ${'dominant'.padEnd(22)} ${'max-of-1'.padStart(8)}  flag`);
  for (const s of sessions) {
    const flag = s.outlier ? '⚠ OUTLIER' : '';
    console.log(`  ${s.sessionId.slice(0, 20).padEnd(20)} ${String(s.total).padStart(6)} ${(s.dominantTool || '').padEnd(22)} ${String(s.maxToolCount).padStart(8)}  ${flag}`);
  }
  console.log('');
}

function verifyCmd(opts) {
  const fp = _logPath(opts.root);
  if (!fs.existsSync(fp)) { console.log('no audit log present'); process.exit(0); }
  const r = verifyAuditLog(fp);
  if (opts.json) { console.log(JSON.stringify(r, null, 2)); return; }
  if (r.ok) console.log(`Audit chain verified: ${r.entries} entries.`);
  else { console.error(`Audit chain BROKEN at line ${r.brokenAt}: ${r.reason || `expected prev=${r.expected}, got ${r.got}`}`); process.exit(1); }
}

const opts = args();
switch (opts.sub) {
  case 'review':  reviewCmd(opts); break;
  case 'metrics': metricsCmd(opts); break;
  case 'verify':  verifyCmd(opts); break;
  default:
    console.error(`Unknown subcommand: ${opts.sub}. Try: review | metrics | verify`);
    process.exit(2);
}
