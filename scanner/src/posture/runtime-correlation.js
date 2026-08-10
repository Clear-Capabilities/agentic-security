// eBPF runtime instrumentation correlation — Recommendation #5 of the
// world-class roadmap.
//
// The hardest false-positive class is "this code path is technically
// reachable but is DEAD in production." Static analysis can't distinguish
// dead code from reachable code; runtime observation can. This module
// consumes an eBPF trace dataset (produced by an out-of-band collector
// running in the customer's prod environment) and demotes findings
// whose call-graph paths were unobserved.
//
// Trace format (JSONL, one record per observation):
//
//   { "ts": "2026-05-28T...", "host": "prod-host-1",
//     "kind": "function-call", "qid": "com.acme.UserController.getUser",
//     "fileRel": "src/main/java/com/acme/UserController.java", "line": 42,
//     "count": 1234, "lastSeen": "2026-05-28T..." }
//
// Common record kinds:
//   - "function-call":   QID was invoked at least once in the trace window
//   - "route-hit":       HTTP route received traffic
//   - "syscall":         filesystem / network / process syscall fired
//   - "file-touch":      file was read / written
//
// The trace file lives at one of:
//   .agentic-security/runtime-trace.jsonl (per-project, committed)
//   $AGENTIC_SECURITY_RUNTIME_TRACE_PATH    (override)
//
// Output: every finding gets a `runtimeObserved: true|false|unknown` field.
//   true   — at least one node on the finding's call-graph path appears in trace
//   false  — none of the nodes appear (finding's path is dead in observed window)
//   unknown — no trace data available

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { createReadStream } from 'node:fs';

import { statePath } from './state-dir.js';
const DEFAULT_TRACE_NAMES = ['runtime-trace.jsonl', 'runtime.jsonl', 'ebpf-trace.jsonl'];
const DEFAULT_OBSERVATION_WINDOW_DAYS = 30;

export async function loadTrace(scanRoot, opts = {}) {
  const explicit = opts.tracePath || process.env.AGENTIC_SECURITY_RUNTIME_TRACE_PATH;
  const candidates = explicit ? [explicit] : DEFAULT_TRACE_NAMES.map(n => statePath(scanRoot, n));
  let chosen = null;
  for (const c of candidates) {
    if (fs.existsSync(c)) { chosen = c; break; }
  }
  if (!chosen) return null;
  const trace = {
    path: chosen,
    qidsObserved: new Set(),
    routesObserved: new Set(),
    filesObserved: new Set(),
    fileLinesObserved: new Map(), // file → Set<line>
    syscallsObserved: new Set(),
    recordCount: 0,
  };
  const window = (opts.windowDays || DEFAULT_OBSERVATION_WINDOW_DAYS) * 86400_000;
  const now = Date.now();
  const stream = createReadStream(chosen, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let r;
    try { r = JSON.parse(line); } catch { continue; }
    if (r.ts) {
      const tsMs = Date.parse(r.ts);
      if (Number.isFinite(tsMs) && now - tsMs > window) continue;
    }
    trace.recordCount++;
    switch (r.kind) {
      case 'function-call':
        if (r.qid) trace.qidsObserved.add(r.qid);
        if (r.fileRel && typeof r.line === 'number') {
          let set = trace.fileLinesObserved.get(r.fileRel);
          if (!set) { set = new Set(); trace.fileLinesObserved.set(r.fileRel, set); }
          set.add(r.line);
        }
        if (r.fileRel) trace.filesObserved.add(r.fileRel);
        break;
      case 'route-hit':
        if (r.route) trace.routesObserved.add(r.route);
        break;
      case 'syscall':
        if (r.name) trace.syscallsObserved.add(r.name);
        break;
      case 'file-touch':
        if (r.fileRel) trace.filesObserved.add(r.fileRel);
        break;
    }
  }
  return trace;
}

/**
 * Test whether a finding's call-graph path was observed in trace.
 * Checks:
 *   1. The finding's file appears in filesObserved (necessary condition)
 *   2. AT LEAST ONE line on the finding's chain (source, sink, intermediate
 *      nodes) was observed in that file
 *   3. The finding's containing function's qid appears in qidsObserved
 */
export function findingObservedInRuntime(finding, trace) {
  if (!trace) return 'unknown';
  // qid match (most specific)
  if (finding.scope && trace.qidsObserved.has(finding.scope)) return true;
  if (finding.functionQid && trace.qidsObserved.has(finding.functionQid)) return true;
  // file + any-line on the chain match
  const file = finding.file || (finding.sink && finding.sink.file);
  if (file && trace.filesObserved.has(file)) {
    const linesObserved = trace.fileLinesObserved.get(file);
    if (linesObserved) {
      const chainLines = [
        finding.line,
        ...(finding.chain || []).map(s => s.line),
        ...(finding.taintPath || []).map(s => s.line),
      ].filter(n => typeof n === 'number');
      for (const ln of chainLines) {
        // Allow ±2 line tolerance for compiler reordering / minor inlining.
        for (let off = -2; off <= 2; off++) {
          if (linesObserved.has(ln + off)) return true;
        }
      }
    }
    // File appears but no line match — partial evidence. Don't claim
    // observed; don't claim dead.
    return 'unknown';
  }
  // route match — every finding inside a route handler whose route was hit.
  if (finding._inRoute && finding._inRoute.path && trace.routesObserved.has(finding._inRoute.path)) return true;
  if (finding.routeRooted && finding._inRoute && trace.routesObserved.size > 0) {
    for (const r of trace.routesObserved) {
      if (finding._inRoute.path && r.includes(finding._inRoute.path)) return true;
    }
  }
  return false;
}

/**
 * Annotate all findings with runtimeObserved + demote unobserved findings.
 * Demotion: critical → high, high → medium, medium → low.
 *
 * Findings classified as unknown are left alone (no demotion). This is
 * the principled position — absence of observation in a partial trace
 * is not evidence of dead code.
 */
export async function annotateRuntimeCorrelation(scanRoot, findings, opts = {}) {
  if (!Array.isArray(findings)) return { observed: 0, dead: 0, unknown: 0 };
  const trace = await loadTrace(scanRoot, opts);
  if (!trace) {
    for (const f of findings) f.runtimeObserved = 'unknown';
    return { observed: 0, dead: 0, unknown: findings.length, trace: null };
  }
  let observed = 0, dead = 0, unknown = 0;
  const demoteLadder = { critical: 'high', high: 'medium', medium: 'low', low: 'info' };
  for (const f of findings) {
    const v = findingObservedInRuntime(f, trace);
    f.runtimeObserved = v;
    if (v === true) observed++;
    else if (v === false) {
      dead++;
      // Demote one tier — the finding is real but unobserved in 30 days
      // of production traffic, so it's not P0.
      const next = demoteLadder[f.severity];
      if (next) {
        f._runtimeDemoted = f.severity;
        f.severity = next;
      }
    } else unknown++;
  }
  return { observed, dead, unknown, trace: { recordCount: trace.recordCount, path: trace.path } };
}

export const _internals = { DEFAULT_TRACE_NAMES, DEFAULT_OBSERVATION_WINDOW_DAYS };
