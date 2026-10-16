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
import { linkObservationToSnapshot, normalizeIdentity } from '../lineage/deployment-identity.js';
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
    // E5-02: with a snapshot identity, each record is compared with it. A record from a different build is dropped and counted; one that carries no
    // comparable identity is kept as unattested; one that matches is counted as matched.
    recordsMatched: 0, recordsUnattested: 0, recordsMismatched: 0,
  };
  const snap = opts.snapshotIdentity ? normalizeIdentity(opts.snapshotIdentity) : null;
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
    if (snap) {
      const link = linkObservationToSnapshot({ commit: r.commit, buildHash: r.buildHash, imageDigest: r.imageDigest, sbomRef: r.sbomRef, environment: r.environment }, snap);
      if (link.state === 'mismatched') { trace.recordsMismatched++; continue; }
      if (link.state === 'matched') trace.recordsMatched++; else trace.recordsUnattested++;
    } else trace.recordsUnattested++;
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
 * Annotate every finding with what the runtime trace says about it, and say what that does NOT mean.
 *
 * `runtimeObserved` keeps its three values (true, false, 'unknown'); `runtimeEvidence` states them in words:
 *   observed               a function, line or route on the finding's path appears in the trace
 *   not_observed_in_window nothing on its path appears in the window. This is a statement about the window and the instrumentation, NOT a statement
 *                          that the code is unreachable or safe: low traffic, a rare path, an uninstrumented file and an incomplete window all look
 *                          the same from here
 *   unknown                no trace, or the file appears with no matching line
 *
 * SEVERITY IS NOT CHANGED BY DEFAULT. This module used to lower the severity of every unobserved finding one tier. Absence of observation cannot
 * justify that (and the lineage observation path never did), so demotion is now an explicit, opt-in policy: `opts.demote === true` or
 * AGENTIC_SECURITY_RUNTIME_DEMOTE=1. Even then it needs cited evidence: the trace must hold at least `minRecords` records, the finding must be rooted in a
 * route, and that route must be absent from a trace that does hold route hits (traffic reached the service and did not reach this route). A finding that
 * fails any condition is left as it is.
 * A demoted finding records the evidence under `_runtimeDemotionEvidence`; a finding is never removed.
 */
export async function annotateRuntimeCorrelation(scanRoot, findings, opts = {}) {
  if (!Array.isArray(findings)) return { observed: 0, dead: 0, unknown: 0, demoted: 0 };
  const trace = await loadTrace(scanRoot, opts);
  const windowDays = opts.windowDays || DEFAULT_OBSERVATION_WINDOW_DAYS;
  if (!trace || trace.recordCount === 0) {
    // no file, or nothing usable in it (empty, outside the window, or every record from another build): there is nothing to compare a finding with
    const basis = !trace ? 'no runtime trace was available' : (trace.recordsMismatched > 0 ? `all ${trace.recordsMismatched} usable record(s) came from a different build` : 'the trace holds no records inside the window');
    for (const f of findings) { f.runtimeObserved = 'unknown'; f.runtimeEvidence = { state: 'unknown', basis, windowDays, recordCount: 0, ...(trace ? { recordsMismatched: trace.recordsMismatched } : {}) }; }
    return { observed: 0, dead: 0, unknown: findings.length, demoted: 0, trace: trace ? { recordCount: 0, path: trace.path, recordsMismatched: trace.recordsMismatched } : null };
  }
  const demote = opts.demote === true || process.env.AGENTIC_SECURITY_RUNTIME_DEMOTE === '1';
  const minRecords = Number.isInteger(opts.minRecords) ? opts.minRecords : 100;
  let observed = 0, dead = 0, unknown = 0, demoted = 0;
  const demoteLadder = { critical: 'high', high: 'medium', medium: 'low', low: 'info' };
  for (const f of findings) {
    const v = findingObservedInRuntime(f, trace);
    f.runtimeObserved = v;
    const file = f.file || (f.sink && f.sink.file);
    f.runtimeEvidence = v === true ? { state: 'observed', basis: 'a function, line or route on the finding\'s path is in the trace', windowDays, recordCount: trace.recordCount, corroboration: (opts.snapshotIdentity && trace.recordsMatched > 0 && trace.recordsUnattested === 0) ? 'corroborated' : 'unattested', recordsMismatched: trace.recordsMismatched }
      : v === false ? { state: 'not_observed_in_window', basis: 'nothing on the finding\'s path is in the trace', windowDays, recordCount: trace.recordCount, meaning: 'absence of observation is not evidence that the code is unreachable or safe' }
      : { state: 'unknown', basis: 'the trace cannot say (the file appears but no line on the path matches, or there is no trace)', windowDays, recordCount: trace.recordCount };
    if (v === true) observed++;
    else if (v === false) {
      dead++;
      const next = demoteLadder[f.severity];
      // The cited evidence is TRAFFIC ON THE FINDING'S OWN ROUTE'S NEIGHBOURS: the finding is rooted in a route, the trace holds route hits, and this
      // route is not among them. A finding with no route, or a trace with no route hits, has nothing to cite and is left alone.
      const routePath = f._inRoute && f._inRoute.path;
      const routeEvidence = !!(routePath && trace.routesObserved.size > 0 && !trace.routesObserved.has(routePath));
      if (demote && next && routeEvidence && trace.recordCount >= minRecords) {
        f._runtimeDemoted = f.severity;
        f._runtimeDemotionEvidence = { policy: 'opt-in runtime demotion', basis: 'route-rooted finding whose route was not hit while other routes were', route: routePath, routesObserved: trace.routesObserved.size, recordCount: trace.recordCount, minRecords, windowDays, tracePath: trace.path };
        f.severity = next;
        demoted++;
      }
    } else unknown++;
  }
  return { observed, dead, unknown, demoted, trace: { recordCount: trace.recordCount, path: trace.path } };
}

export const _internals = { DEFAULT_TRACE_NAMES, DEFAULT_OBSERVATION_WINDOW_DAYS };
