// One measured scan of one directory. Runs inside a child process so peak RSS
// is attributable to the unit (process.resourceUsage().maxRSS is a process-wide
// high-water mark and never decreases).
//
// Deep analysis and the lineage graph are forced on for every unit, the same
// way bench/layer-recall forces deep mode: the point is to measure what the
// graph and taint layers can do, not what the default tier chose to run.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { disableStateWrites } from '../../_lib/tree-integrity.mjs';
import { runScan } from '../../../scanner/src/runScan.js';
import { completionOfGraph } from '../../../scanner/src/lineage/completion.js';

export function compactGraph(scan, prefix) {
  const g = scan.lineageGraph;
  if (!g) return null;
  const nodeById = new Map(g.nodes.map((n) => [n.id, n]));
  const deById = new Map(g.dataElements.map((d) => [d.id, d]));
  const norm = (f) => (prefix ? path.posix.join(prefix, f) : f);
  const flows = g.flows.map((f) => {
    const s = nodeById.get(f.source);
    const k = nodeById.get(f.sink);
    const des = (f.dataElementIds || []).map((id) => deById.get(id)).filter(Boolean);
    return {
      fields: des.map((d) => d.name),
      files: [...new Set(des.flatMap((d) => (d.sourceLocations || []).map((l) => norm(l.file))))].sort(),
      sourceKind: s ? s.subtype : null,
      sinkKind: k ? k.kind : null,
      sinkSub: k ? k.subtype : null,
    };
  });
  const cov = g.coverage || {};
  const env = completionOfGraph(g);
  return {
    nodes: g.nodes.length,
    edges: g.edges.length,
    flowCount: g.flows.length,
    completion: { status: env.status, queryExhausted: env.queryExhausted, modelCoverage: env.modelCoverage, reasons: env.reasons || [] },
    callStatementSites: cov.sinks ? cov.sinks.callStatementSites : null,
    connectedSinkSites: cov.sinks ? cov.sinks.connected : null,
    truncatedQueries: cov.paths ? cov.paths.truncatedQueries : null,
    pathsEnumerated: cov.paths ? cov.paths.enumerated : null,
    flows,
  };
}

export function compactFindings(scan, rootDir, prefix) {
  const out = [];
  for (const f of scan.findings) {
    if (f.severity === 'info') continue;
    let file = f.file || '';
    if (path.isAbsolute(file)) file = path.relative(rootDir, file);
    file = file.split(path.sep).join('/');
    out.push({
      file: prefix ? path.posix.join(prefix, file) : file,
      line: Number.isInteger(f.line) ? f.line : null,
      cwe: f.cwe || null,
      parser: f.parser || null,
      severity: f.severity,
    });
  }
  return out;
}

/** spec: { id, dir, prefix, stateWrites?: boolean, env?: {} } */
export async function runUnit(spec) {
  if (!spec.stateWrites) await disableStateWrites();
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  process.env.AGENTIC_SECURITY_LINEAGE_DEEP = '1';
  for (const [k, v] of Object.entries(spec.env || {})) process.env[k] = v;
  const t0 = process.hrtime.bigint();
  let scan;
  let error = null;
  try {
    ({ scan } = await runScan(spec.dir));
  } catch (e) {
    error = String((e && e.message) || e);
  }
  const ms = Number((process.hrtime.bigint() - t0) / 1000000n);
  const base = { id: spec.id, ms, peakRssMb: Math.round(process.resourceUsage().maxRSS / 1024) };
  if (error || !scan) return { ...base, status: 'error', error };
  return {
    ...base,
    status: 'ok',
    files: scan.filesScanned,
    lineage: scan.lineageStatus ? { enabled: !!scan.lineageStatus.enabled, failure: scan.lineageStatus.failure || null } : null,
    findings: compactFindings(scan, spec.dir, spec.prefix),
    graph: compactGraph(scan, spec.prefix),
  };
}

export function listFiles(dir) {
  const out = [];
  const walk = (d) => {
    let es;
    try { es = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of es) {
      if (e.name === '.git' || e.name === 'node_modules' || e.name === '.agentic-security') continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p); else out.push(p);
    }
  };
  walk(dir);
  return out.sort();
}
