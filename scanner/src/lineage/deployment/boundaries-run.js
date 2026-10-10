// boundaries-run.js: the operator entry point that builds a boundary context for scanned findings (X-308 wiring).
//
// Nothing in the default scan builds a boundary context. This is the one place that does, and it runs only when an operator
// asks for it (`agentic-security boundaries`) AND the `deployment-boundaries` feature is on (off by default). Rules it keeps:
//   - Local files only. It reads the directory it is pointed at, bounded, with no symlink followed, and optionally one scan
//     result file. It opens no socket, spawns no process, reads no credential and executes no configuration.
//   - Read-only with respect to the project. The only write is the report file the operator names with `out`, refused when the
//     target is a symlink.
//   - Off means off. With the feature off nothing is read: the result is a typed `disabled` and no file is opened.
//   - Everything that was not established is carried through: ingest gaps, unsupported syntax, files not read, trace sampling
//     and staleness, findings with no service binding. A result never says safe.
//
// Reserved names inside the directory: `service-bindings.json` (finding path prefix to service), `identities.json` (policy file
// to the identity it belongs to) and `traces.jsonl` / `traces.ndjson` (sanitized runtime trace lines). They are inputs, never
// ingested as configuration.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { featureStatus, limitValues, typed } from '../../posture/assurance/config.js';
import { readFileBounded } from '../../posture/assurance/bounded-io.js';
import { STATE_DIR_NAME } from '../../posture/state-dir.js';
import { ingestDeploymentFiles, MAX_INGEST_FILES, DEPLOYMENT_FEATURE } from './ingest.js';
import { importTraceLines, correlateObservations, applyCorrelation } from './trace-correlation.js';
import { attachBoundaryContext, boundaryFields, boundaryCoverage } from './projection.js';

export const BOUNDARIES_REPORT_SCHEMA = 'agentic-security/boundaries-report';
export const BOUNDARIES_REPORT_VERSION = '1.0.0';
export const BINDINGS_FILE = 'service-bindings.json';
export const IDENTITIES_FILE = 'identities.json';
export const TRACE_FILES = Object.freeze(['traces.jsonl', 'traces.ndjson']);
export const MAX_FINDINGS = 5000;

const RESERVED = new Set([BINDINGS_FILE, IDENTITIES_FILE, ...TRACE_FILES]);
const CONFIG_EXTENSIONS = new Set(['.yaml', '.yml', '.json', '.tf', '.hcl', '.tfvars', '.conf', '.toml', '.xml']);
const SKIP_DIRS = new Set(['.git', 'node_modules', STATE_DIR_NAME]);
const MAX_WALK_ENTRIES = 5000;

/** List candidate configuration files under `dir`, relative and sorted. Symlinks are never followed or listed. */
export function listConfigFiles(dir) {
  const found = [];
  const skipped = { symlinks: 0, overLimit: false };
  let seen = 0;
  const walk = (d, rel) => {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (++seen > MAX_WALK_ENTRIES) { skipped.overLimit = true; return; }
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { skipped.symlinks += 1; continue; }
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(path.join(d, e.name), r); continue; }
      if (!e.isFile()) continue;
      if (!rel && RESERVED.has(e.name)) continue;
      if (CONFIG_EXTENSIONS.has(path.extname(e.name).toLowerCase())) found.push(r);
    }
  };
  walk(dir, '');
  return { files: found.sort(), skipped };
}

function readJsonFile(file, maxBytes, what) {
  const r = readFileBounded(file, maxBytes);
  if (r.status !== 'ok') return { ok: false, reason: `${what}: ${r.reason}` };
  try { return { ok: true, value: JSON.parse(r.text) }; } catch (e) { return { ok: false, reason: `${what} is not valid JSON (${String(e.message).split('\n')[0]})` }; }
}

/**
 * Read the findings of a scan result file. A sibling `.sig` that exists must verify; a result with no signature is read and
 * labelled unverified.
 */
export function readScanFindings(file, { maxBytes, verify } = {}) {
  const r = readFileBounded(file, maxBytes);
  if (r.status !== 'ok') return { ok: false, reason: `scan result: ${r.reason}`, findings: [], integrity: 'unreadable' };
  let integrity = 'unsigned';
  if (typeof verify === 'function') {
    const v = verify(r.text, `${file}.sig`);
    if (v === false) return { ok: false, reason: 'the scan result has a signature that does not verify; it is not used', findings: [], integrity: 'signature-mismatch' };
    if (v === true) integrity = 'verified';
  }
  let doc;
  try { doc = JSON.parse(r.text); } catch (e) { return { ok: false, reason: `scan result is not valid JSON (${String(e.message).split('\n')[0]})`, findings: [], integrity }; }
  const list = Array.isArray(doc) ? doc : doc?.findings;
  if (!Array.isArray(list)) return { ok: false, reason: 'scan result has no findings array', findings: [], integrity };
  return { ok: true, reason: null, findings: list.filter((f) => f && typeof f === 'object' && !Array.isArray(f)), integrity };
}

/**
 * Build a boundary graph from a directory of deployment sources and attach a context to each finding.
 *
 * @param {object} o
 * @param {object} o.config        resolveAssuranceConfig() result (the feature gate)
 * @param {string} o.from          directory with configuration, optional traces, bindings and identities
 * @param {string} [o.environment] default 'prod'
 * @param {string|null} [o.repository]
 * @param {string|null} [o.revision]  exact 40/64 hex commit the files were read at
 * @param {string|null} [o.findingsFile]  a scan result (last-scan.json)
 * @param {object[]|null} [o.findings]     findings already in memory (an evaluation passes these instead of a file)
 * @param {Function} [o.verifySignature]  (body, sigFile) => true | false | null
 * @param {string} [o.now]         ISO time used to judge trace staleness; defaults to the current time
 * @returns {object} typed result; `status` is ok | disabled | blocked | unsupported | error. Never throws.
 */
export function runBoundaries({ config, from, environment = 'prod', repository = null, revision = null, findingsFile = null, findings: suppliedFindings = null, verifySignature, now } = {}) {
  const gate = featureStatus(config, DEPLOYMENT_FEATURE);
  if (gate.status !== 'ok') return { ...gate, report: null };
  const limits = limitValues(config);
  const fail = (code, reason) => typed('error', code, reason, { feature: DEPLOYMENT_FEATURE, report: null });

  if (typeof from !== 'string' || !from) return fail('invalid-input', '--from names the directory with deployment configuration');
  let root;
  try { root = fs.realpathSync(from); if (!fs.statSync(root).isDirectory()) throw new Error('not a directory'); } catch { return fail('invalid-input', `--from '${from}' is not a readable directory`); }

  const clock = now ?? new Date().toISOString();
  const notes = [];
  const listing = listConfigFiles(root);
  if (listing.skipped.symlinks) notes.push(`${listing.skipped.symlinks} symbolic link(s) were not followed`);
  if (listing.skipped.overLimit) notes.push(`the directory walk stopped at ${MAX_WALK_ENTRIES} entries; later files were not listed`);
  let paths = listing.files;
  if (paths.length > MAX_INGEST_FILES) { notes.push(`${paths.length - MAX_INGEST_FILES} configuration file(s) beyond the ${MAX_INGEST_FILES} file limit were not read`); paths = paths.slice(0, MAX_INGEST_FILES); }
  if (!paths.length) return fail('invalid-input', `no configuration files (${[...CONFIG_EXTENSIONS].join(', ')}) were found under '${from}'`);

  let identities = {};
  const idFile = path.join(root, IDENTITIES_FILE);
  if (fs.existsSync(idFile)) {
    const j = readJsonFile(idFile, limits.maxFileBytes, IDENTITIES_FILE);
    if (!j.ok) return fail('invalid-input', j.reason);
    if (!j.value || typeof j.value !== 'object' || Array.isArray(j.value)) return fail('invalid-input', `${IDENTITIES_FILE} must be an object mapping a file path to an identity`);
    identities = Object.fromEntries(Object.entries(j.value).filter(([, v]) => typeof v === 'string'));
  }
  let bindings = [];
  const bindFile = path.join(root, BINDINGS_FILE);
  if (fs.existsSync(bindFile)) {
    const j = readJsonFile(bindFile, limits.maxFileBytes, BINDINGS_FILE);
    if (!j.ok) return fail('invalid-input', j.reason);
    if (!Array.isArray(j.value)) return fail('invalid-input', `${BINDINGS_FILE} must be an array of { pathPrefix, service } objects`);
    bindings = j.value;
  } else notes.push(`no ${BINDINGS_FILE}: no finding can be tied to a service, so every finding reports exposure as not assessed`);

  const ingested = ingestDeploymentFiles({ config, root, paths, environment, repository, revision, identities });
  if (ingested.status !== 'ok') return fail(ingested.code ?? 'invalid-config', ingested.reason ?? 'ingest failed');
  let graph = ingested.graph;

  const observation = { supplied: false, accepted: 0, rejected: 0, status: 'not-supplied', coverage: null };
  const traceName = TRACE_FILES.find((n) => fs.existsSync(path.join(root, n)));
  if (traceName) {
    observation.supplied = true;
    const t = readFileBounded(path.join(root, traceName), limits.maxFileBytes);
    if (t.status !== 'ok') { observation.status = 'unreadable'; notes.push(`${traceName} was not read: ${t.reason}`); }
    else {
      const imp = importTraceLines(t.text, { environment });
      if (imp.status !== 'ok') { observation.status = imp.status; notes.push(`${traceName} was not imported: ${imp.reason}`); }
      else {
        observation.accepted = imp.set.stats.accepted; observation.rejected = imp.set.stats.rejected;
        const corr = correlateObservations(graph, imp.set, { now: clock });
        if (corr.status !== 'ok') { observation.status = corr.status; notes.push(`traces were not correlated: ${corr.reason}`); }
        else {
          const applied = applyCorrelation(graph, corr);
          if (applied.ok) { graph = applied.graph; observation.status = 'correlated'; observation.coverage = corr.coverage; }
          else { observation.status = 'invalid-graph'; notes.push('correlated traces produced an invalid graph and were not applied'); }
        }
      }
    }
  }

  let findings = [];
  let integrity = 'not-supplied';
  if (Array.isArray(suppliedFindings)) {
    integrity = 'in-memory';
    findings = suppliedFindings.filter((f) => f && typeof f === 'object' && !Array.isArray(f));
    if (findings.length > MAX_FINDINGS) { notes.push(`${findings.length - MAX_FINDINGS} finding(s) beyond the ${MAX_FINDINGS} limit were not given a context`); findings = findings.slice(0, MAX_FINDINGS); }
  } else if (findingsFile) {
    const s = readScanFindings(findingsFile, { maxBytes: limits.maxFileBytes, verify: verifySignature });
    if (!s.ok) return fail('invalid-input', s.reason);
    integrity = s.integrity;
    findings = s.findings;
    if (findings.length > MAX_FINDINGS) { notes.push(`${findings.length - MAX_FINDINGS} finding(s) beyond the ${MAX_FINDINGS} limit were not given a context`); findings = findings.slice(0, MAX_FINDINGS); }
    if (integrity === 'unsigned') notes.push('the scan result carries no signature, so its integrity was not verified');
  }

  const attached = attachBoundaryContext({ config, findings, graph, bindings, now: clock });
  if (attached.status !== 'ok') return { ...attached, report: null };
  const contexts = attached.findings.map((f) => f.boundaryContext).filter(Boolean);
  const rows = attached.findings.map((f) => ({
    id: f.id ?? null, stableId: f.stableId ?? null, file: f.file ?? null, line: Number.isInteger(f.line) ? f.line : null, vuln: f.vuln ?? null,
    ...(f.boundaryContext ? boundaryFields(f.boundaryContext) : { boundaryContext: null, boundaryView: null, notAnalyzed: 'the context could not be computed for this finding' }),
  }));
  const report = {
    schema: BOUNDARIES_REPORT_SCHEMA, schemaVersion: BOUNDARIES_REPORT_VERSION,
    feature: DEPLOYMENT_FEATURE, environment, repository, revision,
    graph: {
      digest: graph.digest, nodeCount: graph.nodes.length, edgeCount: graph.edges.length, gapCount: graph.gaps.length,
      unresolvedNodeCount: graph.nodes.filter((n) => !n.resolved).length,
      gaps: graph.gaps.map((g) => ({ code: g.code, subject: g.subject, file: g.file ?? null, message: g.message })),
      files: ingested.files, sourceCount: graph.sources.length,
    },
    observation,
    scanResult: { supplied: Boolean(findingsFile) || integrity === 'in-memory', integrity, findingCount: findings.length },
    coverage: boundaryCoverage(contexts),
    findings: rows,
    errors: attached.errors,
    notes,
    statement: 'Configured relationships were not exercised and runtime traffic coverage is not established; a path that is not listed has not been shown to be absent.',
  };
  return typed('ok', null, 'boundary contexts built from local files', { feature: DEPLOYMENT_FEATURE, report, graph });
}

/** Text form of a report. Reuses each context's own projected text; adds nothing about safety. */
export function renderBoundariesText(report) {
  const L = [];
  L.push(`Deployment boundaries (environment ${report.environment}${report.repository ? `, repository ${report.repository}` : ''})`);
  L.push(`  Graph: ${report.graph.nodeCount} node(s), ${report.graph.edgeCount} edge(s), ${report.graph.gapCount} gap(s), ${report.graph.unresolvedNodeCount} unresolved; digest ${report.graph.digest.slice(0, 12)}`);
  for (const f of report.graph.files) L.push(`    ${f.file}: ${f.adapter ?? 'not read'} (${f.status})`);
  for (const g of report.graph.gaps.slice(0, 20)) L.push(`    gap ${g.code}: ${g.subject}`);
  if (report.graph.gaps.length > 20) L.push(`    and ${report.graph.gaps.length - 20} more gap(s)`);
  L.push(`  Traces: ${report.observation.status}${report.observation.supplied ? ` (${report.observation.accepted} accepted, ${report.observation.rejected} rejected)` : ''}`);
  L.push(`  Scan result: ${report.scanResult.supplied ? `${report.scanResult.findingCount} finding(s), integrity ${report.scanResult.integrity}` : 'not supplied, so no finding was analyzed'}`);
  for (const f of report.findings) {
    L.push(`  ${f.id ?? f.stableId ?? 'finding'} ${f.file ?? ''}${f.line ? `:${f.line}` : ''} ${f.vuln ?? ''}`.trimEnd());
    for (const t of f.boundaryView?.text ?? [f.notAnalyzed ?? 'not analyzed']) L.push(`    ${t}`);
  }
  for (const line of report.coverage.lines) L.push(line);
  for (const n of report.notes) L.push(`  Note: ${n}`);
  L.push(`  ${report.statement}`);
  return `${L.join('\n')}\n`;
}
