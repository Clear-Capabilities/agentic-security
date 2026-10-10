// ingest.js: turn customer-supplied deployment files into a boundary graph
// (X-302), and invalidate it when a source file changes.
//
// What this module will and will not do:
//  - It reads only files the caller names, under one root, as bounded UTF-8
//    text. It follows no symlink out of the root, opens no socket, spawns no
//    process, reads no credential and calls no cloud API. The pure entry point
//    (`ingestDeploymentConfig`) takes text and cannot touch the file system at
//    all; the file entry point (`ingestDeploymentFiles`) is gated by the
//    `deployment-boundaries` feature so it is inert unless an operator turns
//    it on.
//  - It does not execute configuration. Terraform HCL, nginx style
//    configuration and other languages are reported as typed unsupported
//    syntax, with a hint where a supported equivalent exists, and contribute
//    no edges.
//  - An adapter that throws on hostile input is contained: the file becomes a
//    typed gap and the other files are still ingested.
//
// Every edge an adapter emits carries the file, the sha256 of the exact text
// parsed, the parser name and the parser version. `invalidateChangedSources`
// uses those digests to drop what a changed or removed file used to support,
// so a stale relation does not outlive its evidence.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { digestOfBytes } from '../../posture/assurance/identity.js';
import { featureStatus, limitValues, typed } from '../../posture/assurance/config.js';
import { readFileBounded } from '../../posture/assurance/bounded-io.js';
import { buildBoundaryGraph } from './boundary-graph.js';
import { parseKubernetes, KUBERNETES_PARSER, KUBERNETES_PARSER_VERSION } from './adapter-kubernetes.js';
import { parseCompose, COMPOSE_PARSER, COMPOSE_PARSER_VERSION } from './adapter-compose.js';
import { parseTerraformPlan, parseIamPolicy, TERRAFORM_PARSER, TERRAFORM_PARSER_VERSION, IAM_PARSER, IAM_PARSER_VERSION } from './adapter-cloud.js';

export const DEPLOYMENT_FEATURE = 'deployment-boundaries';
export const MAX_INGEST_FILES = 200;

const ADAPTERS = Object.freeze({
  kubernetes: { parse: parseKubernetes, parser: KUBERNETES_PARSER, version: KUBERNETES_PARSER_VERSION },
  compose: { parse: parseCompose, parser: COMPOSE_PARSER, version: COMPOSE_PARSER_VERSION },
  'terraform-plan': { parse: parseTerraformPlan, parser: TERRAFORM_PARSER, version: TERRAFORM_PARSER_VERSION },
  'iam-policy': { parse: parseIamPolicy, parser: IAM_PARSER, version: IAM_PARSER_VERSION },
});
export const ADAPTER_NAMES = Object.freeze(Object.keys(ADAPTERS));

const UNSUPPORTED_SYNTAX = {
  '.tf': 'Terraform HCL is not interpreted (it would need evaluation); supply the JSON from `terraform show -json <plan>`',
  '.hcl': 'HCL is not interpreted; supply a supported JSON or YAML form',
  '.tfvars': 'Terraform variable files carry values, not topology, and are not read',
  '.conf': 'proxy and server configuration syntax is not supported by any adapter',
  '.toml': 'TOML configuration is not supported by any adapter',
  '.xml': 'XML configuration is not supported by any adapter',
};

/** Decide which adapter reads a file, or why none does. Pure. */
export function detectFormat(file, text) {
  const ext = path.extname(file).toLowerCase();
  if (UNSUPPORTED_SYNTAX[ext]) return { adapter: null, code: 'unsupported-syntax', reason: UNSUPPORTED_SYNTAX[ext] };
  if (ext === '.json') {
    let doc;
    try { doc = JSON.parse(text); } catch (e) { return { adapter: null, code: 'malformed-input', reason: `not valid JSON (${String(e.message).split('\n')[0]})` }; }
    if (doc && typeof doc === 'object' && !Array.isArray(doc)) {
      if (typeof doc.format_version === 'string' && Array.isArray(doc.resource_changes)) return { adapter: 'terraform-plan' };
      if (Object.hasOwn(doc, 'Statement')) return { adapter: 'iam-policy' };
    }
    return { adapter: null, code: 'unsupported-format', reason: 'JSON that is neither a terraform plan nor an IAM policy document' };
  }
  if (ext === '.yaml' || ext === '.yml') {
    if (/^services:\s*(#.*)?$/m.test(text)) return { adapter: 'compose' };
    if (/^apiVersion:\s*\S/m.test(text) && /^kind:\s*\S/m.test(text)) return { adapter: 'kubernetes' };
    return { adapter: null, code: 'unsupported-format', reason: 'YAML that is neither a compose file nor a Kubernetes manifest' };
  }
  return { adapter: null, code: 'unsupported-format', reason: `no adapter reads '${ext || 'files without an extension'}'` };
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const REV = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/**
 * Ingest already-read files. Pure: no file system, no network, no clock.
 *
 * @param {object} p
 * @param {Array<{path: string, text: string}>} p.files
 * @param {string} p.environment  the deployment environment these files describe
 * @param {string|null} [p.repository]
 * @param {string|null} [p.revision]   exact commit these files were read at, when known
 * @param {Record<string,string>} [p.identities]  file path -> identity a policy document belongs to
 * @returns {{status: 'ok'|'invalid-input'|'invalid-graph', graph: object|null, files: object[], errors: object[]}}
 */
export function ingestDeploymentConfig({ files, environment, repository = null, revision = null, identities = {} } = {}) {
  if (typeof environment !== 'string' || !NAME.test(environment)) return { status: 'invalid-input', graph: null, files: [], errors: [{ code: 'BAD_TYPE', path: 'environment', message: 'environment must be a name such as prod or staging' }] };
  if (repository !== null && (typeof repository !== 'string' || !NAME.test(repository))) return { status: 'invalid-input', graph: null, files: [], errors: [{ code: 'BAD_TYPE', path: 'repository', message: 'repository must be null or a name' }] };
  if (revision !== null && !(typeof revision === 'string' && REV.test(revision))) return { status: 'invalid-input', graph: null, files: [], errors: [{ code: 'BAD_TYPE', path: 'revision', message: 'revision must be null or an exact 40/64 hex commit' }] };
  if (!Array.isArray(files)) return { status: 'invalid-input', graph: null, files: [], errors: [{ code: 'BAD_TYPE', path: 'files', message: 'files must be an array' }] };

  const nodes = [], edges = [], gaps = [], sources = [], report = [];
  const sorted = [...files].filter(f => f && typeof f.path === 'string' && typeof f.text === 'string').sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  if (files.length > MAX_INGEST_FILES) gaps.push({ code: 'limit-exceeded', subject: 'files', file: null, message: `${files.length} files supplied; only the first ${MAX_INGEST_FILES} are read` });
  for (const f of sorted.slice(0, MAX_INGEST_FILES)) {
    const bytes = Buffer.from(f.text, 'utf8');
    const digest = digestOfBytes(bytes);
    const fmt = detectFormat(f.path, f.text);
    if (!fmt.adapter) {
      gaps.push({ code: fmt.code, subject: f.path, file: f.path, message: fmt.reason });
      report.push({ file: f.path, adapter: null, status: fmt.code });
      continue;
    }
    const a = ADAPTERS[fmt.adapter];
    let out;
    try {
      out = a.parse(f.text, { file: f.path, digest, environment, repository, revision, identity: identities[f.path] ?? null });
    } catch (e) {
      gaps.push({ code: 'malformed-input', subject: f.path, file: f.path, message: `the ${fmt.adapter} adapter could not read this file (${String(e?.message ?? e).split('\n')[0]})` });
      report.push({ file: f.path, adapter: fmt.adapter, status: 'malformed-input' });
      continue;
    }
    nodes.push(...out.nodes); edges.push(...out.edges); gaps.push(...out.gaps);
    sources.push({ file: f.path, digest, parser: a.parser, parserVersion: a.version, bytes: bytes.length });
    report.push({ file: f.path, adapter: fmt.adapter, status: out.nodes.length || out.edges.length ? 'ingested' : (out.gaps[0]?.code ?? 'empty') });
  }
  const built = buildBoundaryGraph({ repository, revision, nodes, edges, gaps, sources });
  if (!built.ok) return { status: 'invalid-graph', graph: null, files: report, errors: built.errors };
  return { status: 'ok', graph: built.graph, files: report, errors: [] };
}

// ------------------------------------------------------------ file entry point

/** Resolve `rel` under `root`, refusing absolute paths, traversal and symlinks. Returns the real path or null. */
export function resolveUnderRoot(root, rel) {
  if (typeof rel !== 'string' || rel === '' || path.isAbsolute(rel) || rel.split(/[\\/]/).includes('..')) return null;
  let realRoot;
  try { realRoot = fs.realpathSync(root); } catch { return null; }
  const full = path.join(realRoot, rel);
  let st;
  try { st = fs.lstatSync(full); } catch { return null; }
  if (st.isSymbolicLink() || !st.isFile()) return null;
  let real;
  try { real = fs.realpathSync(full); } catch { return null; }
  return real === full && (real === realRoot || real.startsWith(realRoot + path.sep)) ? real : null;
}

/**
 * Read named files under `root` and ingest them. Gated by the
 * `deployment-boundaries` feature (off by default; the environment, an explicit
 * option or the operator's config turn it on). Returns a typed result and never
 * throws.
 *
 * @param {object} p
 * @param {object} p.config  resolveAssuranceConfig() result
 * @param {string} p.root
 * @param {string[]} p.paths  relative paths under root
 */
export function ingestDeploymentFiles({ config, root, paths, environment, repository = null, revision = null, identities = {} } = {}) {
  const gate = featureStatus(config, DEPLOYMENT_FEATURE);
  if (gate.status !== 'ok') return gate;
  if (!Array.isArray(paths)) return typed('blocked', 'invalid-config', 'paths must be an array', { feature: DEPLOYMENT_FEATURE });
  const maxBytes = limitValues(config).maxFileBytes;
  const files = [];
  const readGaps = [];
  for (const rel of paths.slice(0, MAX_INGEST_FILES)) {
    const real = resolveUnderRoot(root, rel);
    if (!real) { readGaps.push({ code: 'malformed-input', subject: String(rel), file: null, message: 'path is outside the root, is a symlink, or is not a regular file; it is not read' }); continue; }
    const r = readFileBounded(real, maxBytes);
    if (r.status !== 'ok') { readGaps.push({ code: r.code === 'limit-exceeded' ? 'limit-exceeded' : 'malformed-input', subject: String(rel), file: String(rel), message: r.reason }); continue; }
    files.push({ path: rel.split(path.sep).join('/'), text: r.text });
  }
  const out = ingestDeploymentConfig({ files, environment, repository, revision, identities });
  if (out.status !== 'ok') return typed('blocked', 'invalid-config', out.errors.map(e => e.message).join('; ') || 'invalid ingest input', { feature: DEPLOYMENT_FEATURE, ...out });
  if (readGaps.length) {
    // Re-build with the read gaps included so the graph tells the whole story.
    const again = buildBoundaryGraph({ ...out.graph, repository, revision, gaps: [...out.graph.gaps, ...readGaps] });
    if (again.ok) out.graph = again.graph;
  }
  return typed('ok', null, 'ingested', { feature: DEPLOYMENT_FEATURE, ...out });
}

// ------------------------------------------------------------ invalidation

/**
 * Drop what changed or removed source files used to support (X-302.AC03).
 *
 * `currentDigests` maps file -> the sha256 of the file as it is NOW (a missing
 * entry means the file is gone). Static edges sourced from a file whose digest
 * differs are removed; a node that only a stale file declared stops being
 * resolved; nodes nothing references any more are dropped; a gap records each
 * invalidated file. Runtime and inferred edges are untouched because they do
 * not claim a file as evidence. Returns a rebuilt, validated graph.
 */
export function invalidateChangedSources(graph, currentDigests) {
  const cur = currentDigests instanceof Map ? currentDigests : new Map(Object.entries(currentDigests ?? {}));
  const stale = new Map(); // file -> 'changed' | 'missing'
  for (const s of graph.sources) {
    const now = cur.get(s.file);
    if (now === undefined) stale.set(s.file, 'missing');
    else if (now !== s.digest) stale.set(s.file, 'changed');
  }
  if (stale.size === 0) return { ok: true, graph, invalidatedEdgeIds: [], staleFiles: [], errors: [] };

  const isStale = (ref) => ref && stale.has(ref.file) && cur.get(ref.file) !== ref.digest;
  const keptEdges = [], invalidated = [];
  for (const e of graph.edges) {
    if (e.source && isStale(e.source)) invalidated.push(e.id); else keptEdges.push(e);
  }
  const referenced = new Set();
  for (const e of keptEdges) { referenced.add(e.from); referenced.add(e.to); }
  const nodes = [];
  for (const n of graph.nodes) {
    const declaredBy = n.declaredBy.filter(d => !isStale(d));
    const lostDeclaration = declaredBy.length < n.declaredBy.length;
    if (declaredBy.length === 0 && !referenced.has(n.id)) continue; // nothing supports it any more
    if (lostDeclaration && declaredBy.length === 0) nodes.push({ ...n, declaredBy, resolved: false, unresolvedReason: 'the file that declared it changed or was removed', repository: null });
    else nodes.push({ ...n, declaredBy });
  }
  const gaps = [...graph.gaps];
  for (const [file, why] of [...stale].sort()) {
    gaps.push({ code: why === 'missing' ? 'source-missing' : 'source-changed', subject: file, file, message: `${file} ${why === 'missing' ? 'is no longer present' : 'has changed since it was ingested'}; the relations it supported were dropped and must be re-ingested` });
  }
  const sources = graph.sources.filter(s => !stale.has(s.file));
  const built = buildBoundaryGraph({ repository: graph.repository, revision: graph.revision, nodes, edges: keptEdges, gaps, sources });
  if (!built.ok) return { ok: false, graph: null, invalidatedEdgeIds: invalidated, staleFiles: [...stale.keys()].sort(), errors: built.errors };
  return { ok: true, graph: built.graph, invalidatedEdgeIds: invalidated.sort(), staleFiles: [...stale.keys()].sort(), errors: [] };
}
