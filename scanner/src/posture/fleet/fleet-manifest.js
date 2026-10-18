// The fleet manifest (PRD 4 "Fleet Manifest"). `fleet.yaml`:
//
//   organization: example
//   repositories:
//     - id: frontend
//       path: ../frontend
//   workers: 4
//   perRepoTimeout: 20m
//
// Parsing reuses util/yaml.js (the one YAML entry point in this codebase). Validation is closed-world: an unknown
// top-level key, a duplicate repository id, or a path that does not resolve to a real directory all refuse the
// whole manifest rather than silently skipping one repo.
import fs from 'node:fs';
import path from 'node:path';
import { load as loadYaml } from '../../util/yaml.js';

const FLEET_MANIFEST_SCHEMA_KEYS = Object.freeze(['organization', 'repositories', 'workers', 'perRepoTimeout', 'retries', 'resources']);
const REPO_KEYS = Object.freeze(['id', 'path', 'required', 'kind', 'internetFacing', 'environment', 'dataClasses', 'trustZone', 'calls', 'produces', 'consumes', 'reads', 'writes', 'providers', 'aliases']);
const RESOURCE_KEYS = Object.freeze(['id', 'kind', 'dataClasses', 'trustZone', 'internetFacing', 'environment', 'aliases']);
const REPO_KINDS = Object.freeze(['service', 'library', 'frontend', 'worker', 'gateway']);
const RESOURCE_KINDS = Object.freeze(['queue', 'database', 'external-provider', 'gateway']);
export const ENVIRONMENTS = Object.freeze(['production', 'staging', 'development']);
const NAME_RE = /^[a-z][a-z0-9-]{0,63}$/;
const DURATION_RE = /^(\d+)(s|m|h)$/;

export function parseDuration(s, fallbackMs) {
  if (typeof s === 'number' && s > 0) return s * 1000;
  const m = DURATION_RE.exec(String(s ?? ''));
  if (!m) return fallbackMs;
  const n = Number(m[1]);
  return m[2] === 's' ? n * 1000 : m[2] === 'm' ? n * 60000 : n * 3600000;
}

/** Validate a parsed manifest object against the manifest's own base directory (for path resolution). */
export function validateFleetManifest(doc, { baseDir = '.' } = {}) {
  const errors = [];
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { ok: false, errors: ['manifest must be a YAML mapping'] };
  for (const k of Object.keys(doc)) if (!FLEET_MANIFEST_SCHEMA_KEYS.includes(k)) errors.push(`unknown top-level key: ${k}`);
  if (typeof doc.organization !== 'string' || !doc.organization) errors.push('organization is required and must be a string');
  if (!Array.isArray(doc.repositories) || doc.repositories.length === 0) errors.push('repositories must be a non-empty array');
  const seen = new Set();
  const repos = [];
  const idList = (v, where) => { if (v === undefined) return []; if (!Array.isArray(v) || !v.every((x) => typeof x === 'string' && NAME_RE.test(x))) { errors.push(`${where} must be a list of ids`); return []; } return v; };
  const aliasList = (v, where) => { if (v === undefined) return []; if (!Array.isArray(v) || v.length > 16 || !v.every((x) => typeof x === 'string' && /^[a-z0-9][a-z0-9._-]{0,99}$/.test(x))) { errors.push(`${where} must be a list of up to 16 lower-case names or hostnames`); return []; } return v; };
  const classes = (v, where) => { if (v === undefined) return []; if (!Array.isArray(v) || !v.every((x) => typeof x === 'string' && /^[a-z][a-z0-9-]{0,30}$/.test(x))) { errors.push(`${where} must be a list of data class names such as pci or pii`); return []; } return v; };
  for (const [i, r] of (Array.isArray(doc.repositories) ? doc.repositories : []).entries()) {
    if (!r || typeof r !== 'object') { errors.push(`repositories[${i}] must be a mapping`); continue; }
    for (const k of Object.keys(r)) if (!REPO_KEYS.includes(k)) errors.push(`repositories[${i}]: unknown key ${k}`);
    if (typeof r.id !== 'string' || !NAME_RE.test(r.id)) { errors.push(`repositories[${i}].id must be a lowercase kebab-case string`); continue; }
    if (seen.has(r.id)) { errors.push(`duplicate repository id: ${r.id}`); continue; }
    seen.add(r.id);
    if (typeof r.path !== 'string' || !r.path) { errors.push(`repositories[${i}].path is required`); continue; }
    const abs = path.resolve(baseDir, r.path);
    let isDir = false;
    try { isDir = fs.statSync(abs).isDirectory(); } catch { /* reported below */ }
    if (!isDir) errors.push(`repositories[${i}].path does not resolve to a directory: ${r.path}`);
    if (r.kind !== undefined && !REPO_KINDS.includes(r.kind)) errors.push(`repositories[${i}].kind must be one of ${REPO_KINDS.join(', ')}`);
    if (r.environment !== undefined && !ENVIRONMENTS.includes(r.environment)) errors.push(`repositories[${i}].environment must be one of ${ENVIRONMENTS.join(', ')}`);
    for (const k of ['required', 'internetFacing']) if (r[k] !== undefined && typeof r[k] !== 'boolean') errors.push(`repositories[${i}].${k} must be true or false`);
    if (r.trustZone !== undefined && !(typeof r.trustZone === 'string' && NAME_RE.test(r.trustZone))) errors.push(`repositories[${i}].trustZone must be a name`);
    repos.push({
      id: r.id, path: abs, required: r.required !== false, kind: r.kind ?? null, internetFacing: r.internetFacing === true, environment: r.environment ?? null,
      dataClasses: classes(r.dataClasses, `repositories[${i}].dataClasses`), trustZone: r.trustZone ?? null,
      aliases: aliasList(r.aliases, `repositories[${i}].aliases`), calls: idList(r.calls, `repositories[${i}].calls`), produces: idList(r.produces, `repositories[${i}].produces`), consumes: idList(r.consumes, `repositories[${i}].consumes`),
      reads: idList(r.reads, `repositories[${i}].reads`), writes: idList(r.writes, `repositories[${i}].writes`), providers: idList(r.providers, `repositories[${i}].providers`),
    });
  }
  const resources = [];
  const resIds = new Set();
  if (doc.resources !== undefined && !Array.isArray(doc.resources)) errors.push('resources must be a list');
  for (const [i, r] of (Array.isArray(doc.resources) ? doc.resources : []).entries()) {
    if (!r || typeof r !== 'object') { errors.push(`resources[${i}] must be a mapping`); continue; }
    for (const k of Object.keys(r)) if (!RESOURCE_KEYS.includes(k)) errors.push(`resources[${i}]: unknown key ${k}`);
    if (typeof r.id !== 'string' || !NAME_RE.test(r.id)) { errors.push(`resources[${i}].id must be a lowercase kebab-case string`); continue; }
    if (seen.has(r.id) || resIds.has(r.id)) { errors.push(`resource id ${r.id} collides with another repository or resource`); continue; }
    resIds.add(r.id);
    if (!RESOURCE_KINDS.includes(r.kind)) errors.push(`resources[${i}].kind must be one of ${RESOURCE_KINDS.join(', ')}`);
    if (r.environment !== undefined && !ENVIRONMENTS.includes(r.environment)) errors.push(`resources[${i}].environment must be one of ${ENVIRONMENTS.join(', ')}`);
    if (r.internetFacing !== undefined && typeof r.internetFacing !== 'boolean') errors.push(`resources[${i}].internetFacing must be true or false`);
    resources.push({ id: r.id, kind: r.kind, aliases: aliasList(r.aliases, `resources[${i}].aliases`), dataClasses: classes(r.dataClasses, `resources[${i}].dataClasses`), trustZone: r.trustZone ?? null, internetFacing: r.internetFacing === true, environment: r.environment ?? null });
  }
  const known = new Set([...seen, ...resIds]);
  for (const r of repos) {
    for (const [field, kinds] of [['calls', ['repo', 'gateway']], ['produces', ['queue']], ['consumes', ['queue']], ['reads', ['database']], ['writes', ['database']], ['providers', ['external-provider']]]) {
      for (const target of r[field]) {
        if (!known.has(target)) { errors.push(`repository ${r.id}: ${field} names ${target}, which is neither a repository nor a resource`); continue; }
        const res = resources.find((x) => x.id === target);
        const ok = res ? kinds.includes(res.kind) : kinds.includes('repo');
        if (!ok) errors.push(`repository ${r.id}: ${field} cannot point at ${target}${res ? ` (a ${res.kind})` : ' (a repository)'}`);
      }
    }
  }
  if (doc.workers != null && !(Number.isInteger(doc.workers) && doc.workers >= 1 && doc.workers <= 32)) errors.push('workers must be an integer in 1..32');
  if (doc.retries != null && !(Number.isInteger(doc.retries) && doc.retries >= 0 && doc.retries <= 5)) errors.push('retries must be an integer in 0..5');
  if (doc.perRepoTimeout != null && parseDuration(doc.perRepoTimeout, null) == null) errors.push(`perRepoTimeout is not a valid duration: ${doc.perRepoTimeout}`);
  if (errors.length) return { ok: false, errors };
  return {
    ok: true, errors: [],
    manifest: {
      organization: doc.organization, repositories: repos, resources,
      workers: doc.workers ?? 4, retries: doc.retries ?? 1, perRepoTimeoutMs: parseDuration(doc.perRepoTimeout, 20 * 60000),
    },
  };
}

export function loadFleetManifest(filePath) {
  let text;
  try { text = fs.readFileSync(filePath, 'utf8'); } catch (e) { return { ok: false, errors: [`cannot read ${filePath}: ${e.message}`] }; }
  let doc;
  try { doc = loadYaml(text); } catch (e) { return { ok: false, errors: [`invalid YAML: ${e.message}`] }; }
  return validateFleetManifest(doc, { baseDir: path.dirname(path.resolve(filePath)) });
}

export function starterManifestYaml(organization = 'example') {
  return `organization: ${organization}
repositories:
  - id: example-repo
    path: .
workers: 4
perRepoTimeout: 20m
`;
}
