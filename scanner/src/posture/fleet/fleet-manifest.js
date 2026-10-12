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

const FLEET_MANIFEST_SCHEMA_KEYS = Object.freeze(['organization', 'repositories', 'workers', 'perRepoTimeout']);
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
  for (const [i, r] of (Array.isArray(doc.repositories) ? doc.repositories : []).entries()) {
    if (!r || typeof r !== 'object') { errors.push(`repositories[${i}] must be a mapping`); continue; }
    if (typeof r.id !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(r.id)) { errors.push(`repositories[${i}].id must be a lowercase kebab-case string`); continue; }
    if (seen.has(r.id)) { errors.push(`duplicate repository id: ${r.id}`); continue; }
    seen.add(r.id);
    if (typeof r.path !== 'string' || !r.path) { errors.push(`repositories[${i}].path is required`); continue; }
    const abs = path.resolve(baseDir, r.path);
    let isDir = false;
    try { isDir = fs.statSync(abs).isDirectory(); } catch { /* reported below */ }
    if (!isDir) errors.push(`repositories[${i}].path does not resolve to a directory: ${r.path}`);
    repos.push({ id: r.id, path: abs });
  }
  if (doc.workers != null && !(Number.isInteger(doc.workers) && doc.workers >= 1 && doc.workers <= 32)) errors.push('workers must be an integer in 1..32');
  if (doc.perRepoTimeout != null && parseDuration(doc.perRepoTimeout, null) == null) errors.push(`perRepoTimeout is not a valid duration: ${doc.perRepoTimeout}`);
  if (errors.length) return { ok: false, errors };
  return {
    ok: true, errors: [],
    manifest: {
      organization: doc.organization, repositories: repos,
      workers: doc.workers ?? 4, perRepoTimeoutMs: parseDuration(doc.perRepoTimeout, 20 * 60000),
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
