// Build, freeze, load and diff the requirements manifest. The acceptance hash
// covers everything that defines "done" (IDs, weights, dependencies, criteria
// text, suite), so editing any of it without producing a new manifest version
// is detected and fails closed.
import { readFileSync, mkdirSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { sha256, canonicalJson, atomicWriteJson, readJson, nowIso } from './util.mjs';
import { parsePrd, readPrd, categoryOf, ImportError, findCycles } from './prd-import.mjs';
import { validate } from './schema.mjs';
import { layout } from './state.mjs';
import { validateProfile } from './profile.mjs';

const SCHEMA_DIR = new URL('../schemas/', import.meta.url);
export const loadSchema = (name) => JSON.parse(readFileSync(new URL(name, SCHEMA_DIR), 'utf8'));

export function acceptanceCore(r) {
  return { id: r.id, weight: r.weight, dependencies: [...r.dependencies].sort(), suite: r.suite, criteria: r.criteria.map((c) => ({ id: c.id, text: c.text })) };
}
export function computeAcceptanceHash(requirements) {
  return sha256(canonicalJson(requirements.map(acceptanceCore).sort((a, b) => (a.id < b.id ? -1 : 1))));
}

export function buildRequirements({ parsed, profile, repoRoot }) {
  const problems = [];
  const extra = (profile.extraRequirements || []).map((e) => ({ ...e, extra: true }));
  const all = [...parsed.requirements, ...extra];
  const seen = new Set();
  for (const r of all) { if (seen.has(r.id)) problems.push(`duplicate requirement ID ${r.id} (profile.extraRequirements collides with the PRD)`); seen.add(r.id); }
  const ids = new Set(all.map((r) => r.id));
  for (const r of extra) {
    if (!Array.isArray(r.criteria) || !r.criteria.length) problems.push(`${r.id}: extra requirement needs criteria`);
    for (const d of r.dependencies || []) if (!ids.has(d)) problems.push(`${r.id}: depends on unknown ID ${d}`);
  }
  problems.push(...findCycles(all));
  const out = [];
  for (const r of all) {
    const suite = profile.suites[r.suite];
    if (!suite) { problems.push(`${r.id}: suite "${r.suite}" has no command mapping in the execution profile (unknown mandatory command)`); continue; }
    const prefix = r.id.split('-')[0];
    const watch = profile.watch[prefix];
    if (!watch) { problems.push(`${r.id}: no watch globs for category ${prefix}`); continue; }
    out.push({
      id: r.id, title: r.title, category: categoryOf(r.id) || 'shared', weight: r.weight, required: true,
      dependencies: r.dependencies || [], suite: r.suite,
      description: Array.isArray(r.description) ? r.description.join(' ') : (r.description || ''),
      watch,
      criteria: r.criteria.map((c) => ({ id: c.id, text: c.text, assertionIds: [c.id] })),
      verification: {
        kind: suite.kind, cwd: suite.cwd, executable: suite.executable,
        args: suite.kind === 'node-test' ? ['--test', ...suite.files] : [],
        files: suite.files || [], expectedExitCode: 0, timeoutSeconds: suite.timeoutSeconds,
        ...(suite.requiresTools ? { requiresTools: suite.requiresTools } : {}),
      },
      ...(r.extra ? { addedAfterBaseline: true } : {}),
    });
  }
  if (problems.length) throw new ImportError(problems);
  void repoRoot;
  return out;
}

export function diffManifests(prev, next) {
  const pm = new Map(prev.requirements.map((r) => [r.id, r]));
  const nm = new Map(next.requirements.map((r) => [r.id, r]));
  const removed = [...pm.keys()].filter((id) => !nm.has(id));
  const added = [...nm.keys()].filter((id) => !pm.has(id));
  const changed = [];
  const lostCriteria = [];
  const weakened = [];
  for (const [id, n] of nm) {
    const p = pm.get(id);
    if (!p) continue;
    if (canonicalJson(acceptanceCore(p)) !== canonicalJson(acceptanceCore(n))) changed.push(id);
    const nc = new Set(n.criteria.map((c) => c.id));
    for (const c of p.criteria) if (!nc.has(c.id)) lostCriteria.push(c.id);
    if (n.weight < p.weight) weakened.push(`${id} weight ${p.weight}->${n.weight}`);
  }
  return {
    added, removed, changed, lostCriteria, weakened,
    denominator: {
      before: { requirements: prev.totals.requirements, criteria: prev.totals.criteria, weight: prev.totals.weight },
      after: { requirements: next.totals.requirements, criteria: next.totals.criteria, weight: next.totals.weight },
    },
  };
}

export function listManifestVersions(repoRoot) {
  const L = layout(repoRoot);
  try {
    return readdirSync(L.manifestDir).map((f) => /^requirements\.v(\d+)\.json$/.exec(f)).filter(Boolean).map((m) => +m[1]).sort((a, b) => a - b);
  } catch { return []; }
}
export function manifestPath(repoRoot, v) { return join(layout(repoRoot).manifestDir, `requirements.v${v}.json`); }

// Loads and integrity-checks the newest manifest. Never repairs.
export function loadManifest(repoRoot, version = null) {
  const versions = listManifestVersions(repoRoot);
  if (!versions.length) return { ok: false, error: 'no manifest: run `init` first' };
  const v = version ?? versions[versions.length - 1];
  const file = manifestPath(repoRoot, v);
  const m = readJson(file, null);
  if (!m) return { ok: false, error: `manifest v${v} unreadable or corrupt` };
  const errs = validate(loadSchema('requirements.schema.json'), m);
  if (errs.length) return { ok: false, error: `manifest v${v} fails schema validation: ${errs.slice(0, 5).join('; ')}` };
  const h = computeAcceptanceHash(m.requirements);
  if (h !== m.acceptanceHash) return { ok: false, error: `manifest v${v} acceptance hash mismatch (criteria, weights, dependencies or suites were edited after freezing)` };
  const t = {
    requirements: m.requirements.length,
    criteria: m.requirements.reduce((n, r) => n + r.criteria.length, 0),
    weight: m.requirements.reduce((n, r) => n + r.weight, 0),
  };
  if (t.requirements !== m.totals.requirements || t.criteria !== m.totals.criteria || t.weight !== m.totals.weight) {
    return { ok: false, error: `manifest v${v} totals disagree with its contents (a requirement or criterion was removed)` };
  }
  return { ok: true, manifest: m, version: v, file };
}

export function checkPrdFresh(repoRoot, manifest) {
  const p = resolve(repoRoot, manifest.prd.path);
  let cur;
  try { cur = readPrd(p).sha256; } catch (e) { return { ok: false, error: `PRD unreadable: ${e.code || e.message}` }; }
  return cur === manifest.prd.sha256 ? { ok: true } : { ok: false, error: `PRD changed since manifest v${manifest.manifestVersion} was frozen; run init to create a new manifest version` };
}

export function createManifest({ repoRoot, prdPath, profile, profileSha, checkout = {}, tools = {}, baselineGates = [], allowRemovals = false }) {
  const validateRepo = resolve(repoRoot);
  validateProfile(profile, validateRepo);
  const prd = readPrd(resolve(validateRepo, prdPath));
  const parsed = parsePrd(prd.text);
  const requirements = buildRequirements({ parsed, profile, repoRoot: validateRepo });
  const prevVersions = listManifestVersions(validateRepo);
  const prev = prevVersions.length ? loadManifest(validateRepo) : null;
  if (prev && !prev.ok) throw new ImportError([`existing manifest is invalid and will not be overwritten: ${prev.error}`]);
  const totals = {
    requirements: requirements.length,
    criteria: requirements.reduce((n, r) => n + r.criteria.length, 0),
    weight: requirements.reduce((n, r) => n + r.weight, 0),
  };
  const manifest = {
    manifestVersion: prev ? prev.version + 1 : 1,
    schemaVersion: 1,
    supersedes: prev ? prev.version : null,
    createdAt: nowIso(),
    prd: { path: prdPath, sha256: prd.sha256, declaredTotals: parsed.declared },
    acceptanceHash: computeAcceptanceHash(requirements),
    totals, checkout, tools, baselineGates,
    profile: { name: profile.name, sha256: profileSha, limits: profile.limits },
    requirements,
  };
  let diff = null;
  if (prev) {
    diff = diffManifests(prev.manifest, manifest);
    const bad = [];
    if (diff.removed.length) bad.push(`requirements removed: ${diff.removed.join(', ')}`);
    if (diff.lostCriteria.length) bad.push(`criteria lost: ${diff.lostCriteria.join(', ')}`);
    if (diff.weakened.length) bad.push(`weights reduced: ${diff.weakened.join(', ')}`);
    if (bad.length && !allowRemovals) throw new ImportError([`new manifest would shrink the frozen scope (${bad.join('; ')}); the denominator may only grow`]);
    manifest.changes = diff;
  }
  const errs = validate(loadSchema('requirements.schema.json'), manifest);
  if (errs.length) throw new ImportError(errs.map((e) => `schema: ${e}`));
  return { manifest, diff, unchanged: !!prev && !diff.added.length && !diff.changed.length && prev.manifest.prd.sha256 === manifest.prd.sha256 && prev.manifest.profile.sha256 === manifest.profile.sha256 };
}

export function writeManifest(repoRoot, manifest) {
  const L = layout(repoRoot);
  mkdirSync(L.manifestDir, { recursive: true, mode: 0o700 });
  const file = manifestPath(repoRoot, manifest.manifestVersion);
  atomicWriteJson(file, manifest);
  return file;
}
