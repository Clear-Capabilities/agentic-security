// The cross-repository dependency graph for the fleet feature (PRD 4).
//
// Reads each repo's own manifest to learn (a) the package name it publishes under, if any, and (b) the package
// names it depends on. An edge A -> B means "A declares a dependency that resolves to B's own published name" —
// i.e. B is upstream of A, and a defect in B can affect A. This is a real, lightweight cross-repo dependency graph
// built purely from manifests already on disk; it does not need deployment config (Kubernetes/compose/Terraform)
// the way the existing deployment-boundary graph does, so a fleet of plain application repos works out of the box.
import fs from 'node:fs';
import path from 'node:path';

const MANIFESTS = Object.freeze([
  { file: 'package.json', ecosystem: 'npm' },
  { file: 'go.mod', ecosystem: 'go' },
  { file: 'Cargo.toml', ecosystem: 'cargo' },
  { file: 'requirements.txt', ecosystem: 'pypi' },
  { file: 'pyproject.toml', ecosystem: 'pypi' },
]);

function readBounded(p, maxBytes = 1024 * 1024) {
  try {
    const st = fs.statSync(p);
    if (!st.isFile() || st.size > maxBytes) return null;
    return fs.readFileSync(p, 'utf8');
  } catch { return null; }
}

function parsePackageJson(text) {
  let j;
  try { j = JSON.parse(text); } catch { return { name: null, deps: new Set() }; }
  const specs = new Map();
  for (const block of [j.peerDependencies, j.devDependencies, j.dependencies]) for (const [k, v] of Object.entries(block || {})) if (typeof v === 'string') specs.set(k, v.slice(0, 200));
  const deps = new Set([...Object.keys(j.dependencies || {}), ...Object.keys(j.devDependencies || {}), ...Object.keys(j.peerDependencies || {})]);
  return { name: typeof j.name === 'string' ? j.name : null, deps, specs, version: typeof j.version === 'string' ? j.version : null };
}

function parseGoMod(text) {
  const m = /^module\s+(\S+)/m.exec(text);
  const deps = new Set();
  const block = /require\s*\(([\s\S]*?)\)/.exec(text);
  const lines = block ? block[1].split('\n') : text.split('\n').filter((l) => /^require\s/.test(l.trim()));
  for (const raw of lines) {
    const l = raw.replace(/^require\s+/, '').trim();
    const dm = /^(\S+)\s+v?\S+/.exec(l);
    if (dm) deps.add(dm[1]);
  }
  return { name: m ? m[1] : null, deps };
}

function parseCargoToml(text) {
  const nm = /\[package\][\s\S]*?\bname\s*=\s*"([^"]+)"/.exec(text);
  const deps = new Set();
  const section = /\[dependencies\]([\s\S]*?)(\n\[|$)/.exec(text);
  if (section) {
    for (const line of section[1].split('\n')) {
      const dm = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(line);
      if (dm) deps.add(dm[1]);
    }
  }
  return { name: nm ? nm[1] : null, deps };
}

function parseRequirementsTxt(text) {
  const deps = new Set();
  for (const raw of text.split('\n')) {
    const l = raw.trim();
    if (!l || l.startsWith('#') || l.startsWith('-')) continue;
    const dm = /^([A-Za-z0-9._-]+)/.exec(l);
    if (dm) deps.add(dm[1].toLowerCase());
  }
  return { name: null, deps };
}

function parsePyprojectToml(text) {
  const nm = /\[project\][\s\S]*?\bname\s*=\s*"([^"]+)"/.exec(text);
  const deps = new Set();
  const section = /dependencies\s*=\s*\[([\s\S]*?)\]/.exec(text);
  if (section) {
    for (const m of section[1].matchAll(/"([A-Za-z0-9._-]+)/g)) deps.add(m[1].toLowerCase());
  }
  return { name: nm ? nm[1] : null, deps };
}

const PARSERS = { 'package.json': parsePackageJson, 'go.mod': parseGoMod, 'Cargo.toml': parseCargoToml, 'requirements.txt': parseRequirementsTxt, 'pyproject.toml': parsePyprojectToml };

/** One repo's declared identity and dependency names, merged across every manifest file it has. */
export function readRepoManifest(repoPath) {
  let name = null;
  const deps = new Set();
  const ecosystems = new Set();
  const specs = new Map();
  const files = new Map();
  for (const { file, ecosystem } of MANIFESTS) {
    const text = readBounded(path.join(repoPath, file));
    if (text == null) continue;
    const parsed = PARSERS[file](text);
    if (parsed.name && !name) name = parsed.name;
    for (const d of parsed.deps) { deps.add(d); if (!files.has(d)) files.set(d, file); }
    for (const [d, spec] of parsed.specs ?? []) specs.set(d, spec);
    ecosystems.add(ecosystem);
  }
  return { name, deps, ecosystems: [...ecosystems], specs, files };
}

/**
 * Build the fleet dependency graph. `repos`: [{id, path}]. An edge {from, to} means `from` depends on `to` (so a
 * defect in `to` can affect `from`). Matching is by declared package NAME only — two repos that happen to share a
 * name under different ecosystems are not disambiguated, a disclosed limit, not a guess.
 */
export function buildFleetDependencyGraph(repos) {
  const manifests = new Map();
  for (const r of repos) manifests.set(r.id, { ...r, manifest: readRepoManifest(r.path) });

  const byName = new Map();
  for (const [id, r] of manifests) if (r.manifest.name) {
    if (!byName.has(r.manifest.name)) byName.set(r.manifest.name, []);
    byName.get(r.manifest.name).push(id);
  }

  const edges = [];
  for (const [id, r] of manifests) {
    for (const dep of r.manifest.deps) {
      const targets = byName.get(dep);
      if (!targets) continue;
      for (const to of targets) if (to !== id) edges.push({ from: id, to, via: dep, evidence: [{ source: 'package-manifest', repo: id, file: r.manifest.files.get(dep) ?? null, declared: dep, spec: r.manifest.specs.get(dep) ?? null }] });
    }
  }
  const nodes = [...manifests.values()].map((r) => ({ id: r.id, path: r.path, declaredName: r.manifest.name, ecosystems: r.manifest.ecosystems }));
  return { nodes, edges };
}

/** Transitive downstream closure: which fleet repos depend on `repoId`, directly or transitively, with the shortest path to each. */
export function blastRadius(graph, repoId) {
  const incoming = new Map();
  for (const e of graph.edges) { if (!incoming.has(e.to)) incoming.set(e.to, []); incoming.get(e.to).push(e.from); }
  const best = new Map();
  const queue = [{ id: repoId, path: [repoId] }];
  while (queue.length) {
    const { id, path: p } = queue.shift();
    for (const from of incoming.get(id) || []) {
      if (best.has(from)) continue;
      const newPath = [...p, from];
      best.set(from, { depth: newPath.length - 1, path: newPath });
      queue.push({ id: from, path: newPath });
    }
  }
  return [...best.entries()].map(([id, v]) => ({ id, ...v })).sort((a, b) => a.depth - b.depth || (a.id < b.id ? -1 : 1));
}
