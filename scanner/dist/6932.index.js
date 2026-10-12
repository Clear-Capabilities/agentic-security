export const id = 6932;
export const ids = [6932,3736];
export const modules = {

/***/ 36932:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  cmdFleet: () => (/* binding */ cmdFleet)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/util/yaml.js + 1 modules
var yaml = __webpack_require__(82340);
;// CONCATENATED MODULE: ./src/posture/fleet/fleet-manifest.js
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




const FLEET_MANIFEST_SCHEMA_KEYS = Object.freeze(['organization', 'repositories', 'workers', 'perRepoTimeout']);
const DURATION_RE = /^(\d+)(s|m|h)$/;

function parseDuration(s, fallbackMs) {
  if (typeof s === 'number' && s > 0) return s * 1000;
  const m = DURATION_RE.exec(String(s ?? ''));
  if (!m) return fallbackMs;
  const n = Number(m[1]);
  return m[2] === 's' ? n * 1000 : m[2] === 'm' ? n * 60000 : n * 3600000;
}

/** Validate a parsed manifest object against the manifest's own base directory (for path resolution). */
function validateFleetManifest(doc, { baseDir = '.' } = {}) {
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
    const abs = external_node_path_.resolve(baseDir, r.path);
    let isDir = false;
    try { isDir = external_node_fs_.statSync(abs).isDirectory(); } catch { /* reported below */ }
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

function loadFleetManifest(filePath) {
  let text;
  try { text = external_node_fs_.readFileSync(filePath, 'utf8'); } catch (e) { return { ok: false, errors: [`cannot read ${filePath}: ${e.message}`] }; }
  let doc;
  try { doc = (0,yaml/* load */.Hh)(text); } catch (e) { return { ok: false, errors: [`invalid YAML: ${e.message}`] }; }
  return validateFleetManifest(doc, { baseDir: external_node_path_.dirname(external_node_path_.resolve(filePath)) });
}

function starterManifestYaml(organization = 'example') {
  return `organization: ${organization}
repositories:
  - id: example-repo
    path: .
workers: 4
perRepoTimeout: 20m
`;
}

;// CONCATENATED MODULE: ./src/posture/fleet/fleet-graph.js
// The cross-repository dependency graph for the fleet feature (PRD 4).
//
// Reads each repo's own manifest to learn (a) the package name it publishes under, if any, and (b) the package
// names it depends on. An edge A -> B means "A declares a dependency that resolves to B's own published name" —
// i.e. B is upstream of A, and a defect in B can affect A. This is a real, lightweight cross-repo dependency graph
// built purely from manifests already on disk; it does not need deployment config (Kubernetes/compose/Terraform)
// the way the existing deployment-boundary graph does, so a fleet of plain application repos works out of the box.



const MANIFESTS = Object.freeze([
  { file: 'package.json', ecosystem: 'npm' },
  { file: 'go.mod', ecosystem: 'go' },
  { file: 'Cargo.toml', ecosystem: 'cargo' },
  { file: 'requirements.txt', ecosystem: 'pypi' },
  { file: 'pyproject.toml', ecosystem: 'pypi' },
]);

function readBounded(p, maxBytes = 1024 * 1024) {
  try {
    const st = external_node_fs_.statSync(p);
    if (!st.isFile() || st.size > maxBytes) return null;
    return external_node_fs_.readFileSync(p, 'utf8');
  } catch { return null; }
}

function parsePackageJson(text) {
  let j;
  try { j = JSON.parse(text); } catch { return { name: null, deps: new Set() }; }
  const deps = new Set([...Object.keys(j.dependencies || {}), ...Object.keys(j.devDependencies || {}), ...Object.keys(j.peerDependencies || {})]);
  return { name: typeof j.name === 'string' ? j.name : null, deps };
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
function readRepoManifest(repoPath) {
  let name = null;
  const deps = new Set();
  const ecosystems = new Set();
  for (const { file, ecosystem } of MANIFESTS) {
    const text = readBounded(external_node_path_.join(repoPath, file));
    if (text == null) continue;
    const parsed = PARSERS[file](text);
    if (parsed.name && !name) name = parsed.name;
    for (const d of parsed.deps) deps.add(d);
    ecosystems.add(ecosystem);
  }
  return { name, deps, ecosystems: [...ecosystems] };
}

/**
 * Build the fleet dependency graph. `repos`: [{id, path}]. An edge {from, to} means `from` depends on `to` (so a
 * defect in `to` can affect `from`). Matching is by declared package NAME only — two repos that happen to share a
 * name under different ecosystems are not disambiguated, a disclosed limit, not a guess.
 */
function buildFleetDependencyGraph(repos) {
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
      for (const to of targets) if (to !== id) edges.push({ from: id, to, via: dep });
    }
  }
  const nodes = [...manifests.values()].map((r) => ({ id: r.id, path: r.path, declaredName: r.manifest.name, ecosystems: r.manifest.ecosystems }));
  return { nodes, edges };
}

/** Transitive downstream closure: which fleet repos depend on `repoId`, directly or transitively, with the shortest path to each. */
function blastRadius(graph, repoId) {
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

// EXTERNAL MODULE: ./src/posture/policy-bundle.js
var policy_bundle = __webpack_require__(23736);
;// CONCATENATED MODULE: ./src/posture/fleet.js
// PRD Epic 5 — fleet orchestration.
//
// Many repositories, one invocation, one rolled-up result set. The existing
// `org-scan` could iterate repos; what it could not do is survive an
// interruption, bound its own concurrency, tell you what is NEW since the last
// run, or route a finding to the person who owns the file. Those four are the
// difference between a loop and something an organisation can put on a
// schedule.
//
// THE HARD LINE (PRD §2.2, §10): everything here runs from the CLI on the
// customer's infrastructure. There is no server, no account, no multi-tenancy,
// and the "UI" is a static artifact generated from local files. A fleet feature
// is exactly where a local-first tool drifts into a platform, so the constraint
// is stated here rather than left to judgement.
//
// FOUR PROPERTIES, EACH OF WHICH IS A FAILURE MODE IF ABSENT:
//
//   1. ISOLATION — one repo that explodes must not take the run with it. A
//      fleet scan that dies on repo 3 of 50 is worse than useless: it looks
//      like a completed scan of 3 repos.
//   2. RESUMABILITY — the checkpoint records COMPLETED repos, and is written
//      after each one. A resumed run skips them rather than re-scanning, which
//      is what makes a 50-repo run survivable on a laptop or a flaky runner.
//   3. BOUNDED CONCURRENCY — an unbounded fan-out over 50 repos will exhaust
//      memory or file handles on the machine it was supposed to help.
//   4. HONEST ROLL-UP — a repo that FAILED is counted as failed, never folded
//      into "0 findings". Silent zeros are how a fleet report says everything
//      is fine because nothing ran.
//
// DELTA IS COMPUTED FROM STABLE IDS, not counts. "3 more criticals than last
// week" tells you nothing about which; a set difference over stableId tells you
// exactly what appeared, and is what a scheduled run should notify on.





const SCHEMA = 'agentic-security/fleet-state@1';

/** Read a checkpoint, or an empty one. Never throws. */
function loadFleetState(stateFile) {
  try {
    const j = JSON.parse(external_node_fs_.readFileSync(stateFile, 'utf8'));
    if (j && j.schema === SCHEMA) return j;
  } catch { /* absent or unreadable -> start clean */ }
  return { schema: SCHEMA, completed: {}, startedAt: null };
}

function _saveFleetState(stateFile, state) {
  try {
    external_node_fs_.mkdirSync(external_node_path_.dirname(stateFile), { recursive: true });
    external_node_fs_.writeFileSync(stateFile, JSON.stringify(state, null, 2));
    return true;
  } catch { return false; }
}

/**
 * Owners for a path, from a CODEOWNERS file.
 *
 * Last matching rule wins, which is the documented CODEOWNERS precedence — a
 * first-match implementation silently routes to the most general owner, which
 * is the one least able to act on the finding.
 */
function ownersFor(codeownersText, filePath) {
  if (typeof codeownersText !== 'string' || !filePath) return [];
  let owners = [];
  for (const raw of codeownersText.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    const pattern = parts.shift();
    const these = parts.filter(p => p.startsWith('@') || p.includes('@'));
    if (!these.length) continue;
    if (_matchesGlob(pattern, filePath)) owners = these;
  }
  return owners;
}

function _matchesGlob(pattern, file) {
  const f = file.replace(/^\.?\//, '');
  let p = pattern.replace(/^\.?\//, '');
  if (p === '*') return true;
  if (p.endsWith('/')) return f.startsWith(p);
  const PLACEHOLDER = '\uE000'; // escape SEQUENCE in source -- 6 ASCII chars, not a raw embedded byte
  const rx = new RegExp('^' + p
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, PLACEHOLDER)
    .replace(/\*/g, '[^/]*')
    .replace(new RegExp(PLACEHOLDER, 'g'), '.*') + '(/.*)?$');
  return rx.test(f);
}

function _readCodeowners(repoRoot) {
  for (const rel of ['CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS']) {
    try { return external_node_fs_.readFileSync(external_node_path_.join(repoRoot, rel), 'utf8'); } catch { /* next */ }
  }
  return null;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function _summarise(scan) {
  const all = [
    ...(scan.findings || []), ...(scan.secrets || []),
    ...(scan.logicVulns || []), ...(scan.supplyChain || []),
  ];
  const bySeverity = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  const ids = [];
  let proven = 0;
  for (const f of all) {
    const sev = String(f.severity || 'info').toLowerCase();
    if (sev in bySeverity) bySeverity[sev]++;
    if (f.stableId) ids.push(f.stableId);
    if (f.proofTier === 'execution-proven') proven++;
  }
  return { total: all.length, bySeverity, proven, ids, findings: all };
}

/**
 * M4 §4.4 — provenance-aware debt for ONE repo, computed here (inside the
 * worker, from the untrimmed findings array) rather than inside `rollupFleet`,
 * because FR-1005 forbids raw finding data from surviving onto the per-repo
 * result entry (`test('FR-1005: ... the entry must not carry the raw findings
 * array at all')` in fleet.test.js) — a finding can carry a raw source
 * snippet, so only this derived summary (a finding id, a commit date, a day
 * count; never a file path or snippet) is threaded onto `entry.provenanceDebt`.
 *
 * A finding contributes only when its `findingProvenance.status` is
 * `'complete'` — the honest end of the confidence spectrum (see
 * `provenance/schema.js`'s `PROVENANCE_STATUS`). `partial`/`uncommitted`/etc.
 * are not proof of origin and must never win "oldest".
 */
function _provenanceDebtForRepo(findings, now = Date.now()) {
  let oldest = null;
  let completeCount = 0;
  for (const f of (findings || [])) {
    if (f.findingProvenance?.status !== 'complete') continue;
    const authorDate = f.findingProvenance?.findingOrigin?.authorDate;
    if (!authorDate) continue;
    completeCount++;
    const ageDays = Math.max(0, Math.floor((now - Date.parse(authorDate)) / 86400000));
    if (!oldest || ageDays > oldest.ageDays) {
      // FR-PROV-019: "Reports never show an age without its basis and
      // confidence." The basis is structurally implied here (only
      // status:'complete' findings reach this line, so the age is always
      // git-derived, and the rendered text says "proven-origin") — but the
      // confidence half has to be carried explicitly, same as
      // mttr.js's renderSlaSummary. Captured at selection time so the
      // renderers below cannot show the age without it.
      oldest = {
        findingId: f.id || f.stableId || null,
        authorDate,
        ageDays,
        confidence: f.findingProvenance?.confidence?.level || null,
      };
    }
  }
  return { oldest, completeCount };
}

/**
 * Scan many repositories with bounded concurrency, resumably.
 *
 * `runScan` is injected so this module has no engine import cycle and so the
 * orchestration can be tested without running real scans.
 */
async function runFleet({
  repos = [], concurrency = 4, stateFile, runScan,
  resume = true, previous = null, onProgress = () => {},
  // X-704: repositories whose every durable portfolio work unit is verified and current
  // (portfolio/work-units.js `fullyVerifiedRepositories`). They are skipped like a resumed completed repo,
  // and, as with a resumed repo, the skip is reported in `skipped` rather than counted as scanned.
  portfolioVerified = [],
} = {}) {
  if (typeof runScan !== 'function') {
    return { ok: false, reason: 'no runScan supplied' };
  }
  const state = (resume && stateFile) ? loadFleetState(stateFile) : { schema: SCHEMA, completed: {}, startedAt: null };
  const results = [];
  const skipped = [];

  const queue = repos.filter((r) => {
    if ((resume && state.completed[r]) || portfolioVerified.includes(r)) { skipped.push(r); return false; }
    return true;
  });

  const limit = Math.max(1, Math.min(concurrency, 32));
  let cursor = 0;

  async function worker() {
    while (cursor < queue.length) {
      const repo = queue[cursor++];
      let entry;
      try {
        const { scan } = await runScan(repo);
        const s = _summarise(scan);
        const codeowners = _readCodeowners(repo);
        // Route each finding to the owner of its file. Done here rather than at
        // report time because the CODEOWNERS file lives in the repo, and by
        // report time the fleet has moved on.
        const owners = {};
        if (codeowners) {
          for (const f of s.findings) {
            if (!f.file) continue;
            const o = ownersFor(codeowners, f.file);
            for (const own of o) (owners[own] ||= []).push(f.stableId || `${f.file}:${f.line}`);
          }
        }
        // FR-1006: "assurance-health views" and "policy drift" — a repo can
        // be RISK-clean (zero/low findings) while still having a governance
        // gap (a partial scan, a rejected/expired policy bundle nobody
        // noticed). scanHealth comes straight from the engine's own
        // computeScanHealth (FR-206) — nothing new is inferred here, this is
        // the first time the fleet rollup SURFACES a signal that already
        // existed per-scan. computePolicyDrift is null (not an empty object)
        // when the repo has no policy bundles configured at all — matching
        // this session's "no baseline configured -> no-op" convention.
        let policyDrift = null;
        try { policyDrift = (0,policy_bundle/* computePolicyDrift */.rE)(repo); } catch { /* best-effort — never fail a repo's scan over drift reporting */ }
        // M4 §4.4: provenance-aware debt, computed HERE (from `s.findings`,
        // the untrimmed array) rather than in `rollupFleet` — by the time
        // `rollupFleet` sees `results`, the raw findings are gone (FR-1005).
        // Only the derived summary (id/date/age, never a file or snippet)
        // survives onto the entry. `mttr` threads through the SAME aggregate
        // `mttr.js`'s `computeMTTR` already produces (`scan.mttr`, stamped by
        // the CLI's persistence step — see posture/mttr.js) rather than
        // inventing a second notion of remediation time; there is no
        // `scan.remediatedFindings` field anywhere in this codebase.
        const provenanceDebt = _provenanceDebtForRepo(s.findings);
        entry = {
          repo, ok: true, total: s.total, bySeverity: s.bySeverity,
          proven: s.proven, ids: s.ids, owners, scannedAt: new Date().toISOString(),
          scanHealth: scan.scanHealth || null, policyDrift,
          provenanceDebt, mttr: scan.mttr || null,
        };
      } catch (e) {
        // A failed repo is FAILED, never zero findings.
        entry = { repo, ok: false, error: String(e?.message || e), total: null, bySeverity: null, ids: [], scannedAt: new Date().toISOString(), scanHealth: null, policyDrift: null, provenanceDebt: null, mttr: null };
      }
      results.push(entry);
      if (stateFile) {
        // FR-1006 (assurance-hardening PRD): "scan freshness" — this field
        // existed as an always-null stub before (never read anywhere, never
        // populated), which is the same as not existing for anyone trying to
        // answer "when was this repo last scanned". Stamped from the SAME
        // entry.scannedAt the results array already carries, not a second,
        // possibly-diverging timestamp.
        state.completed[repo] = { at: entry.scannedAt, ok: entry.ok, total: entry.total };
        _saveFleetState(stateFile, state);
      }
      onProgress(entry);
    }
  }

  await Promise.all(Array.from({ length: limit }, () => worker()));
  return { ok: true, results, skipped, rollup: rollupFleet(results, previous) };
}

/**
 * Roll many per-repo results into one view, with a delta when a previous run
 * is supplied.
 */
function rollupFleet(results, previous = null) {
  const scanned = results.filter(r => r.ok);
  const failed = results.filter(r => !r.ok);
  const bySeverity = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  let total = 0, proven = 0;
  for (const r of scanned) {
    total += r.total || 0;
    proven += r.proven || 0;
    for (const s of SEVERITIES) bySeverity[s] += r.bySeverity?.[s] || 0;
  }

  // Delta by stable id, not by count.
  let newFindings = null;
  if (previous && Array.isArray(previous.results)) {
    const before = new Set(previous.results.flatMap(r => r.ids || []));
    newFindings = {};
    for (const r of scanned) {
      const fresh = (r.ids || []).filter(id => !before.has(id));
      if (fresh.length) newFindings[r.repo] = fresh;
    }
  }

  // FR-1006: governance/coverage gaps, counted and surfaced SEPARATELY from
  // the risk rollup above (total/bySeverity/proven) — a repo can contribute
  // zero to those and still need attention here. `null` scanHealth (a
  // failed repo, or a runScan that predates FR-206) is not counted as
  // partial — absence of a signal is not evidence of a problem.
  const partialScanHealth = scanned.filter(r => r.scanHealth && r.scanHealth.status !== 'complete');
  const withPolicyDrift = scanned.filter(r => r.policyDrift && (r.policyDrift.overrides.length || r.policyDrift.rejected.length));

  // M4 §4.4: provenance-aware debt + MTTR, surfaced as its own section
  // alongside the FR-1006 governance section above — same additive pattern,
  // same reason: a repo can be risk-clean and still carry old, PROVEN debt,
  // and that must not be folded into (or hidden by) the risk rollup above.
  //
  // `oldestProvenDebt` only ever comes from a repo's own `provenanceDebt`,
  // which `runFleet`'s worker computed from `findingProvenance.status ===
  // 'complete'` findings only — never a wall-clock guess dressed as proof.
  // A repo with no complete-status findings is disclosed BY NAME in
  // `reposWithNoProvenDebt`, never silently absent from a "no debt" story a
  // reader could misread as "this repo has no old findings" when the truth
  // is "we couldn't PROVE any origin here". A `results` entry that predates
  // this field (no `provenanceDebt` key at all — e.g. an older checkpoint,
  // or a hand-built test fixture) is treated the same as "none found",
  // consistent with every other optional signal in this rollup (scanHealth,
  // policyDrift).
  let oldestProvenDebt = null;
  const reposWithNoProvenDebt = [];
  const perRepoOldestProvenDebt = [];
  for (const r of scanned) {
    const oldest = r.provenanceDebt?.oldest || null;
    if (!oldest) { reposWithNoProvenDebt.push(r.repo); continue; }
    const withRepo = { repo: r.repo, ...oldest };
    perRepoOldestProvenDebt.push(withRepo);
    if (!oldestProvenDebt || oldest.ageDays > oldestProvenDebt.ageDays) oldestProvenDebt = withRepo;
  }

  // Fleet-wide MTTR reuses each repo's own `scan.mttr` (mttr.js's
  // `computeMTTR` output — `{count, meanDays, medianDays, perSeverity}`),
  // combined as a count-weighted mean, rather than recomputing wall-clock
  // remediation time here from a second source of truth. `byAgeBasis` is
  // deliberately always `{}`: `computeMTTR` does not track ageBasis per
  // remediated finding (only per-severity), and there is no
  // `scan.remediatedFindings` array anywhere in this codebase to derive one
  // from — see `runFleet`'s worker comment. Reporting a fabricated breakdown
  // would be worse than reporting none.
  //
  // FINAL-REVIEW FIX (M4, item 4): `mttr` used to default to `{n:0, ...}`
  // whenever no scanned repo's `.mttr` counted a remediation — which is
  // exactly what happens on EVERY real production fleet run, since
  // `scripts/fleet.mjs` drives `runFleet` with `runScan` straight from
  // `src/runScan.js`, and that function never sets `.mttr` at all (the only
  // real setter is the CLI's OWN single-repo persistence step in
  // `bin/agentic-security.js`, which fleet mode does not go through — see
  // that file's comment for the full investigation). `{n:0,...}` and "no
  // repo ever attempted to compute this" are materially different facts:
  // the first is a real, honest zero; the second is a missing capability.
  // Collapsing them made every real fleet run silently render a fabricated-
  // looking "no remediated findings recorded yet" line that reads as a
  // measurement rather than an absence.
  //
  // `anyMttrSupplied` distinguishes them: it is true only when at least one
  // SCANNED repo's entry carried a non-null `.mttr` object at all — which
  // only happens when something upstream (the CLI's own persistence path,
  // or a caller-supplied `runScan` that wires the same pipeline itself)
  // actually ran `computeMTTR`. `mttr` stays `null` — not a zeroed object —
  // when nothing did, so a consumer can tell "tracked, zero fixes so far"
  // from "not tracked at all" without inspecting `n`.
  let mttrCount = 0, mttrWeightedDays = 0, anyMttrSupplied = false;
  for (const r of scanned) {
    const m = r.mttr;
    if (m == null) continue;
    anyMttrSupplied = true;
    if (typeof m.count === 'number' && m.count > 0 && typeof m.meanDays === 'number') {
      mttrCount += m.count;
      mttrWeightedDays += m.meanDays * m.count;
    }
  }
  const mttr = anyMttrSupplied
    ? { n: mttrCount, meanDays: mttrCount ? mttrWeightedDays / mttrCount : null, byAgeBasis: {} }
    : null;

  return {
    repos: results.length,
    scanned: scanned.length,
    // Surfaced at the top level, not buried: a fleet report whose failures are
    // a footnote reads as a clean fleet.
    failed: failed.length,
    failures: failed.map(f => ({ repo: f.repo, error: f.error })),
    total, proven, bySeverity,
    reposWithPartialScanHealth: partialScanHealth.length,
    reposWithPolicyDrift: withPolicyDrift.length,
    ...(newFindings ? { newFindings } : {}),
    provenance: { oldestProvenDebt, reposWithNoProvenDebt, perRepoOldestProvenDebt, mttr },
  };
}

/** One-line summary. Leads with failures when there are any. */
function renderFleetSummary(rollup) {
  if (!rollup) return null;
  const head = rollup.failed
    ? `${rollup.failed} of ${rollup.repos} repo(s) FAILED to scan — their findings are unknown, not zero; `
    : '';
  const sev = SEVERITIES.filter(s => rollup.bySeverity[s]).map(s => `${rollup.bySeverity[s]} ${s}`).join(', ');
  const nf = rollup.newFindings
    ? ` ${Object.values(rollup.newFindings).reduce((a, b) => a + b.length, 0)} new since last run.`
    : '';
  // FR-1006: governance/coverage gaps reported as their own clause, never
  // folded into the risk sentence — a fleet with zero findings but 12 repos
  // on a partial scan is not "clean."
  const gov = [];
  if (rollup.reposWithPartialScanHealth) gov.push(`${rollup.reposWithPartialScanHealth} repo(s) with a partial (not complete) scan`);
  if (rollup.reposWithPolicyDrift) gov.push(`${rollup.reposWithPolicyDrift} repo(s) with policy drift or a rejected policy bundle`);
  const govClause = gov.length ? ` GOVERNANCE: ${gov.join('; ')}.` : '';
  // M4 §4.4: proven-origin debt as its own clause, matching the governance
  // clause's honesty rule — a null `oldestProvenDebt` gets an explicit "none"
  // line rather than silently vanishing from the sentence, which would read
  // as "no debt" instead of "nothing PROVEN yet."
  const prov = rollup.provenance;
  let provClause = '';
  if (prov) {
    // FR-PROV-019: the age never ships without its basis ("proven-origin",
    // structurally guaranteed by the status:'complete' filter upstream) AND
    // its confidence. A finding whose provenance carried no confidence level
    // says so rather than implying certainty by omission.
    const bits = prov.oldestProvenDebt
      ? [`oldest proven-origin finding: ${prov.oldestProvenDebt.repo} (${prov.oldestProvenDebt.ageDays}d, `
         + `${prov.oldestProvenDebt.confidence ? `${String(prov.oldestProvenDebt.confidence).toUpperCase()} confidence` : 'confidence unknown'})`]
      : ['no proven-origin findings across the fleet'];
    if (prov.reposWithNoProvenDebt.length) bits.push(`${prov.reposWithNoProvenDebt.length} repo(s) with no complete-status provenance`);
    provClause = ` PROVENANCE: ${bits.join('; ')}.`;
  }
  // X-707: portfolio progress is its own clause, present only when the `portfolio-assurance` feature attached it
  // (portfolio/progress.js `attachPortfolioProgress`), so flag-off output is byte-identical. It states verified units and
  // repositories separately from the scan counts above: a finished controller is not a passing portfolio.
  const pp = rollup.portfolioProgress;
  const portfolioClause = pp ? ` PORTFOLIO: ${pp.units.verified}/${pp.units.total} unit(s) verified, ${pp.coverage.fullyVerified}/${pp.coverage.total} repo(s) fully verified, ${pp.review.pending} pending human review; ${pp.completion.statement}` : '';
  return `${head}${rollup.scanned} repo(s) scanned, ${rollup.total} finding(s)`
    + `${sev ? ` (${sev})` : ''}, ${rollup.proven} execution-proven.${nf}${govClause}${provClause}${portfolioClause}`;
}

/**
 * A self-contained rollup page. No network, no scripts, no fonts — it must
 * render from local artifacts on an air-gapped machine (PRD AC3).
 */
function renderFleetHtml(rollup, results) {
  const esc = (s) => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  // FR-1006: "scan freshness" — WHEN each repo was last scanned, not just
  // whether it was. A failed repo still carries a real scannedAt (the
  // attempt happened; it just didn't succeed) so a reader can tell "failed
  // just now" from "failed, and nobody has retried in weeks" apart.
  const rows = results.map(r => r.ok
    ? `<tr><td>${esc(r.repo)}</td><td>${r.total}</td>`
      + SEVERITIES.map(s => `<td>${r.bySeverity?.[s] ?? 0}</td>`).join('')
      + `<td>${r.proven ?? 0}</td><td>${esc(r.scannedAt || 'unknown')}</td></tr>`
    : `<tr class="fail"><td>${esc(r.repo)}</td><td colspan="7">SCAN FAILED — ${esc(r.error)}</td><td>${esc(r.scannedAt || 'unknown')}</td></tr>`).join('\n');
  // FR-1006: a SEPARATE table, not a column bolted onto the risk table above
  // — "distinguishes risk findings from scan and governance coverage gaps"
  // is most honestly satisfied by keeping the two visually and structurally
  // apart, not by merging them into one row a reader has to parse. Only
  // repos with something to report appear here; a fleet with nothing to flag
  // gets a one-line "nothing to report" rather than an empty table.
  const govRows = results
    .filter(r => (r.scanHealth && r.scanHealth.status !== 'complete') || (r.policyDrift && (r.policyDrift.overrides.length || r.policyDrift.rejected.length)))
    .map(r => {
      const healthCell = r.scanHealth && r.scanHealth.status !== 'complete'
        ? esc(`${r.scanHealth.status}: ${(r.scanHealth.conditions || []).join('; ') || 'see scanHealth'}`)
        : '—';
      const driftParts = [];
      if (r.policyDrift?.overrides?.length) {
        driftParts.push(...r.policyDrift.overrides.map(o => `${esc(o.key)} overridden by ${esc(o.overriddenBy)}`));
      }
      if (r.policyDrift?.rejected?.length) {
        driftParts.push(...r.policyDrift.rejected.map(x => `${esc(x.scope)} policy REJECTED: ${esc(x.reason)}`));
      }
      const driftCell = driftParts.length ? driftParts.join('; ') : '—';
      return `<tr><td>${esc(r.repo)}</td><td>${healthCell}</td><td>${driftCell}</td></tr>`;
    }).join('\n');
  const govSection = govRows
    ? `<h2>Governance / coverage gaps</h2>
<table border="1" cellpadding="4">
<tr><th>repo</th><th>scan health</th><th>policy drift</th></tr>
${govRows}
</table>`
    : `<h2>Governance / coverage gaps</h2>
<p>Nothing to report — every scanned repo has a complete scan and no policy drift.</p>`;
  // M4 §4.4: a SEPARATE section, same precedent as the governance section
  // above — proven-origin debt is neither a risk-severity fact nor a
  // governance-coverage fact, so it gets its own visual and structural space
  // rather than being bolted onto either existing table. Lists the oldest
  // finding PER REPO (not just the single fleet-wide oldest), so a reader can
  // see which repos are carrying old proven debt, not only the single worst
  // one.
  const prov = rollup.provenance;
  let provSection = '';
  if (prov) {
    // FR-PROV-019: the confidence column is not decoration — an age column
    // with no confidence beside it is exactly the "age without its basis and
    // confidence" the PRD forbids. The basis is the table's own framing
    // (every row is proven-origin by construction); the confidence has to be
    // shown per row, and an absent level reads "unknown" rather than blank,
    // so a missing value can never be mistaken for a confident one.
    const provRows = (prov.perRepoOldestProvenDebt || [])
      .map(p => `<tr><td>${esc(p.repo)}</td><td>${esc(p.findingId ?? 'unknown')}</td><td>${esc(p.authorDate)}</td><td>${p.ageDays}</td><td>${esc(p.confidence ? String(p.confidence).toUpperCase() : 'unknown')}</td></tr>`)
      .join('\n');
    const provTable = provRows
      ? `<table border="1" cellpadding="4">
<tr><th>repo</th><th>finding</th><th>author date</th><th>age (days)</th><th>origin confidence</th></tr>
${provRows}
</table>`
      : `<p>No complete-status (proven-origin) findings across the fleet.</p>`;
    const noProvenNote = prov.reposWithNoProvenDebt.length
      ? `<p>${prov.reposWithNoProvenDebt.length} repo(s) with no complete-status provenance: ${prov.reposWithNoProvenDebt.map(esc).join(', ')}</p>`
      : '';
    const mttrByBasisRows = Object.entries(prov.mttr?.byAgeBasis || {})
      .map(([basis, n]) => `<tr><td>${esc(basis)}</td><td>${n}</td></tr>`).join('\n');
    const mttrByBasisTable = mttrByBasisRows
      ? `<table border="1" cellpadding="4">
<tr><th>age basis</th><th>count</th></tr>
${mttrByBasisRows}
</table>`
      : '';
    // Three distinct states, not two (final-review fix, item 4): `prov.mttr
    // === null` means no scanned repo ever supplied a real mttr.js aggregate
    // at all — the honest disclosure is "not available", never "no
    // remediated findings recorded yet", which reads as a real zero
    // measurement rather than an absent capability. A non-null `mttr` with
    // `n === 0` is the legitimate zero: something DID track remediation and
    // genuinely found none yet.
    const mttrLine = !prov.mttr
      ? `<p>Fleet MTTR: not available — fleet mode does not yet track finding remediation history across runs.</p>`
      : prov.mttr.n > 0
      ? `<p>Fleet MTTR: ${prov.mttr.n} remediated finding(s)${prov.mttr.meanDays != null ? `, mean ${Math.round(prov.mttr.meanDays)}d to remediate` : ''}.</p>${mttrByBasisTable}`
      : `<p>Fleet MTTR: no remediated findings recorded yet.</p>`;
    provSection = `<h2>Provenance-Proven Debt</h2>
${provTable}
${noProvenNote}
${mttrLine}`;
  }
  return `<!-- generated offline; no external resources -->
<h1>Fleet scan</h1>
<p>${esc(renderFleetSummary(rollup) || '')}</p>
<h2>Risk findings</h2>
<table border="1" cellpadding="4">
<tr><th>repo</th><th>total</th>${SEVERITIES.map(s => `<th>${s}</th>`).join('')}<th>proven</th><th>scanned at</th></tr>
${rows}
</table>
${govSection}
${provSection}`;
}

const _internals = { SCHEMA, SEVERITIES, _matchesGlob, _summarise, _provenanceDebtForRepo };

// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
;// CONCATENATED MODULE: ./src/posture/fleet/cli.js
// `agentic-security fleet init|scan|status|resume|query`.
//
// Reuses the existing posture/fleet.js (runFleet: bounded concurrency, resumable checkpoint, per-repo isolation,
// honest rollup) for the scanning half — this module adds only the manifest-driven entry point and the
// cross-repository dependency graph (fleet-graph.js) that runFleet has no notion of.







const GRAPH_FILE = 'fleet-graph.json';
const STATE_FILE = 'fleet-state.json';

function graphPath(root) { return (0,state_dir.statePath)(root, GRAPH_FILE); }
function statePathFor(root) { return (0,state_dir.statePath)(root, STATE_FILE); }

async function cmdFleet(args, root) {
  const sub = args._[1];
  if (sub === 'init') return cmdInit(args, root);
  if (sub === 'scan') return cmdScan(args, root);
  if (sub === 'status') return cmdStatus(args, root);
  if (sub === 'resume') return cmdScan(args, root, { resumeOnly: true });
  if (sub === 'query') return cmdQuery(args, root);
  console.error('usage: fleet init | scan <manifest.yaml> | status <manifest.yaml> | resume <manifest.yaml> | query --depends-on <repo-id> [<manifest.yaml>]');
  return 4;
}

function manifestArg(args) {
  const m = args._[2];
  return m && !String(m).startsWith('--') ? m : 'fleet.yaml';
}

async function cmdInit(args, root) {
  const target = external_node_path_.resolve(root, manifestArg(args) === 'fleet.yaml' ? 'fleet.yaml' : manifestArg(args));
  if (external_node_fs_.existsSync(target) && !args.flags.force) { console.error(`${target} already exists. Pass --force to overwrite.`); return 4; }
  external_node_fs_.writeFileSync(target, starterManifestYaml(args.flags.organization || 'example'));
  console.log(`Wrote ${target}. Edit it to list your repositories, then run: agentic-security fleet scan ${external_node_path_.basename(target)}`);
  return 0;
}

async function cmdScan(args, root, { resumeOnly = false } = {}) {
  const manifestFile = external_node_path_.resolve(root, manifestArg(args));
  const loaded = loadFleetManifest(manifestFile);
  if (!loaded.ok) { console.error(`Invalid fleet manifest: ${loaded.errors.join('; ')}`); return 4; }
  const { manifest } = loaded;

  if (!(0,state_dir/* ensureStateDir */.xH)(root)) { console.error('No safe state directory for this project.'); return 4; }
  const prevRollupFile = (0,state_dir.statePath)(root, 'fleet-rollup.json');
  let previous = null;
  try { previous = JSON.parse(external_node_fs_.readFileSync(prevRollupFile, 'utf8')); } catch { /* first run */ }

  const { runScan: runScanFn } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 45950));
  // runScanFn resolves to { scan, meta } already — runFleet's worker expects exactly that shape from runScan, so
  // this must NOT wrap `scan` a second time (an earlier draft did, and every repo silently reported 0 findings:
  // `_summarise` reads `scan.findings` defensively rather than throwing on the wrong shape).
  const runScan = (repoPath) => runScanFn(repoPath, { provenance: false });

  console.error(`[fleet] scanning ${manifest.repositories.length} repository(ies) for ${manifest.organization} (${manifest.workers} worker(s))...`);
  const result = await runFleet({
    repos: manifest.repositories.map((r) => r.id), concurrency: manifest.workers,
    stateFile: statePathFor(root), resume: true, previous,
    runScan: async (repoId) => runScan(manifest.repositories.find((r) => r.id === repoId).path),
    onProgress: (entry) => { console.error(`[fleet] ${entry.ok ? 'done' : 'FAILED'}: ${entry.repo}${entry.ok ? ` (${entry.total} finding(s))` : ` — ${entry.error}`}`); },
  });
  if (resumeOnly && result.skipped.length === manifest.repositories.length) console.error('[fleet] nothing to resume — every repository was already complete.');

  (0,state_dir/* safeWriteState */.Ep)(prevRollupFile, JSON.stringify(result.rollup, null, 2));
  const graph = buildFleetDependencyGraph(manifest.repositories);
  (0,state_dir/* safeWriteState */.Ep)(graphPath(root), JSON.stringify({ organization: manifest.organization, builtAt: new Date().toISOString(), ...graph }, null, 2));

  console.log(renderFleetSummary(result.rollup));
  console.log(`\nRepositories requested: ${manifest.repositories.length}`);
  console.log(`Complete: ${result.results.filter((r) => r.ok).length + result.skipped.length}`);
  console.log(`Failed: ${result.results.filter((r) => !r.ok).length}`);
  const anyFailed = result.results.some((r) => !r.ok);
  return anyFailed ? 1 : 0;
}

async function cmdStatus(args, root) {
  const f = (0,state_dir.statePath)(root, 'fleet-rollup.json');
  if (!external_node_fs_.existsSync(f)) { console.error('No fleet scan has been run yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
  const rollup = JSON.parse(external_node_fs_.readFileSync(f, 'utf8'));
  if (args.flags.json) console.log(JSON.stringify(rollup, null, 2));
  else console.log(renderFleetSummary(rollup));
  return 0;
}

async function cmdQuery(args, root) {
  const target = args.flags['depends-on'];
  if (!target) { console.error('usage: fleet query --depends-on <repo-id>'); return 4; }
  const f = graphPath(root);
  if (!external_node_fs_.existsSync(f)) { console.error('No fleet dependency graph yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
  const graph = JSON.parse(external_node_fs_.readFileSync(f, 'utf8'));
  if (!graph.nodes.some((n) => n.id === target)) { console.error(`${target} is not a repository in the last fleet scan.`); return 4; }
  const radius = blastRadius(graph, target);
  if (args.flags.json) { console.log(JSON.stringify({ target, blastRadius: radius }, null, 2)); return 0; }
  if (!radius.length) { console.log(`No fleet repository depends on ${target} (by declared package name).`); return 0; }
  console.log(`Repositories depending on ${target} (directly or transitively):`);
  for (const r of radius) console.log(`  ${r.id}  (depth ${r.depth}, via ${r.path.slice(1).join(' -> ')})`);
  return 0;
}


/***/ }),

/***/ 23736:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   buildPolicyBundle: () => (/* binding */ buildPolicyBundle),
/* harmony export */   ensurePolicyKeyPair: () => (/* binding */ ensurePolicyKeyPair),
/* harmony export */   loadPolicyBundles: () => (/* binding */ loadPolicyBundles),
/* harmony export */   loadPolicyPublicKey: () => (/* binding */ loadPolicyPublicKey),
/* harmony export */   rE: () => (/* binding */ computePolicyDrift),
/* harmony export */   resolveEffectivePolicy: () => (/* binding */ resolveEffectivePolicy),
/* harmony export */   signPolicyBundle: () => (/* binding */ signPolicyBundle)
/* harmony export */ });
/* unused harmony exports POLICY_BUNDLE_SCHEMA, SCOPES, canonicalPolicyBytes, verifyPolicyBundle */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(77598);
/* harmony import */ var _evidence_bundle_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(98317);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(31174);
// Signed, portable policy bundles (assurance-hardening PRD FR-1001).
//
// "Support signed portable policy bundles with organization, repository, and
// environment inheritance" | "Tampered or expired policy is rejected;
// effective policy is explainable."
//
// WHY REUSE evidence-bundle.js's Ed25519 SCHEME, NOT integrity.js's HMAC
// -------------------------------------------------------------------------
// A policy bundle is authored by one party (typically a central security
// team, "the organization") and distributed to many repositories that never
// had the signing key. integrity.js's per-install symmetric HMAC is
// tamper-evidence for the SAME install that wrote it — a different install
// verifying a bundle it didn't sign is exactly the case that scheme cannot
// serve. evidence-bundle.js already solved this for findings: Ed25519,
// verify with only the public key. This module reuses that primitive
// directly (canonicalisation shape, allowlist-signed-fields discipline,
// exclusive-create key generation) rather than inventing a third signing
// mechanism, per this session's own established "survey before building a
// parallel primitive" practice (see D-0023/D-0025 for the same discipline
// applied to identity and exception mechanisms respectively).
//
// EA-03 LESSON, APPLIED HERE FROM THE START
// -------------------------------------------------------------------------
// evidence-bundle.js's own history (see its EA-03 comment) is the reason
// `canonicalPolicyBytes` signs an explicit ALLOWLIST and `verifyPolicyBundle`
// REJECTS any top-level key outside it: a bundle with a field stapled on
// after signing must fail verification, not silently pass with the addition
// unverified. Getting this right on the first pass — rather than discovering
// the gap the way evidence-bundle.js did — is the entire point of writing it
// down here.
//
// SCOPE — WHAT THIS MODULE DOES NOT DO
// -------------------------------------------------------------------------
// It does not invent a policy SCHEMA — `policy` is an opaque object; whatever
// keys a bundle carries (egress rules, severity floors, approved providers,
// anything else this repo already treats as policy) are merged the same way.
// It does not implement deep/recursive merging — inheritance is shallow,
// top-level-key override (organization -> repository -> environment, most
// specific wins per key), matching how every other flat policy config file
// in this repo (egress-policy.yml, compliance-severity-policy.json, …) is
// already shaped. A future consumer needing nested-key inheritance is new,
// separate scope, not assumed here.








const POLICY_BUNDLE_SCHEMA = 'agentic-security/policy-bundle@1';

const SCOPES = ['organization', 'repository', 'environment'];
// Inheritance order — later entries override earlier ones, per top-level key.
const INHERITANCE_ORDER = ['organization', 'repository', 'environment'];

function keyDir() {
  const xdg = process.env.XDG_CONFIG_HOME || node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.homedir(), '.config');
  return node_path__WEBPACK_IMPORTED_MODULE_2__.join(xdg, 'agentic-security', 'policy-bundles');
}

/** A SEPARATE Ed25519 keypair from evidence-bundle.js's finding-attestation
 * key — signing "this policy is authentic" and "this finding really came
 * from a scan run by me" are different trust domains and must not share a
 * key. Reuses evidence-bundle.js's hardened, race-safe generation logic
 * directly (its exclusive-create collision handling is the kind of code
 * worth NOT re-implementing) rather than duplicating it — the separation
 * that matters is the DIRECTORY (`policy-bundles/`, isolated from
 * evidence-bundle.js's own key dir), not the leaf filenames, which are
 * `attest-key.pem`/`attest-key.pub.pem` regardless of caller (a
 * evidence-bundle.js internal, not overridable here) — a readability wart,
 * not a security one, since the directory is what prevents key reuse. */
function ensurePolicyKeyPair(dir = keyDir()) {
  return (0,_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_4__.ensureKeyPair)(dir);
}

/**
 * Deterministic JSON, keys sorted at every level — identical algorithm to
 * evidence-bundle.js's canonicalJson (duplicated rather than imported: it is
 * a pure, three-line function, and importing it would couple this module's
 * signature format to evidence-bundle.js's internals for no real benefit).
 */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

// The complete set of fields a legitimately-built bundle carries, BEFORE
// signing. This is the signed allowlist AND (in verifyPolicyBundle) the
// complete set of keys a signed bundle is permitted to have alongside
// `signature` — see the EA-03 note above for why both matter.
const BUNDLE_FIELDS = ['schema', 'scope', 'policy', 'issuedAt', 'expiresAt'];
const BUNDLE_TOP_LEVEL_KEYS = new Set([...BUNDLE_FIELDS, 'signature']);

function canonicalPolicyBytes(bundle) {
  const signed = {};
  for (const k of BUNDLE_FIELDS) signed[k] = bundle[k] ?? null;
  return Buffer.from(canonicalJson(signed), 'utf8');
}

/**
 * Build an unsigned bundle. `policy` is caller-supplied and opaque — this
 * module does not validate its shape, only its provenance and freshness.
 */
function buildPolicyBundle(scope, policy, { issuedAt, expiresAt } = {}) {
  if (!SCOPES.includes(scope)) return null;
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) return null;
  return {
    schema: POLICY_BUNDLE_SCHEMA,
    scope,
    policy,
    issuedAt: issuedAt ?? new Date().toISOString(),
    expiresAt: expiresAt ?? null,
  };
}

/** Sign a bundle. Returns a new object; the input is not mutated. */
function signPolicyBundle(bundle, privateKeyPem) {
  const sig = node_crypto__WEBPACK_IMPORTED_MODULE_3__.sign(null, canonicalPolicyBytes(bundle), privateKeyPem);
  return {
    ...bundle,
    signature: { algorithm: 'ed25519', canonicalisation: POLICY_BUNDLE_SCHEMA, value: sig.toString('base64') },
  };
}

/**
 * Verify a bundle: signature authenticity AND freshness. Never throws — a
 * malformed or tampered bundle from an untrusted source (a repo checking out
 * whatever an org distributed) is an expected input, not exceptional.
 *
 * @returns {{ok: boolean, reason: string|null}}
 */
function verifyPolicyBundle(bundle, publicKeyPem, { now = Date.now() } = {}) {
  if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'bundle is not an object' };
  if (bundle.schema !== POLICY_BUNDLE_SCHEMA) return { ok: false, reason: `unrecognised schema: ${bundle.schema}` };
  if (!SCOPES.includes(bundle.scope)) return { ok: false, reason: `unrecognised scope: ${bundle.scope}` };
  const unknownKeys = Object.keys(bundle).filter(k => !BUNDLE_TOP_LEVEL_KEYS.has(k));
  if (unknownKeys.length) {
    return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknownKeys.join(', ')}` };
  }
  const sig = bundle.signature;
  if (!sig?.value) return { ok: false, reason: 'bundle is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  let sigOk = false;
  try {
    sigOk = node_crypto__WEBPACK_IMPORTED_MODULE_3__.verify(null, canonicalPolicyBytes(bundle), publicKeyPem, Buffer.from(sig.value, 'base64'));
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
  if (!sigOk) return { ok: false, reason: 'signature does not match the bundle contents — it was modified after signing' };
  if (bundle.expiresAt) {
    const exp = Date.parse(bundle.expiresAt);
    if (!Number.isFinite(exp)) return { ok: false, reason: `expiresAt is not a valid date: ${bundle.expiresAt}` };
    if (exp < now) return { ok: false, reason: `policy expired on ${bundle.expiresAt}` };
  }
  return { ok: true, reason: null };
}

/**
 * Merge verified bundles into one effective policy, in inheritance order
 * (organization -> repository -> environment; most specific wins per key).
 * A tampered or expired bundle is EXCLUDED from the merge (rejected, not
 * silently dropped — its scope and reason are reported so a rejection is
 * visible, not just absent). `provenance[key]` names which scope's bundle
 * last set that key — the "effective policy is explainable" half of the
 * acceptance criterion.
 *
 * @param {Array<{scope: string, bundle: object}>} entries
 * @param {string} publicKeyPem
 * @returns {{effective: object, provenance: Record<string,string>,
 *   accepted: string[], rejected: Array<{scope:string, reason:string}>}}
 */
function resolveEffectivePolicy(entries, publicKeyPem, { now = Date.now() } = {}) {
  const byScope = new Map();
  for (const e of entries || []) {
    if (e && SCOPES.includes(e.scope)) byScope.set(e.scope, e.bundle);
  }
  const effective = {};
  const provenance = {};
  const accepted = [];
  const rejected = [];
  for (const scope of INHERITANCE_ORDER) {
    const bundle = byScope.get(scope);
    if (!bundle) continue;
    const v = verifyPolicyBundle(bundle, publicKeyPem, { now });
    if (!v.ok) { rejected.push({ scope, reason: v.reason }); continue; }
    accepted.push(scope);
    for (const [k, val] of Object.entries(bundle.policy)) {
      effective[k] = val;
      provenance[k] = scope;
    }
  }
  return { effective, provenance, accepted, rejected };
}

/**
 * Load whichever policy bundle files exist under
 * `.agentic-security/policy-bundles/{organization,repository,environment}.json`.
 * Degrades gracefully — a missing directory or missing/malformed individual
 * file is simply absent from the result, never thrown. Read-first-in-try/
 * catch throughout (no existsSync-then-readFileSync — D-0012/D-0022).
 */
function loadPolicyBundles(scanRoot) {
  if (!scanRoot) return [];
  const entries = [];
  for (const scope of SCOPES) {
    let fp;
    try { fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_5__.statePath)(scanRoot, 'policy-bundles', `${scope}.json`); } catch { continue; }
    let raw;
    try { raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { continue; }
    try {
      const bundle = JSON.parse(raw);
      if (bundle && typeof bundle === 'object') entries.push({ scope, bundle });
    } catch { /* malformed — skip, do not throw */ }
  }
  return entries;
}

/**
 * Read the operator-supplied public key an org distributes alongside its
 * bundles, from `.agentic-security/policy-bundle-public-key.pem`. Returns
 * null (not a throw) if absent or unreadable — resolution then rejects
 * every bundle for lack of a key, same as any other "no public key
 * supplied" case in verifyPolicyBundle.
 */
function loadPolicyPublicKey(scanRoot) {
  if (!scanRoot) return null;
  let fp;
  try { fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_5__.statePath)(scanRoot, 'policy-bundle-public-key.pem'); } catch { return null; }
  try { return node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { return null; }
}

/**
 * FR-1006 ("policy drift"): does this repository's LOCALLY resolved effective
 * policy diverge from what the organization-scope bundle alone specifies —
 * and is anything the repo is relying on actually being rejected (tampered
 * or expired) rather than enforced? Both are GOVERNANCE gaps, distinct from
 * risk findings, which is the exact distinction FR-1006's acceptance
 * criterion asks fleet output to make.
 *
 * No bundles configured at all is a no-op (`null`), matching this session's
 * established convention: drift can only be reported relative to a
 * baseline, and a repo with no organization bundle has no baseline to drift
 * from.
 *
 * @returns {{accepted: string[], rejected: Array<{scope,reason}>,
 *   overrides: Array<{key, organizationValue, effectiveValue, overriddenBy}>}
 *   | null}
 */
function computePolicyDrift(scanRoot) {
  const entries = loadPolicyBundles(scanRoot);
  if (!entries.length) return null;
  const publicKeyPem = loadPolicyPublicKey(scanRoot);
  const { effective, provenance, accepted, rejected } = resolveEffectivePolicy(entries, publicKeyPem);

  const overrides = [];
  const orgEntry = entries.find(e => e.scope === 'organization');
  if (orgEntry && accepted.includes('organization')) {
    for (const [key, organizationValue] of Object.entries(orgEntry.bundle.policy || {})) {
      const overriddenBy = provenance[key];
      if (overriddenBy && overriddenBy !== 'organization' && !_deepEqual(effective[key], organizationValue)) {
        overrides.push({ key, organizationValue, effectiveValue: effective[key], overriddenBy });
      }
    }
  }
  return { accepted, rejected, overrides };
}

function _deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}


/***/ })

};
