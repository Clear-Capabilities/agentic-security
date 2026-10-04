// Resolved dependency data in the scan path (QA-005.AC04): explicit exports a user or tool wrote on purpose become part of a normal scan,
// instead of being reachable only from a unit test.
//
//   Haskell   dist-newstyle/cache/plan.json and .stack-work/dependencies.json   -> a resolved graph (transitive packages, exact
//             versions, scopes) joined to the declared manifests; stale data is used for nothing and disclosed.
//   Nix       nix-export.json (and .direnv/nix-export.json)                       -> an imported closure, matched against an advisory
//             snapshot with upstream-identity and patch-evidence rules; no feed means "unknown", never "clean".
//   Eval      AGENTIC_SECURITY_NIX_EVAL=1 + AGENTIC_SECURITY_NIX_TARGET=<attr>   -> an isolated, opt-in evaluation whose state is its
//             own scan-health field. A scan that did not select it never runs a Nix evaluator.
//
// Nothing here fetches, builds, evaluates or runs a project's code unless the evaluation is selected AND the sandbox proves its isolation.

import { readFileSync, existsSync } from 'node:fs';
import { statePath } from '../posture/state-dir.js';
import { analyzeHaskellManifests } from './haskell-manifests.js';
import { buildResolvedGraph } from './haskell-resolved-graph.js';
import { importNixClosure } from './nix-closure.js';
import { NixAdvisoryData, matchNixVulnerabilities, overlayEvidence } from './nix-sca.js';
import { configuredAdvisoryDb, collectUsage, manifestFiles } from './haskell-supply.js';
import { runIsolatedEval, mergeEvaluationHealth, _which } from './nix-eval-isolation.js';

export const RESOLVED_PASS_VERSION = 'resolved-pass/1';

const PLAN = /(?:^|\/)dist-newstyle\/cache\/plan\.json$/;
const STACK_EXPORT = /(?:^|\/)\.stack-work\/dependencies\.json$/;
const NIX_EXPORT = /(?:^|\/)nix-export\.json$/;
const ACTIONABLE = new Set(['affected', 'possibly-affected', 'candidate', 'backported-verified']);

const memo = new WeakMap();
const memoized = (files, key, make) => { let m = memo.get(files); if (!m) { m = new Map(); memo.set(files, m); } if (!m.has(key)) m.set(key, make()); return m.get(key); };

function parseJson(text) { try { return { ok: true, value: JSON.parse(text) }; } catch (e) { return { ok: false, reason: String((e && e.message) || e).slice(0, 120) }; } }

/** The resolved Haskell graph for a file set, or null when no explicit export is present. Cached per file set. */
export function resolvedHaskellGraph(files) {
  return memoized(files, 'hs-graph', () => {
    const planFile = Object.keys(files).find((p) => PLAN.test(p));
    const stackFile = !planFile ? Object.keys(files).find((p) => STACK_EXPORT.test(p)) : null;
    const src = planFile || stackFile;
    if (!src) return null;
    const mf = manifestFiles(files);
    const manifests = mf.length ? analyzeHaskellManifests(mf) : null;
    const parsed = parseJson(files[src]);
    if (!parsed.ok) return { file: src, graph: { source: planFile ? 'cabal-plan' : 'stack-export', graphAvailable: false, units: null, edges: null, freshness: { status: 'unverified', reasons: [] }, closure: { complete: false, reason: 'malformed_resolved_data' }, gaps: [{ kind: planFile ? 'malformed_plan' : 'malformed_stack_export', detail: `${src} is not valid JSON: ${parsed.reason}` }], declared: [] }, manifests };
    const graph = buildResolvedGraph({ manifests, ...(planFile ? { plan: parsed.value } : { stackExport: parsed.value }), expected: {} });
    return { file: src, graph, manifests };
  });
}

/**
 * Components for the resolved graph: every Hackage unit with an exact version, its scope and where it came from. Only a graph that is
 * not stale contributes; a stale one is returned as a gap (never as components), and a partial one says it is partial.
 */
export function resolvedHackageComponents(files) {
  const r = resolvedHaskellGraph(files);
  if (!r) return { components: [], gaps: [], summary: null };
  const g = r.graph;
  const gaps = (g.gaps || []).map((x) => ({ kind: `resolved-${x.kind}`, detail: x.detail || x.message || x.kind, file: r.file }));
  const summary = { file: r.file, source: g.source, graphAvailable: g.graphAvailable, freshness: g.freshness, closure: g.closure, units: g.units ? g.units.length : null, edges: g.edges ? g.edges.length : null };
  if (!g.graphAvailable || g.freshness.status === 'stale') return { components: [], gaps, summary };
  const SCOPE = { runtime: 'required', test: 'optional', benchmark: 'optional', setup: 'optional', 'build-tool': 'optional' };
  const direct = new Set((g.declared || []).map((d) => d.name));
  const components = [];
  for (const u of g.units) {
    if (u.origin === 'local' || u.origin === 'compiler' || !u.name || !u.version) continue;   // the project itself and boot libraries are not dependencies to match
    const scopes = Array.isArray(u.scopes) && u.scopes.length ? u.scopes : ['runtime'];
    const scope = scopes.includes('runtime') ? 'runtime' : scopes[0];
    components.push({ ecosystem: 'hackage', name: u.name, version: u.version, declaredRange: null, resolution: 'plan', scope, engineScope: SCOPE[scope] || 'required', target: null, componentKind: u.componentKind || null, manifest: r.file, line: null, ghcComponent: false, direct: direct.has(u.name), unitId: u.id, origin: u.origin, versionSource: { file: r.file, line: null } });
  }
  return { components, gaps, summary };
}

// ── Nix closure ──────────────────────────────────────────────────────────────────
function loadNixExports(files) {
  const exports = []; const sources = []; const problems = []; let expected = {};
  for (const p of Object.keys(files).filter((x) => NIX_EXPORT.test(x)).sort()) {
    const parsed = parseJson(files[p]);
    sources.push(p);
    if (!parsed.ok) { problems.push({ kind: 'malformed-export', file: p, detail: parsed.reason }); continue; }
    const j = parsed.value;
    if (j && Array.isArray(j.exports)) { exports.push(...j.exports.filter((e) => e && typeof e === 'object')); if (j.expected && typeof j.expected === 'object') expected = { ...expected, ...j.expected }; }
    else if (j && typeof j === 'object' && j.schema && (j.data !== undefined || j.text !== undefined)) exports.push(j);
    else exports.push({ text: files[p] });
  }
  return { exports, sources, problems, expected };
}

/** The imported closure (and each derivation's env block) for a file set, or null when there is no export. Cached per file set. */
export function nixClosureOf(files, { now = Date.now() } = {}) {
  return memoized(files, 'nix-closure', () => {
    const { exports, sources, problems, expected } = loadNixExports(files);
    if (!sources.length) return null;
    const closure = importNixClosure({ exports, expected, now });
    const drvEnv = {};
    for (const ex of exports) {
      if (ex.schema !== 'nix-derivation-show-json') continue;
      let data = ex.data; if (data === undefined && typeof ex.text === 'string') { const p = parseJson(ex.text); data = p.ok ? p.value : null; }
      for (const [k, v] of Object.entries(data || {})) if (v && v.env) drvEnv[k] = v.env;
    }
    return { closure, drvEnv, sources, problems };
  });
}

/** Advisory records for Nix: a snapshot named by AGENTIC_SECURITY_NIX_ADVISORIES or kept in the project state directory. */
export function configuredNixAdvisories(root, env = process.env, hackageDb = null) {
  const path = env.AGENTIC_SECURITY_NIX_ADVISORIES || (root && existsSync(statePath(root, 'nix-advisories.json')) ? statePath(root, 'nix-advisories.json') : null);
  if (!path) return { data: null, reason: 'no Nix advisory snapshot is configured (set AGENTIC_SECURITY_NIX_ADVISORIES or provide nix-advisories.json in the project state directory)' };
  let snap; try { snap = JSON.parse(readFileSync(path, 'utf8')); } catch (e) { return { data: null, reason: `the Nix advisory snapshot is unreadable: ${e.code || e.message}` }; }
  const records = Array.isArray(snap) ? snap : (Array.isArray(snap.records) ? snap.records : []);
  return { data: new NixAdvisoryData({ records, hackage: hackageDb, source: 'pinned-snapshot', generatedAt: (snap && snap.generatedAt) || null }), reason: null };
}

/** Closure statuses and findings, with every disclosure the import and the feed produced. */
export function analyzeNixClosure(files, opts = {}) {
  return memoized(files, 'nix-analysis', () => _analyzeNixClosure(files, opts));
}
function _analyzeNixClosure(files, { scanRoot = null, env = process.env, now = Date.now() } = {}) {
  const c = nixClosureOf(files, { now });
  if (!c) return null;
  const hackage = configuredAdvisoryDb(scanRoot, env).db;
  const adv = configuredNixAdvisories(scanRoot, env, hackage);
  let usage = null; try { usage = collectUsage(files); } catch { usage = null; }
  let matched = null;
  try { matched = matchNixVulnerabilities({ closure: c.closure, drvEnv: c.drvEnv, data: adv.data, overlays: overlayEvidence(files), haskellUsage: usage }); } catch (e) { matched = null; c.problems.push({ kind: 'match-failed', detail: String((e && e.message) || e).slice(0, 160) }); }
  const gaps = [];
  for (const d of c.closure.disclosures || []) gaps.push({ kind: `closure-${d.kind}`, detail: d.detail });
  for (const p of c.problems) gaps.push({ kind: `closure-${p.kind}`, detail: p.detail, file: p.file });
  if (!adv.data) gaps.push({ kind: 'closure-advisory-feed-unavailable', detail: `${adv.reason}. The closure's components were NOT checked against any advisory: the absence of findings is not a clean result.` });
  else if (adv.data.stale) gaps.push({ kind: 'closure-advisory-feed-stale', detail: `the Nix advisory snapshot is stale or undated (${adv.data.ageDays == null ? 'age unknown' : `${Math.floor(adv.data.ageDays)} day(s) old`})` });
  const findings = ((matched && matched.findings) || []).filter((f) => ACTIONABLE.has(f.status)).map((f) => ({ ...f, file: c.sources[0], line: 1 }));
  return { status: c.closure.status, claims: c.closure.claims, sources: c.sources, summary: matched ? matched.summary : null, feed: matched ? matched.feed : null, statuses: matched ? matched.statuses : [], findings, gaps, licenses: matched ? matched.licenses : null, closure: c.closure };
}

// ── isolated evaluation (opt in) ─────────────────────────────────────────────────
/** Runs the isolated evaluation when AGENTIC_SECURITY_NIX_EVAL=1; otherwise null. Never throws; a failure is a recorded state. */
export async function runSelectedNixEval(root, env = process.env, overrides = {}) {
  if (env.AGENTIC_SECURITY_NIX_EVAL !== '1') return null;
  const attribute = env.AGENTIC_SECURITY_NIX_TARGET || '';
  const nixBin = overrides.nix || (_which ? _which('nix') : null);
  if (!attribute) return { status: 'blocked', reason: 'no evaluation target: set AGENTIC_SECURITY_NIX_TARGET to a flake output attribute (for example nixosConfigurations.host.config.system.build.toplevel.drvPath)', projectCodeEvaluated: false };
  if (!nixBin) return { status: 'unsupported', reason: 'the nix binary was not found on PATH; the project\'s Nix code was NOT evaluated', projectCodeEvaluated: false };
  try { return await runIsolatedEval({ nix: typeof nixBin === 'string' ? { file: nixBin } : nixBin, root, attribute, system: env.AGENTIC_SECURITY_NIX_SYSTEM || null, ...overrides }); }
  catch (e) { return { status: 'failed', reason: `the evaluation harness failed: ${String((e && e.message) || e).slice(0, 160)}`, projectCodeEvaluated: false }; }
}

export { mergeEvaluationHealth };
