// Baseline capture (CORE-001): what this checkout actually is, before the
// differentiation work changes it.
//
// Principles:
//   - READ-ONLY. Capture reads source, runs read-only git and version queries, and
//     returns a manifest. It writes nothing; the CLI writes only to a path that
//     `assertSafeOutput` accepts, which is never inside an application source root.
//   - NOTHING IS FABRICATED. Every environmental fact is `{status:'known', value}`
//     or `{status:'unknown', reason}`. A tool that is missing, a bundle that is
//     absent, a repository with no HEAD: each is recorded as unknown with the reason.
//   - EXACT BYTES. Digests are over working-tree bytes, so uncommitted edits move
//     them, and the dirty path list says which files differ from HEAD.
//   - EVIDENCE IS BOUND TO WHAT IT COVERS. Each capability records the digest of
//     every source and evidence file it cites. `evaluateBaseline` compares a fresh
//     capture to a recorded one and invalidates exactly the capabilities whose cited
//     files changed; unrelated user changes are kept, listed and never touched.
//
// The manifest is not deterministic across machines (it records HEAD, dirty paths
// and tool versions), so it is generated on demand and not committed.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { hardenGitArgs, hardenGitEnv } from '../../util/git-hardening.js';
import { STATE_DIR_NAME } from '../state-dir.js';
import { digestOf, digestOfBytes } from './identity.js';
import { RECOMMENDATION_MAPPINGS, CAPABILITY_INVENTORY } from './baseline-inventory.js';

export const BASELINE_SCHEMA = 'agentic-security/baseline-manifest';
export const BASELINE_VERSION = '1.0.0';
export const CAPABILITY_STATUSES = Object.freeze(['implemented', 'partial', 'unsupported', 'unmeasured']);

// Directories whose contents are application source: capture never writes here.
export const SOURCE_ROOTS = Object.freeze(['scanner/src', 'scanner/bin', 'scanner/scripts', 'hooks', 'commands', 'agents', 'scripts']);
// What the source digest covers.
export const SOURCE_DIGEST_PATHS = Object.freeze(['scanner/src', 'scanner/bin', 'scanner/package.json', 'scanner/package-lock.json']);
const BUNDLE_PATH = 'scanner/dist/agentic-security.mjs';

const known = (value) => ({ status: 'known', value });
const unknown = (reason) => ({ status: 'unknown', reason });

function defaultExec(cmd, args, { cwd, timeoutMs = 15_000 } = {}) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: timeoutMs, env: cmd === 'git' ? hardenGitEnv() : process.env, maxBuffer: 64 * 1024 * 1024 });
  if (r.error) return { status: null, stdout: '', stderr: String(r.error.code || r.error.message) };
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function git(exec, root, args) {
  return exec('git', hardenGitArgs(args), { cwd: root });
}

function fileDigest(root, rel) {
  try {
    const st = fs.lstatSync(path.join(root, rel));
    if (!st.isFile()) return null;
    return digestOfBytes(fs.readFileSync(path.join(root, rel)));
  } catch { return null; }
}

function tool(exec, root, cmd, args) {
  const r = exec(cmd, args, { cwd: root });
  if (r.status !== 0 || !r.stdout.trim()) return unknown(`${cmd} ${args.join(' ')} did not report a version${r.stderr ? ` (${String(r.stderr).trim().split('\n')[0]})` : ''}`);
  return known(r.stdout.trim().split('\n')[0]);
}

/** Parse `git status --porcelain=v1 -z`. Renames carry two paths; both are reported. */
export function parsePorcelain(out) {
  const parts = out.split('\0').filter(Boolean);
  const entries = [];
  for (let i = 0; i < parts.length; i++) {
    const rec = parts[i];
    const xy = rec.slice(0, 2); const p = rec.slice(3);
    if (xy[0] === 'R' || xy[0] === 'C') { entries.push({ path: p, xy }); i++; if (parts[i]) entries.push({ path: parts[i], xy: 'R-from' }); continue; }
    entries.push({ path: p, xy });
  }
  return entries;
}

function classify(xy) {
  if (xy === '??') return 'untracked';
  if (xy.includes('D')) return 'deleted';
  if (xy === 'R-from') return 'renamed-from';
  if (xy[0] !== ' ' && xy[1] !== ' ') return 'staged-and-modified';
  if (xy[0] !== ' ') return 'staged';
  return 'modified';
}

function collectSourceFiles(exec, root) {
  const r = git(exec, root, ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', ...SOURCE_DIGEST_PATHS]);
  if (r.status !== 0) return null;
  return [...new Set(r.stdout.split('\0').filter(Boolean))].sort();
}

/**
 * Capture the baseline. `exec` and `now` are injectable so tests can prove the
 * unknown paths and stay clock-free; `inventory`/`mappings` default to the real ones.
 */
export function captureBaseline({
  root, exec = defaultExec, now = () => new Date().toISOString(),
  inventory = CAPABILITY_INVENTORY, mappings = RECOMMENDATION_MAPPINGS,
} = {}) {
  if (!root) throw new Error('captureBaseline needs a root');
  const problems = [];
  const abs = path.resolve(root);

  // ---- git state
  const headR = git(exec, abs, ['rev-parse', 'HEAD']);
  const head = headR.status === 0 && /^[0-9a-f]{40,64}$/.test(headR.stdout.trim()) ? known(headR.stdout.trim()) : unknown('no git HEAD could be resolved');
  const branchR = git(exec, abs, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const branch = branchR.status === 0 ? known(branchR.stdout.trim()) : unknown('branch could not be resolved');
  const statusR = git(exec, abs, ['status', '--porcelain=v1', '-z', '--untracked-files=all']);
  let dirty;
  if (statusR.status !== 0) dirty = unknown('git status failed; the worktree state is not known');
  else {
    dirty = known(parsePorcelain(statusR.stdout).map(e => ({ path: e.path, change: classify(e.xy), digest: fileDigest(abs, e.path) })).sort((x, y) => x.path.localeCompare(y.path)));
  }

  // ---- digests
  const files = collectSourceFiles(exec, abs);
  let sourceDigest;
  if (!files) sourceDigest = unknown('source file list unavailable (git ls-files failed)');
  else {
    const lines = [];
    for (const f of files) { const d = fileDigest(abs, f); if (d) lines.push(`${f}\0${d}`); }
    sourceDigest = known({ digest: digestOf(lines), fileCount: lines.length, covers: [...SOURCE_DIGEST_PATHS] });
  }
  const bundleBytes = fileDigest(abs, BUNDLE_PATH);
  let bundle;
  if (!bundleBytes) bundle = unknown(`${BUNDLE_PATH} is not present in this checkout`);
  else {
    let sidecar = null;
    try { sidecar = fs.readFileSync(path.join(abs, `${BUNDLE_PATH}.sha256`), 'utf8').trim().split(/\s+/)[0] || null; } catch { /* no sidecar */ }
    bundle = known({ path: BUNDLE_PATH, digest: bundleBytes, sidecar: sidecar ? `sha256:${sidecar}` : null, sidecarMatches: sidecar ? `sha256:${sidecar}` === bundleBytes : null });
  }

  // ---- versions
  let pkg = null;
  try { pkg = JSON.parse(fs.readFileSync(path.join(abs, 'scanner/package.json'), 'utf8')); } catch { /* reported below */ }
  const versions = {
    node: known(process.version),
    platform: known(`${process.platform}-${process.arch}`),
    scanner: pkg?.version ? known(pkg.version) : unknown('scanner/package.json has no readable version'),
    npm: tool(exec, abs, 'npm', ['--version']),
    git: tool(exec, abs, 'git', ['--version']),
    python3: tool(exec, abs, 'python3', ['--version']),
  };

  // ---- feature entry points that exist now
  const entryPoints = {
    packageBin: pkg?.bin ? known(pkg.bin) : unknown('no bin map in scanner/package.json'),
    npmScripts: pkg?.scripts ? known(Object.keys(pkg.scripts).sort()) : unknown('no scripts in scanner/package.json'),
    commands: listDir(abs, 'commands', f => f.endsWith('.md')),
    hooks: listDir(abs, 'hooks', f => f.endsWith('.js') && !f.endsWith('.test.js')),
  };

  // ---- seven recommendation mappings, each extension point verified
  const recMappings = mappings.map(m => {
    const ext = m.extensionPoints.map(p => ({ path: p, exists: exists(abs, p) }));
    for (const e of ext) if (!e.exists) problems.push(`mapping ${m.n}: extension point '${e.path}' does not exist`);
    return { n: m.n, title: m.title, priority: m.priority, slice: m.slice, extensionPoints: ext };
  });

  // ---- capability inventory
  const capabilities = inventory.map(c => {
    const sourceDigests = {}; const evidenceDigests = {};
    for (const p of c.source) sourceDigests[p] = pathDigest(abs, p);
    for (const e of c.evidence) evidenceDigests[e.path] = pathDigest(abs, e.path);
    const missing = [...Object.entries(sourceDigests), ...Object.entries(evidenceDigests)].filter(([, d]) => d === null).map(([p]) => p);
    for (const p of missing) problems.push(`capability '${c.id}': path '${p}' does not exist`);
    const symbols = c.entryPoints.map(ep => ({ ...ep, exported: symbolExported(abs, ep.path, ep.symbol) }));
    for (const s of symbols) if (!s.exported) problems.push(`capability '${c.id}': '${s.symbol}' is not exported by ${s.path}`);
    if (!CAPABILITY_STATUSES.includes(c.status)) problems.push(`capability '${c.id}': status '${c.status}' is not one of ${CAPABILITY_STATUSES.join(', ')}`);
    if (c.status === 'implemented' && c.gap) problems.push(`capability '${c.id}': 'implemented' must not carry a gap`);
    if (c.status !== 'implemented' && !c.gap) problems.push(`capability '${c.id}': '${c.status}' must say what is missing`);
    if (!c.source.length) problems.push(`capability '${c.id}': no source path`);
    if (!c.evidence.length) problems.push(`capability '${c.id}': no test or artifact`);
    return {
      id: c.id, workstream: c.workstream, title: c.title, status: c.status, gap: c.gap, prd: c.prd,
      source: c.source, evidence: c.evidence, entryPoints: symbols,
      pathsMissing: missing, sourceDigests, evidenceDigests,
    };
  });

  const manifest = {
    schema: BASELINE_SCHEMA, schemaVersion: BASELINE_VERSION,
    repository: { head, branch, dirtyPaths: dirty },
    digests: { source: sourceDigest, bundle },
    versions, entryPoints,
    recommendationMappings: recMappings,
    capabilities,
    problems,
  };
  manifest.baselineId = digestOf(manifest);
  // The capture time is real but is not part of the identity.
  manifest.capturedAt = now();
  return manifest;
}

function exists(root, rel) { try { fs.accessSync(path.join(root, rel)); return true; } catch { return false; } }

function listDir(root, rel, keep) {
  try { return known(fs.readdirSync(path.join(root, rel)).filter(keep).sort()); } catch { return unknown(`${rel}/ is not readable`); }
}

/** Digest of a file, or of a directory as the digest of its files' digests; null when the path does not exist. */
function pathDigest(root, rel) {
  const p = path.join(root, rel);
  let st;
  try { st = fs.lstatSync(p); } catch { return null; }
  if (st.isFile()) return digestOfBytes(fs.readFileSync(p));
  if (!st.isDirectory()) return null;
  const lines = [];
  const walk = (d, prefix) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((x, y) => x.name.localeCompare(y.name))) {
      if (e.name === STATE_DIR_NAME || e.name === 'node_modules') continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full, `${prefix}${e.name}/`);
      else if (e.isFile()) lines.push(`${prefix}${e.name}\0${digestOfBytes(fs.readFileSync(full))}`);
    }
  };
  walk(p, '');
  return digestOf(lines);
}

function symbolExported(root, rel, symbol) {
  try {
    const text = fs.readFileSync(path.join(root, rel), 'utf8');
    return new RegExp(`^\\s*export\\s+(?:async\\s+)?(?:function\\*?|const|class)\\s+${symbol}\\b`, 'm').test(text)
      || new RegExp(`^\\s*export\\s*\\{[^}]*\\b${symbol}\\b`, 'm').test(text);
  } catch { return false; }
}

/**
 * Compare a recorded baseline with a fresh capture of the same checkout.
 *
 * - A capability is `invalidated` when any source or evidence file it cites
 *   changed or disappeared; it lists the changed paths. Otherwise it stays `valid`.
 * - Dirty paths are classified: `retained` (already dirty at baseline, same bytes),
 *   `changedSince` (dirty at baseline, bytes now different), `introduced` (newly
 *   dirty), `resolved` (was dirty, now clean). Each is split into `applicable`
 *   (cited by some capability) and `unrelated`. Unrelated changes never invalidate
 *   anything and are always disclosed.
 */
export function evaluateBaseline(recorded, current) {
  const capabilities = recorded.capabilities.map(rc => {
    const cc = current.capabilities.find(x => x.id === rc.id);
    const changed = [];
    if (!cc) changed.push('(capability no longer inventoried)');
    else {
      for (const [p, d] of Object.entries(rc.sourceDigests)) if (cc.sourceDigests[p] !== d) changed.push(p);
      for (const [p, d] of Object.entries(rc.evidenceDigests)) if (cc.evidenceDigests[p] !== d) changed.push(p);
    }
    return { id: rc.id, status: rc.status, validity: changed.length ? 'invalidated' : 'valid', changedPaths: changed };
  });

  const cited = new Set();
  const citedDirs = [];
  for (const c of recorded.capabilities) for (const p of [...c.source, ...c.evidence.map(e => e.path)]) { cited.add(p); citedDirs.push(p.replace(/\/$/, '')); }
  const isApplicable = (p) => citedDirs.some(c => p === c || p.startsWith(`${c}/`));

  const rd = recorded.repository.dirtyPaths; const cd = current.repository.dirtyPaths;
  const userChanges = { comparable: rd.status === 'known' && cd.status === 'known', retained: [], changedSince: [], introduced: [], resolved: [] };
  if (userChanges.comparable) {
    const before = new Map(rd.value.map(e => [e.path, e])); const after = new Map(cd.value.map(e => [e.path, e]));
    const tag = (e, kind) => ({ path: e.path, change: e.change, scope: isApplicable(e.path) ? 'applicable' : 'unrelated', kind });
    for (const [p, e] of after) {
      const b = before.get(p);
      if (!b) userChanges.introduced.push(tag(e, 'introduced'));
      else if (b.digest === e.digest) userChanges.retained.push(tag(e, 'retained'));
      else userChanges.changedSince.push(tag(e, 'changedSince'));
    }
    for (const [p, e] of before) if (!after.has(p)) userChanges.resolved.push(tag(e, 'resolved'));
  }

  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  return {
    baselineId: recorded.baselineId,
    headChanged: !same(recorded.repository.head, current.repository.head),
    bundleChanged: !same(recorded.digests.bundle, current.digests.bundle),
    sourceChanged: !same(recorded.digests.source, current.digests.source),
    capabilities,
    invalidated: capabilities.filter(c => c.validity === 'invalidated').map(c => c.id),
    valid: capabilities.filter(c => c.validity === 'valid').map(c => c.id),
    userChanges,
  };
}

/** A manifest is only as trustworthy as its own shape: check statuses, unknown-marking and the id. */
export function validateBaseline(m) {
  const errors = [];
  if (!m || typeof m !== 'object') return { ok: false, errors: ['not an object'] };
  if (m.schema !== BASELINE_SCHEMA) errors.push('schema mismatch');
  if (!/^1\./.test(String(m.schemaVersion))) errors.push('unsupported schemaVersion');
  const check = (name, v) => {
    if (!v || (v.status !== 'known' && v.status !== 'unknown')) errors.push(`${name}: not a known/unknown fact`);
    else if (v.status === 'unknown' && (!v.reason || 'value' in v)) errors.push(`${name}: an unknown fact needs a reason and no value`);
    else if (v.status === 'known' && !('value' in v)) errors.push(`${name}: a known fact needs a value`);
  };
  check('head', m.repository?.head); check('branch', m.repository?.branch); check('dirtyPaths', m.repository?.dirtyPaths);
  check('digests.source', m.digests?.source); check('digests.bundle', m.digests?.bundle);
  for (const [k, v] of Object.entries(m.versions || {})) check(`versions.${k}`, v);
  if (!Array.isArray(m.recommendationMappings) || m.recommendationMappings.length !== 7) errors.push('exactly seven recommendation mappings are required');
  for (const c of m.capabilities || []) if (!CAPABILITY_STATUSES.includes(c.status)) errors.push(`capability ${c.id}: bad status`);
  const { baselineId, capturedAt, ...rest } = m;
  if (baselineId !== digestOf(rest)) errors.push('baselineId does not match the manifest content');
  return { ok: errors.length === 0, errors };
}

/**
 * Where a baseline may be written. Never inside an application source root, and
 * never over a file git tracks (which would change application source).
 */
export function assertSafeOutput(root, outPath, exec = defaultExec) {
  const abs = path.resolve(root); const out = path.resolve(outPath);
  const rel = path.relative(abs, out);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return { ok: true, reason: 'outside the repository' };
  const inSource = SOURCE_ROOTS.some(r => rel === r || rel.startsWith(`${r}${path.sep}`));
  if (inSource) return { ok: false, reason: `'${rel}' is inside an application source root` };
  const tracked = git(exec, abs, ['ls-files', '--error-unmatch', '--', rel]);
  if (tracked.status === 0) return { ok: false, reason: `'${rel}' is tracked by git; refusing to overwrite application files` };
  return { ok: true, reason: 'untracked path outside the source roots' };
}
