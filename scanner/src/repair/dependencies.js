// Dependency repair (verified-remediation PRD FR-14, M4-02, M4-03), npm first.
//
// Two verifier-side halves, both over the EXACT files of a revision (the manifest and the lockfile are candidate files like any other):
//
//   checkResolution   the `dependency-resolved` obligation. The lockfile must agree with the manifest (every manifest dependency is in
//                     the lockfile's root entry with the same range, and the installed version satisfies it: AC-14.2, a manifest-only
//                     edit with a stale lockfile fails); every resolved package must come from the declared package sources with the
//                     integrity the lockfile records, re-hashed here from the tarball bytes (provenance); every package's own
//                     dependencies must resolve (Node's lookup, walking up) to a version satisfying their range; and NO resolved
//                     instance of the advisory's package, direct or transitive, may be in the vulnerable range (AC-14.3).
//   materialize       builds node_modules for the application oracles from the lockfile: each entry's tarball is read from the package
//                     sources, its integrity checked, and its files extracted through the hardened tar reader. The application then
//                     runs against the packages a candidate actually resolves to (AC-14.1, AC-14.4: an API change without the source
//                     adaptation, or a behaviour-breaking upgrade, fails the behaviour obligations).
//
// Limits, stated: npm lockfile version 2 or 3 only; packages come from local tarballs declared by the profile (no registry, no network,
// so a package source outside the project is a named limitation); the package manager itself is not executed and no install script
// runs; ranges are the npm subset `x.y.z`, `^`, `~`, `>`, `>=`, `<`, `<=`, `=`, space for AND and `||` for OR (no prerelease logic,
// no `x` wildcards beyond `*`).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { decompressIfGzip, readTarEntries } from '../artifact/safe-tar.js';

const parseV = (v) => { const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(v).trim()); return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null; };
const cmp = (a, b) => { for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; };

function comparators(part) {
  const out = [];
  for (const tok of part.trim().split(/\s+/).filter(Boolean)) {
    if (tok === '*' || tok === 'x') continue;
    const m = /^(\^|~|>=|<=|>|<|=)?(v?\d+\.\d+\.\d+)$/.exec(tok);
    if (!m) return null;
    const v = parseV(m[2]); const op = m[1] || '=';
    if (op === '^') { out.push(['>=', v]); out.push(['<', v[0] > 0 ? [v[0] + 1, 0, 0] : v[1] > 0 ? [0, v[1] + 1, 0] : [0, 0, v[2] + 1]]); }
    else if (op === '~') { out.push(['>=', v]); out.push(['<', [v[0], v[1] + 1, 0]]); }
    else out.push([op, v]);
  }
  return out;
}

/** Does `version` satisfy `range`? null when the range is outside the supported subset (never guessed). */
export function satisfies(version, range) {
  const v = parseV(version);
  if (!v || typeof range !== 'string') return null;
  let any = false;
  for (const part of range.split('||')) {
    const cs = comparators(part);
    if (cs === null) return null;
    if (cs.every(([op, w]) => { const c = cmp(v, w); return op === '=' ? c === 0 : op === '>' ? c > 0 : op === '>=' ? c >= 0 : op === '<' ? c < 0 : c <= 0; })) any = true;
  }
  return any;
}

const nameOf = (p) => { const i = p.lastIndexOf('node_modules/'); return i < 0 ? null : p.slice(i + 'node_modules/'.length); };

/** Node's lookup from a package path: the nearest node_modules/<name> walking up. */
function resolveFrom(pkgs, fromPath, name) {
  let base = fromPath;
  for (;;) {
    const cand = `${base ? `${base}/` : ''}node_modules/${name}`;
    if (pkgs[cand]) return cand;
    if (!base) return null;
    const i = base.lastIndexOf('/node_modules/');
    base = i < 0 ? '' : base.slice(0, i);
  }
}

function tarballFor(root, dep, entry) {
  const r = String(entry.resolved || '');
  if (!r.startsWith('file:')) return { problem: `${entry.name || '?'}: resolved from ${r.split(':')[0] || 'nowhere'}, not from the declared package sources` };
  const rel = path.posix.normalize(r.slice(5));
  const sources = path.posix.normalize(dep.sources).replace(/\/$/, '');
  if (rel.startsWith('..') || path.isAbsolute(rel) || !(rel === sources || rel.startsWith(`${sources}/`))) return { problem: `${rel}: outside the declared package sources ${sources}` };
  let bytes;
  try {
    const abs = path.join(root, rel);
    const realRoot = fs.realpathSync(root);
    if (!fs.realpathSync(abs).startsWith(realRoot + path.sep)) return { problem: `${rel}: a link out of the project` };
    bytes = fs.readFileSync(abs);
  } catch { return { problem: `${rel}: the tarball is missing` }; }
  const m = /^sha512-([A-Za-z0-9+/=]+)$/.exec(String(entry.integrity || ''));
  if (!m) return { problem: `${rel}: the lockfile records no sha512 integrity` };
  if (crypto.createHash('sha512').update(bytes).digest('base64') !== m[1]) return { problem: `${rel}: the tarball does not match the integrity the lockfile records` };
  return { bytes, rel };
}

function readPackage(bytes) {
  const files = {};
  for (const e of readTarEntries(decompressIfGzip(bytes))) {
    if (e.unsafe || !['0', '\0', ''].includes(e.typeflag) || !e.name.startsWith('package/')) continue;
    files[e.name.slice('package/'.length)] = e.data.toString('utf8');
  }
  return files;
}

/**
 * The `dependency-resolved` check over one revision's files. Pure apart from reading the declared tarballs under `root`.
 * @returns {{ok:boolean, problems:string[], vulnerable:object[], resolved:object[]}}
 */
export function checkResolution(root, dep, files) {
  const problems = []; const vulnerable = [];
  let manifest; let lock;
  try { manifest = JSON.parse(files['package.json']); } catch { return { ok: false, problems: ['package.json is missing or not JSON'], vulnerable, resolved: [] }; }
  try { lock = JSON.parse(files['package-lock.json']); } catch { return { ok: false, problems: ['package-lock.json is missing or not JSON'], vulnerable, resolved: [] }; }
  if (![2, 3].includes(lock.lockfileVersion) || !lock.packages || typeof lock.packages !== 'object') return { ok: false, problems: ['only npm lockfile versions 2 and 3 are supported'], vulnerable, resolved: [] };
  const pkgs = lock.packages;
  const rootDeps = manifest.dependencies || {};
  const lockRoot = pkgs['']?.dependencies || {};
  for (const [name, range] of Object.entries(rootDeps)) {
    if (lockRoot[name] !== range) problems.push(`the lockfile is stale: package.json asks for ${name}@${range}, the lockfile root records ${lockRoot[name] ?? 'nothing'}`);
    const at = pkgs[`node_modules/${name}`];
    if (!at) { problems.push(`${name} is not installed by the lockfile`); continue; }
    const s = /^file:/.test(range) ? null : satisfies(at.version, range);
    if (s === false) problems.push(`the lockfile installs ${name}@${at.version}, which does not satisfy ${range}`);
  }
  for (const name of Object.keys(lockRoot)) if (!(name in rootDeps)) problems.push(`the lockfile root records ${name}, which package.json no longer asks for`);
  const resolved = [];
  for (const [p, entry] of Object.entries(pkgs)) {
    if (!p) continue;
    const name = nameOf(p);
    if (!name || typeof entry?.version !== 'string') { problems.push(`${p}: not a package entry`); continue; }
    const t = tarballFor(root, dep, { ...entry, name });
    if (t.problem) problems.push(t.problem);
    else {
      try {
        const meta = JSON.parse(readPackage(t.bytes)['package.json'] || '{}');
        if (meta.name !== name || meta.version !== entry.version) problems.push(`${p}: the tarball holds ${meta.name}@${meta.version}, the lockfile says ${name}@${entry.version}`);
      } catch (e) { problems.push(`${p}: the tarball could not be read (${String(e.message).slice(0, 80)})`); }
    }
    for (const [d, range] of Object.entries(entry.dependencies || {})) {
      const at = resolveFrom(pkgs, p, d);
      if (!at) problems.push(`${name}@${entry.version} needs ${d}@${range}, which nothing installs`);
      else if (satisfies(pkgs[at].version, range) === false) problems.push(`${name}@${entry.version} needs ${d}@${range} and resolves ${pkgs[at].version}`);
    }
    resolved.push({ path: p, name, version: entry.version });
    if (name === dep.package) {
      const bad = satisfies(entry.version, dep.vulnerable);
      if (bad === null) problems.push(`the vulnerable range ${dep.vulnerable} is outside the supported range syntax`);
      if (bad) vulnerable.push({ path: p, version: entry.version, transitive: p !== `node_modules/${name}` });
    }
  }
  for (const v of vulnerable) problems.push(`${v.transitive ? 'a transitive' : 'the direct'} ${dep.package}@${v.version} at ${v.path} is in the vulnerable range ${dep.vulnerable} (${dep.advisory})`);
  return { ok: problems.length === 0, problems, vulnerable, resolved };
}

/**
 * The files the application oracles run: the revision's application files plus node_modules built from its lockfile. Entries that do
 * not verify are left out (the resolution obligation reports them); the application then fails to load what it needs.
 */
export function materialize(root, dep, files, { maxFiles = 400, maxBytes = 4 << 20 } = {}) {
  const out = { ...files };
  let lock;
  try { lock = JSON.parse(files['package-lock.json']); } catch { return out; }
  let n = 0; let bytes = 0;
  for (const [p, entry] of Object.entries(lock?.packages || {})) {
    const name = nameOf(p);
    if (!p || !name) continue;
    const t = tarballFor(root, dep, { ...entry, name });
    if (t.problem) continue;
    for (const [rel, text] of Object.entries(readPackage(t.bytes))) {
      const norm = path.posix.normalize(rel);
      if (norm.startsWith('..') || path.posix.isAbsolute(norm)) continue;
      if (++n > maxFiles || (bytes += text.length) > maxBytes) throw new Error('the resolved packages exceed the verifier\'s size bound');
      out[`${p}/${norm}`] = text;
    }
  }
  return out;
}
