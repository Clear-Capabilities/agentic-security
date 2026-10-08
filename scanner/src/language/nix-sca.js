// Patch-aware Nix vulnerability matching and reachability (NIX-009).
//
// Input is a resolved closure (nix-closure.js), pinned advisory records, optional nixpkgs metadata
// (`knownVulnerabilities`, license, identifiers) and optional overlay/patch evidence from the Nix source.
// The outcome for each component is one of:
//
//   affected             the upstream version is inside an affected range and nothing excuses it
//   fixed                the version/revision is at or past the fix (or the overlay moves it there)
//   backported-verified  in range, BUT a patch whose content hash is in the advisory's fix-patch list is applied
//   possibly-affected    in range with an UNVERIFIED patch claim (a CVE-named patch file proves nothing),
//                        or only a range overlap, or an ambiguous identity with a plausible match
//   candidate            the upstream identity is ambiguous or name-only: matches are leads, never verdicts
//   unknown              no usable version/identity/feed: this is NEVER reported as "not affected"
//   not-affected         mapped, version outside every affected range
//
// A nixpkgs commit, a store hash or a derivation hash is never an upstream software version and is never
// put in a query. Wrapped Haskell packages reuse the Hackage matcher (PVP ordering). Inclusion in the
// runtime closure and Haskell import/API reachability are separate evidence tiers: a store path or a build
// input can establish the first and never the second.

import { AdvisoryDb, matchComponent as matchHackage, reachability as hackageReachability, licensePolicy, hackagePurl, normalizeAdvisory } from './haskell-sca.js';
import { parseVersion as parsePvp } from './haskell-manifests.js';
import { advisorySeverity, NO_RATING_BASIS } from './cvss.js';
import { parseNix } from './nix-parser.js';
import { cpeKey } from './nix-advisory-feed.js';

export const NIX_SCA_VERSION = 'nix-sca/1';
const HEX40 = /^[0-9a-f]{40}$/i;
const STORE_HASH = /^[0-9a-df-np-sv-z]{32}$/;
const UPSTREAM_NOISE = /^(?:git|unstable|master|main|HEAD|latest|unstable-\d{4}-\d{2}-\d{2})$/i;

/** A nixpkgs revision, a store-path hash or a date stamp is not an upstream version. */
export function isNotAnUpstreamVersion(v) {
  if (typeof v !== 'string' || !v) return 'no version';
  if (HEX40.test(v)) return 'a 40-hex string is a git revision (for example a nixpkgs commit), not a software version';
  if (STORE_HASH.test(v)) return 'a 32-character base32 string is a store-path hash, not a software version';
  if (/^[0-9a-f]{7,12}$/i.test(v) && /[a-f]/i.test(v)) return 'a short hexadecimal string is a revision, not a software version';
  if (UPSTREAM_NOISE.test(v)) return `"${v}" is a moving ref, not a software version`;
  if (!/\d/.test(v)) return `"${v}" has no numeric component`;
  return null;
}

// ── generic version ordering for upstream software ───────────────────────────
const PRE = /^(?:alpha|beta|rc|pre|dev|snapshot|a|b)$/i;
function tokens(v) { return String(v).toLowerCase().replace(/^v(?=\d)/, '').split(/[^a-z0-9]+/).filter(Boolean).flatMap((t) => t.match(/\d+|[a-z]+/g) || []); }
export function compareUpstream(a, b) {
  const x = tokens(a), y = tokens(b);
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const p = x[i], q = y[i];
    if (p === undefined) return PRE.test(q) ? 1 : (/^\d+$/.test(q) && Number(q) === 0 ? 0 : -1);
    if (q === undefined) return PRE.test(p) ? -1 : (/^\d+$/.test(p) && Number(p) === 0 ? 0 : 1);
    const pn = /^\d+$/.test(p), qn = /^\d+$/.test(q);
    if (pn && qn) { const d = Number(p) - Number(q); if (d) return d < 0 ? -1 : 1; continue; }
    if (pn !== qn) { if (!pn && PRE.test(p)) return -1; if (!qn && PRE.test(q)) return 1; return pn ? 1 : -1; }
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

// ── advisories ───────────────────────────────────────────────────────────────
const sha = (s) => String(s || '').toLowerCase().replace(/^sha256[-:]/, '');
function eventsToRanges(events) {
  // `introduced_excluding` is not an OSV event: it carries an exclusive start bound (the NVD live feed has them), so 8.0 is not in "after 8.0".
  const out = []; let lo = null; let loExc = false;
  for (const e of events || []) {
    if ('introduced' in e) { lo = e.introduced === '0' ? null : e.introduced; loExc = false; }
    else if ('introduced_excluding' in e) { lo = e.introduced_excluding; loExc = true; }
    else if ('fixed' in e) { out.push({ lo, loExc, hi: e.fixed, hiInc: false }); lo = null; loExc = false; }
    else if ('last_affected' in e) { out.push({ lo, loExc, hi: e.last_affected, hiInc: true }); lo = null; loExc = false; }
  }
  if (events && events.some((e) => 'introduced' in e || 'introduced_excluding' in e) && (lo !== null || !out.length || !events.some((e) => 'fixed' in e || 'last_affected' in e))) out.push({ lo, loExc, hi: null, hiInc: false });
  return out;
}
const inRange = (v, r) => (r.lo === null || (r.loExc ? compareUpstream(v, r.lo) > 0 : compareUpstream(v, r.lo) >= 0)) && (r.hi === null || (r.hiInc ? compareUpstream(v, r.hi) <= 0 : compareUpstream(v, r.hi) < 0));

/** Normalize a non-Hackage OSV-style record into what Nix matching needs. */
export function normalizeGenericAdvisory(rec) {
  if (!rec || typeof rec.id !== 'string') return null;
  const aliases = [...new Set((rec.aliases || []).filter((x) => typeof x === 'string'))];
  const affected = [];
  for (const a of rec.affected || []) {
    if (!a || !a.package) continue;
    const ranges = (a.ranges || []).filter((r) => r.type !== 'GIT').flatMap((r) => eventsToRanges(r.events));
    const git = (a.ranges || []).filter((r) => r.type === 'GIT').map((r) => ({ repo: r.repo || null, events: r.events || [] }));
    affected.push({
      ecosystem: a.package.ecosystem || null, name: a.package.name || null, purl: a.package.purl || null, cpe: a.package.cpe || null,
      ranges, versions: Array.isArray(a.versions) ? a.versions : [], git,
      fixedIn: [...new Set((a.ranges || []).flatMap((r) => (r.events || []).filter((e) => 'fixed' in e).map((e) => e.fixed)))],
      fixPatches: ((a.database_specific && a.database_specific.fix_patches) || (rec.database_specific && rec.database_specific.fix_patches) || []).map((p) => ({ name: p.name || null, sha256: p.sha256 ? sha(p.sha256) : null })),
    });
  }
  return { id: rec.id, severityInfo: advisorySeverity(rec), ids: [rec.id, ...aliases], cves: [rec.id, ...aliases].filter((x) => /^CVE-/.test(x)), summary: rec.summary || '', withdrawn: rec.withdrawn || null, published: rec.published || null, modified: rec.modified || null, references: (rec.references || []).map((r) => r.url).filter(Boolean), affected };
}

export class NixAdvisoryData {
  constructor({ records = [], hackage = null, source = 'records', generatedAt = null, now = Date.now(), maxAgeDays = 30, covered = null } = {}) {
    this.source = source; this.generatedAt = generatedAt; this.maxAgeDays = maxAgeDays; this.now = now;
    // `covered` is {'vendor:product': ISO time that CPE identity was last fully read from the live feed}. null means the snapshot makes no
    // per-identity claim (a hand-built or operator-pinned snapshot) and is matched exactly as it always was.
    this.covered = covered && typeof covered === 'object' ? covered : null;
    this.records = records.map(normalizeGenericAdvisory).filter(Boolean);
    this.hackage = hackage;                      // an AdvisoryDb (HS-009) for wrapped Haskell packages
    const gen = generatedAt ? Date.parse(generatedAt) : NaN;
    this.ageDays = Number.isFinite(gen) ? (now - gen) / 86400000 : null;
    this.stale = this.ageDays === null ? true : this.ageDays > maxAgeDays;
    this.feed = { source, generatedAt, status: this.stale ? 'stale-cache' : 'current', records: this.records.length };
  }
  /** 'covered' | 'uncovered' | 'stale' for a CPE identity ('vendor:product'); always 'covered' when the snapshot makes no per-identity claim. */
  cpeCoverage(key) {
    if (!this.covered) return 'covered';
    const t = Date.parse(this.covered[key]);
    if (!Number.isFinite(t)) return 'uncovered';
    return (this.now - t) / 86400000 > this.maxAgeDays ? 'stale' : 'covered';
  }
}

// ── upstream identity ────────────────────────────────────────────────────────
export const HASKELL_ENV_HINTS = ['libraryHaskellDepends', 'setupHaskellDepends', 'executableHaskellDepends', 'isLibrary', 'isExecutable', 'enableSeparateDataOutput', 'compilerName', 'enableLibraryProfiling'];
function purlFromUrl(u) {
  const m = /^https?:\/\/(?:www\.)?github\.com\/([^/]+)\/([^/#?]+?)(?:\.git)?(?:\/|$)/.exec(u || '');
  if (m) return { purl: `pkg:github/${m[1].toLowerCase()}/${m[2].toLowerCase()}`, host: 'github' };
  const g = /^https?:\/\/gitlab\.com\/([^/]+)\/([^/#?]+?)(?:\.git)?(?:\/|$)/.exec(u || '');
  if (g) return { purl: `pkg:gitlab/${g[1].toLowerCase()}/${g[2].toLowerCase()}`, host: 'gitlab' };
  return null;
}

/**
 * The identity a component can be matched under. Never invents authority: `explicit` needs the package
 * metadata to say so, `src-derived` needs a recognised source host, anything else is `name-only`.
 */
export function upstreamIdentity(node, drvEnv, meta, overlay) {
  const cands = [];
  const version = (overlay && overlay.version) || node.version;
  const vguard = isNotAnUpstreamVersion(version);
  const base = { pname: node.pname, version: vguard ? null : version, versionRejected: vguard || null, versionSource: overlay && overlay.version ? 'overlay' : node.versionAuthority };
  const isHs = drvEnv && HASKELL_ENV_HINTS.some((k) => k in drvEnv);
  if (isHs && node.pname) cands.push({ ecosystem: 'Hackage', name: node.pname, purl: hackagePurl(node.pname, base.version), authority: 'explicit', basis: 'Haskell build attributes in the derivation' });
  const ids = meta && meta.identifiers ? meta.identifiers : null;
  if (ids && typeof ids.purl === 'string') cands.push({ purl: ids.purl, authority: 'explicit', basis: 'meta.identifiers.purl' });
  const cpes = ids ? [].concat(ids.cpe || [], ids.possibleCPEs || [], ids.v1 && ids.v1.cpeParts ? [ids.v1.cpeParts] : []).filter(Boolean) : [];
  const cpeStrings = cpes.map(cpeKey).filter(Boolean);   // 'vendor:product' from a full CPE string or a {vendor, product} part; malformed values are dropped
  const uniqueCpe = [...new Set(cpeStrings)];
  if (uniqueCpe.length === 1 && ids && ids.cpe && !ids.possibleCPEs) cands.push({ cpe: uniqueCpe[0], authority: 'explicit', basis: 'meta.identifiers.cpe' });
  else for (const c of uniqueCpe) cands.push({ cpe: c, authority: 'candidate', basis: uniqueCpe.length > 1 ? 'one of several possible CPEs' : 'possible CPE' });
  for (const u of (node.upstream && node.upstream.urls) || []) { const p = purlFromUrl(u); if (p) cands.push({ purl: p.purl, authority: 'src-derived', basis: `source URL host ${p.host}` }); }
  if (meta && meta.homepage) { const p = purlFromUrl(meta.homepage); if (p) cands.push({ purl: p.purl, authority: 'src-derived', basis: 'meta.homepage' }); }
  if (!cands.some((c) => c.authority === 'explicit' || c.authority === 'src-derived') && node.pname) cands.push({ name: node.pname, authority: 'name-only', basis: 'store/derivation name only' });
  const uniq = []; const seen = new Set();
  for (const c of cands) { const k = JSON.stringify([c.ecosystem, c.name, c.purl, c.cpe, c.authority]); if (!seen.has(k)) { seen.add(k); uniq.push(c); } }
  const strong = uniq.filter((c) => c.authority === 'explicit' || c.authority === 'src-derived');
  const distinctTargets = new Set(strong.map((c) => c.purl || c.cpe || `${c.ecosystem}:${c.name}`));
  return { ...base, candidates: uniq, ambiguous: distinctTargets.size > 1 || (strong.length === 0 && uniq.length > 1) || uniq.some((c) => c.authority === 'candidate'), authority: strong.length && distinctTargets.size === 1 && !uniq.some((c) => c.authority === 'candidate') ? strong[0].authority : (uniq[0] ? 'name-only' : 'none'), haskell: !!isHs };
}

/**
 * The upstream identities of every dependency in a closure, in the form the matcher will use, so a pre-scan step can ask a live feed
 * about exactly what the matcher will look up. `cpes` holds 'vendor:product' keys (explicit and candidate); a component with none is
 * listed in `withoutCpe` so the caller can say what a CPE-keyed feed cannot cover.
 */
export function closureIdentities({ closure, drvEnv = {}, meta = {}, overlays = {} } = {}) {
  const nodes = (closure && closure.nodes) || [];
  const roots = new Set((closure && closure.roots) || []);
  const subjects = new Map();
  for (const n of nodes) {
    if (n.kind !== 'output' || roots.has(n.id)) continue;
    const key = n.deriver || n.id;
    if (!subjects.has(key)) subjects.set(key, { drv: n.deriver || null, node: n });
    const s = subjects.get(key);
    if (n.outputName === 'out' || (s.node.outputName !== 'out' && n.scopes.includes('runtime'))) s.node = n;
  }
  const cpes = new Set(); const withoutCpe = [];
  for (const s of subjects.values()) {
    const node = s.node;
    const ident = upstreamIdentity(node, (s.drv && drvEnv[s.drv]) || null, meta[node.pname] || meta[node.storeName] || null, overlays[node.pname] || null);
    const mine = ident.candidates.filter((c) => c.cpe).map((c) => c.cpe);
    if (mine.length) mine.forEach((k) => cpes.add(k)); else if (node.pname) withoutCpe.push(node.pname);
  }
  return { cpes: [...cpes].sort(), withoutCpe: [...new Set(withoutCpe)].sort() };
}

// ── overlays and patches ─────────────────────────────────────────────────────
const segName = (s) => (s && s.kind === 'static' ? s.name : null);
const unparen = (n) => { let x = n; while (x && x.type === 'paren') x = x.expr; return x; };

/** pname -> {version?, patches:[{name,source,sha256?,url?}], file, line} from overlay `overrideAttrs` calls. */
export function overlayEvidence(files) {
  const out = {};
  for (const [file, text] of Object.entries(files || {})) {
    if (!/\.nix$/i.test(file) || typeof text !== 'string') continue;
    const parse = parseNix(text, { file });
    if (!parse.ast) continue;
    const stack = [parse.ast];
    while (stack.length) {
      const n = stack.pop();
      if (!n || typeof n !== 'object') continue;
      if (n.type === 'attrset') {
        for (const b of n.bindings || []) {
          if (b.kind !== 'attr' || !b.value) continue;
          const key = (b.path || []).map(segName);
          if (key.length !== 1 || !key[0]) continue;
          const call = unparen(b.value);
          if (!call || call.type !== 'app') continue;
          const fn = unparen(call.fn);
          const last = fn && fn.type === 'select' ? segName(fn.attrpath[fn.attrpath.length - 1]) : null;
          if (last !== 'overrideAttrs') continue;
          const rec = out[key[0]] || (out[key[0]] = { patches: [], file, line: b.span ? b.span.startLine : null, mechanism: 'overlay-overrideAttrs' });
          let body = unparen(call.arg);
          while (body && body.type === 'lambda') body = unparen(body.body);
          if (body && body.type === 'attrset') {
            for (const ob of body.bindings) {
              if (ob.kind !== 'attr') continue;
              const k = (ob.path || []).map(segName).join('.');
              if (k === 'version') { const v = unparen(ob.value); if (v && v.literal !== undefined) rec.version = v.literal; }
              if (k === 'patches') collectPatches(ob.value, rec.patches);
            }
          }
        }
      }
      for (const k of Object.keys(n)) { const c = n[k]; if (c && typeof c === 'object') { if (Array.isArray(c)) stack.push(...c); else stack.push(c); } }
    }
  }
  return out;
}
function collectPatches(node, acc) {
  const n = unparen(node);
  if (!n) return;
  if (n.type === 'list') for (const it of n.items) collectPatches(it, acc);
  else if (n.type === 'binop') { collectPatches(n.left, acc); collectPatches(n.right, acc); }
  else if (n.type === 'path' && n.literal) acc.push({ name: String(n.literal).replace(/^.*\//, ''), source: 'path', sha256: null });
  else if (n.type === 'app') {
    const flat = []; let f = n; while (f && f.type === 'app') { flat.unshift(f.arg); f = unparen(f.fn); }
    const nm = f && f.type === 'select' ? segName(f.attrpath[f.attrpath.length - 1]) : (f && f.type === 'ident' ? f.name : null);
    if (nm === 'fetchpatch' || nm === 'fetchpatch2') {
      const a = unparen(flat[0]); let url = null; let hash = null;
      if (a && a.type === 'attrset') for (const b of a.bindings) { if (b.kind !== 'attr') continue; const k = (b.path || []).map(segName).join('.'); const v = unparen(b.value); if (k === 'url' && v) url = v.literal ?? null; if ((k === 'sha256' || k === 'hash') && v) hash = v.literal ?? null; }
      acc.push({ name: url ? url.replace(/[?#].*$/, '').replace(/^.*\//, '') : 'fetchpatch', source: 'fetchpatch', url, sha256: hash ? sha(hash) : null });
    }
  }
}

// ── matching ─────────────────────────────────────────────────────────────────
const CVE_IN_NAME = /CVE-\d{4}-\d{4,}/i;
function patchEvidence(patches, advisory, aff) {
  const claims = []; let verified = null;
  const fixHashes = new Set((aff.fixPatches || []).map((p) => p.sha256).filter(Boolean));
  const fixNames = new Set((aff.fixPatches || []).map((p) => p.name).filter(Boolean));
  for (const p of patches || []) {
    const cveInName = (CVE_IN_NAME.exec(p.name || '') || [])[0];
    const namesThis = cveInName && advisory.ids.some((i) => i.toUpperCase() === cveInName.toUpperCase());
    if (p.sha256 && fixHashes.has(sha(p.sha256))) { verified = verified || { patch: p.name, by: 'content hash matches an advisory fix patch' }; continue; }
    if (namesThis || (p.name && fixNames.has(p.name))) claims.push({ patch: p.name, claim: namesThis ? `named after ${cveInName}` : 'name matches an advisory fix patch', verified: false, why: p.sha256 ? 'its content hash is not one the advisory lists' : 'no content hash: a file name proves nothing about what the patch does' });
  }
  return { verified, claims };
}

function genericMatch(adv, aff, ident, node, patches) {
  const v = ident.version;
  const out = { status: 'unknown', reason: '' };
  if (aff.git.length && node.upstream && node.upstream.rev) {
    const rev = node.upstream.rev.toLowerCase();
    const fixed = aff.git.flatMap((g) => g.events.filter((e) => 'fixed' in e).map((e) => String(e.fixed).toLowerCase()));
    const listed = new Set([...(aff.versions || []).map((x) => String(x).toLowerCase()), ...aff.git.flatMap((g) => g.events.filter((e) => 'introduced' in e || 'last_affected' in e).map((e) => String(e.introduced ?? e.last_affected).toLowerCase()))]);
    if (fixed.includes(rev)) return { status: 'fixed', reason: 'the source revision is the advisory fix commit' };
    if ([...listed].includes(rev)) return { status: 'affected', reason: 'the source revision is an affected commit listed by the advisory' };
    out.reason = 'the source revision is neither the fix nor a listed affected commit; commit ordering is not available, so no verdict';
    if (!v) return out;
  }
  if (!v) return { status: 'unknown', reason: ident.versionRejected || 'no upstream version' };
  let inside = aff.ranges.some((r) => inRange(v, r));
  if (!inside && aff.versions.some((x) => compareUpstream(v, x) === 0)) inside = true;
  if (!aff.ranges.length && !aff.versions.length) return { status: 'unknown', reason: 'the advisory has no version information for this package' };
  if (inside) return { status: 'affected', reason: 'the version is inside an affected range' };
  if ((aff.fixedIn || []).some((f) => compareUpstream(v, f) >= 0)) return { status: 'fixed', reason: `the version is at or past the fix (${aff.fixedIn.join(', ')})` };
  return { status: 'not-affected', reason: 'the version is outside every affected range' };
}

/**
 * @param {{closure: object, data: NixAdvisoryData|null, meta?: Record<string,object>, overlays?: object,
 *          haskellUsage?: {imports: object[], callees: Set<string>}, services?: Array<{service:string, packages:string[]}>,
 *          symbols?: Record<string,string[]>, kev?: Set<string>|null, epss?: Record<string,number>|null,
 *          licensePolicy?: object, drvEnv?: Record<string,object>}} opts
 *   meta is keyed by derivation name or pname; drvEnv by derivation path (the env block of the drv show export).
 */
export function matchNixVulnerabilities(opts = {}) {
  const { closure, data = null, meta = {}, overlays = {}, haskellUsage = null, services = [], symbols = {}, kev = null, epss = null } = opts;
  const findings = []; const statuses = [];
  const feed = data ? data.feed : { source: null, generatedAt: null, status: 'feed-unavailable', records: 0 };
  const nodes = (closure && closure.nodes) || [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  // one subject per derivation: its outputs are one build
  const subjects = new Map();
  const roots = new Set((closure && closure.roots) || []);
  for (const n of nodes) {
    if (n.kind !== 'output' || roots.has(n.id)) continue;      // the target itself is not a dependency of itself
    const key = n.deriver || n.id;
    if (!subjects.has(key)) subjects.set(key, { drv: n.deriver || null, outputs: [], node: n });
    const s = subjects.get(key); s.outputs.push(n);
    if (n.outputName === 'out' || (s.node.outputName !== 'out' && n.scopes.includes('runtime'))) s.node = n;
  }
  const summary = { components: 0, matched: 0, mappedNoMatch: 0, unmapped: 0, candidates: 0 };
  for (const s of subjects.values()) {
    const node = s.node;
    const env = (opts.drvEnv && s.drv && opts.drvEnv[s.drv]) || null;
    const m = meta[node.pname] || meta[node.storeName] || null;
    const ov = overlays[node.pname] || null;
    const patches = [...(node.patches || []), ...((ov && ov.patches) || [])];
    const ident = upstreamIdentity(node, env, m, ov);
    summary.components++;
    const nixBuild = { derivation: s.drv, outputs: s.outputs.map((o) => ({ name: o.outputName, path: o.id })), system: node.system, storeHash: node.hash, patches: patches.map((p) => ({ name: p.name, source: p.source || 'derivation', sha256: p.sha256 || null })), overlay: ov ? { file: ov.file, line: ov.line, versionOverride: ov.version || null } : null, scopes: node.scopes };
    const inclusion = node.scopes.includes('runtime') ? 'runtime-closure' : (node.scopes.length ? 'build-only' : 'unknown');
    const svc = services.filter((x) => x.packages.some((p) => p === node.pname || p === node.storeName)).map((x) => x.service);
    const tiers = { inclusion, services: svc, reachability: { import: 'unknown', function: 'unknown', basis: 'a store path or a build input proves inclusion only, never that code is called' } };
    const base = { name: node.pname, version: ident.version, nixBuild, identity: { authority: ident.authority, candidates: ident.candidates, versionSource: ident.versionSource, versionRejected: ident.versionRejected }, tiers, feed };
    const push = (st, extra = {}) => statuses.push({ ...base, status: st.status, reason: st.reason, ...extra });

    // knownVulnerabilities marked by nixpkgs themselves
    const kvs = (m && Array.isArray(m.knownVulnerabilities) ? m.knownVulnerabilities : []).filter((x) => typeof x === 'string');
    for (const kv of kvs) findings.push(finding(base, { id: `nixpkgs:knownVulnerabilities:${node.pname}`, ids: [kv.match(CVE_IN_NAME) ? kv.match(CVE_IN_NAME)[0] : `nixpkgs-known-vulnerable:${node.pname}`], summary: kv }, 'affected', 'nixpkgs marks this package with knownVulnerabilities', { source: 'nixpkgs-meta', ghc: false }, { kev, epss }));
    if (!data) { push({ status: 'unknown', reason: 'no advisory feed was supplied: absence of a match is not a clean result' }); summary.unmapped++; continue; }
    if (ident.versionRejected && !ident.haskell && !(node.upstream && node.upstream.rev)) { push({ status: 'unknown', reason: `the version cannot be queried: ${ident.versionRejected}` }); summary.unmapped++; continue; }

    let matched = false; let mapped = false; let hackageGap = null;
    // Hackage (wrapped Haskell packages): reuse the PVP matcher
    if (ident.haskell && data.hackage && ident.version && parsePvp(ident.version) && data.hackage.coverage(node.pname) !== 'covered') {
      // A feed that never looked up this package (or looked too long ago) says nothing about it: that is unknown, not "no advisory matches".
      hackageGap = data.hackage.coverage(node.pname) === 'stale'
        ? 'the Hackage advisory feed last covered this package longer ago than its age limit: the absence of a match is not a clean result'
        : 'the Hackage advisory feed never covered this package: the absence of a match is not a clean result';
    } else if (ident.haskell && data.hackage && ident.version && parsePvp(ident.version)) {
      mapped = true;
      for (const { adv, aff } of data.hackage.forPackage(node.pname)) {
        if (adv.withdrawn) continue;
        const r = matchHackage(aff, { name: node.pname, version: ident.version });
        if (r.status === 'not-affected') continue;
        const pe = patchEvidence(patches, { ids: adv.ids }, { fixPatches: [] });
        const st = decide(r, pe, ident);
        matched = true;
        if (haskellUsage) { const rr = hackageReachability(node.pname, haskellUsage.imports, haskellUsage.callees, symbols[adv.id] || null); tiers.reachability = { import: rr.import, function: rr.function, basis: rr.reason }; }
        findings.push(finding({ ...base, tiers: { ...tiers } }, { id: adv.canonicalId, ids: adv.ids, summary: adv.summary, cves: adv.cveAliases, severityInfo: adv.severityInfo }, st.status, st.reason, { source: data.hackage.source, ecosystem: 'Hackage', fixedIn: aff.fixedIn, patchEvidence: pe }, { kev, epss }));
      }
    }
    // generic records by PURL / CPE; only authoritative identities are matched, candidates are leads
    for (const adv of data.records) {
      if (adv.withdrawn) continue;
      for (const aff of adv.affected) {
        const target = ident.candidates.find((c) => (c.purl && aff.purl && c.purl === aff.purl) || (c.cpe && aff.cpe && c.cpe === aff.cpe) || (c.name && aff.name && !aff.purl && !aff.cpe && c.name === aff.name && c.authority === 'name-only') || (c.ecosystem === 'Hackage' && aff.ecosystem === 'Hackage' && c.name === aff.name));
        if (!target) continue;
        if (aff.ecosystem === 'Hackage') continue;                   // handled above
        mapped = mapped || target.authority === 'explicit' || target.authority === 'src-derived';
        const gm = genericMatch(adv, aff, ident, node, patches);
        if (gm.status === 'not-affected' && target.authority !== 'candidate' && target.authority !== 'name-only') continue;
        const pe = patchEvidence(patches, adv, aff);
        let st = gm.status === 'affected' ? decide(gm, pe, ident) : gm;
        // identity gate: only an authoritative, unambiguous identity may produce a firm verdict
        if (target.authority === 'candidate' || target.authority === 'name-only' || ident.ambiguous) {
          st = { status: gm.status === 'affected' || gm.status === 'possibly-affected' ? 'candidate' : (gm.status === 'fixed' ? 'candidate' : gm.status === 'not-affected' ? 'unknown' : gm.status), reason: `${gm.reason}; the upstream identity is ${target.authority === 'candidate' ? 'ambiguous (several possible CPEs)' : 'name-only'}, so this is a lead, not a verdict` };
          summary.candidates++;
        }
        matched = true;
        findings.push(finding({ ...base, tiers: { ...tiers } }, adv, st.status, st.reason, { source: data.source, ecosystem: aff.ecosystem, fixedIn: aff.fixedIn, patchEvidence: pe, identityBasis: target.basis, identityAuthority: target.authority }, { kev, epss }));
      }
    }
    // A feed that records coverage per CPE identity can only vouch for the identities it actually read. Without a covered, explicit,
    // unambiguous CPE identity, "no match" says nothing, so it is unknown (never not-affected).
    let covGap = null;
    if (!hackageGap && data.covered) {
      const cpeCands = ident.candidates.filter((c) => c.cpe);
      const firm = !ident.ambiguous ? cpeCands.find((c) => c.authority === 'explicit') : null;
      if (firm) {
        const cv = data.cpeCoverage(firm.cpe);
        if (cv === 'covered') mapped = true;
        else covGap = cv === 'stale' ? `the live advisory feed last read ${firm.cpe} longer ago than its age limit: the absence of a match is not a clean result` : `the live advisory feed never read ${firm.cpe} (it was not queried or the query did not complete): the absence of a match is not a clean result`;
      } else if (!matched && !cpeCands.length) covGap = 'the live advisory feed is keyed by CPE and this component declares no CPE identity (a source URL or purl alone is not something it can look up): the absence of a match is not a clean result';
    }
    if (matched) summary.matched++;
    if (covGap) { if (!matched) summary.unmapped++; push({ status: 'unknown', reason: covGap }, { identityMapped: false, feedCoverage: 'incomplete' }); }
    else if (matched) { /* findings above are the result */ }
    else if (hackageGap) { summary.unmapped++; push({ status: 'unknown', reason: hackageGap }, { identityMapped: false, feedCoverage: 'incomplete' }); }
    else if (mapped) { summary.mappedNoMatch++; push({ status: 'not-affected', reason: 'mapped to an upstream identity and no advisory in the supplied feed matches this version' }, { identityMapped: true }); }
    else { summary.unmapped++; push({ status: 'unknown', reason: ident.ambiguous ? 'the upstream identity is ambiguous: no verdict' : 'the upstream identity could not be mapped to anything an advisory is keyed by' }, { identityMapped: false }); }
  }
  return { version: NIX_SCA_VERSION, findings, statuses, feed, summary, licenses: licenseReport(nodes.filter((n) => !roots.has(n.id)), meta, opts.licensePolicy) };
}

function decide(r, pe, ident) {
  if (r.status === 'possibly-affected') return { status: 'possibly-affected', reason: r.reason };
  if (pe.verified) return { status: 'backported-verified', reason: `in the affected range, but ${pe.verified.by} (${pe.verified.patch})` };
  if (pe.claims.length) return { status: 'possibly-affected', reason: `in the affected range with an UNVERIFIED patch claim (${pe.claims[0].patch}: ${pe.claims[0].why})` };
  return { status: 'affected', reason: r.reason };
}

function finding(base, adv, status, reason, extra, { kev, epss }) {
  const cves = adv.cves || (adv.ids || []).filter((x) => /^CVE-/.test(x));
  const kevHit = cves.length ? (kev ? cves.some((c) => kev.has(c)) : 'unknown') : 'not-applicable';
  const ep = cves.map((c) => epss && epss[c]).filter((x) => typeof x === 'number');
  const level = { affected: 'high', 'possibly-affected': 'medium', candidate: 'low', 'backported-verified': 'info', fixed: 'info', unknown: 'low', 'not-affected': 'info' }[status] || 'low';
  // The advisory's own rating applies only where the package is judged vulnerable; the other statuses keep their fixed,
  // lower levels (a verified backport must never be raised by the upstream score).
  const sev = adv.severityInfo || { level: null, score: null, basis: NO_RATING_BASIS };
  const rated = !!sev.level && (status === 'affected' || status === 'possibly-affected');
  return {
    type: 'vulnerable_dep', ecosystem: 'nix', language: 'nix', capability: 'sca', analysisKind: 'application', evidenceKind: 'closure',
    name: base.name, version: base.version, osvId: adv.id, ids: adv.ids || [adv.id], cveAliases: cves, summary: adv.summary || '',
    status, matchStatus: status, matchReason: reason, severity: rated ? sev.level : level, severityBasis: rated ? sev.basis : sev.level ? `the match status "${status}" fixes this level; the advisory rating (${sev.basis}) is not applied` : sev.basis, ...(rated ? { severityScore: sev.score } : {}),
    nixBuild: base.nixBuild, identity: base.identity, tiers: base.tiers, feed: base.feed,
    kev: kevHit, epss: ep.length ? Math.max(...ep) : 'unknown',
    fixedIn: extra.fixedIn || [], patchEvidence: extra.patchEvidence || { verified: null, claims: [] }, dataSource: { feed: extra.source || base.feed.source, ecosystem: extra.ecosystem || null, identityBasis: extra.identityBasis || null, identityAuthority: extra.identityAuthority || null, feedStatus: base.feed.status },
    file: null, line: null, vuln: `Vulnerable package in the Nix closure (${status})`, cwe: 'CWE-1104', parser: 'NIX-SCA', family: 'sca',
    description: `${base.name}${base.version ? ` ${base.version}` : ''} (${adv.id}): ${reason}.`,
    remediation: (extra.fixedIn && extra.fixedIn.length) ? `Update ${base.name} to ${extra.fixedIn.join(' or ')} (override the input or overlay), then regenerate the closure export.` : 'No fixed version is recorded in the advisory data.',
    confidence: status === 'affected' ? 0.85 : status === 'possibly-affected' ? 0.5 : 0.3,
  };
}

function licenseReport(nodes, meta, policy) {
  const comps = nodes.filter((n) => n.kind === 'output' && (n.outputName === 'out' || !n.outputName)).map((n) => ({ name: n.pname, version: n.version }));
  const md = {};
  for (const c of comps) { const m = meta[c.name]; if (m && m.license) md[c.name] = { license: typeof m.license === 'string' ? m.license : (m.license.spdxId || m.license.shortName || null) }; }
  return licensePolicy(comps, md, policy);
}

export { AdvisoryDb, normalizeAdvisory };
