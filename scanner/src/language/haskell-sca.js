// Hackage advisories, reachability and supply-chain policy (HS-009).
//
// Identity. Packages are queried under the exact OSV ecosystem string `Hackage` (the wire value, not the
// word "Haskell") and named by `pkg:hackage/<name>@<version>`. HSEC advisory ids are preserved even when no
// CVE alias exists; KEV/EPSS enrichment is keyed on CVE aliases only and an absent value is `unknown`, never
// zero risk.
//
// Versions. Cabal/PVP versions have any number of components and compare with missing trailing components
// as 0 (1.2 == 1.2.0.0). They are never fed to a SemVer matcher: advisory ranges and declared ranges are both
// turned into intervals over that ordering and intersected exactly.
//
// Honest statuses. A component is `affected` only when its RESOLVED version is inside an affected interval;
// a declared range that merely overlaps one is `possibly-affected`; no resolved version and no usable range is
// `unknown`; a missing/stale feed is reported as such and is never read as clean. A withdrawn advisory is
// listed, never matched. Compiler-provided (GHC boot) packages are a separate scope: their advisories are
// resolved against the compiler version, not treated as an ordinary dependency.
//
// Nothing here uses the network by itself: callers supply records (a pinned snapshot, a cache, or an OSV
// response). The wire query is built here so its exact shape is testable.

import { createHash, createVerify } from 'node:crypto';
import { parseVersion, compareVersions, parseVersionRange, caretUpperBound } from './haskell-manifests.js';

export const HS_SCA_VERSION = 'haskell-sca/1';
export const OSV_ECOSYSTEM = 'Hackage';

/** Packages whose version is fixed by the compiler: advisories on them are GHC-component advisories. */
export const GHC_BOOT_PACKAGES = Object.freeze(new Set([
  'base', 'ghc-prim', 'ghc-bignum', 'template-haskell', 'ghc', 'ghc-boot', 'ghc-boot-th', 'integer-gmp', 'rts', 'ghc-heap', 'libiserv', 'ghci',
  'array', 'binary', 'bytestring', 'containers', 'deepseq', 'directory', 'exceptions', 'filepath', 'haskeline', 'mtl', 'parsec', 'pretty',
  'process', 'stm', 'text', 'time', 'transformers', 'unix', 'xhtml', 'terminfo', 'Cabal', 'Cabal-syntax',
]));

export const hackagePurl = (name, version) => `pkg:hackage/${encodeURIComponent(name).replace(/%2D/g, '-')}${version ? `@${encodeURIComponent(version)}` : ''}`;

/** The exact JSON body an OSV `/v1/query` takes for one component. */
export function osvWireQuery(name, version) {
  return { package: { name, ecosystem: OSV_ECOSYSTEM }, ...(version ? { version } : {}) };
}

// ── intervals over the PVP ordering ──────────────────────────────────────────
// { lo: version|null (-inf), loInc, hi: version|null (+inf), hiInc }
const ZERO = [0n];
const iv = (lo, loInc, hi, hiInc) => ({ lo, loInc, hi, hiInc });
const cmp = (a, b) => compareVersions(a, b);

function normalizeIntervals(list) {
  return list.filter((x) => !isEmpty(x));
}
function isEmpty(x) {
  if (x.lo === null || x.hi === null) return false;
  const c = cmp(x.lo, x.hi);
  return c > 0 || (c === 0 && !(x.loInc && x.hiInc));
}
export function intersectIntervals(a, b) {
  let lo = a.lo, loInc = a.loInc;
  if (b.lo !== null && (lo === null || cmp(b.lo, lo) > 0 || (cmp(b.lo, lo) === 0 && !b.loInc))) { lo = b.lo; loInc = b.loInc; }
  let hi = a.hi, hiInc = a.hiInc;
  if (b.hi !== null && (hi === null || cmp(b.hi, hi) < 0 || (cmp(b.hi, hi) === 0 && !b.hiInc))) { hi = b.hi; hiInc = b.hiInc; }
  return iv(lo, loInc, hi, hiInc);
}
export function intervalsOverlap(A, B) {
  for (const a of A) for (const b of B) if (!isEmpty(intersectIntervals(a, b))) return true;
  return false;
}
export function intervalsContain(A, version) {
  const v = typeof version === 'string' ? parseVersion(version) : version;
  if (!v) return null;
  return A.some((x) => (x.lo === null || cmp(v, x.lo) > 0 || (cmp(v, x.lo) === 0 && x.loInc)) && (x.hi === null || cmp(v, x.hi) < 0 || (cmp(v, x.hi) === 0 && x.hiInc)));
}

/** Declared Cabal range AST -> intervals. Returns null when the range cannot be understood. */
export function rangeToIntervals(text) {
  const parsed = parseVersionRange(text);
  if (!parsed.ok) return null;
  const go = (n) => {
    switch (n.t) {
      case 'any': return [iv(null, false, null, false)];
      case 'none': return [];
      case 'and': { const out = []; for (const a of go(n.l)) for (const b of go(n.r)) out.push(intersectIntervals(a, b)); return normalizeIntervals(out); }
      case 'or': return [...go(n.l), ...go(n.r)];
      case 'cmp': {
        const v = n.version.map((x) => BigInt(x));
        switch (n.op) {
          case '>=': return [iv(v, true, null, false)];
          case '>': return [iv(v, false, null, false)];
          case '<': return [iv(ZERO, true, v, false)];
          case '<=': return [iv(ZERO, true, v, true)];
          case '^>=': return [iv(v, true, caretUpperBound(v), false)];
          case '==':
            if (n.wildcard) { const up = [...v]; up[up.length - 1] = up[up.length - 1] + 1n; return [iv(v, true, up, false)]; }
            return [iv(v, true, v, true)];
          default: throw new Error(`unsupported operator ${n.op}`);
        }
      }
      default: throw new Error(`unsupported range node ${n.t}`);
    }
  };
  try { return go(parsed.ast); } catch { return null; }
}

// ── advisory records ─────────────────────────────────────────────────────────
function eventsToIntervals(events) {
  const out = [];
  let lo = null; let loInc = true;
  for (const e of events || []) {
    if ('introduced' in e) { lo = e.introduced === '0' ? ZERO : parseVersion(e.introduced); loInc = true; if (!lo) return null; }
    else if ('fixed' in e) { const hi = parseVersion(e.fixed); if (!hi || !lo) return null; out.push(iv(lo, loInc, hi, false)); lo = null; }
    else if ('last_affected' in e) { const hi = parseVersion(e.last_affected); if (!hi || !lo) return null; out.push(iv(lo, loInc, hi, true)); lo = null; }
    else if ('limit' in e) { const hi = parseVersion(e.limit); if (!hi || !lo) return null; out.push(iv(lo, loInc, hi, false)); lo = null; }
  }
  if (lo) out.push(iv(lo, loInc, null, false));      // introduced with no fix: open ended
  return normalizeIntervals(out);
}

/**
 * Normalise one OSV record. Unusable pieces are recorded in `problems`, never thrown.
 */
export function normalizeAdvisory(rec) {
  const problems = [];
  if (!rec || typeof rec !== 'object' || typeof rec.id !== 'string') return { id: null, problems: ['not an OSV record'], affected: [] };
  const aliases = [...new Set((rec.aliases || []).filter((x) => typeof x === 'string'))];
  const ids = [rec.id, ...aliases];
  const canonicalId = ids.find((x) => /^HSEC-/.test(x)) || ids.find((x) => /^GHSA-/.test(x)) || ids.find((x) => /^CVE-/.test(x)) || rec.id;
  const affected = [];
  for (const a of rec.affected || []) {
    if (!a || !a.package || a.package.ecosystem !== OSV_ECOSYSTEM) continue;
    const ranges = (a.ranges || []).filter((r) => r.type === 'ECOSYSTEM');
    let intervals = [];
    let ok = ranges.length > 0;
    for (const r of ranges) { const x = eventsToIntervals(r.events); if (x === null) { ok = false; problems.push(`unparseable range in ${a.package.name}`); } else intervals.push(...x); }
    if (!ranges.length && Array.isArray(a.versions) && a.versions.length) {
      intervals = a.versions.map((v) => { const p = parseVersion(v); return p ? iv(p, true, p, true) : null; }).filter(Boolean);
      ok = intervals.length > 0;
    }
    const unfixed = intervals.some((x) => x.hi === null);
    affected.push({ name: a.package.name, purl: a.package.purl || hackagePurl(a.package.name), intervals, ok, unfixed, fixedIn: fixedVersions(ranges), ghcComponent: GHC_BOOT_PACKAGES.has(a.package.name) });
  }
  return {
    id: rec.id, canonicalId, ids, cveAliases: ids.filter((x) => /^CVE-/.test(x)), ghsaAliases: ids.filter((x) => /^GHSA-/.test(x)),
    summary: rec.summary || '', details: rec.details || '', published: rec.published || null, modified: rec.modified || null,
    withdrawn: rec.withdrawn || null, references: (rec.references || []).map((r) => r.url).filter(Boolean),
    severity: rec.severity || [], affected, problems,
  };
}
const fixedVersions = (ranges) => [...new Set((ranges || []).flatMap((r) => (r.events || []).filter((e) => 'fixed' in e).map((e) => e.fixed)))];

// ── advisory database (pinned snapshot / records) ────────────────────────────
export class AdvisoryDb {
  constructor({ records = [], source = 'records', generatedAt = null, now = Date.now(), maxAgeDays = 30, integrity = null, covered = null } = {}) {
    this.source = source;
    // `covered` is {package: ISO time it was last queried}. null means the snapshot makes no per-package claim (a hand-built or
    // operator-pinned snapshot): every package is then treated as covered, as it always was.
    this.covered = covered && typeof covered === 'object' ? covered : null;
    this.now = now;
    this.generatedAt = generatedAt;
    this.integrity = integrity;
    this.problems = [];
    this.advisories = [];
    this.byPackage = new Map();
    for (const rec of records) {
      const n = normalizeAdvisory(rec);
      if (!n.id) { this.problems.push(...n.problems); continue; }
      this.problems.push(...n.problems.map((p) => `${n.id}: ${p}`));
      this.advisories.push(n);
      for (const a of n.affected) { if (!this.byPackage.has(a.name)) this.byPackage.set(a.name, []); this.byPackage.get(a.name).push({ adv: n, aff: a }); }
    }
    const gen = generatedAt ? Date.parse(generatedAt) : NaN;
    this.ageDays = Number.isFinite(gen) ? (now - gen) / 86400000 : null;
    this.stale = this.ageDays === null ? true : this.ageDays > maxAgeDays;
    this.maxAgeDays = maxAgeDays;
  }
  forPackage(name) { return this.byPackage.get(name) || []; }
  /** 'covered' | 'uncovered' | 'stale' for a package; always 'covered' when the snapshot makes no per-package claim. */
  coverage(name) {
    if (!this.covered) return 'covered';
    const t = Date.parse(this.covered[name]);
    if (!Number.isFinite(t)) return 'uncovered';
    return (this.now - t) / 86400000 > this.maxAgeDays ? 'stale' : 'covered';
  }
}

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const canon = (v) => JSON.stringify(v, Object.keys(v).sort());

/**
 * A snapshot is `{schema, generatedAt, records:[OSV...], recordHashes:{id:sha256}}`. It is accepted only if
 * every record matches its recorded hash AND (when given) the whole snapshot matches `pinnedSha256` and/or an
 * RSA/Ed25519 signature verifies. Anything else is refused, with the reason.
 */
export function loadAdvisorySnapshot(snapshot, { pinnedSha256 = null, signature = null, publicKeyPem = null, now = Date.now(), maxAgeDays = 30 } = {}) {
  const refuse = (reason) => ({ ok: false, reason, db: null });
  if (!snapshot || typeof snapshot !== 'object' || !Array.isArray(snapshot.records)) return refuse('not an advisory snapshot');
  for (const rec of snapshot.records) {
    const want = snapshot.recordHashes && snapshot.recordHashes[rec.id];
    if (!want) return refuse(`record ${rec.id} has no recorded hash`);
    if (sha256(JSON.stringify(rec)) !== want) return refuse(`record ${rec.id} does not match its recorded hash`);
  }
  const body = snapshotBody(snapshot);
  const digest = sha256(body);
  if (pinnedSha256 && digest !== pinnedSha256) return refuse('snapshot hash does not match the pinned value');
  let signed = false;
  if (signature || publicKeyPem) {
    if (!(signature && publicKeyPem)) return refuse('signature and public key must be supplied together');
    try {
      const v = createVerify('sha256'); v.update(body);
      if (!v.verify(publicKeyPem, Buffer.from(signature, 'base64'))) return refuse('signature does not verify');
      signed = true;
    } catch (e) { return refuse(`signature check failed: ${e.message}`); }
  }
  const db = new AdvisoryDb({ records: snapshot.records, source: 'snapshot', generatedAt: snapshot.generatedAt, now, maxAgeDays, integrity: { sha256: digest, hashPinned: !!pinnedSha256, signed }, covered: snapshot.covered || null });
  return { ok: true, db, digest };
}

export function buildSnapshot(records, generatedAt) {
  const recordHashes = Object.fromEntries(records.map((r) => [r.id, sha256(JSON.stringify(r))]));
  return { schema: 1, generatedAt, records, recordHashes };
}
// `covered` joins the hashed body only when present, so a snapshot without it keeps the digest it always had.
export const snapshotBody = (s) => JSON.stringify({ schema: s.schema, generatedAt: s.generatedAt, records: s.records, recordHashes: s.recordHashes, ...(s.covered ? { covered: s.covered } : {}) });

// ── matching ─────────────────────────────────────────────────────────────────
/**
 * @param {{name:string, version?:string|null, declaredRange?:string|null}} comp
 * @returns {{status:'affected'|'not-affected'|'possibly-affected'|'unknown', reason:string}}
 */
export function matchComponent(aff, comp) {
  if (!aff.ok) return { status: 'unknown', reason: 'the advisory range could not be understood' };
  if (comp.version) {
    const inside = intervalsContain(aff.intervals, comp.version);
    if (inside === null) return { status: 'unknown', reason: `"${comp.version}" is not a Cabal version` };
    return inside ? { status: 'affected', reason: 'the resolved version is inside an affected range' } : { status: 'not-affected', reason: 'the resolved version is outside every affected range' };
  }
  if (comp.declaredRange) {
    const declared = rangeToIntervals(comp.declaredRange);
    if (declared === null) return { status: 'unknown', reason: 'the declared range could not be parsed' };
    if (!declared.length) return { status: 'unknown', reason: 'the declared range admits no version' };
    const overlap = intervalsOverlap(declared, aff.intervals);
    if (!overlap) return { status: 'not-affected', reason: 'no version allowed by the declared range is affected' };
    const subset = declared.every((d) => aff.intervals.some((a) => !isEmpty(intersectIntervals(d, a)) && containsInterval(a, d)));
    return subset ? { status: 'affected', reason: 'every version allowed by the declared range is affected' } : { status: 'possibly-affected', reason: 'the declared range allows both affected and unaffected versions; no resolved version is known' };
  }
  return { status: 'unknown', reason: 'neither a resolved version nor a declared range is known' };
}
function containsInterval(outer, inner) {
  const loOk = outer.lo === null || (inner.lo !== null && (cmp(inner.lo, outer.lo) > 0 || (cmp(inner.lo, outer.lo) === 0 && (outer.loInc || !inner.loInc))));
  const hiOk = outer.hi === null || (inner.hi !== null && (cmp(inner.hi, outer.hi) < 0 || (cmp(inner.hi, outer.hi) === 0 && (outer.hiInc || !inner.hiInc))));
  return loOk && hiOk;
}

/**
 * Evaluate components against an advisory database.
 * @param {Array<{name, version?, declaredRange?, scope?, target?, manifest?, line?, kind?}>} components
 * @param {AdvisoryDb|null} db  null = no feed at all
 * @param {{kev?: Set<string>|null, epss?: Record<string,number>|null, imports?: object}} [opts]
 */
export function evaluateComponents(components, db, opts = {}) {
  const findings = [];
  const statuses = [];
  const feed = !db ? { status: 'feed-unavailable', detail: 'no advisory data was supplied; absence of findings does NOT mean the dependencies are clean' }
    : db.stale ? { status: 'stale-cache', detail: `advisory data is ${db.ageDays === null ? 'of unknown age' : `${Math.round(db.ageDays)} days old`} (limit ${db.maxAgeDays})` }
    : { status: 'current', detail: `${db.advisories.length} advisories from ${db.source}` };
  for (const comp of components) {
    const base = { name: comp.name, version: comp.version || null, declaredRange: comp.declaredRange || null, scope: comp.scope || null, target: comp.target || null, purl: hackagePurl(comp.name, comp.version || null) };
    if (!db) { statuses.push({ ...base, status: 'feed-unavailable' }); continue; }
    const cov = db.coverage(comp.name);
    if (cov !== 'covered') { statuses.push({ ...base, status: cov === 'stale' ? 'feed-stale' : 'feed-incomplete', reason: cov === 'stale' ? 'this package was last looked up longer ago than the feed age limit; the absence of advisories is not evidence' : 'the advisory feed never covered this package; the absence of advisories is not evidence' }); continue; }
    const hits = db.forPackage(comp.name);
    if (!hits.length) { statuses.push({ ...base, status: 'no-advisories', feed: feed.status }); continue; }
    let any = false;
    for (const { adv, aff } of hits) {
      if (adv.withdrawn) { statuses.push({ ...base, status: 'withdrawn', advisory: adv.canonicalId, withdrawn: adv.withdrawn }); continue; }
      const m = matchComponent(aff, comp);
      const ghc = aff.ghcComponent;
      statuses.push({ ...base, status: ghc && m.status !== 'not-affected' ? `ghc-component:${m.status}` : m.status, advisory: adv.canonicalId, reason: m.reason, ghcComponent: ghc });
      if (m.status === 'not-affected') continue;
      any = true;
      const kevHit = adv.cveAliases.length ? (opts.kev ? adv.cveAliases.some((c) => opts.kev.has(c)) : 'unknown') : 'not-applicable';
      const epssVals = adv.cveAliases.map((c) => opts.epss && opts.epss[c]).filter((x) => typeof x === 'number');
      findings.push({
        type: 'vulnerable_dep', ecosystem: 'hackage', name: comp.name, version: comp.version || null, declaredRange: comp.declaredRange || null,
        osvId: adv.canonicalId, ids: adv.ids, cveAliases: adv.cveAliases, ghsaAliases: adv.ghsaAliases,
        summary: adv.summary, fixedIn: aff.fixedIn, unfixed: aff.unfixed, references: adv.references.slice(0, 5),
        severity: 'medium', severityBasis: 'the advisory carries no severity rating',
        matchStatus: m.status, matchReason: m.reason, resolution: comp.version ? 'resolved' : (comp.declaredRange ? 'declared-range' : 'none'),
        scope: comp.scope || null, target: comp.target || null, purl: base.purl, ghcComponent: ghc,
        ...(ghc ? { remediation: `${comp.name} is provided by the compiler: upgrade GHC (the fix is in ${comp.name} ${aff.fixedIn.join(', ') || '(no fixed version published)'}), not a Cabal dependency bound.` } : { remediation: aff.fixedIn.length ? `Upgrade ${comp.name} to ${aff.fixedIn.join(' or ')}.` : `No fixed version of ${comp.name} is published; remove or replace the dependency.` }),
        kev: kevHit, epss: epssVals.length ? Math.max(...epssVals) : 'unknown',
        file: comp.manifest || null, line: comp.line || null, versionSource: comp.versionSource || null,
        dataSource: { feed: db.source, generatedAt: db.generatedAt, integrity: db.integrity, feedStatus: feed.status },
        language: 'haskell', capability: 'sca', analysisKind: 'application', evidenceKind: 'manifest',
        confidence: m.status === 'affected' ? 0.9 : 0.5,
        ...(m.status === 'possibly-affected' ? { uncertainty: [{ kind: 'unresolved-import', detail: 'no resolved version: only a declared range is known (generate a Cabal plan or a Stack export to resolve it)' }] } : {}),
      });
    }
    if (!any && !statuses.some((s) => s.name === comp.name && s.status !== 'not-affected')) statuses.push({ ...base, status: 'not-affected' });
  }
  return { findings, statuses, feed };
}

// ── reachability (imports) ───────────────────────────────────────────────────
/** Modules each modelled package exposes. A package absent from this table has UNKNOWN import reachability. */
export const PACKAGE_MODULES = Object.freeze({
  'xml-conduit': ['Text.XML', 'Text.XML.Cursor', 'Text.XML.Stream.Parse', 'Text.XML.Stream.Render', 'Text.XML.Unresolved'],
  aeson: ['Data.Aeson', 'Data.Aeson.Types', 'Data.Aeson.Parser', 'Data.Aeson.Key', 'Data.Aeson.KeyMap', 'Data.Aeson.Encoding', 'Data.Aeson.TH'],
  pandoc: ['Text.Pandoc', 'Text.Pandoc.Readers', 'Text.Pandoc.Writers', 'Text.Pandoc.Class'],
  'cmark-gfm': ['CMarkGFM'],
  crypton: ['Crypto.Hash', 'Crypto.Cipher.Types', 'Crypto.Random', 'Crypto.PubKey.RSA', 'Crypto.PubKey.ECC.ECDSA'],
  cryptonite: ['Crypto.Hash', 'Crypto.Cipher.Types', 'Crypto.Random', 'Crypto.PubKey.RSA'],
  'git-annex': ['Annex'],
  'hackage-server': ['Distribution.Server'],
  'cabal-install': ['Distribution.Client'],
});

/**
 * @param {string} pkg
 * @param {Array<{module:string, qualified?:boolean, as?:string, items?:string[]|null, hiding?:boolean}>} imports  from the Haskell IR
 * @param {Set<string>} [usedCallees] import-qualified callee names found in the project (`Text.XML.parseLBS`)
 * @param {string[]|null} [symbols] advisory-supplied affected symbols ("Text.XML.Stream.Parse.parseBytes"); null = none given
 */
export function reachability(pkg, imports, usedCallees = new Set(), symbols = null) {
  const mods = PACKAGE_MODULES[pkg];
  if (!mods) return { import: 'unknown', function: 'unknown', reason: `no module mapping for ${pkg}: import reachability cannot be decided (this is NOT "unreachable")` };
  const hit = (imports || []).filter((i) => mods.includes(i.module) || mods.some((m) => i.module.startsWith(`${m}.`)));
  if (!hit.length) return { import: 'not-imported', function: 'not-imported', reason: `no module of ${pkg} is imported` };
  if (!symbols || !symbols.length) return { import: 'imported', function: 'unknown', modules: [...new Set(hit.map((h) => h.module))], reason: 'the advisory names no affected function, so function-level reachability is unknown' };
  const used = [...usedCallees];
  const called = symbols.filter((s) => used.includes(s));
  if (called.length) return { import: 'imported', function: 'reachable', modules: [...new Set(hit.map((h) => h.module))], called, reason: 'an affected function is called through a resolved import' };
  // No resolved call was found. That is NOT proof of unreachability: a re-export, a wildcard import, a
  // higher-order use or an unmodelled module can still reach the symbol, so the answer stays unknown.
  return { import: 'imported', function: 'unknown', modules: [...new Set(hit.map((h) => h.module))], reason: 'no resolved call to an affected function was found; absence of a resolved call is not proof of unreachability' };
}

// ── supply-chain policy: sources, near names, lifecycle, license ─────────────
/** Curated, tested registry of very widely used Hackage packages (NOT an npm list). */
export const POPULAR_PACKAGES = Object.freeze(['aeson', 'text', 'bytestring', 'containers', 'mtl', 'lens', 'conduit', 'http-client', 'http-conduit', 'warp', 'wai', 'scotty', 'servant', 'servant-server', 'yesod', 'persistent', 'postgresql-simple', 'optparse-applicative', 'vector', 'unordered-containers', 'hashable', 'transformers', 'stm', 'async', 'time', 'directory', 'filepath', 'process', 'cryptonite', 'crypton', 'tls', 'pandoc', 'megaparsec', 'attoparsec', 'parsec', 'xml-conduit', 'zlib', 'random', 'QuickCheck', 'hspec', 'tasty']);

const lev = (a, b) => {
  const m = a.length, n = b.length; const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 1; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[m][n];
};

/**
 * Name similarity is a CANDIDATE, never a verdict: Hackage has no scopes and legitimate near-names exist.
 * `registry` (optional) maps a package name to known facts ({exists, maintainers, firstUploaded}); without
 * registry evidence the result stays `unknown`.
 */
export function nearNameCandidates(components, { registry = null, popular = POPULAR_PACKAGES } = {}) {
  const out = [];
  for (const c of components) {
    if (popular.includes(c.name)) continue;
    for (const p of popular) {
      if (Math.abs(p.length - c.name.length) > 1) continue;
      if (lev(c.name.toLowerCase(), p.toLowerCase()) === 1 && p.length > 4) {
        const fact = registry ? registry[c.name] : null;
        out.push({ name: c.name, similarTo: p, status: fact ? (fact.exists ? 'registered-package-near-name' : 'not-on-hackage') : 'unknown', verdict: 'candidate', malicious: false, evidence: fact || null, note: 'edit distance 1 from a popular package; similarity alone is not evidence of malice' });
        break;
      }
    }
  }
  return out;
}

const COMMIT = /^[0-9a-f]{40}$/i;
/** `source-repository-package` stanzas and Stack `extra-deps` git sources: pinned to a commit, or floating. */
export function sourceIntegrity(manifests) {
  const out = [];
  for (const r of manifests.sourceRepositories || []) {
    const pinned = typeof r.tag === 'string' && COMMIT.test(r.tag);
    const kind = pinned ? 'pinned-commit' : (r.tag ? 'tag-or-branch' : 'floating');
    out.push({ ...r, integrity: kind, finding: !pinned, severity: !pinned ? (r.tag ? 'low' : 'medium') : null, reason: pinned ? 'pinned to a full commit hash' : (r.tag ? 'a tag or branch can be moved; pin the commit hash' : 'no tag or commit: the default branch head is fetched') });
  }
  return out;
}

/** Lifecycle (deprecated / yanked) is known only from supplied Hackage metadata; absent evidence is `unknown`. */
export function lifecycle(components, metadata = null) {
  return components.map((c) => {
    const m = metadata && metadata[c.name];
    if (!m) return { name: c.name, version: c.version || null, status: 'unknown', source: null };
    const ver = c.version && m.versions && m.versions[c.version];
    return { name: c.name, version: c.version || null, status: m.deprecated ? 'deprecated' : (ver && ver.deprecated ? 'version-deprecated' : 'active'), supersededBy: m.supersededBy || null, source: 'hackage-metadata' };
  });
}

/** License policy over supplied metadata; a package whose license is not known is `unknown`, not allowed. */
export function licensePolicy(components, metadata, policy = { deny: ['GPL-3.0-only', 'AGPL-3.0-only'], allow: null }) {
  return components.map((c) => {
    const m = metadata && metadata[c.name];
    const license = m && (c.version && m.versions && m.versions[c.version] && m.versions[c.version].license || m.license) || null;
    if (!license) return { name: c.name, version: c.version || null, license: null, status: 'unknown', reason: 'no license metadata supplied for this package' };
    if (policy.deny.includes(license)) return { name: c.name, version: c.version || null, license, status: 'denied', reason: `${license} is on the deny list` };
    if (policy.allow && !policy.allow.includes(license)) return { name: c.name, version: c.version || null, license, status: 'not-allowed', reason: `${license} is not on the allow list` };
    return { name: c.name, version: c.version || null, license, status: 'allowed', reason: '' };
  });
}

export { sha256 as _sha256, canon as _canon };
