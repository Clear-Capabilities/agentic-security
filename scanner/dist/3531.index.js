export const id = 3531;
export const ids = [3531];
export const modules = {

/***/ 33531:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LANGUAGE_BOM_VERSION: () => (/* binding */ LANGUAGE_BOM_VERSION),
/* harmony export */   genericPurl: () => (/* binding */ genericPurl),
/* harmony export */   languageBom: () => (/* binding */ languageBom),
/* harmony export */   languagePbom: () => (/* binding */ languagePbom),
/* harmony export */   purlFromGitHost: () => (/* binding */ purlFromGitHost),
/* harmony export */   purlFromUpstreamUrl: () => (/* binding */ purlFromUpstreamUrl)
/* harmony export */ });
/* harmony import */ var _haskell_supply_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(86349);
/* harmony import */ var _haskell_sca_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(2437);
/* harmony import */ var _haskell_resolved_graph_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(86359);
/* harmony import */ var _nix_inventory_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(81303);
// Hackage and Nix components, dependency edges and target provenance for the SBOM emitters (X-010).
//
// Turns what the language analyses already know into BOM-shaped data WITHOUT inventing any of it:
//
//   * A version appears only where a resolver or a lock states one. A declared range (`aeson ==2.1.*`) is a property,
//     never a version. A Nix package selector (`pkgs.git`) is not a component at all.
//   * A dependency graph appears only from a fresh resolved plan/export. A manifest or a freeze file gives declared
//     edges at most, and the document says so through `compositions` (`incomplete`), never `complete`.
//   * Resolved builds are never merged away: two Hackage units that differ in flags, or two Nix outputs that share a
//     name and version but not a store hash, stay two components with two bom-refs.
//   * A license appears only when a source states one. Nothing here guesses a license from a name.
//   * Purls follow the registered type rules: `hackage`, `github` for validated upstream hosts, and `generic` (with
//     vcs_url / download_url qualifiers) as the labelled fallback. Nix build provenance travels beside the identity
//     as properties (store path, derivation, system, installable, lock digest), not inside the purl.






const LANGUAGE_BOM_VERSION = 'language-bom/1';

const enc = (s) => encodeURIComponent(String(s)).replace(/%2F/gi, '/').replace(/%40/g, '%40');
const qEnc = (s) => encodeURIComponent(String(s));
const prop = (name, value) => (value === null || value === undefined || value === '' ? null : { name: `agentic-security:${name}`, value: typeof value === 'string' ? value : JSON.stringify(value) });
const props = (...xs) => xs.filter(Boolean);

/** purl for a generic component, qualifiers sorted by key as the purl spec requires. */
function genericPurl(name, version, qualifiers = {}) {
  const q = Object.entries(qualifiers).filter(([, v]) => v !== null && v !== undefined && v !== '').sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => `${k.toLowerCase()}=${qEnc(v)}`);
  return `pkg:generic/${enc(name)}${version ? `@${qEnc(version)}` : ''}${q.length ? `?${q.join('&')}` : ''}`;
}

/** A purl for a recognised source host; null otherwise (never guessed). */
function purlFromGitHost(type, owner, repo, rev) {
  if (!['github', 'gitlab', 'bitbucket'].includes(type) || !owner || !repo) return null;
  return `pkg:${type}/${enc(String(owner).toLowerCase())}/${enc(String(repo).toLowerCase())}${rev ? `@${qEnc(rev)}` : ''}`;
}
const GH_URL = /^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/(?:releases\/download|archive)\//i;
/** Validated upstream identity from a source URL on a known host. */
function purlFromUpstreamUrl(url, version) {
  const m = GH_URL.exec(String(url || ''));
  return m ? purlFromGitHost('github', m[1], m[2], version) : null;
}

const cdxScope = (scopes) => ((scopes || []).includes('runtime') ? 'required' : 'excluded');

// ── Haskell ─────────────────────────────────────────────────────────────────
function haskellBom(files, opts) {
  const out = { components: [], dependencies: [], compositions: [], properties: [], gaps: [], root: null };
  const { components: declared, manifests } = (0,_haskell_supply_js__WEBPACK_IMPORTED_MODULE_0__/* .hackageComponents */ .vG)(files);
  if (!manifests) return out;
  const pkg = (manifests.packages || [])[0] || null;
  const rootRef = pkg ? `haskell-root:${pkg.name}@${pkg.version || 'unversioned'}` : 'haskell-root';
  if (pkg) out.root = { type: 'application', 'bom-ref': rootRef, name: pkg.name, ...(pkg.version ? { version: pkg.version } : {}) };

  const graph = opts.resolved || (0,_haskell_resolved_graph_js__WEBPACK_IMPORTED_MODULE_2__/* .buildResolvedGraph */ .xU)({ manifests, plan: opts.plan, stackExport: opts.stackExport, expected: opts.expected, rejectStale: opts.rejectStale });
  out.properties.push(prop('haskell:resolution', graph.source), prop('haskell:freshness', graph.freshness && graph.freshness.status), prop('haskell:closure', graph.closure));
  if (graph.compiler) out.properties.push(prop('haskell:compiler', graph.compiler.id));
  out.gaps.push(...(graph.gaps || []).map((g) => ({ ...g, source: 'haskell' })));

  const refOf = new Map();                                         // unit id -> bom-ref
  if (graph.graphAvailable && graph.units) {
    for (const u of graph.units) {
      if (u.origin === 'local') { refOf.set(u.id, rootRef); continue; }
      const ref = `hackage:${u.id}`;
      refOf.set(u.id, ref);
      let purl = null;
      if (u.origin === 'hackage' || u.origin === 'compiler') purl = (0,_haskell_sca_js__WEBPACK_IMPORTED_MODULE_1__/* .hackagePurl */ .Gf)(u.name, u.version || null);
      else if (u.origin === 'vcs') purl = genericPurl(u.name, u.version, { vcs_url: u.repo && u.repo.uri });
      else if (u.origin === 'url') purl = genericPurl(u.name, u.version, { download_url: u.repo && u.repo.uri });
      out.components.push({
        ecosystem: 'hackage', name: u.name, version: u.version || null, purl, bomRef: ref, filePath: (files && Object.keys(files).find((f) => /\.cabal$|cabal\.project$/.test(f))) || undefined, cdxScope: cdxScope(u.scopes), scopes: u.scopes || [],
        // identity across versions: the package, plus its flag assignment when it has one (two builds stay two components)
        identityKey: `hackage:${u.name}${u.flags && Object.keys(u.flags).length ? `?${JSON.stringify(u.flags)}` : ''}${u.sublibrary ? `:${u.sublibrary}` : ''}`,
        ...(u.sha256 ? { hashes: [{ alg: 'SHA-256', content: u.sha256 }] } : {}),
        properties: props(prop('haskell:unitId', u.id), prop('haskell:origin', u.origin), prop('haskell:scopes', u.scopes), prop('haskell:flags', u.flags && Object.keys(u.flags).length ? u.flags : null), prop('haskell:boot', u.boot ? true : null), prop('haskell:component', u.component && u.component.kind), prop('haskell:originEvidence', u.originEvidence)),
      });
    }
    const dep = new Map();
    for (const e of graph.edges || []) {
      const from = refOf.get(e.from); const to = refOf.get(e.to);
      if (!from || !to || from === to) continue;
      if (!dep.has(from)) dep.set(from, new Map());
      const toUnit = (graph.units || []).find((x) => x.id === e.to);
      dep.get(from).set(to, (toUnit && toUnit.scopes && toUnit.scopes.includes('runtime')) ? 'runtime' : ((toUnit && toUnit.scopes && toUnit.scopes.includes('test')) ? 'test' : 'build'));
    }
    for (const [ref, m] of [...dep.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) out.dependencies.push({ ref, dependsOn: [...m.keys()].sort(), kinds: Object.fromEntries(m) });
    out.compositions.push({ aggregate: graph.closure && graph.closure.complete ? 'complete' : 'incomplete', dependencies: [...new Set([...refOf.values()])].sort() });
  } else {
    // Declared inventory only: names and (where a freeze or exact pin states one) versions. Not a closure.
    const seen = new Map();
    for (const d of declared) {
      const key = `${d.name}@${d.version || ''}`;
      const ref = d.version ? `hackage:${d.name}@${d.version}` : `hackage:${d.name}`;
      if (seen.has(key)) { const c = seen.get(key); if (!c.scopes.includes(d.scope)) c.scopes.push(d.scope); c.cdxScope = cdxScope(c.scopes); continue; }
      const c = {
        ecosystem: 'hackage', name: d.name, version: d.version || null, purl: (0,_haskell_sca_js__WEBPACK_IMPORTED_MODULE_1__/* .hackagePurl */ .Gf)(d.name, d.version || null), bomRef: ref, filePath: d.manifest || undefined, scopes: [d.scope], cdxScope: cdxScope([d.scope]), identityKey: `hackage:${d.name}`,
        properties: props(prop('haskell:declaredRange', d.declaredRange), prop('haskell:resolution', d.resolution), prop('haskell:boot', d.ghcComponent ? true : null), prop('haskell:manifest', d.manifest)),
      };
      seen.set(key, c); out.components.push(c);
    }
    if (declared.length) {
      out.dependencies.push({ ref: rootRef, dependsOn: out.components.map((c) => c.bomRef).sort(), kinds: Object.fromEntries(out.components.map((c) => [c.bomRef, (c.scopes || []).includes('runtime') ? 'runtime' : 'build'])) });
      out.compositions.push({ aggregate: 'incomplete', dependencies: [rootRef] });
    }
    out.gaps.push({ kind: 'declared-inventory-only', source: 'haskell', detail: 'no fresh plan or Stack export: components are the declared dependencies, versions only where a freeze or an exact pin states one; transitive packages are not listed' });
  }
  return out;
}

// ── Nix ─────────────────────────────────────────────────────────────────────
function nixInputBom(files) {
  const out = { components: [], dependencies: [], compositions: [], properties: [], gaps: [], root: null };
  const inv = (0,_nix_inventory_js__WEBPACK_IMPORTED_MODULE_3__/* .analyzeNixInputs */ .Tw)({ files });
  out.gaps.push(...inv.gaps.map((g) => ({ ...g, source: 'nix' })));
  const refOf = new Map();
  for (const f of inv.flakes) {
    const nodes = (f.graph && f.graph.nodes) || [];
    for (const n of nodes) {
      if (n.root || !n.reachable) continue;
      const key = `${f.file}:${n.key}`;
      const ref = `nix-input:${key}`;
      refOf.set(`${f.file}|${n.key}`, ref);
      const lk = n.locked || null;
      const rev = lk && (lk.rev || null);
      let purl = null; let url = null;
      if (lk && lk.type) {
        purl = purlFromGitHost(lk.type, lk.owner, lk.repo, rev);
        if (!purl && lk.url) purl = genericPurl(n.name, rev, lk.type === 'tarball' ? { download_url: lk.url } : { vcs_url: lk.url });
        if (lk.type === 'github') url = `https://github.com/${lk.owner}/${lk.repo}`;
        else if (lk.url) url = lk.url;
      }
      if (!purl) purl = genericPurl(n.name, null);
      out.components.push({
        ecosystem: 'nix', name: n.name, version: rev, purl, bomRef: ref, filePath: f.lock && f.lock.file ? f.lock.file : f.file, cdxScope: 'required', scopes: ['source'], identityKey: `nix-input:${f.file}:${n.key}`,
        ...(url ? { externalReferences: [{ type: 'vcs', url }] } : {}),
        properties: props(prop('nix:class', 'flake-input'), prop('nix:lockNode', n.key), prop('nix:flakeFile', f.file), prop('nix:fetchType', lk && lk.type), prop('nix:narHash', lk && lk.narHash), prop('nix:locked', lk ? true : false), prop('nix:purlBasis', purl.startsWith('pkg:generic') ? 'generic-fallback' : 'validated-upstream-host')),
      });
    }
    const edges = (f.graph && f.graph.edges) || [];
    const by = new Map();
    for (const e of edges) { const a = refOf.get(`${f.file}|${e.from}`); const b = e.to ? refOf.get(`${f.file}|${e.to}`) : null; if (a && b && a !== b) { if (!by.has(a)) by.set(a, new Set()); by.get(a).add(b); } }
    for (const [ref, set] of [...by.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1))) out.dependencies.push({ ref, dependsOn: [...set].sort(), kinds: Object.fromEntries([...set].map((s) => [s, 'runtime'])) });
  }
  if (out.components.length) out.compositions.push({ aggregate: 'incomplete', dependencies: out.components.map((c) => c.bomRef).sort() });
  out.gaps.push({ kind: 'inputs-are-not-a-closure', source: 'nix', detail: 'flake.lock lists source inputs; it is not the build or runtime closure, so the Nix inputs are reported as incomplete' });
  return out;
}

function nixClosureBom(closure) {
  const out = { components: [], dependencies: [], compositions: [], properties: [], gaps: [], root: null };
  if (!closure || closure.status !== 'ok') { if (closure) out.gaps.push({ kind: 'closure-not-usable', source: 'nix', detail: `closure import status ${closure.status}` }); return out; }
  const prov = (closure.provenance || [])[0] || {};
  const target = prov.target || {};
  out.properties.push(prop('nix:target.system', target.system), prop('nix:target.installable', target.installable), prop('nix:toolVersion', prov.toolVersion), prop('nix:exactRuntimeClosure', closure.claims && closure.claims.exactRuntimeClosure), prop('nix:exactBuildGraph', closure.claims && closure.claims.exactBuildGraph));
  const refOf = new Map();
  for (const n of closure.nodes) {
    if (n.kind !== 'output' && n.kind !== 'source') continue;
    if (!n.pname && !n.storeName) continue;
    const name = n.pname || n.storeName;
    const ref = `nix-store:${n.hash}-${n.storeName}`;
    refOf.set(n.id, ref);
    const urls = (n.upstream && n.upstream.urls) || [];
    let purl = null; let basis = 'generic-fallback';
    for (const u of urls) { const p = purlFromUpstreamUrl(u, n.version); if (p) { purl = p; basis = 'validated-upstream-host'; break; } }
    if (!purl) purl = genericPurl(name, n.version || null);
    const scopes = n.scopes || [];
    out.components.push({
      ecosystem: 'nix', name, version: n.version || null, purl, bomRef: ref, cdxScope: cdxScope(scopes), scopes,
      identityKey: `nix:${name}:${n.system || ''}:${n.outputName || 'out'}${n.sameNameDifferentBuild ? `:${n.hash}` : ''}`,
      properties: props(prop('nix:class', n.kind === 'source' ? 'source' : 'store-output'), prop('nix:storePath', n.id), prop('nix:system', n.system), prop('nix:output', n.outputName), prop('nix:scopes', scopes), prop('nix:versionAuthority', n.versionAuthority), prop('nix:identity', n.identity), prop('nix:purlBasis', basis), prop('nix:sameNameDifferentBuild', n.sameNameDifferentBuild ? true : null), prop('nix:patches', (n.patches || []).map((p) => p.name)), prop('nix:installable', target.installable)),
    });
  }
  const by = new Map();
  for (const e of closure.edges) {
    if (e.kind !== 'reference') continue;
    const a = refOf.get(e.from); const b = refOf.get(e.to);
    if (!a || !b || a === b) continue;
    if (!by.has(a)) by.set(a, new Set()); by.get(a).add(b);
  }
  for (const [ref, set] of [...by.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1))) out.dependencies.push({ ref, dependsOn: [...set].sort(), kinds: Object.fromEntries([...set].map((s) => [s, 'runtime'])) });
  const runtimeRefs = closure.nodes.filter((n) => n.kind === 'output' && (n.scopes || []).includes('runtime')).map((n) => refOf.get(n.id)).filter(Boolean).sort();
  if (runtimeRefs.length) out.compositions.push({ aggregate: closure.claims && closure.claims.exactRuntimeClosure ? 'complete' : 'incomplete', dependencies: runtimeRefs });
  return out;
}

/**
 * @param {Record<string,string>} files rel path -> content (sources and manifests)
 * @param {{closure?: object, resolved?: object, plan?: object, stackExport?: object, expected?: object, rejectStale?: boolean}} [opts]
 *   `closure` is an importNixClosure() result (an explicit, provenance-carrying export); nothing is run or fetched.
 */
function languageBom(files, opts = {}) {
  const parts = [haskellBom(files || {}, opts), nixInputBom(files || {}), nixClosureBom(opts.closure)];
  const merged = { version: LANGUAGE_BOM_VERSION, components: [], dependencies: [], compositions: [], properties: [], gaps: [], root: null };
  const byRef = new Map();
  for (const p of parts) {
    for (const c of p.components) { if (!byRef.has(c.bomRef)) { byRef.set(c.bomRef, c); merged.components.push(c); } }
    for (const d of p.dependencies) merged.dependencies.push(d);
    merged.compositions.push(...p.compositions);
    merged.properties.push(...p.properties);
    merged.gaps.push(...p.gaps);
    if (!merged.root && p.root) merged.root = p.root;
  }
  // a dependency edge may only name refs that exist (the root ref is allowed)
  const known = new Set([...byRef.keys(), ...(merged.root ? [merged.root['bom-ref']] : [])]);
  merged.dependencies = merged.dependencies.map((d) => ({ ...d, dependsOn: d.dependsOn.filter((r) => known.has(r)) })).filter((d) => known.has(d.ref));
  merged.components.sort((a, b) => (a.bomRef < b.bomRef ? -1 : 1));
  return merged;
}

/**
 * The language half of a Pipeline Bill of Materials: what is fetched and how it is pinned before anything is built.
 * Static facts from the manifests and lock files only; nothing is fetched or evaluated.
 */
function languagePbom(files) {
  const out = { version: LANGUAGE_BOM_VERSION, haskell: null, nix: null };
  const { manifests } = (0,_haskell_supply_js__WEBPACK_IMPORTED_MODULE_0__/* .hackageComponents */ .vG)(files || {});
  if (manifests) {
    out.haskell = {
      packages: (manifests.packages || []).map((p) => ({ name: p.name, version: p.version || null, buildType: p.buildType || null, file: p.file })),
      customSetup: (manifests.packages || []).some((p) => String(p.buildType || '').toLowerCase() === 'custom'),
      sourceRepositories: (manifests.sourceRepositories || []).map((r) => ({ location: r.location, tag: r.tag || null, pinned: /^[0-9a-f]{40}$/i.test(r.tag || ''), file: r.file, line: r.line })),
      compiler: (manifests.projects || []).map((p) => p.withCompiler).find(Boolean) || null,
    };
  }
  const inv = (0,_nix_inventory_js__WEBPACK_IMPORTED_MODULE_3__/* .analyzeNixInputs */ .Tw)({ files: files || {} });
  if (inv.flakes.length || inv.legacy.length) {
    out.nix = {
      inputs: inv.flakes.flatMap((f) => (f.declared || []).map((d) => ({ flake: f.file, name: d.name, url: d.url || null, status: d.status, fetchType: d.lockedFetch ? d.lockedFetch.type : null, rev: d.lockedFetch ? d.lockedFetch.rev || null : null, narHash: d.lockedFetch ? d.lockedFetch.narHash || null : null, locked: !!d.locked }))),
      legacy: inv.legacy.map((l) => ({ kind: l.kind, file: l.file, line: l.line || null, resolution: l.resolution || null })),
      closure: { complete: false, reason: 'inputs and fetchers only; a build or runtime closure needs an explicit export' },
    };
  }
  return out;
}


/***/ })

};
