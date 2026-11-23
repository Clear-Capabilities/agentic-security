export const id = 6248;
export const ids = [6248];
export const modules = {

/***/ 70123:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  g: () => (/* binding */ buildContext)
});

// EXTERNAL MODULE: ./src/ir/index.js + 11 modules
var ir = __webpack_require__(98297);
// EXTERNAL MODULE: ./src/context-intelligence/graph-schema.js
var graph_schema = __webpack_require__(50152);
;// CONCATENATED MODULE: ./src/context-intelligence/adapters/existing-ir.js
//
// Adapter: shared IR (`buildProjectIR`) -> symbol-graph/1.
//
// The IR is REUSED, not copied. All languages the IR lowers (JS/TS, Python, Java, C#, Kotlin, Go, PHP, Ruby, Rust,
// C/C++, and Haskell through the shared call graph) arrive through the one call graph, so this adapter has no
// per-language logic; per-language capability is a matter for the capability matrix, not for branching here.



function graphFromSource(fileContents) {
  const { perFile, callGraph } = (0,ir.buildProjectIR)(fileContents);
  const graph = (0,graph_schema/* buildSymbolGraph */.Nk)({ fileContents, functions: callGraph.functions, edges: callGraph.edges });
  return { graph, perFile, callGraph };
}

// EXTERNAL MODULE: ./src/context-intelligence/entrypoints.js
var context_intelligence_entrypoints = __webpack_require__(59381);
// EXTERNAL MODULE: ./src/context-intelligence/reachability.js
var reachability = __webpack_require__(77875);
// EXTERNAL MODULE: ./src/context-intelligence/packer.js
var packer = __webpack_require__(22526);
// EXTERNAL MODULE: ./src/context-intelligence/manifest.js
var context_intelligence_manifest = __webpack_require__(1325);
// EXTERNAL MODULE: ./src/context-intelligence/files.js
var files = __webpack_require__(72873);
// EXTERNAL MODULE: external "node:child_process"
var external_node_child_process_ = __webpack_require__(31421);
;// CONCATENATED MODULE: ./src/context-intelligence/repo-info.js
//
// Best-effort git identity of the checkout. Absent git is not an error: the fields are null and the snapshot hash
// (content-based) still identifies the analysed bytes exactly.


function git(root, args) {
  try {
    return (0,external_node_child_process_.execFileSync)('git', ['-C', root, ...args], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 1024 * 1024 }).trim();
  } catch { return null; }
}

function repositoryInfo(root, snapshotHash) {
  const commit = git(root, ['rev-parse', 'HEAD']);
  const status = commit ? git(root, ['status', '--porcelain']) : null;
  return { commit: commit || null, dirty: status === null ? null : status.length > 0, snapshotHash };
}

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/context-intelligence/canonical.js
var canonical = __webpack_require__(44652);
;// CONCATENATED MODULE: ./src/context-intelligence/adapters/haskell-hie.js
//
// Optional compiler-semantic metadata: a READ-ONLY importer for a Haskell declaration/reference export (`hie-export/1`).
//
// What this is and is not:
//   * It imports an export that already exists. It never runs GHC, `hiedb`, Cabal or Stack, never builds, and never
//     executes anything from the repository (no Template Haskell, no custom Setup, no plugins). A later explicit
//     metadata-build command would need a sandbox proof that does not exist in this build, so there is none.
//   * `hie-export/1` is the interchange format DCI defines for the data GHC's `-fwrite-ide-info` / `hiedb` hold
//     (declarations with exact spans, and references between them). Producing it from `.hie` files is a separate,
//     explicit, operator step documented in docs/guides/context-intelligence.md; the binary `.hie` files themselves
//     are not parsed here.
//   * The export is untrusted input. It must name the compiler and tool, and it must carry the SHA-256 of every source
//     file it describes; a file whose current hash differs makes the whole adapter DEGRADE (the static graph is kept and
//     the mismatch is reported). Paths must be repository-relative and may not escape; sizes are capped.
//   * Compiler facts are merged as additional, provenance-tagged evidence. A static edge is never silently overwritten:
//     an unresolved static call that the compiler resolves is marked superseded (and counted as closed by the compiler);
//     a static edge that DISAGREES with the compiler stays, and both are flagged as a conflict, which keeps the bundle
//     partial.




const HIE_EXPORT_SCHEMA = 'hie-export/1';
const HIE_EXPORT_FILE = 'hie-export.json';
const LIMITS = Object.freeze({ maxBytes: 16 * 1024 * 1024, maxDecls: 200000, maxRefs: 1000000, maxName: 300 });
const SUPPORTED_COMPILER = /^ghc$/i;

function degrade(reason, detail) { return { status: 'degraded', reason, detail: detail || null, declarations: [], references: [] }; }

/**
 * Load and validate an export. Returns { status: 'ok'|'degraded'|'off', ... }. Never throws, never reads outside the
 * repository, and treats ANY validation failure as a degradation of the adapter, not of the scan.
 */
function loadHieMetadata(rootReal, hieDir, { fileContents }) {
  if (!hieDir) return { status: 'off', reason: 'no-directory-configured', declarations: [], references: [] };
  const dirRel = (0,canonical/* safeRelPath */.Qz)(hieDir);
  if (!dirRel) return degrade('unsafe-directory');
  const abs = external_node_path_.join(rootReal, dirRel, HIE_EXPORT_FILE);
  let text;
  try {
    const st = external_node_fs_.lstatSync(abs);
    if (st.isSymbolicLink() || !st.isFile()) return degrade('not-a-regular-file');
    if (st.size > LIMITS.maxBytes) return degrade('too-large');
    const real = external_node_fs_.realpathSync(abs);
    if (real !== rootReal && !real.startsWith(rootReal + external_node_path_.sep)) return degrade('escapes-root');
    text = external_node_fs_.readFileSync(abs, 'utf8');
  } catch (e) {
    return degrade(e && e.code === 'ENOENT' ? 'export-not-found' : 'unreadable');
  }
  let doc;
  try { doc = JSON.parse(text); } catch { return degrade('invalid-json'); }
  if (!doc || doc.schemaVersion !== HIE_EXPORT_SCHEMA) return degrade('unsupported-schema-version', String(doc && doc.schemaVersion));
  if (!doc.compiler || !SUPPORTED_COMPILER.test(String(doc.compiler.name || '')) || typeof doc.compiler.version !== 'string') return degrade('compiler-not-identified');
  if (!doc.tool || typeof doc.tool.name !== 'string' || typeof doc.tool.version !== 'string') return degrade('tool-not-identified');
  if (!Array.isArray(doc.files) || !Array.isArray(doc.declarations) || !Array.isArray(doc.references)) return degrade('malformed');
  if (doc.declarations.length > LIMITS.maxDecls || doc.references.length > LIMITS.maxRefs) return degrade('over-size-limit');

  // source snapshot match: every file the export describes must be byte-identical to what is being analysed
  const stale = [];
  const described = new Set();
  for (const f of doc.files) {
    const rel = (0,canonical/* safeRelPath */.Qz)(String(f && f.path));
    if (!rel || rel !== f.path) return degrade('unsafe-path-in-export', String(f && f.path).slice(0, 80));
    described.add(rel);
    if (typeof fileContents[rel] !== 'string') { stale.push(`${rel}:missing`); continue; }
    if ((0,canonical/* sha256 */.sc)(fileContents[rel]) !== f.sha256) stale.push(`${rel}:hash-differs`);
  }
  if (stale.length) return degrade('source-snapshot-mismatch', stale.slice(0, 10).join(', '));

  const declarations = [];
  for (const d of doc.declarations) {
    const rel = (0,canonical/* safeRelPath */.Qz)(String(d && d.file));
    if (!rel || !described.has(rel) || typeof d.name !== 'string' || d.name.length > LIMITS.maxName) return degrade('malformed-declaration');
    const total = fileContents[rel].split('\n').length;
    if (![d.startLine, d.endLine].every(Number.isInteger) || d.startLine < 1 || d.endLine < d.startLine || d.endLine > total) return degrade('declaration-span-out-of-range', `${rel}:${d.name}`);
    declarations.push({ name: d.name, file: rel, startLine: d.startLine, endLine: d.endLine });
  }
  const references = [];
  for (const r of doc.references) {
    if (!r || typeof r.from !== 'string' || typeof r.to !== 'string' || r.from.length > LIMITS.maxName || r.to.length > LIMITS.maxName || !Number.isInteger(r.line)) return degrade('malformed-reference');
    references.push({ from: r.from, to: r.to, line: r.line });
  }
  declarations.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.startLine - b.startLine || (a.name < b.name ? -1 : 1));
  references.sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : 0) || a.line - b.line || (a.to < b.to ? -1 : 1));
  return { status: 'ok', tool: doc.tool, compiler: doc.compiler, declarations, references, exportHash: (0,canonical/* hashOf */.qQ)({ declarations, references }) };
}

function uncorroboratedReferences(graph, references, fileContents) {
  const byName = new Map();
  for (const sym of graph.symbols) {
    if (sym.kind !== 'function' || sym.id.includes('::<anon>@')) continue;
    if (!byName.has(sym.name)) byName.set(sym.name, []);
    byName.get(sym.name).push(sym);
  }
  const bad = [];
  for (const r of references) {
    const owners = byName.get(r.from) || [];
    if (owners.length !== 1) continue; // an ambiguous or unknown name is already counted as unmatched and adds nothing
    const sym = owners[0];
    const text = fileContents[sym.file];
    const callee = String(r.to).split(/[.:]/).pop();
    const lineText = typeof text === 'string' ? text.split('\n')[r.line - 1] : undefined;
    const inside = r.line >= sym.startLine && r.line <= sym.endLine;
    if (!inside || lineText === undefined || !callee || !lineText.includes(callee)) bad.push(`${r.from}->${r.to}@${r.line}`);
  }
  return bad;
}

/**
 * Merge an imported export into the static graph. Returns { graph, semantic } where `semantic` carries the provenance
 * and the static-versus-compiler difference report.
 */
function mergeHieIntoGraph(graph, meta, fileContents) {
  if (meta.status !== 'ok') {
    return { graph, semantic: { source: ['static-ir'], status: meta.status, reason: meta.reason || null, detail: meta.detail || null, diff: null } };
  }
  // The export is untrusted even when its file hashes match: it is checked into the repository it describes. A reference
  // is accepted only if the line it names, inside the declaration it names, actually mentions the callee. One that does
  // not degrades the whole import, so a crafted export cannot add edges that the source does not contain.
  const uncorroborated = uncorroboratedReferences(graph, meta.references, fileContents || {});
  if (uncorroborated.length) {
    return { graph, semantic: { source: ['static-ir'], status: 'degraded', reason: 'reference-not-in-source', detail: uncorroborated.slice(0, 5).join(', '), diff: null } };
  }
  const idsByName = new Map();
  for (const s of graph.symbols) {
    if (s.kind !== 'function' || s.id.includes('::<anon>@')) continue;
    if (!idsByName.has(s.name)) idsByName.set(s.name, []);
    idsByName.get(s.name).push(s.id);
  }
  const edges = graph.edges.map(e => ({ ...e }));
  const diff = { newSymbols: [], newEdges: 0, resolvedUnknowns: 0, conflicts: [], remainingMaterialUnknowns: 0, unmatchedReferences: 0 };

  // declarations the static pass never saw are reported (not added: DCI has no source-hash-verified span for them
  // beyond what the export says, and an export-only symbol would be an unverified span)
  const known = new Set(graph.symbols.map(s => `${s.file}\0${s.name}`));
  for (const d of meta.declarations) if (!known.has(`${d.file}\0${d.name}`)) diff.newSymbols.push(`${d.file}::${d.name}`);

  for (const r of meta.references) {
    const from = (idsByName.get(r.from) || [])[0];
    const to = (idsByName.get(r.to) || [])[0];
    if (!from || !to || (idsByName.get(r.from) || []).length !== 1 || (idsByName.get(r.to) || []).length !== 1) { diff.unmatchedReferences++; continue; }
    const same = edges.filter(e => e.from === from && e.line === r.line);
    const agree = same.find(e => e.to === to);
    if (agree) continue; // static already has it: nothing to add
    const conflicting = same.find(e => e.to && e.to !== to && e.calleeName.split(/[.:]/).pop() === r.to.split(/[.:]/).pop());
    if (conflicting) {
      conflicting.conflict = true;
      diff.conflicts.push({ from, line: r.line, static: conflicting.to, compiler: to });
      edges.push({ from, to, line: r.line, calleeName: r.to, kind: 'call', resolver: 'compiler-enriched', conditionality: 'unknown', resolution: 'compiler', confidence: 'high', unresolvedReason: null, candidates: [], conflict: true });
      diff.newEdges++;
      continue;
    }
    const unresolved = same.find(e => !e.to && (e.calleeName.split(/[.:]/).pop() === r.to.split(/[.:]/).pop()));
    if (unresolved) { unresolved.superseded = true; diff.resolvedUnknowns++; }
    edges.push({ from, to, line: r.line, calleeName: r.to, kind: 'call', resolver: 'compiler-enriched', conditionality: unresolved ? unresolved.conditionality : 'unknown', resolution: 'compiler', confidence: 'high', unresolvedReason: null, candidates: [], conflict: false });
    diff.newEdges++;
  }
  edges.sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : 0) || (a.line - b.line) || (a.calleeName < b.calleeName ? -1 : a.calleeName > b.calleeName ? 1 : 0) || ((a.to || '') < (b.to || '') ? -1 : 1));
  diff.remainingMaterialUnknowns = edges.filter(e => !e.to && !e.superseded && e.confidence === 'low').length;
  const body = { schemaVersion: graph.schemaVersion, snapshotHash: graph.snapshotHash, symbols: graph.symbols, edges, imports: graph.imports, semantic: { exportHash: meta.exportHash, compiler: meta.compiler, tool: meta.tool } };
  return {
    graph: { ...body, hash: (0,canonical/* hashOf */.qQ)(body) },
    semantic: { source: ['static-ir', 'hie-import'], status: 'ok', compiler: meta.compiler, tool: meta.tool, exportHash: meta.exportHash, diff },
  };
}

;// CONCATENATED MODULE: ./src/context-intelligence/build.js
//
// Orchestration: source snapshot -> symbol graph -> entry points -> per-entry-point reachability -> bundles + manifests.
// Pure with respect to the repository (read-only); persistence is store.js's job. No model, no network.










/**
 * Build every bundle for a project.
 *   opts.config   normalised DCI config
 *   opts.route    optional filter: a label substring or an entrypoint id
 *   opts.onEvent  optional progress callback (JSON-serialisable events)
 */
async function buildContext(root, opts = {}) {
  const config = opts.config;
  const emit = typeof opts.onEvent === 'function' ? opts.onEvent : () => {};
  const snap = opts.snapshot || await (0,files/* readSnapshot */.RA)(root, { maxFiles: config.maxFiles });
  if (!snap.ok) return { ok: false, reason: snap.reason, detail: snap };
  const { fileContents } = snap;
  emit({ event: 'snapshot', files: Object.keys(fileContents).length, skipped: snap.skipped.length });

  let { graph, perFile, callGraph } = graphFromSource(fileContents);
  let semantic = { source: ['static-ir'], status: 'off', diff: null };
  if (config.semanticMetadata.mode === 'import') {
    const meta = loadHieMetadata(snap.rootReal, config.semanticMetadata.haskellHieDir, { fileContents });
    const merged = mergeHieIntoGraph(graph, meta, fileContents);
    graph = merged.graph;
    semantic = merged.semantic;
  }
  const problems = (0,graph_schema/* validateGraph */.dC)(graph, fileContents);
  if (problems.length) return { ok: false, reason: 'graph-invalid', detail: problems.slice(0, 20) };
  emit({ event: 'graph', symbols: graph.symbols.length, edges: graph.edges.length, hash: graph.hash });

  let entrypoints = await (0,context_intelligence_entrypoints/* collectEntrypoints */.Os)({ fileContents, graph, config });
  const counts = (0,context_intelligence_entrypoints/* countDispositions */.kD)(entrypoints);
  emit({ event: 'entrypoints', ...counts });
  if (opts.route) entrypoints = entrypoints.filter(e => e.id === opts.route || e.label.includes(opts.route));

  const repository = snap.commit ? { commit: snap.commit, dirty: false, snapshotHash: snap.snapshotHash } : repositoryInfo(snap.rootReal, snap.snapshotHash);
  const bundles = [];
  for (const ep of entrypoints) {
    if (ep.disposition === 'excluded_by_policy') { bundles.push({ entrypoint: ep, manifest: null, pack: null, reach: null }); continue; }
    const reach = (0,reachability/* reachFrom */.sX)({ graph, fileContents, entrypoint: ep, limits: { maxSymbols: config.context.maxSymbols, maxDepth: config.context.maxDepth } });
    const pack = (0,packer/* packContext */.JH)({ entrypoint: ep, reach, graph, fileContents, config: { profile: config.context.profile, maxTokens: config.context.maxTokens, pruneLowValue: config.context.pruneLowValue, tokenizer: opts.tokenizer } });
    const manifest = (0,context_intelligence_manifest/* buildManifest */.u1)({ entrypoint: ep, reach, pack, graph, fileContents, repository, semanticSource: semantic.source });
    bundles.push({ entrypoint: ep, manifest, pack, reach });
    emit({ event: 'bundle', entrypoint: ep.id, integrity: pack.integrity, packages: pack.packages.length });
  }
  const built = bundles.filter(b => b.manifest);
  return {
    ok: true, root: snap.rootReal, repository, graph, semantic, ir: { perFile, callGraph }, snapshotHash: snap.snapshotHash, entrypoints, bundles, fileContents, skipped: snap.skipped,
    summary: {
      entrypointsFound: counts.total, resolved: counts.resolved, partial: counts.partially_resolved, unresolved: counts.unresolved, excluded: counts.excluded_by_policy,
      bundlesBuilt: built.length,
      complete: built.filter(b => b.manifest.context.integrity === 'complete').length,
      partialBundles: built.filter(b => b.manifest.context.integrity === 'partial').length,
      unavailable: built.filter(b => b.manifest.context.integrity === 'unavailable').length,
      unresolvedEdges: built.reduce((n, b) => n + b.manifest.unknowns.filter(u => u.material).length, 0),
      tokens: built.reduce((n, b) => n + b.pack.packages.reduce((m, p) => m + p.tokensEstimated, 0), 0),
    },
  };
}


/***/ }),

/***/ 33238:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   I6: () => (/* binding */ normalizeConfig),
/* harmony export */   Z9: () => (/* binding */ loadConfig)
/* harmony export */ });
/* unused harmony exports CONFIG_SCHEMA_VERSION, CONFIG_FILE, DEFAULT_CONFIG */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(31174);
/* harmony import */ var _packer_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(22526);
/* harmony import */ var _entrypoints_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(59381);
//
// DCI configuration: `.agentic-security/context-intelligence.json`, operator-authored, never written by the scanner.
//
// `enabled` is false by default and means exactly one thing: DCI is not woven into any other command. The explicit
// `context ...` commands are the opt-in and always work; building and inspecting need no model and no network.
// A model call needs an explicit `context review`, a configured endpoint, and a pass through the egress policy.
// `review.enabled` is reserved for a future automatic integration and is not read by the explicit command.





const CONFIG_SCHEMA_VERSION = 1;
const CONFIG_FILE = 'context-intelligence.json';

const DEFAULT_CONFIG = Object.freeze({
  schemaVersion: CONFIG_SCHEMA_VERSION,
  enabled: false,
  entrypointKinds: ['http'],
  exclude: [],
  maxEntrypoints: 5000,
  maxFiles: 3000,
  semanticMetadata: { mode: 'off', haskellHieDir: null },
  context: { profile: 'standard', maxTokens: null, pruneLowValue: true, maxSymbols: 60, maxDepth: 12 },
  review: { enabled: false, allowRemote: false, questionPacks: ['authz-idor'], concurrency: 2, maxCalls: 100, maxWallSeconds: 900, maxCostUsd: null, maxTokensPerJob: 40000, maxRetries: 3, maxTokensPerRepo: null, anonymizePrompts: false },
  replay: { contentAddressed: true, retention: 'inherit' },
});

const clamp = (v, lo, hi, d) => (Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.trunc(v))) : d);

/** Validate and normalise a parsed config object. Returns { config, problems }; unknown keys are reported, never silently kept. */
function normalizeConfig(raw) {
  const problems = [];
  const r = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const d = DEFAULT_CONFIG;
  if (raw !== undefined && raw !== null && r !== raw) problems.push('config-is-not-an-object');
  if (r.schemaVersion !== undefined && r.schemaVersion !== CONFIG_SCHEMA_VERSION) problems.push(`unsupported-schemaVersion:${r.schemaVersion}`);
  for (const k of Object.keys(r)) if (!Object.hasOwn(d, k)) problems.push(`unknown-key:${k}`);

  const kinds = Array.isArray(r.entrypointKinds) ? r.entrypointKinds.filter(k => _entrypoints_js__WEBPACK_IMPORTED_MODULE_3__/* .ENTRYPOINT_KINDS */ .Fr.includes(k)) : d.entrypointKinds;
  if (Array.isArray(r.entrypointKinds) && kinds.length !== r.entrypointKinds.length) problems.push('unknown-entrypoint-kind');
  const sm = r.semanticMetadata && typeof r.semanticMetadata === 'object' ? r.semanticMetadata : {};
  const cx = r.context && typeof r.context === 'object' ? r.context : {};
  const rv = r.review && typeof r.review === 'object' ? r.review : {};
  const rp = r.replay && typeof r.replay === 'object' ? r.replay : {};
  const mode = ['off', 'import'].includes(sm.mode) ? sm.mode : 'off';
  if (sm.mode !== undefined && mode !== sm.mode) problems.push(`semanticMetadata.mode-not-supported:${sm.mode}`);

  const config = {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    enabled: r.enabled === true,
    entrypointKinds: kinds.length ? [...new Set(kinds)] : d.entrypointKinds,
    exclude: Array.isArray(r.exclude) ? r.exclude.filter(x => typeof x === 'string' && x.length < 300).slice(0, 200) : [],
    maxEntrypoints: clamp(r.maxEntrypoints, 1, 50000, d.maxEntrypoints),
    maxFiles: clamp(r.maxFiles, 1, 20000, d.maxFiles),
    semanticMetadata: { mode, haskellHieDir: typeof sm.haskellHieDir === 'string' ? sm.haskellHieDir : null },
    context: {
      profile: Object.hasOwn(_packer_js__WEBPACK_IMPORTED_MODULE_2__/* .PROFILES */ .jI, cx.profile) ? cx.profile : d.context.profile,
      maxTokens: Number.isFinite(cx.maxTokens) ? clamp(cx.maxTokens, 1000, 400000, null) : null,
      pruneLowValue: cx.pruneLowValue !== false,
      maxSymbols: clamp(cx.maxSymbols, 5, 400, d.context.maxSymbols),
      maxDepth: clamp(cx.maxDepth, 1, 40, d.context.maxDepth),
    },
    review: {
      enabled: rv.enabled === true,
      allowRemote: rv.allowRemote === true,
      questionPacks: Array.isArray(rv.questionPacks) && rv.questionPacks.length ? rv.questionPacks.filter(x => typeof x === 'string') : d.review.questionPacks,
      concurrency: clamp(rv.concurrency, 1, 16, d.review.concurrency),
      maxCalls: clamp(rv.maxCalls, 1, 5000, d.review.maxCalls),
      maxWallSeconds: clamp(rv.maxWallSeconds, 5, 86400, d.review.maxWallSeconds),
      maxCostUsd: Number.isFinite(rv.maxCostUsd) && rv.maxCostUsd >= 0 ? rv.maxCostUsd : null,
      maxTokensPerJob: clamp(rv.maxTokensPerJob, 1000, 400000, d.review.maxTokensPerJob),
      maxRetries: clamp(rv.maxRetries, 0, 3, d.review.maxRetries),
      maxTokensPerRepo: Number.isFinite(rv.maxTokensPerRepo) && rv.maxTokensPerRepo >= 1000 ? Math.trunc(rv.maxTokensPerRepo) : null,
      anonymizePrompts: rv.anonymizePrompts === true,
    },
    replay: { contentAddressed: rp.contentAddressed !== false, retention: typeof rp.retention === 'string' ? rp.retention : 'inherit' },
  };
  return { config, problems };
}

/** Load the config for a project. A missing file is the defaults; a malformed one is reported, and the defaults are used. */
function loadConfig(root) {
  let raw = null;
  const problems = [];
  try {
    raw = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync((0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_1__.statePath)(root, CONFIG_FILE), 'utf8'));
  } catch (err) {
    if (err && err.code !== 'ENOENT') problems.push('config-unreadable-or-invalid-json');
  }
  const n = normalizeConfig(raw);
  return { config: n.config, problems: [...problems, ...n.problems] };
}


/***/ }),

/***/ 59381:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Fr: () => (/* binding */ ENTRYPOINT_KINDS),
/* harmony export */   Os: () => (/* binding */ collectEntrypoints),
/* harmony export */   kD: () => (/* binding */ countDispositions)
/* harmony export */ });
/* unused harmony export DISPOSITIONS */
/* harmony import */ var _canonical_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(44652);
/* harmony import */ var _spans_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(77311);
/* harmony import */ var _controls_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(17202);
/* harmony import */ var _posture_entrypoint_inventory_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(11366);
/* harmony import */ var _imports_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(86588);
//
// Entry points -> exact handler symbols.
//
// There is NO second route detector here. HTTP routes come from the engine's own route scan (`scanRoutes`) and, for
// Haskell, from the existing web model (`analyzeHaskellWeb`); non-HTTP surfaces come from the existing entry-point
// inventory. What this module adds is the join the context packer needs and the existing records do not carry: which
// declaration is the handler, which middleware wraps it, and an honest disposition for every route.
//
// Every detected entry point ends in exactly ONE disposition:
//   resolved             handler is a known declaration and nothing about how it is wired is in doubt
//   partially_resolved   a handler (or a registration block) is known, but something is not: a middleware that does
//                        not resolve, a handler matched by name only, a router whose mount point is not visible
//   unresolved           no handler could be identified; the manifest still exists and says so
//   excluded_by_policy   deliberately not processed (operator exclusion, or the entry-point cap)






const DISPOSITIONS = Object.freeze(['resolved', 'partially_resolved', 'unresolved', 'excluded_by_policy']);
const ENTRYPOINT_KINDS = Object.freeze(['http', 'webhook', 'queue', 'cron', 'upload', 'cli']);

const JS_FILE = /\.(?:js|jsx|mjs|cjs|ts|tsx)$/i;
const HS_FILE = /\.l?hs$/i;
const INLINE_FN = /^(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::\s*[\w<>\[\]|. ]+)?\s*=>|[A-Za-z_$][\w$]*\s*=>|\\)/;
const IDENT_CHAIN = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*/;

function lastSeg(n) { const p = String(n).split(/[.:]/); return p[p.length - 1]; }

function globToRe(g) {
  const esc = String(g).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\0').replace(/\*/g, '[^/]*').replace(/\0/g, '.*');
  return new RegExp(`^${esc}$`);
}

function symbolIndexes(graph) {
  const byFile = new Map();
  const byName = new Map();
  const byId = new Map();
  const imports = new Map();
  for (const i of graph.imports || []) { if (!imports.has(i.file)) imports.set(i.file, []); imports.get(i.file).push(i); }
  for (const s of graph.symbols) {
    byId.set(s.id, s);
    if (!byFile.has(s.file)) byFile.set(s.file, []);
    byFile.get(s.file).push(s);
    if (s.kind === 'function' && !s.name.startsWith('<')) {
      for (const key of new Set([s.name, lastSeg(s.name)])) {
        if (!byName.has(key)) byName.set(key, []);
        byName.get(key).push(s);
      }
    }
  }
  for (const arr of byFile.values()) arr.sort((a, b) => a.declLine - b.declLine || (a.id < b.id ? -1 : 1));
  return { byFile, byName, byId, imports };
}

/** Resolve a referenced name to a symbol: same-file exact, then project-unique by name (low confidence). */
function resolveName(name, file, idx) {
  // an import statement binds the name to a specific module: that beats any project-wide guess
  const imp = (idx.imports.get(file) || []).find(i => i.local === name.split('.')[0]);
  if (imp && imp.kind === 'repo') {
    const member = name.includes('.') ? name.split('.').pop() : (imp.member === '*' || imp.member === 'default' ? name : imp.member);
    const hit = (idx.byName.get(member) || []).filter(s => s.file === imp.target);
    if (hit.length === 1) return { symbol: hit[0], resolution: 'resolved', via: 'import' };
  }
  const exact = (idx.byName.get(name) || []).filter(s => s.file === file);
  if (exact.length === 1) return { symbol: exact[0], resolution: 'resolved' };
  if (exact.length > 1) return { symbol: null, resolution: 'ambiguous', candidates: exact.map(s => s.id) };
  const key = lastSeg(name);
  const all = idx.byName.get(name) || idx.byName.get(key) || [];
  if (all.length === 1) return { symbol: all[0], resolution: 'name-match' };
  if (all.length > 1) return { symbol: null, resolution: 'ambiguous', candidates: all.slice(0, 5).map(s => s.id) };
  return { symbol: null, resolution: 'unresolved' };
}

/** `X.use(...)` registrations in a JS/TS file: the global / prefix middleware a route can inherit. */
function collectUses(fileContents) {
  const uses = [];
  for (const [file, text] of Object.entries(fileContents)) {
    if (!JS_FILE.test(file)) continue;
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const m = /^\s*([A-Za-z_$][\w$]*)\.use\s*\(/.exec(lines[i]);
      if (!m) continue;
      const st = (0,_spans_js__WEBPACK_IMPORTED_MODULE_4__/* .callStatement */ .yP)(lines, i + 1);
      if (!st) continue;
      const args = (0,_spans_js__WEBPACK_IMPORTED_MODULE_4__/* .splitArgs */ .sG)(st.text);
      let prefix = '/';
      let rest = args;
      const q = args[0] && /^(['"`])(.*)\1$/.exec(args[0]);
      if (q) { prefix = q[2]; rest = args.slice(1); }
      // GA-03.2: a first argument that is a call, a template with interpolation or a concatenation is a prefix
      // the scan cannot read; the use still records its middleware, but nothing is mounted under a guessed '/'.
      const prefixDynamic = !q && !!args[0] && (/^[A-Za-z_$][\w$.]*\s*\(/.test(args[0]) && !/^require\s*\(/.test(args[0]) || /\$\{|\+/.test(args[0]));
      const names = rest.map(a => { const id = IDENT_CHAIN.exec(a.replace(/^\[|\]$/g, '')); return id ? { name: id[0], text: a } : { name: null, text: a }; });
      uses.push({ file, line: i + 1, receiver: m[1], prefix, prefixDynamic, args: names });
    }
  }
  return uses;
}

function routeKey(r) { return `${r.file}|${r.line}|${r.method}|${r.path}`; }

async function collectRoutes(fileContents) {
  const { scanRoutes } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 67198));
  const { analyzeHaskellWeb } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 18542));
  const routes = [];
  const seen = new Set();
  const add = (r) => { const k = routeKey(r); if (!seen.has(k)) { seen.add(k); routes.push(r); } };
  const hs = {};
  for (const file of Object.keys(fileContents).sort()) {
    if (HS_FILE.test(file)) { hs[file] = fileContents[file]; continue; }
    let found = [];
    try { found = scanRoutes(file, fileContents[file]) || []; } catch { found = []; }
    for (const r of found) add({ ...r, language: 'generic' });
  }
  if (Object.keys(hs).length) {
    let web = null;
    try { web = analyzeHaskellWeb(hs); } catch { web = null; }
    if (web) for (const r of web.routes) add({ method: r.method, path: r.path, framework: r.framework, file: r.file, line: r.line, hasAuth: r.auth.status === 'authenticated', language: 'haskell', handler: r.handler, webModel: { auth: r.auth, role: r.role, ownership: r.ownership, idLookups: r.idLookups, csrf: r.csrf, sensitive: r.sensitive, uploads: r.uploads } });
  }
  return routes;
}

function resolveHandler(route, ctx) {
  const { fileContents, idx, graph } = ctx;
  const lines = fileContents[route.file].split('\n');
  const reasons = [];
  const out = { handlerSymbol: null, handlerKind: 'unknown', rootSpan: null, middleware: [], reasons, confidence: 'none' };
  const fileSyms = idx.byFile.get(route.file) || [];

  if (route.language === 'haskell') {
    const h = route.handler || {};
    if (h.kind === 'named' && h.name) {
      const r = resolveName(h.name, route.file, idx);
      if (r.symbol) { out.handlerSymbol = r.symbol.id; out.handlerKind = 'named'; out.confidence = r.resolution === 'resolved' ? 'exact' : 'name-match'; if (r.resolution !== 'resolved') reasons.push('handler-matched-by-name-only'); }
      else reasons.push(`handler-${r.resolution}`);
    } else if (h.kind === 'inline') {
      out.handlerKind = 'inline';
      out.rootSpan = { file: route.file, ...(0,_spans_js__WEBPACK_IMPORTED_MODULE_4__/* .inlineBlockSpan */ .$X)(lines, route.line) };
      const enclosing = fileSyms.filter(s => s.kind === 'function' && s.startLine <= route.line && s.endLine >= route.line).sort((a, b) => (b.startLine - a.startLine))[0];
      out.handlerSymbol = enclosing ? enclosing.id : null;
      out.confidence = enclosing ? 'inline-block' : 'none';
      if (!enclosing) reasons.push('inline-handler-without-enclosing-declaration');
    } else {
      reasons.push('handler-not-statically-known');
      // the manifest still shows where the route is registered, so the gap is inspectable rather than absent
      out.rootSpan = { file: route.file, ...(0,_spans_js__WEBPACK_IMPORTED_MODULE_4__/* .inlineBlockSpan */ .$X)(lines, route.line) };
    }
    return out;
  }

  const rawLine = lines[route.line - 1] || '';
  if (/^\s*@/.test(rawLine)) {
    // decorator / annotation style: the handler is the next declaration
    const decl = fileSyms.filter(s => s.kind === 'function' && s.declLine >= route.line && s.declLine <= route.line + 12).sort((a, b) => a.declLine - b.declLine)[0];
    if (decl) {
      out.handlerSymbol = decl.id; out.handlerKind = 'decorated'; out.confidence = 'exact';
      // dependency-injected guards in the signature (`user=Depends(require_user)`) run before the body
      for (const d of (0,_controls_js__WEBPACK_IMPORTED_MODULE_1__/* .dependencyParams */ .qr)((0,_controls_js__WEBPACK_IMPORTED_MODULE_1__/* .signatureText */ .gs)(lines, decl.declLine))) {
        const r = resolveName(d.dependency, route.file, idx);
        out.middleware.push({ name: d.dependency, symbolId: r.symbol ? r.symbol.id : null, resolution: r.resolution, line: decl.declLine, dependency: true, param: d.param });
        if (!r.symbol) reasons.push(`dependency-${r.resolution}:${d.dependency}`);
        else if (r.resolution === 'name-match') reasons.push(`dependency-matched-by-name-only:${d.dependency}`);
      }
    }
    else reasons.push('decorated-handler-not-found');
    return out;
  }

  const st = JS_FILE.test(route.file) ? (0,_spans_js__WEBPACK_IMPORTED_MODULE_4__/* .callStatement */ .yP)(lines, route.line) : null;
  if (!st) {
    // not a call-style registration we can parse: fall back to the enclosing declaration, flagged
    const enclosing = fileSyms.filter(s => s.kind === 'function' && s.startLine <= route.line && s.endLine >= route.line).sort((a, b) => b.startLine - a.startLine)[0];
    if (enclosing) { out.handlerSymbol = enclosing.id; out.handlerKind = 'enclosing'; out.confidence = 'enclosing'; reasons.push('registration-form-not-parsed'); }
    else reasons.push('registration-form-not-parsed');
    return out;
  }
  out.rootSpan = { file: route.file, startLine: route.line, endLine: st.endLine, precision: 'brace' };
  const args = (0,_spans_js__WEBPACK_IMPORTED_MODULE_4__/* .splitArgs */ .sG)(st.text).slice(1); // drop the path
  const flat = [];
  for (const a of args) {
    if (a.startsWith('[') && a.endsWith(']')) flat.push(...(0,_spans_js__WEBPACK_IMPORTED_MODULE_4__/* .splitArgs */ .sG)(`(${a.slice(1, -1)})`));
    else flat.push(a);
  }
  if (!flat.length) { reasons.push('registration-has-no-handler-argument'); return out; }
  const last = flat[flat.length - 1];
  for (let i = 0; i < flat.length - 1; i++) {
    const a = flat[i];
    if (INLINE_FN.test(a)) { out.middleware.push({ name: '<inline>', symbolId: null, resolution: 'inline', line: route.line }); continue; }
    const id = IDENT_CHAIN.exec(a);
    if (!id) { out.middleware.push({ name: null, text: a.slice(0, 80), symbolId: null, resolution: 'unresolved', line: route.line }); reasons.push('middleware-not-an-identifier'); continue; }
    const r = resolveName(id[0], route.file, idx);
    out.middleware.push({ name: id[0], symbolId: r.symbol ? r.symbol.id : null, resolution: r.resolution, line: route.line, factory: /\(/.test(a) });
    if (!r.symbol) reasons.push(`middleware-${r.resolution}:${id[0]}`);
    else if (r.resolution === 'name-match') reasons.push(`middleware-matched-by-name-only:${id[0]}`);
  }
  if (INLINE_FN.test(last)) {
    const cands = fileSyms.filter(s => s.kind === 'function' && s.name.startsWith('<anon>') === false && false);
    const anon = fileSyms.filter(s => s.id.includes('::<anon>@') && s.declLine >= route.line && s.declLine <= st.endLine);
    const outermost = anon.filter(a => !anon.some(b => b !== a && b.startLine <= a.startLine && b.endLine >= a.endLine && (b.startLine < a.startLine || b.endLine > a.endLine)));
    void cands;
    const pick = outermost.sort((a, b) => a.declLine - b.declLine || (a.id < b.id ? -1 : 1)).pop();
    if (pick) { out.handlerSymbol = pick.id; out.handlerKind = 'inline'; out.confidence = 'exact'; }
    else reasons.push('inline-handler-not-in-ir');
  } else {
    const id = IDENT_CHAIN.exec(last);
    if (!id) { reasons.push('handler-not-an-identifier'); }
    else {
      const r = resolveName(id[0], route.file, idx);
      if (r.symbol) { out.handlerSymbol = r.symbol.id; out.handlerKind = 'named'; out.confidence = r.resolution === 'resolved' ? 'exact' : 'name-match'; if (r.resolution !== 'resolved') reasons.push('handler-matched-by-name-only'); }
      else reasons.push(`handler-${r.resolution}:${id[0]}`);
    }
  }
  void graph;
  return out;
}

// ── Router mounts (GA-03.2, 0.195.26) ──────────────────────────────────────
//
// `router.get('/:id', h)` is reachable at `/users/:id` only through `app.use('/users', router)`, and that mount
// can sit in another file (`app.use('/users', require('./users'))`, `import users from './users.js'`). Before
// this, every route on a router-looking receiver was `partially_resolved` with `router-mount-not-resolved` and
// its path was the local one. Now a mount is found when the mounted argument is (a) a receiver with routes in
// the same file, (b) a name imported from a file whose `module.exports` / `export default` is that file's
// router receiver, or (c) an inline `require('./x')` of such a file. Mounts compose: `app.use('/api', v1)` and
// `v1.use('/users', users)` make `/api/users/:id`. A router mounted at several prefixes is reachable at each,
// so it yields one entry point per prefix (sorted; at most MAX_MOUNT_PATHS). Depth is bounded; a cycle stops.
// A mount's other identifier arguments (`app.use('/api', auth, router)`) are middleware every mounted route
// inherits, recorded with the mount's prefix as their scope. What stays unresolved: a router passed through a
// variable the import map cannot follow, a mount whose prefix is not a string literal, a dynamic
// `app.use(prefixVar, router)`, and anything registered outside the scanned files.
const MAX_MOUNT_DEPTH = 4;
const MAX_MOUNT_PATHS = 8;
const ROUTE_RECEIVER_RE = /([A-Za-z_$][\w$]*)\.(?:get|post|put|patch|delete|all|options|head|route)\s*\(/;
const ROUTER_NAME_RE = /^(?:router|routes?|r|api|\w*Router)$/i;

function routeReceiver(fileContents, route) {
  if (!JS_FILE.test(route.file)) return null;
  const line = (fileContents[route.file] || '').split('\n')[route.line - 1] || '';
  const m = ROUTE_RECEIVER_RE.exec(line);
  return m ? m[1] : null;
}

/** The receiver a file exports as its module (`module.exports = router`, `export default router`), or null. */
function exportedReceiver(text) {
  const t = String(text || '');
  const m = /\bmodule\.exports\s*=\s*([A-Za-z_$][\w$]*)\s*;?/.exec(t) || /\bexport\s+default\s+([A-Za-z_$][\w$]*)\s*;?/.exec(t);
  return m ? m[1] : null;
}

function joinMountPath(prefix, routePath) {
  const p = String(prefix || '/').replace(/\/+$/, '');
  const r = String(routePath || '');
  if (!p) return r.startsWith('/') ? r : '/' + r;
  if (!r || r === '/') return p;
  return p + (r.startsWith('/') ? r : '/' + r);
}

/**
 * Every mount of a router: key `${file}|${receiver}` -> [{ prefix, file, line, receiver, middleware }], where
 * `receiver` is the receiver the router was mounted ON (so a chain can be followed upward).
 */
function buildMountIndex(fileContents, uses, routes) {
  const files = new Set(Object.keys(fileContents));
  const imports = (0,_imports_js__WEBPACK_IMPORTED_MODULE_3__/* .buildImportMap */ .kB)(fileContents);
  const receiversByFile = new Map();
  for (const r of routes) {
    const recv = routeReceiver(fileContents, r);
    if (!recv) continue;
    if (!receiversByFile.has(r.file)) receiversByFile.set(r.file, new Set());
    receiversByFile.get(r.file).add(recv);
  }
  // a receiver that mounts something is a router too (an intermediate `v1.use('/users', users)`)
  for (const u of uses) { if (!receiversByFile.has(u.file)) receiversByFile.set(u.file, new Set()); receiversByFile.get(u.file).add(u.receiver); }
  const index = new Map();
  const add = (file, receiver, mount) => { const k = `${file}|${receiver}`; if (!index.has(k)) index.set(k, []); index.get(k).push(mount); };
  // a module is a router module only when its exported receiver registers routes or mounts in that file
  const isRouter = (file, receiver) => !!receiver && (receiversByFile.get(file) || new Set()).has(receiver);
  for (const u of uses) {
    if (u.prefixDynamic) continue;
    const middleware = [];
    for (const a of u.args) {
      let target = null;
      const req = /^require\(\s*(['"])([^'"]+)\1\s*\)$/.exec(String(a.text || '').trim());
      if (req) {
        const res = (0,_imports_js__WEBPACK_IMPORTED_MODULE_3__/* .resolveJsModule */ .iC)(u.file, req[2], files);
        const recv = res && res.target && files.has(res.target) ? exportedReceiver(fileContents[res.target]) : null;
        if (recv && isRouter(res.target, recv)) target = { file: res.target, receiver: recv };
      } else if (a.name && a.name !== u.receiver && isRouter(u.file, a.name)) {
        target = { file: u.file, receiver: a.name };
      } else if (a.name) {
        const via = (0,_imports_js__WEBPACK_IMPORTED_MODULE_3__/* .resolveViaImports */ .xU)(imports, u.file, a.name);
        const recv = via && via.kind === 'exact-import' && via.targetFile && files.has(via.targetFile) ? exportedReceiver(fileContents[via.targetFile]) : null;
        if (recv && isRouter(via.targetFile, recv)) target = { file: via.targetFile, receiver: recv };
      }
      if (target) add(target.file, target.receiver, { prefix: u.prefix, file: u.file, line: u.line, receiver: u.receiver, middleware: [...middleware] });
      else if (a.name && !req) middleware.push(a.name);
    }
  }
  return index;
}

/** The mount chains (root first) through which (file, receiver) is reachable; [] when it is mounted nowhere. */
function mountChains(index, file, receiver, depth = 0, seen = new Set()) {
  const key = `${file}|${receiver}`;
  const mounts = index.get(key) || [];
  if (!mounts.length || depth >= MAX_MOUNT_DEPTH || seen.has(key)) return [];
  const out = [];
  const next = new Set(seen); next.add(key);
  for (const m of mounts) {
    const parents = mountChains(index, m.file, m.receiver, depth + 1, next);
    if (!parents.length) out.push([m]);
    else for (const pc of parents) out.push([...pc, m]);
    if (out.length >= MAX_MOUNT_PATHS) break;
  }
  return out.slice(0, MAX_MOUNT_PATHS);
}

function pathMatchesPrefix(routePath, prefix) {
  if (prefix === '/' || prefix === '') return true;
  const p = prefix.replace(/\/+$/, '');
  return routePath === p || routePath.startsWith(p + '/') || routePath.startsWith(p);
}

/**
 * Build the entry-point records.
 *   config.entrypointKinds, config.exclude (globs on file or route path), config.maxEntrypoints
 */
async function collectEntrypoints({ fileContents, graph, config = {} }) {
  const kinds = new Set(config.entrypointKinds && config.entrypointKinds.length ? config.entrypointKinds : ['http']);
  const idx = symbolIndexes(graph);
  const uses = collectUses(fileContents);
  const routes = (kinds.has('http') || kinds.has('webhook')) ? await collectRoutes(fileContents) : [];
  const mountIndex = buildMountIndex(fileContents, uses, routes);
  const exclude = (config.exclude || []).map(globToRe);
  const cap = Number.isInteger(config.maxEntrypoints) && config.maxEntrypoints > 0 ? config.maxEntrypoints : 5000;
  const ctx = { fileContents, idx, graph };
  const records = [];

  if (kinds.has('http') || kinds.has('webhook')) {
    for (const route of routes) {
      const isWebhook = /webhook/i.test(route.path || '');
      if (isWebhook && !kinds.has('webhook') && !kinds.has('http')) continue;
      const h = resolveHandler(route, ctx);
      const reasons = [...h.reasons];
      const middleware = [...h.middleware];
      const receiver = routeReceiver(fileContents, route);
      const chains = receiver ? mountChains(mountIndex, route.file, receiver) : [];
      // inherited middleware registered with `X.use(...)` on the same receiver, earlier in the same file
      if (JS_FILE.test(route.file)) {
        for (const u of uses) {
          if (u.file !== route.file || u.line >= route.line || u.receiver !== receiver) continue;
          if (!pathMatchesPrefix(String(route.path || ''), u.prefix)) continue;
          for (const a of u.args) {
            if (!a.name) { middleware.push({ name: null, text: a.text.slice(0, 80), symbolId: null, resolution: 'unresolved', line: u.line, scope: u.prefix, inherited: true }); reasons.push('inherited-middleware-not-an-identifier'); continue; }
            const r = resolveName(a.name, u.file, idx);
            middleware.push({ name: a.name, symbolId: r.symbol ? r.symbol.id : null, resolution: r.resolution, line: u.line, scope: u.prefix, inherited: true });
            if (!r.symbol) reasons.push(`inherited-middleware-${r.resolution}:${a.name}`);
          }
        }
        if (receiver && !chains.length && ROUTER_NAME_RE.test(receiver)) reasons.push('router-mount-not-resolved');
      }
      // middleware the mount statements apply to everything mounted under them (`app.use('/api', auth, router)`):
      // per chain, so a router mounted twice inherits each mount's own middleware and not the other's
      const chainMiddleware = (chain) => {
        const mw = []; const why = [];
        for (const hop of chain) {
          for (const name of hop.middleware) {
            const r = resolveName(name, hop.file, idx);
            mw.push({ name, symbolId: r.symbol ? r.symbol.id : null, resolution: r.resolution, line: hop.line, scope: hop.prefix, inherited: true, viaMount: true });
            if (!r.symbol) why.push(`inherited-middleware-${r.resolution}:${name}`);
          }
        }
        return { mw, why };
      };
      const authScheme = route.webModel
        ? { status: route.webModel.auth.status, kind: route.webModel.auth.kind || null, basis: 'haskell-web-model', role: route.webModel.role.status, ownership: route.webModel.ownership || null, idLookups: route.webModel.idLookups || [], csrf: !!route.webModel.csrf }
        : { status: route.hasAuth ? 'authenticated' : 'none', basis: 'route-scan-heuristic', note: 'authentication seen near the registration; says nothing about ownership' };
      const mountsOf = chains.map(chain => ({
        prefix: chain.reduce((acc, hop) => joinMountPath(acc, hop.prefix), '/'),
        chain: chain.map(hop => ({ file: hop.file, line: hop.line, receiver: hop.receiver, prefix: hop.prefix })),
        ...chainMiddleware(chain),
      })).sort((a, b) => (a.prefix < b.prefix ? -1 : a.prefix > b.prefix ? 1 : 0));
      const base = {
        kind: isWebhook ? 'webhook' : 'http',
        method: String(route.method || 'GET'),
        pathTemplate: String(route.path || ''),
        registeredPath: String(route.path || ''),
        mount: null,
        framework: route.framework || null,
        language: route.language === 'haskell' ? 'haskell' : (JS_FILE.test(route.file) ? 'javascript' : (route.file.split('.').pop())),
        registrationSite: { file: route.file, line: route.line },
        handlerSymbol: h.handlerSymbol,
        handlerKind: h.handlerKind,
        handlerConfidence: h.confidence,
        rootSpan: h.rootSpan,
        middleware,
        authScheme,
        externalDependencies: [],
        resolutionReasons: [...new Set(reasons)].sort(),
      };
      if (!mountsOf.length) { records.push(base); continue; }
      for (const m of mountsOf) {
        const { mw, why, ...mount } = m;
        records.push({
          ...base, pathTemplate: joinMountPath(mount.prefix, base.registeredPath), mount: { ...mount, alternatives: mountsOf.length },
          middleware: [...base.middleware.map(x => ({ ...x })), ...mw],
          resolutionReasons: [...new Set([...base.resolutionReasons, ...why])].sort(),
        });
      }
    }
  }

  // non-HTTP surfaces from the existing inventory
  const wantInv = ['queue', 'cron', 'upload', 'cli', 'webhook'].filter(k => kinds.has(k));
  if (wantInv.length) {
    const inv = (0,_posture_entrypoint_inventory_js__WEBPACK_IMPORTED_MODULE_2__/* .buildEntrypointInventory */ .f6)(fileContents, { routes: [] });
    for (const e of inv.entrypoints) {
      if (!wantInv.includes(e.type)) continue;
      const fileSyms = idx.byFile.get(e.file) || [];
      const enclosing = fileSyms.filter(s => s.kind === 'function' && s.startLine <= e.line && s.endLine >= e.line).sort((a, b) => b.startLine - a.startLine)[0];
      records.push({
        kind: e.type, method: '', pathTemplate: e.name, framework: null,
        language: JS_FILE.test(e.file) ? 'javascript' : e.file.split('.').pop(),
        registrationSite: { file: e.file, line: e.line },
        handlerSymbol: enclosing ? enclosing.id : null,
        handlerKind: enclosing ? 'enclosing' : 'unknown', handlerConfidence: enclosing ? 'enclosing' : 'none',
        rootSpan: null, middleware: [],
        authScheme: { status: e.trust === 'authenticated' ? 'authenticated' : 'none', basis: 'inventory-heuristic' },
        externalDependencies: [],
        resolutionReasons: enclosing ? ['non-http-handler-is-enclosing-declaration'] : ['no-enclosing-declaration'],
      });
    }
  }

  // ids, dispositions
  records.sort((a, b) =>
    (a.registrationSite.file < b.registrationSite.file ? -1 : a.registrationSite.file > b.registrationSite.file ? 1 : 0) ||
    (a.registrationSite.line - b.registrationSite.line) || (a.method < b.method ? -1 : 1) || (a.pathTemplate < b.pathTemplate ? -1 : a.pathTemplate > b.pathTemplate ? 1 : 0));
  const ord = new Map();
  records.forEach((r, i) => {
    const hname = r.handlerSymbol || `@${r.registrationSite.line}`;
    const stem = (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .hashOf */ .qQ)({ k: r.kind, m: r.method, p: r.pathTemplate, f: r.registrationSite.file, h: r.handlerSymbol ? r.handlerSymbol : null });
    const n = (ord.get(stem) || 0) + 1;
    ord.set(stem, n);
    r.id = `ep:${stem.slice(0, 20)}${n > 1 ? `-${n}` : ''}`;
    r.label = (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .safeLabel */ .IW)(`${r.method ? r.method + ' ' : ''}${r.pathTemplate}`) || r.kind;
    void hname;
    let disposition;
    const excluded = exclude.some(re => re.test(r.registrationSite.file) || re.test(r.pathTemplate));
    if (excluded) { disposition = 'excluded_by_policy'; r.resolutionReasons = [...r.resolutionReasons, 'excluded-by-operator-pattern']; }
    else if (i >= cap) { disposition = 'excluded_by_policy'; r.resolutionReasons = [...r.resolutionReasons, 'max-entrypoints-cap']; }
    else if (!r.handlerSymbol && !r.rootSpan) disposition = 'unresolved';
    else if (!r.handlerSymbol) disposition = 'partially_resolved';
    else if (r.resolutionReasons.length) disposition = 'partially_resolved';
    else disposition = 'resolved';
    r.disposition = disposition;
  });
  return records;
}

/** Counts per disposition. Every entry point is in exactly one bucket, so the buckets always sum to the total. */
function countDispositions(records) {
  const c = { total: records.length, resolved: 0, partially_resolved: 0, unresolved: 0, excluded_by_policy: 0 };
  for (const r of records) c[r.disposition]++;
  return c;
}


/***/ }),

/***/ 72873:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   RA: () => (/* binding */ readSnapshot),
/* harmony export */   zK: () => (/* binding */ readGitSnapshot)
/* harmony export */ });
/* unused harmony exports SOURCE_EXTS, IGNORE_GLOBS */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(31421);
/* harmony import */ var _util_glob_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(30397);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(31174);
/* harmony import */ var _canonical_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(44652);
//
// Which files DCI analyses, and how they are read. Reading goes through `readRepoFile`, so a symlink, a file that
// resolves outside the repository, or an oversized file is skipped with a counted reason, never followed.







const SOURCE_EXTS = /\.(?:js|jsx|mjs|cjs|ts|tsx|py|java|cs|kt|go|php|rb|rs|c|cc|cpp|h|hpp|l?hs|nix)$/i;
const IGNORE_GLOBS = ['node_modules/**', '.git/**', 'dist/**', 'build/**', 'vendor/**', '**/.agentic-security/**', 'dist-newstyle/**', '.stack-work/**', '.direnv/**', 'coverage/**', '**/*.min.js'];

/** Read the analysable source set. Returns { ok, fileContents, skipped, snapshotHash } or { ok:false, reason }. */
async function readSnapshot(root, { maxFiles = 3000 } = {}) {
  let rootReal;
  try { rootReal = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(root); } catch { return { ok: false, reason: 'root-not-found' }; }
  const rels = (await (0,_util_glob_js__WEBPACK_IMPORTED_MODULE_3__/* .listFiles */ .CS)(rootReal, { ignore: IGNORE_GLOBS })).filter(f => SOURCE_EXTS.test(f)).sort();
  if (rels.length > maxFiles) return { ok: false, reason: 'too-many-files', count: rels.length, limit: maxFiles };
  const fileContents = {};
  const skipped = [];
  for (const rel of rels) {
    const r = (0,_canonical_js__WEBPACK_IMPORTED_MODULE_5__/* .readRepoFile */ .v6)(rootReal, rel);
    if (r.ok) fileContents[rel] = r.text;
    else skipped.push({ file: rel, reason: r.reason });
  }
  for (const l of findSymlinks(rootReal)) skipped.push({ file: l, reason: 'symlink' });
  skipped.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  return { ok: true, rootReal, fileContents, skipped, snapshotHash: (0,_canonical_js__WEBPACK_IMPORTED_MODULE_5__/* .snapshotHashOf */ .w9)(fileContents) };
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'vendor', _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_4__/* .STATE_DIR_NAME */ .Ky, 'dist-newstyle', '.stack-work', '.direnv', 'coverage']);

/** Symlinked source files and directories (never followed), so they are counted as skipped instead of vanishing. */
function findSymlinks(rootReal, limit = 5000) {
  const found = [];
  let seen = 0;
  const walk = (abs, rel) => {
    let entries;
    try { entries = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(abs, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (++seen > limit) return;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { if (e.name.indexOf('.') === -1 || SOURCE_EXTS.test(e.name)) found.push(r); continue; }
      if (e.isDirectory() && !SKIP_DIRS.has(e.name)) walk(node_path__WEBPACK_IMPORTED_MODULE_1__.join(abs, e.name), r);
    }
  };
  walk(rootReal, '');
  return found;
}

/**
 * Read the analysable source set as it was at a git ref, without touching the working tree. `ref` is passed to git as a
 * single argv element after `--end-of-options`-style validation, never through a shell. Returns the same shape as
 * `readSnapshot`, or { ok:false, reason }.
 */
function readGitSnapshot(root, ref, { maxFiles = 3000 } = {}) {
  if (typeof ref !== 'string' || !/^[A-Za-z0-9._\/~^@{}:-]{1,200}$/.test(ref) || ref.startsWith('-')) return { ok: false, reason: 'bad-ref' };
  let rootReal;
  try { rootReal = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(root); } catch { return { ok: false, reason: 'root-not-found' }; }
  const git = (args, max = 64 * 1024 * 1024) => (0,node_child_process__WEBPACK_IMPORTED_MODULE_2__.execFileSync)('git', ['-C', rootReal, ...args], { encoding: 'utf8', timeout: 30000, maxBuffer: max, stdio: ['ignore', 'pipe', 'ignore'] });
  let commit;
  try { commit = git(['rev-parse', '--verify', `${ref}^{commit}`]).trim(); } catch { return { ok: false, reason: 'unknown-ref' }; }
  let names;
  try { names = git(['ls-tree', '-r', '--name-only', '-z', commit]).split('\0').filter(Boolean); } catch { return { ok: false, reason: 'ls-tree-failed' }; }
  const ignore = IGNORE_GLOBS.map(g => new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*\//g, '(?:.*/)?').replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*') + '$'));
  const rels = names.filter(f => SOURCE_EXTS.test(f) && (0,_canonical_js__WEBPACK_IMPORTED_MODULE_5__/* .safeRelPath */ .Qz)(f) === f && !ignore.some(re => re.test(f))).sort();
  if (rels.length > maxFiles) return { ok: false, reason: 'too-many-files', count: rels.length, limit: maxFiles };
  const fileContents = {};
  const skipped = [];
  for (const rel of rels) {
    try {
      const mode = git(['ls-tree', commit, '--', rel]).split(' ')[0];
      if (mode === '120000' || mode === '160000') { skipped.push({ file: rel, reason: 'symlink-or-submodule' }); continue; }
      const text = git(['show', `${commit}:${rel}`], 2 * 1024 * 1024);
      fileContents[rel] = (0,_canonical_js__WEBPACK_IMPORTED_MODULE_5__/* .normalizeText */ .fQ)(text);
    } catch { skipped.push({ file: rel, reason: 'unreadable-at-ref' }); }
  }
  return { ok: true, rootReal, fileContents, skipped, snapshotHash: (0,_canonical_js__WEBPACK_IMPORTED_MODULE_5__/* .snapshotHashOf */ .w9)(fileContents), commit };
}


/***/ })

};
