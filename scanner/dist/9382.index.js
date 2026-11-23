export const id = 9382;
export const ids = [9382];
export const modules = {

/***/ 84050:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   D: () => (/* binding */ reviewsToCandidates),
/* harmony export */   p: () => (/* binding */ adjudicate)
/* harmony export */ });
/* harmony import */ var _canonical_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(44652);
/* harmony import */ var _discovery_confirm_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(64547);
/* harmony import */ var _discovery_disprove_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(93953);
/* harmony import */ var _discovery_judge_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(79704);
//
// Review results -> existing discovery candidates -> existing adjudication.
//
// A DCI review is a hypothesis. This module normalises an accepted `potential_issue` into the SAME candidate schema the
// `hunt` pipeline uses, so the existing machinery decides what happens next and nothing about it is reimplemented here:
//
//   confirm.js   routes the candidate back through the taint engine. A novel authorization or business-logic
//                hypothesis the taint engine cannot prove stays `unconfirmed`; it is neither rejected nor promoted.
//   disprove.js  the only stage that may remove a candidate, and only by an argued majority.
//   judge.js     shapes the finding. Severity comes from the CONFIRMATION TIER (taint-confirmed high, sink-adjacent
//                medium, unconfirmed low). A model's confidence, likelihood or adjectives are never an input, and
//                nothing here can produce `critical`.
//
// One shared defect reached through many routes is ONE candidate with many witnesses, not many top-level findings.





const SINK_ROLES = ['data-access', 'database-read', 'database-write', 'state-change', 'sink', 'side-effect'];

function normalizeInvariant(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim(); }

function primaryEvidence(evidence) {
  for (const role of SINK_ROLES) {
    const hit = evidence.find(e => e.role === role);
    if (hit) return hit;
  }
  return evidence[0];
}

/**
 * Build candidates from verified reviews.
 *   records   [{ review, entrypoints: [{id,label}], pack }]  (only status 'completed' + 'potential_issue' qualifies)
 */
function reviewsToCandidates(records) {
  const groups = new Map();
  for (const r of records) {
    const rv = r.review;
    if (!rv || rv.status !== 'completed' || rv.conclusion !== 'potential_issue' || !rv.evidence.length) continue;
    const ev = primaryEvidence(rv.evidence);
    const key = (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)(`${r.pack.id}|${ev.file}|${ev.startLine}|${normalizeInvariant(rv.invariant)}`).slice(0, 12);
    if (!groups.has(key)) {
      groups.set(key, {
        id: key,
        focusAreaId: String(rv.contextHash).slice(0, 12),
        lens: r.pack.lens,
        title: `${r.pack.title}: ${r.entrypoints[0].label}`,
        file: ev.file,
        line: ev.startLine,
        family: r.pack.family,
        cwe: r.pack.cwe,
        rationale: rv.narrative || rv.invariant,
        entryPoint: r.entrypoints.map(e => e.label).join('; '),
        sink: ev.claim || ev.role,
        origin: 'context-intelligence',
        questionPack: rv.questionPack,
        advisoryOnly: rv.advisoryOnly === true,
        witnesses: [],
        sourceSpanEvidence: rv.evidence.map(e => ({ role: e.role, file: e.file, startLine: e.startLine, endLine: e.endLine })),
        scopeIntegrity: { contextIntegrity: rv.contextIntegrity, standalone: rv.standalone, deterministicAgreement: rv.deterministicAgreement, deterministicProtection: rv.deterministicProtection || null },
        reviewStatus: rv.status,
        uncertainties: rv.uncertainties,
        recommendedValidation: rv.recommendedValidation,
      });
    }
    const g = groups.get(key);
    for (const e of r.entrypoints) {
      if (!g.witnesses.some(w => w.entrypointId === e.id)) g.witnesses.push({ entrypointId: e.id, label: e.label, contextHash: rv.contextHash, questionPack: rv.questionPack });
    }
  }
  return [...groups.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
}

/**
 * Run the existing adjudication. All stages are optional and injected:
 *   taintProbe   -> confirm.js     refute -> disprove.js (needs a governed invoker: `{ llmInvoke | endpoint policy }`)
 * Returns { findings, duplicates, suppressed, refuted, advisory }. `findings` carry a `contextIntelligence` block and
 * `parser: 'DISCOVERY'`, so the report layer keeps them advisory exactly as it does for `hunt`.
 */
async function adjudicate(candidates, opts = {}) {
  const advisory = candidates.filter(c => c.advisoryOnly);
  const real = candidates.filter(c => !c.advisoryOnly);
  const confirmed = await (0,_discovery_confirm_js__WEBPACK_IMPORTED_MODULE_1__/* .confirmAll */ .iX)(real, { taintProbe: opts.taintProbe });
  let survivors = confirmed;
  let refuted = [];
  if (opts.refute) {
    const panel = await (0,_discovery_disprove_js__WEBPACK_IMPORTED_MODULE_2__/* .disprovePanel */ .Jx)(confirmed, { ...opts.refute, scanRoot: opts.scanRoot });
    survivors = panel.survivors;
    refuted = panel.refuted;
  }
  const byId = new Map(candidates.map(c => [c.id, c]));
  const judged = (0,_discovery_judge_js__WEBPACK_IMPORTED_MODULE_3__/* .judgeCandidates */ .m)(survivors, opts.priorScan, opts.triageFeedback);
  const decorate = (f) => {
    const id = String(f.id).split('-').pop();
    const c = byId.get(id) || survivors.find(s => f.id.endsWith(s.id)) || null;
    if (!c) return f;
    return {
      ...f,
      contextIntelligence: {
        origin: 'context-intelligence', questionPack: c.questionPack, witnesses: c.witnesses, witnessCount: c.witnesses.length,
        sourceSpanEvidence: c.sourceSpanEvidence, scopeIntegrity: c.scopeIntegrity, reviewStatus: c.reviewStatus,
        uncertainties: c.uncertainties, recommendedValidation: c.recommendedValidation,
        ...(c.deterministic ? { deterministic: c.deterministic } : {}),
        note: c.deterministic ? 'Derived from the code analysis and a deterministic counterexample attempt; no model produced this. Severity comes from the confirmation tier only.' : 'A model hypothesis checked for citations, not a proof. Severity comes from the confirmation tier only.',
      },
    };
  };
  return {
    findings: judged.fresh.map(decorate),
    duplicates: judged.duplicates.map(decorate),
    suppressed: judged.suppressed.map(decorate),
    refuted: refuted.map(c => ({ id: c.id, title: c.title, file: c.file, line: c.line, refutation: c.refutation })),
    advisory: advisory.map(c => ({ id: c.id, title: c.title, file: c.file, line: c.line, questionPack: c.questionPack, witnesses: c.witnesses, rationale: c.rationale })),
  };
}


/***/ }),

/***/ 89382:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  cmdContext: () => (/* binding */ cmdContext)
});

// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: ./src/context-intelligence/build.js + 3 modules
var build = __webpack_require__(70123);
// EXTERNAL MODULE: ./src/context-intelligence/config.js
var context_intelligence_config = __webpack_require__(33238);
// EXTERNAL MODULE: ./src/context-intelligence/store.js
var store = __webpack_require__(65535);
;// CONCATENATED MODULE: ./src/context-intelligence/diff.js
//
// Incremental invalidation and route diffs.
//
// Invalidation is by RECOMPUTATION, not by prediction: the symbol graph is rebuilt from the current snapshot (cheap,
// local, no model) and every bundle is content-addressed. A review is reused only when the bundle it was made from has
// exactly the same context hash, so:
//   * a change to a shared authorization middleware changes the text of every route that includes it, so all of their
//     hashes change and all of their cached reviews are invalidated, though no handler file was touched;
//   * an unrelated edit leaves untouched bundles byte-identical, so their reviews are cache hits;
//   * a dirty worktree or a different branch is a different snapshot, so a review of another state is never replayed
//     as current.
// There is no optimistic reuse path: if the previous index cannot be read or verified, everything is a miss.


/** symbol / file -> the entry points whose bundles include it. Used to EXPLAIN invalidation, never to skip a rebuild. */
function reverseDependencies(manifests) {
  const bySymbol = new Map();
  const byFile = new Map();
  for (const m of manifests) {
    for (const s of m.reachableSymbols) {
      if (!bySymbol.has(s.symbolId)) bySymbol.set(s.symbolId, new Set());
      bySymbol.get(s.symbolId).add(m.entrypointId);
      if (!byFile.has(s.file)) byFile.set(s.file, new Set());
      byFile.get(s.file).add(m.entrypointId);
    }
  }
  const toObj = (map) => Object.fromEntries([...map.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([k, v]) => [k, [...v].sort()]));
  return { symbols: toObj(bySymbol), files: toObj(byFile) };
}

function routeKey(m) { return `${m.entrypoint.kind}|${m.entrypoint.method}|${m.entrypoint.path}|${m.entrypoint.registrationSite.file}`; }
const ctlKey = (c) => `${c.kind}|${c.file}|${c.line}|${c.evidence}|${c.basis}`;
const sensKey = (s) => `${s.kind}|${s.file}|${s.basis}`;
const unkKey = (u) => `${u.reason}|${u.calleeName}|${u.site.split(':')[0]}`;
const symKey = (s) => `${s.symbolId}|${s.spanHash}`;

function setDiff(a, b) {
  const A = new Set(a), B = new Set(b);
  return { added: [...B].filter(x => !A.has(x)).sort(), removed: [...A].filter(x => !B.has(x)).sort() };
}

/** Diff two sets of manifests (each an array). */
function diffManifestSets(fromManifests, toManifests) {
  const from = new Map(fromManifests.map(m => [routeKey(m), m]));
  const to = new Map(toManifests.map(m => [routeKey(m), m]));
  const added = [], removed = [], changed = [], unchanged = [];
  for (const [k, m] of [...to.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const prev = from.get(k);
    if (!prev) { added.push({ route: `${m.entrypoint.method} ${m.entrypoint.path}`.trim(), file: m.entrypoint.registrationSite.file, integrity: m.context.integrity }); continue; }
    if (prev.contextHash === m.contextHash) { unchanged.push(k); continue; }
    const controls = setDiff(prev.controls.map(ctlKey), m.controls.map(ctlKey));
    const sensitive = setDiff(prev.sensitiveOperations.map(sensKey), m.sensitiveOperations.map(sensKey));
    const unknowns = setDiff(prev.unknowns.filter(u => u.material).map(unkKey), m.unknowns.filter(u => u.material).map(unkKey));
    const deps = setDiff(prev.reachableSymbols.map(symKey), m.reachableSymbols.map(symKey));
    const protection = {};
    for (const dim of Object.keys(m.protection)) {
      const a = prev.protection?.[dim]?.state; const b = m.protection[dim].state;
      if (a !== b) protection[dim] = { from: a || null, to: b };
    }
    changed.push({
      route: `${m.entrypoint.method} ${m.entrypoint.path}`.trim(), file: m.entrypoint.registrationSite.file,
      contextHash: { from: prev.contextHash, to: m.contextHash },
      integrity: { from: prev.context.integrity, to: m.context.integrity },
      authControlChanges: controls, newSensitiveOperations: sensitive.added, removedSensitiveOperations: sensitive.removed,
      unknownEdgeChanges: unknowns, dependencyChanges: { addedOrChangedSymbols: deps.added.length, removedOrChangedSymbols: deps.removed.length }, protectionChanges: protection,
    });
  }
  for (const [k, m] of [...from.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    if (!to.has(k)) removed.push({ route: `${m.entrypoint.method} ${m.entrypoint.path}`.trim(), file: m.entrypoint.registrationSite.file });
  }
  return { added, removed, changed, unchangedCount: unchanged.length };
}

/**
 * Cache accounting against the stored index: for each current bundle, is the same context hash already stored, and if
 * not, why (new route, or which previous hash it replaced).
 */
function cacheReport(root, currentManifests, { hasReview = () => false } = {}) {
  const idx = (0,store/* readStoreJson */.WS)(root, 'index.json');
  const previous = new Map();
  let indexStatus = 'missing';
  if (idx.ok && idx.value && Array.isArray(idx.value.entrypoints)) {
    indexStatus = 'ok';
    for (const e of idx.value.entrypoints) previous.set(e.entrypointId, e.contextHash);
  } else if (!idx.ok && idx.code === 'corrupt-json') indexStatus = 'corrupt';
  const rep = { indexStatus, hits: 0, misses: 0, invalidated: 0, newRoutes: 0, reviewCacheHits: 0, details: [] };
  for (const m of currentManifests) {
    const stored = (0,store/* readManifest */.WI)(root, m.contextHash);
    const prevHash = previous.get(m.entrypointId);
    if (stored.ok && stored.value.manifestHash === m.manifestHash) rep.hits++;
    else rep.misses++;
    if (prevHash === undefined) { rep.newRoutes++; }
    else if (prevHash !== m.contextHash) { rep.invalidated++; rep.details.push({ entrypointId: m.entrypointId, route: `${m.entrypoint.method} ${m.entrypoint.path}`.trim(), previous: prevHash, current: m.contextHash }); }
    if (hasReview(m)) rep.reviewCacheHits++;
  }
  return rep;
}

// EXTERNAL MODULE: ./src/context-intelligence/canonical.js
var canonical = __webpack_require__(44652);
// EXTERNAL MODULE: ./src/context-intelligence/dependency-key.js
var dependency_key = __webpack_require__(8771);
;// CONCATENATED MODULE: ./src/context-intelligence/persist.js
//
// Persist a build: every bundle (manifest + package texts), the index that maps entry points to their current bundle,
// and the reverse-dependency map. Nothing else about the repository is written.





const INDEX_SCHEMA = 'context-index/1';

function persistBuild(root, built, config) {
  const failures = [];
  const manifests = [];
  for (const b of built.bundles) {
    if (!b.manifest) continue;
    const r = (0,store/* writeBundle */.Mf)(root, b);
    if (!r.ok) { failures.push({ entrypointId: b.entrypoint.id, code: r.code, reason: r.reason }); continue; }
    manifests.push(b.manifest);
  }
  const index = {
    schemaVersion: INDEX_SCHEMA,
    graph: { schemaVersion: built.graph.schemaVersion, hash: built.graph.hash, source: built.semantic.source },
    repository: built.repository,
    configHash: (0,canonical/* hashOf */.qQ)(config),
    summary: built.summary,
    entrypoints: built.entrypoints.map(e => {
      const b = built.bundles.find(x => x.entrypoint.id === e.id);
      return {
        entrypointId: e.id, label: e.label, kind: e.kind, disposition: e.disposition, file: e.registrationSite.file,
        contextHash: b && b.manifest ? b.manifest.contextHash : null,
        integrity: b && b.manifest ? b.manifest.context.integrity : null,
        resolutionReasons: e.resolutionReasons,
        // D-AC05: the inputs outside the packed text, so a reader can tell the bundle went stale without a rebuild
        dependencies: b && b.manifest ? (({ key, files, middleware }) => ({ key, files, middleware }))((0,dependency_key/* dependencyKeyOf */.gc)({ manifest: b.manifest, fileContents: built.fileContents || {} })) : null,
      };
    }),
  };
  const wi = (0,store/* writeStoreJson */.DU)(root, 'index.json', index);
  if (!wi.ok) failures.push({ code: wi.code, reason: wi.reason, what: 'index.json' });
  const wr = (0,store/* writeStoreJson */.DU)(root, 'reverse-dependencies.json', reverseDependencies(manifests));
  if (!wr.ok) failures.push({ code: wr.code, reason: wr.reason, what: 'reverse-dependencies.json' });
  return { ok: failures.length === 0, failures, written: manifests.length };
}

// EXTERNAL MODULE: ./src/context-intelligence/files.js
var files = __webpack_require__(72873);
// EXTERNAL MODULE: ./src/context-intelligence/prompts/packs.js
var prompts_packs = __webpack_require__(55944);
// EXTERNAL MODULE: ./src/context-intelligence/review.js
var review = __webpack_require__(37132);
// EXTERNAL MODULE: ./src/context-intelligence/queue.js
var queue = __webpack_require__(63457);
// EXTERNAL MODULE: ./src/context-intelligence/candidates.js
var context_intelligence_candidates = __webpack_require__(84050);
;// CONCATENATED MODULE: ./src/context-intelligence/capabilities.js
//
// Capability matrix: what DCI supports, per language, entry-point kind and question pack, with the evidence behind each
// claim and its known limits. The words are used strictly:
//
//   verified      covered by reproducible fixture tests in this repository, for the BUILD half (resolution, bundling,
//                 integrity). It says nothing about how good a model's review is.
//   experimental  works on fixtures, narrow or unmeasured; no accuracy claim
//   unsupported   not implemented
//   blocked       cannot be done here, for a stated reason
//
// Review quality is `experimental` everywhere: there is no real-world adjudicated holdout in this repository, so no
// accuracy statement is made (see evaluation/ and docs/guides/context-intelligence.md).
const T = (f) => `test/context-intelligence/${f}`;

const BUILD = [
  { language: 'javascript/typescript', kind: 'http', frameworks: 'Express-style call registration (get/post/put/patch/delete/all, router.use, app.use)', status: 'verified', evidence: [T('build-js.test.js')], limits: 'Router mounts in another file and middleware factories are not followed (reported as router-mount-not-resolved); destructured and named imports are followed, re-exports and tsconfig path aliases are not.' },
  { language: 'python', kind: 'http', frameworks: 'decorator registration (Flask/FastAPI-style @app.route / @router.get), FastAPI Depends()/Security() guards', status: 'experimental', evidence: [T('build-python-haskell.test.js'), T('frameworks.test.js')], limits: 'Decorator guards are read from the decorator lines and Depends() guards from the signature (only dependencies named like an auth or user provider bind the principal); framework-level before_request hooks and Django URL conf are not modelled.' },
  { language: 'haskell', kind: 'http', frameworks: 'Scotty, WAI, Servant, Yesod (through the existing web model)', status: 'verified', evidence: [T('build-python-haskell.test.js'), T('frameworks.test.js')], limits: 'Static source analysis; the existing web model decides what a route is. Dynamic routes are reported unresolved.' },
  { language: 'php', kind: 'http', frameworks: 'Laravel Route:: registration (the entry point only)', status: 'experimental', evidence: ['test/engineering-excellence/e4-01-dci-audit.test.js'], limits: 'Measured by the E4-01 audit on one fixture: the routes resolve, but no control or sensitive operation was extracted from the handlers.' },
  { language: 'java/kotlin/c#/go/ruby/rust', kind: 'http', frameworks: 'whatever the engine route scan recognises', status: 'unsupported', evidence: [], limits: 'Measured by the E4-01 audit (docs/engineering-excellence/DCI_MATURITY.md) on one fixture per language (Spring, net/http, ASP.NET, Rails): no entry point was found, so no bundle is built.' },
  { language: 'any with a recognised surface', kind: 'webhook/queue/cron/upload/cli', frameworks: 'existing entry-point inventory', status: 'experimental', evidence: [T('build-js.test.js')], limits: 'Handler is the enclosing declaration of the surface; no framework wiring beyond that.' },
  { language: 'haskell', kind: 'compiler metadata import', frameworks: 'hie-export/1 JSON export of GHC declarations and references', status: 'experimental', evidence: [T('hie-adapter.test.js')], limits: 'Reads an export; never runs GHC or hiedb. The export is validated against the source snapshot. No export produced by a real GHC run is checked in.' },
  { language: 'any', kind: 'compiler metadata build', frameworks: 'automatic metadata generation', status: 'blocked', evidence: [], limits: 'Running a compiler on untrusted source needs a sandbox proof this build does not have (Template Haskell, custom Setup and plugins run code).' },
  { language: 'other semantic sources (TypeScript compiler API, Roslyn, go/packages, language servers)', kind: 'compiler metadata import', frameworks: '-', status: 'unsupported', evidence: [], limits: 'Extension point only: the graph schema carries a resolver field (source-static | compiler-enriched).' },
  { language: 'any', kind: 'provider batch API', frameworks: 'provider-hosted batch submission', status: 'blocked', evidence: [], limits: 'No provider batch contract is verified on this checkout. The offline batch files (request export, result import with hash checks) are implemented and tested.' },
];

function capabilityMatrix() {
  const reviews = ['authz-idor', 'authz-function', 'cross-route-consistency', 'transaction-integrity', 'external-failure', 'sensitive-audit', 'business-invariant'].map(p => ({
    language: 'any bundle that builds', kind: `review: ${p}`, frameworks: 'governed single-turn model call over a frozen bundle', status: 'experimental',
    evidence: [T('review-queue.test.js'), T('queue-diff.test.js')], limits: 'Mechanics are tested with a fake provider; no accuracy measurement exists. The synthetic evaluation suite is a mechanism check, not an estimate.',
  }));
  return [...BUILD, ...reviews];
}

// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
;// CONCATENATED MODULE: ./src/context-intelligence/cli.js
//
// `agentic-security context <build|inspect|diff|review|status|eval|verify|export|cleanup>`
//
// Additive: no existing command changes. `build`, `inspect`, `diff`, `status`, `verify`, `export` and `cleanup` read
// the repository and write only DCI's own state, with no model and no network. `review` is the only subcommand that
// can reach a model, and only through the governed discovery caller (egress policy, redaction, local-only).
//
// Exit codes: 0 done; 1 bad arguments or a refused operation; 2 the input was too large to analyse; 3 (with
// `--strict`) the run finished but some eligible work has no verified result; 130 cancelled.
















const flag = (a, k) => (a.flags[k] === undefined ? undefined : a.flags[k]);
const truthy = (v) => v === true || (typeof v === 'string' && v !== 'false' && v !== '0');
const num = (v) => (v === undefined || v === true ? undefined : Number(v));

/** Everything this command prints goes through here: repository-supplied names must not carry escape sequences to a terminal. */
function say(text) { console.log((0,canonical/* cleanForTerminal */.bt)(text)); }

function out(format, text, obj) {
  if (format === 'json') say(JSON.stringify(obj, null, 2));
  else if (format === 'jsonl') say(JSON.stringify(obj));
  else say(text);
}

function usage() {
  say([
    'Usage: agentic-security context <subcommand> [--root <dir>] [--format text|json|jsonl]',
    '',
    '  build     Resolve entry points and write one inspectable context bundle each (no model, no network)',
    '            [--entrypoints http,webhook,queue,cron,upload,cli] [--profile compact|standard|extended] [--max-tokens N] [--route <label|id>] [--no-write]',
    '  inspect   Show one bundle: --route <label|id> | --hash <contextHash>  [--show-context] [--package N]',
    '  diff      Routes added/removed/changed between two refs: --from <ref> [--to <ref>]  (omit --to for the working tree)',
    '  review    Focused one-call reviews over frozen bundles: --question <pack[,pack]> [--route x] [--local-only] [--allow-remote] [--concurrency N]',
    '            [--max-calls N] [--max-wall-seconds N] [--max-cost-usd N --cost-per-call-usd N] [--retry-failed] [--refute] [--strict]',
    '            [--dry-run] [--export-batch] [--import-batch <results.jsonl> --batch-id <id>]',
    '  status    Coverage so far: entry points, bundles, review jobs',
    '  eval      Frozen evaluation: --suite fixtures --baseline deterministic|hunt --variant dci [--format json]',
    '  verify    Re-check stored bundles against their hashes and the current source',
    '  export    One bundle as a single JSON document: --hash <contextHash>',
    '  cleanup   Remove unreferenced old bundles (blocked by a legal hold): [--older-than-days N] [--dry-run]',
    '',
    'Question packs: ' + prompts_packs/* QUESTION_PACKS */.eO.map(p => p.id).join(', '),
  ].join('\n'));
}

function entrypointFilter(arg) { return arg === undefined || arg === true ? undefined : String(arg); }

async function doBuild(root, args, { write = true } = {}) {
  const { config, problems } = (0,context_intelligence_config/* loadConfig */.Z9)(root);
  if (flag(args, 'entrypoints')) config.entrypointKinds = String(flag(args, 'entrypoints')).split(',').map(s => s.trim()).filter(Boolean);
  if (flag(args, 'profile')) config.context.profile = String(flag(args, 'profile'));
  if (flag(args, 'max-tokens')) config.context.maxTokens = num(flag(args, 'max-tokens'));
  const events = [];
  const jsonl = flag(args, 'format') === 'jsonl';
  const built = await (0,build/* buildContext */.g)(root, { config, route: entrypointFilter(flag(args, 'route')), onEvent: (e) => { events.push(e); if (jsonl) say(JSON.stringify(e)); } });
  if (!built.ok) return { ok: false, built, config, problems };
  let persisted = null;
  if (write) persisted = persistBuild(root, built, config);
  return { ok: true, built, config, problems, persisted, events };
}

function routeTable(built) {
  const rows = [];
  for (const e of built.entrypoints) {
    const b = built.bundles.find(x => x.entrypoint.id === e.id);
    const m = b && b.manifest;
    rows.push(`  ${e.disposition.padEnd(18)} ${m ? m.context.integrity.padEnd(11) : '-'.padEnd(11)} ${e.label}  (${e.registrationSite.file}:${e.registrationSite.line})${e.resolutionReasons.length ? '  [' + e.resolutionReasons.join(', ') + ']' : ''}`);
  }
  return rows.join('\n');
}

async function cmdBuild(root, args, format) {
  const r = await doBuild(root, args, { write: !truthy(flag(args, 'no-write')) });
  if (!r.ok) {
    out(format, `context build: ${r.built.reason}${r.built.detail && r.built.detail.count ? ` (${r.built.detail.count} files, limit ${r.built.detail.limit})` : ''}`, { ok: false, reason: r.built.reason, detail: r.built.detail });
    return r.built.reason === 'too-many-files' ? 2 : 1;
  }
  const { built } = r;
  const s = built.summary;
  const obj = { ok: true, graph: { symbols: built.graph.symbols.length, edges: built.graph.edges.length, hash: built.graph.hash, source: built.semantic.source }, snapshotHash: built.snapshotHash, repository: built.repository, summary: s, semantic: built.semantic, configProblems: r.problems, persisted: r.persisted, skippedFiles: built.skipped.length };
  const text = [
    'Deterministic Context Intelligence: build',
    `  graph: ${built.graph.symbols.length} symbols, ${built.graph.edges.length} edges, ${built.graph.hash.slice(0, 12)}  (${built.semantic.source.join(' + ')})`,
    `  entry points found ${s.entrypointsFound}: resolved ${s.resolved}, partially resolved ${s.partial}, unresolved ${s.unresolved}, excluded by policy ${s.excluded}`,
    `  bundles built ${s.bundlesBuilt}: complete ${s.complete}, partial ${s.partialBundles}, unavailable ${s.unavailable}`,
    `  unresolved material calls: ${s.unresolvedEdges}   tokens (estimate, chars/4): ${s.tokens}`,
    built.skipped.length ? `  ${built.skipped.length} file(s) skipped (symlink, oversize or unreadable)` : null,
    built.semantic.status && built.semantic.status !== 'off' ? `  compiler metadata: ${built.semantic.status}${built.semantic.reason ? ` (${built.semantic.reason}${built.semantic.detail ? ': ' + built.semantic.detail : ''})` : ''}` : null,
    r.problems.length ? `  config notes: ${r.problems.join('; ')}` : null,
    r.persisted ? (r.persisted.ok ? `  written: ${r.persisted.written} bundle(s) under .agentic-security/context-intelligence/` : `  WRITE PROBLEMS: ${JSON.stringify(r.persisted.failures)}`) : '  (not written: --no-write)',
    '',
    routeTable(built),
    '',
    'A "complete" bundle means nothing unresolved, omitted, capped or split was found. It does not mean the route is safe.',
  ].filter(x => x !== null).join('\n');
  out(format, text, obj);
  return 0;
}

function findBundle(built, sel) {
  return built.bundles.find(b => b.entrypoint.id === sel) || built.bundles.find(b => b.entrypoint.label === sel) || built.bundles.find(b => b.entrypoint.label.includes(sel));
}

async function cmdInspect(root, args, format) {
  let manifest;
  let fileContents = null;
  if (flag(args, 'hash')) {
    const m = (0,store/* readManifest */.WI)(root, String(flag(args, 'hash')));
    if (!m.ok) { out(format, `context inspect: ${m.code}`, { ok: false, reason: m.code }); return 1; }
    manifest = m.value;
  } else if (flag(args, 'route') && flag(args, 'route') !== true) {
    const idx = (0,store/* readStoreJson */.WS)(root, 'index.json');
    const sel = String(flag(args, 'route'));
    let hash = null;
    if (idx.ok) {
      const hit = idx.value.entrypoints.find(e => e.entrypointId === sel) || idx.value.entrypoints.find(e => e.label === sel) || idx.value.entrypoints.find(e => e.label.includes(sel));
      if (hit) hash = hit.contextHash;
    }
    if (!hash) { out(format, `context inspect: no stored bundle for '${sel}'. Run \`context build\` first.`, { ok: false, reason: 'not-built' }); return 1; }
    const m = (0,store/* readManifest */.WI)(root, hash);
    if (!m.ok) { out(format, `context inspect: ${m.code}`, { ok: false, reason: m.code }); return 1; }
    manifest = m.value;
  } else { out(format, 'context inspect: pass --route <label|id> or --hash <contextHash>', { ok: false, reason: 'missing-selector' }); return 1; }
  void fileContents;
  const pkgIdx = Number.isInteger(num(flag(args, 'package'))) ? num(flag(args, 'package')) : 1;
  const text = truthy(flag(args, 'show-context')) ? (0,store/* readPackageText */.Yt)(root, manifest, pkgIdx) : null;
  const obj = { ok: true, manifest, context: text && text.ok ? text.text : undefined };
  if (format === 'json' || format === 'jsonl') { out(format, '', obj); return 0; }
  const m = manifest;
  const lines = [
    `${m.entrypoint.method} ${m.entrypoint.path}  [${m.entrypoint.kind}]  ${m.entrypoint.registrationSite.file}:${m.entrypoint.registrationSite.line}`,
    `  context hash ${m.contextHash.slice(0, 16)}   integrity ${m.context.integrity}${m.context.integrityReasons.length ? ' (' + m.context.integrityReasons.join(', ') + ')' : ''}   entry point ${m.status.entrypoint}`,
    `  packages: ${m.context.packages.map(p => `${p.index}/${p.total} ~${p.tokensEstimated} tok${p.standalone ? '' : ' (not standalone)'}`).join(', ')}   tokenizer: ${m.context.tokenizer && m.context.tokenizer.name}`,
    `  handler: ${m.entrypoint.handlerSymbol || '(none)'}   auth scheme (${m.entrypoint.authScheme.basis}): ${m.entrypoint.authScheme.status}`,
    '  protection:',
    ...Object.entries(m.protection).map(([k, v]) => `    ${k.padEnd(20)} ${v.state.padEnd(26)} ${v.why}`),
    `  controls (${m.controls.length}):`,
    ...m.controls.slice(0, 12).map(c => `    ${c.kind.padEnd(20)} ${c.file}:${c.line}  ${c.evidence}/${c.basis}${c.rejectionSeen === false ? ' (no rejection seen)' : ''}`),
    `  sensitive operations (${m.sensitiveOperations.length}):`,
    ...m.sensitiveOperations.slice(0, 8).map(c => `    ${c.kind.padEnd(14)} ${c.file}:${c.line}`),
    `  unresolved material calls (${m.unknowns.filter(u => u.material).length}):`,
    ...m.unknowns.filter(u => u.material).slice(0, 10).map(u => `    ${u.site}  ${u.calleeName}  (${u.reason})`),
    `  omissions (${m.omissions.length}):`,
    ...m.omissions.slice(0, 8).map(o => `    ${o.symbolId || o.range}  ${o.reason}`),
    `  boundaries (calls into libraries, not first-party code): ${m.boundaries.length}`,
  ];
  if (text) lines.push('', text.ok ? text.text : `(context text unavailable: ${text.code})`);
  say(lines.join('\n'));
  return 0;
}

async function snapshotFor(root, ref, config) {
  if (ref === undefined || ref === true) return (0,files/* readSnapshot */.RA)(root, { maxFiles: config.maxFiles });
  return (0,files/* readGitSnapshot */.zK)(root, String(ref), { maxFiles: config.maxFiles });
}

async function cmdDiff(root, args, format) {
  const from = flag(args, 'from');
  if (!from || from === true) { out(format, 'context diff: --from <ref> is required', { ok: false, reason: 'missing-from' }); return 1; }
  const { config } = (0,context_intelligence_config/* loadConfig */.Z9)(root);
  const a = await snapshotFor(root, from, config);
  const b = await snapshotFor(root, flag(args, 'to'), config);
  for (const [label, s] of [['--from', a], ['--to', b]]) {
    if (!s.ok) { out(format, `context diff: cannot read ${label}: ${s.reason}`, { ok: false, reason: s.reason, which: label }); return 1; }
  }
  const [ba, bb] = [await (0,build/* buildContext */.g)(root, { config, snapshot: a }), await (0,build/* buildContext */.g)(root, { config, snapshot: b })];
  if (!ba.ok || !bb.ok) { out(format, 'context diff: build failed', { ok: false, reason: (ba.ok ? bb : ba).reason }); return 1; }
  const d = diffManifestSets(ba.bundles.filter(x => x.manifest).map(x => x.manifest), bb.bundles.filter(x => x.manifest).map(x => x.manifest));
  const cache = cacheReport(root, bb.bundles.filter(x => x.manifest).map(x => x.manifest));
  const obj = { ok: true, from: { ref: String(from), commit: a.commit || null, snapshotHash: a.snapshotHash }, to: { ref: flag(args, 'to') === undefined ? 'working-tree' : String(flag(args, 'to')), commit: b.commit || null, snapshotHash: b.snapshotHash }, ...d, cache };
  const text = [
    `context diff ${obj.from.ref} -> ${obj.to.ref}`,
    `  routes: +${d.added.length} added, -${d.removed.length} removed, ${d.changed.length} changed, ${d.unchangedCount} unchanged`,
    ...d.added.map(r => `  + ${r.route}  (${r.file}, ${r.integrity})`),
    ...d.removed.map(r => `  - ${r.route}  (${r.file})`),
    ...d.changed.flatMap(c => [
      `  ~ ${c.route}  (${c.file})  integrity ${c.integrity.from} -> ${c.integrity.to}`,
      ...c.authControlChanges.added.map(x => `      + control ${x}`),
      ...c.authControlChanges.removed.map(x => `      - control ${x}`),
      ...c.newSensitiveOperations.map(x => `      + sensitive operation ${x}`),
      ...c.unknownEdgeChanges.added.map(x => `      + unresolved ${x}`),
      ...Object.entries(c.protectionChanges).map(([k, v]) => `      protection ${k}: ${v.from} -> ${v.to}`),
    ]),
    `  stored bundles reusable for the target: ${cache.hits} hit, ${cache.misses} miss (index ${cache.indexStatus}, ${cache.invalidated} invalidated, ${cache.newRoutes} new)`,
  ].join('\n');
  out(format, text, obj);
  return 0;
}

function statusSnapshot(root) {
  const idx = (0,store/* readStoreJson */.WS)(root, 'index.json');
  const queuesDir = external_node_path_.join((0,store/* storeRoot */.q1)(root), 'queues');
  const reviewsDir = external_node_path_.join((0,store/* storeRoot */.q1)(root), 'reviews');
  const count = (d) => { try { return external_node_fs_.readdirSync(d).filter(n => n.endsWith('.json')).length; } catch { return 0; } };
  const queues = [];
  try {
    for (const n of external_node_fs_.readdirSync(queuesDir).filter(x => x.endsWith('.json')).sort()) {
      const q = (0,store/* readStoreJson */.WS)(root, `queues/${n}`);
      if (q.ok) {
        const tally = {};
        for (const j of Object.values(q.value.jobs || {})) tally[j.state] = (tally[j.state] || 0) + 1;
        queues.push({ runId: q.value.runId, jobs: Object.keys(q.value.jobs || {}).length, states: tally });
      }
    }
  } catch { /* no queues yet */ }
  return { indexed: idx.ok, indexStatus: idx.ok ? 'ok' : idx.code, summary: idx.ok ? idx.value.summary : null, graph: idx.ok ? idx.value.graph : null, repository: idx.ok ? idx.value.repository : null, storedBundles: (0,store/* listStoredBundles */.ZP)(root).length, reviews: count(reviewsDir), queues };
}

async function cmdStatus(root, args, format) {
  const { config, problems } = (0,context_intelligence_config/* loadConfig */.Z9)(root);
  const st = statusSnapshot(root);
  const obj = { ok: true, config: { enabled: config.enabled, entrypointKinds: config.entrypointKinds, semanticMetadata: config.semanticMetadata, context: config.context, review: config.review }, configProblems: problems, ...st, capabilities: capabilityMatrix() };
  const text = [
    'Deterministic Context Intelligence: status',
    st.indexed
      ? `  last build: ${st.summary.entrypointsFound} entry points (${st.summary.resolved} resolved, ${st.summary.partial} partial, ${st.summary.unresolved} unresolved, ${st.summary.excluded} excluded), bundles complete ${st.summary.complete} / partial ${st.summary.partialBundles} / unavailable ${st.summary.unavailable}`
      : `  no build recorded (${st.indexStatus}). Run \`context build\`.`,
    st.indexed ? `  commit ${st.repository.commit || '(no git)'}${st.repository.dirty ? ' + uncommitted changes' : ''}   graph ${st.graph.hash.slice(0, 12)}` : null,
    `  stored bundles: ${st.storedBundles}   verified review results: ${st.reviews}`,
    ...st.queues.map(q => `  review run ${q.runId.slice(0, 10)}: ${q.jobs} jobs ${JSON.stringify(q.states)}`),
    problems.length ? `  config notes: ${problems.join('; ')}` : null,
    `  DCI integration enabled: ${config.enabled} (the explicit \`context\` commands work either way)`,
  ].filter(x => x !== null).join('\n');
  out(format, text, obj);
  return 0;
}

async function cmdVerify(root, args, format) {
  const { config } = (0,context_intelligence_config/* loadConfig */.Z9)(root);
  const snap = await (0,files/* readSnapshot */.RA)(root, { maxFiles: config.maxFiles });
  if (!snap.ok) { out(format, `context verify: ${snap.reason}`, { ok: false, reason: snap.reason }); return 1; }
  const results = [];
  for (const h of (0,store/* listStoredBundles */.ZP)(root)) {
    const v = (0,store/* verifyStoredBundle */.V3)(root, h, { fileContents: snap.fileContents });
    results.push({ contextHash: h, ok: v.ok, problems: v.problems });
  }
  const bad = results.filter(r => !r.ok);
  const obj = { ok: bad.length === 0, checked: results.length, mismatched: bad.length, results };
  out(format, `context verify: ${results.length} bundle(s) checked, ${bad.length} do not match the current source or their own hashes${bad.length ? '\n' + bad.slice(0, 20).map(b => `  ${b.contextHash.slice(0, 12)}: ${b.problems.slice(0, 3).join(', ')}`).join('\n') : ''}`, obj);
  return bad.length ? 1 : 0;
}

async function cmdExport(root, args, format) {
  const h = flag(args, 'hash');
  if (!h || h === true) { out(format, 'context export: --hash <contextHash> is required', { ok: false }); return 1; }
  const r = (0,store/* exportBundle */.Nl)(root, String(h));
  if (!r.ok) { out(format, `context export: refused (${r.problems.join(', ')})`, { ok: false, problems: r.problems }); return 1; }
  say(JSON.stringify(r.export, null, 2));
  return 0;
}

async function cmdCleanup(root, args, format) {
  const r = (0,store/* cleanupStore */.kF)(root, { olderThanDays: Number.isFinite(num(flag(args, 'older-than-days'))) ? num(flag(args, 'older-than-days')) : 30, dryRun: truthy(flag(args, 'dry-run')) });
  const text = r.blockedByLegalHold
    ? `context cleanup: nothing removed, the context-intelligence artifact is under a legal hold (${r.blockedByLegalHold.owner}: ${r.blockedByLegalHold.reason})`
    : `context cleanup: ${r.removed.length} bundle(s) ${r.dryRun ? 'would be ' : ''}removed, ${r.kept.length} kept`;
  out(format, text, { ok: true, ...r });
  return 0;
}

// ---- review ------------------------------------------------------------------------------------------------------

function loadJobFrom(built, packs) {
  const byEp = new Map(built.bundles.map(b => [b.entrypoint.id, b]));
  const packMap = new Map(packs.map(p => [p.id, p]));
  return (job) => {
    const bundles = job.entrypointIds.map(id => byEp.get(id));
    if (bundles.some(b => !b || !b.manifest)) return { error: 'entry point no longer has a bundle' };
    const pack = packMap.get(job.packId);
    if (!pack) return { error: 'question pack unavailable' };
    for (let i = 0; i < bundles.length; i++) {
      if (bundles[i].manifest.contextHash !== job.contextHashes[i]) return { error: 'stale-context: the bundle changed since this job was planned' };
    }
    return {
      pack, entrypoints: bundles.map(b => b.entrypoint), manifests: bundles.map(b => b.manifest),
      packageTexts: bundles.map((b, i) => (b.pack.packages.find(p => p.index === job.packageIndexes[i]) || b.pack.packages[0]).text),
    };
  };
}

async function cmdReview(root, args, format) {
  const { config } = (0,context_intelligence_config/* loadConfig */.Z9)(root);
  const provider = flag(args, 'provider');
  if (provider !== undefined && provider !== 'configured') { out(format, `context review: --provider only accepts 'configured' (the endpoint set through the existing LLM configuration); got '${provider}'`, { ok: false, reason: 'bad-provider' }); return 1; }
  const wanted = flag(args, 'question') && flag(args, 'question') !== true ? String(flag(args, 'question')).split(',').map(s => s.trim()).filter(Boolean) : config.review.questionPacks;
  const packs = wanted.map(prompts_packs/* packById */.Oy);
  if (packs.some(p => !p)) { out(format, `context review: unknown question pack '${wanted[packs.findIndex(p => !p)]}'. Known: ${prompts_packs/* QUESTION_PACKS */.eO.map(p => p.id).join(', ')}`, { ok: false, reason: 'unknown-pack' }); return 1; }

  // --local-only is an explicit statement of intent: it is enforced by the existing egress policy, which denies any
  // non-loopback endpoint, and a denial skips the jobs. There is no fallback to another provider.
  if (truthy(flag(args, 'local-only'))) process.env.AGENTIC_SECURITY_EGRESS_MODE = 'local-only';

  const r = await doBuild(root, args, { write: true });
  if (!r.ok) { out(format, `context review: build failed (${r.built.reason})`, { ok: false, reason: r.built.reason }); return r.built.reason === 'too-many-files' ? 2 : 1; }
  const { built } = r;
  const model = (0,review/* describeModel */.Vy)({ allowRemote: truthy(flag(args, 'allow-remote')) || r.config.review.allowRemote === true });
  const { jobs, droppedByJobLimit } = (0,queue/* planJobs */.KR)({ bundles: built.bundles, packs, model, fileContents: built.fileContents || {}, maxJobs: Math.min(queue/* HARD_LIMITS */.BS.maxJobs, num(flag(args, 'max-jobs')) || queue/* HARD_LIMITS */.BS.maxJobs) });
  const loadJob = loadJobFrom(built, packs);
  const ctxBase = { root: built.root, fileContents: built.fileContents, model };

  if (truthy(flag(args, 'dry-run'))) {
    const obj = { ok: true, dryRun: true, eligibleJobs: jobs.length, droppedByJobLimit, model: { provider: model.provider, model: model.model }, packs: packs.map(p => `${p.id}/${p.version}`) };
    out(format, `context review (dry run): ${jobs.length} job(s) would run over ${built.summary.bundlesBuilt} bundle(s); model ${model.provider || '(none configured)'}/${model.model || '-'}`, obj);
    return 0;
  }

  if (truthy(flag(args, 'export-batch'))) {
    const e = (0,queue/* exportBatch */.Tt)(built.root, jobs, loadJob, { model, review: { buildReviewPrompt: review/* buildReviewPrompt */.Ng, redactPackageText: review/* redactPackageText */.DW, checkEgressForFiles: review/* checkEgressForFiles */.ih } });
    if (!e.ok) { out(format, `context review: batch export failed (${e.code})`, e); return 1; }
    out(format, `context review: batch ${e.batchId} written (${e.requests} request(s), ${e.skipped.length} skipped by policy or error). Upload is the operator's step; import results with --import-batch <file> --batch-id ${e.batchId}.`, { ok: true, ...e });
    return 0;
  }

  if (flag(args, 'import-batch') && flag(args, 'import-batch') !== true) {
    const batchId = flag(args, 'batch-id');
    if (!batchId || batchId === true) { out(format, 'context review: --batch-id is required with --import-batch', { ok: false }); return 1; }
    let text;
    try { text = external_node_fs_.readFileSync(external_node_path_.resolve(String(flag(args, 'import-batch'))), 'utf8'); } catch { out(format, 'context review: cannot read the results file', { ok: false }); return 1; }
    const imp = (0,queue/* importBatch */.S0)(built.root, String(batchId), text, { jobs, loadJob, fileContents: built.fileContents });
    out(format, imp.ok ? `context review: imported ${imp.accepted} accepted, ${imp.declined} declined, ${imp.rejected.length} rejected, ${imp.duplicates} duplicate(s)` : `context review: ${imp.reason}`, imp);
    return imp.ok ? 0 : 1;
  }

  const invoker = (0,review/* resolveInvoker */.X8)({ scanRoot: built.root });
  const ac = new AbortController();
  let interrupted = false;
  const onSig = () => { interrupted = true; ac.abort(); };
  process.on('SIGINT', onSig); process.on('SIGTERM', onSig);
  const jsonl = format === 'jsonl';
  let result;
  try {
    result = await (0,queue/* runQueue */.rj)(jobs, {
      ...ctxBase, invoker, loadJob, signal: ac.signal, retryFailed: truthy(flag(args, 'retry-failed')),
      onEvent: jsonl ? (e) => say(JSON.stringify(e)) : undefined,
      limits: {
        concurrency: num(flag(args, 'concurrency')) || config.review.concurrency,
        maxCalls: num(flag(args, 'max-calls')) || config.review.maxCalls,
        maxWallSeconds: num(flag(args, 'max-wall-seconds')) || config.review.maxWallSeconds,
        maxTokensPerJob: config.review.maxTokensPerJob,
        maxTokensPerRepo: config.review.maxTokensPerRepo,
        anonymizePrompts: config.review.anonymizePrompts,
        maxRetries: config.review.maxRetries,
        jobTimeoutMs: (num(flag(args, 'job-timeout-seconds')) || 120) * 1000,
        maxCostUsd: num(flag(args, 'max-cost-usd')) ?? config.review.maxCostUsd,
        costPerCallUsd: num(flag(args, 'cost-per-call-usd')),
      },
    });
  } finally { process.off('SIGINT', onSig); process.off('SIGTERM', onSig); }

  // verified results -> candidates -> the existing adjudication
  const records = [];
  for (const [, res] of result.results) {
    if (res.state === 'succeeded' && res.review) {
      const job = res.job;
      const lj = loadJob(job);
      if (lj.error) continue;
      records.push({ review: res.review, entrypoints: lj.entrypoints.map(e => ({ id: e.id, label: e.label })), pack: lj.pack });
    }
  }
  const candidates = (0,context_intelligence_candidates/* reviewsToCandidates */.D)(records);
  let priorScan = null, triageFeedback = null;
  try { priorScan = JSON.parse(external_node_fs_.readFileSync((0,state_dir.statePath)(built.root, 'last-scan.json'), 'utf8')); } catch { /* none */ }
  try { triageFeedback = JSON.parse(external_node_fs_.readFileSync((0,state_dir.statePath)(built.root, 'triage-feedback.json'), 'utf8')); } catch { /* none */ }
  const { makeTaintProbe } = await __webpack_require__.e(/* import() */ 9619).then(__webpack_require__.bind(__webpack_require__, 69619));
  const adj = await (0,context_intelligence_candidates/* adjudicate */.p)(candidates, { taintProbe: makeTaintProbe(built.ir.perFile, built.ir.callGraph), priorScan, triageFeedback, scanRoot: built.root, refute: truthy(flag(args, 'refute')) ? {} : null });

  const cov = result.coverage;
  const report = { ok: true, runId: result.runId, interrupted, model: { provider: model.provider, model: model.model }, buildSummary: built.summary, coverage: cov, candidates: candidates.length, findings: adj.findings.map(f => ({ id: f.id, severity: f.severity, file: f.file, line: f.line, vuln: f.vuln, cwe: f.cwe, confirmation: f.discovery && f.discovery.confirmation && f.discovery.confirmation.tier, witnesses: f.contextIntelligence && f.contextIntelligence.witnessCount, contextIntelligence: f.contextIntelligence })), advisory: adj.advisory, refuted: adj.refuted, duplicates: adj.duplicates.length, suppressed: adj.suppressed.length };
  (0,store/* writeStoreJson */.DU)(built.root, `reports/review-${result.runId}.json`, report);
  const text = [
    'Deterministic Context Intelligence: review',
    `  model: ${model.provider || '(none)'}/${model.model || '-'}   packs: ${packs.map(p => p.id).join(', ')}`,
    `  eligible ${cov.eligible} | attempted ${cov.attempted} | succeeded ${cov.succeeded} | partial ${cov.partial} | failed ${cov.failed} | timed out ${cov.timed_out} | skipped by policy ${cov.skipped_by_policy} | cancelled ${cov.cancelled}`,
    `  cached ${cov.cached}, resumed ${cov.resumed}, model calls ${cov.modelCalls}, wall ${Math.round(cov.wallMs / 1000)}s`,
    `  cost: ${cov.estimatedCostUsd === null ? 'not estimated (' + cov.costBasis + ')' : '$' + cov.estimatedCostUsd.toFixed(4) + ' (' + cov.costBasis + ')'}`,
    ...Object.entries(cov.reasons).slice(0, 8).map(([k, v]) => `  ! ${v}x ${k}`),
    cov.missingCoverage > 0 ? `  ${cov.missingCoverage} eligible job(s) have NO verified result. That is missing coverage, not a clean result.` : '  every eligible job has a verified result (that is coverage, not proof of safety)',
    cov.queueStateCorrupt ? '  note: the previous queue checkpoint failed its integrity check and was ignored' : null,
    '',
    adj.findings.length ? `${adj.findings.length} candidate finding(s) (advisory, unconfirmed unless stated; severity comes from the confirmation tier):` : 'No candidate findings survived verification.',
    ...adj.findings.map(f => `  [${f.severity}] ${f.file}:${f.line}  ${f.vuln}  confirmation=${(f.discovery && f.discovery.confirmation && f.discovery.confirmation.tier) || 'unknown'} routes=${f.contextIntelligence ? f.contextIntelligence.witnessCount : 1}`),
    adj.advisory.length ? `  ${adj.advisory.length} advisory-only hypothesis(es) not promoted to findings` : null,
  ].filter(x => x !== null).join('\n');
  out(format, text, report);
  if (interrupted) return 130;
  if (truthy(flag(args, 'strict')) && cov.missingCoverage > 0) return 3;
  return 0;
}

// ---- dispatch -----------------------------------------------------------------------------------------------------

async function cmdContext(args) {
  const sub = args._[1];
  const root = external_node_path_.resolve(flag(args, 'root') && flag(args, 'root') !== true ? String(flag(args, 'root')) : '.');
  const format = ['json', 'jsonl'].includes(flag(args, 'format')) ? flag(args, 'format') : 'text';
  switch (sub) {
    case 'build': return cmdBuild(root, args, format);
    case 'inspect': return cmdInspect(root, args, format);
    case 'diff': return cmdDiff(root, args, format);
    case 'review': return cmdReview(root, args, format);
    case 'status': return cmdStatus(root, args, format);
    case 'verify': return cmdVerify(root, args, format);
    case 'export': return cmdExport(root, args, format);
    case 'cleanup': return cmdCleanup(root, args, format);
    case 'eval': {
      const { cmdEval } = await Promise.all(/* import() */[__webpack_require__.e(9619), __webpack_require__.e(7405)]).then(__webpack_require__.bind(__webpack_require__, 67405));
      return cmdEval(root, args, format);
    }
    default:
      usage();
      return sub === undefined ? 0 : 1;
  }
}



/***/ }),

/***/ 63457:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   BS: () => (/* binding */ HARD_LIMITS),
/* harmony export */   KR: () => (/* binding */ planJobs),
/* harmony export */   S0: () => (/* binding */ importBatch),
/* harmony export */   Tt: () => (/* binding */ exportBatch),
/* harmony export */   rj: () => (/* binding */ runQueue)
/* harmony export */ });
/* unused harmony exports TERMINAL_STATES, QUEUE_SCHEMA_VERSION, resourceKeyOf, jobKeyOf, runIdOf, coverageOf, batchIdOf */
/* harmony import */ var _canonical_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(44652);
/* harmony import */ var _prompts_packs_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(55944);
/* harmony import */ var _review_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(37132);
/* harmony import */ var _store_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(65535);
/* harmony import */ var _dependency_key_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(8771);
//
// Durable, bounded review queue.
//
// Every job ends in exactly one terminal state, with a reason, and the run reports both how many jobs were ELIGIBLE and
// how many were ATTEMPTED, so a run that stopped early can never read as a clean one:
//
//   succeeded          a verified answer was obtained
//   partial            the job ran but the answer was declined (bad citation, malformed, context unavailable)
//   failed             the model call failed and retries were exhausted or the failure is not retryable
//   timed_out          the job-level deadline passed
//   skipped_by_policy  egress policy, redaction, a size limit or an exhausted budget stopped it BEFORE any call
//   cancelled          the run was cancelled before the job finished
//
// Nothing here talks to a provider: the invoker comes from `review.resolveInvoker`, which goes through the governed
// discovery caller. Local-only policy therefore holds by construction, and there is no fallback to a different provider.
//
// Bounds are absolute: jobs, concurrency, model calls (retries count), tokens per job, estimated dollars (only when a
// price is supplied), and wall time. No unbounded queue growth, no infinite retry.






const TERMINAL_STATES = Object.freeze(['succeeded', 'partial', 'failed', 'timed_out', 'skipped_by_policy', 'cancelled']);
const QUEUE_SCHEMA_VERSION = 'review-queue/1';
const HARD_LIMITS = Object.freeze({ maxJobs: 20000, maxConcurrency: 16, maxCalls: 5000, maxRetries: 3, maxWallSeconds: 86400 });
const MAX_GROUP = 6;

/** Group entry points that operate on the same kind of object (the static segment before the last path parameter). */
function resourceKeyOf(pathTemplate) {
  const segs = String(pathTemplate || '').split('/').filter(Boolean);
  let lastParam = -1;
  segs.forEach((s, i) => { if (/^[:{<]/.test(s) || /[}>]$/.test(s)) lastParam = i; });
  for (let i = lastParam - 1; i >= 0; i--) if (!/^[:{<]/.test(segs[i])) return segs[i];
  return null;
}

function jobKeyOf({ entrypointIds, contextHashes, packageIndex, pack, model, dependencyKeys = null }) {
  return (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .hashOf */ .qQ)({
    schema: _prompts_packs_js__WEBPACK_IMPORTED_MODULE_1__/* .REVIEW_SCHEMA_VERSION */ .k6,
    entrypoints: entrypointIds,
    contexts: contextHashes,
    packageIndex,
    pack: (0,_prompts_packs_js__WEBPACK_IMPORTED_MODULE_1__/* .packRef */ .NO)(pack),
    model: { provider: model.provider || null, model: model.model || null },
    settings: {},
    // D-AC05: what the bundle depends on outside its packed text (route registration and middleware, control and boundary files,
    // the contract and the declared environment). Present on every planned job, so a change there misses the cached review.
    ...(dependencyKeys ? { dependencies: dependencyKeys } : {}),
  });
}

/**
 * Plan jobs. `bundles` are build results (`{entrypoint, manifest}`). Excluded entry points get no job; they are counted
 * by the caller from the entry-point dispositions.
 */
function planJobs({ bundles, packs, model, maxJobs = HARD_LIMITS.maxJobs, fileContents = {}, contractRef = null, environment = null }) {
  const live = bundles.filter(b => b.manifest);
  const depKey = new Map(live.map(b => [b.entrypoint.id, (0,_dependency_key_js__WEBPACK_IMPORTED_MODULE_4__/* .dependencyKeyOf */ .gc)({ manifest: b.manifest, fileContents, contractRef, environment }).key]));
  const jobs = [];
  for (const pack of packs) {
    if (pack.multiBundle) {
      const groups = new Map();
      for (const b of live) {
        if (b.manifest.context.integrity === 'unavailable') continue;
        const k = resourceKeyOf(b.entrypoint.pathTemplate);
        if (!k) continue;
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k).push(b);
      }
      for (const [k, members] of [...groups.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
        if (members.length < 2) continue;
        const sorted = members.sort((a, b) => (a.entrypoint.id < b.entrypoint.id ? -1 : 1));
        const used = sorted.slice(0, MAX_GROUP);
        jobs.push({
          key: jobKeyOf({ entrypointIds: used.map(m => m.entrypoint.id), contextHashes: used.map(m => m.manifest.contextHash), packageIndex: 1, pack, model, dependencyKeys: used.map(m => depKey.get(m.entrypoint.id)) }),
          packId: pack.id, packRef: (0,_prompts_packs_js__WEBPACK_IMPORTED_MODULE_1__/* .packRef */ .NO)(pack), label: `${pack.id}: ${k} (${used.length} routes)`, entrypointIds: used.map(m => m.entrypoint.id),
          contextHashes: used.map(m => m.manifest.contextHash), packageIndexes: used.map(() => 1), groupTruncated: sorted.length > used.length ? sorted.length - used.length : 0,
        });
      }
    } else {
      for (const b of live) {
        for (const pk of b.manifest.context.packages.length ? b.manifest.context.packages : [{ index: 1 }]) {
          jobs.push({
            key: jobKeyOf({ entrypointIds: [b.entrypoint.id], contextHashes: [b.manifest.contextHash], packageIndex: pk.index, pack, model, dependencyKeys: [depKey.get(b.entrypoint.id)] }),
            packId: pack.id, packRef: (0,_prompts_packs_js__WEBPACK_IMPORTED_MODULE_1__/* .packRef */ .NO)(pack), label: `${pack.id}: ${b.entrypoint.label}${b.manifest.context.packages.length > 1 ? ` [package ${pk.index}/${pk.total}]` : ''}`,
            entrypointIds: [b.entrypoint.id], contextHashes: [b.manifest.contextHash], packageIndexes: [pk.index], groupTruncated: 0,
          });
        }
      }
    }
  }
  jobs.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const dropped = Math.max(0, jobs.length - maxJobs);
  return { jobs: jobs.slice(0, maxJobs), droppedByJobLimit: dropped };
}

// ---- queue state ----------------------------------------------------------------------------------------------

function runIdOf(jobs, limits) { return (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .hashOf */ .qQ)({ jobs: jobs.map(j => j.key), limits: { calls: limits.maxCalls } }).slice(0, 24); }

function sealState(state) {
  const body = { ...state };
  delete body.stateHash;
  return { ...body, stateHash: (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .canonicalJson */ .dj)(body)) };
}

function loadState(root, runId) {
  const r = (0,_store_js__WEBPACK_IMPORTED_MODULE_3__/* .readStoreJson */ .WS)(root, `queues/${runId}.json`);
  if (!r.ok) return { ok: false, corrupt: r.code === 'corrupt-json' };
  const { stateHash, ...body } = r.value;
  if (r.value.schemaVersion !== QUEUE_SCHEMA_VERSION || (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .canonicalJson */ .dj)(body)) !== stateHash) return { ok: false, corrupt: true };
  return { ok: true, state: r.value };
}

function reviewPath(key) { return `reviews/${key}.json`; }

/** A stored review is reusable only if it still verifies as a review of exactly this job. */
function loadCachedReview(root, job) {
  const r = (0,_store_js__WEBPACK_IMPORTED_MODULE_3__/* .readStoreJson */ .WS)(root, reviewPath(job.key));
  if (!r.ok) return null;
  const v = r.value;
  if (!v || v.jobKey !== job.key || !v.review || v.review.schemaVersion !== _prompts_packs_js__WEBPACK_IMPORTED_MODULE_1__/* .REVIEW_SCHEMA_VERSION */ .k6) return null;
  if ((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .canonicalJson */ .dj)(v.review)) !== v.reviewHash) return null;
  return v;
}

// ---- run --------------------------------------------------------------------------------------------------------

const defaultSleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * Run a planned job list.
 *   ctx.root, ctx.loadJob(job) -> { pack, entrypoints, manifests, packageTexts } | { error }
 *   ctx.fileContents, ctx.invoker ({ok,invoke}|{ok:false,reason,denied}), ctx.model
 *   ctx.limits { concurrency, maxCalls, maxWallSeconds, maxTokensPerJob, maxRetries, jobTimeoutMs, maxCostUsd, costPerCallUsd }
 *   ctx.signal (AbortSignal), ctx.sleep, ctx.random, ctx.now  -- injected so tests are deterministic
 *   ctx.retryFailed (re-run jobs that ended failed/timed_out), ctx.onEvent
 */
async function runQueue(jobs, ctx) {
  const now = ctx.now || (() => Date.now());
  const sleep = ctx.sleep || defaultSleep;
  const random = ctx.random || Math.random;
  const emit = typeof ctx.onEvent === 'function' ? ctx.onEvent : () => {};
  const L = {
    concurrency: Math.min(HARD_LIMITS.maxConcurrency, Math.max(1, ctx.limits.concurrency || 1)),
    maxCalls: Math.min(HARD_LIMITS.maxCalls, Math.max(1, ctx.limits.maxCalls || 100)),
    maxWallMs: Math.min(HARD_LIMITS.maxWallSeconds, Math.max(1, ctx.limits.maxWallSeconds || 900)) * 1000,
    maxTokensPerJob: ctx.limits.maxTokensPerJob || 40000,
    maxTokensPerRepo: Number.isFinite(ctx.limits.maxTokensPerRepo) ? ctx.limits.maxTokensPerRepo : null,
    anonymizePrompts: ctx.limits.anonymizePrompts === true,
    maxRetries: Math.min(HARD_LIMITS.maxRetries, Math.max(0, ctx.limits.maxRetries ?? 3)),
    jobTimeoutMs: ctx.limits.jobTimeoutMs || 120000,
    maxCostUsd: Number.isFinite(ctx.limits.maxCostUsd) ? ctx.limits.maxCostUsd : null,
    costPerCallUsd: Number.isFinite(ctx.limits.costPerCallUsd) ? ctx.limits.costPerCallUsd : null,
  };
  const runId = runIdOf(jobs, L);
  const started = now();
  const loaded = loadState(ctx.root, runId);
  const prior = loaded.ok ? loaded.state.jobs : {};
  const state = { schemaVersion: QUEUE_SCHEMA_VERSION, runId, jobs: {} };
  const results = new Map();
  let calls = 0;
  let estCost = 0;
  let tokensUsed = 0;
  let cooldownUntil = 0;
  let budgetStop = null;
  let persistChain = Promise.resolve();
  const persist = () => {
    persistChain = persistChain.then(() => { (0,_store_js__WEBPACK_IMPORTED_MODULE_3__/* .writeStoreJson */ .DU)(ctx.root, `queues/${runId}.json`, sealState(state)); });
    return persistChain;
  };

  const settle = async (job, outcome) => {
    state.jobs[job.key] = { state: outcome.state, reason: outcome.reason || null, attempts: outcome.attempts || 0, label: job.label };
    results.set(job.key, { job, ...outcome });
    if (outcome.review) {
      const reviewRecord = { schemaVersion: 'review-result/1', jobKey: job.key, questionPack: job.packRef, entrypointIds: job.entrypointIds, contextHashes: job.contextHashes, state: outcome.state, review: outcome.review, reviewHash: (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .canonicalJson */ .dj)(outcome.review)) };
      (0,_store_js__WEBPACK_IMPORTED_MODULE_3__/* .writeStoreJson */ .DU)(ctx.root, reviewPath(job.key), reviewRecord);
    }
    await persist();
    emit({ event: 'job', key: job.key, state: outcome.state, reason: outcome.reason || null });
  };

  // classify jobs: cached / settled-before / to run
  const todo = [];
  for (const job of jobs) {
    const p = prior[job.key];
    const cached = loadCachedReview(ctx.root, job);
    if (cached && cached.state === 'succeeded') {
      results.set(job.key, { job, state: 'succeeded', reason: null, review: cached.review, cached: true, attempts: 0 });
      state.jobs[job.key] = { state: 'succeeded', reason: null, attempts: 0, label: job.label, cached: true };
      continue;
    }
    // A policy skip, a cancellation and an interrupted job say nothing about the model, so they are always re-evaluated:
    // the policy or the endpoint may be different now. Answers (even declined ones) and real failures are kept so a
    // resume does not pay twice, unless the operator asks to retry them.
    const resettable = !p || p.state === 'skipped_by_policy' || p.state === 'cancelled' || p.state === 'running' || p.state === 'pending' || (ctx.retryFailed && (p.state === 'failed' || p.state === 'timed_out'));
    if (!resettable && ['partial', 'failed', 'timed_out', 'succeeded'].includes(p.state)) {
      state.jobs[job.key] = { ...p, resumed: true };
      results.set(job.key, { job, state: p.state, reason: p.reason, attempts: p.attempts, resumed: true, review: cached ? cached.review : undefined });
      continue;
    }
    state.jobs[job.key] = { state: 'pending', reason: null, attempts: 0, label: job.label };
    todo.push(job);
  }
  await persist();

  const gate = async () => { const wait = cooldownUntil - now(); if (wait > 0) await sleep(wait); };

  const budgetReason = () => {
    if (ctx.signal && ctx.signal.aborted) return 'cancelled';
    if (now() - started >= L.maxWallMs) return 'budget-exhausted:wall-time';
    if (calls >= L.maxCalls) return 'budget-exhausted:max-calls';
    if (L.maxTokensPerRepo !== null && tokensUsed >= L.maxTokensPerRepo) return 'budget-exhausted:max-tokens-per-repo';
    if (L.maxCostUsd !== null && L.costPerCallUsd !== null && estCost + L.costPerCallUsd > L.maxCostUsd) return 'budget-exhausted:max-cost';
    return null;
  };

  const runOne = async (job) => {
    const stop = budgetReason();
    if (stop) { return settle(job, stop === 'cancelled' ? { state: 'cancelled', reason: 'run cancelled before this job started' } : { state: 'skipped_by_policy', reason: stop }); }
    if (!ctx.invoker || !ctx.invoker.ok) return settle(job, { state: 'skipped_by_policy', reason: (ctx.invoker && ctx.invoker.reason) || 'no model endpoint is configured' });

    const loadedJob = ctx.loadJob(job);
    if (loadedJob.error) return settle(job, { state: 'failed', reason: loadedJob.error, attempts: 0 });

    let attempts = 0;
    for (;;) {
      const s2 = budgetReason();
      if (s2) return settle(job, s2 === 'cancelled' ? { state: 'cancelled', reason: 'run cancelled', attempts } : { state: 'skipped_by_policy', reason: s2, attempts });
      await gate();
      attempts++;
      calls++;
      if (L.costPerCallUsd !== null) estCost += L.costPerCallUsd;
      state.jobs[job.key] = { state: 'running', reason: null, attempts, label: job.label };
      const out = await (0,_review_js__WEBPACK_IMPORTED_MODULE_2__/* .runReviewOnce */ .z6)({
        pack: loadedJob.pack, entrypoints: loadedJob.entrypoints, manifests: loadedJob.manifests, packageIndexes: job.packageIndexes, packageTexts: loadedJob.packageTexts,
        fileContents: ctx.fileContents, scanRoot: ctx.root, invoker: ctx.invoker, model: ctx.model, limits: { maxTokensPerJob: L.maxTokensPerJob, jobTimeoutMs: L.jobTimeoutMs, anonymizePrompts: L.anonymizePrompts },
      });
      if (out.usage) tokensUsed += (out.usage.inputTokensEstimated || 0) + (out.usage.outputTokensEstimated || 0);
      if (out.state === 'skipped_by_policy') calls--; // nothing was sent
      if (out.state === 'failed' && out.retryable && attempts <= L.maxRetries) {
        // exponential backoff with jitter; the shared cooldown slows every worker, which is what a 429 storm needs
        const backoff = Math.min(30000, 500 * 2 ** (attempts - 1)) + Math.floor(random() * 250);
        cooldownUntil = Math.max(cooldownUntil, now() + backoff);
        emit({ event: 'retry', key: job.key, attempt: attempts, backoffMs: backoff, reason: out.reason });
        continue;
      }
      return settle(job, { ...out, attempts });
    }
  };

  let next = 0;
  const worker = async () => {
    for (;;) {
      const idx = next++;
      if (idx >= todo.length) return;
      try { await runOne(todo[idx]); } catch (err) { await settle(todo[idx], { state: 'failed', reason: `internal error: ${String((err && err.message) || err).slice(0, 120)}` }); }
    }
  };
  const poolSize = Math.min(L.concurrency, Math.max(1, todo.length));
  await Promise.all(Array.from({ length: poolSize }, worker));
  await persistChain;

  // anything still pending/running was never finished: it is cancelled, not clean
  for (const job of todo) {
    const s = state.jobs[job.key];
    if (s && (s.state === 'pending' || s.state === 'running')) await settle(job, { state: 'cancelled', reason: 'run ended before this job finished', attempts: s.attempts });
  }
  budgetStop = budgetReason();
  return { runId, results, coverage: coverageOf(jobs, results, { calls, estCost: L.costPerCallUsd !== null ? estCost : null, costBasis: L.costPerCallUsd !== null ? 'estimate: operator-supplied per-call price' : 'unknown: no price supplied, dollar cap not enforceable', limits: L, wallMs: now() - started, budgetStop, queueStateCorrupt: loaded.corrupt === true }) };
}

function coverageOf(jobs, results, extra = {}) {
  const c = { eligible: jobs.length, attempted: 0, succeeded: 0, partial: 0, failed: 0, timed_out: 0, skipped_by_policy: 0, cancelled: 0, cached: 0, resumed: 0, modelCalls: extra.calls || 0, estimatedCostUsd: extra.estCost ?? null, costBasis: extra.costBasis || null, wallMs: extra.wallMs || 0, budgetStop: extra.budgetStop || null, queueStateCorrupt: !!extra.queueStateCorrupt, reasons: {} };
  for (const job of jobs) {
    const r = results.get(job.key);
    if (!r) { c.cancelled++; continue; }
    c[r.state] = (c[r.state] || 0) + 1;
    if (r.cached) c.cached++;
    if (r.resumed) c.resumed++;
    if (r.state !== 'skipped_by_policy' && r.state !== 'cancelled') c.attempted++;
    if (r.reason) c.reasons[r.reason] = (c.reasons[r.reason] || 0) + 1;
  }
  // only a succeeded job with a conclusion is a reviewed route; everything else is missing coverage, never a clean pass
  c.reviewed = c.succeeded;
  c.missingCoverage = c.eligible - c.succeeded;
  return c;
}

// ---- offline batch: export a request file, import a result file --------------------------------------------------

function batchIdOf(jobs) { return (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .hashOf */ .qQ)(jobs.map(j => j.key)).slice(0, 24); }

/**
 * Write a provider-agnostic batch: a request file (one JSON line per job, with the redacted prompt) and a manifest that
 * binds every request to its job key, context hash and prompt hash. No provider API is called: uploading the file and
 * downloading results is the operator's step, and the contract of any particular provider's batch API is NOT assumed.
 */
function exportBatch(root, jobs, loadJob, ctx) {
  const { buildReviewPrompt, redactPackageText, checkEgressForFiles } = ctx.review;
  const lines = [];
  const entries = [];
  const skipped = [];
  for (const job of jobs) {
    const lj = loadJob(job);
    if (lj.error) { skipped.push({ key: job.key, reason: lj.error }); continue; }
    const files = [...new Set(lj.manifests.flatMap((m, i) => (m.context.packages.find(p => p.index === job.packageIndexes[i]) || { segments: [] }).segments.map(s => s.file)))];
    const eg = checkEgressForFiles(files, { scanRoot: root, model: ctx.model });
    if (!eg.allowed) { skipped.push({ key: job.key, reason: `egress policy denied ${eg.file}: ${eg.reason}` }); continue; }
    const red = lj.packageTexts.map(t => redactPackageText(t, { scanRoot: root }));
    const bad = red.find(r => !r.ok);
    if (bad) { skipped.push({ key: job.key, reason: `redaction refused: ${bad.reason}` }); continue; }
    const { prompt, promptHash } = buildReviewPrompt({ pack: lj.pack, entrypoints: lj.entrypoints, packageTexts: red.map(r => r.text), contextHash: lj.manifests[0].contextHash });
    lines.push(JSON.stringify({ custom_id: job.key, prompt }));
    entries.push({ key: job.key, packRef: job.packRef, entrypointIds: job.entrypointIds, contextHashes: job.contextHashes, packageIndexes: job.packageIndexes, promptHash });
  }
  const batchId = batchIdOf(jobs);
  const manifest = { schemaVersion: 'review-batch/1', batchId, jobs: entries, skipped, note: 'Provider batch upload and download are performed by the operator. Results are imported with `context review --import-batch`.' };
  const w1 = (0,_store_js__WEBPACK_IMPORTED_MODULE_3__.writeStoreFile)(root, `batches/${batchId}/requests.jsonl`, lines.join('\n') + (lines.length ? '\n' : ''));
  if (!w1.ok) return w1;
  const w2 = (0,_store_js__WEBPACK_IMPORTED_MODULE_3__/* .writeStoreJson */ .DU)(root, `batches/${batchId}/manifest.json`, manifest);
  if (!w2.ok) return w2;
  return { ok: true, batchId, requests: entries.length, skipped, requestsFile: w1.path };
}

/**
 * Import results for a batch. Each result line is `{ custom_id, response }` where `response` is the model text.
 * A result is REJECTED when it names an unknown job, repeats a job already settled (first wins), or was produced for a
 * context that is no longer the current one (stale or out-of-order). Import is idempotent.
 */
function importBatch(root, batchId, resultsText, ctx) {
  const m = (0,_store_js__WEBPACK_IMPORTED_MODULE_3__/* .readStoreJson */ .WS)(root, `batches/${batchId}/manifest.json`);
  if (!m.ok) return { ok: false, reason: `batch manifest ${m.code}` };
  const byKey = new Map(m.value.jobs.map(j => [j.key, j]));
  const seen = new Set();
  const report = { accepted: 0, declined: 0, rejected: [], duplicates: 0 };
  for (const lineRaw of String(resultsText).split('\n')) {
    const line = lineRaw.trim();
    if (!line) continue;
    let rec;
    try { rec = JSON.parse(line); } catch { report.rejected.push({ reason: 'not-json' }); continue; }
    const key = rec && rec.custom_id;
    const entry = byKey.get(key);
    if (!entry) { report.rejected.push({ key: key || null, reason: 'unknown-job' }); continue; }
    const settled = loadCachedReview(root, { key });
    if (seen.has(key) || (settled && settled.state === 'succeeded')) { report.duplicates++; continue; }
    seen.add(key);
    const job = ctx.jobs.find(j => j.key === key);
    if (!job) { report.rejected.push({ key, reason: 'job-not-in-current-plan' }); continue; }
    const lj = ctx.loadJob(job);
    if (lj.error) { report.rejected.push({ key, reason: lj.error }); continue; }
    if (lj.manifests.some((mm, i) => mm.contextHash !== entry.contextHashes[i])) { report.rejected.push({ key, reason: 'stale-context' }); continue; }
    const promptHash = entry.promptHash;
    const review = (0,_review_js__WEBPACK_IMPORTED_MODULE_2__/* .verifyReview */ .sj)({ raw: typeof rec.response === 'string' ? rec.response : '', pack: lj.pack, entrypoints: lj.entrypoints, manifests: lj.manifests, packageIndexes: job.packageIndexes, fileContents: ctx.fileContents, promptHash });
    const state = review.status === 'completed' ? 'succeeded' : 'partial';
    const record = { schemaVersion: 'review-result/1', jobKey: key, questionPack: job.packRef, entrypointIds: job.entrypointIds, contextHashes: job.contextHashes, state, review, reviewHash: (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .canonicalJson */ .dj)(review)), via: 'batch-import' };
    (0,_store_js__WEBPACK_IMPORTED_MODULE_3__/* .writeStoreJson */ .DU)(root, reviewPath(key), record);
    if (state === 'succeeded') report.accepted++; else report.declined++;
  }
  return { ok: true, ...report };
}



/***/ })

};
