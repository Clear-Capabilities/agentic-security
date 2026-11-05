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
import { hashOf, safeLabel } from './canonical.js';
import { callStatement, inlineBlockSpan, splitArgs } from './spans.js';
import { dependencyParams, signatureText } from './controls.js';
import { buildEntrypointInventory } from '../posture/entrypoint-inventory.js';
import { buildImportMap, resolveViaImports, resolveJsModule } from './imports.js';

export const DISPOSITIONS = Object.freeze(['resolved', 'partially_resolved', 'unresolved', 'excluded_by_policy']);
export const ENTRYPOINT_KINDS = Object.freeze(['http', 'webhook', 'queue', 'cron', 'upload', 'cli']);

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
      const st = callStatement(lines, i + 1);
      if (!st) continue;
      const args = splitArgs(st.text);
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
  const { scanRoutes } = await import('../engine.js');
  const { analyzeHaskellWeb } = await import('../language/haskell-web.js');
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
      out.rootSpan = { file: route.file, ...inlineBlockSpan(lines, route.line) };
      const enclosing = fileSyms.filter(s => s.kind === 'function' && s.startLine <= route.line && s.endLine >= route.line).sort((a, b) => (b.startLine - a.startLine))[0];
      out.handlerSymbol = enclosing ? enclosing.id : null;
      out.confidence = enclosing ? 'inline-block' : 'none';
      if (!enclosing) reasons.push('inline-handler-without-enclosing-declaration');
    } else {
      reasons.push('handler-not-statically-known');
      // the manifest still shows where the route is registered, so the gap is inspectable rather than absent
      out.rootSpan = { file: route.file, ...inlineBlockSpan(lines, route.line) };
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
      for (const d of dependencyParams(signatureText(lines, decl.declLine))) {
        const r = resolveName(d.dependency, route.file, idx);
        out.middleware.push({ name: d.dependency, symbolId: r.symbol ? r.symbol.id : null, resolution: r.resolution, line: decl.declLine, dependency: true, param: d.param });
        if (!r.symbol) reasons.push(`dependency-${r.resolution}:${d.dependency}`);
        else if (r.resolution === 'name-match') reasons.push(`dependency-matched-by-name-only:${d.dependency}`);
      }
    }
    else reasons.push('decorated-handler-not-found');
    return out;
  }

  const st = JS_FILE.test(route.file) ? callStatement(lines, route.line) : null;
  if (!st) {
    // not a call-style registration we can parse: fall back to the enclosing declaration, flagged
    const enclosing = fileSyms.filter(s => s.kind === 'function' && s.startLine <= route.line && s.endLine >= route.line).sort((a, b) => b.startLine - a.startLine)[0];
    if (enclosing) { out.handlerSymbol = enclosing.id; out.handlerKind = 'enclosing'; out.confidence = 'enclosing'; reasons.push('registration-form-not-parsed'); }
    else reasons.push('registration-form-not-parsed');
    return out;
  }
  out.rootSpan = { file: route.file, startLine: route.line, endLine: st.endLine, precision: 'brace' };
  const args = splitArgs(st.text).slice(1); // drop the path
  const flat = [];
  for (const a of args) {
    if (a.startsWith('[') && a.endsWith(']')) flat.push(...splitArgs(`(${a.slice(1, -1)})`));
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
  const imports = buildImportMap(fileContents);
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
        const res = resolveJsModule(u.file, req[2], files);
        const recv = res && res.target && files.has(res.target) ? exportedReceiver(fileContents[res.target]) : null;
        if (recv && isRouter(res.target, recv)) target = { file: res.target, receiver: recv };
      } else if (a.name && a.name !== u.receiver && isRouter(u.file, a.name)) {
        target = { file: u.file, receiver: a.name };
      } else if (a.name) {
        const via = resolveViaImports(imports, u.file, a.name);
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
export async function collectEntrypoints({ fileContents, graph, config = {} }) {
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
    const inv = buildEntrypointInventory(fileContents, { routes: [] });
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
    const stem = hashOf({ k: r.kind, m: r.method, p: r.pathTemplate, f: r.registrationSite.file, h: r.handlerSymbol ? r.handlerSymbol : null });
    const n = (ord.get(stem) || 0) + 1;
    ord.set(stem, n);
    r.id = `ep:${stem.slice(0, 20)}${n > 1 ? `-${n}` : ''}`;
    r.label = safeLabel(`${r.method ? r.method + ' ' : ''}${r.pathTemplate}`) || r.kind;
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
export function countDispositions(records) {
  const c = { total: records.length, resolved: 0, partially_resolved: 0, unresolved: 0, excluded_by_policy: 0 };
  for (const r of records) c[r.disposition]++;
  return c;
}
