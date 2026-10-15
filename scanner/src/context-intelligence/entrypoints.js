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
import { hashOf } from './canonical.js';
import { callStatement, inlineBlockSpan, splitArgs } from './spans.js';
import { dependencyParams, signatureText } from './controls.js';
import { buildEntrypointInventory } from '../posture/entrypoint-inventory.js';

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
      const names = rest.map(a => { const id = IDENT_CHAIN.exec(a.replace(/^\[|\]$/g, '')); return id ? { name: id[0], text: a } : { name: null, text: a }; });
      uses.push({ file, line: i + 1, receiver: m[1], prefix, args: names });
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
  const exclude = (config.exclude || []).map(globToRe);
  const cap = Number.isInteger(config.maxEntrypoints) && config.maxEntrypoints > 0 ? config.maxEntrypoints : 5000;
  const ctx = { fileContents, idx, graph };
  const records = [];

  if (kinds.has('http') || kinds.has('webhook')) {
    for (const route of await collectRoutes(fileContents)) {
      const isWebhook = /webhook/i.test(route.path || '');
      if (isWebhook && !kinds.has('webhook') && !kinds.has('http')) continue;
      const h = resolveHandler(route, ctx);
      const reasons = [...h.reasons];
      const middleware = [...h.middleware];
      // inherited middleware registered with `X.use(...)` on the same receiver, earlier in the same file
      if (JS_FILE.test(route.file)) {
        const lines = fileContents[route.file].split('\n');
        const recvM = /([A-Za-z_$][\w$]*)\.(?:get|post|put|patch|delete|all|options|head|route)\s*\(/.exec(lines[route.line - 1] || '');
        const receiver = recvM ? recvM[1] : null;
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
        if (receiver && /^(?:router|routes?|r|api|\w*Router)$/i.test(receiver) && !uses.some(u => u.receiver !== receiver && u.args.some(a => a.name === receiver))) {
          reasons.push('router-mount-not-resolved');
        }
      }
      const authScheme = route.webModel
        ? { status: route.webModel.auth.status, kind: route.webModel.auth.kind || null, basis: 'haskell-web-model', role: route.webModel.role.status, ownership: route.webModel.ownership || null, idLookups: route.webModel.idLookups || [], csrf: !!route.webModel.csrf }
        : { status: route.hasAuth ? 'authenticated' : 'none', basis: 'route-scan-heuristic', note: 'authentication seen near the registration; says nothing about ownership' };
      const base = {
        kind: isWebhook ? 'webhook' : 'http',
        method: String(route.method || 'GET'),
        pathTemplate: String(route.path || ''),
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
      records.push(base);
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
    r.label = `${r.method ? r.method + ' ' : ''}${r.pathTemplate}`.trim() || r.kind;
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
