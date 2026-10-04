// Flake, legacy input and declared package inventory (NIX-007).
//
// Three different things are inventoried and never merged:
//   input      a source dependency named by flake.nix (url, follows, flake=false) and, when flake.lock is
//              present, its locked node (fetch type, rev, narHash) and the exact follows-resolved edge graph
//   selector   a package SELECTOR such as pkgs.git or `with pkgs; [ curl ]`: a name in an attribute set, not a
//              version. A selector is NEVER resolved to a version here, even when the lock pins nixpkgs: the
//              nixpkgs revision is not the package version, and `pkgs` may be an overlay or another channel.
//   resolved   an exact package from a derivation/closure export (NIX-008). Nothing in this module produces one.
//
// A lock file describes source inputs. It is not a runtime closure, and the result says so (`closure`).
// Legacy forms (channels, NIX_PATH, <nixpkgs>, fetchTarball of a branch, local paths) are recorded with the
// resolution they actually have and the trust warning that follows from it. Static only: nothing here
// evaluates Nix, contacts a registry or forces flakes.

import { redactUrlsDeep } from './secrets.js';
import { parseNix } from './nix-parser.js';
import { buildNixIR } from './nix-ir.js';
import { isLanguageExcludedPath } from './discovery.js';

export const NIX_INVENTORY_VERSION = 'nix-inventory/1';
export const MAX_LOCK_NODES = 20_000;
const SUPPORTED_LOCK_VERSIONS = new Set([5, 6, 7]);
const OUTPUT_KINDS = new Set(['packages', 'legacyPackages', 'devShells', 'apps', 'checks', 'nixosConfigurations', 'nixosModules', 'overlays', 'overlay', 'defaultPackage', 'devShell', 'defaultApp', 'homeConfigurations', 'darwinConfigurations', 'templates', 'formatter', 'hydraJobs', 'lib', 'nixosModule']);

const dirOf = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
const join = (d, f) => (d ? `${d}/${f}` : f);

// ── lock parsing ─────────────────────────────────────────────────────────────
function fetchMeta(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const m = { type: entry.type || null };
  for (const k of ['owner', 'repo', 'url', 'ref', 'rev', 'narHash', 'path', 'dir', 'host', 'id', 'lastModified', 'revCount', 'submodules']) if (entry[k] !== undefined) m[k] = entry[k];
  return m;
}

function resolveFollows(nodes, rootKey, path, guard) {
  // `follows` is a path of input NAMES from the root: root.inputs[p0] -> node, node.inputs[p1] -> ...
  let cur = rootKey; const walked = [];
  for (const name of path) {
    const n = nodes[cur];
    if (!n || !n.inputs || !(name in n.inputs)) return { error: `follows path ${path.join('/')} does not exist (no input "${name}" on ${cur})` };
    const target = n.inputs[name];
    walked.push(name);
    if (Array.isArray(target)) {
      const key = target.join('/');
      if (guard.has(key)) return { cycle: [...guard, key] };
      guard.add(key);
      const r = resolveFollows(nodes, rootKey, target, guard);
      guard.delete(key);
      if (r.error || r.cycle) return r;
      cur = r.key;
    } else cur = target;
  }
  return { key: cur };
}

/** Parse flake.lock text into a labelled graph. Never throws. */
export function parseFlakeLock(text, file = 'flake.lock') {
  let doc;
  try { doc = JSON.parse(text); } catch (e) { return { status: 'invalid', file, error: String(e.message || e), nodes: [], edges: [], cycles: [], dangling: [], orphans: [] }; }
  if (!doc || typeof doc !== 'object' || typeof doc.nodes !== 'object' || doc.nodes === null) return { status: 'invalid', file, error: 'no "nodes" object', nodes: [], edges: [], cycles: [], dangling: [], orphans: [] };
  const rawNodes = doc.nodes;
  const keys = Object.keys(rawNodes);
  if (keys.length > MAX_LOCK_NODES) return { status: 'budget_exceeded', file, error: `${keys.length} nodes exceed ${MAX_LOCK_NODES}`, nodes: [], edges: [], cycles: [], dangling: [], orphans: [] };
  const rootKey = typeof doc.root === 'string' ? doc.root : 'root';
  const version = Number.isInteger(doc.version) ? doc.version : null;
  const out = { status: 'ok', file, version, versionSupported: SUPPORTED_LOCK_VERSIONS.has(version), root: rootKey, nodes: [], edges: [], cycles: [], dangling: [], orphans: [], problems: [] };
  if (!rawNodes[rootKey]) { out.status = 'invalid'; out.error = `root node "${rootKey}" is missing`; return out; }
  if (!out.versionSupported) out.problems.push(`lock version ${version} is not one of ${[...SUPPORTED_LOCK_VERSIONS].join('/')}; edges are best-effort`);

  const edgeSet = new Set();
  const reachable = new Set([rootKey]);
  const queue = [rootKey];
  const cycles = new Set();
  while (queue.length) {
    const from = queue.shift();
    const n = rawNodes[from];
    for (const [name, target] of Object.entries((n && n.inputs) || {})) {
      let to = null; let via = 'inputs'; let followsPath = null;
      if (Array.isArray(target)) {
        via = 'follows'; followsPath = target;
        const r = resolveFollows(rawNodes, rootKey, target, new Set([target.join('/')]));
        if (r.cycle) { cycles.add(r.cycle.join(' -> ')); out.edges.push({ from, name, via, followsPath, to: null, status: 'cycle' }); continue; }
        if (r.error) { out.dangling.push({ from, name, reason: r.error }); out.edges.push({ from, name, via, followsPath, to: null, status: 'dangling' }); continue; }
        to = r.key;
      } else if (typeof target === 'string') to = target;
      else { out.dangling.push({ from, name, reason: `input "${name}" has an unusable target` }); continue; }
      if (!rawNodes[to]) { out.dangling.push({ from, name, reason: `edge target "${to}" is not a node` }); out.edges.push({ from, name, via, followsPath, to, status: 'dangling' }); continue; }
      const k = `${from}\u0000${name}`;
      if (edgeSet.has(k)) continue;
      edgeSet.add(k);
      out.edges.push({ from, name, via, followsPath, to, status: 'ok' });
      if (!reachable.has(to)) { reachable.add(to); queue.push(to); }
    }
  }
  out.cycles = [...cycles];
  // a node reachable from itself through plain (non-follows) edges is also a cycle
  const adj = new Map();
  for (const e of out.edges) if (e.status === 'ok') { if (!adj.has(e.from)) adj.set(e.from, []); adj.get(e.from).push(e.to); }
  const color = new Map();
  const dfs = (u, stack) => {
    color.set(u, 1);
    for (const v of adj.get(u) || []) {
      if (color.get(v) === 1) out.cycles.push([...stack, u, v].join(' -> '));
      else if (!color.get(v)) dfs(v, [...stack, u]);
    }
    color.set(u, 2);
  };
  dfs(rootKey, []);
  out.cycles = [...new Set(out.cycles)];
  // nodes
  const nameOf = new Map();
  for (const e of out.edges) if (e.from === rootKey && e.to && e.status === 'ok' && !nameOf.has(e.to)) nameOf.set(e.to, e.name);
  for (const k of keys) {
    const n = rawNodes[k];
    const locked = fetchMeta(n.locked); const original = fetchMeta(n.original);
    const isRoot = k === rootKey;
    out.nodes.push({
      key: k, root: isRoot, name: isRoot ? null : (nameOf.get(k) || k),
      flake: n.flake !== false, componentClass: 'input', kind: 'source-dependency',
      locked, original, reachable: reachable.has(k),
      resolution: isRoot ? null : lockResolution(locked),
      inputs: Object.keys(n.inputs || {}),
    });
    if (!reachable.has(k)) out.orphans.push(k);
  }
  return out;
}

function lockResolution(l) {
  if (!l) return 'unlocked';
  if (l.rev && l.narHash) return 'locked-rev-and-hash';
  if (l.rev) return 'locked-rev';
  if (l.narHash) return 'locked-hash-only';
  if (l.type === 'path') return 'local-path';
  if (l.type === 'indirect') return 'unresolved-indirect';
  return 'floating';
}

function warningsFor(node) {
  const w = [];
  const l = node.locked; const o = node.original;
  if (node.root) return w;
  if (!l) w.push({ kind: 'unlocked', detail: 'no locked fetch metadata for this node' });
  else {
    if (l.type === 'path') w.push({ kind: 'local-path', detail: `local path input${l.path ? ` (${l.path})` : ''}: not fetched from a pinned remote` });
    if (l.type === 'indirect') w.push({ kind: 'indirect-registry', detail: `indirect reference "${l.id}" depends on the flake registry at evaluation time` });
    if (l.type !== 'path' && l.type !== 'indirect' && !l.rev && !l.narHash) w.push({ kind: 'no-integrity', detail: 'locked without rev or narHash' });
    if (l.type !== 'path' && l.type !== 'indirect' && !l.narHash) w.push({ kind: 'no-narhash', detail: 'no narHash: the fetched content is not integrity-checked' });
    if (l.type === 'tarball' && !l.rev) w.push({ kind: 'tarball-no-rev', detail: 'tarball input has no source revision, only a content hash' });
  }
  if (o && o.ref && l && l.rev) { /* ref pinned by rev: fine */ }
  return w;
}

// ── flake.nix ────────────────────────────────────────────────────────────────
function declaredInputs(file, text) {
  const parse = parseNix(text, { file });
  if (!parse.ast) return { ok: false, inputs: [], outputs: [], status: parse.status };
  const ir = buildNixIR(parse, { file, source: text });
  if (ir.fileKind !== 'flake' || !ir.flake) return { ok: false, inputs: [], outputs: [], status: 'not-a-flake', ir };
  const outputs = [];
  for (const b of ir.bindings) {
    const head = b.path[0];
    if (OUTPUT_KINDS.has(head) && b.origin !== 'let') outputs.push({ kind: head, path: b.path.filter(Boolean), attr: b.pathText, line: b.span ? b.span.startLine : null, span: b.span || null, dynamic: b.dynamic || b.path.includes(null) });
  }
  return { ok: true, inputs: ir.flake.inputs, outputs, status: parse.status, description: ir.flake.description, ir, params: ir.flake.outputs ? ir.flake.outputs.params : [] };
}

// ── legacy / selectors: AST walks ────────────────────────────────────────────
const FETCHERS = new Set(['fetchTarball', 'fetchurl', 'fetchGit', 'fetchTree', 'fetchzip', 'fetchMercurial']);
const SELECTOR_ROLES = [
  [/(^|\.)environment\.systemPackages$/, 'system'], [/(^|\.)users\.users\.[^.]+\.packages$/, 'user'], [/(^|\.)home\.packages$/, 'user'], [/(^|\.)(?:nativeBuildInputs|buildInputs|propagatedBuildInputs|checkInputs|nativeCheckInputs|installCheckInputs|depsBuildBuild)$/, 'build'],
  [/(^|\.)(?:packages|buildInputs|nativeBuildInputs)$/, 'dev'], [/(^|\.)package$/, 'service'], [/(^|\.)extraPackages$/, 'service'], [/(^|\.)path$/, 'service'],
];
const roleOf = (attrPath) => { const p = attrPath.filter(Boolean).join('.'); for (const [re, role] of SELECTOR_ROLES) if (re.test(p)) return role; return 'unspecified'; };
const segName = (s) => (s && s.kind === 'static' ? s.name : null);
const unparen = (n) => { let x = n; while (x && x.type === 'paren') x = x.expr; return x; };

function walkAst(root, cb) {
  const stack = [{ n: root, path: [], withs: [] }];
  while (stack.length) {
    const { n, path, withs } = stack.pop();
    if (!n || typeof n !== 'object') continue;
    cb(n, path, withs);
    switch (n.type) {
      case 'attrset': case 'let': {
        for (const b of n.bindings || []) {
          if (b.kind === 'attr') { const key = (b.path || []).map(segName); stack.push({ n: b.value, path: n.type === 'let' ? [] : [...path, ...key], withs }); }
        }
        if (n.type === 'let') stack.push({ n: n.body, path, withs });
        break;
      }
      case 'with': { const base = unparen(n.env); const nm = base && base.type === 'ident' ? base.name : (base && base.type === 'select' && unparen(base.base) && unparen(base.base).type === 'ident' ? unparen(base.base).name : null); stack.push({ n: n.env, path, withs }); stack.push({ n: n.body, path, withs: [...withs, nm] }); break; }
      case 'lambda': stack.push({ n: n.body, path, withs }); break;
      case 'app': stack.push({ n: n.fn, path, withs }); stack.push({ n: n.arg, path, withs }); break;
      case 'list': for (const it of n.items) stack.push({ n: it, path, withs }); break;
      case 'binop': stack.push({ n: n.left, path, withs }); stack.push({ n: n.right, path, withs }); break;
      case 'if': stack.push({ n: n.then, path, withs }); stack.push({ n: n.else, path, withs }); break;
      case 'paren': stack.push({ n: n.expr, path, withs }); break;
      case 'select': stack.push({ n: n.base, path, withs }); break;
      case 'string': for (const p of n.parts || []) if (p.kind === 'interp') stack.push({ n: p.expr, path, withs }); break;
      default: break;
    }
  }
}

function collectLegacyAndSelectors(file, text, flakeProvider) {
  const parse = parseNix(text, { file });
  const legacy = []; const selectors = [];
  if (!parse.ast) return { legacy, selectors };
  const line = (n) => (n && n.span ? n.span.startLine : null);
  walkAst(parse.ast, (n, path, withs) => {
    if (n.type === 'spath') legacy.push({ kind: 'angle-bracket', value: `<${n.value}>`, file, line: line(n), resolution: 'nix-path-lookup', warnings: [{ kind: 'nix-path', detail: `<${n.value}> resolves through NIX_PATH at evaluation time: the result depends on the evaluating machine` }] });
    if (n.type === 'attrset') {
      for (const b of n.bindings || []) {
        if (b.kind !== 'attr') continue;
        const key = (b.path || []).map(segName).filter(Boolean).join('.');
        const full = [...path.filter(Boolean), ...(b.path || []).map(segName).filter(Boolean)].join('.');
        const v = unparen(b.value);
        if (/(?:^|\.)nix\.nixPath$/.test(full) && v && v.type === 'list') {
          for (const it of v.items) { const s = unparen(it); legacy.push({ kind: 'nixPath', value: s && s.literal !== undefined ? s.literal : null, file, line: line(it), resolution: s && s.literal && /^[^=]*=(?:flake:|\/nix\/store\/)/.test(s.literal) ? 'pinned-path' : 'nix-path-entry', warnings: [{ kind: 'nix-path', detail: 'nix.nixPath entries feed <...> lookups; they are not part of any lock' }] }); }
        }
        if (/(?:^|\.)nix\.channel\.enable$/.test(full)) legacy.push({ kind: 'channel-setting', value: v && v.type === 'ident' ? v.name : null, file, line: line(b), resolution: 'setting', warnings: [] });
        if (/(?:^|\.)system\.autoUpgrade\.(?:channel|flake)$/.test(full) && v && v.literal !== undefined) legacy.push({ kind: /channel$/.test(full) ? 'channel' : 'auto-upgrade-flake', value: v.literal, file, line: line(b), resolution: /channel$/.test(full) ? 'floating-channel' : 'flake-ref', warnings: /channel$/.test(full) ? [{ kind: 'floating-channel', detail: `channel ${v.literal} moves over time; nothing pins a revision` }] : [] });
        if (/(?:^|\.)nix\.registry\.[^.]+\.(?:to|from)$/.test(full) || /(?:^|\.)nix\.registry\./.test(full)) legacy.push({ kind: 'registry', value: full, file, line: line(b), resolution: 'registry-entry', warnings: [] });
        const sel = SELECTOR_ROLES.some(([re]) => re.test(full)) ? roleOf(full.split('.')) : null;
        if (sel && v) collectSelectors(v, full.split('.'), sel, withs, file, selectors, flakeProvider);
      }
    }
    if (n.type === 'app') {
      let fn = unparen(n.fn); const args = [n.arg];
      while (fn && fn.type === 'app') { args.unshift(fn.arg); fn = unparen(fn.fn); }
      const name = fn && fn.type === 'ident' ? fn.name : (fn && fn.type === 'select' ? segName(fn.attrpath[fn.attrpath.length - 1]) : null);
      const root = fn && fn.type === 'select' ? (unparen(fn.base) || {}).name : null;
      if (name && FETCHERS.has(name) && (root === 'builtins' || root === 'pkgs' || !root || true)) legacy.push(fetcherEntry(name, args, file, line(n)));
      if (name === 'getFlake' && root === 'builtins') { const a = unparen(args[0]); legacy.push({ kind: 'getFlake', value: a && a.literal !== undefined ? a.literal : null, file, line: line(n), resolution: a && a.literal && /[?&]rev=[0-9a-f]{40}/.test(a.literal) ? 'rev-pinned' : 'floating-ref', warnings: [{ kind: 'impure-eval', detail: 'builtins.getFlake fetches at evaluation time and is not recorded in the lock of the calling flake' }] }); }
      if (name === 'import' && fn && fn.type === 'ident') { const a = unparen(args[0]); if (a && a.type === 'path' && a.literal && /^(?:\/|~)/.test(a.literal)) legacy.push({ kind: 'local-path', value: a.literal, file, line: line(n), resolution: 'absolute-path', warnings: [{ kind: 'local-path', detail: `${a.literal} is outside the repository: the build depends on the machine` }] }); }
    }
  });
  return { legacy, selectors };
}

function fetcherEntry(name, args, file, ln) {
  const a = unparen(args[0]);
  let url = null; let sha = false; let rev = null; let ref = null;
  if (a && a.type === 'string' && a.literal !== undefined) url = a.literal;
  if (a && a.type === 'attrset') {
    for (const b of a.bindings) {
      if (b.kind !== 'attr') continue; const k = (b.path || []).map(segName).join('.');
      const v = unparen(b.value);
      if (k === 'url' && v && v.literal !== undefined) url = v.literal;
      if (/^(?:sha256|hash)$/.test(k)) sha = true;
      if (k === 'rev' && v && v.literal !== undefined) rev = v.literal;
      if (k === 'ref' && v && v.literal !== undefined) ref = v.literal;
    }
  }
  const pinnedByUrl = url && /\/archive\/[0-9a-f]{40}\.(?:tar|zip)|\?rev=[0-9a-f]{40}|\/[0-9a-f]{40}(?:\.tar|\/)/.test(url);
  const floatingUrl = url && /\/archive\/(?:refs\/heads\/)?[A-Za-z][\w.-]*\.(?:tar\.gz|tgz|zip)$/.test(url) && !pinnedByUrl;
  let resolution;
  if (rev && /^[0-9a-f]{40}$/.test(rev) && (sha || name === 'fetchGit')) resolution = sha ? 'rev-and-hash' : 'rev-pinned';
  else if (rev && /^[0-9a-f]{40}$/.test(rev)) resolution = 'rev-pinned';
  else if (sha) resolution = 'hash-pinned';
  else if (pinnedByUrl) resolution = 'rev-in-url';
  else if (floatingUrl || ref) resolution = 'floating-ref';
  else resolution = 'unpinned';
  const warnings = [];
  if (resolution === 'unpinned' || resolution === 'floating-ref') warnings.push({ kind: 'unpinned-fetch', detail: `${name} of ${url || 'a computed url'}${ref ? ` (ref ${ref})` : ''} has no revision or hash: its content changes over time` });
  if (!sha && name !== 'fetchGit' && resolution !== 'rev-in-url') warnings.push({ kind: 'no-integrity', detail: `${name} has no sha256/hash` });
  return { kind: name, value: url, file, line: ln, resolution, rev: rev || null, ref: ref || null, integrity: sha ? 'hash' : 'none', warnings };
}

function collectSelectors(v, attrPath, role, withs, file, out, flakeProvider) {
  const items = [];
  const walk = (n) => {
    n = unparen(n);
    if (!n) return;
    if (n.type === 'list') for (const it of n.items) walk(it);
    else if (n.type === 'binop') { walk(n.left); walk(n.right); }
    else if (n.type === 'with') { const b = unparen(n.env); const nm = b && b.type === 'ident' ? b.name : (b && b.type === 'select' ? (unparen(b.base) || {}).name : null); collectSelectorsIn(n.body, [...withs, nm]); }
    else if (n.type === 'if') { walk(n.then); walk(n.else); }
    else items.push(n);
  };
  const collectSelectorsIn = (body, ws) => { const b = unparen(body); if (b && b.type === 'list') for (const it of b.items) classify(unparen(it), ws); else if (b) classify(b, ws); };
  const classify = (n, ws) => {
    if (!n) return;
    if (n.type === 'ident' && ws.includes('pkgs')) out.push({ ...sel(n.name, 'pkgs', n, `pkgs.${n.name}`), via: 'with pkgs' });
    else if (n.type === 'select') {
      const base = unparen(n.base); const segs = n.attrpath.map(segName);
      if (base && base.type === 'ident' && base.name === 'pkgs' && segs.every(Boolean)) out.push(sel(segs.join('.'), 'pkgs', n, `pkgs.${segs.join('.')}`));
      else if (base && base.type === 'ident' && /^(?:nixpkgs|inputs)$/.test(base.name) && segs.every(Boolean)) {
        const lp = segs.indexOf('legacyPackages'); const pk = segs.indexOf('packages');
        const idx = lp >= 0 ? lp : pk;
        if (idx >= 0 && segs.length > idx + 2) out.push(sel(segs.slice(idx + 2).join('.'), `${base.name}.${segs.slice(0, idx + 1).join('.')}`, n, `${base.name}.${segs.join('.')}`));
      }
    }
  };
  const sel = (attr, provider, n, text) => ({
    componentClass: 'selector', kind: 'software-package', selector: text, attr, provider, role, attrPath: attrPath.filter(Boolean).join('.'),
    file, line: n.span ? n.span.startLine : null, span: n.span || null,
    version: null, versionResolved: false, status: 'selector-only',
    providerEvidence: provider === 'pkgs' ? { status: 'module-argument', input: flakeProvider ? flakeProvider.name : null, note: 'pkgs is a module argument: it may be an overlay, a different channel or a pinned import, so the lock is not claimed as its source' } : { status: 'named-input', input: provider.split('.')[0] },
  });
  walk(v);
  for (const n of items) classify(n, withs);
}

// ── orchestration ────────────────────────────────────────────────────────────
/**
 * @param {{files: Record<string,string>}} opts  rel path -> content
 */
export function analyzeNixInputs(opts = {}) {
  const files = {};
  for (const [p, t] of Object.entries(opts.files || {})) if (typeof t === 'string' && !isLanguageExcludedPath(p) && (/\.nix$/i.test(p) || /(^|\/)flake\.lock$/i.test(p))) files[p] = t;
  const out = { version: NIX_INVENTORY_VERSION, flakes: [], legacy: [], selectors: [], components: [], gaps: [], closure: { complete: false, status: 'not-computed', reason: 'flake.lock and flake.nix describe source inputs and package selectors; a runtime closure needs an explicit target-specific export (NIX-008)' } };
  const flakeFiles = Object.keys(files).filter((f) => /(^|\/)flake\.nix$/.test(f)).sort();
  const lockOwners = new Set();
  for (const ff of flakeFiles) {
    const dir = dirOf(ff);
    const lockPath = join(dir, 'flake.lock');
    const decl = declaredInputs(ff, files[ff]);
    const flake = { file: ff, dir, status: decl.status, description: decl.description || null, declared: [], outputs: decl.outputs || [], outputParams: decl.params || [], lock: null, graph: null, warnings: [], componentClass: 'input' };
    if (!decl.ok) { out.gaps.push({ kind: 'flake-not-parsed', file: ff, detail: `flake.nix could not be read as a flake (${decl.status})` }); out.flakes.push(flake); continue; }
    let lock;
    if (typeof files[lockPath] === 'string') { lock = parseFlakeLock(files[lockPath], lockPath); lockOwners.add(lockPath); }
    else lock = { status: 'missing', file: lockPath, nodes: [], edges: [], cycles: [], dangling: [], orphans: [] };
    flake.lock = { status: lock.status, file: lockPath, version: lock.version ?? null, error: lock.error || null, problems: lock.problems || [] };
    if (lock.status === 'missing') out.gaps.push({ kind: 'missing-flake-lock', file: ff, detail: `${lockPath} is absent: inputs are unlocked and resolve at evaluation time` });
    if (lock.status === 'invalid' || lock.status === 'budget_exceeded') out.gaps.push({ kind: 'invalid-flake-lock', file: lockPath, detail: lock.error });
    for (const c of lock.cycles) out.gaps.push({ kind: 'lock-cycle', file: lockPath, detail: `cycle in lock graph: ${c}` });
    for (const d of lock.dangling) out.gaps.push({ kind: 'lock-dangling-edge', file: lockPath, detail: `${d.from}.${d.name}: ${d.reason}` });
    const rootEdges = new Map(lock.edges.filter((e) => e.from === lock.root).map((e) => [e.name, e]));
    const nodeByKey = new Map(lock.nodes.map((n) => [n.key, n]));
    for (const inp of decl.inputs) {
      const e = rootEdges.get(inp.name);
      const node = e && e.to ? nodeByKey.get(e.to) : null;
      const row = {
        name: inp.name, url: inp.url, flake: inp.flake, follows: inp.follows, nestedFollows: inp.nestedFollows, dynamic: !!inp.dynamic,
        line: inp.span ? inp.span.startLine : null, locked: !!node, lockNode: node ? node.key : null,
        sourceKind: inp.flake === false ? 'nonflake-source' : 'flake', componentClass: 'input', kind: 'source-dependency',
        status: lock.status === 'ok' ? (node ? 'locked' : (inp.follows ? 'follows-declared' : 'declared-not-in-lock')) : (lock.status === 'missing' ? 'unlocked' : 'lock-unusable'),
        lockedFetch: node ? node.locked : null, originalFetch: node ? node.original : null, resolution: node ? node.resolution : 'unlocked',
        warnings: [],
      };
      if (node) row.warnings.push(...warningsFor(node));
      if (node && inp.url && node.original) {
        const want = String(inp.url);
        const o = node.original;
        const ref = o.type === 'github' ? `github:${o.owner}/${o.repo}${o.ref ? `/${o.ref}` : ''}` : null;
        if (ref && /^github:/.test(want) && want.replace(/\?.*$/, '').replace(/\/[0-9a-f]{40}$/, '') !== ref && want.replace(/\?.*$/, '') !== ref) row.warnings.push({ kind: 'lock-url-mismatch', detail: `flake.nix declares ${want} but the lock was made for ${ref}: the lock is stale for this input` });
      }
      if (!node && lock.status === 'ok' && !inp.follows) row.warnings.push({ kind: 'unlocked-input', detail: `input ${inp.name} is declared but not present in flake.lock` });
      flake.declared.push(row);
    }
    if (lock.status === 'ok') {
      const declaredNames = new Set(decl.inputs.map((i) => i.name));
      for (const [name, e] of rootEdges) if (!declaredNames.has(name)) flake.warnings.push({ kind: 'stale-lock-input', detail: `flake.lock has input "${name}" that flake.nix no longer declares`, name, node: e.to });
      for (const o of lock.orphans) flake.warnings.push({ kind: 'orphan-lock-node', detail: `lock node ${o} is not reachable from the root`, node: o });
    }
    flake.graph = { root: lock.root || null, nodes: lock.nodes.map((n) => ({ ...n, warnings: warningsFor(n) })), edges: lock.edges, cycles: lock.cycles, dangling: lock.dangling, orphans: lock.orphans };
    out.flakes.push(flake);
    // components: reachable lock nodes (source dependencies), de-duplicated by node key
    const flakeProvider = flake.declared.find((d) => d.name === 'nixpkgs') || null;
    for (const n of flake.graph.nodes) if (!n.root && n.reachable) out.components.push({ componentClass: 'input', kind: 'source-dependency', name: n.name, node: n.key, flake: n.flake, fetch: n.locked, original: n.original, resolution: n.resolution, flakeFile: ff, warnings: n.warnings, version: null, versionResolved: false });
    flake._provider = flakeProvider ? { name: flakeProvider.name, rev: flakeProvider.lockedFetch && flakeProvider.lockedFetch.rev, ref: flakeProvider.originalFetch && flakeProvider.originalFetch.ref } : null;
  }
  for (const p of Object.keys(files)) if (/(^|\/)flake\.lock$/.test(p) && !lockOwners.has(p)) out.gaps.push({ kind: 'lock-without-flake', file: p, detail: 'flake.lock has no flake.nix next to it; its inputs are listed without declarations' });
  // legacy forms and package selectors from every Nix source
  const provider = out.flakes.length && out.flakes[0]._provider ? out.flakes[0]._provider : null;
  for (const f of Object.keys(files).filter((p) => /\.nix$/i.test(p)).sort()) {
    const r = collectLegacyAndSelectors(f, files[f], provider);
    out.legacy.push(...r.legacy); out.selectors.push(...r.selectors);
  }
  for (const f of out.flakes) delete f._provider;
  for (const s of out.selectors) out.components.push({ ...s });
  out.coverage = { flakes: out.flakes.length, locks: out.flakes.filter((f) => f.lock && f.lock.status === 'ok').length, inputs: out.components.filter((c) => c.componentClass === 'input').length, selectors: out.selectors.length, legacy: out.legacy.length };
  return redactUrlsDeep(out);
}
