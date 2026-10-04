// Nix interpolation and embedded-shell taint (NIX-003).
//
// A Nix string that becomes a shell script is two languages stacked: Nix decides what text is produced,
// the shell decides what that text does. This module keeps the boundary explicit:
//
//   * The Nix string is DECODED into the exact generated script (escapes resolved, indentation stripped),
//     with one placeholder (U+FFFC) per `${...}` interpolation and a per-character map back to the original
//     Nix source offsets. A literal `''${HOME}` is therefore shell text (a shell expansion), never a Nix
//     interpolation, and `${name}` is a Nix interpolation, never shell text.
//   * The generated script is lexed as shell: quoting state at every placeholder (unquoted, "...", '...',
//     heredoc, command substitution, comment), the command it is an argument of and its sink class.
//   * Each interpolated expression is resolved through let bindings, function parameters, selects, imported
//     helper files and small helper lambdas to a set of ORIGINS: configuration, attacker (environment,
//     files and fetched content outside the repository), argument, secret, store path, constant. Origins
//     stay distinct all the way to the finding; configuration is never promoted to attacker.
//   * Protection is judged in context: escapeShellArg(s) neutralises a value only in an UNQUOTED position;
//     inside "..." or '...' it is a wrong-context escape and is reported as such.
//
// Static only: nothing here evaluates Nix, runs a shell or touches the network. Scripts in a shell or
// language that is not modelled are listed as coverage gaps and never reported as analyzed.

import { parseNix, makeLocator } from './nix-parser.js';
import { resolveImportPath } from './nix-ir.js';
import { isLanguageExcludedPath } from './discovery.js';

export const NIX_SCRIPT_VERSION = 'nix-script-taint/1';
const PH = '￼';
const MAX_DEPTH = 24;

// ── where shell lives ────────────────────────────────────────────────────────
const SHELL_ATTRS = new Set(['script', 'preStart', 'postStart', 'preStop', 'postStop', 'reload', 'buildPhase', 'installPhase', 'configurePhase', 'checkPhase', 'unpackPhase', 'patchPhase', 'fixupPhase', 'installCheckPhase', 'distPhase', 'postInstall', 'preInstall', 'postBuild', 'preBuild', 'postPatch', 'prePatch', 'postConfigure', 'preConfigure', 'postUnpack', 'preUnpack', 'postFixup', 'preFixup', 'postCheck', 'preCheck', 'shellHook', 'buildCommand', 'extraCommands', 'postDeviceCommands', 'preDeviceCommands', 'shellInit', 'interactiveShellInit', 'loginShellInit', 'promptInit', 'setup', 'userSetup']);
const SHELL_BUILDERS = new Map([
  ['writeShellScript', { shell: 'bash', arg: 1 }], ['writeShellScriptBin', { shell: 'bash', arg: 1 }], ['writeBash', { shell: 'bash', arg: 1 }], ['writeBashBin', { shell: 'bash', arg: 1 }], ['writeDash', { shell: 'dash', arg: 1 }], ['writeDashBin', { shell: 'dash', arg: 1 }],
  ['runCommand', { shell: 'bash', arg: 2 }], ['runCommandLocal', { shell: 'bash', arg: 2 }], ['runCommandNoCC', { shell: 'bash', arg: 2 }], ['runCommandCC', { shell: 'bash', arg: 2 }],
  ['writeScript', { shell: 'shebang', arg: 1 }], ['writeScriptBin', { shell: 'shebang', arg: 1 }],
  ['writeFish', { shell: 'fish', arg: 1 }], ['writeFishBin', { shell: 'fish', arg: 1 }], ['writePython3', { shell: 'python', arg: 1 }], ['writePython3Bin', { shell: 'python', arg: 1 }], ['writePerl', { shell: 'perl', arg: 1 }], ['writeRuby', { shell: 'ruby', arg: 1 }], ['writeJS', { shell: 'node', arg: 1 }], ['writeNu', { shell: 'nushell', arg: 1 }],
]);
const SUPPORTED_SHELLS = new Set(['bash', 'sh', 'dash', 'ash', 'ksh', 'mksh']);
const PROTECT_ONE = new Set(['escapeShellArg']);
const PROTECT_MANY = new Set(['escapeShellArgs']);
const WRONG_ESCAPES = new Set(['escapeRegex', 'escapeXML', 'escapeNixString', 'escapeNixIdentifier', 'escapeURL', 'escapeC', 'escapeSystemdPath', 'escapeSystemdExecArg']);
const PASS_THROUGH = new Set(['toString', 'toLower', 'toUpper', 'removeSuffix', 'removePrefix', 'trim', 'fileContents', 'optionalString', 'concatStringsSep', 'concatMapStringsSep', 'concatStrings', 'replaceStrings', 'substring', 'head', 'elemAt', 'attrValues', 'attrNames', 'toJSON', 'fromJSON', 'importJSON', 'importTOML', 'fromTOML', 'getAttr', 'catAttrs', 'optional', 'optionals', 'flatten', 'filter', 'sort', 'unique', 'mapAttrsToList', 'listToAttrs', 'genList', 'foldl\'', 'foldl', 'concatLists', 'map', 'mkIf', 'mkDefault', 'mkForce', 'mkOverride', 'mkMerge', 'mkBefore', 'mkAfter']);
const TRUSTED_PARAMS = new Set(['pkgs', 'lib', 'stdenv', 'self', 'inputs', 'system', 'modulesPath', 'utils', 'nixpkgs', 'flake-utils', 'callPackage', 'fetchurl', 'fetchFromGitHub', 'fetchgit', 'fetchzip', 'writeShellScript', 'writeShellScriptBin', 'runCommand', 'runCommandLocal', 'makeWrapper', 'bash', 'coreutils', 'systemd', 'writeText', 'writeTextFile', 'buildEnv', 'symlinkJoin', 'mkShell', 'mkDerivation', 'buildGoModule', 'rustPlatform', 'darwin']);
const CONFIG_PARAMS = new Set(['config', 'options', 'osConfig']);
const RUNTIME_SECRET_DIRS = /^\/(?:run\/(?:secrets|agenix|credentials|keys)|var\/lib\/(?:secrets|credentials)|etc\/secrets)\b/;
const SECRET_NAME = /(?:pass(?:word|wd|phrase)?|psk|secret|token|api_?key|private_?key|credential|auth_?key|client_?secret|bearer|cookie|session_?key)/i;
const PATHISH_TAIL = /(?:file|path|dir|directory|package|pkg|enable|port|user|group|name)$/i;
const FETCHERS = new Set(['fetchurl', 'fetchTarball', 'fetchGit', 'fetchzip', 'fetchFromGitHub', 'fetchgit', 'fetchTree', 'fetchClosure', 'fetchMercurial', 'fetchpatch']);
const FS_CMDS = new Set(['rm', 'rmdir', 'mv', 'cp', 'chmod', 'chown', 'chgrp', 'mkdir', 'ln', 'touch', 'tee', 'dd', 'install', 'truncate', 'shred', 'unlink', 'rsync', 'tar', 'unzip', 'cat', 'sed', 'find', 'mount', 'umount']);
const NET_CMDS = new Set(['curl', 'wget', 'nc', 'ncat', 'netcat', 'ssh', 'scp', 'sftp', 'rsync', 'ftp', 'telnet', 'socat', 'git', 'psql', 'mysql', 'redis-cli', 'mongo', 'aws', 'gsutil']);
const EVAL_CMDS = new Set(['eval', 'source', '.', 'exec', 'xargs', 'sudo', 'su', 'doas', 'nohup', 'env', 'timeout', 'watch', 'time', 'nice', 'ionice', 'setsid', 'runuser']);
const SHELLS = new Set(['sh', 'bash', 'dash', 'zsh', 'ksh', 'ash', 'fish']);
const SKIP_WORDS = new Set(['!', 'if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'while', 'until', 'for', 'case', 'esac', 'in', '{', '}', 'function', 'select', 'coproc']);

const baseName = (s) => String(s || '').replace(/^.*\//, '');
const spanOf = (n) => (n && n.span ? n.span : null);

// ── files ────────────────────────────────────────────────────────────────────
class Workspace {
  constructor(files) {
    this.files = files; this.parsed = new Map();
  }
  parse(file) {
    if (this.parsed.has(file)) return this.parsed.get(file);
    const text = this.files[file];
    let rec = null;
    if (typeof text === 'string') {
      const p = parseNix(text, { file });
      rec = { file, text, parse: p, ast: p.ast, loc: makeLocator(text) };
    }
    this.parsed.set(file, rec);
    return rec;
  }
}

// ── lexical environments and value resolution ────────────────────────────────
const unparen = (n) => { let x = n; while (x && x.type === 'paren') x = x.expr; return x; };
const mkEnv = (parent, vars, withs, file) => ({ parent, vars, withs: withs || [], file });
const lookup = (env, name) => { for (let e = env; e; e = e.parent) if (e.vars.has(name)) return { b: e.vars.get(name), env: e }; return null; };
const withsOf = (env) => { const out = []; for (let e = env; e; e = e.parent) out.push(...e.withs); return out; };
const segName = (s) => (s && s.kind === 'static' ? s.name : null);
const attrKey = (path) => path.map(segName);

function bindingsEnv(node, env, file) {
  const vars = new Map();
  for (const b of node.bindings || []) {
    if (b.kind === 'attr') {
      const k = attrKey(b.path);
      if (k.length && k.every((x) => x !== null)) {
        // nested attr paths: a.b.c = v  ->  register a as a synthetic attrset by path
        if (k.length === 1) vars.set(k[0], { kind: 'bind', value: b.value, span: b.span, file });
        else {
          const head = k[0];
          const cur = vars.get(head);
          const entry = cur && cur.kind === 'pathset' ? cur : { kind: 'pathset', paths: [], span: b.span, file };
          entry.paths.push({ path: k.slice(1), value: b.value, span: b.span });
          vars.set(head, entry);
        }
      }
    } else if (b.kind === 'inherit') {
      for (const nm of b.names || []) {
        const name = segName(nm);
        if (name) vars.set(name, { kind: 'inherit', from: b.from, span: nm.span || b.span, file, name });
      }
    }
  }
  return vars;
}

/** Look up a static attribute path in an attrset node; returns {value, span} or null. */
function attrIn(node, path) {
  if (!node || node.type !== 'attrset') return null;
  for (const b of node.bindings || []) {
    if (b.kind !== 'attr') continue;
    const k = attrKey(b.path);
    if (k.some((x) => x === null)) continue;
    if (k.length <= path.length && k.every((x, i) => x === path[i])) {
      const rest = path.slice(k.length);
      if (!rest.length) return { value: b.value, span: b.span };
      const inner = attrIn(unparen(b.value), rest);
      if (inner) return inner;
    }
  }
  return null;
}

class Resolver {
  constructor(ws) { this.ws = ws; this.cycle = new Set(); }

  /** File top-level expression with module/function formals bound by name. */
  fileTop(file) {
    const rec = this.ws.parse(file);
    if (!rec || !rec.ast) return null;
    let node = unparen(rec.ast);
    let env = mkEnv(null, new Map(), [], file);
    while (node && node.type === 'lambda') {
      const vars = new Map();
      if (node.param.kind === 'pattern') for (const f of node.param.formals) vars.set(f.name, { kind: 'param', name: f.name, span: f.span, file, def: f.default });
      else if (node.param.name) vars.set(node.param.name, { kind: 'param', name: node.param.name, span: node.span, file });
      if (node.param.atName) vars.set(node.param.atName, { kind: 'param', name: node.param.atName, span: node.span, file });
      env = mkEnv(env, vars, [], file);
      node = unparen(node.body);
    }
    return { node, env, file, rec };
  }

  /** Follow identifiers/selects/imports to a node. Returns {node, env, file, hops} (node may be non-static). */
  deref(expr, env, hops = [], depth = 0) {
    const n = unparen(expr);
    if (!n || depth > MAX_DEPTH) return { node: n, env, hops, partial: true };
    if (n.type === 'ident') {
      const f = lookup(env, n.name);
      if (!f) return { node: n, env, hops, free: true };
      const b = f.b;
      if (b.kind === 'bind') {
        const key = `${b.file}:${b.span && b.span.startOffset}`;
        if (this.cycle.has(key)) return { node: n, env, hops, partial: true };
        this.cycle.add(key);
        try { return this.deref(b.value, b.argEnv || f.env, [...hops, { file: b.file, span: b.span, label: `let ${n.name}` }], depth + 1); } finally { this.cycle.delete(key); }
      }
      if (b.kind === 'inherit') {
        if (b.from) { const base = this.deref(b.from, f.env, hops, depth + 1); return this.selectFrom(base, [b.name], hops, depth + 1); }
        const outer = f.env.parent ? lookup(f.env.parent, b.name) : null;
        if (outer) return this.deref({ type: 'ident', name: b.name, span: b.span }, f.env.parent, [...hops, { file: b.file, span: b.span, label: `inherit ${b.name}` }], depth + 1);
        return { node: n, env, hops, free: true };
      }
      if (b.kind === 'pathset') return { node: { type: 'attrset', bindings: b.paths.map((p) => ({ kind: 'attr', path: p.path.map((name) => ({ kind: 'static', name })), value: p.value, span: p.span })), span: b.span }, env: f.env, hops, file: b.file };
      if (b.kind === 'param') return { node: n, env, hops: [...hops, { file: b.file, span: b.span, label: `parameter ${b.name}` }], param: b };
      return { node: n, env, hops };
    }
    if (n.type === 'select') {
      const base = this.deref(n.base, env, hops, depth + 1);
      const path = n.attrpath.map(segName);
      if (path.some((x) => x === null)) return { node: n, env, hops, partial: true };
      return this.selectFrom(base, path, hops, depth + 1, n);
    }
    if (n.type === 'app') {
      const fn = unparen(n.fn);
      if (fn && fn.type === 'ident' && fn.name === 'import') {
        const arg = unparen(n.arg);
        const lit = arg && (arg.type === 'path' || arg.type === 'string') && !arg.interpolated ? arg.literal : null;
        const target = lit ? resolveImportPath(env.file, /\.nix$/.test(lit) || /\/$/.test(lit) ? lit : `${lit}`) : null;
        const cand = target ? [target, `${target.replace(/\/$/, '')}/default.nix`].find((c) => typeof this.ws.files[c] === 'string') : null;
        if (cand) { const top = this.fileTop(cand); if (top) return { ...top, hops: [...hops, { file: cand, span: spanOf(top.node), label: `import ${lit}` }], imported: cand }; }
        return { node: n, env, hops, unresolvedImport: lit || true };
      }
      // `import ./f.nix { ... }` : apply
      const inner = fn && fn.type === 'app' ? this.deref(fn, env, hops, depth + 1) : null;
      if (inner && inner.imported && inner.node && inner.node.type !== 'lambda') return inner;
    }
    return { node: n, env, hops, file: env && env.file };
  }

  selectFrom(base, path, hops, depth, orig) {
    const node = unparen(base.node);
    if (node && node.type === 'attrset') {
      const hit = attrIn(node, path);
      if (hit) return this.deref(hit.value, base.env, [...base.hops, { file: base.file || (base.env && base.env.file), span: hit.span, label: path.join('.') }], depth + 1);
    }
    return { node: orig || node, env: base.env, hops: base.hops, selected: path, base, partial: true };
  }
}

// ── origins ──────────────────────────────────────────────────────────────────
const SAFE_KINDS = new Set(['constant', 'store']);
const mkOrigin = (kind, detail, chain) => ({ kind, detail, chain: chain || [] });
const dedupe = (list) => { const seen = new Set(); const out = []; for (const o of list) { const k = `${o.kind}|${o.detail}`; if (!seen.has(k)) { seen.add(k); out.push(o); } } return out; };
const hop = (file, span, label, kind = 'nix') => (span ? { file, line: span.startLine, column: span.startColumn, endLine: span.endLine, endColumn: span.endColumn, label, kind } : null);

class Evaluator {
  constructor(res) { this.res = res; this.seen = new Set(); }

  combine(parts) {
    const origins = dedupe(parts.flatMap((p) => p.origins));
    const risky = parts.filter((p) => p.origins.some((o) => !SAFE_KINDS.has(o.kind)));
    const protection = risky.length && risky.every((p) => p.protection) ? risky[0].protection : null;
    const wrong = parts.map((p) => p.wrongEscape).find(Boolean) || null;
    return { origins, protection, wrongEscape: wrong };
  }
  constant(detail = 'literal') { return { origins: [mkOrigin('constant', detail)], protection: null }; }
  unknown(detail) { return { origins: [mkOrigin('unknown', detail)], protection: null }; }

  paramOrigin(name, b, withHops) {
    const hops = withHops || [];
    if (CONFIG_PARAMS.has(name)) return { origins: [mkOrigin('configuration', `module parameter ${name}`, hops)], protection: null };
    if (TRUSTED_PARAMS.has(name)) return { origins: [mkOrigin('store', `trusted parameter ${name}`, hops)], protection: null };
    return { origins: [mkOrigin('argument', `function argument "${name}"`, hops)], protection: null };
  }

  eval(expr, env, depth = 0) {
    const n = unparen(expr);
    if (!n || depth > MAX_DEPTH) return this.unknown('depth limit');
    switch (n.type) {
      case 'string': {
        if (!n.interpolated) return this.constant('string literal');
        const parts = [this.constant('string text')];
        for (const p of n.parts) if (p.kind === 'interp') parts.push(this.eval(p.expr, env, depth + 1));
        return this.combine(parts);
      }
      case 'path': return n.interpolated ? this.unknown('interpolated path') : this.constant('path literal');
      case 'ident': return this.evalIdent(n, env, depth);
      case 'select': return this.evalSelect(n, env, depth);
      case 'app': return this.evalApp(n, env, depth);
      case 'binop': return this.combine([this.eval(n.left, env, depth + 1), this.eval(n.right, env, depth + 1)]);
      case 'if': return this.combine([this.eval(n.then, env, depth + 1), this.eval(n.else, env, depth + 1)]);
      case 'list': return n.items.length ? this.combine(n.items.map((i) => this.eval(i, env, depth + 1))) : this.constant('empty list');
      case 'attrset': return this.combine((n.bindings || []).filter((b) => b.kind === 'attr' && b.value).map((b) => this.eval(b.value, env, depth + 1)).concat([this.constant('attrset')]));
      case 'let': { const e2 = mkEnv(env, bindingsEnv(n, env, env.file), [], env.file); return this.eval(n.body, e2, depth + 1); }
      case 'with': { const w = this.withName(n.env); const e2 = mkEnv(env, new Map(), [w], env.file); return this.eval(n.body, e2, depth + 1); }
      case 'assert': return this.eval(n.body, env, depth + 1);
      case 'lambda': return this.constant('function');
      case 'unop': case 'hasattr': return this.constant('boolean');
      default: return this.constant(n.type);
    }
  }
  withName(e) { const n = unparen(e); if (n && n.type === 'ident') return n.name; if (n && n.type === 'select') { const b = unparen(n.base); return b && b.type === 'ident' ? b.name : null; } return null; }

  evalIdent(n, env, depth) {
    const f = lookup(env, n.name);
    if (!f) {
      if (n.name === 'null' || n.name === 'true' || n.name === 'false') return this.constant(n.name);
      if (['builtins', 'abort', 'throw', 'toString', 'import', 'derivation', 'map'].includes(n.name)) return this.constant(`builtin ${n.name}`);
      for (const w of withsOf(env)) { if (w === 'pkgs' || w === 'lib' || w === 'builtins') return { origins: [mkOrigin('store', `with ${w}`)], protection: null }; if (w && CONFIG_PARAMS.has(w)) return { origins: [mkOrigin('configuration', `with ${w}`)], protection: null }; }
      return this.unknown(`unresolved name "${n.name}"`);
    }
    const b = f.b;
    const here = hop(b.file, b.span, `${n.name}`);
    if (b.kind === 'param') {
      if (b.def) return this.combine([this.paramOrigin(n.name, b, here ? [here] : []), this.eval(b.def, f.env, depth + 1)]);
      return this.paramOrigin(n.name, b, here ? [here] : []);
    }
    const d = this.res.deref(n, env, []);
    if (d.param) return this.paramOrigin(d.param.name, d.param, d.hops.map((h) => hop(h.file, h.span, h.label)).filter(Boolean));
    if (d.node && d.node !== n) {
      const key = `${b.file}:${b.span && b.span.startOffset}:${n.name}`;
      if (this.seen.has(key)) return this.unknown(`recursive definition of ${n.name}`);
      this.seen.add(key);
      try { return this.withChain(this.eval(d.node, d.env, depth + 1), d.hops); } finally { this.seen.delete(key); }
    }
    return this.unknown(`could not resolve ${n.name}`);
  }
  withChain(r, hops) {
    const hs = (hops || []).map((h) => hop(h.file, h.span, h.label)).filter(Boolean);
    if (!hs.length) return r;
    // data-flow order: the definition (nearest the source) first, the use site last
    return { ...r, origins: r.origins.map((o) => ({ ...o, chain: [...o.chain, ...[...hs].reverse()] })) };
  }

  evalSelect(n, env, depth) {
    const path = n.attrpath.map(segName);
    const root = unparen(n.base);
    if (root && root.type === 'ident') {
      const f = lookup(env, root.name);
      const isParam = f && f.b.kind === 'param';
      if (isParam && CONFIG_PARAMS.has(root.name) && path.every((x) => x !== null)) {
        const full = `${root.name}.${path.join('.')}`;
        const here = hop(f.b.file, spanOf(n), full);
        const last = path[path.length - 1];
        if (SECRET_NAME.test(path.join('.')) && !PATHISH_TAIL.test(last)) return { origins: [mkOrigin('secret', `option ${full}`, here ? [here] : [])], protection: null };
        return { origins: [mkOrigin('configuration', `option ${full}`, here ? [here] : [])], protection: null };
      }
      if ((root.name === 'pkgs' || root.name === 'lib' || root.name === 'builtins') && (!f || isParam)) return { origins: [mkOrigin('store', `${root.name}.${path.filter(Boolean).join('.')}`)], protection: null };
    }
    const d = this.res.deref(n, env, []);
    if (d.param) return this.paramOrigin(d.param.name, d.param, d.hops.map((h) => hop(h.file, h.span, h.label)).filter(Boolean));
    if (d.node && d.node !== n) return this.withChain(this.eval(d.node, d.env, depth + 1), d.hops);
    // select on a value we cannot see through: inherit the base's origins
    const base = this.eval(n.base, env, depth + 1);
    const tail = path.filter(Boolean);
    const d2 = base.origins.some((o) => o.kind === 'configuration')
      ? {
        origins: base.origins.map((o) => {
          if (o.kind !== 'configuration') return o;
          const detail = `${o.detail}.${tail.join('.')}`;
          const last = tail[tail.length - 1] || '';
          const secret = SECRET_NAME.test(tail.join('.')) && !PATHISH_TAIL.test(last);
          return { ...o, kind: secret ? 'secret' : 'configuration', detail };
        }),
        protection: null,
      } : base;
    return d2;
  }

  calleeOf(fn) {
    const n = unparen(fn);
    if (!n) return { name: null, full: null };
    if (n.type === 'ident') return { name: n.name, full: n.name, root: n.name };
    if (n.type === 'select') {
      const segs = n.attrpath.map(segName);
      const root = unparen(n.base);
      const rn = root && root.type === 'ident' ? root.name : null;
      return { name: segs[segs.length - 1], full: `${rn || '?'}.${segs.join('.')}`, root: rn };
    }
    return { name: null, full: null };
  }
  flatten(n) {
    const args = []; let fn = unparen(n);
    while (fn && fn.type === 'app') { args.unshift(fn.arg); fn = unparen(fn.fn); }
    return { fn, args };
  }

  evalApp(n, env, depth) {
    const { fn, args } = this.flatten(n);
    const c = this.calleeOf(fn);
    const name = c.name;
    const argv = (i) => (args[i] !== undefined ? this.eval(args[i], env, depth + 1) : this.constant('missing'));
    if (name && PROTECT_ONE.has(name)) { const r = argv(0); return { ...r, protection: 'escapeShellArg', protectionName: name }; }
    if (name && PROTECT_MANY.has(name)) { const r = argv(0); return { ...r, protection: 'escapeShellArgs', protectionName: name }; }
    if (name && WRONG_ESCAPES.has(name)) { const r = argv(0); return { ...r, wrongEscape: name }; }
    if (c.full === 'builtins.getEnv' || name === 'getEnv') return { origins: [mkOrigin('attacker', 'environment variable read at evaluation time (builtins.getEnv)')], protection: null };
    if (name === 'readFile' || name === 'fileContents' || name === 'readFileType') return this.evalReadFile(args[0], env, depth);
    if (c.full && /^(?:builtins\.)?(?:fetch\w+)$/.test(c.full) || (name && FETCHERS.has(name))) return { origins: [mkOrigin('store', `fetched source (${name})`)], protection: null };
    if (name === 'map' || name === 'concatMap' || name === 'mapAttrsToList' || name === 'concatMapStringsSep') {
      const fIdx = name === 'concatMapStringsSep' ? 1 : 0;
      const f = args[fIdx] ? this.calleeOf(args[fIdx]) : { name: null };
      const rest = args.map((a, i) => (i === fIdx ? null : this.eval(a, env, depth + 1))).filter(Boolean);
      const r = rest.length ? this.combine(rest) : this.constant('empty');
      if (f.name && (PROTECT_ONE.has(f.name) || PROTECT_MANY.has(f.name))) return { ...r, protection: 'escapeShellArgs' };
      return r;
    }
    if (name === 'concatStringsSep' || name === 'concatStrings') {
      const parts = args.map((a) => this.eval(a, env, depth + 1));
      const sep = parts[0]; const rest = parts.slice(1);
      const r = rest.length ? this.combine(rest) : this.constant('empty');
      return { ...r, origins: dedupe([...(sep ? sep.origins : []), ...r.origins]) };
    }
    if (name === 'optionalString' || name === 'optional' || name === 'optionals') return args[1] ? this.eval(args[1], env, depth + 1) : this.constant('empty');
    if (name === 'getExe' || name === 'getBin' || name === 'getLib' || name === 'getDev' || name === 'getExe\'') return { origins: [mkOrigin('store', `${name} (store path)`)], protection: null };
    if (name === 'writeText' || name === 'writeTextFile' || name === 'writeShellScript' || name === 'writeShellScriptBin' || name === 'writeScript' || name === 'writeScriptBin' || name === 'runCommand' || name === 'mkDerivation') return { origins: [mkOrigin('store', `${name} output (store path)`)], protection: null };
    // user helper: lambda or an identifier bound to one (possibly imported from another file)
    const helper = this.helperLambda(fn, env);
    if (helper) return this.applyHelper(helper, args, env, depth);
    if (name && PASS_THROUGH.has(name)) return args.length ? this.combine(args.map((a) => this.eval(a, env, depth + 1))) : this.constant('empty');
    // unknown function: its result depends on its arguments; the function itself is not evidence
    const parts = args.map((a) => this.eval(a, env, depth + 1));
    const r = parts.length ? this.combine(parts) : this.constant('call');
    if (name && !r.origins.every((o) => SAFE_KINDS.has(o.kind))) r.origins = dedupe([...r.origins, mkOrigin('unknown', `result of ${c.full || name} (not modelled)`)]);
    return { ...r, protection: null };
  }

  helperLambda(fn, env) {
    const d = this.res.deref(fn, env, []);
    const node = unparen(d.node);
    if (node && node.type === 'lambda' && !d.partial) return { lambda: node, env: d.env, hops: d.hops };
    return null;
  }
  applyHelper(h, args, env, depth) {
    let node = h.lambda; let e = h.env; let i = 0;
    while (node && node.type === 'lambda' && i < args.length) {
      const vars = new Map();
      if (node.param.kind === 'pattern') {
        const a = unparen(args[i]);
        for (const f of node.param.formals) {
          const hit = a && a.type === 'attrset' ? attrIn(a, [f.name]) : null;
          vars.set(f.name, hit ? { kind: 'bind', value: hit.value, span: hit.span, file: env.file, argEnv: env } : { kind: 'param', name: f.name, span: f.span, file: e.file, def: f.default });
        }
      } else if (node.param.name) vars.set(node.param.name, { kind: 'bind', value: args[i], span: spanOf(args[i]), file: env.file, argEnv: env });
      e = mkEnv(e, vars, [], e.file);
      node = unparen(node.body); i++;
    }
    if (!node) return this.unknown('helper body');
    if (node.type === 'lambda') return this.constant('partially applied function');
    // arguments are evaluated in the CALLER's scope: wrap bind values so idents resolve there
    const r = this.eval(node, e, depth + 1);
    return this.withChain(r, h.hops);
  }
  /** A path that only exists decrypted at RUNTIME (sops-nix / agenix / systemd credentials / conventional secret dirs). */
  runtimeSecretPath(arg, env) {
    const d = this.res.deref(arg, env, []);
    const n = unparen(d.node);
    const lit = n && (n.type === 'string' || n.type === 'path') && !n.interpolated ? n.literal : null;
    if (lit && RUNTIME_SECRET_DIRS.test(lit)) return lit;
    const target = d.node === n && n && n.type === 'select' ? n : null;
    const sel = n && n.type === 'select' ? n : unparen(arg);
    if (sel && sel.type === 'select') {
      const base = unparen(sel.base); const segs = sel.attrpath.map(segName);
      const root = base && base.type === 'ident' ? base.name : null;
      if (root && CONFIG_PARAMS.has(root) && segs.every((x) => x !== null) && /^(sops|age|agenix)$/.test(segs[0]) && segs.includes('secrets') && segs[segs.length - 1] === 'path') return `config.${segs.join('.')}`;
    }
    void target;
    return null;
  }

  evalReadFile(arg, env, depth) {
    if (!arg) return this.unknown('readFile');
    const d = this.res.deref(arg, env, []);
    const node = unparen(d.node);
    const ao = this.eval(arg, env, depth + 1);
    const rp = this.runtimeSecretPath(arg, env);
    if (rp) return { origins: [mkOrigin('secret', `decrypted secret copied at evaluation time (${rp})`, [hop(env.file, spanOf(unparen(arg)), 'readFile of a runtime secret path')].filter(Boolean))], protection: null, decryptCopy: true };
    if (ao.origins.some((o) => o.kind === 'secret')) return { origins: [mkOrigin('secret', 'file content read at evaluation time (path derives from a secret option)')], protection: null };
    if (node && node.type === 'path' && !node.interpolated && !String(node.literal).startsWith('/')) return { origins: [mkOrigin('configuration', `repository file ${node.literal}`, (d.hops || []).map((h) => hop(h.file, h.span, h.label)).filter(Boolean))], protection: null };
    if (node && node.type === 'app') { const c = this.calleeOf(this.flatten(node).fn); if (c.name && FETCHERS.has(c.name)) return { origins: [mkOrigin('attacker', `content fetched from the network (${c.name}) and read at evaluation time`)], protection: null }; }
    return { origins: [mkOrigin('attacker', 'file content read at evaluation time from a path outside the repository')], protection: null };
  }
}

// ── string decoding: generated script + source map ───────────────────────────
function decodeString(rec, node) {
  const src = rec.text;
  const indented = !!node.indented;
  const d = indented ? 2 : 1;
  const chars = []; // {ch, src, ph?}
  const interps = [];
  const parts = node.parts;
  // raw boundaries of text parts
  let cursor = node.start + d;
  const raws = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (p.kind === 'interp') {
      const open = src.lastIndexOf('${', p.expr.start);
      let close = src.indexOf('}', p.expr.end);
      if (close < 0) close = p.expr.end;
      raws.push({ part: p, rawStart: open < 0 ? p.expr.start : open, rawEnd: close + 1 });
    } else raws.push({ part: p, rawStart: null, rawEnd: null });
  }
  for (let i = 0; i < raws.length; i++) {
    const r = raws[i];
    if (r.part.kind === 'interp') { cursor = r.rawEnd; continue; }
    const next = raws.slice(i + 1).find((x) => x.part.kind === 'interp');
    const end = next ? next.rawStart : node.end - d;
    r.rawStart = cursor; r.rawEnd = end;
  }
  let approximate = false;
  // Pre-strip decoded characters with source offsets (escapes resolved).
  const pre = [];
  for (const r of raws) {
    if (r.part.kind === 'interp') {
      const idx = interps.length;
      interps.push({ expr: r.part.expr, rawStart: r.rawStart, rawEnd: r.rawEnd, span: r.part.expr.span || rec.loc.span(r.part.expr.start, r.part.expr.end), index: idx });
      pre.push({ ch: PH, src: r.rawStart, srcEnd: r.rawEnd, ph: idx });
      continue;
    }
    const raw = src.slice(r.rawStart, r.rawEnd);
    for (let i = 0; i < raw.length;) {
      const c = raw[i];
      if (indented) {
        if (c === "'" && raw[i + 1] === "'" && raw[i + 2] === '$') { pre.push({ ch: '$', src: r.rawStart + i, srcEnd: r.rawStart + i + 3 }); i += 3; continue; }
        if (c === "'" && raw[i + 1] === "'" && raw[i + 2] === "'") { pre.push({ ch: "'", src: r.rawStart + i, srcEnd: r.rawStart + i + 3 }, { ch: "'", src: r.rawStart + i, srcEnd: r.rawStart + i + 3 }); i += 3; continue; }
        if (c === "'" && raw[i + 1] === "'" && raw[i + 2] === '\\') { const e = raw[i + 3]; pre.push({ ch: e === 'n' ? '\n' : e === 'r' ? '\r' : e === 't' ? '\t' : e, src: r.rawStart + i, srcEnd: r.rawStart + i + 4 }); i += 4; continue; }
      } else if (c === '\\' && i + 1 < raw.length) {
        const e = raw[i + 1]; pre.push({ ch: e === 'n' ? '\n' : e === 'r' ? '\r' : e === 't' ? '\t' : e, src: r.rawStart + i, srcEnd: r.rawStart + i + 2 }); i += 2; continue;
      }
      pre.push({ ch: c, src: r.rawStart + i, srcEnd: r.rawStart + i + 1 }); i++;
    }
  }
  // The parser's text parts are the FINAL generated text (indentation already stripped). Align them with the
  // pre-strip characters: a character is deleted only if it is indentation whitespace.
  const target = [];
  for (const p of parts) { if (p.kind === 'interp') target.push(PH); else for (const ch of p.value) target.push(ch); }
  const out = [];
  let i = 0;
  for (let j = 0; j < target.length; j++) {
    while (i < pre.length && pre[i].ch !== target[j] && /[ \t\n]/.test(pre[i].ch)) i++;
    if (i < pre.length && pre[i].ch === target[j]) { out.push(pre[i]); i++; continue; }
    approximate = true;
    const ref = pre[Math.min(i, pre.length - 1)] || { src: node.start, srcEnd: node.end };
    out.push({ ch: target[j], src: ref.src, srcEnd: ref.srcEnd, approx: true });
  }
  return { chars: out, interps, approximate, indented };
}

const genPos = (text, idx) => { let line = 1; let last = 0; for (let i = 0; i < idx; i++) if (text[i] === '\n') { line++; last = i + 1; } return { line, column: idx - last }; };

// ── shell lexer ──────────────────────────────────────────────────────────────
/**
 * Lex generated shell. Returns placeholder contexts and `$VAR` expansions.
 * context: unquoted | double | single | heredoc-expanding | heredoc-literal | comment | escaped
 */
export function lexShell(text) {
  const phs = []; const exps = []; const cmds = [];
  const stack = [{ m: 'normal' }];
  let cmd = { words: [], start: 0 };
  let word = null;
  const pendingHeredocs = [];
  let i = 0; const n = text.length;
  const top = () => stack[stack.length - 1];
  const startWord = (idx) => { if (!word) { word = { text: '', start: idx, phs: [], exps: [], quoted: false }; cmd.words.push(word); } return word; };
  const endWord = () => { word = null; };
  const endCmd = () => { endWord(); if (cmd.words.length) cmds.push(cmd); cmd = { words: [], start: i }; };
  const ctxName = () => { const t = top(); return t.m === 'dq' ? 'double' : t.m === 'sq' ? 'single' : 'unquoted'; };
  const atWordStart = () => !word;
  while (i < n) {
    const c = text[i]; const t = top();
    if (t.m === 'sq') {
      if (c === "'") { stack.pop(); i++; continue; }
      if (c === PH) { const p = { idx: i, context: 'single', word: startWord(i), cmd }; word.phs.push(p); phs.push(p); word.text += PH; i++; continue; }
      startWord(i).text += c; i++; continue;
    }
    if (t.m === 'dq') {
      if (c === '\\' && i + 1 < n) { startWord(i).text += text[i + 1] === PH ? PH : c + text[i + 1]; if (text[i + 1] === PH) { const p = { idx: i + 1, context: 'double', escaped: true, word: word, cmd }; word.phs.push(p); phs.push(p); } i += 2; continue; }
      if (c === '"') { stack.pop(); i++; continue; }
      if (c === '`') { stack.push({ m: 'bt' }); i++; continue; }
      if (c === '$' && text[i + 1] === '(') { stack.push({ m: 'cmdsub', depth: 1 }); i += 2; continue; }
      if (c === PH) { const p = { idx: i, context: 'double', word: startWord(i), cmd }; word.phs.push(p); phs.push(p); word.text += PH; i++; continue; }
      if (c === '$') { const m = /^\$(?:\{([A-Za-z_]\w*)[^}]*\}|([A-Za-z_]\w*)|(\d|[@*?#!$-]))/.exec(text.slice(i)); if (m) { const e = { name: m[1] || m[2] || m[3], idx: i, end: i + m[0].length, context: 'double', word: startWord(i), cmd }; word.exps.push(e); exps.push(e); word.text += m[0]; i += m[0].length; continue; } }
      startWord(i).text += c; i++; continue;
    }
    // normal / cmdsub / backtick
    if (c === '\\' && i + 1 < n) { if (text[i + 1] === '\n') { i += 2; continue; } const w = startWord(i); w.text += text[i + 1] === PH ? PH : text[i + 1]; if (text[i + 1] === PH) { const p = { idx: i + 1, context: 'unquoted', escaped: true, word: w, cmd }; w.phs.push(p); phs.push(p); } i += 2; continue; }
    if (c === "'") { startWord(i).quoted = true; stack.push({ m: 'sq' }); i++; continue; }
    if (c === '"') { startWord(i).quoted = true; stack.push({ m: 'dq' }); i++; continue; }
    if (c === '`') { if (t.m === 'bt') { stack.pop(); } else stack.push({ m: 'bt' }); i++; continue; }
    if (c === '$' && text[i + 1] === '(' ) { stack.push({ m: 'cmdsub', depth: 1 }); startWord(i); i += 2; continue; }
    if (t.m === 'cmdsub') { if (c === '(') t.depth++; else if (c === ')') { t.depth--; if (t.depth === 0) { stack.pop(); i++; continue; } } }
    if (c === '#' && atWordStart()) { let j = i; while (j < n && text[j] !== '\n') { if (text[j] === PH) phs.push({ idx: j, context: 'comment', word: null, cmd }); j++; } i = j; continue; }
    if (c === '<' && text[i + 1] === '<' && text[i + 2] !== '<') {
      const m = /^<<(-?)\s*(?:'([^']*)'|"([^"]*)"|\\?([A-Za-z_][\w.-]*))/.exec(text.slice(i));
      if (m) { pendingHeredocs.push({ strip: !!m[1], delim: m[2] ?? m[3] ?? m[4], quoted: m[2] !== undefined || m[3] !== undefined || text[i + 2 + (m[1] ? 1 : 0)] === '\\' }); i += m[0].length; continue; }
    }
    if (c === '\n') {
      endCmd();
      i++;
      while (pendingHeredocs.length) {
        const h = pendingHeredocs.shift();
        for (;;) {
          if (i >= n) break;
          let e = text.indexOf('\n', i); if (e < 0) e = n;
          const line = text.slice(i, e);
          if ((h.strip ? line.replace(/^\t+/, '') : line) === h.delim) { i = e + 1; break; }
          for (let j = i; j < e; j++) {
            if (text[j] === PH) phs.push({ idx: j, context: h.quoted ? 'heredoc-literal' : 'heredoc-expanding', word: null, cmd: null });
            else if (!h.quoted && text[j] === '$') { const m = /^\$(?:\{([A-Za-z_]\w*)[^}]*\}|([A-Za-z_]\w*))/.exec(text.slice(j, e)); if (m) exps.push({ name: m[1] || m[2], idx: j, end: j + m[0].length, context: 'heredoc-expanding', word: null, cmd: null }); }
          }
          i = e + 1;
        }
      }
      continue;
    }
    if (c === ' ' || c === '\t' || c === '\r') { endWord(); i++; continue; }
    if (c === ';' || c === '&' || c === '|' || c === '(' || c === ')' || c === '{' && !word || c === '}' && !word) {
      if ((c === '|' || c === '&') && text[i + 1] === c) { endCmd(); i += 2; continue; }
      if (c === '|') { cmd.pipeNext = true; endCmd(); i++; continue; }
      if (c === ';' || c === '&' || c === '(' || c === ')' || c === '{' || c === '}') { endCmd(); i++; continue; }
    }
    if (c === PH) { const p = { idx: i, context: ctxName(), word: startWord(i), cmd }; word.phs.push(p); phs.push(p); word.text += PH; i++; continue; }
    if (c === '$') {
      const m = /^\$(?:\{([A-Za-z_]\w*)[^}]*\}|([A-Za-z_]\w*)|(\d|[@*?#!$-]))/.exec(text.slice(i));
      if (m) { const e = { name: m[1] || m[2] || m[3], idx: i, end: i + m[0].length, context: ctxName(), word: startWord(i), cmd }; word.exps.push(e); exps.push(e); word.text += m[0]; i += m[0].length; continue; }
    }
    startWord(i).text += c; i++;
  }
  endCmd();
  // command naming
  for (const cm of cmds) {
    let k = 0;
    while (k < cm.words.length && (/^[A-Za-z_]\w*=/.test(cm.words[k].text) || SKIP_WORDS.has(cm.words[k].text))) k++;
    cm.nameIdx = k;
    cm.name = k < cm.words.length && !cm.words[k].phs.length ? baseName(cm.words[k].text) : null;
    cm.nameWord = cm.words[k] || null;
  }
  return { phs, exps, cmds };
}

function sinkOf(cm, wordIdx) {
  if (!cm || cm.name === null) return { kind: 'argument', command: null };
  const name = cm.name;
  if (wordIdx === cm.nameIdx) return { kind: 'command-position', command: name === PH ? null : name };
  if (EVAL_CMDS.has(name)) return { kind: 'eval', command: name };
  if (SHELLS.has(name) && cm.words.some((w, j) => j > cm.nameIdx && /^-\w*c\w*$/.test(w.text))) return { kind: 'eval', command: `${name} -c` };
  if (FS_CMDS.has(name)) return { kind: 'filesystem', command: name };
  if (NET_CMDS.has(name)) return { kind: 'network', command: name };
  return { kind: 'argument', command: name };
}

// ── script sites ─────────────────────────────────────────────────────────────
function shebangOf(chars) {
  const first = chars.slice(0, 200).map((c) => c.ch).join('').split('\n')[0];
  if (!/^#!/.test(first)) return null;
  const t = first.replace(/^#!\s*/, '').replace(new RegExp(PH, 'g'), '').trim().split(/\s+/);
  let prog = baseName(t[0]);
  if (prog === 'env') prog = baseName(t.slice(1).find((x) => !x.startsWith('-')) || '');
  return prog || baseName(first.replace(/^#!/, '').trim());
}

function collectSites(ws, file) {
  const rec = ws.parse(file);
  if (!rec || !rec.ast) return { sites: [], gaps: [] };
  const sites = []; const gaps = [];
  const res = new Resolver(ws);
  const visit = (node, env, attrPath, parent, depth, asFn = false) => {
    if (!node || typeof node !== 'object' || depth > 200) return;
    switch (node.type) {
      case 'lambda': {
        const vars = new Map();
        if (node.param.kind === 'pattern') for (const f of node.param.formals) vars.set(f.name, { kind: 'param', name: f.name, span: f.span, file, def: f.default });
        else if (node.param.name) vars.set(node.param.name, { kind: 'param', name: node.param.name, span: node.span, file });
        if (node.param.atName) vars.set(node.param.atName, { kind: 'param', name: node.param.atName, span: node.span, file });
        visit(node.body, mkEnv(env, vars, [], file), attrPath, node, depth + 1);
        return;
      }
      case 'let': {
        const e2 = mkEnv(env, bindingsEnv(node, env, file), [], file);
        for (const b of node.bindings) if (b.kind === 'attr') visit(b.value, e2, [], node, depth + 1);
        visit(node.body, e2, attrPath, node, depth + 1);
        return;
      }
      case 'with': { visit(node.env, env, attrPath, node, depth + 1); visit(node.body, mkEnv(env, new Map(), [new Evaluator(res).withName(node.env)], file), attrPath, node, depth + 1); return; }
      case 'attrset': {
        const e2 = node.rec ? mkEnv(env, bindingsEnv(node, env, file), [], file) : env;
        for (const b of node.bindings) {
          if (b.kind !== 'attr' || !b.value) continue;
          const key = attrKey(b.path);
          const full = [...attrPath, ...key];
          const last = key[key.length - 1];
          const v = unparen(b.value);
          // `environment.etc."run.sh".text` (a name that says shell, or a shebang line) is a generated script file as well
          const etcAt = full.indexOf('etc');
          const etcScript = last === 'text' && etcAt >= 0 && etcAt < full.length - 2
            && (/\.(?:sh|bash)$/i.test(String(full[etcAt + 1] || '')) || (v && v.type === 'string' && v.parts && v.parts[0] && v.parts[0].kind === 'text' && /^#!\s*(?:\/\S*\/)?(?:env\s+)?(?:ba|da|z|k|a)?sh\b/.test(String(v.parts[0].value))));
          const hasWritten = SHELL_ATTRS.has(last) || (last === 'text' && full.some((s) => s === 'activationScripts' || s === 'writeShellApplication')) || etcScript;
          if (hasWritten) {
            if (v && v.type === 'string') sites.push({ node: v, env: e2, path: full, kind: 'attr', parentAttrset: node, bindingSpan: b.span, shell: 'bash' });
            else if (v && v.type === 'ident') { const d = res.deref(v, e2, []); if (d.node && d.node.type === 'string') sites.push({ node: d.node, env: d.env, path: full, kind: 'attr-via-binding', parentAttrset: node, bindingSpan: b.span, shell: 'bash', fileOverride: d.file }); else gaps.push({ kind: 'script-not-analyzable', file, line: b.span.startLine, detail: `${full.join('.')} is not a string literal Nix can be read statically (${v.type})` }); }
            else if (v && v.type !== 'lambda' && !(v.type === 'attrset')) gaps.push({ kind: 'script-not-analyzable', file, line: b.span ? b.span.startLine : 1, detail: `${full.join('.')} is built by an expression (${v.type}); only string literals are analyzed` });
          }
          visit(b.value, e2, full, node, depth + 1);
        }
        return;
      }
      case 'app': {
        const ev = new Evaluator(res);
        const { fn, args } = ev.flatten(node);
        const c = ev.calleeOf(fn);
        const b = !asFn && c.name && SHELL_BUILDERS.get(c.name);
        if (b && args.length >= b.arg) {
          // the script is the LAST argument (some writers take an options attrset before it)
          const a = unparen(args[args.length - 1]);
          if (a && a.type === 'string') sites.push({ node: a, env, path: [c.name], kind: 'builder', builder: c.name, parentAttrset: null, bindingSpan: a.span, shell: b.shell });
          else if (args.length >= b.arg + 1) gaps.push({ kind: 'script-not-analyzable', file, line: (a && a.span && a.span.startLine) || 1, detail: `${c.name} script is built by an expression (${a && a.type}); only string literals are analyzed` });
        }
        if (!asFn && c.name === 'writeShellApplication') {
          const arg = unparen(args[0]);
          const hit = arg && arg.type === 'attrset' ? attrIn(arg, ['text']) : null;
          const tv = hit && unparen(hit.value);
          if (tv && tv.type === 'string') sites.push({ node: tv, env, path: [c.name, 'text'], kind: 'builder', builder: c.name, parentAttrset: arg, bindingSpan: hit.span, shell: 'bash' });
        }
        visit(node.fn, env, attrPath, node, depth + 1, true); visit(node.arg, env, attrPath, node, depth + 1);
        return;
      }
      default: {
        for (const k of ['left', 'right', 'operand', 'expr', 'cond', 'then', 'else', 'body', 'base']) if (node[k] && typeof node[k] === 'object') visit(node[k], env, attrPath, node, depth + 1);
        if (node.items) for (const it of node.items) visit(it, env, attrPath, node, depth + 1);
      }
    }
  };
  visit(rec.ast, mkEnv(null, new Map(), [], file), [], null, 0);
  // an attr string that is ALSO inside a builder app can be reported twice: de-duplicate by node start
  const seen = new Set(); const uniq = [];
  for (const s of sites) { const k = `${s.fileOverride || file}:${s.node.start}`; if (!seen.has(k)) { seen.add(k); uniq.push(s); } }
  return { sites: uniq, gaps, res };
}

// ── analysis ─────────────────────────────────────────────────────────────────
const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function threatOf(origins) {
  const kinds = new Set(origins.filter((o) => !SAFE_KINDS.has(o.kind)).map((o) => o.kind));
  if (kinds.has('attacker')) return 'attacker';
  if (kinds.has('argument')) return 'argument';
  if (kinds.has('configuration')) return 'configuration';
  if (kinds.has('secret')) return 'secret';
  if (kinds.has('unknown')) return 'unknown';
  return null;
}

const TYPED_TAIL = /\.(?:port|enable\w*|openFirewall|timeout\w*|count|size|level|interval|uid|gid|mode|verbose|debug)$/;
function severityFor(threat, sink, context, origins = []) {
  if (threat === 'configuration' && origins.filter((o) => o.kind === 'configuration').every((o) => TYPED_TAIL.test(o.detail))) return 'low';
  const cmdPos = sink.kind === 'command-position' || sink.kind === 'eval';
  if (threat === 'attacker') return cmdPos ? 'critical' : 'high';
  if (threat === 'argument') return cmdPos ? 'high' : 'medium';
  if (threat === 'configuration') return cmdPos ? 'medium' : 'medium';
  if (threat === 'secret') return 'low';
  return 'low';
}

const RULES = Object.freeze({
  'nix-shell-injection': { cwe: 'CWE-78', family: 'cmdi', vuln: 'Nix interpolation reaches a shell command unescaped', remediation: 'Wrap the value in lib.escapeShellArg (unquoted position) or pass it as an environment variable and quote the shell expansion.' },
  'nix-escape-wrong-context': { cwe: 'CWE-116', family: 'wrong-context-escape', vuln: 'escapeShellArg used inside quotes (wrong shell context)', remediation: 'lib.escapeShellArg produces its own single quotes: place it in an UNQUOTED position, or drop the surrounding quotes.' },
  'nix-escape-wrong-kind': { cwe: 'CWE-116', family: 'wrong-context-escape', vuln: 'Escaping function does not escape for the shell', remediation: 'Use lib.escapeShellArg / lib.escapeShellArgs for shell words.' },
  'nix-service-env-shell': { cwe: 'CWE-78', family: 'cmdi', vuln: 'Service environment value expanded unquoted in a generated script', remediation: 'Quote the expansion ("$NAME") and validate or escape the value where it is set.' },
  'nix-shell-eval': { cwe: 'CWE-95', family: 'cmdi', vuln: 'Shell evaluates a variable as code in a generated script', remediation: 'Do not eval or `sh -c` a variable; pass arguments directly.' },
  'nix-shell-unquoted-expansion': { cwe: 'CWE-78', family: 'cmdi', vuln: 'Unquoted shell expansion in a destructive command', remediation: 'Quote the expansion ("$VAR") and guard against empty values (${VAR:?}).' },
  'nix-pipe-to-shell': { cwe: 'CWE-494', family: 'download-exec', vuln: 'Network download piped into a shell', remediation: 'Fetch with a pinned hash (fetchurl) and run the result from the store.' },
});

export function analyzeNixScripts(opts = {}) {
  const files = {};
  for (const [p, t] of Object.entries(opts.files || {})) if (typeof t === 'string' && /\.nix$/i.test(p) && !isLanguageExcludedPath(p)) files[p] = t;
  const ws = new Workspace(files);
  const findings = []; const flows = []; const gaps = []; const scripts = [];
  const res = new Resolver(ws);
  const ev = new Evaluator(res);

  for (const file of Object.keys(files).sort()) {
    const rec = ws.parse(file);
    if (!rec || !rec.ast) { gaps.push({ kind: 'parse-failed', file, detail: rec ? `parse status ${rec.parse.status}` : 'unreadable' }); continue; }
    const { sites, gaps: g } = collectSites(ws, file);
    gaps.push(...g);
    for (const site of sites) {
      const sfile = site.fileOverride || file;
      const srec = ws.parse(sfile);
      const dec = decodeString(srec, site.node);
      const text = dec.chars.map((c) => c.ch).join('');
      const shebang = shebangOf(dec.chars);
      const shellName = shebang || (site.shell === 'shebang' ? null : site.shell);
      const loc = (idx0, idx1) => {
        const a = genPos(text, idx0); const b = genPos(text, idx1);
        return { file: sfile, line: a.line, startColumn: a.column, endLine: b.line, endColumn: b.column, generated: true };
      };
      const srcSpanOf = (idx0, idx1) => {
        const first = dec.chars[idx0]; const last = dec.chars[Math.max(idx0, idx1 - 1)];
        if (!first || !last) return null;
        const approx = !!(first.approx || last.approx);
        const s = first.src; const e = Math.max(last.srcEnd, s + 1);
        return { ...srec.loc.span(s, e), approximate: approx };
      };
      const script = { file: sfile, attrPath: site.path.join('.'), kind: site.kind, shell: shellName, generated: text, span: spanOf(site.node), decoded: dec.approximate ? 'approximate' : 'exact', map: (a, b) => srcSpanOf(a, b), placeholders: dec.interps.length };
      scripts.push(script);
      if (shellName && !SUPPORTED_SHELLS.has(shellName)) {
        gaps.push({ kind: SHELLS.has(shellName) ? 'unsupported-shell' : 'unsupported-script-language', file: sfile, line: spanOf(site.node) ? site.node.span.startLine : 1, detail: `${site.path.join('.')} is a ${shellName} script: it is not analyzed (only ${[...SUPPORTED_SHELLS].join('/')} is modelled), so no verdict about it should be read as coverage` });
        continue;
      }
      if (dec.approximate) gaps.push({ kind: 'approximate-location-map', file: sfile, line: site.node.span.startLine, detail: 'escape sequences prevented an exact character map; locations point at the enclosing string segment' });
      const lex = lexShell(text);
      const siteFile = sfile;

      // origins per interpolation
      const originOf = new Map();
      for (const it of dec.interps) {
        const r = ev.eval(it.expr, site.env, 0);
        originOf.set(it.index, r);
      }
      const envMap = collectEnvironment(site, ev);

      const emit = (rule, o) => {
        const R = RULES[rule];
        const f = {
          id: `NIX-SCRIPT-${rule}-${siteFile}:${o.line}:${o.column}`,
          severity: o.severity, file: siteFile, line: o.line, column: o.column, vuln: o.vuln || R.vuln, cwe: R.cwe,
          description: o.description, remediation: o.remediation || R.remediation, parser: 'NIX-SCRIPT', family: R.family, rule,
          language: 'nix', capability: 'sast', analysisKind: 'config', evidenceKind: 'source', confidence: o.confidence ?? 0.8,
          originalLocation: o.originalLocation, generatedLocation: o.generatedLocation, chain: o.chain,
          origins: o.origins.map((x) => ({ kind: x.kind, detail: x.detail })), sink: o.sink, protection: o.protection || null,
          shell: shellName || 'bash', attrPath: script.attrPath,
          bridge: null, applicationFlow: 'not-inferred',
          ...(o.uncertainty ? { uncertainty: o.uncertainty } : {}), ...(o.extra || {}),
        };
        findings.push(f);
        return f;
      };

      for (const p of lex.phs) {
        const it = dec.interps[dec.chars[p.idx].ph];
        const r = originOf.get(it.index);
        const spanNix = it.span;
        const gloc = loc(p.idx, p.idx + 1);
        const sink = sinkOf(p.cmd, p.cmd && p.word ? p.cmd.words.indexOf(p.word) : -1);
        const nextCh = text[p.idx + 1];
        let origins = r.origins;
        // a bare argument/unknown used as a path prefix ("${pkg}/bin/x") is a store path use
        if (nextCh === '/') origins = origins.map((o) => (o.kind === 'argument' || o.kind === 'unknown' ? mkOrigin('store', `${o.detail} used as a path prefix`, o.chain) : o));
        const threat = threatOf(origins);
        const chain = [...originChain(origins), hop(sfile, spanNix, `interpolation \${${srec.text.slice(it.expr.start, it.expr.end).replace(/\s+/g, ' ').slice(0, 60)}}`), { file: sfile, line: gloc.line, column: gloc.startColumn, endLine: gloc.endLine, endColumn: gloc.endColumn, label: `shell ${sink.kind}${sink.command ? ` (${sink.command})` : ''}`, kind: 'shell', generated: true }].filter(Boolean);
        const base = { line: spanNix.startLine, column: spanNix.startColumn, originalLocation: spanNix, generatedLocation: gloc, chain, origins, sink: { ...sink, context: p.context }, protection: r.protection };
        flows.push({ file: sfile, line: spanNix.startLine, origins: origins.map((x) => x.kind), originDetails: origins.map((x) => ({ kind: x.kind, detail: x.detail })), context: p.context, sink, protection: r.protection, protectedInContext: !!r.protection && p.context === 'unquoted', rule: null, originalLocation: spanNix, generatedLocation: gloc, chain, attrPath: site.path.join('.'), scriptHasTrace: /^\s*set\s+-\w*x/m.test(text) });
        if (p.context === 'comment' || p.context === 'heredoc-literal' && !threat) continue;
        if (!threat) continue;
        if (r.wrongEscape) { emit('nix-escape-wrong-kind', { ...base, severity: 'medium', description: `${r.wrongEscape} does not escape for the shell, but the value reaches a shell script (${p.context}).` }); flows[flows.length - 1].rule = 'wrong-kind'; continue; }
        if (r.protection) {
          if (p.context === 'unquoted') { flows[flows.length - 1].rule = 'protected'; continue; }          // correct use
          emit('nix-escape-wrong-context', { ...base, severity: threat === 'attacker' ? 'high' : 'medium', description: `${r.protection} is applied but the interpolation sits ${p.context === 'single' ? "inside single quotes ('...')" : p.context === 'double' ? 'inside double quotes ("...")' : `in a ${p.context} context`}: the escaping adds its own quotes, which breaks out of or is neutralised by the surrounding ones${p.context === 'double' || p.context === 'heredoc-expanding' ? ', and $(...)/backticks are still expanded' : ''}.`, protection: r.protection });
          flows[flows.length - 1].rule = 'wrong-context';
          continue;
        }
        if (threat === 'secret' && p.context !== 'unquoted') continue;   // placement of secrets is NIX-006; here only injection is judged
        const unknownOnly = threat === 'unknown';
        const sev = severityFor(threat, sink, p.context, origins);
        const ctxText = { unquoted: 'unquoted', double: 'inside double quotes', single: 'inside single quotes', 'heredoc-expanding': 'in an expanding heredoc' }[p.context] || p.context;
        emit('nix-shell-injection', { ...base, severity: sev, description: `A ${threat === 'unknown' ? 'value whose origin could not be resolved' : `${threat}-origin value`} is interpolated ${ctxText} into ${sink.kind === 'command-position' ? 'command position' : `${sink.command ? `an argument of ${sink.command}` : 'a shell command'}`} without lib.escapeShellArg. ${threat === 'configuration' ? 'It is set by the configuration, not by an attacker, so exploitation needs control of that configuration.' : threat === 'argument' ? 'It is a caller-supplied function argument.' : ''}`.trim(), confidence: unknownOnly ? 0.3 : (threat === 'configuration' ? 0.6 : 0.8), ...(unknownOnly ? { uncertainty: [{ kind: 'unresolved-target', detail: origins.find((o) => o.kind === 'unknown').detail }] } : {}) });
        flows[flows.length - 1].rule = 'injection';
      }

      // shell variable expansions in the generated text: service environment and eval-like use
      for (const e of lex.exps) {
        const word = e.word; const cm = e.cmd;
        const wIdx = cm && word ? cm.words.indexOf(word) : -1;
        const sink = sinkOf(cm, wIdx);
        const srcSpan = srcSpanOf(e.idx, e.end);
        if (!srcSpan) continue;
        const gloc = loc(e.idx, e.end);
        const envHit = envMap.get(e.name);
        const unquoted = e.context === 'unquoted';
        const destructive = cm && /^(?:rm|chmod|chown|mv|cp|ln)$/.test(cm.name || '') && cm.words.some((w) => /^-\w*[rRf]\w*$/.test(w.text));
        const evalLike = sink.kind === 'eval' || (cm && cm.name === 'eval');
        const envThreat = envHit ? threatOf(envHit.result.origins) : null;
        if (envHit && envThreat && (unquoted || evalLike) && sink.kind !== 'argument' || envHit && envThreat && unquoted && (destructive || sink.kind === 'filesystem' || sink.kind === 'network')) {
          const sev = envThreat === 'attacker' ? 'high' : envThreat === 'argument' ? 'medium' : envThreat === 'configuration' ? 'medium' : 'low';
          const chain = [...originChain(envHit.result.origins), hop(sfile, envHit.span, `environment.${e.name}`), { file: sfile, line: gloc.line, column: gloc.startColumn, endLine: gloc.endLine, endColumn: gloc.endColumn, label: `shell expansion $${e.name} (${sink.kind}${sink.command ? `: ${sink.command}` : ''})`, kind: 'shell', generated: true }].filter(Boolean);
          emit('nix-service-env-shell', { line: srcSpan.startLine, column: srcSpan.startColumn, severity: sev, description: `Service environment variable ${e.name} (${envThreat}-origin) is expanded ${unquoted ? 'unquoted' : e.context} as ${sink.kind === 'command-position' ? 'a command' : `an argument of ${sink.command || 'a command'}`} in the generated script.`, originalLocation: srcSpan, generatedLocation: gloc, chain, origins: envHit.result.origins, sink: { ...sink, context: e.context }, extra: { environmentVariable: e.name, environmentSource: hop(sfile, envHit.span, `environment.${e.name}`) } });
          continue;
        }
        if (unquoted && evalLike && cm && (cm.name === 'eval' || SHELLS.has(cm.name))) emit('nix-shell-eval', { line: srcSpan.startLine, column: srcSpan.startColumn, severity: 'medium', description: `The script evaluates $${e.name} as shell code (${cm.name}).`, originalLocation: srcSpan, generatedLocation: gloc, chain: [hop(sfile, srcSpan, `shell expansion $${e.name}`)].filter(Boolean), origins: [mkOrigin('unknown', `shell variable ${e.name}`)], sink: { ...sink, context: e.context }, confidence: 0.5 });
        else if (unquoted && destructive && e.name !== '?' && !/^\d$/.test(e.name) && !(envHit && !envThreat)) emit('nix-shell-unquoted-expansion', { line: srcSpan.startLine, column: srcSpan.startColumn, severity: 'low', description: `$${e.name} is unquoted in ${cm.name} with a recursive/forced flag: word splitting or an empty value changes which paths are affected.`, originalLocation: srcSpan, generatedLocation: gloc, chain: [hop(sfile, srcSpan, `shell expansion $${e.name}`)].filter(Boolean), origins: [mkOrigin('unknown', `shell variable ${e.name}`)], sink: { ...sink, context: e.context }, confidence: 0.4 });
      }
      for (const m of text.matchAll(/(?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/g)) {
        const span = srcSpanOf(m.index, m.index + m[0].length); if (!span) continue;
        const gloc = loc(m.index, m.index + m[0].length);
        emit('nix-pipe-to-shell', { line: span.startLine, column: span.startColumn, severity: 'medium', description: 'A network download is piped straight into a shell inside a generated script.', originalLocation: span, generatedLocation: gloc, chain: [{ file: sfile, line: gloc.line, column: gloc.startColumn, endLine: gloc.endLine, endColumn: gloc.endColumn, label: 'shell pipeline', kind: 'shell', generated: true }], origins: [mkOrigin('attacker', 'content downloaded at build/activation time')], sink: { kind: 'eval', command: 'sh', context: 'unquoted' }, confidence: 0.7 });
      }
    }
  }
  const order = (a, b) => (SEV[b.severity] - SEV[a.severity]) || a.file.localeCompare(b.file) || a.line - b.line;
  findings.sort(order);
  return { version: NIX_SCRIPT_VERSION, findings, flows, gaps, scripts: scripts.map(({ map, ...s }) => Object.defineProperty(s, 'mapRange', { value: map, enumerable: false })), analyzed: scripts.length };
}

function originChain(origins) {
  const out = [];
  for (const o of origins) if (!SAFE_KINDS.has(o.kind)) for (const h of o.chain || []) if (h) out.push(h);
  const seen = new Set();
  return out.filter((h) => { const k = `${h.file}:${h.line}:${h.column}:${h.label}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

/** systemd `environment` attrset next to the script: NAME -> evaluated value. */
function collectEnvironment(site, ev) {
  const map = new Map();
  const parent = site.parentAttrset;
  if (!parent || parent.type !== 'attrset') return map;
  const add = (name, valueNode, span) => { map.set(name, { result: ev.eval(valueNode, site.env, 0), span }); };
  for (const b of parent.bindings) {
    if (b.kind !== 'attr' || !b.value) continue;
    const k = attrKey(b.path);
    if (k[0] === 'environment' && k.length === 2 && k[1]) add(k[1], b.value, b.span);
    else if (k[0] === 'environment' && k.length === 1) {
      const set = unparen(b.value);
      if (set && set.type === 'attrset') for (const eb of set.bindings) if (eb.kind === 'attr' && eb.value) { const ek = attrKey(eb.path); if (ek.length === 1 && ek[0]) add(ek[0], eb.value, eb.span); }
    }
  }
  return map;
}

export { PH as SHELL_PLACEHOLDER, RULES as NIX_SCRIPT_RULES, Workspace, Resolver, Evaluator, mkEnv, bindingsEnv, unparen, attrKey, segName, attrIn, hop, mkOrigin, SAFE_KINDS, SECRET_NAME, PATHISH_TAIL, CONFIG_PARAMS, RUNTIME_SECRET_DIRS, spanOf, lookup, dedupe };
