// Nix secret placement and configuration lineage (NIX-006).
//
// The Nix store is world-readable and everything Nix evaluates into a derivation, a unit file or a
// generated config ends up in it. This module follows credential-bearing values to where they land:
//
//   plaintext-source  a credential literal written in the Nix source itself
//   store             the value reaches a store path: writeText/toFile content, systemd unit
//                     environment, environment.etc text, a generated script, a Home Manager file
//   build             the value is a derivation attribute (it is in the .drv environment) or a build input
//   log               the value is printed (echo / logger / trace) by a script or by evaluation
//
// Runtime references are SAFE for the boundary they model: `passwordFile = config.sops.secrets.x.path`,
// "/run/secrets/x", EnvironmentFile and LoadCredential point at a file that exists decrypted only at
// runtime; sops/agenix ciphertext files are not plaintext. A manager name never sanitises every
// consumer, though: `builtins.readFile config.sops.secrets.x.path` is a deliberate decrypt-and-copy and
// still fires, because the decrypted content is now a store value.
//
// Nothing is decrypted, read from the host, or discovered by crawling: only the files handed in are
// looked at, and a finding never carries the secret value, only its source, destination, kind and length.

import {
  Workspace, Resolver, Evaluator, mkEnv, bindingsEnv, unparen, attrKey, segName, attrIn, hop, mkOrigin, SAFE_KINDS,
  SECRET_NAME, PATHISH_TAIL, CONFIG_PARAMS, RUNTIME_SECRET_DIRS, spanOf, analyzeNixScripts,
} from './nix-script-taint.js';
import { isLanguageExcludedPath } from './discovery.js';

export const NIX_SECRETS_VERSION = 'nix-secrets/1';

const TOKEN_FORMATS = [
  ['private key block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/, 'critical'],
  ['AWS access key id', /\bAKIA[0-9A-Z]{16}\b/, 'critical'],
  ['GitHub token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/, 'critical'],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, 'high'],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}\b/, 'critical'],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/, 'high'],
  ['API secret key', /\bsk-(?:live-|proj-|ant-)?[A-Za-z0-9_-]{24,}\b/, 'high'],
];
const PLACEHOLDER = /^(?:|<[^>]*>|@[A-Za-z0-9_]+@|\$\{?[A-Za-z_]\w*\}?|%[A-Za-z_]+%|changeme|change-me|replaceme|todo|xxx+|\*+|null|none|example|dummy|placeholder|your[-_ ]?\w*|secret|password)$/i;
const ENV_DESTS = new Set(['environment']);
const TRACE_FNS = new Set(['trace', 'traceVal', 'traceValFn', 'traceSeq', 'traceShow', 'warn', 'traceIf', 'traceSeqN', 'traceValSeq', 'traceVerbose']);
const WRITERS = new Map([
  ['writeText', 1], ['writeTextFile', null], ['writeShellScript', 1], ['writeShellScriptBin', 1], ['writeScript', 1], ['writeScriptBin', 1], ['writeBash', 1], ['writeBashBin', 1],
  ['toFile', 1], ['writeTextDir', 1], ['runCommand', 2], ['runCommandLocal', 2], ['runCommandNoCC', 2], ['writeShellApplication', null],
]);
const DERIVATION_FNS = new Set(['mkDerivation', 'buildGoModule', 'buildPythonPackage', 'buildPythonApplication', 'buildNpmPackage', 'rustPlatform.buildRustPackage', 'buildRustPackage', 'stdenv.mkDerivation', 'runCommand', 'runCommandLocal', 'runCommandNoCC', 'mkShell', 'buildEnv', 'derivation', 'dockerTools.buildImage', 'buildImage', 'buildLayeredImage']);
const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const secretName = (n) => typeof n === 'string' && SECRET_NAME.test(n) && !PATHISH_TAIL.test(n);

export const SECRET_RULES = Object.freeze({
  'nix-secret-plaintext': { cwe: 'CWE-798', family: 'hardcoded-secret', vuln: 'Credential written as a literal in Nix source', remediation: 'Keep the value out of the Nix source: reference a runtime file (sops-nix/agenix path, LoadCredential) instead.' },
  'nix-secret-store': { cwe: 'CWE-312', family: 'secret-in-store', vuln: 'Secret value reaches the world-readable Nix store', remediation: 'Pass a runtime file reference (…File option, EnvironmentFile, LoadCredential) instead of the value, so the secret is never part of a store path.' },
  'nix-secret-build': { cwe: 'CWE-312', family: 'secret-in-build', vuln: 'Secret is a derivation input or environment variable', remediation: 'Do not pass secrets into derivations: they are recorded in the .drv and the build sandbox output. Read them at runtime.' },
  'nix-secret-log': { cwe: 'CWE-532', family: 'secret-in-log', vuln: 'Secret value is printed to a log or trace', remediation: 'Do not echo or trace secrets; log a fingerprint or a reference instead.' },
  'nix-secret-decrypt-copy': { cwe: 'CWE-312', family: 'secret-in-store', vuln: 'Decrypted secret copied into a store value at evaluation time', remediation: 'A sops-nix/agenix path exists only at runtime. Reading it during evaluation copies the decrypted content into the store; hand the path to the service instead.' },
  'nix-secret-plaintext-file': { cwe: 'CWE-312', family: 'hardcoded-secret', vuln: 'Plaintext credentials file used where an encrypted file is expected', remediation: 'Encrypt the file (sops/age) before committing; the manager option only protects an encrypted file.' },
});

const redact = (value) => ({ redacted: true, length: typeof value === 'string' ? value.length : null });

/** Is this literal a plausible credential (not empty, placeholder, a path or a reference)? */
export function plausibleSecret(v) {
  if (typeof v !== 'string') return false;
  const t = v.trim();
  if (t.length < 4) return false;
  if (PLACEHOLDER.test(t)) return false;
  if (/^\/(?:run|var|etc|nix|home|usr|opt|tmp)\//.test(t) || /^\.{0,2}\//.test(t)) return false;
  if (/^(?:https?|file|unix):\/\/[^:@\s]*$/.test(t)) return false;
  if (/^\$\{|^\$[A-Za-z_]/.test(t)) return false;
  // wpa_supplicant's `ext:NAME` is a REFERENCE to a variable supplied at runtime (networking.wireless.environmentFile), not a value
  if (/^ext:[A-Za-z0-9_.-]+$/.test(t)) return false;
  return true;
}

/** Classify where an attribute path lands. */
function destOf(path) {
  const p = path.map((x) => x || '*');
  const has = (...xs) => xs.every((x) => p.includes(x));
  const last = p[p.length - 1];
  if (p[0] === 'systemd' && (has('environment') || (last === 'Environment' || last === 'SetCredential'))) return { exposure: 'store', label: 'systemd unit file' };
  if (p[0] === 'environment' && (p[1] === 'etc' || p[1] === 'variables' || p[1] === 'sessionVariables' || p[1] === 'shellAliases')) return { exposure: 'store', label: p[1] === 'etc' ? '/etc file built from the store' : 'system-wide environment' };
  if (p[0] === 'home' && (p[1] === 'file' || p[1] === 'sessionVariables')) return { exposure: 'store', label: 'Home Manager file' };
  if (p[0] === 'users' && p[1] === 'users' && /^(?:password|initialPassword|hashedPassword|initialHashedPassword)$/.test(last)) return { exposure: 'store', label: 'user account definition' };
  return null;
}

class Walker {
  constructor(files) {
    this.files = files; this.ws = new Workspace(files); this.res = new Resolver(this.ws); this.ev = new Evaluator(this.res);
    this.findings = []; this.safe = []; this.gaps = []; this.seen = new Set(); this.scriptKeys = new Set();
  }

  isRuntimeRef(expr, env) {
    const n = unparen(expr);
    if (!n) return false;
    if (n.type === 'string' && !n.interpolated && RUNTIME_SECRET_DIRS.test(n.literal || '')) return true;
    if (n.type === 'string' && n.interpolated) {
      // "tok:${config.sops.secrets.tok.path}" / "${config.age.secrets.x.path}": only runtime path references and text
      const parts = n.parts.filter((p) => p.kind === 'interp');
      return parts.length > 0 && parts.every((p) => this.isRuntimeRef(p.expr, env));
    }
    if (n.type === 'select') {
      const base = unparen(n.base); const segs = n.attrpath.map(segName);
      if (base && base.type === 'ident' && CONFIG_PARAMS.has(base.name) && segs.every((x) => x !== null)) {
        if (/^(?:sops|age|agenix)$/.test(segs[0]) && (segs.includes('placeholder') || segs.includes('templates') || (segs.includes('secrets') && /^(?:path|name)$/.test(segs[segs.length - 1])))) return true;
      }
    }
    if (n.type === 'ident') { const d = this.res.deref(n, env, []); if (d.node && d.node !== n) return this.isRuntimeRef(d.node, d.env); }
    return false;
  }

  /** Secret origin of an expression, after discounting runtime references. */
  secretOrigins(expr, env) {
    const r = this.ev.eval(expr, env, 0);
    const kept = r.origins.filter((o) => o.kind === 'secret' && !/^option config\.(?:sops|age|agenix)\./.test(o.detail));
    return { ...r, secret: kept };
  }

  emit(rule, o) {
    const R = SECRET_RULES[rule];
    // one exposure per location (build wins over the generic store view of the same attribute); log is separate
    const key = `${rule === 'nix-secret-log' ? 'log' : 'value'}|${o.file}|${o.line}|${o.column}`;
    if (this.seen.has(key)) return null;
    this.seen.add(key);
    const f = {
      id: `NIX-SECRET-${rule}-${o.file}:${o.line}:${o.column}`, severity: o.severity, file: o.file, line: o.line, column: o.column,
      vuln: R.vuln, cwe: R.cwe, description: o.description, remediation: R.remediation, parser: 'NIX-SECRET', family: R.family, rule,
      language: 'nix', capability: 'secrets', analysisKind: 'config', evidenceKind: 'source', confidence: o.confidence ?? 0.8,
      exposure: o.exposure, source: o.source, destination: o.destination || null, evidence: o.evidence || { redacted: true },
      originalLocation: o.originalLocation || null, chain: o.chain || [], origins: (o.origins || []).map((x) => ({ kind: x.kind, detail: x.detail })),
      secretValue: 'redacted',
    };
    this.findings.push(f);
    return f;
  }

  at(file, span) { return span ? { file, line: span.startLine, column: span.startColumn } : { file, line: 1, column: 0 }; }

  // ── pieces ────────────────────────────────────────────────────────────────
  inspectLiteral(file, full, v, span, destination) {
    const last = full[full.length - 1];
    const text = v.literal;
    for (const [label, re, sev] of TOKEN_FORMATS) {
      if (re.test(text)) {
        this.emit('nix-secret-plaintext', { ...this.at(file, v.span || span), file, severity: sev, exposure: 'plaintext-source', description: `A ${label} is written as a literal at ${full.filter(Boolean).join('.') || 'a string'} (value redacted).`, source: { kind: 'literal', file, line: (v.span || span).startLine, attr: full.filter(Boolean).join('.') }, destination: destination || { kind: 'source', label: 'Nix source (and every store path that embeds it)' }, evidence: { ...redact(text), format: label }, originalLocation: v.span || span, chain: [hop(file, v.span || span, `literal ${label}`)].filter(Boolean), origins: [mkOrigin('secret', `literal ${label}`)] });
        return true;
      }
    }
    if (secretName(last) && plausibleSecret(text)) {
      const hashed = /hash/i.test(last);
      this.emit('nix-secret-plaintext', { ...this.at(file, v.span || span), file, severity: hashed ? 'medium' : 'high', exposure: 'plaintext-source', description: `${full.filter(Boolean).join('.')} is assigned a ${hashed ? 'password hash' : 'credential'} literal (value redacted); it is part of the Nix source and of every store path built from it.`, source: { kind: 'literal', file, line: (v.span || span).startLine, attr: full.filter(Boolean).join('.') }, destination: destination || { kind: 'source', label: 'Nix source (and every store path that embeds it)' }, evidence: redact(text), originalLocation: v.span || span, chain: [hop(file, v.span || span, `literal assigned to ${last}`)].filter(Boolean), origins: [mkOrigin('secret', `literal credential in ${last}`)], confidence: hashed ? 0.6 : 0.8 });
      return true;
    }
    return false;
  }

  /** key=value secrets inside literal text (a config file body, an Environment entry). */
  inspectText(file, node, full, destination, env) {
    if (!node || node.type !== 'string') return;
    for (const part of node.parts) {
      if (part.kind !== 'text') continue;
      for (const m of part.value.matchAll(/(?:^|[\s"'])([A-Za-z_][\w.-]*)\s*[=:]\s*["']?([^\s"'$@][^\s"']{3,})/g)) {
        if (secretName(m[1]) && plausibleSecret(m[2]) && !RUNTIME_SECRET_DIRS.test(m[2])) {
          this.emit('nix-secret-plaintext', { ...this.at(file, node.span), file, severity: 'high', exposure: destination ? destination.exposure : 'plaintext-source', description: `A generated text contains ${m[1]}=… with a literal credential (value redacted).`, source: { kind: 'literal', file, line: node.span.startLine, attr: full.filter(Boolean).join('.') }, destination: destination || { kind: 'source', label: 'Nix source' }, evidence: { ...redact(m[2]), key: m[1] }, originalLocation: node.span, chain: [hop(file, node.span, `literal ${m[1]}=…`)].filter(Boolean), origins: [mkOrigin('secret', `literal ${m[1]}`)] });
        }
      }
    }
  }

  reportFlow(file, r, node, full, destination, kind, env, extra = {}) {
    const decrypt = r.origins.some((o) => /decrypted secret copied/.test(o.detail));
    const span = spanOf(node) || { startLine: 1, startColumn: 0 };
    const rule = decrypt ? 'nix-secret-decrypt-copy' : kind === 'build' ? 'nix-secret-build' : kind === 'log' ? 'nix-secret-log' : 'nix-secret-store';
    const sev = kind === 'log' ? 'medium' : decrypt ? 'high' : kind === 'build' ? 'high' : /hash/i.test(full[full.length - 1] || '') ? 'medium' : 'high';
    const o0 = r.secret[0];
    this.emit(rule, {
      ...this.at(file, span), file, severity: sev, exposure: kind,
      description: `${decrypt ? 'A decrypted secret is copied into' : 'A secret-origin value reaches'} ${destination.label} (${kind === 'log' ? 'printed' : kind === 'build' ? 'derivation input' : 'world-readable store path'}). Source: ${o0 ? o0.detail : 'secret'}; value redacted.`,
      source: { kind: decrypt ? 'decrypted-file' : 'option', detail: o0 && o0.detail, file }, destination,
      originalLocation: span, chain: [...(o0 ? o0.chain : []), hop(file, span, `reaches ${destination.label}`)].filter(Boolean),
      origins: r.secret, evidence: { redacted: true, via: full.filter(Boolean).join('.') }, ...extra,
    });
  }

  // ── walking ───────────────────────────────────────────────────────────────
  walkFile(file) {
    const rec = this.ws.parse(file);
    if (!rec || !rec.ast) { this.gaps.push({ kind: 'parse-failed', file, detail: rec ? `parse status ${rec.parse.status}` : 'unreadable' }); return; }
    this.visit(file, rec.ast, mkEnv(null, new Map(), [], file), [], 0, false);
  }

  visit(file, node, env, path, depth, asFn) {
    if (!node || typeof node !== 'object' || depth > 200) return;
    switch (node.type) {
      case 'lambda': {
        const vars = new Map();
        if (node.param.kind === 'pattern') for (const f of node.param.formals) vars.set(f.name, { kind: 'param', name: f.name, span: f.span, file, def: f.default });
        else if (node.param.name) vars.set(node.param.name, { kind: 'param', name: node.param.name, span: node.span, file });
        if (node.param.atName) vars.set(node.param.atName, { kind: 'param', name: node.param.atName, span: node.span, file });
        this.visit(file, node.body, mkEnv(env, vars, [], file), path, depth + 1, false); return;
      }
      case 'let': {
        const e2 = mkEnv(env, bindingsEnv(node, env, file), [], file);
        for (const b of node.bindings) if (b.kind === 'attr') this.visit(file, b.value, e2, [], depth + 1, false);
        this.visit(file, node.body, e2, path, depth + 1, false); return;
      }
      case 'with': { this.visit(file, node.env, env, path, depth + 1, false); this.visit(file, node.body, mkEnv(env, new Map(), [this.ev.withName(node.env)], file), path, depth + 1, false); return; }
      case 'attrset': {
        const e2 = node.rec ? mkEnv(env, bindingsEnv(node, env, file), [], file) : env;
        for (const b of node.bindings) {
          if (b.kind !== 'attr' || !b.value) continue;
          const full = [...path, ...attrKey(b.path)];
          this.inspectBinding(file, full, b.value, b.span, e2);
          this.visit(file, b.value, e2, full, depth + 1, false);
        }
        return;
      }
      case 'app': {
        if (!asFn) this.inspectApp(file, node, env, path);
        this.visit(file, node.fn, env, path, depth + 1, true); this.visit(file, node.arg, env, path, depth + 1, false); return;
      }
      case 'string': {
        if (!node.interpolated) { for (const [label, re, sev] of TOKEN_FORMATS) if (re.test(node.literal || '')) { /* reported through its binding when it has one; bare strings: */ if (!this.stringSeen(file, node)) this.emit('nix-secret-plaintext', { ...this.at(file, node.span), file, severity: sev, exposure: 'plaintext-source', description: `A ${label} is written as a literal (value redacted).`, source: { kind: 'literal', file, line: node.span.startLine }, destination: { kind: 'source', label: 'Nix source' }, evidence: { ...redact(node.literal), format: label }, originalLocation: node.span, chain: [hop(file, node.span, `literal ${label}`)].filter(Boolean), origins: [mkOrigin('secret', `literal ${label}`)] }); } }
        for (const part of node.parts) if (part.kind === 'interp') this.visit(file, part.expr, env, path, depth + 1, false);
        return;
      }
      default:
        for (const k of ['left', 'right', 'operand', 'expr', 'cond', 'then', 'else', 'body', 'base']) if (node[k] && typeof node[k] === 'object') this.visit(file, node[k], env, path, depth + 1, false);
        if (node.items) for (const it of node.items) this.visit(file, it, env, path, depth + 1, false);
    }
  }
  stringSeen(file, node) { const k = `${file}:${node.start}`; if (this.scriptKeys.has(k)) return true; this.scriptKeys.add(k); return false; }

  inspectBinding(file, full, value, bspan, env) {
    const v = unparen(value);
    const last = full[full.length - 1];
    const dest = destOf(full);
    const sname = secretName(last);
    // literal credentials
    if (v && v.type === 'string' && !v.interpolated) {
      this.scriptKeys.add(`${file}:${v.start}`);
      if (this.inspectLiteral(file, full, v, bspan, dest ? { kind: 'store', label: dest.label, exposure: dest.exposure } : null)) return;
      if (dest && last === 'text') this.inspectText(file, v, full, { kind: 'store', label: dest.label, exposure: 'store' }, env);
      return;
    }
    // systemd serviceConfig.Environment = [ "K=V" ... ] / SetCredential
    if (v && v.type === 'list' && full.includes('serviceConfig') && /^(?:Environment|SetCredential)$/.test(last)) {
      for (const it of v.items) {
        const s = unparen(it);
        if (!s || s.type !== 'string') continue;
        const dst = { kind: 'store', label: 'systemd unit file', exposure: 'store' };
        const text = s.parts.filter((p) => p.kind === 'text').map((p) => p.value).join('');
        const key = (/^\s*([A-Za-z_][\w.-]*)\s*[=:]/.exec(text) || [])[1];
        if (!s.interpolated) { this.scriptKeys.add(`${file}:${s.start}`); this.inspectText(file, s, full, dst, env); continue; }
        const r = this.secretOrigins(s, env);
        if (r.secret.length && !this.isRuntimeRef(s, env)) this.reportFlow(file, r, s, full, dst, 'store', env, { source: { kind: 'option', detail: r.secret[0].detail, file, key } });
      }
      return;
    }
    // evaluate the value for secret origins
    if (!v || v.type === 'attrset' || v.type === 'lambda' || v.type === 'list') return;
    if (this.isRuntimeRef(v, env)) { this.safe.push({ file, line: bspan && bspan.startLine, attr: full.filter(Boolean).join('.'), reason: 'runtime secret reference' }); return; }
    const r = this.secretOrigins(v, env);
    const hereDest = dest ? { kind: 'store', label: dest.label, exposure: dest.exposure } : null;
    if (r.secret.length) {
      // a secret-named binding at a store-bound destination, or ANY decrypt-and-copy
      const decrypt = r.origins.some((o) => /decrypted secret copied/.test(o.detail));
      if (hereDest || decrypt) { this.reportFlow(file, r, v, full, hereDest || { kind: 'store', label: 'a value in the Nix store', exposure: 'store' }, 'store', env); return; }
      if (sname) this.reportFlow(file, r, v, full, { kind: 'store', label: `option ${full.filter(Boolean).join('.')} (rendered into the store)`, exposure: 'store' }, 'store', env);
      return;
    }
    // text content with embedded literals under a store-bound destination
    if (v.type === 'string' && hereDest && last === 'text') { this.scriptKeys.add(`${file}:${v.start}`); this.inspectText(file, v, full, hereDest, env); }
  }

  inspectApp(file, node, env, path) {
    const { fn, args } = this.ev.flatten(node);
    const c = this.ev.calleeOf(fn);
    const name = c.name; const full = c.full || name;
    if (!name) return;
    // eval-time logging
    if (TRACE_FNS.has(name) && (c.root === 'builtins' || c.root === 'lib' || c.root === 'pkgs' || !c.root || true) && args.length) {
      const msgArgs = name === 'warn' || name === 'trace' || name === 'traceIf' ? args.slice(0, 1) : args.slice(0, 1);
      for (const a of msgArgs) {
        const r = this.secretOrigins(a, env);
        if (r.secret.length && !this.isRuntimeRef(a, env)) this.reportFlow(file, r, a, [name], { kind: 'log', label: `evaluation trace output (${name})` }, 'log', env);
      }
    }
    // writers: the content argument becomes a store file
    if (WRITERS.has(name) && (c.root === 'pkgs' || c.root === 'builtins' || c.root === 'writers' || c.root === 'lib' || !c.root || c.root !== null)) {
      const idx = WRITERS.get(name);
      const dst = { kind: 'store', label: `store file written by ${name}`, exposure: 'store' };
      let content = null; let attrs = null;
      if (idx !== null && args[idx]) content = args[idx];
      if (idx === null) { const a = unparen(args[0]); if (a && a.type === 'attrset') { const hit = attrIn(a, ['text']); if (hit) content = hit.value; attrs = a; } }
      if (name === 'runCommand' || name === 'runCommandLocal' || name === 'runCommandNoCC') { const a = unparen(args[1]); if (a && a.type === 'attrset') attrs = a; }
      if (content) {
        const cn = unparen(content);
        if (cn && cn.type === 'string' && !cn.interpolated) { this.scriptKeys.add(`${file}:${cn.start}`); this.inspectText(file, cn, [name], dst, env); }
        else if (cn && !this.isRuntimeRef(cn, env)) {
          const r = this.secretOrigins(cn, env);
          if (r.secret.length) this.reportFlow(file, r, cn, [name], dst, 'store', env);
          else if (cn.type === 'string') { this.scriptKeys.add(`${file}:${cn.start}`); this.inspectText(file, cn, [name], dst, env); }
        }
      }
      if (attrs && /^runCommand/.test(name)) this.inspectDerivationAttrs(file, attrs, env, name);
    }
    if (DERIVATION_FNS.has(name) || DERIVATION_FNS.has(full || '')) {
      const a = unparen(args[args.length - 1]);
      if (a && a.type === 'attrset' && !/^runCommand/.test(name)) this.inspectDerivationAttrs(file, a, env, name);
    }
  }

  inspectDerivationAttrs(file, attrs, env, builder) {
    for (const b of attrs.bindings) {
      if (b.kind !== 'attr' || !b.value) continue;
      const key = attrKey(b.path); const last = key[key.length - 1];
      const val = unparen(b.value);
      if (!val || val.type === 'lambda') continue;
      const dst = { kind: 'build', label: `derivation ${builder} attribute ${key.filter(Boolean).join('.')} (recorded in the .drv)`, exposure: 'build' };
      if (val.type === 'string' && !val.interpolated) {
        this.scriptKeys.add(`${file}:${val.start}`);
        if (secretName(last) && plausibleSecret(val.literal)) this.emit('nix-secret-build', { ...this.at(file, b.span), file, severity: 'high', exposure: 'build', description: `Derivation attribute ${key.join('.')} carries a credential literal (value redacted); derivation attributes are recorded in the .drv and the build environment.`, source: { kind: 'literal', file, line: b.span.startLine, attr: key.join('.') }, destination: dst, evidence: redact(val.literal), originalLocation: b.span, chain: [hop(file, b.span, `literal ${last}`)].filter(Boolean), origins: [mkOrigin('secret', `literal ${last}`)] });
        continue;
      }
      if (this.isRuntimeRef(val, env)) continue;
      if (val.type === 'attrset') continue;
      const r = this.secretOrigins(val, env);
      if (r.secret.length) this.reportFlow(file, r, val, key, dst, 'build', env);
    }
  }
}

/** Files the manager options point at: plaintext where ciphertext is required is its own finding. */
function inspectReferencedFiles(w, allFiles, out) {
  const looksEncrypted = (t) => /ENC\[AES256_GCM,|-----BEGIN AGE ENCRYPTED FILE-----|^age-encryption\.org\/v1|\bsops:\s*\n/m.test(t) || /"sops"\s*:/.test(t);
  const looksPlainCreds = (t) => /^\s*[A-Za-z_][\w.-]*(?:pass(?:word)?|secret|token|api_?key|private_?key)[\w.-]*\s*[:=]\s*\S{4,}/im.test(t) || /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(t);
  for (const file of Object.keys(w.files)) {
    const rec = w.ws.parse(file);
    if (!rec || !rec.ast) continue;
    const stack = [rec.ast];
    while (stack.length) {
      const n = stack.pop();
      if (!n || typeof n !== 'object') continue;
      if (n.type === 'attrset') {
        for (const b of n.bindings) {
          if (b.kind !== 'attr' || !b.value) continue;
          const key = attrKey(b.path); const last = key[key.length - 1];
          const v = unparen(b.value);
          if (v && v.type === 'path' && !v.interpolated && (last === 'sopsFile' || last === 'file')) {
            const rel = String(v.literal);
            const target = rel.startsWith('.') ? (file.includes('/') ? file.replace(/\/[^/]*$/, '/') : '') + rel.replace(/^\.\//, '') : rel;
            const text = allFiles[target.replace(/\/\.\//g, '/')];
            if (typeof text === 'string' && !looksEncrypted(text) && looksPlainCreds(text)) {
              out.push({ file, bspan: b.span, target, last });
            }
          }
        }
      }
      for (const k of Object.keys(n)) { const c = n[k]; if (c && typeof c === 'object') { if (Array.isArray(c)) stack.push(...c); else stack.push(c); } }
    }
  }
}

/**
 * @param {{files: Record<string,string>}} opts  every file handed in (Nix sources and referenced data files)
 */
export function analyzeNixSecrets(opts = {}) {
  const all = opts.files || {};
  const nix = {};
  for (const [p, t] of Object.entries(all)) if (typeof t === 'string' && /\.nix$/i.test(p) && !isLanguageExcludedPath(p)) nix[p] = t;
  const w = new Walker(nix);
  for (const f of Object.keys(nix).sort()) w.walkFile(f);

  // secrets interpolated into generated scripts (NIX-003 flows), distinct from injection
  const scripts = analyzeNixScripts({ files: nix });
  for (const fl of scripts.flows) {
    const secret = (fl.originDetails || []).filter((o) => o.kind === 'secret' && !/^option config\.(?:sops|age|agenix)\./.test(o.detail));
    if (!secret.length) continue;
    const cmd = fl.sink && fl.sink.command;
    const printing = /^(?:echo|printf|logger|tee|cat|print|wall|notify-send|systemd-cat)$/.test(cmd || '') || fl.scriptHasTrace || (fl.sink && fl.sink.kind === 'argument' && cmd === 'curl' && false);
    const sp = fl.originalLocation;
    const origins = secret.map((o) => mkOrigin('secret', o.detail, fl.chain || []));
    const dst = { kind: 'store', label: `generated script ${fl.attrPath} (a store file)`, exposure: 'store' };
    const decrypt = secret.some((o) => /decrypted secret copied/.test(o.detail));
    w.emit(decrypt ? 'nix-secret-decrypt-copy' : 'nix-secret-store', { ...w.at(fl.file, sp), file: fl.file, severity: 'high', exposure: 'store', description: `A secret-origin value is interpolated into the generated script ${fl.attrPath}, which becomes a world-readable store file (value redacted). Source: ${secret[0].detail}.`, source: { kind: 'option', detail: secret[0].detail, file: fl.file }, destination: dst, originalLocation: sp, generatedLocation: fl.generatedLocation, chain: fl.chain, origins, evidence: { redacted: true, via: fl.attrPath } });
    if (printing) w.emit('nix-secret-log', { ...w.at(fl.file, sp), file: fl.file, severity: 'medium', exposure: 'log', description: `The same secret is ${cmd ? `printed by ${cmd}` : 'echoed by a traced script'} in ${fl.attrPath} (value redacted).`, source: { kind: 'option', detail: secret[0].detail, file: fl.file }, destination: { kind: 'log', label: `script output of ${fl.attrPath} (journal / build log)` }, originalLocation: sp, generatedLocation: fl.generatedLocation, chain: fl.chain, origins, evidence: { redacted: true, via: fl.attrPath } });
  }

  const plain = [];
  inspectReferencedFiles(w, all, plain);
  for (const p of plain) w.emit('nix-secret-plaintext-file', { ...w.at(p.file, p.bspan), file: p.file, severity: 'high', exposure: 'plaintext-source', description: `${p.last} points at ${p.target}, which holds credentials but has no sops/age encryption markers (content not shown).`, source: { kind: 'file', file: p.target }, destination: { kind: 'source', label: 'repository and every clone' }, originalLocation: p.bspan, chain: [hop(p.file, p.bspan, `${p.last} = ${p.target}`)].filter(Boolean), origins: [mkOrigin('secret', `plaintext file ${p.target}`)], evidence: { redacted: true } });

  const findings = w.findings.sort((a, b) => (SEV[b.severity] - SEV[a.severity]) || a.file.localeCompare(b.file) || a.line - b.line);
  return { version: NIX_SECRETS_VERSION, findings, safe: w.safe, gaps: [...w.gaps, ...scripts.gaps], analyzed: Object.keys(nix).length };
}

export { SAFE_KINDS };
