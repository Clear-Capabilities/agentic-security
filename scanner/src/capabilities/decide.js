// Deterministic capability decisions (X-501.AC02, X-501.AC03).
//
// `decide(bound, action, ctx)` answers one question: does this task's bound
// manifest permit this one action? The answer is a frozen
// `{ decision, code, reason, kind, subject, taskId, manifestDigest }`:
//
//   - deny-by-default: the answer is `allow` only when a specific declared grant
//     covers the action; every other path, including every error, is `deny`
//   - deterministic: no clock, no randomness, no environment; the same bound
//     manifest, action and context give the same answer (the filesystem is read
//     only to resolve symbolic links and to look at an executable)
//   - sanitized: `code` comes from the closed table in reasons.js and `reason` is
//     the fixed sentence beside it; the one request-derived field, `subject`, is
//     redacted and length-capped
//   - fail-closed: an unknown action kind, a binding that does not match, an
//     argument list that is not plain strings, a path that cannot be resolved,
//     an interpreter that is not declared as one: all `deny`
//
// This is a POLICY decision. Whether the operating system then actually stops the
// task from doing what the decision denied is the runner's job (runner.js), and
// only the runner may claim enforcement. A hook or an in-process check that calls
// this function explains; it does not enforce.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { detectSecretShapes } from './secrets.js';
import { CAPABILITY_KINDS } from '../posture/assurance/contracts.js';
import { reasonText, sanitizeSubject } from './reasons.js';
import { lexicalPath, canonicalPath, isWithin } from './paths.js';
import { normalizeHost, classifyAddress } from './address.js';
import { deriveChild } from './manifest.js';

const MAX_ARGS = 256;
const MAX_ARG_LEN = 8192;

// Executables that run code supplied elsewhere (their arguments, a script file,
// standard input): shells, language runtimes, launchers and build drivers. A
// shell allowlist cannot see through any of them, so each is refused unless the
// manifest declares it as a scoped interpreter with its exact argument list.
const INTERPRETER_NAMES = new Set([
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'tcsh', 'fish', 'ash', 'busybox', 'env', 'xargs', 'nice', 'nohup',
  'time', 'timeout', 'sudo', 'doas', 'su', 'ssh', 'osascript', 'launchctl', 'script', 'expect', 'tclsh', 'wish',
  'awk', 'gawk', 'mawk', 'nawk', 'java', 'jshell', 'deno', 'bun', 'nodejs', 'swift', 'make', 'gmake',
  'npm', 'npx', 'yarn', 'pnpm', 'pip', 'pip3', 'pipx', 'gem', 'bundle', 'cargo', 'go', 'gradle', 'mvn', 'watch',
]);
const INTERPRETER_FAMILY = /^(?:python|pypy|ruby|perl|php|lua|luajit|node|tclsh)[0-9.]*$/;

/**
 * What kind of executable this is. `interpreter` is true for a known shell or
 * runtime by name, and for any file that starts with a `#!` line (a script,
 * whatever it is called). A name is a hint, the shebang is the file's own word.
 */
export function classifyExecutable(realPath) {
  const base = path.basename(realPath).toLowerCase();
  if (INTERPRETER_NAMES.has(base) || INTERPRETER_FAMILY.test(base)) return { interpreter: true, via: 'name' };
  let fd;
  try {
    fd = fs.openSync(realPath, 'r');
    const buf = Buffer.alloc(2);
    const n = fs.readSync(fd, buf, 0, 2, 0);
    if (n === 2 && buf[0] === 0x23 && buf[1] === 0x21) return { interpreter: true, via: 'shebang' };
  } catch { /* unreadable: handled by the caller's stat check */ } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* ignore */ } }
  }
  return { interpreter: false, via: null };
}

function result(bound, action, decision, code, subject) {
  return Object.freeze({
    decision, code, reason: reasonText(code), kind: typeof action?.kind === 'string' ? sanitizeSubject(action.kind, 40) : 'unknown',
    subject: sanitizeSubject(subject), taskId: bound?.binding?.taskId ?? null, manifestDigest: bound?.binding?.digest ?? null,
  });
}

function argsDigest(args) {
  return crypto.createHash('sha256').update(JSON.stringify(args)).digest('hex').slice(0, 12);
}

// ---------------------------------------------------------------- filesystem

function decideFilesystem(bound, action, ctx) {
  const write = action.kind === 'filesystem-write';
  const subject = typeof action.path === 'string' ? action.path : '(not a string)';
  const lex = lexicalPath(action.path);
  if (!lex.ok) return result(bound, action, 'deny', 'path-invalid', subject);
  // Any parent-directory segment is refused outright. Lexical normalization of
  // `link/..` disagrees with what the kernel does when `link` is a symlink, so
  // a path containing one cannot be judged by its normalized form.
  if (lex.dotdot) return result(bound, action, 'deny', 'path-traversal', subject);
  const real = canonicalPath(lex.path);
  if (!real) return result(bound, action, 'deny', 'path-invalid', subject);

  for (const p of ctx.protectedPaths || []) {
    const pl = lexicalPath(p);
    if (!pl.ok) continue;
    const pr = canonicalPath(pl.path) ?? pl.path;
    if (isWithin(real, pr) || isWithin(lex.path, pl.path)) return result(bound, action, 'deny', 'protected-path', subject);
  }
  const fsGrants = bound.manifest.filesystem;
  const roots = write ? fsGrants.write : [...fsGrants.read, ...fsGrants.write];
  if (!roots.length) return result(bound, action, 'deny', 'no-grant', subject);
  const lexicallyIn = roots.some((r) => isWithin(lex.path, r));
  if (!lexicallyIn) return result(bound, action, 'deny', 'outside-roots', subject);
  const really = roots.some((r) => isWithin(real, canonicalPath(r) ?? r));
  if (!really) return result(bound, action, 'deny', 'symlink-escape', subject);
  return result(bound, action, 'allow', 'allowed', subject);
}

// ---------------------------------------------------------------- commands

function decideCommand(bound, action, ctx) {
  const exe = action.executable;
  const args = action.args === undefined ? [] : action.args;
  const subjectBase = typeof exe === 'string' ? exe : '(not a string)';
  const lexExe = lexicalPath(exe);
  if (!lexExe.ok || lexExe.dotdot) return result(bound, action, 'deny', 'executable-not-absolute', subjectBase);
  if (!Array.isArray(args) || args.length > MAX_ARGS || !args.every((a) => typeof a === 'string' && a.length <= MAX_ARG_LEN && !a.includes('\0'))) {
    return result(bound, action, 'deny', 'args-invalid', `${subjectBase} (malformed arguments)`);
  }
  const subject = `${subjectBase} (${args.length} args, args sha256:${argsDigest(args)})`;

  // Arguments are visible to every process on the host and to every descendant.
  // A secret does not belong in one, whatever command it is handed to.
  const canaries = (ctx.canaries || []).filter((c) => typeof c === 'string' && c.length >= 6);
  for (const a of args) {
    let secret = false;
    try { secret = detectSecretShapes(a); } catch { secret = true; }
    if (secret || canaries.some((c) => a.includes(c))) return result(bound, action, 'deny', 'secret-in-argument', subject);
  }

  let real; let st;
  try { real = fs.realpathSync(lexExe.path); st = fs.statSync(real); } catch { return result(bound, action, 'deny', 'executable-unresolvable', subject); }
  if (!st.isFile()) return result(bound, action, 'deny', 'executable-unresolvable', subject);
  try { fs.accessSync(real, fs.constants.X_OK); } catch { return result(bound, action, 'deny', 'executable-unresolvable', subject); }

  for (const w of bound.manifest.filesystem.write) {
    if (isWithin(real, canonicalPath(w) ?? w)) return result(bound, action, 'deny', 'executable-in-writable-root', subject);
  }

  const entries = bound.manifest.commands.filter((c) => (canonicalPath(c.executable) ?? c.executable) === real);
  if (!entries.length) return result(bound, action, 'deny', 'command-not-listed', subject);

  const cls = classifyExecutable(real);
  const matches = (e) => {
    const v = e.args.values;
    if (e.args.mode === 'any') return true;
    if (e.args.mode === 'exact') return v.length === args.length && v.every((x, i) => x === args[i]);
    return args.length >= v.length && v.every((x, i) => x === args[i]);
  };
  const argOk = entries.filter(matches);
  if (!argOk.length) {
    // An interpreter whose entries pin different arguments is the unpinned case.
    if (cls.interpreter && !entries.some((e) => e.interpreter)) return result(bound, action, 'deny', 'interpreter-blocked', subject);
    return result(bound, action, 'deny', 'args-not-permitted', subject);
  }
  if (cls.interpreter) {
    const scoped = argOk.find((e) => e.interpreter === 'scoped');
    if (!scoped) return result(bound, action, 'deny', 'interpreter-blocked', subject);
    if (scoped.args.mode !== 'exact') return result(bound, action, 'deny', 'interpreter-args-unpinned', subject);
  }
  return result(bound, action, 'allow', 'allowed', subject);
}

// ---------------------------------------------------------------- network

function hostMatches(entryHost, host) {
  if (entryHost === host) return true;
  if (!entryHost.startsWith('*.')) return false;
  const base = entryHost.slice(2);
  return host !== base && host.endsWith(`.${base}`);
}

function decideNetwork(bound, action) {
  const h = normalizeHost(action.host);
  const subject = typeof action.host === 'string' ? `${action.scheme ?? '?'}://${action.host}:${action.port ?? '?'}` : '(not a string)';
  if (!h.ok) return result(bound, action, 'deny', 'host-invalid', subject);
  if (!Number.isInteger(action.port) || action.port < 1 || action.port > 65535) return result(bound, action, 'deny', 'port-invalid', subject);
  const scheme = action.scheme === undefined ? 'https' : action.scheme;
  if (scheme !== 'http' && scheme !== 'https') return result(bound, action, 'deny', 'scheme-not-declared', subject);
  const onHost = bound.manifest.network.filter((d) => hostMatches(d.host, h.host));
  if (!onHost.length) return result(bound, action, 'deny', 'destination-not-declared', subject);
  const onPort = onHost.filter((d) => d.port === action.port);
  if (!onPort.length) return result(bound, action, 'deny', 'port-not-declared', subject);
  const onScheme = onPort.filter((d) => d.schemes.includes(scheme));
  if (!onScheme.length) return result(bound, action, 'deny', 'scheme-not-declared', subject);

  // Address checks apply to a host NAME once it has been resolved. The caller
  // (the proxy) resolves once, passes the addresses here and connects to those
  // same addresses, so what is checked is what is connected to.
  const resolved = Array.isArray(action.resolvedAddresses) ? action.resolvedAddresses : null;
  if (h.kind === 'name' && resolved) {
    if (!resolved.length) return result(bound, action, 'deny', 'dns-private-address', subject);
    const verdicts = onScheme.map((d) => {
      if (d.addresses && !resolved.every((a) => d.addresses.includes(a))) return 'dns-changed';
      if (!d.allowPrivateResolution && resolved.some((a) => classifyAddress(a) !== 'public')) return 'dns-private-address';
      return 'ok';
    });
    if (!verdicts.includes('ok')) return result(bound, action, 'deny', verdicts.includes('dns-changed') ? 'dns-changed' : 'dns-private-address', subject);
  }
  return result(bound, action, 'allow', 'allowed', subject);
}

// ---------------------------------------------------------------- tools, delegation

function decideTool(bound, action) {
  const subject = typeof action.tool === 'string' ? action.tool : '(not a string)';
  if (typeof action.tool !== 'string' || !bound.manifest.tools.includes(action.tool)) return result(bound, action, 'deny', 'tool-not-declared', subject);
  return result(bound, action, 'allow', 'allowed', subject);
}

function decideDelegation(bound, action) {
  const d = bound.manifest.delegation;
  const depth = Number.isInteger(action.depth) && action.depth >= 0 ? action.depth : 0;
  const subject = `delegation at depth ${depth}`;
  if (!d.allow) return result(bound, action, 'deny', 'delegation-not-allowed', subject);
  if (depth >= d.maxDepth) return result(bound, action, 'deny', 'delegation-depth', subject);
  if (action.request !== undefined) {
    const child = deriveChild(bound.manifest, action.request);
    if (!child.ok) return result(bound, action, 'deny', 'scope-expansion', subject);
  }
  return result(bound, action, 'allow', 'allowed', subject);
}

/**
 * @param {{manifest: object, binding: object}} bound   from `bindManifest`
 * @param {object} action  `{ kind, ... }`; kind is one of CAPABILITY_KINDS
 * @param {object} ctx
 * @param {{taskId:string, revision:string, policyVersion:number}} ctx.binding  what the caller believes it is acting for
 * @param {string[]} [ctx.protectedPaths]  paths no task may touch, whatever the manifest says
 * @param {string[]} [ctx.canaries]        values that must never appear in an argument
 */
export function decide(bound, action, ctx = {}) {
  if (!bound || !bound.manifest || !bound.binding) return result(bound, action, 'deny', 'invalid-manifest', '(no manifest)');
  const b = ctx.binding;
  const bb = bound.binding;
  if (!b || b.taskId !== bb.taskId || b.revision !== bb.revision || b.policyVersion !== bb.policyVersion) {
    return result(bound, action, 'deny', 'binding-mismatch', '(binding)');
  }
  if (!action || typeof action !== 'object' || Array.isArray(action) || !CAPABILITY_KINDS.includes(action.kind)) {
    return result(bound, action, 'deny', 'unknown-action', typeof action?.kind === 'string' ? action.kind : '(no kind)');
  }
  try {
    switch (action.kind) {
      case 'filesystem-read':
      case 'filesystem-write': return decideFilesystem(bound, action, ctx);
      case 'command': return decideCommand(bound, action, ctx);
      case 'network': return decideNetwork(bound, action);
      case 'tool': return decideTool(bound, action);
      case 'delegation': return decideDelegation(bound, action);
      default: return result(bound, action, 'deny', 'unknown-action', action.kind);
    }
  } catch {
    // A decision never throws. An unexpected failure is a denial.
    return result(bound, action, 'deny', 'invalid-manifest', '(decision failed)');
  }
}
