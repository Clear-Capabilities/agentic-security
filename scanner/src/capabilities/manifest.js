// Task capability manifests (X-501).
//
// A manifest is the complete statement of what one task may do: readable and
// writable roots, structured commands, network destinations, tool actions,
// resource limits and whether it may delegate. It is
//
//   deny-by-default   a section that is absent grants nothing; there is no
//                     wildcard that means "everything", and no field whose
//                     default is more permissive than its absence
//   closed-world      an unknown field, an unknown schema version, a relative
//                     path, a wildcard host with no domain behind it or a value
//                     of the wrong type invalidates the whole manifest; nothing
//                     is carried through, ignored or defaulted open
//   bound             to a task id, an exact repository revision and a policy
//                     version, carried as `binding` with the manifest digest, so
//                     a grant made for one task, revision or policy version
//                     cannot be replayed for another (decide.js checks it)
//   monotonic         `deriveChild` builds a child manifest only from a subset
//                     of the parent's grants; anything wider is `SCOPE_EXPANSION`
//                     and no child manifest is produced
//
// Pure data except for `deriveChild`, which compares canonical (symlink-resolved)
// paths so a link inside a granted root cannot widen a child.
import path from 'node:path';
import {
  result, guardObject, checkHeader, checkFields, checkString, checkCommit, isPlainObject,
} from '../posture/assurance/schema-kit.js';
import { digestOf } from '../posture/assurance/identity.js';
import { LIMITS } from '../posture/assurance/config.js';
import { lexicalPath, canonicalPath, isWithin } from './paths.js';
import { normalizeHost } from './address.js';

export const MANIFEST_SCHEMA = 'agentic-security/capability-manifest';
export const MANIFEST_SCHEMA_VERSION = '1.0.0';
export const ARG_MODES = Object.freeze(['exact', 'prefix', 'any']);
export const NETWORK_SCHEMES = Object.freeze(['http', 'https']);
export const MAX_DELEGATION_DEPTH = 8;

const MANIFEST_ALLOWED = [
  'schema', 'schemaVersion', 'taskId', 'parentTaskId', 'repository', 'policyVersion', 'filesystem', 'commands',
  'network', 'tools', 'resources', 'delegation', 'createdAt',
];
const MANIFEST_REQUIRED = ['schema', 'schemaVersion', 'taskId', 'repository', 'policyVersion'];

// Resource limits a manifest can carry. The first three come straight from the
// assurance config (same ranges), the file-size cap is enforced by the sandbox
// prelude, and the last two are CARRIED but never claimed enforced: see
// `RESOURCE_ENFORCEMENT` in runner.js.
export const RESOURCE_RANGES = Object.freeze({
  timeoutMs: { min: LIMITS.timeoutMs.min, max: LIMITS.timeoutMs.max },
  maxOutputBytes: { min: LIMITS.maxOutputBytes.min, max: LIMITS.maxOutputBytes.max },
  maxFileSizeKb: { min: 1, max: 1_048_576 },
  maxProcesses: { min: 1, max: 4096 },
  maxMemoryMiB: { min: LIMITS.maxMemoryMiB.min, max: LIMITS.maxMemoryMiB.max },
});

const TOOL_NAME = /^[A-Za-z0-9_.:-]{1,80}$/;
const MAX_LIST = 256;
const MAX_ARGS = 256;
const MAX_ARG_LEN = 8192;

function checkPathList(ctx, where, list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > MAX_LIST) { ctx.err('BAD_TYPE', where, `must be an array of at most ${MAX_LIST} absolute paths`); return []; }
  const out = [];
  list.forEach((p, i) => {
    const lex = lexicalPath(p);
    if (!lex.ok) { ctx.err('BAD_PATH', `${where}[${i}]`, 'must be an absolute path without NUL bytes'); return; }
    if (lex.dotdot) { ctx.err('BAD_PATH', `${where}[${i}]`, 'must not contain parent-directory segments'); return; }
    if (lex.path === path.sep) { ctx.err('BAD_PATH', `${where}[${i}]`, 'the filesystem root cannot be granted'); return; }
    out.push(lex.path);
  });
  return [...new Set(out)].sort();
}

function checkCommands(ctx, list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > MAX_LIST) { ctx.err('BAD_TYPE', 'commands', `must be an array of at most ${MAX_LIST} entries`); return []; }
  const out = [];
  list.forEach((c, i) => {
    const w = `commands[${i}]`;
    if (!isPlainObject(c)) { ctx.err('BAD_TYPE', w, 'must be an object'); return; }
    for (const k of Object.keys(c)) if (!['executable', 'args', 'interpreter'].includes(k)) ctx.err('UNKNOWN_FIELD', `${w}.${k}`, 'not part of a command entry');
    const lex = lexicalPath(c.executable);
    if (!lex.ok || lex.dotdot) { ctx.err('BAD_PATH', `${w}.executable`, 'must be an absolute path without parent-directory segments'); return; }
    let args = { mode: 'exact', values: [] };
    if (c.args !== undefined) {
      if (!isPlainObject(c.args)) { ctx.err('BAD_TYPE', `${w}.args`, 'must be an object {mode, values}'); return; }
      for (const k of Object.keys(c.args)) if (!['mode', 'values'].includes(k)) ctx.err('UNKNOWN_FIELD', `${w}.args.${k}`, 'not part of args');
      if (!ARG_MODES.includes(c.args.mode)) { ctx.err('UNKNOWN_ENUM', `${w}.args.mode`, `must be one of: ${ARG_MODES.join(', ')}`); return; }
      const values = c.args.values === undefined ? [] : c.args.values;
      const okValues = Array.isArray(values) && values.length <= MAX_ARGS
        && values.every((v) => typeof v === 'string' && v.length <= MAX_ARG_LEN && !v.includes('\0'));
      if (!okValues) { ctx.err('BAD_TYPE', `${w}.args.values`, 'must be an array of plain strings within the size limits'); return; }
      if (c.args.mode === 'any' && values.length) { ctx.err('RULE_VIOLATION', `${w}.args.values`, `mode 'any' takes no values`); return; }
      args = { mode: c.args.mode, values: [...values] };
    }
    let interpreter = null;
    if (c.interpreter !== undefined && c.interpreter !== null) {
      if (c.interpreter !== 'scoped') { ctx.err('UNKNOWN_ENUM', `${w}.interpreter`, `must be 'scoped' when present`); return; }
      if (args.mode !== 'exact') { ctx.err('RULE_VIOLATION', `${w}.interpreter`, `a scoped interpreter must pin its exact arguments (mode 'exact')`); return; }
      interpreter = 'scoped';
    }
    out.push({ executable: lex.path, args, interpreter });
  });
  const key = (c) => `${c.executable}\0${c.args.mode}\0${JSON.stringify(c.args.values)}\0${c.interpreter}`;
  const seen = new Map(out.map((c) => [key(c), c]));
  return [...seen.values()].sort((a, b) => (key(a) < key(b) ? -1 : 1));
}

function checkNetwork(ctx, list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > MAX_LIST) { ctx.err('BAD_TYPE', 'network', `must be an array of at most ${MAX_LIST} entries`); return []; }
  const out = [];
  list.forEach((d, i) => {
    const w = `network[${i}]`;
    if (!isPlainObject(d)) { ctx.err('BAD_TYPE', w, 'must be an object'); return; }
    for (const k of Object.keys(d)) if (!['host', 'port', 'schemes', 'allowPrivateResolution', 'addresses'].includes(k)) ctx.err('UNKNOWN_FIELD', `${w}.${k}`, 'not part of a network entry');
    if (typeof d.host !== 'string') { ctx.err('BAD_TYPE', `${w}.host`, 'must be a string'); return; }
    let wildcard = false;
    let hostText = d.host;
    if (hostText.startsWith('*.')) { wildcard = true; hostText = hostText.slice(2); }
    const h = normalizeHost(hostText);
    if (!h.ok) { ctx.err('BAD_TYPE', `${w}.host`, 'must be a host name, an IP address or a *.domain wildcard'); return; }
    if (wildcard && (h.kind !== 'name' || h.host.split('.').length < 2)) {
      ctx.err('RULE_VIOLATION', `${w}.host`, 'a wildcard needs a registrable domain behind it (*.example.com), never a bare suffix or an address');
      return;
    }
    if (!Number.isInteger(d.port) || d.port < 1 || d.port > 65535) { ctx.err('BAD_TYPE', `${w}.port`, 'must be an integer from 1 to 65535; wildcard ports do not exist'); return; }
    const schemes = d.schemes === undefined ? ['https'] : d.schemes;
    if (!Array.isArray(schemes) || !schemes.length || !schemes.every((s) => NETWORK_SCHEMES.includes(s))) {
      ctx.err('UNKNOWN_ENUM', `${w}.schemes`, `must be a non-empty subset of: ${NETWORK_SCHEMES.join(', ')}`); return;
    }
    if (d.allowPrivateResolution !== undefined && typeof d.allowPrivateResolution !== 'boolean') { ctx.err('BAD_TYPE', `${w}.allowPrivateResolution`, 'must be a boolean'); return; }
    let addresses = null;
    if (d.addresses !== undefined && d.addresses !== null) {
      const ok = Array.isArray(d.addresses) && d.addresses.length > 0 && d.addresses.length <= 32
        && d.addresses.every((a) => { const n = normalizeHost(a); return n.ok && n.kind !== 'name'; });
      if (!ok) { ctx.err('BAD_TYPE', `${w}.addresses`, 'must be a non-empty array of IP addresses'); return; }
      addresses = [...new Set(d.addresses.map((a) => normalizeHost(a).host))].sort();
    }
    out.push({
      host: `${wildcard ? '*.' : ''}${h.host}`, port: d.port, schemes: [...new Set(schemes)].sort(),
      allowPrivateResolution: d.allowPrivateResolution === true, addresses,
    });
  });
  const key = (n) => JSON.stringify(n);
  const seen = new Map(out.map((n) => [key(n), n]));
  return [...seen.values()].sort((a, b) => (key(a) < key(b) ? -1 : 1));
}

function checkResources(ctx, r) {
  if (r === undefined) return {};
  if (!isPlainObject(r)) { ctx.err('BAD_TYPE', 'resources', 'must be an object'); return {}; }
  const out = {};
  for (const [k, v] of Object.entries(r)) {
    const range = RESOURCE_RANGES[k];
    if (!range) { ctx.err('UNKNOWN_FIELD', `resources.${k}`, 'not a known resource limit'); continue; }
    if (!Number.isInteger(v) || v < range.min || v > range.max) { ctx.err('BAD_TYPE', `resources.${k}`, `must be an integer from ${range.min} to ${range.max}`); continue; }
    out[k] = v;
  }
  return out;
}

function checkDelegation(ctx, d) {
  if (d === undefined) return { allow: false, maxDepth: 0 };
  if (!isPlainObject(d)) { ctx.err('BAD_TYPE', 'delegation', 'must be an object'); return { allow: false, maxDepth: 0 }; }
  for (const k of Object.keys(d)) if (!['allow', 'maxDepth'].includes(k)) ctx.err('UNKNOWN_FIELD', `delegation.${k}`, 'not part of delegation');
  if (typeof d.allow !== 'boolean') { ctx.err('BAD_TYPE', 'delegation.allow', 'must be a boolean'); return { allow: false, maxDepth: 0 }; }
  const maxDepth = d.maxDepth === undefined ? (d.allow ? 1 : 0) : d.maxDepth;
  if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > MAX_DELEGATION_DEPTH) { ctx.err('BAD_TYPE', 'delegation.maxDepth', `must be an integer from 0 to ${MAX_DELEGATION_DEPTH}`); return { allow: false, maxDepth: 0 }; }
  if (!d.allow && maxDepth !== 0) { ctx.err('RULE_VIOLATION', 'delegation.maxDepth', 'a task that may not delegate has depth 0'); return { allow: false, maxDepth: 0 }; }
  if (d.allow && maxDepth === 0) { ctx.err('RULE_VIOLATION', 'delegation.maxDepth', 'a task that may delegate needs a depth of at least 1'); return { allow: false, maxDepth: 0 }; }
  return { allow: d.allow, maxDepth };
}

/**
 * Validate and normalize a manifest. Returns `{ ok, errors, manifest }`;
 * `manifest` is the frozen normalized form and is present only when `ok`.
 * Never throws.
 */
export function validateManifest(m) {
  const g = guardObject(m);
  const ctx = g.ctx;
  if (!g.ok) return { ...result(ctx), manifest: null };
  if (!checkHeader(ctx, m, MANIFEST_SCHEMA)) return { ...result(ctx), manifest: null };
  checkFields(ctx, m, MANIFEST_ALLOWED, MANIFEST_REQUIRED);
  checkString(ctx, 'taskId', m.taskId);
  if (m.parentTaskId !== undefined && m.parentTaskId !== null) checkString(ctx, 'parentTaskId', m.parentTaskId);
  if (!isPlainObject(m.repository)) ctx.err('BAD_TYPE', 'repository', 'must be an object {revision}');
  else {
    for (const k of Object.keys(m.repository)) if (k !== 'revision') ctx.err('UNKNOWN_FIELD', `repository.${k}`, 'not part of repository');
    checkCommit(ctx, 'repository.revision', m.repository.revision ?? null, { nullable: false });
  }
  if (!Number.isInteger(m.policyVersion) || m.policyVersion < 1) ctx.err('BAD_TYPE', 'policyVersion', 'must be a positive integer');

  let fsRead = []; let fsWrite = [];
  if (m.filesystem !== undefined) {
    if (!isPlainObject(m.filesystem)) ctx.err('BAD_TYPE', 'filesystem', 'must be an object {read, write}');
    else {
      for (const k of Object.keys(m.filesystem)) if (!['read', 'write'].includes(k)) ctx.err('UNKNOWN_FIELD', `filesystem.${k}`, 'not part of filesystem');
      fsRead = checkPathList(ctx, 'filesystem.read', m.filesystem.read);
      fsWrite = checkPathList(ctx, 'filesystem.write', m.filesystem.write);
    }
  }
  const commands = checkCommands(ctx, m.commands);
  const network = checkNetwork(ctx, m.network);
  let tools = [];
  if (m.tools !== undefined) {
    if (!Array.isArray(m.tools) || m.tools.length > MAX_LIST || !m.tools.every((t) => typeof t === 'string' && TOOL_NAME.test(t))) {
      ctx.err('BAD_TYPE', 'tools', `must be an array of tool names (${TOOL_NAME})`);
    } else tools = [...new Set(m.tools)].sort();
  }
  const resources = checkResources(ctx, m.resources);
  const delegation = checkDelegation(ctx, m.delegation);
  if (ctx.errors.length) return { ...result(ctx), manifest: null };

  const manifest = {
    schema: MANIFEST_SCHEMA, schemaVersion: m.schemaVersion, taskId: m.taskId,
    parentTaskId: m.parentTaskId ?? null,
    repository: { revision: m.repository.revision }, policyVersion: m.policyVersion,
    filesystem: { read: fsRead, write: fsWrite }, commands, network, tools, resources, delegation,
  };
  return { ok: true, errors: [], manifest: deepFreeze(manifest) };
}

function deepFreeze(o) {
  if (o && typeof o === 'object' && !Object.isFrozen(o)) {
    Object.freeze(o);
    for (const v of Object.values(o)) deepFreeze(v);
  }
  return o;
}

/** Digest of the normalized manifest: the policy identity a receipt binds to. */
export function manifestDigest(manifest) {
  return digestOf(manifest);
}

/**
 * Validate and bind. The returned object is what every decision and the runner
 * consume: the normalized manifest plus the binding it is valid for.
 */
export function bindManifest(m) {
  const v = validateManifest(m);
  if (!v.ok) return { ok: false, errors: v.errors, bound: null };
  const bound = {
    manifest: v.manifest,
    binding: Object.freeze({
      taskId: v.manifest.taskId, revision: v.manifest.repository.revision,
      policyVersion: v.manifest.policyVersion, digest: manifestDigest(v.manifest),
    }),
  };
  return { ok: true, errors: [], bound: Object.freeze(bound) };
}

// ---------------------------------------------------------------- inheritance

function canon(p) { return canonicalPath(p) ?? p; }

function rootCovered(child, parentRoots) {
  const c = canon(child);
  return parentRoots.some((r) => {
    const pr = canon(r);
    return isWithin(c, pr) && isWithin(child, r);
  });
}

function hostCovered(child, parent) {
  if (child === parent) return true;
  if (!parent.startsWith('*.')) return false;
  const base = parent.slice(2);
  const c = child.startsWith('*.') ? child.slice(2) : child;
  return c !== base && c.endsWith(`.${base}`);
}

function networkCovered(c, p) {
  if (!hostCovered(c.host, p.host) || c.port !== p.port) return false;
  if (!c.schemes.every((s) => p.schemes.includes(s))) return false;
  if (c.allowPrivateResolution && !p.allowPrivateResolution) return false;
  if (p.addresses) { if (!c.addresses || !c.addresses.every((a) => p.addresses.includes(a))) return false; }
  return true;
}

function commandCovered(c, p) {
  if (canon(c.executable) !== canon(p.executable)) return false;
  if (c.interpreter && !p.interpreter) return false;
  const pv = p.args.values; const cv = c.args.values;
  if (p.args.mode === 'any') return true;
  if (p.args.mode === 'exact') return c.args.mode === 'exact' && cv.length === pv.length && cv.every((v, i) => v === pv[i]);
  // parent prefix
  return c.args.mode !== 'any' && cv.length >= pv.length && pv.every((v, i) => v === cv[i]);
}

/**
 * Build a child task's manifest from a request, only if it is a subset of the
 * parent's. Omitted repository, policy version and resource limits are
 * inherited; anything else that is omitted is simply not granted. Returns
 * `{ ok, errors, manifest }`; on any widening `ok` is false with
 * `SCOPE_EXPANSION` errors and NO manifest, so there is no partial grant.
 *
 * @param {object} parent  a normalized manifest (from `validateManifest`/`bindManifest`)
 * @param {object} request manifest-shaped; `taskId` required
 */
export function deriveChild(parent, request) {
  const errors = [];
  const pv = validateManifest(parent);
  if (!pv.ok) return { ok: false, errors: [{ code: 'RULE_VIOLATION', path: 'parent', message: 'the parent manifest is invalid' }], manifest: null };
  const p = pv.manifest;
  if (!isPlainObject(request)) return { ok: false, errors: [{ code: 'NOT_AN_OBJECT', path: '', message: 'request must be an object' }], manifest: null };

  const merged = { ...request, schema: MANIFEST_SCHEMA, schemaVersion: request.schemaVersion ?? p.schemaVersion };
  merged.parentTaskId = p.taskId;
  if (request.parentTaskId !== undefined && request.parentTaskId !== null && request.parentTaskId !== p.taskId) {
    errors.push({ code: 'SCOPE_EXPANSION', path: 'parentTaskId', message: 'a child names its actual parent' });
  }
  merged.repository = request.repository ?? { revision: p.repository.revision };
  merged.policyVersion = request.policyVersion ?? p.policyVersion;
  if (merged.repository?.revision !== p.repository.revision) errors.push({ code: 'SCOPE_EXPANSION', path: 'repository.revision', message: 'a child is bound to its parent\'s repository revision' });
  if (merged.policyVersion !== p.policyVersion) errors.push({ code: 'SCOPE_EXPANSION', path: 'policyVersion', message: 'a child is bound to its parent\'s policy version' });
  if (request.taskId === p.taskId) errors.push({ code: 'SCOPE_EXPANSION', path: 'taskId', message: 'a child has its own task id' });
  // Inherit limits the parent set; the child may only lower them.
  merged.resources = { ...(p.resources), ...(isPlainObject(request.resources) ? request.resources : {}) };

  const cv = validateManifest(merged);
  if (!cv.ok) return { ok: false, errors: [...errors, ...cv.errors], manifest: null };
  const c = cv.manifest;

  const parentReadable = [...p.filesystem.read, ...p.filesystem.write];
  c.filesystem.read.forEach((r, i) => { if (!rootCovered(r, parentReadable)) errors.push({ code: 'SCOPE_EXPANSION', path: `filesystem.read[${i}]`, message: 'not inside a root the parent may read' }); });
  c.filesystem.write.forEach((r, i) => { if (!rootCovered(r, p.filesystem.write)) errors.push({ code: 'SCOPE_EXPANSION', path: `filesystem.write[${i}]`, message: 'not inside a root the parent may write' }); });
  c.commands.forEach((cmd, i) => { if (!p.commands.some((pc) => commandCovered(cmd, pc))) errors.push({ code: 'SCOPE_EXPANSION', path: `commands[${i}]`, message: 'not covered by a command the parent may run' }); });
  c.network.forEach((n, i) => { if (!p.network.some((pn) => networkCovered(n, pn))) errors.push({ code: 'SCOPE_EXPANSION', path: `network[${i}]`, message: 'not covered by a destination the parent may reach' }); });
  c.tools.forEach((t, i) => { if (!p.tools.includes(t)) errors.push({ code: 'SCOPE_EXPANSION', path: `tools[${i}]`, message: 'not a tool the parent may use' }); });
  for (const [k, v] of Object.entries(c.resources)) {
    if (p.resources[k] !== undefined && v > p.resources[k]) errors.push({ code: 'SCOPE_EXPANSION', path: `resources.${k}`, message: 'higher than the parent limit' });
  }
  if (c.delegation.allow) {
    if (!p.delegation.allow) errors.push({ code: 'SCOPE_EXPANSION', path: 'delegation.allow', message: 'the parent may not delegate' });
    else if (c.delegation.maxDepth > p.delegation.maxDepth - 1) errors.push({ code: 'SCOPE_EXPANSION', path: 'delegation.maxDepth', message: 'must be lower than the parent depth' });
  }
  if (errors.length) return { ok: false, errors, manifest: null };
  return { ok: true, errors: [], manifest: c };
}
