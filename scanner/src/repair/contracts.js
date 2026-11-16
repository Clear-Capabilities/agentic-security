// Repair contracts (verified-remediation PRD FR-04, section 6.2): what a repair must establish, as declarative obligations over
// registered verifier operations.
//
// Inputs: a normalized finding, an operator-declared application profile (profile.js) and the exact source snapshot. Output: a closed,
// versioned RepairContract (schemas.js) whose identity covers the source, the configuration and dependency digests, the profile's policy
// facts, the oracle logic each obligation runs on, and the edit scope. Identical inputs give an identical contract id (no clock, no
// randomness); a change to any of them gives a different one (AC-04.1, AC-04.2).
//
// The family decides the required obligations, not which checks happen to be available (FR-04):
//   sql-injection          the declared untrusted inputs carry attack probes that must reach no planted secret (development set, plus
//                          a sealed held-out set), the declared legitimate values must still return their expected data, and legitimate
//                          values the original mishandles (a quote in a name) must work after the repair (AC-04.3). Behavioural
//                          equivalence is never required of attacker input (AC-04.7).
//   object-authorization   the full actor matrix: for every declared object and operation, each actor (owner, other member, another
//                          tenant, admin, anonymous) gets the outcome the declared policy gives it. A denied read must not disclose the
//                          object's planted secret; a denied update must not change durable state, whatever the HTTP status (a 403 that
//                          still wrote is a violation); allowed actors must keep working (AC-04.4).
// Project tests, the rescan and the footprint run through the central verifier as the `project-tests` obligation.
//
// A missing prerequisite (no seed secret to protect, no read operation, an application file that does not exist) makes the contract
// `blocked` with the reason: it is never weakened into a contract that could pass (AC-04.6).
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { digestOf } from '../posture/assurance/identity.js';
import { getOracle } from '../posture/oracles/registry.js';
import { SCHEMAS, SCHEMA_VERSION, OBLIGATION_KINDS, contractIdOf, contractDigestOf, validateContract } from './schemas.js';
import { validateProfile, policyAllows } from './profile.js';
import { isPrivateAddress } from '../posture/oracles/app-adapters.js';

export const CONTRACT_BUILDER_VERSION = '1';

/**
 * Per-profile support (verified-remediation PRD FR-12, AC-12.5, M3-06): what has been executed, per family, runtime and platform, and
 * the test that executes it. macOS and Linux are separate columns; one platform's execution never qualifies the other. `declared` means
 * the profile validates and a contract builds, but no test executes that combination. Printed by `repair plan`; the reference page's
 * "Profile support" table is held to this list by the contract test.
 */
export const PROFILE_SUPPORT = Object.freeze([
  { family: 'sql-injection', runtime: 'node', macos: 'integration-tested', linux: 'blocked', recipe: 'sql-parameterize-template', evidence: 'scanner/test/repair/repair-workflow.test.js' },
  { family: 'sql-injection', runtime: 'python', macos: 'integration-tested', linux: 'blocked', recipe: null, evidence: 'scanner/test/repair/repair-workflow.test.js' },
  { family: 'object-authorization', runtime: 'node', macos: 'integration-tested', linux: 'blocked', recipe: null, evidence: 'scanner/test/repair/repair-workflow.test.js' },
  { family: 'object-authorization', runtime: 'python', macos: 'declared', linux: 'blocked', recipe: null, evidence: null },
  { family: 'ssrf', runtime: 'node', macos: 'integration-tested', linux: 'blocked', recipe: null, evidence: 'scanner/test/repair/repair-workflow.test.js' },
  { family: 'path-traversal', runtime: 'node', macos: 'integration-tested', linux: 'blocked', recipe: 'path-realpath-containment', evidence: 'scanner/test/repair/repair-workflow.test.js' },
  { family: 'password-storage', runtime: 'node', macos: 'integration-tested', linux: 'blocked', recipe: null, evidence: 'scanner/test/repair/repair-workflow.test.js' },
  { family: 'password-storage', runtime: 'python', macos: 'declared', linux: 'blocked', recipe: null, evidence: null },
]);

/** The support row for a contract's family and runtime, or null (an unsupported combination is refused when the profile validates). */
export const supportFor = (family, runtime) => PROFILE_SUPPORT.find((s) => s.family === family && s.runtime === (runtime || 'node')) || null;

// Attack probes for a value placed in a SQL string literal. Split once, statically: the development set feeds back to candidate
// generation; the sealed set is run only on a candidate that passed everything else, and its content never leaves the coordinator.
const SQL_PROBES = Object.freeze({
  development: ["x' OR '1'='1", "x' OR 1=1 --"],
  sealed: ["zz' OR 'a'='a' --", "') OR ('1'='1", 'x" OR "1"="1'],
});

const DEFAULT_EDIT_BUDGET = Object.freeze({ maxFiles: 3, maxEditedLines: 100 });
// Paths a candidate may never touch, whatever the profile says: the verifier's own state, version control, dependency trees and the
// project's test and runner configuration (a candidate cannot weaken the checks that judge it).
export const PROTECTED_PATTERNS = Object.freeze([
  '.agentic-security/**', '.git/**', 'node_modules/**', '**/*.test.*', '**/*.spec.*', 'test/**', 'tests/**', '__tests__/**',
  'package.json', 'package-lock.json', 'jest.config.*', 'vitest.config.*', '.mocharc*', '**/__oracle_*',
]);

const fill = (tpl, map, { encode }) => tpl.replace(/\{\{(value|id)\}\}/g, (_, k) => (encode ? encodeURIComponent(String(map[k])) : String(map[k])));
const fillBody = (body, map) => (body === undefined ? undefined : JSON.parse(JSON.stringify(body), (k, v) => (typeof v === 'string' ? fill(v, map, { encode: false }) : v)));
const reqOf = (r, actor, map) => ({ method: r.method, path: fill(r.path, map, { encode: true }), headers: { ...(actor?.headers || {}) }, ...(r.body !== undefined ? { body: fillBody(r.body, map) } : {}) });

/** Read the application files and the configuration that can change behaviour. Never follows a link out of the root. */
export function snapshotSource(root, profile) {
  const files = {}; const missing = [];
  const realRoot = fs.realpathSync(root);
  for (const rel of profile.application.files) {
    const abs = path.resolve(realRoot, rel);
    try {
      const st = fs.lstatSync(abs);
      if (!st.isFile() || st.isSymbolicLink() || !abs.startsWith(realRoot + path.sep)) { missing.push(rel); continue; }
      files[rel] = fs.readFileSync(abs, 'utf8');
    } catch { missing.push(rel); }
  }
  const configDigests = {};
  for (const rel of ['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', '.nvmrc']) {
    try { configDigests[rel] = digestOf(fs.readFileSync(path.join(realRoot, rel), 'utf8')); } catch { /* absent */ }
  }
  let python = null;
  if (profile.application.runtime === 'python') {
    for (const p of ['/usr/bin/python3', '/opt/homebrew/bin/python3', '/usr/local/bin/python3']) {
      try { if (fs.statSync(p).isFile()) { python = String(spawnSync(p, ['-I', '-c', 'import sys, sqlite3; print(sys.version.split()[0], sqlite3.sqlite_version)'], { encoding: 'utf8', timeout: 5000 }).stdout || '').trim() || null; break; } } catch { /* next */ }
    }
  }
  configDigests.runtime = digestOf({ node: process.versions.node, sqlite: process.versions.sqlite || null, ...(profile.application.runtime === 'python' ? { python } : {}) });
  return { files, missing, sourceDigest: digestOf(files), configDigests };
}

function obligation(kind, id, inputs, { required = true, origin = 'generated-from-profile', scope }) {
  const k = OBLIGATION_KINDS[kind];
  const o = getOracle(k.oracle);
  return {
    id, kind, required, oracleId: k.oracle, oracleVersion: o.version, oracleLogicDigest: o.logicDigest,
    scope, baselineExpectation: k.expectBaseline, patchedExpectation: k.expectPatched, evidenceOrigin: origin,
    inputs, inputsDigest: digestOf(inputs), description: k.description,
  };
}

const appInputs = (profile, requests, stateChecks = [], extra = {}) => ({
  ...(profile.application.runtime === 'python' ? { runtime: 'python' } : {}),
  export: profile.application.export, schemaSql: profile.database.schemaSql, seed: profile.database.seed, requests, stateChecks, ...extra,
});

function seedHasSecret(profile, name) {
  return JSON.stringify(profile.database.seed).includes(`{{secret:${name}}}`);
}

function sqlObligations(profile, actors, blocked) {
  const out = [];
  const controls = []; const after = []; const dev = []; const sealed = [];
  for (const inp of profile.sql.inputs) {
    const actor = actors[inp.actor];
    for (const s of inp.protectedSecrets) if (!seedHasSecret(profile, s)) blocked.push(`sql input ${inp.id}: the seed plants no {{secret:${s}}} value, so a disclosure could not be observed`);
    inp.benign.forEach((b, j) => {
      const r = { id: `${inp.id.replace(/-/g, '_')}_benign_${j}`, role: 'control', ...reqOf(inp, actor, { value: b.value }), expect: { status: b.expectStatus || [200], bodyIncludes: b.expectIncludes } };
      (b.originalMishandles ? after : controls).push(r);
    });
    const probe = (set, list) => SQL_PROBES[set].forEach((v, j) => list.push({ id: `${inp.id.replace(/-/g, '_')}_${set}_${j}`, role: 'attack', ...reqOf(inp, actor, { value: v }), forbid: { secrets: [...inp.protectedSecrets] }, probe: v }));
    probe('development', dev); probe('sealed', sealed);
  }
  if (!controls.length) blocked.push('sql: no benign value is declared that the original serves correctly; mark only quoted values originalMishandles');
  const stateChecks = (profile.sql.stateChecks || []).map((c) => ({ ...c, role: 'attack' }));
  const strip = (r) => { const { probe, ...rest } = r; return rest; };
  if (controls.length) {
    out.push(obligation('app-attack-blocked', 'sql-attacks-development', appInputs(profile, [...controls, ...dev.map(strip)], stateChecks), { scope: 'declared untrusted inputs, development probe set' }));
    out.push(obligation('app-attack-sealed', 'sql-attacks-sealed', appInputs(profile, [...controls, ...sealed.map(strip)], stateChecks), { scope: 'declared untrusted inputs, sealed probe set (never fed back)' }));
    out.push(obligation('app-behaviour-preserved', 'sql-legitimate-queries', appInputs(profile, controls), { scope: 'declared legitimate values' }));
  }
  if (after.length) out.push(obligation('app-behaviour-after', 'sql-legitimate-quoted-values', appInputs(profile, after), { scope: 'legitimate values the original mishandles' }));
  return out;
}

/** Controls (and the after-repair controls) from an input's declared legitimate values. Shared by every value-input family. */
function benignRequests(inp, actor, controls, after) {
  inp.benign.forEach((b, j) => {
    const r = { id: `${inp.id.replace(/-/g, '_')}_benign_${j}`, role: 'control', ...reqOf(inp, actor, { value: b.value }), expect: { status: b.expectStatus || [200], bodyIncludes: b.expectIncludes } };
    (b.originalMishandles ? after : controls).push(r);
  });
}

/** The obligations of a value-input family from its development and sealed attack values. */
function valueFamilyObligations(family, profile, actors, blocked, { probes, forbid, extra, scopeNoun }) {
  const out = []; const controls = []; const after = []; const dev = []; const sealed = [];
  for (const inp of profile[family].inputs) {
    const actor = actors[inp.actor];
    benignRequests(inp, actor, controls, after);
    for (const set of ['development', 'sealed']) probes[set].forEach((v, j) => (set === 'sealed' ? sealed : dev).push({ id: `${inp.id.replace(/-/g, '_')}_${set}_${j}`, role: 'attack', ...reqOf(inp, actor, { value: v }), forbid: forbid(v) }));
  }
  if (!controls.length) blocked.push(`${family}: no legitimate value is declared that the original serves correctly`);
  if (!dev.length) blocked.push(`${family}: the declaration yields no attack value, so no forbidden effect could be observed`);
  if (blocked.length) return out;
  out.push(obligation('app-attack-blocked', `${family}-attacks-development`, appInputs(profile, [...controls, ...dev], [], extra), { scope: `${scopeNoun}, development attack set` }));
  if (sealed.length) out.push(obligation('app-attack-sealed', `${family}-attacks-sealed`, appInputs(profile, [...controls, ...sealed], [], extra), { scope: `${scopeNoun}, sealed attack set (never fed back)` }));
  out.push(obligation('app-behaviour-preserved', `${family}-legitimate-requests`, appInputs(profile, controls, [], extra), { scope: 'declared legitimate values' }));
  if (after.length) out.push(obligation('app-behaviour-after', `${family}-legitimate-after`, appInputs(profile, after, [], extra), { scope: 'legitimate values the original mishandles' }));
  return out;
}

const SECRET_NAMES = (text) => [...String(text).matchAll(/\{\{secret:([a-z][a-z0-9-]{0,31})\}\}/g)].map((m) => m[1]);
const ipv4Int = (a) => a.split('.').reduce((n, o) => n * 256 + Number(o), 0);

/**
 * SSRF attack values, generated from the declared network. A host is forbidden when the policy does not permit every address it can
 * resolve to (an allowlist names the approved hosts; public-only forbids loopback, private, link-local and the other internal ranges,
 * so a host that rebinds from a public to a private address is forbidden). Development: each forbidden host by name and by address,
 * and every approved host's declared redirect that leaves the approved set. Sealed: the same destinations spelled differently
 * (decimal and IPv4-mapped IPv6 addresses, upper case with a trailing dot, an approved host as user information).
 */
function ssrfProbes(s) {
  const permittedAddr = (h, a) => (s.policy === 'public-only' ? !isPrivateAddress(a) : s.approved.includes(h.name));
  const forbidden = s.hosts.filter((h) => !h.addresses.every((a) => permittedAddr(h, a)));
  const port = (h) => (h.port && h.port !== 80 ? `:${h.port}` : '');
  const pathOf = (h) => h.routes?.[0]?.path || '/';
  const development = []; const sealed = [];
  for (const h of forbidden) {
    development.push(`http://${h.name}${port(h)}${pathOf(h)}`);
    const v4 = h.addresses.find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a) && !permittedAddr(h, a));
    if (v4) {
      development.push(`http://${v4}${port(h)}${pathOf(h)}`);
      sealed.push(`http://${ipv4Int(v4)}${port(h)}${pathOf(h)}`, `http://[::ffff:${v4}]${port(h)}${pathOf(h)}`);
    }
    sealed.push(`http://${h.name.toUpperCase()}.${port(h)}${pathOf(h)}`);
    if (s.approved[0]) sealed.push(`http://${s.approved[0]}@${h.name}${port(h)}${pathOf(h)}`);
  }
  const forbiddenNames = new Set(forbidden.map((h) => h.name));
  const forbiddenAddrs = new Set(forbidden.flatMap((h) => h.addresses));
  for (const h of s.hosts.filter((x) => !forbiddenNames.has(x.name))) {
    for (const r of h.routes || []) {
      const loc = r.status >= 300 && r.status < 400 ? Object.entries(r.headers || {}).find(([k]) => k.toLowerCase() === 'location')?.[1] : null;
      if (!loc) continue;
      let target; try { target = new URL(loc, `http://${h.name}`); } catch { continue; }
      const host = target.hostname.replace(/^\[|\]$/g, '');
      if (forbiddenNames.has(host) || forbiddenAddrs.has(host)) development.push(`http://${h.name}${port(h)}${r.path}`);
    }
  }
  const secrets = [...new Set(forbidden.flatMap((h) => (h.routes || []).flatMap((r) => SECRET_NAMES(r.body || ''))))];
  return { development: [...new Set(development)], sealed: [...new Set(sealed)].filter((v) => !development.includes(v)), secrets, forbidden: forbidden.map((h) => h.name) };
}

function ssrfObligations(profile, actors, blocked) {
  const s = profile.ssrf;
  const p = ssrfProbes(s);
  if (!p.forbidden.length) blocked.push('ssrf: every declared host is permitted by the policy, so there is no forbidden destination to test');
  const network = { policy: s.policy, approved: s.approved, hosts: s.hosts };
  return valueFamilyObligations('ssrf', profile, actors, blocked, {
    probes: p, forbid: () => ({ ...(p.secrets.length ? { secrets: [...p.secrets] } : {}), connections: true }), extra: { network }, scopeNoun: 'declared untrusted URL inputs',
  });
}

/**
 * Path traversal attack values, generated from the declared tree. Every file outside the allowed root that plants a secret is a
 * target. Development: the relative escape, the absolute path, and every declared link inside the root that points outside it.
 * Sealed: an escape through a subdirectory and a `./` prefix (each must also disclose on the original, or it is quarantined).
 */
function traversalProbes(f) {
  const root = f.root.replace(/\/$/, '');
  const inside = (rel) => rel === root || rel.startsWith(`${root}/`);
  const development = []; const sealed = []; const secrets = new Set();
  const subdir = Object.keys(f.tree).filter(inside).map((r) => r.slice(root.length + 1).split('/')).find((parts) => parts.length > 1)?.[0] || null;
  for (const [rel, content] of Object.entries(f.tree)) {
    if (inside(rel)) continue;
    const names = SECRET_NAMES(content);
    if (!names.length) continue;
    names.forEach((n) => secrets.add(n));
    const up = path.posix.relative(root, rel);
    // the file, its absolute path, and its directory (for an application that appends a file name to the request value)
    development.push(up, `{{fs:abs}}/${rel}`, path.posix.dirname(up));
    for (const [link, target] of Object.entries(f.links || {})) {
      if (!inside(link)) continue;
      const dest = path.posix.normalize(path.posix.join(path.posix.dirname(link), target));
      if (inside(dest) || !(rel === dest || rel.startsWith(`${dest}/`))) continue;
      development.push(`${path.posix.relative(root, link)}/${path.posix.relative(dest, rel)}`);
    }
    const dir = path.posix.dirname(up);
    sealed.push(`./${up}`, `./${dir}`);
    if (subdir) sealed.push(`${subdir}/../${up}`, `${subdir}/../${dir}`);
  }
  return { development: [...new Set(development)], sealed: [...new Set(sealed)], secrets: [...secrets] };
}

function filesystemObligations(profile, actors, blocked) {
  const f = profile.filesystem;
  const p = traversalProbes(f);
  if (!p.secrets.length) blocked.push('filesystem: no file outside the allowed root plants a {{secret:<name>}} value, so a disclosure could not be observed');
  const files = { root: f.root, tree: f.tree, ...(f.links ? { links: f.links } : {}) };
  return valueFamilyObligations('filesystem', profile, actors, blocked, {
    probes: p, forbid: () => ({ secrets: [...p.secrets] }), extra: { files }, scopeNoun: 'declared untrusted path inputs',
  });
}

/**
 * Password storage: the stored credential is judged by the verifier, not by the application's own answers. New users register (two
 * with the same password, to show salting) and their stored values must not be plaintext or a fast digest and must recompute under
 * the approved format; legitimate logins (legacy users included, wrong passwords refused) must keep working; and a legacy user's
 * stored value must be migrated to the approved format after a successful login.
 */
function passwordObligations(profile, actors, blocked) {
  const w = profile.passwords;
  const actor = actors[w.actor];
  const T = `SELECT ${w.hashColumn} FROM ${w.table} WHERE ${w.userColumn} = ?`;
  const fillCred = (tpl, user, password) => {
    const f = (s) => s.replace(/\{\{user\}\}/g, user).replace(/\{\{password\}\}/g, password);
    const enc = (s) => s.replace(/\{\{user\}\}/g, encodeURIComponent(user)).replace(/\{\{password\}\}/g, encodeURIComponent(password));
    return { method: tpl.method, path: enc(tpl.path), headers: { ...(actor?.headers || {}) }, ...(tpl.body !== undefined ? { body: JSON.parse(JSON.stringify(tpl.body), (k, v) => (typeof v === 'string' ? f(v) : v)) } : {}) };
  };
  const reg = (id, user, pw) => ({ id, role: 'control', ...fillCred(w.register, user, pw), expect: { status: w.register.expectStatus || [200, 201] } });
  const login = (id, user, pw, ok) => ({ id, role: 'control', ...fillCred(w.login, user, pw), expect: { status: ok ? (w.login.expectStatus || [200]) : w.login.denyStatus } });
  const approved = { format: 'scrypt', minN: w.approved.minN, minR: w.approved.minR, minSaltBytes: w.approved.minSaltBytes, minKeyBytes: w.approved.minKeyBytes };
  const NEW_PW = '{{secret:new-password}}';
  const legacySeed = w.legacy.users.map((u) => ({ sql: `INSERT INTO ${w.table} (${w.userColumn}, ${w.hashColumn}) VALUES (?, ?)`, params: [u.name, crypto.createHash(w.legacy.digest).update(u.password, 'utf8').digest('hex')] }));
  const withSeed = (inputs) => ({ ...inputs, seed: [...inputs.seed, ...legacySeed] });
  const out = [];
  const storage = [
    reg('register_new_a', 'new-user-a', NEW_PW), reg('register_new_b', 'new-user-b', NEW_PW),
    login('login_new_a', 'new-user-a', NEW_PW, true), login('login_new_a_wrong', 'new-user-a', 'not-the-password', false),
  ];
  const storageChecks = [
    { id: 'stored_new_a', role: 'attack', sql: T, params: ['new-user-a'], credential: { password: NEW_PW, properties: ['not-plaintext', 'not-fast-digest', 'approved-format'], approved } },
    { id: 'stored_new_b', role: 'attack', sql: T, params: ['new-user-b'], credential: { password: NEW_PW, properties: ['not-plaintext', 'not-fast-digest', 'approved-format', 'distinct-from'], distinctFrom: 'stored_new_a', approved } },
  ];
  out.push(obligation('app-attack-blocked', 'password-storage', withSeed(appInputs(profile, storage, storageChecks)), { scope: 'stored credentials of newly registered users: not plaintext, not a fast digest, salted, recomputed under the approved format' }));
  const legit = [];
  w.legacy.users.forEach((u, i) => { legit.push(login(`login_legacy_${i}`, u.name, u.password, true), login(`login_legacy_${i}_wrong`, u.name, `${u.password}-wrong`, false)); });
  legit.push(reg('register_new_c', 'new-user-c', 'another-pass-1'), login('login_new_c', 'new-user-c', 'another-pass-1', true));
  out.push(obligation('app-behaviour-preserved', 'password-legitimate-logins', withSeed(appInputs(profile, legit)), { scope: 'legacy and new users log in with the right password and are refused with a wrong one' }));
  const migrate = w.legacy.users.map((u, i) => login(`login_legacy_${i}_migrate`, u.name, u.password, true));
  const migrated = w.legacy.users.map((u, i) => ({ id: `migrated_legacy_${i}`, role: 'control', sql: T, params: [u.name], credential: { password: u.password, properties: ['not-fast-digest', 'approved-format'], approved } }));
  out.push(obligation('app-behaviour-after', 'password-legacy-migrated', withSeed(appInputs(profile, migrate, migrated)), { scope: 'a legacy user\'s stored value is in the approved format after a successful login' }));
  void blocked;
  return out;
}

function authzObligations(profile, actors, blocked) {
  const z = profile.authorization;
  const out = [];
  const reads = []; const readControls = []; const writeAttacks = []; const writeControls = []; const attackChecks = []; const controlChecks = [];
  const matrix = [];
  for (const obj of z.objects) {
    if (!seedHasSecret(profile, obj.secret)) blocked.push(`object ${obj.id}: the seed plants no {{secret:${obj.secret}}} value, so a disclosure could not be observed`);
    let lastWriter = null; const deniedWriters = [];
    for (const op of z.operations) {
      for (const actor of Object.values(actors)) {
        const allowed = policyAllows(z.policy, actor, obj, actors);
        const rid = `${op.id}_${obj.id}_${actor.id}`.replace(/-/g, '_');
        matrix.push({ object: obj.id, operation: op.id, effect: op.effect, actor: actor.id, role: actor.role ?? null, tenant: actor.tenant ?? null, owner: obj.owner, allowed });
        if (op.effect === 'read') {
          if (allowed) readControls.push({ id: rid, role: 'control', ...reqOf(op, actor, { id: obj.rowId }), expect: { status: op.expectStatus || [200], bodyIncludes: [`{{secret:${obj.secret}}}`] } });
          else reads.push({ id: rid, role: 'attack', ...reqOf(op, actor, { id: obj.rowId }), forbid: { secrets: [obj.secret] } });
        } else {
          const value = `${allowed ? 'written' : 'forged'}-by-${actor.id}-${obj.id}`;
          const r = reqOf(op, actor, { id: obj.rowId, value });
          if (allowed) { writeControls.push({ id: rid, role: 'control', ...r, expect: { status: op.expectStatus || [200, 201, 204] } }); lastWriter = value; }
          else { writeAttacks.push({ id: rid, role: 'attack', ...r, forbid: {} }); deniedWriters.push(rid); }
        }
      }
    }
    // One check per object: its content is still the planted value after every denied write. Several denied writes to one object would
    // overwrite each other, so a per-write check would see only the last; the object-level check sees any of them. `guards` names the
    // requests it judges (verifier-side metadata, never sent to the application).
    if (deniedWriters.length) attackChecks.push({ id: `${obj.id.replace(/-/g, '_')}_unchanged`, role: 'attack', sql: `SELECT count(*) AS n FROM ${z.table} WHERE ${z.idColumn} = ? AND ${z.contentColumn} = ?`, params: [obj.rowId, `{{secret:${obj.secret}}}`], expect: [{ n: 1 }], guards: deniedWriters });
    if (lastWriter) controlChecks.push({ id: `${obj.id.replace(/-/g, '_')}_written`, role: 'control', sql: `SELECT count(*) AS n FROM ${z.table} WHERE ${z.idColumn} = ? AND ${z.contentColumn} = ?`, params: [obj.rowId, lastWriter], expect: [{ n: 1 }] });
  }
  for (const c of z.controls || []) {
    writeControls.push({ id: `control_${c.id.replace(/-/g, '_')}`, role: 'control', ...reqOf(c, actors[c.actor], {}), expect: { status: c.expectStatus || [200], ...(c.expectIncludes ? { bodyIncludes: c.expectIncludes } : {}) } });
  }
  if (!readControls.length) blocked.push('authorization: no actor is allowed to read any declared object, so the application cannot be shown to work');
  if (!reads.length && !writeAttacks.length) blocked.push('authorization: the policy allows every actor everything, so there is nothing to deny');
  if (blocked.length) return { obligations: out, matrix };
  // The security run holds every denied attempt plus the allowed READS only: an allowed write would overwrite the state a denied write
  // must be judged by. Allowed writes are judged in the behaviour run. Order: allowed reads, denied reads, then denied writes, so a
  // write that succeeds on a vulnerable revision cannot make an earlier legitimate read look broken.
  out.push(obligation('app-attack-blocked', 'authz-denied-actors', appInputs(profile, [...readControls, ...reads, ...writeAttacks], attackChecks), { scope: 'every declared actor x object x operation the policy denies' }));
  out.push(obligation('app-behaviour-preserved', 'authz-allowed-workflows', appInputs(profile, [...readControls, ...writeControls], controlChecks), { scope: 'every declared actor x object x operation the policy allows' }));
  return { obligations: out, matrix };
}

/**
 * @param {{finding:object, profile:object, profileOrigin:'repository-file'|'operator-profile-outside-repository', source:{files,sourceDigest,configDigests,missing}, commit?:string|null, family:'sql-injection'|'object-authorization', editBudget?:{maxFiles:number,maxEditedLines:number}}} o
 * @returns {{contract:object|null, blocked:string[], problems:string[], matrix?:object[]}}
 */
export function buildContract(o) {
  const problems = validateProfile(o.profile);
  if (problems.length) return { contract: null, blocked: [], problems };
  const profile = o.profile;
  const blocked = [];
  for (const m of o.source.missing || []) blocked.push(`application file ${m} is missing or not a regular file`);
  const actors = Object.fromEntries(profile.actors.map((a) => [a.id, a]));
  let obligations; let matrix = null;
  if (o.family === 'sql-injection') {
    if (!profile.sql) return { contract: null, blocked: ['the profile has no sql section for a sql-injection finding'], problems: [] };
    obligations = sqlObligations(profile, actors, blocked);
  } else if (o.family === 'object-authorization') {
    if (!profile.authorization) return { contract: null, blocked: ['the profile has no authorization section for an authorization finding'], problems: [] };
    ({ obligations, matrix } = authzObligations(profile, actors, blocked));
  } else if (o.family === 'ssrf') {
    if (!profile.ssrf) return { contract: null, blocked: ['the profile has no ssrf section for a server-side request forgery finding'], problems: [] };
    obligations = ssrfObligations(profile, actors, blocked);
  } else if (o.family === 'password-storage') {
    if (!profile.passwords) return { contract: null, blocked: ['the profile has no passwords section for a password storage finding'], problems: [] };
    obligations = passwordObligations(profile, actors, blocked);
  } else if (o.family === 'path-traversal') {
    if (!profile.filesystem) return { contract: null, blocked: ['the profile has no filesystem section for a path traversal finding'], problems: [] };
    obligations = filesystemObligations(profile, actors, blocked);
  } else return { contract: null, blocked: [`family ${o.family} has no registered repair contract in this milestone`], problems: [] };
  obligations.push({
    id: 'central-verifier', kind: 'project-tests', required: true, oracleId: null, oracleVersion: null, oracleLogicDigest: null,
    scope: profile.tests ? `rescan, new-finding delta, footprint and the per-test delta of '${profile.tests.command}'` : 'rescan, new-finding delta and footprint; no project test command was declared, so the test leg is not run and the record says so',
    baselineExpectation: null, patchedExpectation: 'passed', evidenceOrigin: 'registered-family', description: OBLIGATION_KINDS['project-tests'].description,
  });
  const approved = o.profileOrigin === 'operator-profile-outside-repository' && profile.approval;
  const policyFacts = [{
    id: 'application-profile', origin: o.profileOrigin, approval: approved ? 'approved' : 'declared',
    digest: digestOf({ actors: profile.actors, sql: profile.sql ?? null, authorization: profile.authorization ?? null, ssrf: profile.ssrf ?? null, filesystem: profile.filesystem ?? null, passwords: profile.passwords ?? null, database: profile.database }),
    ...(approved ? { approvedBy: profile.approval.approvedBy } : {}),
  }];
  const knownUnknowns = [
    'only the declared requests, actors, objects and state checks are verified; behaviour outside them is not observed',
    'no call-graph slice beyond the declared application files is computed: callers outside them are not exercised',
    'requests run one at a time in a single process; no concurrency is exercised',
  ];
  if (!approved) knownUnknowns.push('the profile facts are declared, not approved: a verified result holds for the declared contract only');
  if (!profile.tests) knownUnknowns.push('no project test command was declared');
  const findingFile = o.finding?.locations?.[0]?.file || o.finding?.file || null;
  const contract = {
    schema: SCHEMAS.contract, schemaVersion: SCHEMA_VERSION,
    family: o.family,
    findingRefs: [o.finding.findingId || o.finding.stableId || o.finding.id],
    rootCauseGroup: digestOf({ family: o.family, file: findingFile }),
    sourceCommit: o.commit ?? null, sourceDigest: o.source.sourceDigest, configDigests: o.source.configDigests,
    profile: { application: profile.application, database: { engine: profile.database.engine }, runtime: profile.application.runtime || 'node', builder: CONTRACT_BUILDER_VERSION, ...(matrix ? { actorMatrix: matrix } : {}) },
    obligations, policyFacts,
    editScope: { allowed: [...profile.application.files], prohibited: [...PROTECTED_PATTERNS], ...(o.editBudget || DEFAULT_EDIT_BUDGET) },
    executionPolicy: { execution: 'trust-boundary', network: 'denied', model: 'none-unless-operator-configured' },
    knownUnknowns,
  };
  contract.contractId = contractIdOf(contract);
  contract.contractDigest = contractDigestOf(contract);
  const v = validateContract(contract);
  if (!v.ok) return { contract: null, blocked, problems: v.errors.map((e) => `${e.path}: ${e.message}`) };
  return { contract, blocked, problems: [], ...(matrix ? { matrix } : {}) };
}

/** The obligations of a contract as a reader sees them: kind, scope, required, oracle. Used by CLI and MCP alike (AC-04.5). */
export function obligationSummary(contract) {
  return contract.obligations.map((o) => ({ id: o.id, kind: o.kind, required: o.required, oracle: o.oracleId ? `${o.oracleId}@${o.oracleVersion}` : 'central-verifier', scope: o.scope, requests: o.inputs?.requests?.length ?? null, stateChecks: o.inputs?.stateChecks?.length ?? null }));
}

export { SQL_PROBES };
