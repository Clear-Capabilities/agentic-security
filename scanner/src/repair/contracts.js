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
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { digestOf } from '../posture/assurance/identity.js';
import { getOracle } from '../posture/oracles/registry.js';
import { SCHEMAS, SCHEMA_VERSION, OBLIGATION_KINDS, contractIdOf, contractDigestOf, validateContract } from './schemas.js';
import { validateProfile, policyAllows } from './profile.js';

export const CONTRACT_BUILDER_VERSION = '1';

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

const appInputs = (profile, requests, stateChecks = []) => ({
  ...(profile.application.runtime === 'python' ? { runtime: 'python' } : {}),
  export: profile.application.export, schemaSql: profile.database.schemaSql, seed: profile.database.seed, requests, stateChecks,
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
  } else return { contract: null, blocked: [`family ${o.family} has no registered repair contract in this milestone`], problems: [] };
  obligations.push({
    id: 'central-verifier', kind: 'project-tests', required: true, oracleId: null, oracleVersion: null, oracleLogicDigest: null,
    scope: profile.tests ? `rescan, new-finding delta, footprint and the per-test delta of '${profile.tests.command}'` : 'rescan, new-finding delta and footprint; no project test command was declared, so the test leg is not run and the record says so',
    baselineExpectation: null, patchedExpectation: 'passed', evidenceOrigin: 'registered-family', description: OBLIGATION_KINDS['project-tests'].description,
  });
  const approved = o.profileOrigin === 'operator-profile-outside-repository' && profile.approval;
  const policyFacts = [{
    id: 'application-profile', origin: o.profileOrigin, approval: approved ? 'approved' : 'declared',
    digest: digestOf({ actors: profile.actors, sql: profile.sql ?? null, authorization: profile.authorization ?? null, database: profile.database }),
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
