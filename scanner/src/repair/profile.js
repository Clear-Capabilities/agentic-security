// The application profile (verified-remediation PRD FR-04, FR-05): how to start the application and what its legitimate behaviour is.
//
// A profile is DECLARED by the operator; nothing here is inferred from code and presented as approved intent. It names the entry module
// and factory, the database schema and seed, the actors (with the request headers that authenticate each), and per family the inputs or
// objects the contract is built from. A profile file inside the repository is repository-supplied input: its facts are recorded as
// `declared`, never `approved`, and it cannot widen execution (it has no field that could: execution is enabled only by the operator).
//
// Closed world: an unknown field is an error. Identifiers that reach SQL (table and column names in generated state checks) must be plain
// identifiers. Validation never throws.
import { isPlainObject } from '../posture/assurance/schema-kit.js';
import { isRelPath } from './schemas.js';

export const PROFILE_SCHEMA = 'agentic-security/repair-profile';
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const SLUG = /^[a-z][a-z0-9-]{0,39}$/;
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
const POLICY_RULES = ['owner', 'same-tenant-admin', 'any-admin'];
const EFFECTS = ['read', 'update'];

const keysOnly = (errs, obj, allowed, where) => { for (const k of Object.keys(obj)) if (!allowed.includes(k)) errs.push(`${where}: unknown field '${k}'`); };

function checkRequestShape(errs, r, where) {
  if (!METHODS.includes(r.method)) errs.push(`${where}.method must be one of ${METHODS.join(', ')}`);
  if (typeof r.path !== 'string' || !r.path.startsWith('/') || r.path.length > 500) errs.push(`${where}.path must start with /`);
  if (r.body !== undefined && !isPlainObject(r.body)) errs.push(`${where}.body must be an object`);
}

/** Problems with a profile; an empty list means it can be used. */
export function validateProfile(p) {
  const errs = [];
  if (!isPlainObject(p)) return ['the profile must be a JSON object'];
  keysOnly(errs, p, ['schema', 'schemaVersion', 'application', 'database', 'actors', 'sql', 'authorization', 'tests', 'approval'], 'profile');
  if (p.schema !== PROFILE_SCHEMA) errs.push(`schema must be '${PROFILE_SCHEMA}'`);
  if (!/^1\.\d+\.\d+$/.test(String(p.schemaVersion))) errs.push('schemaVersion must be 1.x.y');
  const a = p.application;
  if (!isPlainObject(a)) errs.push('application is required');
  else {
    keysOnly(errs, a, ['entry', 'export', 'files', 'runtime'], 'application');
    if (!isRelPath(a.entry)) errs.push('application.entry must be a relative path');
    if (typeof a.export !== 'string' || !IDENT.test(a.export)) errs.push('application.export must be an identifier');
    if (!Array.isArray(a.files) || !a.files.length || a.files.length > 60 || !a.files.every(isRelPath)) errs.push('application.files must list 1 to 60 relative paths');
    else if (!a.files.includes(a.entry)) errs.push('application.files must include the entry');
    if (a.runtime !== undefined && a.runtime !== 'node') errs.push("application.runtime: only 'node' is supported");
  }
  const d = p.database;
  if (!isPlainObject(d)) errs.push('database is required');
  else {
    keysOnly(errs, d, ['engine', 'schemaSql', 'seed'], 'database');
    if (d.engine !== 'sqlite') errs.push("database.engine: only 'sqlite' is supported in this milestone");
    if (typeof d.schemaSql !== 'string' || !d.schemaSql.trim()) errs.push('database.schemaSql is required');
    if (!Array.isArray(d.seed)) errs.push('database.seed must be an array');
  }
  const actorIds = new Set();
  if (!Array.isArray(p.actors) || !p.actors.length) errs.push('actors must be a non-empty array');
  else for (const [i, ac] of p.actors.entries()) {
    if (!isPlainObject(ac)) { errs.push(`actors[${i}] must be an object`); continue; }
    keysOnly(errs, ac, ['id', 'tenant', 'role', 'headers', 'anonymous'], `actors[${i}]`);
    if (typeof ac.id !== 'string' || !SLUG.test(ac.id) || actorIds.has(ac.id)) errs.push(`actors[${i}].id must be a unique slug`);
    actorIds.add(ac.id);
    if (!isPlainObject(ac.headers || {})) errs.push(`actors[${i}].headers must be an object`);
  }
  if (p.sql === undefined && p.authorization === undefined) errs.push('the profile needs a sql or an authorization section');
  if (p.sql !== undefined) {
    if (!isPlainObject(p.sql) || !Array.isArray(p.sql.inputs) || !p.sql.inputs.length) errs.push('sql.inputs must be a non-empty array');
    else {
      keysOnly(errs, p.sql, ['inputs', 'stateChecks'], 'sql');
      for (const [i, inp] of p.sql.inputs.entries()) {
        const w = `sql.inputs[${i}]`;
        if (!isPlainObject(inp)) { errs.push(`${w} must be an object`); continue; }
        keysOnly(errs, inp, ['id', 'actor', 'method', 'path', 'body', 'benign', 'protectedSecrets'], w);
        if (typeof inp.id !== 'string' || !SLUG.test(inp.id)) errs.push(`${w}.id must be a slug`);
        if (!actorIds.has(inp.actor)) errs.push(`${w}.actor must name a declared actor`);
        checkRequestShape(errs, inp, w);
        if (!JSON.stringify([inp.path, inp.body ?? null]).includes('{{value}}')) errs.push(`${w}: the path or body must mark the untrusted value with {{value}}`);
        if (!Array.isArray(inp.benign) || !inp.benign.length) errs.push(`${w}.benign must list at least one legitimate value with its expected response`);
        else for (const [j, b] of inp.benign.entries()) {
          if (!isPlainObject(b) || typeof b.value !== 'string') { errs.push(`${w}.benign[${j}].value must be a string`); continue; }
          keysOnly(errs, b, ['value', 'expectIncludes', 'expectStatus', 'originalMishandles'], `${w}.benign[${j}]`);
          if (!Array.isArray(b.expectIncludes) || !b.expectIncludes.length) errs.push(`${w}.benign[${j}].expectIncludes must list at least one expected value`);
        }
        if (!Array.isArray(inp.protectedSecrets) || !inp.protectedSecrets.length || !inp.protectedSecrets.every((s) => SLUG.test(s))) errs.push(`${w}.protectedSecrets must name the planted secrets another actor's data holds`);
      }
    }
  }
  if (p.authorization !== undefined) {
    const z = p.authorization;
    if (!isPlainObject(z)) errs.push('authorization must be an object');
    else {
      keysOnly(errs, z, ['table', 'idColumn', 'contentColumn', 'objects', 'operations', 'policy'], 'authorization');
      for (const k of ['table', 'idColumn', 'contentColumn']) if (typeof z[k] !== 'string' || !IDENT.test(z[k])) errs.push(`authorization.${k} must be an identifier`);
      if (!Array.isArray(z.objects) || !z.objects.length) errs.push('authorization.objects must be a non-empty array');
      else for (const [i, o] of z.objects.entries()) {
        if (!isPlainObject(o)) { errs.push(`authorization.objects[${i}] must be an object`); continue; }
        keysOnly(errs, o, ['id', 'owner', 'rowId', 'secret'], `authorization.objects[${i}]`);
        if (!actorIds.has(o.owner)) errs.push(`authorization.objects[${i}].owner must name a declared actor`);
        if (!(Number.isInteger(o.rowId) || (typeof o.rowId === 'string' && o.rowId.length <= 64))) errs.push(`authorization.objects[${i}].rowId must be an integer or short string`);
        if (typeof o.secret !== 'string' || !SLUG.test(o.secret)) errs.push(`authorization.objects[${i}].secret must name the planted secret the object holds`);
      }
      if (!Array.isArray(z.operations) || !z.operations.length) errs.push('authorization.operations must be a non-empty array');
      else {
        for (const [i, op] of z.operations.entries()) {
          if (!isPlainObject(op)) { errs.push(`authorization.operations[${i}] must be an object`); continue; }
          keysOnly(errs, op, ['id', 'effect', 'method', 'path', 'body', 'expectStatus'], `authorization.operations[${i}]`);
          if (!EFFECTS.includes(op.effect)) errs.push(`authorization.operations[${i}].effect must be one of ${EFFECTS.join(', ')} (other effects are not supported in this milestone)`);
          checkRequestShape(errs, op, `authorization.operations[${i}]`);
          if (!String(op.path).includes('{{id}}')) errs.push(`authorization.operations[${i}].path must mark the object id with {{id}}`);
          if (op.effect === 'update' && !JSON.stringify(op.body ?? null).includes('{{value}}')) errs.push(`authorization.operations[${i}]: an update body must mark the written value with {{value}}`);
        }
        if (!z.operations.some((op) => op?.effect === 'read')) errs.push('authorization.operations needs at least one read operation (the security run uses it to show the application works)');
      }
      const pol = z.policy;
      if (!isPlainObject(pol) || !Array.isArray(pol.allow) || !pol.allow.length || !pol.allow.every((r) => POLICY_RULES.includes(r))) errs.push(`authorization.policy.allow must list rules from ${POLICY_RULES.join(', ')}`);
    }
  }
  if (p.tests !== undefined) {
    if (!isPlainObject(p.tests) || typeof p.tests.command !== 'string' || !p.tests.command.trim()) errs.push('tests.command must be a string');
    else keysOnly(errs, p.tests, ['command', 'required', 'flaky'], 'tests');
  }
  if (p.approval !== undefined && !(isPlainObject(p.approval) && typeof p.approval.approvedBy === 'string' && p.approval.approvedBy.trim() && typeof p.approval.reason === 'string' && p.approval.reason.trim())) errs.push('approval must be {approvedBy, reason}');
  return errs;
}

/** Which actors a policy allows to act on an object. Pure. */
export function policyAllows(policy, actor, object, actorsById) {
  if (!actor || actor.anonymous) return false;
  const owner = actorsById[object.owner];
  for (const rule of policy.allow) {
    if (rule === 'owner' && actor.id === object.owner) return true;
    if (rule === 'same-tenant-admin' && actor.role === 'admin' && owner && actor.tenant === owner.tenant) return true;
    if (rule === 'any-admin' && actor.role === 'admin') return true;
  }
  return false;
}
