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
import { validateNetwork, validateFiles } from '../posture/oracles/app-adapters.js';

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

/** One declared untrusted value input (sql, ssrf, filesystem): the request carrying {{value}} and its legitimate values. */
function checkValueInput(errs, inp, w, actorIds, { secrets }) {
  if (!isPlainObject(inp)) { errs.push(`${w} must be an object`); return; }
  keysOnly(errs, inp, ['id', 'actor', 'method', 'path', 'body', 'benign', ...(secrets ? ['protectedSecrets'] : [])], w);
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
  if (secrets && (!Array.isArray(inp.protectedSecrets) || !inp.protectedSecrets.length || !inp.protectedSecrets.every((s) => SLUG.test(s)))) errs.push(`${w}.protectedSecrets must name the planted secrets another actor's data holds`);
}

function checkInputs(errs, sec, name, actorIds, opts) {
  if (!Array.isArray(sec.inputs) || !sec.inputs.length || sec.inputs.length > 8) { errs.push(`${name}.inputs must hold 1 to 8 inputs`); return; }
  for (const [i, inp] of sec.inputs.entries()) checkValueInput(errs, inp, `${name}.inputs[${i}]`, actorIds, opts);
}

/** Problems with a profile; an empty list means it can be used. */
export function validateProfile(p) {
  const errs = [];
  if (!isPlainObject(p)) return ['the profile must be a JSON object'];
  // a draft from `repair profile-draft` marks what the code could not state with `TODO: ...`; such a profile is not finished
  const unfinished = [];
  const scanTodo = (v, at) => {
    if (unfinished.length >= 5) return;
    if (typeof v === 'string' && /^TODO:/.test(v)) unfinished.push(at);
    else if (Array.isArray(v)) v.forEach((x, i) => scanTodo(x, `${at}[${i}]`));
    else if (isPlainObject(v)) for (const [k, x] of Object.entries(v)) { if (/^TODO:/.test(k)) unfinished.push(`${at}.<key>`); scanTodo(x, at ? `${at}.${k}` : k); }
  };
  scanTodo(p, '');
  if (unfinished.length) errs.push(`the profile is an unfinished draft: complete the TODO values at ${unfinished.join(', ')}${unfinished.length >= 5 ? ' (and more)' : ''}`);
  keysOnly(errs, p, ['schema', 'schemaVersion', 'application', 'database', 'actors', 'sql', 'authorization', 'ssrf', 'filesystem', 'passwords', 'dependency', 'credential', 'workflow', 'infrastructure', 'migration', 'tests', 'approval'], 'profile');
  // A profile with only an infrastructure section runs no application: no factory, database or actors are needed.
  const infraOnly = p.infrastructure !== undefined && !['sql', 'authorization', 'ssrf', 'filesystem', 'passwords', 'dependency', 'credential', 'workflow'].some((k) => p[k] !== undefined);
  if (p.schema !== PROFILE_SCHEMA) errs.push(`schema must be '${PROFILE_SCHEMA}'`);
  if (!/^1\.\d+\.\d+$/.test(String(p.schemaVersion))) errs.push('schemaVersion must be 1.x.y');
  const a = p.application;
  if (!isPlainObject(a)) errs.push('application is required');
  else {
    keysOnly(errs, a, ['entry', 'export', 'files', 'runtime'], 'application');
    if (!isRelPath(a.entry)) errs.push('application.entry must be a relative path');
    if (!(infraOnly && a.export === undefined) && (typeof a.export !== 'string' || !IDENT.test(a.export))) errs.push('application.export must be an identifier');
    if (!Array.isArray(a.files) || !a.files.length || a.files.length > 60 || !a.files.every(isRelPath)) errs.push('application.files must list 1 to 60 relative paths');
    else if (!a.files.includes(a.entry)) errs.push('application.files must include the entry');
    if (a.runtime !== undefined && !['node', 'python'].includes(a.runtime)) errs.push("application.runtime must be 'node' or 'python'");
    if (a.runtime === 'python' && !/\.py$/.test(String(a.entry))) errs.push('application.entry must be a .py file for the python runtime');
  }
  const d = p.database;
  if (infraOnly && d === undefined) { /* nothing runs */ } else if (!isPlainObject(d)) errs.push('database is required');
  else {
    keysOnly(errs, d, ['engine', 'schemaSql', 'seed'], 'database');
    if (d.engine !== 'sqlite') errs.push("database.engine: only 'sqlite' is supported in this milestone");
    if (typeof d.schemaSql !== 'string' || !d.schemaSql.trim()) errs.push('database.schemaSql is required');
    if (!Array.isArray(d.seed)) errs.push('database.seed must be an array');
  }
  const actorIds = new Set();
  if (infraOnly && p.actors === undefined) { /* nothing runs */ } else if (!Array.isArray(p.actors) || !p.actors.length) errs.push('actors must be a non-empty array');
  else for (const [i, ac] of p.actors.entries()) {
    if (!isPlainObject(ac)) { errs.push(`actors[${i}] must be an object`); continue; }
    keysOnly(errs, ac, ['id', 'tenant', 'role', 'headers', 'anonymous'], `actors[${i}]`);
    if (typeof ac.id !== 'string' || !SLUG.test(ac.id) || actorIds.has(ac.id)) errs.push(`actors[${i}].id must be a unique slug`);
    actorIds.add(ac.id);
    if (!isPlainObject(ac.headers || {})) errs.push(`actors[${i}].headers must be an object`);
  }
  if (!['sql', 'authorization', 'ssrf', 'filesystem', 'passwords', 'credential', 'workflow', 'infrastructure'].some((k) => p[k] !== undefined)) errs.push('the profile needs a sql, authorization, ssrf, filesystem, passwords, credential, workflow or infrastructure section');
  // Infrastructure: the configuration files whose EFFECTIVE result is judged together, the environment, the services that must not be
  // exposed and the approved services that must stay exposed.
  if (p.infrastructure !== undefined) {
    const x = p.infrastructure;
    if (!isPlainObject(x)) errs.push('infrastructure must be an object');
    else {
      keysOnly(errs, x, ['files', 'environment', 'mustNotExpose', 'mustStayExposed', 'privileges'], 'infrastructure');
      if (!Array.isArray(x.files) || !x.files.length || x.files.length > 40 || !x.files.every(isRelPath)) errs.push('infrastructure.files must list 1 to 40 configuration files');
      else if (isPlainObject(a) && Array.isArray(a.files) && !x.files.every((f) => a.files.includes(f))) errs.push('infrastructure.files must be application files (a repair edits them)');
      if (typeof x.environment !== 'string' || !SLUG.test(x.environment)) errs.push('infrastructure.environment must be a slug');
      const names = (v) => Array.isArray(v) && v.every((s) => typeof s === 'string' && /^[A-Za-z0-9][\w.-]{0,62}$/.test(s));
      // privilege: actions an identity must not be able to perform, and the ones it must keep (IAM policies in a Terraform plan)
      const pv = x.privileges;
      const grantList = (v) => Array.isArray(v) && v.length <= 32 && v.every((g) => isPlainObject(g) && Object.keys(g).every((k) => ['identity', 'action', 'resource'].includes(k))
        && typeof g.identity === 'string' && /^[A-Za-z0-9][\w./:-]{0,120}$/.test(g.identity) && typeof g.action === 'string' && /^[A-Za-z0-9-]{1,40}:[A-Za-z0-9]{1,80}$/.test(g.action)
        && typeof g.resource === 'string' && /^[\w:./*-]{1,200}$/.test(g.resource) && !/[*?]/.test(g.resource));
      if (pv !== undefined) {
        if (!isPlainObject(pv)) errs.push('infrastructure.privileges must be an object');
        else {
          keysOnly(errs, pv, ['mustNotAllow', 'mustAllow'], 'infrastructure.privileges');
          if (!grantList(pv.mustNotAllow) || !pv.mustNotAllow.length) errs.push('infrastructure.privileges.mustNotAllow must list 1 to 32 {identity, action, resource} entries with an exact resource (no wildcard)');
          if (!grantList(pv.mustAllow || [])) errs.push('infrastructure.privileges.mustAllow must list at most 32 {identity, action, resource} entries with an exact resource');
        }
      }
      if (!names(x.mustNotExpose) || (!x.mustNotExpose.length && !isPlainObject(pv))) errs.push('infrastructure.mustNotExpose must name at least one service (it may be empty when privileges are declared)');
      if (!names(x.mustStayExposed)) errs.push('infrastructure.mustStayExposed must list the approved exposed services (it may be empty)');
    }
  }
  // Workflow and idempotency: the operations, the normal workflows built from them (with the state each must leave) and the invariants
  // that must hold after ANY sequence. Repeated, reordered and concurrent variants are generated from these; nothing is inferred.
  // A schema migration the repair needs (FR-16, M4-06): the up and down files the candidate writes (new files, outside the application
  // files), the deployment order, and the rows an older revision may write while rolled back, inserted before the migration re-applies.
  if (p.migration !== undefined) {
    const m = p.migration;
    if (!isPlainObject(m)) errs.push('migration must be an object');
    else {
      keysOnly(errs, m, ['up', 'down', 'deployOrder', 'interim'], 'migration');
      for (const k of ['up', 'down']) {
        if (!isRelPath(m[k]) || !/\.sql$/.test(m[k])) errs.push(`migration.${k} must be a relative .sql path`);
        else if (isPlainObject(a) && Array.isArray(a.files) && a.files.includes(m[k])) errs.push(`migration.${k} must not be an application file: the candidate writes it`);
      }
      if (m.up === m.down) errs.push('migration.up and migration.down must differ');
      if (!['migrate-then-deploy', 'deploy-then-migrate'].includes(m.deployOrder)) errs.push("migration.deployOrder must be 'migrate-then-deploy' or 'deploy-then-migrate'");
      if (m.interim !== undefined && (!Array.isArray(m.interim) || m.interim.length > 16 || !m.interim.every((x) => isPlainObject(x) && typeof x.sql === 'string' && /^\s*INSERT\b/i.test(x.sql) && !/;\s*\S/.test(x.sql) && Array.isArray(x.params)))) errs.push('migration.interim must list at most 16 INSERT statements with params arrays');
      if (!p.database) errs.push('migration needs a database section');
    }
  }
  if (p.workflow !== undefined) {
    const w = p.workflow;
    if (!isPlainObject(w)) errs.push('workflow must be an object');
    else {
      keysOnly(errs, w, ['operations', 'normal', 'invariants'], 'workflow');
      const ops = new Set();
      if (!Array.isArray(w.operations) || !w.operations.length || w.operations.length > 16) errs.push('workflow.operations must hold 1 to 16 operations');
      else for (const [i, o] of w.operations.entries()) {
        const at = `workflow.operations[${i}]`;
        if (!isPlainObject(o)) { errs.push(`${at} must be an object`); continue; }
        keysOnly(errs, o, ['id', 'actor', 'method', 'path', 'body', 'mutating', 'expectStatus'], at);
        if (typeof o.id !== 'string' || !SLUG.test(o.id) || ops.has(o.id)) errs.push(`${at}.id must be a unique slug`);
        ops.add(o.id);
        if (!actorIds.has(o.actor)) errs.push(`${at}.actor must name a declared actor`);
        checkRequestShape(errs, o, at);
        if (typeof o.mutating !== 'boolean') errs.push(`${at}.mutating must say whether the operation changes durable state`);
      }
      const check = (c, at) => {
        if (!isPlainObject(c) || typeof c.id !== 'string' || !SLUG.test(c.id) || typeof c.sql !== 'string' || !/^\s*SELECT\b/i.test(c.sql) || !('expect' in c)) errs.push(`${at} must be {id, sql (one SELECT), params, expect}`);
      };
      if (!Array.isArray(w.normal) || !w.normal.length || w.normal.length > 8) errs.push('workflow.normal must hold 1 to 8 legitimate workflows');
      else for (const [i, n] of w.normal.entries()) {
        const at = `workflow.normal[${i}]`;
        if (!isPlainObject(n)) { errs.push(`${at} must be an object`); continue; }
        keysOnly(errs, n, ['id', 'steps', 'checks'], at);
        if (typeof n.id !== 'string' || !SLUG.test(n.id)) errs.push(`${at}.id must be a slug`);
        if (!Array.isArray(n.steps) || !n.steps.length || n.steps.length > 8 || !n.steps.every((s) => ops.has(s))) errs.push(`${at}.steps must list 1 to 8 declared operation ids`);
        (n.checks || []).forEach((c, j) => check(c, `${at}.checks[${j}]`));
      }
      if (!Array.isArray(w.invariants) || !w.invariants.length || w.invariants.length > 12) errs.push('workflow.invariants must hold 1 to 12 state invariants that hold after any sequence');
      else w.invariants.forEach((c, j) => check(c, `workflow.invariants[${j}]`));
    }
  }
  // A leaked credential: where it is (never its value), the environment name the replacement is wired from, whether the old credential
  // must be revoked, and the legitimate requests that must work with the replacement (against declared hosts that accept only it).
  if (p.credential !== undefined) {
    const c = p.credential;
    if (!isPlainObject(c)) errs.push('credential must be an object');
    else {
      keysOnly(errs, c, ['location', 'env', 'revocation', 'provider', 'network', 'controls'], 'credential');
      if (!isPlainObject(c.location) || !isRelPath(c.location.file) || !Number.isInteger(c.location.line) || c.location.line < 1) errs.push('credential.location must be {file, line}: where the leaked value is, never the value');
      else if (isPlainObject(a) && Array.isArray(a.files) && !a.files.includes(c.location.file)) errs.push('credential.location.file must be one of the application files');
      if (typeof c.env !== 'string' || !/^[A-Z_][A-Z0-9_]{0,63}$/.test(c.env)) errs.push('credential.env must be the upper-case environment name the replacement is read from');
      if (!['required', 'not-required'].includes(c.revocation)) errs.push("credential.revocation must be 'required' or 'not-required'");
      if (typeof c.provider !== 'string' || !SLUG.test(c.provider)) errs.push('credential.provider must be a slug naming the issuing service');
      const n = validateNetwork(c.network);
      if (n) errs.push(`credential.network: ${n}`);
      if (!Array.isArray(c.controls) || !c.controls.length) errs.push('credential.controls must list the requests that must work with the replacement credential');
      else for (const [i, r] of c.controls.entries()) {
        const w = `credential.controls[${i}]`;
        if (!isPlainObject(r)) { errs.push(`${w} must be an object`); continue; }
        keysOnly(errs, r, ['id', 'actor', 'method', 'path', 'body', 'expectStatus', 'expectIncludes'], w);
        if (typeof r.id !== 'string' || !SLUG.test(r.id)) errs.push(`${w}.id must be a slug`);
        if (!actorIds.has(r.actor)) errs.push(`${w}.actor must name a declared actor`);
        checkRequestShape(errs, r, w);
      }
      if (a?.runtime === 'python') errs.push('the credential section is supported for the node runtime only in this release');
    }
  }
  // A vulnerable dependency (npm): the advisory's package and range, where the package tarballs live, and which section's attacks show
  // the vulnerability in this application. The manifest and the lockfile must be application files: a repair edits them.
  if (p.dependency !== undefined) {
    const d = p.dependency;
    if (!isPlainObject(d)) errs.push('dependency must be an object');
    else {
      keysOnly(errs, d, ['ecosystem', 'package', 'vulnerable', 'advisory', 'sources', 'exploit'], 'dependency');
      if (d.ecosystem !== 'npm') errs.push("dependency.ecosystem: only 'npm' is supported in this release");
      if (typeof d.package !== 'string' || !/^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]{0,213}$/.test(d.package)) errs.push('dependency.package must be an npm package name');
      if (typeof d.vulnerable !== 'string' || !d.vulnerable.trim() || d.vulnerable.length > 200) errs.push('dependency.vulnerable must be a version range');
      if (typeof d.advisory !== 'string' || !d.advisory.trim()) errs.push('dependency.advisory must name the advisory');
      if (!isRelPath(d.sources)) errs.push('dependency.sources must be a relative directory holding the package tarballs');
      if (!['filesystem', 'sql', 'ssrf'].includes(d.exploit) || p[d.exploit] === undefined) errs.push('dependency.exploit must name the profile section (filesystem, sql or ssrf) whose attacks show the vulnerability');
      if (isPlainObject(a) && Array.isArray(a.files) && !['package.json', 'package-lock.json'].every((f) => a.files.includes(f))) errs.push('application.files must include package.json and package-lock.json for a dependency repair');
    }
  }
  // Password storage: where the application stores a credential, how a user registers and logs in, the legacy format existing users
  // carry (with known test passwords: the legacy rows are built from them), and the approved storage format and its minimum costs.
  if (p.passwords !== undefined) {
    const w = p.passwords;
    if (!isPlainObject(w)) errs.push('passwords must be an object');
    else {
      keysOnly(errs, w, ['table', 'userColumn', 'hashColumn', 'legacy', 'register', 'login', 'approved', 'actor'], 'passwords');
      for (const k of ['table', 'userColumn', 'hashColumn']) if (typeof w[k] !== 'string' || !IDENT.test(w[k])) errs.push(`passwords.${k} must be an identifier`);
      if (!actorIds.has(w.actor)) errs.push('passwords.actor must name a declared actor (the one sending register and login requests)');
      for (const op of ['register', 'login']) {
        const r = w[op];
        if (!isPlainObject(r)) { errs.push(`passwords.${op} is required`); continue; }
        keysOnly(errs, r, ['method', 'path', 'body', 'expectStatus', 'denyStatus'], `passwords.${op}`);
        checkRequestShape(errs, r, `passwords.${op}`);
        const t = JSON.stringify([r.path, r.body ?? null]);
        if (!t.includes('{{user}}') || !t.includes('{{password}}')) errs.push(`passwords.${op}: the path or body must carry {{user}} and {{password}}`);
        if (r.expectStatus !== undefined && (!Array.isArray(r.expectStatus) || !r.expectStatus.every(Number.isInteger))) errs.push(`passwords.${op}.expectStatus must list status codes`);
      }
      if (isPlainObject(w.login) && (!Array.isArray(w.login.denyStatus) || !w.login.denyStatus.length || !w.login.denyStatus.every(Number.isInteger))) errs.push('passwords.login.denyStatus must list the status codes of a refused login');
      const L = w.legacy;
      if (!isPlainObject(L)) errs.push('passwords.legacy is required: the format existing users carry, and at least one user with a known test password');
      else {
        keysOnly(errs, L, ['digest', 'users'], 'passwords.legacy');
        if (!['md5', 'sha1', 'sha256', 'sha512'].includes(L.digest)) errs.push("passwords.legacy.digest must be one of md5, sha1, sha256, sha512 (an unsalted hex digest)");
        if (!Array.isArray(L.users) || !L.users.length || L.users.length > 8 || !L.users.every((u) => isPlainObject(u) && typeof u.name === 'string' && u.name && typeof u.password === 'string' && u.password.length >= 4)) errs.push('passwords.legacy.users must list 1 to 8 {name, password} test users');
      }
      const A = w.approved;
      if (!isPlainObject(A) || A.format !== 'scrypt') errs.push("passwords.approved.format must be 'scrypt' (the only format the verifier recomputes in this release)");
      else for (const k of ['minN', 'minR', 'minSaltBytes', 'minKeyBytes']) if (!Number.isInteger(A[k]) || A[k] < 1) errs.push(`passwords.approved.${k} must be a positive integer`);
    }
  }
  if ((p.ssrf !== undefined || p.filesystem !== undefined) && a?.runtime === 'python') errs.push('the ssrf and filesystem sections are supported for the node runtime only in this release');
  if (p.sql !== undefined) {
    if (!isPlainObject(p.sql)) errs.push('sql must be an object');
    else { keysOnly(errs, p.sql, ['inputs', 'stateChecks'], 'sql'); checkInputs(errs, p.sql, 'sql', actorIds, { secrets: true }); }
  }
  // Server-side request forgery: the network the application can reach is declared (hosts, their DNS answers, what each serves), with a
  // destination policy. Secrets planted in a forbidden host's responses show disclosure; the connection itself is the forbidden effect.
  if (p.ssrf !== undefined) {
    if (!isPlainObject(p.ssrf)) errs.push('ssrf must be an object');
    else {
      keysOnly(errs, p.ssrf, ['policy', 'approved', 'hosts', 'inputs'], 'ssrf');
      const n = validateNetwork({ policy: p.ssrf.policy, approved: p.ssrf.approved, hosts: p.ssrf.hosts });
      if (n) errs.push(`ssrf: ${n}`);
      checkInputs(errs, p.ssrf, 'ssrf', actorIds, { secrets: false });
    }
  }
  // Path traversal: a real file tree with an allowed root; files outside it plant secrets; declared links are real symbolic links.
  if (p.filesystem !== undefined) {
    if (!isPlainObject(p.filesystem)) errs.push('filesystem must be an object');
    else {
      keysOnly(errs, p.filesystem, ['root', 'tree', 'links', 'inputs'], 'filesystem');
      const f = validateFiles({ root: p.filesystem.root, tree: p.filesystem.tree, ...(p.filesystem.links !== undefined ? { links: p.filesystem.links } : {}) });
      if (f) errs.push(`filesystem: ${f}`);
      checkInputs(errs, p.filesystem, 'filesystem', actorIds, { secrets: false });
    }
  }
  if (p.authorization !== undefined) {
    const z = p.authorization;
    if (!isPlainObject(z)) errs.push('authorization must be an object');
    else {
      keysOnly(errs, z, ['table', 'idColumn', 'contentColumn', 'objects', 'operations', 'policy', 'controls'], 'authorization');
      // Declared legitimate workflows outside the actor matrix (a public page, a health route): they must keep working after a repair.
      if (z.controls !== undefined) {
        if (!Array.isArray(z.controls) || z.controls.length > 32) errs.push('authorization.controls must be an array of at most 32');
        else for (const [i, c] of z.controls.entries()) {
          const w = `authorization.controls[${i}]`;
          if (!isPlainObject(c)) { errs.push(`${w} must be an object`); continue; }
          keysOnly(errs, c, ['id', 'actor', 'method', 'path', 'body', 'expectStatus', 'expectIncludes'], w);
          if (typeof c.id !== 'string' || !SLUG.test(c.id)) errs.push(`${w}.id must be a slug`);
          if (!actorIds.has(c.actor)) errs.push(`${w}.actor must name a declared actor`);
          checkRequestShape(errs, c, w);
          if (c.expectIncludes !== undefined && (!Array.isArray(c.expectIncludes) || !c.expectIncludes.every((x) => typeof x === 'string' && x))) errs.push(`${w}.expectIncludes must list strings`);
        }
      }
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
