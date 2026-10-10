// The executable invariant DSL (X-401).
//
// An INVARIANT is a declarative contract about tenant or business state: who the actors are, which tenants and resources
// exist, which transitions are allowed, which outcomes are forbidden, and which oracle adapter judges them. It is data, never
// code: every field is a closed-world value, every forbidden outcome is an expression from a fixed grammar, and every string
// inside an expression is restricted to a conservative identifier charset, so nothing in a declarative field can carry
// executable content. The oracle (`business-state`, oracles/adapters.js) evaluates the expressions verifier-side with
// `state-assertions.js`, from durable state it observed itself.
//
// Identity. `key` names a contract across its revisions; `revision` counts them; `id` is a hash over the semantic content
// (key, revision, scope, actors, tenants, resources, transitions, forbidden, oracle). Review state, evidence and author are NOT
// in the id, so approving a contract does not change what is approved, and an approval binds to the exact content it was given
// for. Two actors, resources or transitions sharing an identity are rejected as ambiguous.
//
// Review state recorded in the document (`review.state`) is a claim, not authority. Authority is decided only by the signed
// approval ledger (`lifecycle.js`), so a document that says "approved" is not approved.
import { semanticId } from '../assurance/identity.js';
import { SCHEMA_VERSION, checkHeader, checkFields, checkEnum, result, guardObject, isPlainObject, isNonEmptyString } from '../assurance/schema-kit.js';
import { getOracle } from '../oracles/registry.js';
import { EXPRESSIONS, expressionProblems, isSafeText as safe } from './expressions.js';

const INVARIANT_SCHEMA = 'agentic-security/invariant';
const INVARIANT_ID_PREFIX = 'inv';
export const INVARIANT_CLASSES = Object.freeze(['tenant-isolation', 'privilege-constraint', 'value-conservation', 'workflow-order', 'idempotency']);
export const REVIEW_STATES = Object.freeze(['proposed', 'approved', 'rejected', 'superseded']);
const AUTHOR_KINDS = Object.freeze(['human', 'model', 'code']);
export const ORIGINS = Object.freeze(['authored', 'inferred']);
const ENVIRONMENTS = Object.freeze(['disposable-fixture', 'shared', 'production']);
export const BUSINESS_STATE_ORACLE = 'business-state';

const ALLOWED = ['schema', 'schemaVersion', 'id', 'key', 'revision', 'name', 'description', 'class', 'scope', 'actors', 'tenants', 'resources', 'transitions', 'forbidden', 'oracle', 'author', 'review', 'supersedes'];
const REQUIRED = ['schema', 'schemaVersion', 'id', 'key', 'revision', 'name', 'class', 'scope', 'actors', 'tenants', 'resources', 'transitions', 'forbidden', 'oracle', 'author', 'review'];
const ID_FIELDS = ['key', 'revision', 'class', 'scope', 'actors', 'tenants', 'resources', 'transitions', 'forbidden', 'oracle'];

// Bounds, so a contract cannot be used to request unbounded work from the scenario generator.
export const LIMITS = Object.freeze({ actors: 8, tenants: 4, resources: 16, transitions: 24, forbidden: 8 });

const SLUG = /^[a-z][a-z0-9-]{1,63}$/;
const IDENT = /^[A-Za-z_$][\w$]{0,63}$/;
export function invariantId(inv) { return semanticId(INVARIANT_ID_PREFIX, inv, ID_FIELDS); }

/** Build an invariant document from its parts: fills the schema header and the content id. Does not validate. */
export function createInvariant(parts) {
  const inv = { schema: INVARIANT_SCHEMA, schemaVersion: SCHEMA_VERSION, ...parts };
  inv.id = invariantId(inv);
  return inv;
}

function dup(ctx, base, list, what) {
  const seen = new Set();
  for (const [i, x] of list.entries()) {
    if (!isPlainObject(x) || typeof x.id !== 'string') continue;
    if (seen.has(x.id)) ctx.err('DUPLICATE_ID', `${base}[${i}].id`, `${what} identity '${x.id}' is ambiguous: it appears more than once`);
    seen.add(x.id);
  }
}

function listOf(ctx, rec, field, max) {
  const v = rec[field];
  if (!Array.isArray(v)) { ctx.err('BAD_TYPE', field, 'must be an array'); return []; }
  if (v.length > max) ctx.err('BAD_TYPE', field, `at most ${max} entries`);
  return v;
}

/** Validate an invariant document. Pure: reads nothing but the oracle registry. */
export function validateInvariant(rec) {
  const g = guardObject(rec);
  if (!g.ok) return result(g.ctx);
  const { ctx } = g;
  if (!checkHeader(ctx, rec, INVARIANT_SCHEMA)) return result(ctx);
  checkFields(ctx, rec, ALLOWED, REQUIRED);
  if (ctx.errors.length) return result(ctx);

  if (typeof rec.key !== 'string' || !SLUG.test(rec.key)) ctx.err('BAD_TYPE', 'key', 'must be a lowercase slug');
  if (!Number.isInteger(rec.revision) || rec.revision < 1) ctx.err('BAD_TYPE', 'revision', 'must be a positive integer');
  if (!isNonEmptyString(rec.name)) ctx.err('BAD_TYPE', 'name', 'must be a non-empty string');
  if (rec.description !== undefined && typeof rec.description !== 'string') ctx.err('BAD_TYPE', 'description', 'must be a string');
  checkEnum(ctx, 'class', rec.class, INVARIANT_CLASSES);

  // scope: an explicit application scope, never "everywhere"
  const sc = rec.scope;
  if (!isPlainObject(sc)) ctx.err('BAD_TYPE', 'scope', 'must be an object naming the application scope');
  else {
    for (const k of Object.keys(sc)) if (!['application', 'entry', 'factory', 'environment'].includes(k)) ctx.err('UNKNOWN_FIELD', `scope.${k}`, 'not part of the scope');
    if (typeof sc.application !== 'string' || !SLUG.test(sc.application)) ctx.err('BAD_TYPE', 'scope.application', 'must be a lowercase slug naming the application');
    if (!safe(sc.entry) || sc.entry.includes('..') || sc.entry.startsWith('/')) ctx.err('BAD_TYPE', 'scope.entry', 'must be a safe relative path');
    if (typeof sc.factory !== 'string' || !IDENT.test(sc.factory)) ctx.err('BAD_TYPE', 'scope.factory', 'must be an identifier');
    checkEnum(ctx, 'scope.environment', sc.environment, ENVIRONMENTS);
  }

  const tenants = listOf(ctx, rec, 'tenants', LIMITS.tenants);
  const actors = listOf(ctx, rec, 'actors', LIMITS.actors);
  const resources = listOf(ctx, rec, 'resources', LIMITS.resources);
  const transitions = listOf(ctx, rec, 'transitions', LIMITS.transitions);
  const forbidden = listOf(ctx, rec, 'forbidden', LIMITS.forbidden);
  if (tenants.length < 1) ctx.err('MISSING_FIELD', 'tenants', 'at least one tenant is required');
  if (actors.length < 1) ctx.err('MISSING_FIELD', 'actors', 'at least one actor is required');
  if (forbidden.length < 1) ctx.err('MISSING_FIELD', 'forbidden', 'at least one forbidden outcome is required');

  for (const [i, t] of tenants.entries()) if (!isPlainObject(t) || !safe(t.id)) ctx.err('BAD_ID', `tenants[${i}].id`, 'a tenant needs a safe id');
  for (const [i, a] of actors.entries()) {
    if (!isPlainObject(a) || !safe(a.id)) ctx.err('BAD_ID', `actors[${i}].id`, 'an actor needs a safe id');
    else if (!safe(a.role) || !tenants.some((t) => t && t.id === a.tenant)) ctx.err('BAD_TYPE', `actors[${i}]`, 'an actor needs a safe role and a tenant declared in tenants');
  }
  for (const [i, r] of resources.entries()) {
    if (!isPlainObject(r) || !safe(r.id) || !safe(r.kind) || !safe(r.key)) ctx.err('BAD_ID', `resources[${i}]`, 'a resource needs a safe id, kind and key');
    else if (r.tenant !== null && !tenants.some((t) => t && t.id === r.tenant)) ctx.err('BAD_TYPE', `resources[${i}].tenant`, 'must be a declared tenant or null (shared)');
    else if (r.marker !== undefined && !safe(r.marker)) ctx.err('BAD_TYPE', `resources[${i}].marker`, 'must be a short safe string');
  }
  for (const [i, t] of transitions.entries()) {
    if (!isPlainObject(t) || !safe(t.id) || !safe(t.action)) { ctx.err('BAD_ID', `transitions[${i}]`, 'a transition needs a safe id and action'); continue; }
    if (!Array.isArray(t.actors) || t.actors.length < 1 || !t.actors.every((id) => actors.some((a) => a && a.id === id))) ctx.err('DANGLING_REF', `transitions[${i}].actors`, 'every transition actor must be a declared actor');
    if (!resources.some((r) => r && r.id === t.resource)) ctx.err('DANGLING_REF', `transitions[${i}].resource`, 'the transition resource must be a declared resource');
    for (const k of ['from', 'to']) if (t[k] !== undefined && !safe(t[k])) ctx.err('BAD_TYPE', `transitions[${i}].${k}`, 'must be a short safe string');
  }
  dup(ctx, 'tenants', tenants, 'tenant');
  dup(ctx, 'actors', actors, 'actor');
  dup(ctx, 'resources', resources, 'resource');
  dup(ctx, 'transitions', transitions, 'transition');
  dup(ctx, 'forbidden', forbidden, 'forbidden outcome');
  const resourceKeys = resources.filter((r) => isPlainObject(r)).map((r) => r.key);
  if (new Set(resourceKeys).size !== resourceKeys.length) ctx.err('DUPLICATE_ID', 'resources', 'two resources share one store key, so their identities are ambiguous');

  // oracle binding: a registered adapter of the business-state class, and every forbidden outcome bound to it
  const orc = rec.oracle;
  if (!isPlainObject(orc) || typeof orc.adapter !== 'string' || !orc.adapter) ctx.err('MISSING_FIELD', 'oracle.adapter', 'an oracle binding is required');
  else {
    const bound = getOracle(orc.adapter);
    if (!bound) ctx.err('DANGLING_REF', 'oracle.adapter', `'${orc.adapter}' is not a registered oracle adapter`);
    else if (bound.class !== 'business-state') ctx.err('RULE_VIOLATION', 'oracle.adapter', `'${orc.adapter}' is a ${bound.class} oracle, not a business-state oracle`);
    else if (orc.version !== bound.version) ctx.err('RULE_VIOLATION', 'oracle.version', `the binding names version ${JSON.stringify(orc.version)} but the registered adapter is version ${bound.version}`);
    for (const k of Object.keys(orc)) if (!['adapter', 'version'].includes(k)) ctx.err('UNKNOWN_FIELD', `oracle.${k}`, 'not part of an oracle binding');
  }
  for (const [i, f] of forbidden.entries()) {
    if (!isPlainObject(f) || !safe(f.id)) { ctx.err('BAD_ID', `forbidden[${i}].id`, 'a forbidden outcome needs a safe id'); continue; }
    const spec = EXPRESSIONS[f.op];
    if (!spec) { ctx.err('RULE_VIOLATION', `forbidden[${i}].op`, expressionProblems(f)[0]); continue; }
    for (const p of expressionProblems(f)) ctx.err(p.includes('is not a parameter') ? 'UNKNOWN_FIELD' : 'BAD_TYPE', `forbidden[${i}]`, p);
    if (!spec.classes.includes(rec.class)) ctx.err('RULE_VIOLATION', `forbidden[${i}].op`, `'${f.op}' does not express a ${rec.class} contract`);
    if (!isPlainObject(orc) || f.bind !== orc.adapter) ctx.err('MISSING_FIELD', `forbidden[${i}].bind`, 'every forbidden outcome must name the oracle adapter that judges it');
  }

  // authorship and review state are preserved, not defaulted
  const au = rec.author;
  if (!isPlainObject(au) || !safe(au.id)) ctx.err('MISSING_FIELD', 'author.id', 'an author id is required');
  else checkEnum(ctx, 'author.kind', au.kind, AUTHOR_KINDS);
  const rv = rec.review;
  if (!isPlainObject(rv)) ctx.err('BAD_TYPE', 'review', 'must be an object');
  else {
    checkEnum(ctx, 'review.state', rv.state, REVIEW_STATES);
    checkEnum(ctx, 'review.origin', rv.origin, ORIGINS);
    for (const k of Object.keys(rv)) if (!['state', 'origin', 'sources', 'uncertainty'].includes(k)) ctx.err('UNKNOWN_FIELD', `review.${k}`, 'not part of the review block');
    if (rv.origin === 'inferred') {
      if (isPlainObject(au) && au.kind === 'human') ctx.err('RULE_VIOLATION', 'author.kind', 'an inferred invariant is authored by a model or by code, not a human');
      if (!Array.isArray(rv.sources) || rv.sources.length < 1) ctx.err('MISSING_FIELD', 'review.sources', 'an inferred invariant carries its source evidence');
      if (typeof rv.uncertainty !== 'number' || !(rv.uncertainty >= 0 && rv.uncertainty <= 1)) ctx.err('MISSING_FIELD', 'review.uncertainty', 'an inferred invariant states its uncertainty as a number from 0 to 1');
    } else if (rv.origin === 'authored' && isPlainObject(au) && au.kind !== 'human') {
      ctx.err('RULE_VIOLATION', 'author.kind', 'an authored invariant has a human author');
    }
  }
  if (rec.supersedes !== undefined && (typeof rec.supersedes !== 'string' || !rec.supersedes.startsWith(`${INVARIANT_ID_PREFIX}:`))) ctx.err('BAD_ID', 'supersedes', 'must name an invariant id');
  if (!ctx.errors.length) {
    const expected = invariantId(rec);
    if (rec.id !== expected) ctx.err('ID_MISMATCH', 'id', `the id does not match the invariant content (expected ${expected})`);
  }
  return result(ctx);
}
