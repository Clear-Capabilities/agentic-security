// X-401: the executable invariant DSL. Pure: nothing here runs a target.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { validateInvariant, createInvariant, invariantId, INVARIANT_CLASSES, REVIEW_STATES } from '../../src/posture/invariants/schema.js';
import { EXPRESSIONS } from '../../src/posture/invariants/expressions.js';
import { contract } from '../helpers/invariant-fixtures.js';

const clone = (o) => JSON.parse(JSON.stringify(o));
/** Mutate a valid contract and recompute its id, so the failure under test is the mutation and not a stale id. */
const mutate = (name, fn) => { const c = clone(contract(name)); fn(c); c.id = invariantId(c); return c; };
const codes = (rec) => validateInvariant(rec).errors.map((e) => e.code);
const messages = (rec) => validateInvariant(rec).errors.map((e) => `${e.path} ${e.message}`).join(' | ');

describe('[X-401.AC01] the schema expresses actors, tenants, resources, transitions, forbidden outcomes and oracle bindings without executable code', () => {
  test('[X-401.AC01] a complete contract validates and carries every declared element', () => {
    const c = contract('tenant');
    const v = validateInvariant(c);
    assert.deepEqual(v.errors, []);
    assert.equal(v.ok, true);
    for (const field of ['actors', 'tenants', 'resources', 'transitions', 'forbidden', 'oracle']) assert.ok(c[field] && (Array.isArray(c[field]) ? c[field].length : Object.keys(c[field]).length), `${field} is declared`);
    assert.equal(c.oracle.adapter, 'business-state');
    assert.ok(c.forbidden.every((f) => f.bind === c.oracle.adapter), 'every forbidden outcome names its oracle');
  });

  test('[X-401.AC01] a declarative field that carries code is rejected, in every position a string can appear', () => {
    const hostile = ["x'); process.exit(1); //", 'a b', '${process.env.HOME}', '`ls`', '(() => 1)()', 'a;b', '../../etc/passwd'.replace(/\./g, '․'), 'x'.repeat(65)];
    for (const bad of hostile) {
      assert.notEqual(validateInvariant(mutate('tenant', (c) => { c.forbidden[0].prefix = bad; })).ok, true, `prefix ${JSON.stringify(bad.slice(0, 30))} must be rejected`);
      assert.notEqual(validateInvariant(mutate('privilege', (c) => { c.forbidden[0].actions = [bad]; })).ok, true, `actions ${JSON.stringify(bad.slice(0, 30))} must be rejected`);
      assert.notEqual(validateInvariant(mutate('workflow', (c) => { c.forbidden[0].allowed[0].to = bad; })).ok, true, `allowed ${JSON.stringify(bad.slice(0, 30))} must be rejected`);
      assert.notEqual(validateInvariant(mutate('tenant', (c) => { c.resources[0].key = bad; })).ok, true, `resource key ${JSON.stringify(bad.slice(0, 30))} must be rejected`);
    }
    // the same contract with plain values is accepted, so the rejection is about the content and not the position
    assert.equal(validateInvariant(mutate('tenant', (c) => { c.forbidden[0].prefix = 'orders/'; })).ok, true);
  });

  test('[X-401.AC01] a function-valued or non-data field cannot be part of a contract', () => {
    const c = clone(contract('tenant'));
    c.forbidden[0].test = 'actor.tenant !== owner.tenant';
    assert.ok(codes(c).includes('UNKNOWN_FIELD'), 'an extra parameter (an expression string) is not part of the grammar');
    const d = clone(contract('tenant'));
    d.script = 'doEvil()';
    assert.ok(codes(d).includes('UNKNOWN_FIELD'), 'a top-level extra field is rejected (closed world)');
  });
});

describe('[X-401.AC02] invariants support tenant isolation, privilege constraints, money conservation, workflow order and idempotency, each with an explicit application scope', () => {
  const cases = [['tenant', 'tenant-isolation'], ['privilege', 'privilege-constraint'], ['conservation', 'value-conservation'], ['workflow', 'workflow-order'], ['idempotency', 'idempotency']];

  test('[X-401.AC02] all five classes validate', () => {
    assert.deepEqual([...INVARIANT_CLASSES].sort(), cases.map((c) => c[1]).sort());
    for (const [name, cls] of cases) {
      const c = contract(name);
      assert.equal(c.class, cls);
      assert.deepEqual(validateInvariant(c).errors, [], `${name} validates`);
    }
  });

  test('[X-401.AC02] the application scope is explicit: a contract without one, or with a wildcard, is rejected', () => {
    const noScope = clone(contract('tenant')); delete noScope.scope;
    assert.ok(codes(noScope).includes('MISSING_FIELD'));
    assert.match(messages(mutate('tenant', (c) => { c.scope.application = '*'; })), /scope\.application/);
    assert.match(messages(mutate('tenant', (c) => { c.scope.environment = 'everywhere'; })), /scope\.environment/);
    assert.match(messages(mutate('tenant', (c) => { c.scope.entry = '../outside.mjs'; })), /scope\.entry/);
    assert.match(messages(mutate('tenant', (c) => { c.scope.factory = 'create App'; })), /scope\.factory/);
  });

  test('[X-401.AC02] an expression that does not express the contract\'s class is rejected', () => {
    // a money-conservation outcome inside a tenant-isolation contract, and the reverse
    const wrong = mutate('tenant', (c) => { c.forbidden = [{ id: 'sum', op: 'sum-not-conserved', prefix: 'accounts/', field: 'balance', bind: 'business-state' }]; });
    assert.match(messages(wrong), /does not express a tenant-isolation contract/);
    const right = mutate('conservation', (c) => { c.forbidden = [{ id: 'sum', op: 'sum-not-conserved', prefix: 'accounts/', field: 'balance', bind: 'business-state' }]; });
    assert.equal(validateInvariant(right).ok, true);
    // every expression in the grammar is claimed by exactly the class it serves
    for (const [op, spec] of Object.entries(EXPRESSIONS)) assert.ok(spec.classes.length >= 1 && spec.classes.every((k) => INVARIANT_CLASSES.includes(k)), op);
  });

  test('[X-401.AC02] the class-specific parameters are enforced (bounds and shapes), not just present', () => {
    assert.notEqual(validateInvariant(mutate('idempotency', (c) => { c.forbidden[0].max = 0; })).ok, true);
    assert.notEqual(validateInvariant(mutate('idempotency', (c) => { c.forbidden[0].max = 6; })).ok, true);
    assert.equal(validateInvariant(mutate('idempotency', (c) => { c.forbidden[0].max = 2; })).ok, true);
    assert.notEqual(validateInvariant(mutate('workflow', (c) => { c.forbidden[0].allowed = []; })).ok, true);
    assert.notEqual(validateInvariant(mutate('workflow', (c) => { c.forbidden[0].allowed = [{ from: 'new' }]; })).ok, true);
    assert.notEqual(validateInvariant(mutate('privilege', (c) => { c.forbidden[0].allowedRoles = []; })).ok, true);
  });
});

describe('[X-401.AC03] schema tests reject ambiguous identities, missing oracle bindings and unsupported expressions, and preserve author, revision and review state', () => {
  test('[X-401.AC03] ambiguous identities are rejected (duplicate actor, resource, transition or store key)', () => {
    const dupActor = mutate('tenant', (c) => { c.actors.push({ ...c.actors[0], tenant: 'globex' }); });
    assert.ok(codes(dupActor).includes('DUPLICATE_ID'), messages(dupActor));
    const dupResource = mutate('tenant', (c) => { c.resources.push({ ...c.resources[0], key: 'orders/other' }); });
    assert.ok(codes(dupResource).includes('DUPLICATE_ID'), messages(dupResource));
    const dupKey = mutate('tenant', (c) => { c.resources[1].key = c.resources[0].key; });
    assert.match(messages(dupKey), /share one store key/);
    const dupTransition = mutate('tenant', (c) => { c.transitions.push({ ...c.transitions[0] }); });
    assert.ok(codes(dupTransition).includes('DUPLICATE_ID'));
    const dupForbidden = mutate('tenant', (c) => { c.forbidden.push({ ...c.forbidden[0] }); });
    assert.ok(codes(dupForbidden).includes('DUPLICATE_ID'));
    assert.equal(validateInvariant(contract('tenant')).ok, true, 'the unmodified contract is unambiguous');
  });

  test('[X-401.AC03] dangling identities are rejected (a transition naming an unknown actor or resource, an actor in an undeclared tenant)', () => {
    assert.ok(codes(mutate('tenant', (c) => { c.transitions[0].actors = ['nobody']; })).includes('DANGLING_REF'));
    assert.ok(codes(mutate('tenant', (c) => { c.transitions[0].resource = 'missing'; })).includes('DANGLING_REF'));
    assert.notEqual(validateInvariant(mutate('tenant', (c) => { c.actors[0].tenant = 'initech'; })).ok, true);
  });

  test('[X-401.AC03] a missing or wrong oracle binding is rejected', () => {
    assert.ok(codes(mutate('tenant', (c) => { delete c.oracle; })).includes('MISSING_FIELD'));
    assert.ok(codes(mutate('tenant', (c) => { c.oracle = {}; })).includes('MISSING_FIELD'));
    assert.ok(codes(mutate('tenant', (c) => { c.oracle = { adapter: 'no-such-oracle', version: '1' }; })).includes('DANGLING_REF'));
    // a real adapter of the wrong class cannot judge a business-state contract
    assert.match(messages(mutate('tenant', (c) => { c.oracle = { adapter: 'authorization-decision', version: '1' }; })), /not a business-state oracle/);
    // a stale pinned version
    assert.match(messages(mutate('tenant', (c) => { c.oracle.version = '99'; })), /oracle\.version/);
    // an outcome that names no oracle, or a different one from the contract's binding
    assert.match(messages(mutate('tenant', (c) => { delete c.forbidden[0].bind; })), /bind/);
    assert.match(messages(mutate('tenant', (c) => { c.forbidden[0].bind = 'state-transition'; })), /bind/);
  });

  test('[X-401.AC03] an unsupported expression is rejected, never interpreted', () => {
    for (const op of ['eval', 'js', 'sql', 'custom', undefined, 7]) {
      const c = mutate('tenant', (x) => { x.forbidden[0] = { id: 'x', op, expression: 'a > b', bind: 'business-state' }; });
      assert.notEqual(validateInvariant(c).ok, true, `op ${String(op)} must be rejected`);
      assert.match(messages(c), /not a supported expression/);
    }
    assert.notEqual(validateInvariant(mutate('tenant', (c) => { c.forbidden = []; })).ok, true, 'a contract forbids something');
  });

  test('[X-401.AC03] author, revision and review state are preserved, required and part of what is validated', () => {
    const c = contract('tenant', { author: { id: 'ross', kind: 'human' }, revision: 3, review: { state: 'proposed', origin: 'authored' } });
    const round = JSON.parse(JSON.stringify(c));
    assert.deepEqual(round.author, { id: 'ross', kind: 'human' });
    assert.equal(round.revision, 3);
    assert.equal(round.review.state, 'proposed');
    assert.equal(validateInvariant(round).ok, true);
    assert.ok(codes(mutate('tenant', (x) => { delete x.author; })).includes('MISSING_FIELD'));
    assert.ok(codes(mutate('tenant', (x) => { x.author = { id: '', kind: 'human' }; })).includes('MISSING_FIELD'));
    assert.notEqual(validateInvariant(mutate('tenant', (x) => { x.author.kind = 'wizard'; })).ok, true);
    assert.notEqual(validateInvariant(mutate('tenant', (x) => { x.revision = 0; })).ok, true);
    assert.notEqual(validateInvariant(mutate('tenant', (x) => { x.revision = 1.5; })).ok, true);
    assert.notEqual(validateInvariant(mutate('tenant', (x) => { x.review.state = 'pending'; })).ok, true);
    for (const state of REVIEW_STATES) assert.equal(validateInvariant(mutate('tenant', (x) => { x.review.state = state; })).ok, true, `${state} is a representable review state`);
  });

  test('[X-401.AC03] the id binds the content, not the review: approving does not change it, editing does', () => {
    const base = contract('tenant');
    const reviewed = createInvariant({ ...clone(base), review: { state: 'approved', origin: 'authored' }, author: { id: 'someone-else', kind: 'human' } });
    assert.equal(reviewed.id, base.id, 'review state and author are not in the id');
    const edited = createInvariant({ ...clone(base), forbidden: [{ ...base.forbidden[0], prefix: 'invoices/' }] });
    assert.notEqual(edited.id, base.id, 'a changed outcome is a different contract');
    const revised = createInvariant({ ...clone(base), revision: 2 });
    assert.notEqual(revised.id, base.id, 'a new revision is a different contract');
    const tampered = clone(base); tampered.forbidden[0].prefix = 'invoices/';
    assert.ok(codes(tampered).includes('ID_MISMATCH'), 'an edit that keeps the old id is caught');
  });

  test('[X-401.AC03] an inferred contract must say who inferred it, from what, and how sure; a human cannot be recorded as the inferrer', () => {
    const inferred = (over) => mutate('tenant', (c) => { c.author = { id: 'miner', kind: 'code' }; c.review = { state: 'proposed', origin: 'inferred', sources: [{ file: 'a.js' }], uncertainty: 0.5, ...over }; });
    assert.equal(validateInvariant(inferred({})).ok, true);
    assert.ok(codes(inferred({ sources: [] })).includes('MISSING_FIELD'));
    assert.ok(codes(inferred({ uncertainty: 2 })).includes('MISSING_FIELD'));
    assert.ok(codes(inferred({ uncertainty: undefined })).includes('MISSING_FIELD'));
    assert.ok(codes(mutate('tenant', (c) => { c.review = { state: 'proposed', origin: 'inferred', sources: [{ f: 1 }], uncertainty: 0.5 }; })).includes('RULE_VIOLATION'), 'human author on an inferred contract');
    assert.ok(codes(mutate('tenant', (c) => { c.author = { id: 'bot', kind: 'model' }; })).includes('RULE_VIOLATION'), 'a model cannot be the author of an authored contract');
  });

  test('[X-401.AC03] hostile input never throws', () => {
    for (const bad of [null, undefined, 7, 'x', [], { schema: 'agentic-security/invariant' }, { schema: 'other' }]) {
      assert.doesNotThrow(() => validateInvariant(bad));
      assert.equal(validateInvariant(bad).ok, false);
    }
  });
});
