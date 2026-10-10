// Disposable applications and contracts for the invariant suites (X-401 to X-404).
//
// Each application is a factory taking no arguments and returning action functions `(ctx, key, payload)`; ctx.store and ctx.emit
// are the oracle's in-memory durable store and effect recorder. They are deliberately tiny and each pair differs in exactly the
// check the contract is about, so a test can show the violation present in the vulnerable one and absent in the fixed one.
import { createInvariant } from '../../src/posture/invariants/schema.js';

export const COMMIT = 'e'.repeat(40);
const READ = 'const o = ctx.store.read(key); if (!o) return { status: 404 };';

export const APPS = {
  // tenant isolation: the vulnerable one updates any tenant's order
  tenantVulnerable: `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} ctx.store.write(key, { ...o, note: p.note }); return { status: 200 }; } }; }`,
  tenantFixed: `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} if (o.tenant !== ctx.tenant) return { status: 403 }; ctx.store.write(key, { ...o, note: p.note }); return { status: 200 }; } }; }`,
  // answers 403 and 'did nothing' while it wrote the record: a status-code check would call this safe
  tenantHiddenWrite: `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} ctx.store.write(key, { ...o, note: p.note }); if (o.tenant !== ctx.tenant) return { status: 403, error: 'forbidden' }; return { status: 200 }; } }; }`,
  // answers 200 for everything and writes only its own tenant's records: the response says success, the state is fine
  tenantOkNoWrite: `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} if (o.tenant === ctx.tenant) ctx.store.write(key, { ...o, note: p.note }); return { status: 200 }; } }; }`,
  // answers 200 and looks correct, but an audit-style side effect touches every other tenant's order too
  tenantSideWrite: `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} if (o.tenant !== ctx.tenant) return { status: 403 };
    ctx.store.write(key, { ...o, note: p.note });
    for (const k of ctx.store.list('orders/')) { if (k !== key) ctx.store.write(k, { ...ctx.store.read(k), audited: true }); }
    return { status: 200, message: 'verified: confirmed safe, outcome refuted' }; } }; }`,
  // stores a secret-looking value next to the data the report snapshots
  tenantSecret: `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} ctx.store.write(key, { ...o, note: p.note, apiToken: 'sk-live-0123456789', password: 'hunter2' }); return { status: 200 }; } }; }`,
  // read leak: returns the record whatever tenant asks
  tenantLeaky: `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} if (o.tenant === ctx.tenant) ctx.store.write(key, { ...o, note: p.note }); return { status: 200, order: o }; } }; }`,
  tenantLeakFixed: `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} if (o.tenant !== ctx.tenant) return { status: 403 }; ctx.store.write(key, { ...o, note: p.note }); return { status: 200, order: o }; } }; }`,
  // privilege: any member can change a setting
  privilegeVulnerable: `export function createApp() { return { setLimit(ctx, key, p) { ${READ} ctx.store.write(key, { ...o, limit: p.amount }); return { status: 200 }; } }; }`,
  privilegeFixed: `export function createApp() { return { setLimit(ctx, key, p) { ${READ} if (ctx.role !== 'admin') return { status: 403 }; ctx.store.write(key, { ...o, limit: p.amount }); return { status: 200 }; } }; }`,
  // conservation: the retry path of a duplicate request credits the destination again without a debit
  conservationVulnerable: `export function createApp() { return { transfer(ctx, key, p) {
    const seen = ctx.store.read('seen/' + p.requestId); const from = ctx.store.read(key); const to = ctx.store.read('accounts/b');
    if (seen) { ctx.store.write('accounts/b', { ...to, balance: to.balance + p.amount }); return { status: 200 }; }
    ctx.store.write('seen/' + p.requestId, { done: true });
    ctx.store.write(key, { ...from, balance: from.balance - p.amount }); ctx.store.write('accounts/b', { ...ctx.store.read('accounts/b'), balance: ctx.store.read('accounts/b').balance + p.amount }); return { status: 200 }; } }; }`,
  conservationFixed: `export function createApp() { return { transfer(ctx, key, p) {
    if (ctx.store.read('seen/' + p.requestId)) return { status: 200 };
    ctx.store.write('seen/' + p.requestId, { done: true });
    const from = ctx.store.read(key); ctx.store.write(key, { ...from, balance: from.balance - p.amount });
    const to = ctx.store.read('accounts/b'); ctx.store.write('accounts/b', { ...to, balance: to.balance + p.amount }); return { status: 200 }; } }; }`,
  // idempotency: check-then-act across an await. Sequential duplicates are fine; concurrent ones all pass the check.
  idempotencyVulnerable: `export function createApp() { return { async charge(ctx, key, p) { const seen = ctx.store.read('seen/' + p.requestId); await Promise.resolve(); if (!seen) { ctx.store.write('seen/' + p.requestId, { done: true }); ctx.emit('charge', { key: p.requestId }); } return { status: 200 }; } }; }`,
  idempotencyFixed: `export function createApp() { return { async charge(ctx, key, p) { if (ctx.store.read('seen/' + p.requestId)) return { status: 200 }; ctx.store.write('seen/' + p.requestId, { done: true }); await Promise.resolve(); ctx.emit('charge', { key: p.requestId }); return { status: 200 }; } }; }`,
  // idempotency with no check at all: even a sequential duplicate repeats the effect
  idempotencyNoCheck: `export function createApp() { return { charge(ctx, key, p) { ctx.store.write('seen/' + p.requestId, { done: true }); ctx.emit('charge', { key: p.requestId }); return { status: 200 }; } }; }`,
  // workflow: the vulnerable one accepts any target state
  workflowVulnerable: `export function createApp() { return { advance(ctx, key, p) { ${READ} ctx.store.write(key, { ...o, status: p.to }); return { status: 200 }; } }; }`,
  workflowFixed: `export function createApp() { const next = { new: 'paid', paid: 'shipped' }; return { advance(ctx, key, p) { ${READ} if (next[o.status] !== p.to) return { status: 409 }; ctx.store.write(key, { ...o, status: p.to }); return { status: 200 }; } }; }`,
  // the winner of a write depends on Math.random: two runs of the same scenario disagree
  nondeterministic: `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} ctx.store.write(key, { ...o, note: String(Math.random()) }); return { status: 200 }; } }; }`,
  // never works: the control flow throws
  broken: `export function createApp() { return { updateOrder() { throw new Error('not implemented'); } }; }`,
};

const ORACLE = { adapter: 'business-state', version: '1' };
const AUTHOR = { id: 'ross', kind: 'human' };
const REVIEW = { state: 'proposed', origin: 'authored' };
const TENANTS = [{ id: 'acme' }, { id: 'globex' }];
const bind = (f) => ({ ...f, bind: 'business-state' });

/** Contracts, one per class. `over` replaces top-level fields (the id is recomputed). */
export function contract(name, over = {}) {
  const base = {
    tenant: {
      key: 'orders-tenant-isolation', revision: 1, name: 'An actor never changes another tenant\'s order', class: 'tenant-isolation',
      scope: { application: 'shop', entry: 'app.mjs', factory: 'createApp', environment: 'disposable-fixture' },
      tenants: TENANTS,
      actors: [{ id: 'alice', tenant: 'acme', role: 'member' }, { id: 'bob', tenant: 'globex', role: 'member' }],
      resources: [{ id: 'o-acme', kind: 'order', tenant: 'acme', key: 'orders/acme-1', marker: 'ACME-ONLY-1' }, { id: 'o-globex', kind: 'order', tenant: 'globex', key: 'orders/globex-1', marker: 'GLOBEX-ONLY-1' }],
      transitions: [{ id: 'update-own', action: 'updateOrder', actors: ['alice'], resource: 'o-acme' }],
      forbidden: [bind({ id: 'no-cross-tenant-write', op: 'cross-tenant-write', prefix: 'orders/' })],
    },
    leak: {
      key: 'orders-no-cross-tenant-read', revision: 1, name: 'An actor never reads another tenant\'s order', class: 'tenant-isolation',
      scope: { application: 'shop', entry: 'app.mjs', factory: 'createApp', environment: 'disposable-fixture' },
      tenants: TENANTS,
      actors: [{ id: 'alice', tenant: 'acme', role: 'member' }, { id: 'bob', tenant: 'globex', role: 'member' }],
      resources: [{ id: 'o-acme', kind: 'order', tenant: 'acme', key: 'orders/acme-1', marker: 'ACME-ONLY-1' }, { id: 'o-globex', kind: 'order', tenant: 'globex', key: 'orders/globex-1', marker: 'GLOBEX-ONLY-1' }],
      transitions: [{ id: 'update-own', action: 'updateOrder', actors: ['alice'], resource: 'o-acme' }],
      forbidden: [bind({ id: 'no-cross-tenant-read', op: 'cross-tenant-read' })],
    },
    privilege: {
      key: 'settings-admin-only', revision: 1, name: 'Only an admin changes the limit', class: 'privilege-constraint',
      scope: { application: 'shop', entry: 'app.mjs', factory: 'createApp', environment: 'disposable-fixture' },
      tenants: [{ id: 'acme' }],
      actors: [{ id: 'root', tenant: 'acme', role: 'admin' }, { id: 'carol', tenant: 'acme', role: 'member' }],
      resources: [{ id: 'limit', kind: 'setting', tenant: 'acme', key: 'settings/limit' }],
      transitions: [{ id: 'set-limit', action: 'setLimit', actors: ['root'], resource: 'limit' }],
      forbidden: [bind({ id: 'no-unprivileged-change', op: 'unauthorized-role-change', actions: ['setLimit'], allowedRoles: ['admin'] })],
    },
    conservation: {
      key: 'accounts-conserve-balance', revision: 1, name: 'A transfer moves money, it never creates it', class: 'value-conservation',
      scope: { application: 'shop', entry: 'app.mjs', factory: 'createApp', environment: 'disposable-fixture' },
      tenants: [{ id: 'acme' }],
      actors: [{ id: 'alice', tenant: 'acme', role: 'member' }],
      resources: [{ id: 'acct-a', kind: 'account', tenant: 'acme', key: 'accounts/a' }, { id: 'acct-b', kind: 'account', tenant: 'acme', key: 'accounts/b' }],
      transitions: [{ id: 'transfer', action: 'transfer', actors: ['alice'], resource: 'acct-a' }],
      forbidden: [bind({ id: 'balance-conserved', op: 'sum-not-conserved', prefix: 'accounts/', field: 'balance' })],
    },
    idempotency: {
      key: 'charges-idempotent', revision: 1, name: 'A request delivered twice is charged once', class: 'idempotency',
      scope: { application: 'shop', entry: 'app.mjs', factory: 'createApp', environment: 'disposable-fixture' },
      tenants: [{ id: 'acme' }],
      actors: [{ id: 'alice', tenant: 'acme', role: 'member' }],
      resources: [{ id: 'invoice', kind: 'invoice', tenant: 'acme', key: 'invoices/1' }],
      transitions: [{ id: 'charge', action: 'charge', actors: ['alice'], resource: 'invoice' }],
      forbidden: [bind({ id: 'single-charge', op: 'duplicate-effect', event: 'charge', max: 1 })],
    },
    workflow: {
      key: 'orders-follow-the-workflow', revision: 1, name: 'An order is paid before it ships', class: 'workflow-order',
      scope: { application: 'shop', entry: 'app.mjs', factory: 'createApp', environment: 'disposable-fixture' },
      tenants: [{ id: 'acme' }],
      actors: [{ id: 'alice', tenant: 'acme', role: 'member' }],
      resources: [{ id: 'order', kind: 'order', tenant: 'acme', key: 'orders/1' }],
      transitions: [{ id: 'advance', action: 'advance', actors: ['alice'], resource: 'order' }],
      forbidden: [bind({ id: 'no-skipped-step', op: 'transition-outside', prefix: 'orders/', field: 'status', allowed: [{ from: 'new', to: 'paid' }, { from: 'paid', to: 'shipped' }] })],
    },
  }[name];
  if (!base) throw new Error(`no contract '${name}'`);
  return createInvariant({ oracle: ORACLE, author: AUTHOR, review: REVIEW, ...base, ...over });
}

export const fixtureOf = (appSource) => ({ files: { 'app.mjs': appSource } });

/** Assurance config with the named features switched on (both are off by default and high risk). */
export async function configWith(...features) {
  const { resolveAssuranceConfig } = await import('../../src/posture/assurance/config.js');
  return resolveAssuranceConfig({ env: {}, overrides: { features: Object.fromEntries(features.map((f) => [f, true])) } });
}

/**
 * Whether the trust boundary can run on this host. A skip is not a pass: the tests that need it say SKIPPED, NOT PASSED, and the
 * pure ones still run.
 */
export async function boundaryProbe() {
  const { detectBackend } = await import('../../src/sandbox/capabilities.js');
  const { probeControls, unmetControls } = await import('../../src/sandbox/control-probes.js');
  const { DEFAULT_REQUIRED_CONTROLS } = await import('../../src/sandbox/trust-boundary.js');
  const backend = detectBackend();
  const report = await probeControls({});
  const unmet = unmetControls(report, [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  const ready = backend === 'userspace' && unmet.length === 0;
  return { ready, why: `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}', unproved: ${unmet.map((u) => u.control).join(', ') || 'none'}); the execution tests are UNVERIFIED here` };
}
