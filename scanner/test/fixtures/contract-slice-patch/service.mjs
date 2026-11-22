// Invoices service: the store operations shared by the HTTP layer (server.js) and by the business-state oracle, which drives this
// module's `createApp()` factory directly. A principal is `{ id, tenant, role }`; every operation receives it first. The store is a
// document store keyed `invoices/<id>`; each record carries the owning `tenant`, and a read may be scoped with a filter.

export function getInvoice(db, principal, key) {
  const rec = db.findOne(key, { tenant: principal.tenant });
  if (!rec) return { status: 404 };
  return { status: 200, body: rec };
}

export function setInvoiceMemo(db, principal, key, payload) {
  const rec = db.findOne(key, { tenant: principal.tenant });
  if (!rec) return { status: 404 };
  db.updateOne(key, { ...rec, memo: payload && payload.note });
  return { status: 200, body: { ok: true } };
}

export function addInvoice(db, principal, key, payload) {
  const existing = db.findOne(key);
  if (existing) return { status: 409 };
  db.insertOne(key, { tenant: principal.tenant, amount: payload && payload.amount, memo: null });
  return { status: 201, body: { key } };
}

/** A read through a key-value store, honouring an optional `{ tenant }` filter: a record of another tenant reads as absent. */
function scopedRead(kv, key, filter) {
  const rec = kv.read(key);
  if (!rec) return null;
  if (filter && filter.tenant !== undefined && rec.tenant !== filter.tenant) return null;
  return rec;
}

/** The document-store interface the operations use, bound over any key-value store with `read` and `write`. */
export function documentStore(kv) {
  return Object.fromEntries([
    ['findOne', (key, filter) => scopedRead(kv, key, filter)],
    ['updateOne', (key, doc) => kv.write(key, doc)],
    ['insertOne', (key, doc) => kv.write(key, doc)],
  ]);
}

/** Oracle factory: actions take the oracle's `ctx` ({ id, tenant, role, store, emit }) and the declared arguments. */
export function createApp() {
  return {
    readInvoice(ctx, key) { return getInvoice(documentStore(ctx.store), ctx, key); },
    reviseInvoice(ctx, key, payload) { return setInvoiceMemo(documentStore(ctx.store), ctx, key, payload); },
    createInvoice(ctx, key, payload) { return addInvoice(documentStore(ctx.store), ctx, key, payload); },
  };
}
