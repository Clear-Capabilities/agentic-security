// Routing decision receipts (X-605, X-606, X-608): an append-only, hash-chained log of every shadow decision, replay, drift
// assessment, canary event, rollback, promotion verdict and operator control change.
//
// Why a chain. A rollback must not lose the evidence of the decisions that led to it, and an exported log must be checkable by
// someone with only the file. Each receipt carries the hash of the previous one, so a missing, reordered or edited receipt breaks
// `verifyReceiptChain`. This is tamper EVIDENCE for whoever holds the export, not a signature and not independent certification.
//
// A receipt body is JSON-cloned on the way in (no live references, no functions), and callers pass sanitized decision metadata only:
// never a prompt, a response or source text. The clock is a parameter, so a reproduction can fix it.

import { digestOf } from '../assurance/identity.js';

export const ROUTING_RECEIPT_SCHEMA = 'agentic-security/routing-receipt-chain';
export const ROUTING_RECEIPT_KINDS = Object.freeze(['shadow-decision', 'replay', 'promotion', 'drift', 'canary', 'rollback', 'control', 'feedback']);
const MAX_RECEIPTS = 100_000;
const GENESIS = 'sha256:genesis';

export function createReceiptLog({ now = () => new Date().toISOString() } = {}) {
  const receipts = [];
  return {
    append(kind, body) {
      if (!ROUTING_RECEIPT_KINDS.includes(kind)) throw new Error(`unknown routing receipt kind '${kind}'`);
      if (receipts.length >= MAX_RECEIPTS) throw new Error('routing receipt log is full');
      const r = { seq: receipts.length, kind, at: now(), body: JSON.parse(JSON.stringify(body ?? null)), prev: receipts.length ? receipts[receipts.length - 1].hash : GENESIS };
      r.hash = digestOf({ ...r, hash: undefined });
      receipts.push(Object.freeze(r));
      return r;
    },
    entries() { return receipts.slice(); },
    head() { return receipts.length ? receipts[receipts.length - 1].hash : GENESIS; },
    get length() { return receipts.length; },
  };
}

/** Recompute every hash and link. Fails closed on any gap, reorder, edit or unknown kind. */
export function verifyReceiptChain(receipts) {
  if (!Array.isArray(receipts)) return { ok: false, reason: 'not a list of receipts', brokenAt: null };
  let prev = GENESIS;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    if (!r || typeof r !== 'object') return { ok: false, reason: `receipt ${i} is not an object`, brokenAt: i };
    if (r.seq !== i) return { ok: false, reason: `receipt ${i} has sequence ${r.seq} (a receipt is missing or reordered)`, brokenAt: i };
    if (!ROUTING_RECEIPT_KINDS.includes(r.kind)) return { ok: false, reason: `receipt ${i} has an unknown kind`, brokenAt: i };
    if (r.prev !== prev) return { ok: false, reason: `receipt ${i} does not link to the one before it`, brokenAt: i };
    if (digestOf({ ...r, hash: undefined }) !== r.hash) return { ok: false, reason: `receipt ${i} was modified after it was written`, brokenAt: i };
    prev = r.hash;
  }
  return { ok: true, reason: 'chain verified', brokenAt: null };
}

/** The portable export: the chain plus its head, checkable offline with `verifyReceiptChain`. */
export function exportReceipts(log) {
  const receipts = log.entries();
  const byKind = Object.fromEntries(ROUTING_RECEIPT_KINDS.map((k) => [k, receipts.filter((r) => r.kind === k).length]));
  return JSON.parse(JSON.stringify({
    schema: ROUTING_RECEIPT_SCHEMA, schemaVersion: '1.0.0', count: receipts.length, byKind, headHash: log.head(), receipts,
    disclosure: 'a hash-linked log: tamper evidence for the holder of the export, not a signature and not independent certification',
  }));
}
