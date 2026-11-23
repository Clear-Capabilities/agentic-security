// API: trusts the tenant header the gateway sets, and enqueues an invoice update for the worker.
import { queue } from './queue.js';

export function reviseMemo(req, res, db) {
  const tenant = req.headers['x-tenant'];
  const rec = db.findOne(`invoices/${req.params.id}`, { tenant });
  if (!rec) return res.status(404).end();
  queue.publish('invoice-memo', { tenantId: tenant, invoiceId: req.params.id, note: req.body.note });
  return res.status(202).end();
}
