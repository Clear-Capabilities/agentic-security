// Invoices service: HTTP layer. Express routes over the shared store operations in service.mjs. Every route runs behind
// requireSession, which rejects a request without a valid session before any handler, and readJsonBody, which parses the body.
import express from 'express';
import { getInvoice, setInvoiceMemo, addInvoice } from './service.mjs';

const SESSIONS = {
  'session-ana': { id: 'ana', tenant: 'acme', role: 'member' },
  'session-gus': { id: 'gus', tenant: 'globex', role: 'member' },
};

export function requireSession(req, res, next) {
  const principal = SESSIONS[req.headers['x-session']];
  if (!principal) return res.status(401).json({ error: 'unauthenticated' });
  req.principal = principal;
  return next();
}

export function readJsonBody(req, res, next) {
  let raw = '';
  req.on('data', (chunk) => { raw += chunk; });
  req.on('end', () => {
    try { req.body = raw ? JSON.parse(raw) : {}; } catch { return res.status(400).json({ error: 'bad json' }); }
    return next();
  });
}

export function createServer(db) {
  const app = express();
  app.use(requireSession);
  app.use(readJsonBody);

  app.get('/invoices/:id', (req, res) => {
    const r = getInvoice(db, req.principal, `invoices/${req.params.id}`);
    res.status(r.status).json(r.body || {});
  });

  app.put('/invoices/:id/memo', (req, res) => {
    const r = setInvoiceMemo(db, req.principal, `invoices/${req.params.id}`, req.body);
    res.status(r.status).json(r.body || {});
  });

  app.post('/invoices', (req, res) => {
    const r = addInvoice(db, req.principal, `invoices/${req.body.id}`, req.body);
    res.status(r.status).json(r.body || {});
  });

  return app;
}
