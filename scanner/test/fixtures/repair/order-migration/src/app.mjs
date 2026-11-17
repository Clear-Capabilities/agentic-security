// Orders: POST /orders/<id>/pay charges the buyer through the payment provider; POST /orders/<id>/ship ships the order.
// The provider stand-in records every charge it accepts in provider_charges: that table is the provider's side, not the application's.
const providerFor = (db) => ({
  charge: (orderId, amount) => new Promise((resolve) => setImmediate(() => {
    db.prepare('INSERT INTO provider_charges (order_id, amount) VALUES (?, ?)').run(orderId, amount);
    resolve({ ok: true, amount });
  })),
});

export function createApp({ db }) {
  const provider = providerFor(db);
  const byId = db.prepare('SELECT id, buyer, amount, status FROM orders WHERE id = ?');
  const send = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  const handle = async (req, res) => {
    const m = /^\/orders\/(\d+)\/(pay|ship)$/.exec(req.url);
    if (req.method !== 'POST' || !m) return send(res, 404, { error: 'not found' });
    const order = byId.get(Number(m[1]));
    if (!order) return send(res, 404, { error: 'no such order' });
    if (m[2] === 'pay') {
      const r = await provider.charge(order.id, order.amount);
      db.prepare("INSERT INTO events (order_id, kind, amount) VALUES (?, 'charge', ?)").run(order.id, r.amount);
      db.prepare("UPDATE orders SET status = 'paid' WHERE id = ?").run(order.id);
      return send(res, 200, { ok: true, status: 'paid' });
    }
    db.prepare("INSERT INTO events (order_id, kind, amount) VALUES (?, 'ship', 0)").run(order.id);
    db.prepare("UPDATE orders SET status = 'shipped' WHERE id = ?").run(order.id);
    return send(res, 200, { ok: true, status: 'shipped' });
  };
  // the error boundary every framework has: a failed request is a 500, not a dead process
  return async (req, res) => { try { await handle(req, res); } catch { if (!res.headersSent) send(res, 500, { error: 'internal error' }); } };
}
