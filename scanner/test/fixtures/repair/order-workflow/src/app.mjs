// Orders: POST /orders/<id>/pay charges the buyer through the payment provider; POST /orders/<id>/ship ships the order.
const provider = { charge: (amount) => new Promise((resolve) => setImmediate(() => resolve({ ok: true, amount }))) };

export function createApp({ db }) {
  const byId = db.prepare('SELECT id, buyer, amount, status FROM orders WHERE id = ?');
  const send = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  return async (req, res) => {
    const m = /^\/orders\/(\d+)\/(pay|ship)$/.exec(req.url);
    if (req.method !== 'POST' || !m) return send(res, 404, { error: 'not found' });
    const order = byId.get(Number(m[1]));
    if (!order) return send(res, 404, { error: 'no such order' });
    if (m[2] === 'pay') {
      const r = await provider.charge(order.amount);
      db.prepare("INSERT INTO events (order_id, kind, amount) VALUES (?, 'charge', ?)").run(order.id, r.amount);
      db.prepare("UPDATE orders SET status = 'paid' WHERE id = ?").run(order.id);
      return send(res, 200, { ok: true, status: 'paid' });
    }
    db.prepare("INSERT INTO events (order_id, kind, amount) VALUES (?, 'ship', 0)").run(order.id);
    db.prepare("UPDATE orders SET status = 'shipped' WHERE id = ?").run(order.id);
    return send(res, 200, { ok: true, status: 'shipped' });
  };
}
