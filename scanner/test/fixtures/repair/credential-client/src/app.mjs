// Checkout: POST /charge calls the payments service with the merchant API key.
const API_KEY = 'acmepay_merchant_7Hq2xV9Lr4TzP0aB9cD7eF';

export function createApp() {
  return async (req, res) => {
    if (req.method !== 'POST' || req.url !== '/charge') { res.writeHead(404); res.end('not found'); return; }
    try {
      const r = await fetch('http://api.payments.test/v1/charge', { method: 'POST', headers: { authorization: `Bearer ${API_KEY}` } });
      res.writeHead(r.status === 200 ? 200 : 502, { 'content-type': 'text/plain' });
      res.end(r.status === 200 ? await r.text() : 'payment provider refused');
    } catch {
      res.writeHead(502); res.end('payment provider unreachable');
    }
  };
}
