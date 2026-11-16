// A webhook tester: GET /check?url=<url> fetches the URL and returns the start of its body. It resolves the host and refuses an
// internal address first, then lets the client resolve the host again when it connects.
import { lookup } from 'node:dns/promises';
import net from 'node:net';

const INTERNAL = /^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.)/;

export function createApp() {
  return async (req, res) => {
    const u = new URL(req.url, 'http://app.local');
    if (u.pathname !== '/check') { res.writeHead(404); res.end('not found'); return; }
    try {
      const target = new URL(u.searchParams.get('url') || '');
      const host = target.hostname.replace(/^\[|\]$/g, '');
      const address = net.isIP(host) ? host : (await lookup(host)).address;
      if (INTERNAL.test(address)) { res.writeHead(403); res.end('internal destination'); return; }
      const r = await fetch(target, { redirect: 'manual' });
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end((await r.text()).slice(0, 500));
    } catch {
      res.writeHead(502);
      res.end('fetch failed');
    }
  };
}
