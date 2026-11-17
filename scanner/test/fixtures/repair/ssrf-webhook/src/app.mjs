// A webhook relay: POST /notify with {"target": "<url>", "event": "<name>"} posts the event to the target and reports its status.
// Written separately from the link-preview fixture: a JSON body, a POST with options, and the status (not the body) returned.
const readBody = (req) => new Promise((resolve) => { let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { resolve({}); } }); });

export function createApp() {
  return async (req, res) => {
    if (req.method !== 'POST' || req.url !== '/notify') { res.writeHead(404); res.end('not found'); return; }
    const { target, event } = await readBody(req);
    try {
      const reply = await fetch(target, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ event: String(event || 'ping') }) });
      const text = await reply.text();
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ delivered: reply.status, reply: text.slice(0, 200) }));
    } catch {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ delivered: false }));
    }
  };
}
