// A link-preview service: GET /preview?url=<url> fetches the URL on the server and returns the start of its body.
export function createApp() {
  return async (req, res) => {
    const u = new URL(req.url, 'http://app.local');
    if (u.pathname !== '/preview') { res.writeHead(404); res.end('not found'); return; }
    const target = u.searchParams.get('url') || '';
    try {
      const r = await fetch(target);
      const text = (await r.text()).slice(0, 500);
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(text);
    } catch {
      res.writeHead(502);
      res.end('fetch failed');
    }
  };
}
