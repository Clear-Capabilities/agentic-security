// A download route: GET /files?name=<path> returns a file from the public directory, joined by the vulnlib helper.
import fs from 'node:fs';
import { safeJoin } from 'vulnlib';
import { label } from 'otherlib';

export function createApp({ filesRoot }) {
  return (req, res) => {
    const u = new URL(req.url, 'http://app.local');
    if (u.pathname !== '/files') { res.writeHead(404); res.end('not found'); return; }
    const name = u.searchParams.get('name') || '';
    const file = safeJoin(filesRoot, name);
    fs.readFile(file, 'utf8', (err, text) => {
      if (err) { res.writeHead(404); res.end('no such file'); return; }
      res.writeHead(200, { 'content-type': 'text/plain', 'x-label': label(name) });
      res.end(text);
    });
  };
}
