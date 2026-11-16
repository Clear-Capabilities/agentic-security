// Avatars: GET /avatars/<user> returns the stored avatar description of one user.
import fs from 'node:fs';
import path from 'node:path';

export function createApp({ filesRoot }) {
  return async (req, res) => {
    const m = /^\/avatars\/(.+)$/.exec(new URL(req.url, 'http://avatars.local').pathname);
    if (!m) { res.writeHead(404); res.end('unknown route'); return; }
    const user = decodeURIComponent(m[1]);
    const avatarPath = path.join(filesRoot, user, 'avatar.txt');
    try {
      const text = await fs.promises.readFile(avatarPath, 'utf8');
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(text);
    } catch {
      res.writeHead(404);
      res.end('no avatar');
    }
  };
}
