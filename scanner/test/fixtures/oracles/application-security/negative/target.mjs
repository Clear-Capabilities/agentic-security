// Binds both values as parameters: the title is data, never SQL.
export function createApp({ db }) {
  const find = db.prepare('SELECT title, body FROM notes WHERE owner = ? AND title = ?');
  return (req, res) => {
    const url = new URL(req.url, 'http://app.local');
    const user = String(req.headers['x-user'] || '');
    if (!user) { res.writeHead(401).end(); return; }
    const rows = find.all(user, url.searchParams.get('title') || '');
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(rows));
  };
}
