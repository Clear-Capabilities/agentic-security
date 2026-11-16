// Builds the query by string concatenation: the title escapes its quotes and returns every owner's notes.
export function createApp({ db }) {
  return (req, res) => {
    const url = new URL(req.url, 'http://app.local');
    const user = String(req.headers['x-user'] || '');
    if (!user) { res.writeHead(401).end(); return; }
    const title = url.searchParams.get('title') || '';
    const rows = db.prepare(`SELECT title, body FROM notes WHERE owner = '${user}' AND title = '${title}'`).all();
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(rows));
  };
}
