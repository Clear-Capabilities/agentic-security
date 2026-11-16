// Serves both declared requests and stores the new note.
export function createApp({ db }) {
  const find = db.prepare('SELECT title, body FROM notes WHERE owner = ? AND title = ?');
  const add = db.prepare('INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)');
  return (req, res) => {
    const url = new URL(req.url, 'http://app.local');
    const user = String(req.headers['x-user'] || '');
    if (!user) { res.writeHead(401).end(); return; }
    if (req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(find.all(user, url.searchParams.get('title') || '')));
      return;
    }
    let raw = '';
    req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      const b = JSON.parse(raw || '{}');
      add.run(user, String(b.title), String(b.body));
      res.writeHead(201).end();
    });
  };
}
