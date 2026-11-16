// A sortable list: the column name comes from the request. A placeholder cannot carry an identifier.
export function createApp({ db }) {
  return (req, res) => {
    const url = new URL(req.url, 'http://list.local');
    const column = url.searchParams.get('sort') || 'name';
    const rows = db.prepare(`SELECT name, size FROM items ORDER BY ${column}`).all();
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(rows));
  };
}
