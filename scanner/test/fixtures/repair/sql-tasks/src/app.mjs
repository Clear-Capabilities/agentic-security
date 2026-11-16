// A task board: GET /projects/<name>/tasks?status=<status> lists the tasks of one project.
function listTasks(db, project, status) {
  return db.prepare(`SELECT label, status FROM tasks WHERE project = '${project}' AND status = '${status}' ORDER BY id`).all();
}

export function createApp({ db }) {
  return (req, res) => {
    const url = new URL(req.url, 'http://tasks.local');
    const m = /^\/projects\/([^/]+)\/tasks$/.exec(url.pathname);
    res.setHeader('content-type', 'application/json');
    if (req.method !== 'GET' || !m) { res.statusCode = 404; res.end('{"error":"not found"}'); return; }
    try {
      const tasks = listTasks(db, decodeURIComponent(m[1]), url.searchParams.get('status') || 'open');
      res.end(JSON.stringify({ project: decodeURIComponent(m[1]), tasks }));
    } catch {
      res.statusCode = 500;
      res.end('{"error":"query failed"}');
    }
  };
}
