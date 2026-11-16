export function sendJson(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(value));
}

export function readJson(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (d) => { raw += d; });
    req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { resolve({}); } });
  });
}
