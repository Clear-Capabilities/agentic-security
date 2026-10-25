function handler(req, res) {
  res.setHeader(req.query.name, 'fixed');
  res.setHeader('X-Fixed', req.query.value);
}
function evalBoth(req) {
  const f = new Function(req.query.a, 'return 1');
  return f;
}
