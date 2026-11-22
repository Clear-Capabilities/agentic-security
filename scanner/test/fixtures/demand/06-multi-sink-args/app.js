function handler(req, res) {
  el.insertAdjacentHTML(req.query.pos, '<b>fixed</b>');
  el.insertAdjacentHTML('beforeend', req.query.html);
}
function evalBoth(req) {
  const f = new Function(req.query.a, 'return 1');
  return f;
}
