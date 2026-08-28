// Edge case: the exact same line is edited three times — safe, still-safe,
// then vulnerable — before landing on its final HEAD content. This is a
// direct test of `origin-resolver.js`'s core walk: it must not stop at the
// FIRST candidate that merely touched the line (candidate 1, still safe), it
// must correctly determine the predicate is still false there and keep
// walking until the commit where the predicate first becomes true AND is
// absent in that commit's own parent (candidate 3).
export const manifest = {
  id: 'multi-touch-same-line',
  scenario: 'Edge case — several touches to one line before the real vulnerable edit',
  description: 'The vulnerable line is edited three times (safe -> still-safe -> vulnerable); origin must land on the third edit, not the first touch.',
  expect: 'commit',
  build(fx) {
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = ?", [input]);\n}\n',
    );
    fx.commit('safe v1: parameterized', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = ?", [String(input)]);\n}\n',
    );
    fx.commit('safe v2: coerce to string, still parameterized', { date: '2026-01-02T00:00:00Z', authorName: 'Alice' });
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n',
    );
    return fx.commit('regression: drop parameterization', { date: '2026-01-03T00:00:00Z', authorName: 'Bob' });
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
