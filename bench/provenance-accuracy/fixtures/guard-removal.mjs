// PRD Product Acceptance Scenario B — guard removal.
//
// "Source and sink are old; a later commit removes a sanitizer. Origin is the
// removal commit, not either old line blame." The source (`req.query.id`) and
// the sink (the `db.query` call itself) exist from the very first commit —
// only the guard (parameterized placeholder + bound-params array) is removed
// later, in place, on the SAME line. The true origin is the removal commit,
// not the commit that first wrote the line.
export const manifest = {
  id: 'guard-removal',
  scenario: 'PRD Scenario B — guard removal',
  description: 'A parameterized query is edited in place into string-concatenated SQL; source/sink line predates the removal.',
  expect: 'commit',
  build(fx) {
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = ?", [input]);\n}\n',
    );
    fx.commit('safe: parameterized query', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n',
    );
    return fx.commit('remove parameterization', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
