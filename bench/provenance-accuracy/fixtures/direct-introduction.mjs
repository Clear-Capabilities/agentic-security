// PRD Product Acceptance Scenario A — direct introduction.
//
// "A commit adds string-concatenated SQL. The parent is safe. The finding
// reports that commit, author date, author, high confidence, and parent
// absence." The canonical, simplest case: one safe commit, one commit that
// introduces the vulnerable shape on a line that did not exist before.
export const manifest = {
  id: 'direct-introduction',
  scenario: 'PRD Scenario A — direct introduction',
  description: 'A commit adds string-concatenated SQL onto a previously-safe function; parent is safe.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('server.js', 'function h(req) {\n  return 1;\n}\n');
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n',
    );
    return fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
