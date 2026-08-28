// Direct introduction, command-injection family — the same PRD Scenario A
// shape as direct-introduction.mjs, deliberately duplicated against a
// DIFFERENT detector family so this corpus's accuracy figure is not solely a
// statement about the SQL-injection regex rule.
export const manifest = {
  id: 'command-injection-direct',
  scenario: 'PRD Scenario A shape — direct introduction (command injection family)',
  description: 'A commit adds unsanitized user input to a child_process.exec() call; parent is safe.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('ping.js', 'function ping(req, res) {\n  const host = req.body.host;\n  console.log(host);\n}\n');
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile(
      'ping.js',
      'const { exec } = require("child_process");\nfunction ping(req, res) {\n  const host = req.body.host;\n  exec("ping " + host, (e,o) => res.send(o));\n}\n',
    );
    return fx.commit('introduce command injection', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
  },
  finding: { file: 'ping.js', line: 4, vuln: /^Command Injection$/ },
};
