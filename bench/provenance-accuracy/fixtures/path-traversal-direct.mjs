// Direct introduction, path-traversal family — same PRD Scenario A shape as
// direct-introduction.mjs, against a fourth detector family for diversity
// (see command-injection-direct.mjs's header for why that matters).
export const manifest = {
  id: 'path-traversal-direct',
  scenario: 'PRD Scenario A shape — direct introduction (path traversal family)',
  description: 'A commit replaces a hardcoded filename with a user-controlled one in fs.readFile(); parent is safe.',
  expect: 'commit',
  build(fx) {
    fx.writeFile(
      'files.js',
      'const fs = require("fs");\nfunction file(req, res) {\n  const name = req.query.name;\n  fs.readFile("safe.txt", "utf8", (e,d) => res.send(d));\n}\n',
    );
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile(
      'files.js',
      'const fs = require("fs");\nfunction file(req, res) {\n  const name = req.query.name;\n  fs.readFile(name, "utf8", (e,d) => res.send(d));\n}\n',
    );
    return fx.commit('introduce path traversal', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
  },
  finding: { file: 'files.js', line: 4, cwe: 'CWE-22' },
};
