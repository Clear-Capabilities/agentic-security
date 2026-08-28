// Direct introduction, code-injection (eval) family — same PRD Scenario A
// shape as direct-introduction.mjs, against a third detector family for
// diversity (see command-injection-direct.mjs's header for why that matters).
export const manifest = {
  id: 'code-injection-eval-direct',
  scenario: 'PRD Scenario A shape — direct introduction (code injection / eval family)',
  description: 'A commit replaces a safe Number() coercion with eval() of raw user input; parent is safe.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('calc.js', 'function calc(req, res) {\n  const expr = req.body.expr;\n  res.send(String(Number(expr)));\n}\n');
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('calc.js', 'function calc(req, res) {\n  const expr = req.body.expr;\n  res.send(eval(expr));\n}\n');
    return fx.commit('introduce eval code injection', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
  },
  finding: { file: 'calc.js', line: 3, vuln: /^Code Injection$/ },
};
