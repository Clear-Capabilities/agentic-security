// Adverse history (GA-05, 0.195.27): the flaw enters through a merge whose FIRST parent already carries it.
//
// `merge.mjs` merges the feature branch into main, so the merge commit's first parent (main) lacks the flaw. Here the
// direction is reversed: the flaw V is made on the feature branch, main moves on independently, and main is merged
// INTO the feature branch. HEAD is that merge commit, whose first parent (the feature tip) has the flaw and whose
// second parent (main) does not. The origin is V, found by walking the candidates oldest first; the merge commit is
// never a candidate because it did not change the line. Run in deep mode, the mode documented for non-linear history,
// so the non-first-parent retry (`dag-walk.js` `checkAbsentInSomeParent`) is on the scored path.
const SAFE = 'function h(req) {\n  return 1;\n}\n';
const VULN = 'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n';

export const manifest = {
  id: 'non-first-parent-merge',
  scenario: 'Adverse history: merge with the flaw on the first parent',
  description: 'Main is merged into the feature branch that carries the flaw; the origin is the feature commit, not the merge.',
  expect: 'commit',
  mode: 'deep',
  build(fx) {
    fx.writeFile('server.js', SAFE);
    fx.writeFile('README.md', 'r\n');
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    const main = fx.currentBranch();
    fx.checkoutBranch('feature');
    fx.writeFile('server.js', VULN);
    const shaV = fx.commit('introduce sqli on feature', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    fx.checkout(main);
    fx.writeFile('README.md', 'r2\n');
    fx.commit('mainline change', { date: '2026-01-03T00:00:00Z', authorName: 'Carol' });
    fx.checkout('feature');
    fx.merge(main, 'merge main into feature');
    return shaV;
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
