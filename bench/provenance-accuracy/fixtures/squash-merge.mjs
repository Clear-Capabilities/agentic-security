// Adverse history (GA-05, 0.195.27): squash merge.
//
// The feature branch has two commits (a harmless refactor, then the flaw). `git merge --squash` folds both into one
// new commit S on main, and the branch's own commits are not reachable from main. The commit that introduced the flaw
// to the scanned history is S; a resolver that chased the feature branch's commits through the reflog or a surviving
// branch name would be naming history the scanned branch does not contain.
import { execFileSync } from 'node:child_process';

const SAFE = 'function h(req) {\n  return 1;\n}\n';
const VULN = 'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n';
const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

export const manifest = {
  id: 'squash-merge',
  scenario: 'Adverse history: squash merge',
  description: 'Two feature commits are squashed into one commit on the scanned branch; the origin is the squash commit.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('server.js', SAFE);
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    const main = fx.currentBranch();
    fx.checkoutBranch('feature');
    fx.writeFile('server.js', `${SAFE}// refactor note\n`);
    fx.commit('refactor', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    fx.writeFile('server.js', `${VULN}// refactor note\n`);
    fx.commit('introduce sqli', { date: '2026-01-03T00:00:00Z', authorName: 'Bob' });
    fx.checkout(main);
    git(fx.root, ['merge', '--squash', 'feature']);
    git(fx.root, ['commit', '-q', '-m', 'feature (squashed)']);
    return git(fx.root, ['rev-parse', 'HEAD']);
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
