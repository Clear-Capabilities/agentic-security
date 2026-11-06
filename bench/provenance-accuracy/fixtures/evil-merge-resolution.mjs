// Adverse history (GA-05, 0.195.27): the flaw is written by a merge's conflict resolution.
//
// Both branches edit the same line (harmlessly, and differently), the merge conflicts, and the resolution commits the
// flaw: neither parent carries it. The merge commit itself is the origin. This is the case the per-parent check exists
// for: a merge commit is a candidate like any other, and `complete` needs a parent that lacks the predicate, which the
// first parent does here.
import { execFileSync } from 'node:child_process';

const SAFE = 'function h(req) {\n  return 1;\n}\n';
const VULN = 'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n';
const git = (cwd, args, ok = true) => {
  try { return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch (e) { if (ok) throw e; return null; }
};

export const manifest = {
  id: 'evil-merge-resolution',
  scenario: 'Adverse history: conflict resolution introduces the flaw',
  description: 'Two branches edit the same line; the merge resolution writes the flaw, so the merge commit is the origin.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('server.js', SAFE);
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    const main = fx.currentBranch();
    fx.checkoutBranch('feature');
    fx.writeFile('server.js', 'function h(req) {\n  return 2;\n}\n');
    fx.commit('feature edit', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    fx.checkout(main);
    fx.writeFile('server.js', 'function h(req) {\n  return 3;\n}\n');
    fx.commit('main edit', { date: '2026-01-03T00:00:00Z', authorName: 'Carol' });
    git(fx.root, ['merge', '--no-ff', 'feature'], false); // conflicts, as intended
    fx.writeFile('server.js', VULN);
    git(fx.root, ['add', '-A']);
    git(fx.root, ['commit', '-q', '-m', 'merge feature, resolving the conflict']);
    return git(fx.root, ['rev-parse', 'HEAD']);
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
