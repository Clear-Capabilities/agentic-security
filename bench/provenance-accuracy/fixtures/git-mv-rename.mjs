// Adverse history (GA-05, 0.195.27): a true `git mv` after the introduction, line unchanged.
//
// `rename.mjs` covers a delete-plus-re-add with near-identical content. This fixture is the other rename shape: the
// flaw is introduced in `old.js`, then the file is moved to `new.js` by `git mv` with no content change. The move
// commit did not introduce anything, so the origin is the earlier commit A under the old name, found by walking the
// rename chain (`git-evidence.js` `renameChain`, `predicate-replay.js`). A result naming the move commit would blame
// a refactor for a flaw it only carried.
import { execFileSync } from 'node:child_process';

const SAFE = 'function h(req) {\n  return 1;\n}\n';
const VULN = 'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n';
const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

export const manifest = {
  id: 'git-mv-rename',
  scenario: 'Adverse history: git mv after introduction',
  description: 'The file is moved with git mv after the flaw was introduced; the origin is the pre-move commit, not the move.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('old.js', SAFE);
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('old.js', VULN);
    const shaA = fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    git(fx.root, ['mv', 'old.js', 'new.js']);
    git(fx.root, ['commit', '-q', '-m', 'move old.js to new.js']);
    return shaA;
  },
  finding: { file: 'new.js', line: 3, vuln: /^SQL Injection$/ },
};
