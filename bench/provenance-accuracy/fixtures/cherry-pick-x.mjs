// Adverse history (GA-05, 0.195.27): the flaw reaches the scanned branch by `git cherry-pick -x`.
//
// The introducing commit A lives on a feature branch that is never merged. Main cherry-picks it as C, and the `-x`
// trailer records where C came from. From main's history A is unreachable, so the origin commit on this branch is C,
// and in deep mode `findingOrigin.cherryPickOf` must name A (read from the trailer by `dag-walk.js` `detectCherryPick`).
// A cherry-pick without `-x` leaves no trailer and is reported as an ordinary commit; that is a stated limit, not a case.
import { execFileSync } from 'node:child_process';

const SAFE = 'function h(req) {\n  return 1;\n}\n';
const VULN = 'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n';
const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

export const manifest = {
  id: 'cherry-pick-x',
  scenario: 'Adverse history: cherry-pick with -x',
  description: 'The flaw is introduced on an unmerged branch and cherry-picked onto the scanned branch; the origin is the cherry-pick and the record names its source.',
  expect: 'commit',
  mode: 'deep',
  build(fx) {
    fx.writeFile('server.js', SAFE);
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    const main = fx.currentBranch();
    fx.checkoutBranch('feature');
    fx.writeFile('server.js', VULN);
    const shaA = fx.commit('introduce sqli on feature', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    fx.checkout(main);
    fx.writeFile('README.md', 'unrelated\n');
    fx.commit('unrelated change on main', { date: '2026-01-03T00:00:00Z', authorName: 'Carol' });
    git(fx.root, ['cherry-pick', '-x', shaA]);
    const shaC = git(fx.root, ['rev-parse', 'HEAD']);
    return { commit: shaC, facts: { source: shaA } };
  },
  verify(fp, facts) {
    const got = fp.findingOrigin && fp.findingOrigin.cherryPickOf;
    return got === facts.source ? null : `findingOrigin.cherryPickOf is ${JSON.stringify(got)}, expected the cherry-picked commit ${facts.source}`;
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
