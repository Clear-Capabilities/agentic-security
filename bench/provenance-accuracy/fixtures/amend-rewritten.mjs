// Adverse history (GA-05, 0.195.27): rewritten history.
//
// The introducing commit is amended after it was made (the same flaw, with an extra line added to the file), so the
// commit the author first made is unreachable from any ref and only its replacement A2 is in the scanned history.
// The origin is A2. The dropped commit survives in the reflog for a while; the resolver must not read it, because the
// reflog is local, unordered with respect to the branch and absent from every clone.
import { execFileSync } from 'node:child_process';

const SAFE = 'function h(req) {\n  return 1;\n}\n';
const VULN = 'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n';
const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

export const manifest = {
  id: 'amend-rewritten',
  scenario: 'Adverse history: amended introducing commit',
  description: 'The introducing commit is replaced by an amend; the origin is the replacement, never the unreachable original.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('server.js', SAFE);
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('server.js', VULN);
    fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    fx.writeFile('server.js', `${VULN}// amended\n`);
    git(fx.root, ['add', '-A']);
    git(fx.root, ['commit', '-q', '--amend', '--no-edit']);
    return git(fx.root, ['rev-parse', 'HEAD']);
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
