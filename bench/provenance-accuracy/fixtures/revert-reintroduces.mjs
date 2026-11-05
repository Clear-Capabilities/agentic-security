// Adverse history (GA-05, 0.195.27): the origin commit is itself a revert.
//
// base (safe) -> Y introduces the flaw -> Z = `git revert Y` (the flaw is gone) -> W = `git revert Z` (the flaw is back).
// With the whole history visible the oldest-candidate rule names Y, exactly as `reintroduction.mjs` documents, so this
// fixture bounds the walk with `--provenance-since Y`: the candidates are then Z and W only, W is the first commit in
// range that carries the predicate while its parent does not, and W is a revert of Z. In deep mode the record must say
// so: `findingOrigin.revertOf` names Z, by diff inversion (`dag-walk.js` `detectRevert`), not by the commit message
// alone. Before 0.195.27 the annotation was computed only in deep mode's retry loop, which a resolved standard walk
// never reached, so a result like this one carried `revertOf: null` in every mode.
import { execFileSync } from 'node:child_process';

const SAFE = 'function h(req) {\n  return 1;\n}\n';
const VULN = 'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n';
const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

export const manifest = {
  id: 'revert-reintroduces',
  scenario: 'Adverse history: the origin commit is a revert',
  description: 'A fix is reverted, bringing the flaw back; bounded at the first introduction, the origin is the revert commit and the record names what it reverted.',
  expect: 'commit',
  mode: 'deep',
  build(fx) {
    fx.writeFile('server.js', SAFE);
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('server.js', VULN);
    const shaY = fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    git(fx.root, ['revert', '--no-edit', shaY]);
    const shaZ = git(fx.root, ['rev-parse', 'HEAD']);
    git(fx.root, ['revert', '--no-edit', shaZ]);
    const shaW = git(fx.root, ['rev-parse', 'HEAD']);
    return { commit: shaW, env: { AGENTIC_SECURITY_PROVENANCE_SINCE: shaY }, facts: { reverted: shaZ } };
  },
  verify(fp, facts) {
    const got = fp.findingOrigin && fp.findingOrigin.revertOf;
    return got === facts.reverted ? null : `findingOrigin.revertOf is ${JSON.stringify(got)}, expected the reverted commit ${facts.reverted}`;
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
