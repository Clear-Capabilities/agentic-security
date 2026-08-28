// PRD Product Acceptance Scenario F — shallow clone.
//
// "The finding is present at the oldest available commit. Output says
// earliest observable, partial, low confidence, and identifies the shallow
// boundary." Unlike every other fixture in this corpus, there is no single
// commit SHA that is the "right answer" here — the whole point of the
// scenario is that the true origin is NOT visible to this clone, and the
// PRD's "false certainty" success metric (0 cases where partial history is
// labeled definitive origin) is exactly what's being tested. Accuracy for
// this fixture means the engine correctly DECLINED to claim `complete`, not
// that it named a specific commit — see `expect: 'partial'` and
// runner.mjs's `scoreExpectation`.
//
// Build: a real two-commit history (safe baseline, then the introducing
// commit), then a genuine `git clone --depth 1` of it — not merely a
// single-commit repo (that is the DIFFERENT, `root-commit-no-parent.mjs`
// case, which is legitimately `complete` because it is honestly not
// shallow). `git rev-parse --is-shallow-repository` on the clone is what
// `getRepoState()` (git-evidence.js) actually reads, so this is the real
// signal the resolver keys its `shallow-boundary-reached` branch on, not a
// synthesized flag.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFileSync } from 'node:child_process';

export const manifest = {
  id: 'shallow-clone-partial',
  scenario: 'PRD Scenario F — shallow clone',
  description: 'A --depth 1 clone hides the vulnerable commit\'s parent; correct behaviour is declining to claim a verified origin.',
  expect: 'partial',
  build(fx) {
    fx.writeFile('server.js', 'function h(req) {\n  return 1;\n}\n');
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n',
    );
    fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const cloneDir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-provenance-accuracy-shallow-'));
    execFileSync('git', ['clone', '--depth', '1', '--no-local', `file://${fx.root}`, cloneDir], { stdio: 'ignore' });

    return {
      commit: null, // no specific commit is the correct answer for this class
      root: cloneDir,
      cleanup: () => fs.rmSync(cloneDir, { recursive: true, force: true }),
    };
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
