// PRD Product Acceptance Scenario C — rename.
//
// "The file is renamed after introduction. Origin follows the lineage and
// current line attribution shows the later rename only as context."
//
// THIS FIXTURE IS A DOCUMENTED, KNOWN MISS, NOT A BADLY-BUILT FIXTURE.
// docs/superpowers/plans/2026-08-26-finding-provenance-m0-m1.md flagged this
// exact gap while M0/M1 was still in flight ("Known gap, documented not
// hidden: no dedicated rename-tracking fixture test (PRD Scenario C) is
// included in this plan... add it as a follow-up task before considering
// FR-PROV-007 done") and it was never subsequently closed. This corpus is
// that follow-up fixture, and running it confirms the gap is real:
//
//   - `origin-resolver.js`'s `candidateCommitsForLine` uses `git log -L`,
//     which DOES follow a rename automatically (verified directly: `git log
//     -L` requires exactly one pathspec and is documented as incompatible
//     with `--follow`, and empirically returns the pre-rename commit as a
//     candidate against the post-rename path) — so the CANDIDATE LIST is
//     correct and includes the true origin commit.
//   - But `relevantFiles()` (origin-resolver.js) always uses `finding.file`,
//     the CURRENT (post-rename) path, and `replayAt()` (predicate-replay.js)
//     fetches blob content for that SAME current path at every candidate
//     commit via `getBlobAtCommit`. At the pre-rename candidate, that path
//     does not exist yet (the file was still under its OLD name) —
//     `getBlobAtCommit` returns null, `replayAt` reports
//     `present:false, reason:'no-files-at-commit'`, and the resolver never
//     even considers the commit that actually introduced the finding.
//
// The net effect: the resolver degrades to
// `status:'partial', reason:'predicate-never-confirmed-in-candidates'`
// instead of resolving to the true origin commit. This fixture's expectation
// is the CORRECT, PRD-mandated answer (the pre-rename commit) — it is
// EXPECTED to score a miss against the current shipped pipeline, and that
// miss is exactly the honest signal this corpus exists to surface. Fixing
// `relevantFiles`/`replayAt` to translate a finding's current path back to
// its historical name per-candidate (e.g. via `git log --follow --name-only`)
// is out of scope for this measurement task — see the task report for the
// recommendation to file it as a follow-up.
import * as fs from 'node:fs';
import * as path from 'node:path';

export const manifest = {
  id: 'rename',
  scenario: 'PRD Scenario C — rename',
  description: 'File containing the vulnerable line is renamed in a later commit; origin should still resolve to the pre-rename introduction.',
  expect: 'commit',
  build(fx) {
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n',
    );
    const shaVuln = fx.commit('introduce sqli', { date: '2026-01-01T00:00:00Z', authorName: 'Bob' });

    // Rename via delete-old + write-new, the standard way to construct a
    // rename in a git fixture — git records no explicit rename operation;
    // it is always inferred at diff/log time from content similarity, which
    // this construction satisfies (only a trailing comment differs).
    // createGitFixture() has no rename helper of its own (writeFile/commit
    // only), so this reaches through to `fx.root` directly with plain node:fs
    // rather than extending shared test infrastructure for one fixture.
    const serverPath = path.join(fx.root, 'server.js');
    const content = fs.readFileSync(serverPath, 'utf8');
    fs.rmSync(serverPath);
    fx.writeFile('api.js', content + '\n// renamed module\n');
    fx.commit('rename server.js to api.js', { date: '2026-01-02T00:00:00Z', authorName: 'Carol' });

    return shaVuln;
  },
  finding: { file: 'api.js', line: 3, vuln: /^SQL Injection$/ },
};
