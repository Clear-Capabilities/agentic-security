// PRD Product Acceptance Scenario D — merge.
//
// "The vulnerability originates on a feature branch and enters main through a
// merge. Both commits are shown." This fixture asserts the FIRST half of
// that claim — `findingProvenance.findingOrigin.commit` names the
// feature-branch commit, not the merge commit — which is what
// `origin-resolver.js` computes (a plain `git log -L`, no `--first-parent`,
// walking oldest-first, landing on the feature-branch commit whose own first
// parent is the pre-branch baseline). The "both commits are shown" half is
// `findingProvenance.branchIntroduction` (`branch-entry.js`), asserted
// directly by `scanner/test/posture/provenance-branch-entry.test.js` — out of
// scope for THIS corpus, whose ground truth is specifically the origin commit.
export const manifest = {
  id: 'merge',
  scenario: 'PRD Scenario D — merge',
  description: 'Vulnerability is introduced on a feature branch and enters the default branch through a --no-ff merge.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('server.js', 'function h(req) {\n  return 1;\n}\n');
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    const defaultBranch = fx.currentBranch();

    fx.checkoutBranch('feature');
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n',
    );
    const shaVuln = fx.commit('introduce sqli on feature', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    fx.checkout(defaultBranch);
    fx.merge('feature', `merge feature into ${defaultBranch}`);

    return shaVuln;
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
