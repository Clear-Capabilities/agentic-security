// Edge case: the vulnerable line exists in the repository's very first
// (root) commit — no parent at all, but genuinely NOT a shallow clone. This
// is the direct contrast to shallow-clone-partial.mjs: `getFirstParent`
// returns null in BOTH fixtures, and the only thing that tells them apart is
// `repoState.shallow` (a real `git rev-parse --is-shallow-repository`
// result). `origin-resolver.js`'s root-commit branch treats this as weaker
// evidence than a verified parent-absence (`parentBoundaryVerified: false`,
// confidence capped at MEDIUM) but still resolves `status:'complete'` with
// the root commit as origin — the PRD forbids false certainty, not every
// claim made without a parent to check against; a genuine repository root
// really does prove absence-before-existence vacuously.
export const manifest = {
  id: 'root-commit-no-parent',
  scenario: 'Edge case — vulnerable line in the true repository root commit (non-shallow)',
  description: 'The only commit in the repository already contains the vulnerable line; a real repo root, not a shallow boundary.',
  expect: 'commit',
  build(fx) {
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n',
    );
    return fx.commit('only commit — repo root', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
