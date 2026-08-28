// PRD Product Acceptance Scenario E — reintroduction.
//
// "A vulnerability is fixed and later recreated. Lifecycle contains
// introduction, remediation, and reintroduction; current age uses the latest
// open introduction."
//
// WHY THE GROUND TRUTH HERE IS THE *FIRST* INTRODUCTION, NOT THE
// REINTRODUCTION COMMIT. The PRD sentence bundles two different questions
// under one scenario name, and this corpus only measures one of them.
// `findingProvenance.findingOrigin` — what THIS corpus scores — answers "which
// commit first made this predicate true", computed by `origin-resolver.js` as
// a pure function of git history: walk candidates oldest-first, return the
// first one that is present-here and absent-in-parent. That is, and is
// documented (posture/CLAUDE.md's provenance section) to be, the FIRST
// introduction — reintroduction awareness lives in a structurally separate
// mechanism, `provenance/lifecycle.js`'s ledger, which only knows about
// "introduced" vs "reintroduced" by comparing SEQUENTIAL SCANS over time
// (`updateLifecycle` diffs this scan's findings against a persisted
// `.agentic-security/provenance/lifecycle.json` from a PRIOR scan) — it
// cannot be reconstructed from a single scan of a git history built once and
// scanned once, which is this corpus's whole model. Verified directly against
// the real pipeline before this fixture was written: introduce → fix →
// reintroduce (identical code both times) resolves `findingOrigin.commit` to
// the FIRST introduction commit, exactly as `origin-resolver.js`'s own
// documented "oldest candidate wins" contract predicts. That is the correct,
// intended answer for this field — "current age uses the latest open
// introduction" is a claim about `lifecycle.js` + `mttr.js`'s `ageBasis`, not
// about `findingOrigin`, and is out of scope for this specific accuracy
// measurement.
export const manifest = {
  id: 'reintroduction',
  scenario: 'PRD Scenario E — reintroduction',
  description: 'Vulnerability is introduced, fixed, then reintroduced identically; findingOrigin should still resolve to the FIRST introduction.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('server.js', 'function h(req) {\n  return 1;\n}\n');
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });

    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n',
    );
    const shaFirst = fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = ?", [input]);\n}\n',
    );
    fx.commit('fix sqli', { date: '2026-01-03T00:00:00Z', authorName: 'Carol' });

    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n',
    );
    fx.commit('regression: reintroduce sqli', { date: '2026-01-04T00:00:00Z', authorName: 'Dave' });

    return shaFirst;
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
