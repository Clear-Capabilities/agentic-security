// Direct SCA: a commit changes the declared dependency version from a safe
// value into an advisory's vulnerable range. This is the SCA half of PRD
// Scenario A's "direct introduction" idea, exercising `sca-origin.js`'s
// `resolveDirectSCAOrigin` (method `dependency-graph-diff`) rather than
// `origin-resolver.js`'s SAST predicate replay — a materially different code
// path, worth its own fixture per the task brief.
//
// NO package-lock.json. `resolveDirectSCAOrigin`/`extractDeclaredVersion`
// only reads `package.json` (and `requirements.txt`) — verified directly: a
// sibling lockfile present makes the engine attribute the supplyChain entry's
// `filePath` to the LOCKFILE instead (since that's what pins the resolved
// version), and `extractDeclaredVersion` has no lockfile-parsing branch, so
// origin resolution degrades to `status:'partial'` even though the true
// origin is genuinely resolvable from `package.json` alone. Keeping this
// fixture lockfile-free (a legitimate, common real-world shape — plenty of
// small projects pin an exact version in `package.json` with no committed
// lockfile) is what exercises the resolver's actual working path rather than
// this separate, already-known lockfile-attribution gap.
export const manifest = {
  id: 'direct-sca-version-bump',
  scenario: 'Direct SCA — dependency version bump into a vulnerable range',
  description: 'package.json is edited to change a direct dependency\'s pinned version from safe to vulnerable.',
  kind: 'sca',
  expect: 'commit',
  build(fx) {
    fx.writeFile(
      'package.json',
      JSON.stringify({ name: 't', version: '1.0.0', private: true, dependencies: { 'example-lib': '1.3.0' } }),
    );
    fx.commit('safe: dependency pinned at the fixed version', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile(
      'package.json',
      JSON.stringify({ name: 't', version: '1.0.0', private: true, dependencies: { 'example-lib': '1.2.0' } }),
    );
    return fx.commit('downgrade dependency into the vulnerable range', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
  },
  sca: {
    ecosystem: 'npm', name: 'example-lib', version: '1.2.0',
    id: 'FIXTURE-PROVENANCE-ACCURACY-DIRECT-0001',
    description: 'Fixture advisory for the direct-sca-version-bump corpus entry.',
    fixedVersions: ['1.3.0'], severity: 'high',
  },
  finding: { name: 'example-lib', isDirect: true },
};
