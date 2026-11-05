// Adverse history (GA-05, 0.195.27): a lockfile change moves a TRANSITIVE dependency into the vulnerable range.
//
// `direct-sca-version-bump.mjs` covers a declared dependency in `package.json`. Here `package.json` never changes: it
// declares `express`, and `package-lock.json` resolves `express`'s own dependency `qs`. The commit that re-pins the
// nested `qs` from its fixed version back to the vulnerable one is the origin (`transitive-sca.js`, method
// `dependency-graph-diff`), and the evidence node carries the dependency chain `express -> qs` re-derived from the
// lockfile at that commit, not copied from the current tree.
function lockfile(nested) {
  const packages = { '': { name: 'root', version: '1.0.0', dependencies: { express: '^4.0.0' } } };
  for (const [p, version] of Object.entries(nested)) packages[`node_modules/${p}`] = { version };
  return JSON.stringify({ name: 'root', lockfileVersion: 3, packages }, null, 2);
}

export const manifest = {
  id: 'transitive-lockfile-bump',
  scenario: 'Transitive SCA: lockfile re-pins a nested dependency into the vulnerable range',
  description: 'package.json is unchanged; package-lock.json moves a transitive dependency to a vulnerable version.',
  kind: 'sca',
  expect: 'commit',
  build(fx) {
    fx.writeFile('package.json', JSON.stringify({ name: 'root', version: '1.0.0', private: true, dependencies: { express: '^4.0.0' } }));
    fx.writeFile('package-lock.json', lockfile({ express: '4.19.0', 'express/node_modules/qs': '6.5.4' }));
    fx.commit('safe: nested qs at its fixed version', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('package-lock.json', lockfile({ express: '4.19.0', 'express/node_modules/qs': '6.5.3' }));
    const sha = fx.commit('re-pin nested qs to the vulnerable version', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    return { commit: sha };
  },
  verify(fp) {
    const node = (fp.evidenceAttribution || [])[0];
    const chain = node && node.depChain;
    return Array.isArray(chain) && chain.join('>') === 'express>qs' ? null : `evidence depChain is ${JSON.stringify(chain)}, expected express>qs`;
  },
  sca: {
    ecosystem: 'npm', name: 'qs', version: '6.5.3',
    id: 'FIXTURE-PROVENANCE-ACCURACY-TRANSITIVE-0001',
    description: 'Fixture advisory for the transitive-lockfile-bump corpus entry.',
    fixedVersions: ['6.5.4'], severity: 'high',
  },
  finding: { name: 'qs', isDirect: false },
};
