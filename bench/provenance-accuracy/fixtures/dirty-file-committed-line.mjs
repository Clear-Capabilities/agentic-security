// Adverse history (GA-05, 0.195.27): a dirty file whose vulnerable line is committed.
//
// `uncommitted-change.mjs` covers a flaw that exists only in the working tree. This is the neighbouring case that a
// coarse "dirty file means uncommitted" rule gets wrong: the flaw was committed in A, and the file has since been
// edited elsewhere without a commit (a trailing comment). The vulnerable line itself is unchanged, so blame attributes
// it to A and the origin is A with a complete, verified parent boundary; only `analysisBasis.dirty` records that the
// tree was not clean.
const SAFE = 'function h(req) {\n  return 1;\n}\n';
const VULN = 'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n';

export const manifest = {
  id: 'dirty-file-committed-line',
  scenario: 'Adverse history: dirty file, committed vulnerable line',
  description: 'The file has an uncommitted edit on another line; the committed vulnerable line still resolves to its commit.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('server.js', SAFE);
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('server.js', VULN);
    const shaA = fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    fx.writeFile('server.js', `${VULN}// uncommitted trailing note\n`);
    return { commit: shaA };
  },
  verify(fp) {
    if (!fp.analysisBasis || fp.analysisBasis.dirty !== true) return 'analysisBasis.dirty should record the uncommitted edit';
    return null;
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
