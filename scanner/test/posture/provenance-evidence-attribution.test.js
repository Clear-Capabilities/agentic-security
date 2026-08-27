import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { attributeEvidence } from '../../src/posture/provenance/evidence-attribution.js';

test('FR-PROV-005: multi-line finding exposes per-node attribution, not one collapsed author', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    const sha1 = fx.commit('source line', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input); // sink\n');
    const sha2 = fx.commit('sink line touched', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const finding = {
      file: 'server.js', line: 2,
      source: { file: 'server.js', line: 1 },
      sink: { file: 'server.js', line: 2 },
    };
    const nodes = attributeEvidence(fx.root, finding);
    const source = nodes.find((n) => n.role === 'source');
    const sink = nodes.find((n) => n.role === 'sink');
    assert.ok(source);
    assert.ok(sink);
    assert.equal(source.commit, sha1);
    assert.equal(sink.commit, sha2);
    assert.notEqual(source.commit, sink.commit);
  } finally {
    fx.cleanup();
  }
});

test('single-node finding with no source/sink falls back to a sink node at file:line', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'eval(x);\n');
    const sha = fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    const nodes = attributeEvidence(fx.root, { file: 'a.js', line: 1 });
    assert.equal(nodes.length, 1);
    assert.equal(nodes[0].role, 'sink');
    assert.equal(nodes[0].commit, sha);
  } finally {
    fx.cleanup();
  }
});
