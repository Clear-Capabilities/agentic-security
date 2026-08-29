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

// Second independent Finding Provenance PRD audit (Task 7, item 1): the
// audit's own earlier finding was "a secret finding gets role sink" — the
// generic fallback role is misleading for a hardcoded-credential finding,
// whose evidence node names where the SECRET sits, not a taint sink.
// coordinator.js passes `{ secret: true }` for any finding routed with
// `findingType: 'secret'`; this pins the resulting role at the
// attributeEvidence level, independent of the coordinator wiring.
test('opts.secret routes the fallback node to role "secret" instead of the generic "sink"', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('.env', 'API_KEY=sk_live_abc123\n');
    const sha = fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    const nodes = attributeEvidence(fx.root, { file: '.env', line: 1 }, { secret: true });
    assert.equal(nodes.length, 1);
    assert.equal(nodes[0].role, 'secret');
    assert.equal(nodes[0].commit, sha);
  } finally {
    fx.cleanup();
  }
});

// Same mechanism, the other wired role: coordinator.js passes
// `{ removedGuard: true }` once resolveMissingControl has confirmed a real
// present->absent transition (see provenance-missing-control-wiring.test.js
// for the full end-to-end scenario through a real scan). Pinned here at the
// attributeEvidence level in isolation.
test('opts.removedGuard routes the fallback node to role "removed_guard" instead of the generic "sink"', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('routes/auth.js', "router.post('/login', h);\n");
    const sha = fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    const nodes = attributeEvidence(fx.root, { file: 'routes/auth.js', line: 1 }, { removedGuard: true });
    assert.equal(nodes.length, 1);
    assert.equal(nodes[0].role, 'removed_guard');
    assert.equal(nodes[0].commit, sha);
  } finally {
    fx.cleanup();
  }
});

// The taint-flow shape (source/sink present) must NOT be affected by either
// hint — `opts` only governs the no-source/no-sink fallback branch. A
// hypothetical caller passing `{secret:true}` alongside a real source/sink
// finding must still get `source`/`sink`, not have them silently reclassified.
test('opts hints do not affect the source/sink branch when both are present', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    const finding = {
      file: 'server.js', line: 2,
      source: { file: 'server.js', line: 1 },
      sink: { file: 'server.js', line: 2 },
    };
    const nodes = attributeEvidence(fx.root, finding, { secret: true, removedGuard: true });
    assert.ok(nodes.find((n) => n.role === 'source'));
    assert.ok(nodes.find((n) => n.role === 'sink'));
    assert.ok(!nodes.some((n) => n.role === 'secret' || n.role === 'removed_guard'));
  } finally {
    fx.cleanup();
  }
});
