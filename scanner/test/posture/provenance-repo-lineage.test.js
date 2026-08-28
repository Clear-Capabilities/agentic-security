import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { loadRepoLineage } from '../../src/posture/provenance/repo-lineage.js';

test('loadRepoLineage: no config file returns null', () => {
  const fx = createGitFixture();
  try { assert.equal(loadRepoLineage(fx.root), null); } finally { fx.cleanup(); }
});

test('loadRepoLineage: malformed JSON degrades to null, never throws', () => {
  const fx = createGitFixture();
  try {
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'repo-lineage.json'), '{not json');
    assert.equal(loadRepoLineage(fx.root), null);
  } finally { fx.cleanup(); }
});

test('loadRepoLineage: a path that is not a real git repo returns null', () => {
  const fx = createGitFixture();
  try {
    const notARepo = fs.mkdtempSync(path.join(os.tmpdir(), 'as-not-a-repo-'));
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'repo-lineage.json'),
      JSON.stringify({ linkedFrom: { path: notARepo, atCommit: '0'.repeat(40) } }));
    assert.equal(loadRepoLineage(fx.root), null);
    fs.rmSync(notARepo, { recursive: true, force: true });
  } finally { fx.cleanup(); }
});

test('loadRepoLineage: a commit that does not exist in the linked repo returns null', () => {
  const fx = createGitFixture();
  const linked = createGitFixture();
  try {
    linked.writeFile('x.js', '1');
    linked.commit('c1');
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'repo-lineage.json'),
      JSON.stringify({ linkedFrom: { path: linked.root, atCommit: 'f'.repeat(40) } }));
    assert.equal(loadRepoLineage(fx.root), null);
  } finally { fx.cleanup(); linked.cleanup(); }
});

test('loadRepoLineage: a valid, verified link resolves correctly', () => {
  const fx = createGitFixture();
  const linked = createGitFixture();
  try {
    linked.writeFile('x.js', '1');
    const sha = linked.commit('c1');
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'repo-lineage.json'),
      JSON.stringify({ linkedFrom: { path: linked.root, atCommit: sha } }));
    const result = loadRepoLineage(fx.root);
    assert.ok(result);
    assert.equal(result.path, linked.root);
    assert.equal(result.atCommit, sha);
  } finally { fx.cleanup(); linked.cleanup(); }
});

test('loadRepoLineage: an unsafe-looking atCommit (not a real SHA) is rejected before reaching git', () => {
  const fx = createGitFixture();
  try {
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'repo-lineage.json'),
      JSON.stringify({ linkedFrom: { path: fx.root, atCommit: '--upload-pack=evil' } }));
    assert.equal(loadRepoLineage(fx.root), null);
  } finally { fx.cleanup(); }
});
