// Task 6: ai-authorship.js — verifier registry hook (Finding Provenance PRD,
// M4 §4.3). No concrete external signed-commit-metadata standard exists yet,
// so this is an extensible registry defaulting to `unknown` with nothing
// registered, and wired into origin-resolver.js's `originFrom` so every SAST
// findingOrigin carries `aiAuthorship`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  registerAIAuthorshipVerifier,
  resolveAIAuthorship,
  _clearAIAuthorshipVerifiers,
} from '../../src/posture/provenance/ai-authorship.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

test('resolveAIAuthorship: with nothing registered, always unknown', () => {
  _clearAIAuthorshipVerifiers();
  const r = resolveAIAuthorship({ commit: 'abc', authorName: 'Alice', summary: 'x' });
  assert.deepEqual(r, { status: 'unknown', verifier: null });
});

test('resolveAIAuthorship: null commitMeta never throws, resolves unknown', () => {
  _clearAIAuthorshipVerifiers();
  assert.deepEqual(resolveAIAuthorship(null), { status: 'unknown', verifier: null });
});

test('registerAIAuthorshipVerifier: a registered verifier that answers is consulted', () => {
  _clearAIAuthorshipVerifiers();
  registerAIAuthorshipVerifier('claude-co-author-trailer', (meta) =>
    /Co-Authored-By: Claude/.test(meta.summary || '') ? { status: 'ai-assisted', verifier: 'claude-co-author-trailer' } : null);
  const r = resolveAIAuthorship({ commit: 'abc', summary: 'fix: thing\n\nCo-Authored-By: Claude <noreply@anthropic.com>' });
  assert.equal(r.status, 'ai-assisted');
  assert.equal(r.verifier, 'claude-co-author-trailer');
});

test('registerAIAuthorshipVerifier: a verifier that declines (returns null) falls through to unknown', () => {
  _clearAIAuthorshipVerifiers();
  registerAIAuthorshipVerifier('always-declines', () => null);
  const r = resolveAIAuthorship({ commit: 'abc', summary: 'x' });
  assert.deepEqual(r, { status: 'unknown', verifier: null });
});

test('registerAIAuthorshipVerifier: a THROWING verifier is treated as no-opinion, never crashes the resolver', () => {
  _clearAIAuthorshipVerifiers();
  registerAIAuthorshipVerifier('broken', () => { throw new Error('boom'); });
  registerAIAuthorshipVerifier('fallback', () => ({ status: 'human', verifier: 'fallback' }));
  const r = resolveAIAuthorship({ commit: 'abc', summary: 'x' });
  assert.equal(r.status, 'human');
});

test('re-registering the same name replaces, does not stack', () => {
  _clearAIAuthorshipVerifiers();
  registerAIAuthorshipVerifier('v', () => ({ status: 'first', verifier: 'v' }));
  registerAIAuthorshipVerifier('v', () => ({ status: 'second', verifier: 'v' }));
  const r = resolveAIAuthorship({ commit: 'abc', summary: 'x' });
  assert.equal(r.status, 'second');
});

test('two verifiers registered: first-registered-first-consulted, not last-wins', () => {
  _clearAIAuthorshipVerifiers();
  registerAIAuthorshipVerifier('first', () => ({ status: 'from-first', verifier: 'first' }));
  registerAIAuthorshipVerifier('second', () => ({ status: 'from-second', verifier: 'second' }));
  const r = resolveAIAuthorship({ commit: 'abc', summary: 'x' });
  assert.equal(r.status, 'from-first');
  assert.equal(r.verifier, 'first');
});

// origin-resolver.js: every SAST findingOrigin carries aiAuthorship.
//
// `computeStableId`'s real export lives at `src/posture/stable-id.js`, not
// `provenance/schema.js` (the brief's own sketch flagged this as an unverified
// guess) — confirmed by grepping how the OTHER tests in this same file
// (`provenance-origin-resolver.test.js`) import it: `await import
// ('../../src/posture/stable-id.js')`, called as `computeStableId(finding)`.
//
// That same file's own header additionally documents a SECOND thing this
// test must match, not just the import path: `computeStableId` derives its
// hash from `ruleId`/normalized sink signature/path shape, and a HAND-BUILT
// finding object's stableId will almost certainly not match what
// `predicate-replay.js`'s real detector suite reproduces when it re-scans the
// historical blob (`replayAt` -> `runFullScan` -> its own `computeStableId`
// call on the finding IT detects). Confirmed empirically here too: a
// hand-built stableId made `resolveOrigin` report `partial` /
// `predicate-never-confirmed-in-candidates` (replayAt never saw "present"),
// not `complete`. So — same as `realEvalFinding` elsewhere in this file —
// the finding and its stableId are derived from a REAL scan of the fixture's
// own content, not hand-built.
async function realEvalFinding(content, filePath, scanRoot) {
  const { runFullScan } = await import('../../src/engine.js');
  const scan = await runFullScan({ fileContents: { [filePath]: content }, scanRoot }, () => {});
  const finding = (scan.findings || []).find((f) => f.file === filePath && f.family === 'code-injection');
  assert.ok(finding, `expected the code-injection detector to fire on ${filePath}, got: ${JSON.stringify((scan.findings || []).map((f) => ({ file: f.file, family: f.family, parser: f.parser })))}`);
  assert.ok(finding.stableId, 'real finding must carry a stableId from the annotation pipeline');
  return finding;
}

test('origin-resolver.js: every SAST findingOrigin carries aiAuthorship, defaulting to unknown with nothing registered', async () => {
  _clearAIAuthorshipVerifiers();
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'eval(x);\n');
    fx.commit('introduce');
    const finding = await realEvalFinding('eval(x);\n', 'a.js', fx.root);
    const { resolveOrigin } = await import('../../src/posture/provenance/origin-resolver.js');
    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: false } });
    assert.equal(result.status, 'complete');
    assert.deepEqual(result.findingOrigin.aiAuthorship, { status: 'unknown', verifier: null });
  } finally { fx.cleanup(); }
});

test('origin-resolver.js: a registered verifier is reachable end-to-end through resolveOrigin', async () => {
  _clearAIAuthorshipVerifiers();
  registerAIAuthorshipVerifier('claude-co-author-trailer', (meta) =>
    /Co-Authored-By: Claude/.test(meta.summary || '') ? { status: 'ai-assisted', verifier: 'claude-co-author-trailer' } : null);
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'eval(x);\n');
    // `commitMeta`'s `summary` is `%s` (the SUBJECT line only, not the full
    // `%B` body) — see the known-limitation note in ai-authorship.js's
    // header. A real "Co-Authored-By" trailer normally lives in the body,
    // separated from the subject by a blank line, and would NOT be visible
    // through `summary`; this fixture puts the marker directly in the
    // one-line subject so the verifier has something real to match against
    // without overstating what `commitMeta` actually exposes today.
    fx.commit('introduce eval Co-Authored-By: Claude <noreply@anthropic.com>');
    const finding = await realEvalFinding('eval(x);\n', 'a.js', fx.root);
    const { resolveOrigin } = await import('../../src/posture/provenance/origin-resolver.js');
    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: false } });
    assert.equal(result.status, 'complete');
    assert.deepEqual(result.findingOrigin.aiAuthorship, { status: 'ai-assisted', verifier: 'claude-co-author-trailer' });
  } finally {
    fx.cleanup();
    _clearAIAuthorshipVerifiers();
  }
});
