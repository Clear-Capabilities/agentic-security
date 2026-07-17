import { test } from 'node:test';
import assert from 'node:assert';
import { createRequire } from 'node:module';

// The hook is a CJS file under hooks/ (root package is CJS); load it via
// require so we can unit-test the pure mapping without spawning a process.
const require = createRequire(import.meta.url);
const { ALIAS_MAP, resolveAlias, buildContext } = require('../../hooks/legacy-alias-redirect.js');

test('every removed alias maps to a dispatcher mode', () => {
  // 44 aliases were removed in v0.86.0.
  assert.equal(Object.keys(ALIAS_MAP).length, 46);
  for (const [alias, repl] of Object.entries(ALIAS_MAP)) {
    assert.match(repl, /^\/(secure|scan|triage|fix|posture|compliance|supply|setup|labs)\b/, `${alias} -> ${repl}`);
  }
});

test('resolveAlias matches a bare alias', () => {
  const r = resolveAlias('/status');
  assert.equal(r.replacement, '/posture --status');
  assert.equal(r.rest, '');
});

test('resolveAlias preserves trailing args', () => {
  const r = resolveAlias('/explain CVE-2024-1234');
  assert.equal(r.replacement, '/triage --explain');
  assert.equal(r.rest, 'CVE-2024-1234');
});

test('resolveAlias handles the plugin namespace', () => {
  const r = resolveAlias('/agentic-security:show-findings --all');
  assert.equal(r.replacement, '/triage --show');
  assert.equal(r.rest, '--all');
});

test('resolveAlias ignores live commands and non-slash prompts', () => {
  assert.equal(resolveAlias('/scan --all'), null);
  assert.equal(resolveAlias('/posture'), null);
  assert.equal(resolveAlias('just fix my bugs'), null);
  assert.equal(resolveAlias(''), null);
});

test('buildContext names both the old alias and the replacement', () => {
  const ctx = buildContext(resolveAlias('/harden'));
  assert.match(ctx, /\/harden/);
  assert.match(ctx, /\/fix --harden/);
});
