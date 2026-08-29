// Unit coverage for util/git-hardening.js's two primitives. These are
// deliberately narrow (pure functions, no subprocess) — the exploit-shaped
// coverage (does a hostile core.fsmonitor/textconv/ext-diff driver actually
// get suppressed) lives in test/posture/provenance-git-evidence.test.js and
// test/material-change.test.js, against the real call sites.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GIT_HARDENED_CONFIG_ARGS, GIT_HARDENED_ENV, hardenGitArgs, hardenGitEnv } from '../src/util/git-hardening.js';

test('hardenGitArgs: prepends the hardening -c flags, does not append them', () => {
  const out = hardenGitArgs(['show', '-s', '--format=%H', 'abc123']);
  // Must be prepended: a `-c` after the subcommand is parsed as a positional
  // argument to that subcommand, not a global option, so ordering is
  // load-bearing, not cosmetic.
  assert.deepEqual(out.slice(0, GIT_HARDENED_CONFIG_ARGS.length), GIT_HARDENED_CONFIG_ARGS);
  assert.deepEqual(out.slice(GIT_HARDENED_CONFIG_ARGS.length), ['show', '-s', '--format=%H', 'abc123']);
  // Regression pin: if a future edit switched `[...GIT_HARDENED_CONFIG_ARGS, ...args]`
  // to `[...args, ...GIT_HARDENED_CONFIG_ARGS]`, the -c flags would land AFTER
  // the subcommand and silently stop doing anything — this assertion fails
  // exactly that swap.
  assert.notDeepEqual(out.slice(-GIT_HARDENED_CONFIG_ARGS.length), GIT_HARDENED_CONFIG_ARGS);
});

test('hardenGitArgs: non-array input degrades to just the hardening flags, never throws', () => {
  assert.deepEqual(hardenGitArgs(undefined), GIT_HARDENED_CONFIG_ARGS);
  assert.deepEqual(hardenGitArgs(null), GIT_HARDENED_CONFIG_ARGS);
});

test('hardenGitArgs: an empty args array still gets the hardening flags', () => {
  assert.deepEqual(hardenGitArgs([]), GIT_HARDENED_CONFIG_ARGS);
});

test('hardenGitEnv: preserves the parent environment (PATH included) via the spread, not a stripped-down env', () => {
  const originalPath = process.env.PATH;
  assert.ok(originalPath && originalPath.length > 0, 'sanity: PATH must be set in this test process, or this test proves nothing');
  const env = hardenGitEnv();
  assert.equal(env.PATH, originalPath, 'hardenGitEnv() with no argument must inherit the parent PATH — a git subprocess with no PATH cannot even find the `git` binary via a bare command name in some call sites');
  // A representative sample of other ambient vars should also survive —
  // hardenGitEnv must not have silently become an allowlist of two keys.
  assert.equal(env.HOME, process.env.HOME);
});

test('hardenGitEnv: adds GIT_CONFIG_NOSYSTEM=1 and GIT_TERMINAL_PROMPT=0', () => {
  const env = hardenGitEnv();
  assert.equal(env.GIT_CONFIG_NOSYSTEM, '1');
  assert.equal(env.GIT_TERMINAL_PROMPT, '0');
  assert.deepEqual(GIT_HARDENED_ENV, { GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' });
});

test('hardenGitEnv: caller-supplied extra vars are merged in, and win over ambient values', () => {
  const env = hardenGitEnv({ CUSTOM_VAR: 'x', PATH: '/custom/path' });
  assert.equal(env.CUSTOM_VAR, 'x');
  assert.equal(env.PATH, '/custom/path', 'an explicit override must win over the inherited ambient value');
  // The two hardening vars are still present alongside the caller's extras.
  assert.equal(env.GIT_CONFIG_NOSYSTEM, '1');
});

test('hardenGitEnv: a caller cannot use extraEnv to unset the hardening vars (they are merged in AFTER the spread but BEFORE extraEnv... verify extraEnv wins, which is documented/expected, not accidental)', () => {
  // hardenGitEnv's own implementation merges as {...process.env, ...GIT_HARDENED_ENV, ...extraEnv}
  // — extraEnv intentionally wins over the hardening defaults (same convention
  // as hardenGitArgs letting a caller extend args), so a caller CAN override
  // GIT_TERMINAL_PROMPT if it explicitly chooses to. This test pins that this
  // is the actual, deliberate precedence order, not an accident to be
  // "fixed" later without noticing every caller relies on it.
  const env = hardenGitEnv({ GIT_TERMINAL_PROMPT: '1' });
  assert.equal(env.GIT_TERMINAL_PROMPT, '1');
});
