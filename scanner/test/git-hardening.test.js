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

// ── Source-grep guard: the per-invocation flags must stay applied ───────────
//
// The `-c` config flags and the env vars are structurally enforced (every
// call site routes through hardenGitArgs/hardenGitEnv, which cannot be
// partially applied). The PER-SUBCOMMAND flags are not: `--no-ext-diff` and
// `--no-textconv` have to be written into each individual argv, and nothing
// stopped a new call site from omitting one.
//
// That is not hypothetical. It is exactly what happened: the first hardening
// pass added `--no-textconv` to git-evidence.js's content-rendering calls and
// left `material-change.js`'s `git diff` without `--no-ext-diff`, which kept
// a live RCE open (`git diff` honours an external diff driver even with
// --no-textconv set) through a review that otherwise passed. A second review
// caught it by hand. This guard is that reviewer, automated — so the next
// `git diff` call site cannot reopen the same hole silently.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

function* walkJs(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { yield* walkJs(p); continue; }
    if (e.isFile() && p.endsWith('.js')) yield p;
  }
}

// Matches an argv array literal whose FIRST element is the given git
// subcommand — e.g. `['diff', '--unified=0', ...]`. Comments are stripped
// first: a commented-out example must not read as a real call site (this
// codebase has been bitten by comment-blind guards three times; see
// test/no-stray-state.test.js and tree-integrity.test.js for the precedent).
function argvLiteralsFor(src, subcommand) {
  const stripped = src
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    // Block comments are stripped ONLY when `/*` opens a line (after optional
    // indentation). A bare /\/\*[\s\S]*?\*\//g eats real code here: glob
    // literals like '**/*.js' contain `/*`, and runScan.js has one BEFORE its
    // `git diff` call site — that greedy form silently swallowed the call
    // site and made this guard report a false pass. Caught by the sanity
    // test below, which is exactly why it exists.
    .replace(/^[ \t]*\/\*[\s\S]*?\*\//gm, '');
  const re = new RegExp(`\\[\\s*['"\`]${subcommand}['"\`][\\s\\S]{0,400}?\\]`, 'g');
  return stripped.match(re) || [];
}

test('every `git diff` argv in src/ carries --no-ext-diff (the flag whose absence kept a live RCE open)', () => {
  const offenders = [];
  for (const file of walkJs(SRC_DIR)) {
    const src = fs.readFileSync(file, 'utf8');
    for (const argv of argvLiteralsFor(src, 'diff')) {
      if (!argv.includes('--no-ext-diff')) {
        offenders.push(`${path.relative(SRC_DIR, file)}: ${argv.replace(/\s+/g, ' ').slice(0, 120)}`);
      }
    }
  }
  assert.deepEqual(offenders, [],
    'These `git diff` call sites omit --no-ext-diff, so a hostile repo\'s\n' +
    '.gitattributes `diff=<name>` + `[diff "<name>"] command=<script>` (or a\n' +
    'global diff.external) executes that script during the scan. --no-textconv\n' +
    'does NOT cover this: `git diff` honours external drivers by default.\n' +
    'Add --no-ext-diff to each argv listed above.');
});

test('every content-rendering git argv in src/ carries --no-textconv', () => {
  // Scoped to argvs that actually RENDER content. `diff --name-only` emits
  // only paths and was empirically confirmed not to invoke a textconv driver,
  // so requiring the flag there would be cargo cult; `blame` and a `diff`
  // that emits hunks both do render content and both fire textconv without it.
  const offenders = [];
  for (const file of walkJs(SRC_DIR)) {
    const src = fs.readFileSync(file, 'utf8');
    for (const argv of argvLiteralsFor(src, 'blame')) {
      if (!argv.includes('--no-textconv')) {
        offenders.push(`${path.relative(SRC_DIR, file)} [blame]: ${argv.replace(/\s+/g, ' ').slice(0, 120)}`);
      }
    }
    for (const argv of argvLiteralsFor(src, 'diff')) {
      if (argv.includes('--name-only') || argv.includes('--name-status')) continue; // renders no content
      if (!argv.includes('--no-textconv')) {
        offenders.push(`${path.relative(SRC_DIR, file)} [diff]: ${argv.replace(/\s+/g, ' ').slice(0, 120)}`);
      }
    }
  }
  assert.deepEqual(offenders, [],
    'These git argvs render file content without --no-textconv, so a hostile\n' +
    '.gitattributes textconv driver runs during the scan. Add --no-textconv.');
});

test('the source-grep guards actually match something (sanity — a guard that finds no call sites proves nothing)', () => {
  let diffArgvs = 0, blameArgvs = 0;
  for (const file of walkJs(SRC_DIR)) {
    const src = fs.readFileSync(file, 'utf8');
    diffArgvs += argvLiteralsFor(src, 'diff').length;
    blameArgvs += argvLiteralsFor(src, 'blame').length;
  }
  assert.ok(diffArgvs >= 3,
    `expected the guard to find the known git-diff call sites (material-change, runScan, pr-delta), found ${diffArgvs}`);
  assert.ok(blameArgvs >= 2,
    `expected the guard to find the known git-blame call sites (git-history, provenance/git-evidence), found ${blameArgvs}`);
});
