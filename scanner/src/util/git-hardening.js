// Hardening for every `git` subprocess call this scanner makes against a
// SCANNED repository it does not control — i.e. any git invocation whose
// `cwd` (or `-C <dir>`) is a project the scanner was asked to scan, as
// opposed to this project's own trusted checkout.
//
// Verified RCE (second independent Finding Provenance PRD audit,
// FR-PROV-024 / PRD Section 8 "never run repository hooks or untrusted
// build scripts"): git-evidence.js's `_run` invoked `git` with no config
// hardening at all. A hostile repo's `.git/config` can set `core.fsmonitor`
// to point at an attacker script; git executes it on an ordinary READ-ONLY
// command like `git status --porcelain` — no clone, no checkout, no
// deliberate command needed, just `getRepoState()` reading repo state.
// Reproduced against this exact repro shape before this module existed:
// `getRepoState()` alone wrote a marker file outside the repo.
//
// Four independent hostile-config surfaces, each closed by a different
// flag/env var (do not assume one covers another — a same-class RCE
// survived the first round of this hardening precisely because
// `--no-textconv` was assumed to cover `git diff` the same way it covers
// `git show`/`git log -p`/`git blame`, and it does not):
//   - `core.fsmonitor`   -> fires on `git status` (and other porcelain
//                           commands that consult the index). Closed by
//                           `-c core.fsmonitor=` (empty value disables it).
//   - `core.hooksPath`   -> redirects git's hook lookup to an
//                           attacker-controlled directory (pre-commit,
//                           post-checkout, ...). None of THIS module's
//                           read-only operations should fire a hook, but a
//                           caller elsewhere in the tree that does invoke a
//                           hook-shaped command (checkout, commit) inherits
//                           the same exposure — hardened uniformly rather
//                           than relying on each call site to reason about
//                           whether its own command can trigger a hook.
//                           Closed by `-c core.hooksPath=/dev/null`
//                           (verified: git tries to stat
//                           `/dev/null/<hookname>`, which is not a
//                           directory, so hook lookup fails closed — this
//                           is NOT relying on /dev/null being an empty
//                           *file*, it works because it isn't a directory).
//   - `.gitattributes`   -> a `diff=<name>` attribute + a matching
//     textconv driver     `diff.<name>.textconv` config key points a text
//                           filter at an attacker script; fires on any
//                           command that renders blob/diff CONTENT (`git
//                           show`/`git diff`/`git log -p`/`git log -L`/
//                           `git blame`) unless `--no-textconv` is passed.
//                           Verified per-subcommand: `git show -s` (no
//                           content shown) and `git show <sha>:<path>`
//                           (blob cat, not a diff) were NOT exploitable in
//                           this git version, but `git show -U0`, `git log
//                           -L`, and `git blame` all were.
//   - `.git/config` /       an EXTERNAL diff driver — `.gitattributes`
//     `.gitattributes`      `diff=<name>` + `.git/config [diff "<name>"]
//     external diff driver  command=<script>`, or the repo-local/global
//                           `diff.external` config key — is a DIFFERENT
//                           mechanism from the textconv driver above and is
//                           NOT closed by `--no-textconv`. VERIFIED: `git
//                           -c core.fsmonitor= -c core.hooksPath=/dev/null
//                           diff --unified=0 --no-textconv <ref>...HEAD`
//                           still runs the attacker's `diff.evil.command`
//                           script — `--no-textconv` only suppresses the
//                           TEXTCONV driver, and `git diff` (unlike `git
//                           show`/`git log -p`/`git blame`, which were all
//                           verified safe with just `--no-textconv`) honours
//                           an external diff driver by default regardless.
//                           Closed by `--no-ext-diff`, which must be passed
//                           explicitly on every `git diff` invocation (same
//                           reason `--no-textconv` isn't a `-c` flag: it's a
//                           diff-machinery option, not repo config). This
//                           was the live RCE a second review found after the
//                           first round of this hardening shipped —
//                           material-change.js's `classifyGitDiff` (the real
//                           entry point for `/scan --diff`) had
//                           `--no-textconv` but not `--no-ext-diff` and was
//                           still exploitable end-to-end.
//
// A FIFTH surface is known but not exploitable through any call site in this
// codebase today, so it is documented rather than closed: a `clean` smudge
// filter (`.gitattributes` `filter=<name>` + `filter.<name>.clean`) fires on
// a WORKTREE diff (e.g. `git diff --name-only HEAD` with no `<ref>` on the
// other side) and has no git flag to disable it at all (unlike textconv/
// ext-diff). Every `git diff` call site in this codebase diffs two refs
// (`<ref>...HEAD`), never the worktree against HEAD, so nothing here hits
// it — but a future worktree-diff call site would silently reintroduce this
// exact vulnerability class and must not assume `hardenGitArgs` covers it.
//
// `GIT_CONFIG_NOSYSTEM=1` additionally blocks a SYSTEM-level git config
// (outside any repository, e.g. /etc/gitconfig) from re-introducing a
// hostile setting the `-c` flags above didn't anticipate; `GIT_TERMINAL_PROMPT=0`
// stops a git invocation from ever blocking on an interactive credential
// prompt (a hostile repo pointing `origin`/a submodule at a URL that
// prompts). Both are environment variables, not `-c` flags — git does not
// expose either as repo-local config.
//
// Every `git` subprocess call this scanner makes against a scan target's
// repository MUST route its args through `hardenGitArgs` and its env
// through `hardenGitEnv`. A `git show`/`git diff`/`git log -p`/`git log -L`/
// `git blame` invocation must ALSO pass `--no-textconv` explicitly (it is
// not a `-c` config value, so it isn't folded into `GIT_HARDENED_CONFIG_ARGS`
// — it must appear in the invocation's own args, after the config args), and
// a `git diff` invocation must ADDITIONALLY pass `--no-ext-diff` (a
// different flag for a different surface — see above; `--no-textconv` does
// not imply it).

export const GIT_HARDENED_CONFIG_ARGS = Object.freeze([
  '-c', 'core.fsmonitor=',
  '-c', 'core.hooksPath=/dev/null',
]);

export const GIT_HARDENED_ENV = Object.freeze({
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_TERMINAL_PROMPT: '0',
});

// Prepend the hardening `-c` flags to a git argv. These are GLOBAL options
// and must appear before the subcommand, which is why this always prepends
// rather than appending — a `-c` after the subcommand name is parsed as a
// positional argument to that subcommand, not a global option.
export function hardenGitArgs(args) {
  return [...GIT_HARDENED_CONFIG_ARGS, ...(Array.isArray(args) ? args : [])];
}

// Build the `env` option for execFileSync/spawnSync. Node's `env` option
// REPLACES the child's environment rather than merging with it, so this
// always spreads `process.env` first — passing `hardenGitEnv()` with no
// argument must be behaviourally identical to inheriting the parent
// environment plus the two hardening vars, never a stripped-down one.
export function hardenGitEnv(extraEnv) {
  return { ...process.env, ...GIT_HARDENED_ENV, ...(extraEnv || {}) };
}
