#!/usr/bin/env node
// Pre-commit preparation: do, at commit time, the generation steps whose omission otherwise fails the pre-push gate twenty minutes later.
//
//   node scripts/pre-commit-prepare.mjs            run from the committed pre-commit hook
//   node scripts/pre-commit-prepare.mjs --plan     print what it would do for the staged files, change nothing
//
// Two steps, each only when the staged files make it necessary:
//   1. BUNDLE. When a build input is staged (scanner/src, scanner/bin, scanner/vendor, scanner/package.json, frontend/), rebuild
//      scanner/dist and stage it. The bundle embeds package.json and the source, so a commit that changes either without rebuilding
//      fails "committed bundle equals a fresh build" at push time.
//   2. GENERATED DOCS. When a docs page or the capability registry is staged, regenerate the generated tables
//      (`check-positioning-docs.mjs --write`) and re-stage the staged files it changed.
//
// SAFETY. It only ever stages files the commit already concerns. If a build input has UNSTAGED changes (a partial commit), a build would
// capture content that is not in the commit, so it refuses and says how to proceed rather than guessing. A missing dependency install
// is a warning, not a block: the pre-push gate still checks the bundle. `git commit --no-verify` skips it, and so does
// AGENTIC_SECURITY_NO_PRECOMMIT=1. It does not run in CI.
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { cleanEnv, skipReason } from './gate-warm.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_DEFAULT = path.resolve(HERE, '..');

const BUILD_INPUT = [/^scanner\/(src|bin|vendor)\//, /^scanner\/package\.json$/, /^frontend\//];
const DOCS_INPUT = [/^README\.md$/, /^docs\/.*\.md$/, /^docs\/capabilities\.yaml$/];
const matches = (list, f) => list.some((re) => re.test(f));

/**
 * What to do for a commit. Pure: `staged` and `unstaged` are repo-relative paths.
 * @returns {{build: boolean, docs: boolean, blockers: string[]}}
 */
export function plan({ staged, unstaged }) {
  const build = staged.some((f) => matches(BUILD_INPUT, f));
  const docs = staged.some((f) => matches(DOCS_INPUT, f));
  const blockers = [];
  if (build) {
    const partial = unstaged.filter((f) => matches(BUILD_INPUT, f));
    if (partial.length) blockers.push(`build inputs have unstaged changes (${partial.slice(0, 3).join(', ')}${partial.length > 3 ? ', ...' : ''}): a rebuilt bundle would contain content this commit does not. Stage them, or stash them, then commit again.`);
  }
  return { build, docs, blockers };
}

function run(repo, cmd, args, opts = {}) {
  return spawnSync(cmd, args, { cwd: repo, encoding: 'utf8', shell: false, env: cleanEnv(), ...opts });
}
const lines = (r) => (r.status === 0 ? r.stdout.split('\n').map((l) => l.trim()).filter(Boolean) : []);

export function main(argv, { repo = REPO_DEFAULT, env = process.env, out = process.stderr } = {}) {
  if (env.AGENTIC_SECURITY_NO_PRECOMMIT === '1') return 0;
  if (env.CI === 'true' || env.GITHUB_ACTIONS === 'true') return 0;
  if (skipReason({ env: { ...env, AGENTIC_SECURITY_NO_GATE_WARM: '' }, repo })) return 0; // a rebase or merge in progress: leave it alone
  const staged = lines(run(repo, 'git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR']));
  const unstaged = lines(run(repo, 'git', ['diff', '--name-only']));
  const p = plan({ staged, unstaged });
  if (argv.includes('--plan')) { out.write(`${JSON.stringify(p)}\n`); return 0; }
  if (p.blockers.length) { for (const b of p.blockers) out.write(`pre-commit: ${b}\n`); return 1; }

  if (p.build) {
    const scanner = path.join(repo, 'scanner');
    if (!fs.statSync(path.join(scanner, 'node_modules'), { throwIfNoEntry: false })) {
      out.write('pre-commit: scanner/node_modules is missing, so the bundle was not rebuilt. Run `npm install` in scanner/ (the pre-push gate will refuse a stale bundle).\n');
    } else {
      out.write('pre-commit: a build input is staged, rebuilding scanner/dist ...\n');
      const b = run(repo, 'npm', ['run', 'build'], { cwd: scanner, stdio: ['ignore', 'ignore', 'inherit'], encoding: undefined });
      if (b.status !== 0) { out.write('pre-commit: the build failed; fix it before committing (--no-verify to skip, then the push gate will refuse).\n'); return 1; }
      run(repo, 'git', ['add', '--', 'scanner/dist']);
    }
  }

  if (p.docs) {
    const dirtyDocs = unstaged.filter((f) => matches(DOCS_INPUT, f));
    const before = lines(run(repo, 'git', ['diff', '--name-only']));
    const w = run(repo, process.execPath, [path.join(repo, 'scripts', 'check-positioning-docs.mjs'), '--write'], { stdio: ['ignore', 'ignore', 'inherit'], encoding: undefined });
    const after = lines(run(repo, 'git', ['diff', '--name-only']));
    const changed = after.filter((f) => !before.includes(f) && staged.includes(f));
    if (dirtyDocs.length && changed.length) out.write(`pre-commit: generated tables changed in files with unstaged edits (${changed.join(', ')}); review with git diff before committing.\n`);
    else if (changed.length) { run(repo, 'git', ['add', '--', ...changed]); out.write(`pre-commit: regenerated and staged the generated tables in ${changed.join(', ')}\n`); }
    if (w.status !== 0) out.write('pre-commit: the positioning docs check reports findings (see above); the release gate will fail on them.\n');
  }
  return 0;
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) process.exit(main(process.argv.slice(2)));
