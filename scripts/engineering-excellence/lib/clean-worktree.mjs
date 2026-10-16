// A throwaway, detached checkout of one commit for taking a measurement.
//
// A measurement must be taken on a clean tree at a named commit, but a developer's working tree is rarely clean while work goes on. Rather
// than stash, reset or "clean" anything in it, the measurement runs in a separate worktree created from the commit, so the working tree is
// never touched and the measured tree is clean by construction. The generated, gitignored pieces an `npm install` would create
// (node_modules and the vendored Java parser) are linked from the source checkout, and listed in the result so the measurement says so.
import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, readlinkSync, symlinkSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000 }).trim();

export const LINKED_PATHS = Object.freeze(['scanner/node_modules', 'scanner/vendor']);

/**
 * Run `fn({ dir, commit, linked })` inside a detached worktree of `ref`. The worktree is removed afterwards unless `keep`.
 * `parent` is where the worktree is created (default: next to the source checkout).
 */
export async function withCleanWorktree(root, fn, { ref = 'HEAD', keep = false, parent = null, link = LINKED_PATHS } = {}) {
  const commit = git(root, ['rev-parse', ref]);
  const dir = join(parent || dirname(root), `${basename(root)}-measure-${commit.slice(0, 10)}-${process.pid}`);
  git(root, ['worktree', 'add', '--detach', '--quiet', dir, commit]);
  const linked = [];
  try {
    for (const rel of link) {
      const from = join(root, rel); const to = join(dir, rel);
      if (!existsSync(from)) continue;
      mkdirSync(dirname(to), { recursive: true });
      if (!existsSync(to)) { symlinkSync(from, to); linked.push(rel); }
    }
    return await fn({ dir, commit, linked });
  } finally {
    if (!keep) { try { git(root, ['worktree', 'remove', '--force', dir]); } catch { /* the registration is pruned by `git worktree prune` */ } }
  }
}

/** True when `dir` is a symlink pointing at `target` (used by tests). */
export function isLinkTo(dir, target) {
  try { return lstatSync(dir).isSymbolicLink() && readlinkSync(dir) === target; } catch { return false; }
}
