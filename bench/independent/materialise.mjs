#!/usr/bin/env node
// Materialise pre/post trees with CONTEXT, not just the changed files.
// PRD Revision 2 / N1.
//
// THE PROBLEM THIS FIXES
// ----------------------
// The first version fetched only the files a fix commit touched. That made the
// published recall figure a lower bound with a known cause: an interprocedural
// taint engine needs the caller, the route registration and the sanitiser, and
// none of them are in the diff. We were grading an interprocedural engine on
// isolated fragments.
//
// The evidence was in the per-CWE breakdown. On the changed-files-only
// population, CWE-22 (path traversal) scored 0/3 and CWE-918 (SSRF) 0/3 —
// families this engine explicitly targets and routinely finds. Both need a
// request source that lives outside the changed file. That is a measurement
// artefact, not a detection failure.
//
// WHY A SUBTREE AND NOT THE WHOLE REPOSITORY
// ------------------------------------------
// Whole-repo is the ideal and is not free: downloading is cheap (measured: 68 KB
// for a small library, 23 MB for a large monorepo, seconds each) but SCANNING is
// not — a monorepo is thousands of files, times two commits, times every entry.
// At population sizes that make the statistics meaningful that is hours per run,
// which turns the measurement into something nobody runs.
//
// So: the largest ANCESTOR DIRECTORY of the changed files whose source-file
// count still fits a cap. In practice that resolves to the package or module
// containing the fix, which is where intra-package callers live. It is a
// deliberate, stated compromise — strictly better than the diff alone, strictly
// weaker than the whole repository — and the scope actually used is recorded per
// entry so a reader can see it rather than infer it.
//
// A finding whose source is in a DIFFERENT package is still unreachable here.
// The recall figure therefore remains a lower bound; it is simply a much less
// pessimistic one, and the residual gap is now named.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const CACHE_DIR = path.join(HERE, 'cache');

/** Source files worth scanning. Mirrors the miner's extension list. */
const SOURCE_EXT = /\.(?:js|jsx|mjs|cjs|ts|tsx|py|java|cs|kt|go|php|rb)$/i;
/** Never materialise these, whatever the scope resolves to. */
const SKIP = /(^|\/)(node_modules|\.git|dist|build|coverage|vendor)\//i;

/** Source files per side. Above this, walk one level back up the tree. */
export const DEFAULT_FILE_CAP = 400;

/**
 * Choose the widest ancestor directory that still fits the cap.
 *
 * `paths` is every source path in the tarball (repo-relative). Starting at the
 * deepest common directory of the changed files, walk UP while the file count
 * fits, and stop at the last directory that did.
 */
export function chooseScope(paths, changedFiles, cap = DEFAULT_FILE_CAP) {
  const source = paths.filter(p => SOURCE_EXT.test(p) && !SKIP.test(p));
  const countUnder = (dir) => source.filter(p => dir === '' || p.startsWith(dir + '/')).length;

  // Deepest directory containing every changed file.
  const parts = changedFiles.map(f => f.split('/').slice(0, -1));
  let common = parts[0] || [];
  for (const p of parts.slice(1)) {
    let i = 0;
    while (i < common.length && i < p.length && common[i] === p[i]) i++;
    common = common.slice(0, i);
  }

  let best = common.join('/');
  let bestCount = countUnder(best);
  // Walk up while it still fits — a wider scope means more callers in view.
  for (let up = common.slice(0, -1); ; up = up.slice(0, -1)) {
    const dir = up.join('/');
    const n = countUnder(dir);
    if (n > cap) break;
    best = dir; bestCount = n;
    if (up.length === 0) break;
  }
  // The cap can be UNENFORCEABLE: when the changed file sits at the repository
  // root there is no narrower directory to fall back to, so the scope is the
  // whole repository however large. Report that rather than pretending the cap
  // held — a silently-exceeded limit is how a benchmark run quietly becomes an
  // hour longer than anyone budgeted for.
  return {
    dir: best,
    files: bestCount,
    cappedAt: cap,
    wholeRepo: best === '',
    exceededCap: bestCount > cap,
  };
}

function tarballTo(repo, sha, dest) {
  const r = spawnSync('gh', ['api', `repos/${repo}/tarball/${sha}`], {
    encoding: 'buffer', maxBuffer: 512 * 1024 * 1024, shell: false,
  });
  if (r.status !== 0 || !r.stdout?.length) return false;
  fs.writeFileSync(dest, r.stdout);
  return true;
}

function listTar(tgz) {
  const r = spawnSync('tar', ['-tzf', tgz], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  if (r.status !== 0) return null;
  // The archive root is a generated `owner-repo-sha/` prefix; strip it.
  return String(r.stdout).split('\n').filter(Boolean)
    .map(p => p.split('/').slice(1).join('/')).filter(Boolean);
}

function extractScope(tgz, scopeDir, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const args = ['-xzf', tgz, '-C', outDir, '--strip-components=1'];
  if (scopeDir) args.push(`*/${scopeDir}/*`);
  const r = spawnSync('tar', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return r.status === 0;
}

/**
 * Materialise one entry. Returns the scope used, or null if it could not be
 * built — a partial tree is never left behind, because scanning half a package
 * would report a coverage failure as a detection failure.
 */
export function materialiseEntry(entry, { cap = DEFAULT_FILE_CAP } = {}) {
  const dir = path.join(CACHE_DIR, entry.id);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'indep-'));
  try {
    const scopes = {};
    for (const [side, sha] of [['pre', entry.parentCommit], ['post', entry.fixCommit]]) {
      const tgz = path.join(tmp, `${side}.tar.gz`);
      if (!tarballTo(entry.repo, sha, tgz)) return null;
      const listing = listTar(tgz);
      if (!listing) return null;
      const scope = chooseScope(listing, entry.files, cap);
      const out = path.join(dir, side);
      fs.rmSync(out, { recursive: true, force: true });
      if (!extractScope(tgz, scope.dir, out)) return null;
      scopes[side] = scope;
    }
    return scopes;
  } catch {
    fs.rmSync(dir, { recursive: true, force: true });
    return null;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}
