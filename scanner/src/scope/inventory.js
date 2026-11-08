// Scan inventory (PRD FR 01): one eligibility decision per candidate path,
// made BEFORE any file content is read, with a recorded reason for every skip.
//
// Git decides what Git ignores. Ignore semantics are never reimplemented here:
// `git ls-files -z` handles nested .gitignore files, negation, anchoring,
// directory patterns, escaping and unusual filenames. This module only layers
// the scanner's own policy on top, in the PRD's order:
//
//   1. root and filesystem safety (no symlinks, nothing outside the root)
//   2. explicit scanner exclusion      (excludePaths)
//   3. exact explicit inclusion        (includePaths, includeIgnoredPaths)
//   4. Git selection                   (tracked + untracked-not-ignored)
//   5. narrowly defined scanner defaults (build-output directory SEGMENTS)
//
// A tracked file stays eligible even when a later ignore pattern matches it.
// Defaults match whole path segments, never substrings: `.github/workflows/
// buck2.yml` and `tools/buck2/` are not build output.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as cp from 'node:child_process';
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';

/** Generated-output directory names, matched as exact path segments. */
export const GENERATED_DIR_SEGMENTS = Object.freeze([
  'buck-out', 'dist-newstyle', '.stack-work', '.cabal-sandbox',
]);

export const SCOPE_MODES = Object.freeze({ LOCAL: 'local', REPOSITORY: 'repository' });

function git(root, args, { env = {}, maxBuffer = 256 * 1024 * 1024 } = {}) {
  const r = cp.spawnSync('git', hardenGitArgs(args), {
    cwd: root, env: hardenGitEnv(env), maxBuffer, encoding: 'buffer',
  });
  return r.status === 0 ? r.stdout : null;
}

function nulList(buf) {
  return buf.toString('utf8').split('\0').filter(Boolean);
}

function norm(p) {
  return p.split(path.sep).join('/').replace(/^\.\//, '').replace(/\/+$/, '');
}

function segmentOf(rel, segments) {
  for (const s of rel.split('/')) if (segments.includes(s)) return s;
  return null;
}

function sha(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function digestRules(root, mode) {
  // Digest of every ignore source that can change the selection. Hashing the
  // rule files (not the selected set) lets a rule edit invalidate scope caches.
  const sources = [];
  const listed = git(root, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']);
  const files = (listed ? nulList(listed) : []).filter((f) => path.posix.basename(f) === '.gitignore').sort();
  for (const f of files) {
    try { sources.push(`${f}\0${fs.readFileSync(path.join(root, f), 'utf8')}`); } catch { /* vanished */ }
  }
  if (mode === SCOPE_MODES.LOCAL) {
    for (const f of [path.join('.git', 'info', 'exclude')]) {
      try { sources.push(`${f}\0${fs.readFileSync(path.join(root, f), 'utf8')}`); } catch { /* absent */ }
    }
    const gx = git(root, ['config', '--get', 'core.excludesFile']);
    if (gx) {
      const p = gx.toString('utf8').trim().replace(/^~(?=\/)/, process.env.HOME || '~');
      try { sources.push(`global\0${fs.readFileSync(p, 'utf8')}`); } catch { /* absent */ }
    }
  }
  return sha(sources.join('\n--\n'));
}

function isGitWorkTree(root) {
  const out = git(root, ['rev-parse', '--is-inside-work-tree']);
  return !!out && out.toString('utf8').trim() === 'true';
}

/**
 * Ask Git for the selected file set and the ignored subtrees, without reading
 * any file content and without enumerating inside an ignored directory.
 */
function gitSelection(root, mode) {
  const env = mode === SCOPE_MODES.REPOSITORY ? { GIT_CONFIG_GLOBAL: '/dev/null' } : {};
  // Repository mode: honour only .gitignore files in the tree. --exclude-standard
  // would add .git/info/exclude and the global file, which differ between
  // machines, so name the per-directory source explicitly instead.
  const ignoreArgs = mode === SCOPE_MODES.REPOSITORY ? ['--exclude-per-directory=.gitignore'] : ['--exclude-standard'];
  const cands = git(root, ['ls-files', '-z', '--cached', '--others', ...ignoreArgs], { env });
  if (!cands) return null;
  // --directory collapses an ignored directory to one entry instead of walking it.
  const ign = git(root, ['ls-files', '-z', '--others', '--ignored', '--directory', ...ignoreArgs], { env });
  const tracked = git(root, ['ls-files', '-z', '--cached'], { env });
  // Gitlinks (submodules) are index entries with mode 160000.
  const staged = git(root, ['ls-files', '-z', '--stage'], { env });
  const gitlinks = new Set((staged ? nulList(staged) : []).filter((l) => l.startsWith('160000 ')).map((l) => norm(l.slice(l.indexOf('\t') + 1))));
  return {
    gitlinks,
    candidates: nulList(cands).map(norm),
    ignored: ign ? nulList(ign).map((d) => d.replace(/^\.\//, '')) : [],
    tracked: new Set(tracked ? nulList(tracked).map(norm) : []),
  };
}

function unitKind(abs, isGitlink) {
  if (isGitlink) return 'submodule';
  try { if (fs.lstatSync(abs).isDirectory() && fs.existsSync(path.join(abs, '.git'))) return 'nested-repository'; } catch { /* gone */ }
  return null;
}

function lstatKind(abs) {
  try {
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink()) return 'symlink';
    if (st.isFile()) return 'file';
    return 'other';
  } catch { return 'missing'; }
}

function underRoot(root, abs) {
  let real;
  try { real = fs.realpathSync(abs); } catch { return false; }
  const r = fs.realpathSync(root);
  return real === r || real.startsWith(r + path.sep);
}

/**
 * Build the inventory. Never reads file contents.
 *
 * @param {string} root
 * @param {object} [o]
 * @param {boolean} [o.respectGitignore=true]
 * @param {'local'|'repository'} [o.ignoreSource='local']
 * @param {string[]} [o.includePaths]         exact paths; beat Git ignore and default build exclusions
 * @param {string[]} [o.includeIgnoredPaths]  exact ignored files, opted in explicitly
 * @param {string[]} [o.excludePaths]         path or directory prefixes; beat every inclusion
 * @param {string[]} [o.generatedSegments]
 * @returns {{included: string[], skipped: object[], overrides: object[], policy: object}}
 */
export function buildScanInventory(root, o = {}) {
  const {
    respectGitignore = true, ignoreSource = SCOPE_MODES.LOCAL,
    includePaths = [], includeIgnoredPaths = [], excludePaths = [],
    generatedSegments = GENERATED_DIR_SEGMENTS,
  } = o;
  const mode = ignoreSource === SCOPE_MODES.REPOSITORY ? SCOPE_MODES.REPOSITORY : SCOPE_MODES.LOCAL;
  const included = [];
  const skipped = [];
  const overrides = [];
  const exclude = excludePaths.map(norm);
  const include = new Set([...includePaths, ...includeIgnoredPaths].map(norm));
  const ignoredInclude = new Set(includeIgnoredPaths.map(norm));

  const sel = respectGitignore && isGitWorkTree(root) ? gitSelection(root, mode) : null;
  const policy = {
    mode: sel ? mode : 'walk',
    respectGitignore,
    trackedFileSemantics: !!sel,
    ruleDigest: sel ? digestRules(root, mode) : null,
    disclosures: sel ? [] : [
      respectGitignore
        ? 'not a Git work tree: .gitignore rules are not applied and tracked-file semantics are unavailable'
        : 'Git ignore rules disabled by explicit option',
    ],
  };

  let candidates;
  if (sel) {
    candidates = sel.candidates;
    for (const d of sel.ignored) {
      // Reported once per collapsed subtree, never enumerated.
      skipped.push({ path: d, reason: 'git-ignored', rule: d.endsWith('/') ? 'directory' : 'file' });
    }
  } else {
    candidates = walkAll(root);
  }

  const seen = new Set();
  for (const rel of candidates) {
    if (seen.has(rel)) continue;
    seen.add(rel);
    const abs = path.join(root, rel);
    const kind = lstatKind(abs);
    if (kind === 'missing') { skipped.push({ path: rel, reason: 'missing-tracked-file', coverageCondition: true }); continue; }
    if (kind === 'symlink') { skipped.push({ path: rel, reason: 'symlink' }); continue; }
    if (kind === 'other') {
      // A directory that Git lists as one entry is a submodule or a nested repository: a separate scan unit that was not scanned.
      const unit = unitKind(abs, sel && sel.gitlinks.has(rel));
      skipped.push({ path: rel, reason: unit || 'unsupported-entry', coverageCondition: true, ...(unit ? { note: 'separate repository: declare it as its own scan target to cover it' } : {}) });
      continue;
    }
    if (!underRoot(root, abs)) { skipped.push({ path: rel, reason: 'outside-root' }); continue; }
    if (exclude.some((e) => rel === e || rel.startsWith(e + '/'))) { skipped.push({ path: rel, reason: 'explicit-exclude' }); continue; }
    const seg = segmentOf(rel, generatedSegments);
    if (seg && !include.has(rel)) {
      // Tracked files do not override a generated-output default; only an exact inclusion does.
      skipped.push({ path: rel, reason: 'generated-default', segment: seg });
      continue;
    }
    if (seg && include.has(rel)) overrides.push({ path: rel, overrode: 'generated-default', segment: seg });
    included.push(rel);
  }

  // Exact inclusions of files Git ignored (or that the walk never produced).
  for (const rel of include) {
    if (seen.has(rel)) continue;
    if (exclude.some((e) => rel === e || rel.startsWith(e + '/'))) { skipped.push({ path: rel, reason: 'explicit-exclude' }); continue; }
    const abs = path.join(root, rel);
    const kind = lstatKind(abs);
    if (kind !== 'file' || !underRoot(root, abs) || rel.startsWith('../') || path.isAbsolute(rel)) {
      skipped.push({ path: rel, reason: kind === 'symlink' ? 'symlink' : 'include-rejected', coverageCondition: true });
      continue;
    }
    included.push(rel);
    overrides.push({ path: rel, overrode: ignoredInclude.has(rel) ? 'git-ignore' : 'selection', evidenceOnly: false });
  }

  included.sort();
  return { included, skipped, overrides, policy };
}

function walkAll(root) {
  const out = [];
  const stack = [''];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir ? path.join(root, dir) : root, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const rel = dir ? `${dir}/${e.name}` : e.name;
      if (e.name === '.git') continue;
      if (e.isDirectory()) stack.push(rel);
      else out.push(rel);
    }
  }
  return out;
}
