// Project-root resolver for .agentic-security/ state.
//
// BUG HISTORY: Previously, state-writing code used the pattern
//   `path.join(scanRoot || process.cwd(), '.agentic-security', ...)`
// When `scanRoot` was null/undefined and the scanner was invoked from
// a subdirectory (e.g., migrations/, config/), this created
// `.agentic-security/` folders inside those subdirectories — breaking
// the user's build (one report: DB migration system saw the folder as
// a migration file). One user uninstalled the plugin entirely.
//
// FIX: All state writes go through this module. process.cwd() is NEVER
// trusted directly. We walk upward from cwd looking for project markers
// (.git, package.json, etc.) and write state there. A safety check
// refuses to write if no marker is found.

import * as fs from 'node:fs';
import * as path from 'node:path';

const STATE_DIR_NAME = '.agentic-security';

const PROJECT_MARKERS = [
  '.git',
  'package.json',
  'pyproject.toml',
  'go.mod',
  'Cargo.toml',
  'pom.xml',
  'build.gradle',
  'composer.json',
  'Gemfile',
  '.agentic-security',
];

function _findProjectRoot(startDir) {
  let dir = path.resolve(startDir);
  const visited = new Set();
  while (dir && !visited.has(dir)) {
    visited.add(dir);
    for (const m of PROJECT_MARKERS) {
      try {
        if (fs.existsSync(path.join(dir, m))) return dir;
      } catch { /* ignore */ }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

export function resolveProjectRoot(scanRoot) {
  // Prefer caller-provided scanRoot when it points to an existing directory
  if (scanRoot && typeof scanRoot === 'string') {
    try {
      const resolved = path.resolve(scanRoot);
      if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
        return resolved;
      }
    } catch { /* fall through */ }
  }
  // Walk upward from cwd looking for project markers
  const fromCwd = _findProjectRoot(process.cwd());
  if (fromCwd) return fromCwd;
  // No project markers found — return cwd but caller should check via isSafeStateDir
  return process.cwd();
}

export function stateDir(scanRoot) {
  return path.join(resolveProjectRoot(scanRoot), '.agentic-security');
}

export function statePath(scanRoot, ...parts) {
  return path.join(stateDir(scanRoot), ...parts);
}

// Safety check: refuse to create .agentic-security/ unless the parent
// directory has at least one project marker. Prevents littering when
// resolution falls through to a non-project directory.
export function isSafeStateDir(dir) {
  if (!dir) return false;
  const parent = path.dirname(dir);
  for (const m of PROJECT_MARKERS) {
    if (m === '.agentic-security') continue; // would be circular
    try {
      if (fs.existsSync(path.join(parent, m))) return true;
    } catch { /* ignore */ }
  }
  // A directory NESTED inside an already-valid state root is safe too.
  //
  // Without this the check only ever accepted `<project>/.agentic-security`
  // itself, because it looks for a project marker in the immediate parent and
  // `.agentic-security` deliberately does not count as one. Every nested state
  // directory — `llm-cache/`, `fix-history/`, `sbom-history/` — therefore
  // failed, and `safeWriteState` silently refused to write there.
  //
  // The consequence was not theoretical: `llm-validator`'s `writeCache` goes
  // through `safeWriteState`, so the validator cache never persisted a single
  // entry. Every scan re-queried the model for every finding, while a
  // `validator-cache stats|gc` subcommand existed to manage a cache that was
  // always empty. Found by a positive-control test asserting that a
  // legitimately written entry round-trips.
  //
  // This does not weaken the guard. Its purpose is to stop `.agentic-security/`
  // being created in unrelated directories; a subdirectory of a state root that
  // has already been validated is exactly the case it was never meant to catch.
  const segments = path.resolve(dir).split(path.sep);
  const idx = segments.lastIndexOf(STATE_DIR_NAME);
  if (idx > 0 && idx < segments.length - 1) {
    return isSafeStateDir(segments.slice(0, idx + 1).join(path.sep));
  }
  return false;
}

// Safe mkdir: only creates .agentic-security/ if the parent has a project marker.
// Returns the dir on success, null if refused. Logs a warning when refused.
export function ensureStateDir(scanRoot) {
  const dir = stateDir(scanRoot);
  if (!isSafeStateDir(dir)) {
    if (process.env.AGENTIC_SECURITY_DEBUG === '1') {
      process.stderr.write(`[agentic-security] refusing to create state dir at ${dir} — no project marker in parent\n`);
    }
    return null;
  }
  try {
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  } catch {
    return null;
  }
}

// Safe write: only writes if isSafeStateDir(parent) returns true.
// Returns true on success, false if refused or errored.
export function safeWriteState(filePath, content) {
  const dir = path.dirname(filePath);
  if (!isSafeStateDir(dir)) {
    if (process.env.AGENTIC_SECURITY_DEBUG === '1') {
      process.stderr.write(`[agentic-security] refusing to write state file at ${filePath} — no project marker in parent of ${dir}\n`);
    }
    return false;
  }
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, content);
    return true;
  } catch {
    return false;
  }
}
