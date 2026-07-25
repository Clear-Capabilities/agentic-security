// Acquisition of proof-corpus targets.
//
// Clones are blobless and shallow, pinned to a full commit SHA, and live
// OUTSIDE the repository tree. Two reasons: reproducibility (a re-run months
// later produces the same numbers) and licence hygiene (we never hold a copy
// of third-party source in our own tree).

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

const _ID_RE = /^[a-z0-9][a-z0-9._-]*$/;

export function cacheRoot() {
  const override = process.env.AGENTIC_SECURITY_PROOF_CACHE;
  if (typeof override === 'string' && override.length > 0) return override;
  return path.join(os.homedir(), '.claude', 'agentic-security', 'proof-corpus-cache');
}

export function repoDir(id) {
  if (typeof id !== 'string' || !_ID_RE.test(id)) {
    throw new Error(`invalid target id: ${JSON.stringify(id)} (expected /^[a-z0-9][a-z0-9._-]*$/)`);
  }
  return path.join(cacheRoot(), id);
}

function _git(args, cwd, timeoutMs = 900_000) {
  return execFileSync('git', args, {
    cwd,
    timeout: timeoutMs,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
  }).trim();
}

export function currentCommit(dir) {
  try {
    return _git(['rev-parse', 'HEAD'], dir);
  } catch {
    return null;
  }
}

// Resolve a branch or tag name to a full SHA without cloning. Used by
// --refresh-pins so advancing a pin is a deliberate, reviewable act.
export function resolveRef(url, ref) {
  const out = _git(['ls-remote', url, ref], undefined, 120_000);
  const line = out.split('\n').find(Boolean);
  if (!line) throw new Error(`ref not found: ${ref} in ${url}`);
  return line.split(/\s+/)[0];
}

export function ensureClone(target) {
  const { id, url, commit } = target || {};
  if (!commit) {
    throw new Error(
      `target "${id}" has no pinned commit — run the runner with --refresh-pins to resolve it`,
    );
  }
  const dir = repoDir(id);

  if (currentCommit(dir) === commit) return { dir, cached: true };

  fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(path.join(dir, '.git'))) {
    _git(['init', '-q'], dir);
  }
  // Idempotent remote setup: set-url succeeds whether or not origin exists.
  try { _git(['remote', 'add', 'origin', url], dir); }
  catch { _git(['remote', 'set-url', 'origin', url], dir); }

  // Blobless partial clone: full history metadata is skipped and file contents
  // are fetched on demand, which is what keeps ten large repos tractable.
  _git(['fetch', '--depth', '1', '--filter=blob:none', 'origin', commit], dir);
  _git(['checkout', '-q', '--detach', 'FETCH_HEAD'], dir);

  return { dir, cached: false };
}
