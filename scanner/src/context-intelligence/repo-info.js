//
// Best-effort git identity of the checkout. Absent git is not an error: the fields are null and the snapshot hash
// (content-based) still identifies the analysed bytes exactly.
import { execFileSync } from 'node:child_process';

function git(root, args) {
  try {
    return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 1024 * 1024 }).trim();
  } catch { return null; }
}

export function repositoryInfo(root, snapshotHash) {
  const commit = git(root, ['rev-parse', 'HEAD']);
  const status = commit ? git(root, ['status', '--porcelain']) : null;
  return { commit: commit || null, dirty: status === null ? null : status.length > 0, snapshotHash };
}
