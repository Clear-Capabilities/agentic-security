// R15 (PRD §5) — git-history secret sweep.
//
// A secret removed from HEAD but present in any past commit is still
// recoverable from `.git` and must be rotated — the most dangerous secret case,
// and one a working-tree-only scan misses entirely. This sweeps recent history
// (bounded), feeding the ADDED lines of each commit through the same credential
// detector the file scan uses.
//
// The detector is INJECTED (detectFn) rather than imported, so this module has
// no dependency back into engine.js (avoids a circular import) and the parsing
// stays pure + unit-testable. Live-credential validation (is the key active?)
// needs network and is deferred — see the rollup.

import { execFileSync } from 'node:child_process';

// Pull the post-image (added) lines out of a unified diff: lines starting with
// a single '+' (not the '+++' file header). Returns reconstructed text.
export function extractAddedLines(diffText) {
  const out = [];
  for (const line of String(diffText || '').split('\n')) {
    if (line.startsWith('+') && !line.startsWith('+++')) out.push(line.slice(1));
  }
  return out.join('\n');
}

// Pure: run the injected credential detector over a commit's added lines.
// detectFn has the scanCredentials(fp, raw) shape and returns Finding[].
export function scanHistoryDiff(diffText, commit, detectFn) {
  if (typeof detectFn !== 'function') return [];
  const added = extractAddedLines(diffText);
  if (!added.trim()) return [];
  let findings = [];
  try { findings = detectFn(`git-history@${commit}`, added) || []; } catch { return []; }
  return findings.map((f) => ({
    ...f,
    id: `secret-history:${commit}:${f.id || f.vuln || 'secret'}`,
    file: `git-history@${commit}`,
    line: 0,
    commit,
    _historical: true,
    vuln: `${f.vuln || 'Hardcoded Secret'} (in git history)`,
    description: `${f.description || 'A credential was committed.'} Found in commit ${commit}; even if removed from HEAD it remains recoverable from git and must be rotated.`,
    remediation: 'Rotate the credential now, then purge it from history (git filter-repo / BFG) and move it to a secrets manager. Removing it from HEAD alone is insufficient.',
  }));
}

/**
 * Sweep up to `maxCommits` of recent history for secrets. Best-effort: returns
 * [] when `scanRoot` is not a git repo or git is unavailable. Dedups a secret
 * that recurs across commits to its earliest sighting.
 */
export function sweepGitHistory(scanRoot, detectFn, { maxCommits = 50, timeoutMs = 20000 } = {}) {
  if (!scanRoot || typeof detectFn !== 'function') return [];
  let out;
  try {
    out = execFileSync('git', ['-C', scanRoot, 'log', '-p', '-n', String(maxCommits), '--no-color', '--no-merges', '--no-textconv'],
      { encoding: 'utf8', maxBuffer: 96 * 1024 * 1024, timeout: timeoutMs, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch { return []; }
  const parts = out.split(/^commit ([0-9a-f]{7,40})/m); // [pre, sha, body, sha, body, ...]
  const findings = [];
  const seen = new Set();
  for (let i = 1; i < parts.length; i += 2) {
    const sha = (parts[i] || '').slice(0, 12);
    for (const f of scanHistoryDiff(parts[i + 1] || '', sha, detectFn)) {
      const key = `${f.vuln}:${(f.snippet || f.match || '').slice(0, 40)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
    }
  }
  return findings;
}
