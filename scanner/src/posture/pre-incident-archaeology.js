// FR-UX-11 — Pre-incident archaeology.
//
// Given a finding or a CWE, walk the git history of the affected file to
// answer "when did this codebase first become vulnerable to this CWE?"
// Outputs a structured timeline:
//
//   {
//     finding: { stableId, file, line, vuln },
//     firstVulnerableCommit: { sha, author, ts, message } | null,
//     vulnerableForDays: 145,
//     concurrentSafeShapes: [{ sha, ts, snippet }],   // earlier commits where the same file did NOT contain the bug
//     introducingCommit: { sha, author, ts, message } | null,
//   }
//
// We invoke `git log` and `git show` via the shell. If the project is not a
// git repository (no `.git` at root), we return `{ available: false }`.
//
// This is intentionally light: we do not re-run the SAST detector on every
// historical revision. We use a simple substring-presence probe — does the
// finding's sink snippet appear in the historical version of the file?
// Sufficient for the common case and dramatically cheaper than full
// re-scanning. Customers who want forensic-grade archaeology can re-run the
// scanner against `git checkout`-ed historical revisions.

import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

function isGitRepo(root) {
  try {
    return fs.existsSync(path.join(root, '.git'));
  } catch { return false; }
}

function gitLogForFile(root, file, limit = 50) {
  try {
    const out = execSync(
      `git log --pretty=format:%H%x1f%an%x1f%aI%x1f%s --max-count=${limit} -- "${file}"`,
      { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    );
    return out.split(/\n/).filter(Boolean).map(line => {
      const [sha, author, ts, message] = line.split('\x1f');
      return { sha, author, ts, message };
    });
  } catch { return []; }
}

function gitShow(root, sha, file) {
  try {
    return execSync(`git show ${sha}:"${file}"`, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch { return null; }
}

function probeSnippet(content, snippet) {
  if (!content || !snippet) return false;
  // Strip whitespace for a coarse match — historical reformatting shouldn't
  // hide the presence of the same vulnerable expression.
  const normContent = content.replace(/\s+/g, ' ');
  const normSnippet = snippet.replace(/\s+/g, ' ').slice(0, 120);
  return normContent.includes(normSnippet);
}

export function archaeologyForFinding(finding, scanRoot) {
  const root = scanRoot || process.cwd();
  if (!isGitRepo(root)) return { available: false, reason: 'not-a-git-repo' };
  if (!finding || !finding.file) return { available: false, reason: 'no-file' };

  const snippet = finding.sink?.snippet || finding.snippet || '';
  if (!snippet) return { available: false, reason: 'no-snippet' };

  const log = gitLogForFile(root, finding.file, 50);
  if (!log.length) return { available: false, reason: 'no-history' };

  // Walk oldest-first; find the first commit where the snippet is present.
  const ordered = log.slice().reverse();
  let firstVulnerable = null;
  let lastSafe = null;
  for (const c of ordered) {
    const content = gitShow(root, c.sha, finding.file);
    if (content === null) continue;
    const present = probeSnippet(content, snippet);
    if (present && !firstVulnerable) firstVulnerable = c;
    if (!present) lastSafe = c;
  }

  // If snippet isn't present in any commit, treat as no archaeology available.
  if (!firstVulnerable) return { available: false, reason: 'snippet-never-seen' };

  // The "introducing commit" is firstVulnerable; if lastSafe is just before it,
  // we have a clean delta. Otherwise the snippet may have been introduced,
  // removed, reintroduced — present a partial answer.
  const tsFirst = Date.parse(firstVulnerable.ts);
  const tsNow = Date.now();
  const vulnerableForDays = Number.isFinite(tsFirst) ? Math.floor((tsNow - tsFirst) / 86_400_000) : null;

  return {
    available: true,
    finding: {
      stableId: finding.stableId || null,
      file: finding.file,
      line: finding.line || 0,
      vuln: finding.vuln || null,
    },
    firstVulnerableCommit: firstVulnerable,
    introducingCommit: firstVulnerable,
    lastSafeCommit: lastSafe,
    vulnerableForDays,
    historyLength: log.length,
  };
}
