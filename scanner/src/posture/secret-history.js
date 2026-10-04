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
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';
import { providerInfo, scanLanguageSecretConcat, scanDependencyUrlCredentials } from '../language/secrets.js';

// Pull the post-image (added) lines out of a unified diff: lines starting with
// a single '+' (not the '+++' file header). Returns reconstructed text.
export function extractAddedLines(diffText) {
  const out = [];
  for (const line of String(diffText || '').split('\n')) {
    if (line.startsWith('+') && !line.startsWith('+++')) out.push(line.slice(1));
  }
  return out.join('\n');
}

// Split a unified diff into per-file sections with the POST-IMAGE line number of every added line, so a
// finding can name the file and line it was committed at (the combined text alone loses both).
export function splitDiffByFile(diffText) {
  const files = [];
  let cur = null; let next = 0;
  for (const line of String(diffText || '').split('\n')) {
    const h = /^diff --git a\/(.+?) b\/(.+)$/.exec(line);
    if (h) { cur = { path: h[2], added: [] }; files.push(cur); next = 0; continue; }
    if (!cur) continue;
    const hh = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hh) { next = parseInt(hh[1], 10); continue; }
    if (line.startsWith('+++') || line.startsWith('---')) continue;
    if (line.startsWith('+')) { cur.added.push({ text: line.slice(1), line: next }); next++; }
    else if (!line.startsWith('-') && !line.startsWith('\\')) next++;
  }
  return files;
}

// Pure: run the injected credential detector over a commit's added lines.
// detectFn has the scanCredentials(fp, raw) shape and returns Finding[]. `extra` are additional detectors
// ((path, text) => Finding[]) run against each file's added lines WITH the real path, so extension-gated
// detectors (Haskell/Nix split-secret) apply to history too.
export function scanHistoryDiff(diffText, commit, detectFn, extra = []) {
  if (typeof detectFn !== 'function') return [];
  const sections = splitDiffByFile(diffText);
  const remediation = 'Rotate the credential now, then purge it from history (git filter-repo / BFG) and move it to a secrets manager. Removing it from HEAD alone is insufficient.';
  const wrap = (f, sec, addedLines) => {
    const hit = Number.isInteger(f.line) && f.line >= 1 ? addedLines[f.line - 1] : null;
    const prov = f.rotation ? {} : providerInfo(f._rawProviderValue || '');
    const out = {
      ...f, ...prov,
      id: `secret-history:${commit}:${f.id || f.vuln || 'secret'}`,
      file: `git-history@${commit}`, line: 0, commit, _historical: true,
      ...(sec ? { sourceFile: sec.path, sourceLine: hit ? hit.line : null } : {}),
      vuln: `${f.vuln || 'Hardcoded Secret'} (in git history)`,
      description: `${f.description || 'A credential was committed.'} Found in commit ${commit}${sec ? ` (${sec.path}${hit ? `:${hit.line}` : ''})` : ''}; even if removed from HEAD it remains recoverable from git and must be rotated.`,
      remediation,
      // report/index.js's _remediationOf checks `.fix` before `.remediation`
      // — the underlying detector already set `.fix` to a generic "remove
      // the line" string, which would otherwise silently shadow this
      // history-specific instruction ("removing it from HEAD alone is
      // insufficient") in every report format.
      fix: remediation,
    };
    delete out._rawProviderValue;
    return out;
  };
  const results = [];
  if (!sections.length) {
    const added = extractAddedLines(diffText);
    if (!added.trim()) return [];
    let findings = [];
    try { findings = detectFn(`git-history@${commit}`, added) || []; } catch { return []; }
    return findings.map((f) => wrap(f, null, []));
  }
  for (const sec of sections) {
    if (!sec.added.length) continue;
    const text = sec.added.map((a) => a.text).join('\n');
    if (!text.trim()) continue;
    let findings = [];
    try { findings = detectFn(`git-history@${commit}`, text) || []; } catch { findings = []; }
    for (const f of findings) results.push(wrap(f, sec, sec.added));
    for (const ex of extra || []) {
      let more = [];
      try { more = ex(sec.path, text) || []; } catch { more = []; }
      for (const f of more) results.push(wrap(f, sec, sec.added));
    }
  }
  return results;
}

const defaultExtra = [scanLanguageSecretConcat, scanDependencyUrlCredentials];

/**
 * Sweep up to `maxCommits` of recent history for secrets. Best-effort: returns
 * [] when `scanRoot` is not a git repo or git is unavailable. Dedups a secret
 * that recurs across commits to its earliest sighting.
 */
export function sweepGitHistory(scanRoot, detectFn, { maxCommits = 50, timeoutMs = 20000, extraDetectors = null } = {}) {
  if (!scanRoot || typeof detectFn !== 'function') return [];
  let out;
  try {
    // Second independent Finding Provenance PRD audit (FR-PROV-024): this
    // scanRoot is a scanned repository, not this project's own trusted
    // checkout. `--no-textconv` alone (the pre-existing hardening here) closes
    // the .gitattributes textconv surface but NOT `core.fsmonitor` /
    // `core.hooksPath` — this `log -p` call renders every historical commit's
    // diff content, the same shape verified exploitable in
    // provenance/git-evidence.js, so it gets the full hardening too.
    out = execFileSync('git', hardenGitArgs(['-C', scanRoot, 'log', '-p', '-n', String(maxCommits), '--no-color', '--no-merges', '--no-textconv']),
      { encoding: 'utf8', maxBuffer: 96 * 1024 * 1024, timeout: timeoutMs, stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv() });
  } catch { return []; }
  const parts = out.split(/^commit ([0-9a-f]{7,40})/m); // [pre, sha, body, sha, body, ...]
  const findings = [];
  const seen = new Set();
  for (let i = 1; i < parts.length; i += 2) {
    const sha = (parts[i] || '').slice(0, 12);
    for (const f of scanHistoryDiff(parts[i + 1] || '', sha, detectFn, extraDetectors || defaultExtra)) {
      const key = `${f.vuln}:${(f.snippet || f.match || '').slice(0, 40)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
    }
  }
  return findings;
}
