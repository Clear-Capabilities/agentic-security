export const id = 1444;
export const ids = [1444];
export const modules = {

/***/ 1444:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   sweepGitHistory: () => (/* binding */ sweepGitHistory)
/* harmony export */ });
/* unused harmony exports extractAddedLines, scanHistoryDiff */
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(1421);
/* harmony import */ var _util_git_hardening_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(8844);
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




// Pull the post-image (added) lines out of a unified diff: lines starting with
// a single '+' (not the '+++' file header). Returns reconstructed text.
function extractAddedLines(diffText) {
  const out = [];
  for (const line of String(diffText || '').split('\n')) {
    if (line.startsWith('+') && !line.startsWith('+++')) out.push(line.slice(1));
  }
  return out.join('\n');
}

// Pure: run the injected credential detector over a commit's added lines.
// detectFn has the scanCredentials(fp, raw) shape and returns Finding[].
function scanHistoryDiff(diffText, commit, detectFn) {
  if (typeof detectFn !== 'function') return [];
  const added = extractAddedLines(diffText);
  if (!added.trim()) return [];
  let findings = [];
  try { findings = detectFn(`git-history@${commit}`, added) || []; } catch { return []; }
  return findings.map((f) => {
    const remediation = 'Rotate the credential now, then purge it from history (git filter-repo / BFG) and move it to a secrets manager. Removing it from HEAD alone is insufficient.';
    return {
      ...f,
      id: `secret-history:${commit}:${f.id || f.vuln || 'secret'}`,
      file: `git-history@${commit}`,
      line: 0,
      commit,
      _historical: true,
      vuln: `${f.vuln || 'Hardcoded Secret'} (in git history)`,
      description: `${f.description || 'A credential was committed.'} Found in commit ${commit}; even if removed from HEAD it remains recoverable from git and must be rotated.`,
      remediation,
      // report/index.js's _remediationOf checks `.fix` before `.remediation`
      // — the underlying detector already set `.fix` to a generic "remove
      // the line" string, which would otherwise silently shadow this
      // history-specific instruction ("removing it from HEAD alone is
      // insufficient") in every report format.
      fix: remediation,
    };
  });
}

/**
 * Sweep up to `maxCommits` of recent history for secrets. Best-effort: returns
 * [] when `scanRoot` is not a git repo or git is unavailable. Dedups a secret
 * that recurs across commits to its earliest sighting.
 */
function sweepGitHistory(scanRoot, detectFn, { maxCommits = 50, timeoutMs = 20000 } = {}) {
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
    out = (0,node_child_process__WEBPACK_IMPORTED_MODULE_0__.execFileSync)('git', (0,_util_git_hardening_js__WEBPACK_IMPORTED_MODULE_1__/* .hardenGitArgs */ .Ax)(['-C', scanRoot, 'log', '-p', '-n', String(maxCommits), '--no-color', '--no-merges', '--no-textconv']),
      { encoding: 'utf8', maxBuffer: 96 * 1024 * 1024, timeout: timeoutMs, stdio: ['ignore', 'pipe', 'ignore'], env: (0,_util_git_hardening_js__WEBPACK_IMPORTED_MODULE_1__/* .hardenGitEnv */ .Si)() });
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


/***/ })

};
