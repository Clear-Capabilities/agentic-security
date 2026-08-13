export const id = 838;
export const ids = [838];
export const modules = {

/***/ 7838:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   runProjectLinter: () => (/* binding */ runProjectLinter),
/* harmony export */   verifyFix: () => (/* binding */ verifyFix),
/* harmony export */   verifyPatch: () => (/* binding */ verifyPatch)
/* harmony export */ });
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(1421);
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(6760);
/* harmony import */ var _engine_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(3793);
// Closed-loop /fix verification (Sentinel-parity FR-L4-4, FR-L4-5).
//
// Given a candidate patch (the new file content + the finding stableId being
// fixed), verify it:
//
//   1. The original finding's stableId no longer fires on the patched file.
//   2. No new findings at severity ≥ medium were introduced by the patch.
//   3. The project's existing linter (when present) passes on the patched file.
//
// If any of those fail, the caller is expected to NOT apply the patch and
// instead surface a "fix plan" — a numbered list of steps the engineer can
// follow — rather than dump a broken patch on the user.






const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Run a focused re-scan over just the patched file(s) using the in-memory
// engine. No filesystem write needed — we hand the new content in via the
// fileContents map.
async function verifyPatch({
  scanRoot,
  originalFindingStableId,
  files,   // { [relPath]: newContent }
  depFileContents = {},
} = {}) {
  if (!files || typeof files !== 'object') return { ok: false, reason: 'no-files-provided' };
  const fileContents = { ...files };
  let scan;
  try {
    scan = await (0,_engine_js__WEBPACK_IMPORTED_MODULE_3__/* .runFullScan */ .wW)({ fileContents, depFileContents, scanRoot }, () => {});
  } catch (e) {
    return { ok: false, reason: 'rescan-failed', error: e.message };
  }
  const findings = (scan && scan.findings) || [];
  const stillHasOriginal = !!originalFindingStableId &&
    findings.some(f => f.stableId === originalFindingStableId);
  if (stillHasOriginal) {
    return { ok: false, reason: 'original-finding-still-present', stableId: originalFindingStableId };
  }
  const introducedHighOrAbove = findings.filter(f =>
    (SEVERITY_RANK[f.severity] ?? 9) <= SEVERITY_RANK.medium);
  // Don't count findings on lines outside the patched files — but our
  // fileContents map IS the patched files, so every finding is in-scope.
  return {
    ok: introducedHighOrAbove.length === 0,
    reason: introducedHighOrAbove.length === 0 ? 'verified' : 'introduced-new-findings',
    introduced: introducedHighOrAbove.map(f => ({
      vuln: f.vuln, file: f.file, line: f.line, severity: f.severity,
      stableId: f.stableId,
    })),
  };
}

// Detect which linter the project uses and run it on the patched files.
// Returns { ok, runner, output } or { ok: true, runner: 'none' } when no
// linter is configured (silent pass).
function runProjectLinter(scanRoot, filePaths) {
  if (!scanRoot || !Array.isArray(filePaths) || filePaths.length === 0) {
    return { ok: true, runner: 'none' };
  }
  const has = (p) => { try { return node_fs__WEBPACK_IMPORTED_MODULE_1__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(scanRoot, p)); } catch { return false; } };
  // Pick the linter by config file present in the repo root.
  const jsFiles = filePaths.filter(f => /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(f));
  const pyFiles = filePaths.filter(f => /\.py$/i.test(f));
  const goFiles = filePaths.filter(f => /\.go$/i.test(f));
  const javaFiles = filePaths.filter(f => /\.java$/i.test(f));

  if (jsFiles.length && (has('.eslintrc') || has('.eslintrc.json') || has('.eslintrc.js') || has('eslint.config.js') || has('eslint.config.mjs'))) {
    return runLinter(scanRoot, 'eslint', ['--no-error-on-unmatched-pattern', ...jsFiles]);
  }
  if (pyFiles.length && (has('pyproject.toml') || has('ruff.toml') || has('.ruff.toml'))) {
    return runLinter(scanRoot, 'ruff', ['check', ...pyFiles]);
  }
  if (pyFiles.length && has('.flake8')) {
    return runLinter(scanRoot, 'flake8', pyFiles);
  }
  if (goFiles.length && (has('.golangci.yml') || has('.golangci.yaml'))) {
    return runLinter(scanRoot, 'golangci-lint', ['run', ...goFiles]);
  }
  if (javaFiles.length && has('checkstyle.xml')) {
    return runLinter(scanRoot, 'checkstyle', ['-c', 'checkstyle.xml', ...javaFiles]);
  }
  return { ok: true, runner: 'none' };
}

function runLinter(cwd, cmd, args) {
  let r;
  try {
    r = (0,node_child_process__WEBPACK_IMPORTED_MODULE_0__.spawnSync)(cmd, args, { cwd, encoding: 'utf8', timeout: 60_000 });
  } catch (e) {
    return { ok: true, runner: cmd, skipped: true, reason: 'binary-missing', error: e.message };
  }
  if (r.error && r.error.code === 'ENOENT') {
    return { ok: true, runner: cmd, skipped: true, reason: 'binary-missing' };
  }
  if (r.status === null) {
    return { ok: false, runner: cmd, reason: 'timed-out', output: (r.stderr || r.stdout || '').slice(-2000) };
  }
  return {
    ok: r.status === 0,
    runner: cmd,
    exitCode: r.status,
    output: ((r.stderr || '') + (r.stdout || '')).slice(-2000),
  };
}

// Top-level verify: re-scan + lint. Returns the combined verdict + a
// human-readable summary string suitable for surfacing to the user.
async function verifyFix({
  scanRoot,
  originalFindingStableId,
  files,
  depFileContents,
} = {}) {
  const rescan = await verifyPatch({ scanRoot, originalFindingStableId, files, depFileContents });
  const lint = runProjectLinter(scanRoot, Object.keys(files || {}));
  const ok = rescan.ok && (lint.ok || lint.skipped);
  const summary = [
    `re-scan: ${rescan.ok ? 'PASS' : 'FAIL — ' + rescan.reason}`,
    `linter:  ${lint.runner === 'none' ? 'skipped (no linter config)'
              : lint.skipped ? `${lint.runner} not installed`
              : lint.ok ? `${lint.runner} PASS`
              : `${lint.runner} FAIL (exit ${lint.exitCode})`}`,
  ].join('\n');
  return { ok, rescan, lint, summary };
}


/***/ })

};
