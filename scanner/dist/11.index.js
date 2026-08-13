export const id = 11;
export const ids = [11];
export const modules = {

/***/ 11:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  runProjectLinter: () => (/* binding */ runProjectLinter),
  verifyFix: () => (/* binding */ verifyFix),
  verifyPatch: () => (/* binding */ verifyPatch)
});

// EXTERNAL MODULE: external "node:child_process"
var external_node_child_process_ = __webpack_require__(1421);
// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(3024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(6760);
// EXTERNAL MODULE: ./src/engine.js + 592 modules
var engine = __webpack_require__(9408);
;// CONCATENATED MODULE: ./src/posture/fix-honesty-gate.js
// Deterministic honesty gates on fix / finding output (#7).
//
// The project's verification discipline (scanner/CLAUDE.md) exists because
// several releases shipped broken or false because work was reported as done
// without confirming the artifact changed. Two of those failure modes are
// *textual* — they live in the prose an agent emits alongside a fix — and can
// be caught deterministically, with no LLM and no network:
//
//   1. Hand-wave residual-risk prose. "The input is adequately handled",
//      "future work", "tbd", "later" — vague assurances that claim safety
//      without naming a concrete remaining vector. A residual you can't name
//      is a residual you're guessing about; reject the guess.
//
//   2. An unbacked "this is a false positive / provably safe" verdict. Marking
//      a finding safe is a coverage *reduction* — it must cite a `file:line`
//      that shows why, exactly like the rules-override gate refuses to silently
//      shrink coverage.
//
// Plus a conservative fix-tier classifier so a partial remediation can never be
// labelled FULL: any workaround-only signal (rate-limit, docs, log-without-
// reject) is WORKAROUND; anything short of (sink signature changed + all callers
// routed + a discriminating test) is at most MITIGATION; only the full set with
// no partial-sanitization caveat earns FULL.
//
// Pure functions, no side effects, no throwing — safe to call from a command,
// a hook, or the MCP verify_fix path.

// Vague-assurance phrases that a real residual must never hide behind. Matched
// case-insensitively with word boundaries so "later" doesn't trip on
// "collateral" and "tbd" doesn't trip on a longer token.
const BANNED_RESIDUAL_PHRASES = Object.freeze([
  'adequately handled',
  'adequately handles',
  'properly validated',
  'properly handled',
  'handled properly',
  'handled safely',
  'future work',
  'more work needed',
  'to be done',
  'tbd',
  'later',
]);

// A citation shaped like `file:line` — one or more non-space, non-colon chars,
// a colon, then digits. Unanchored: it need only appear somewhere in the item.
const CITATION_RE = /[^\s:]+:\d+/;

// Verdicts that assert the finding is not real and therefore demand a citation.
// Compared after normalizing separators (`_`/space → `-`) and lowercasing, so
// FALSE_POSITIVE, false-positive, and "provably safe" all land here.
const FP_VERDICTS = Object.freeze(new Set(['false-positive', 'provably-safe', 'safe']));

function _escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Reject vague-assurance / hand-wave residual-risk prose.
 *
 * An empty or whitespace-only residual is ok — there is no residual to lie
 * about. A non-empty residual is rejected when it contains any banned phrase;
 * each match yields one violation naming the offending phrase.
 *
 * @param {string} residualText
 * @returns {{ ok: boolean, violations: string[] }}
 */
function checkResidualHonesty(residualText) {
  const text = typeof residualText === 'string' ? residualText : '';
  if (text.trim() === '') return { ok: true, violations: [] };

  const violations = [];
  for (const phrase of BANNED_RESIDUAL_PHRASES) {
    const re = new RegExp(`\\b${_escapeRe(phrase)}\\b`, 'i');
    if (re.test(text)) {
      violations.push(`vague-assurance phrase: "${phrase}"`);
    }
  }
  return { ok: violations.length === 0, violations };
}

function _isCitation(item) {
  if (typeof item === 'string') return CITATION_RE.test(item);
  if (item && typeof item === 'object' && typeof item.location === 'string') {
    return CITATION_RE.test(item.location);
  }
  return false;
}

function _normalizeVerdict(verdict) {
  return String(verdict).trim().toLowerCase().replace(/[_\s]+/g, '-');
}

/**
 * Require a file:line citation behind a "this is not real" verdict.
 *
 * For a false-positive / provably-safe / safe verdict (case-insensitive; also
 * accepts FALSE_POSITIVE), at least one evidence item must be a `file:line`
 * citation — either a string matching /[^\s:]+:\d+/ or an object
 * `{ location: "file:line" }`. Any other verdict passes unconditionally.
 *
 * @param {string} verdict
 * @param {Array|string|object} evidence
 * @returns {{ ok: boolean, violations: string[] }}
 */
function requireCitedEvidence(verdict, evidence) {
  if (typeof verdict !== 'string' || !FP_VERDICTS.has(_normalizeVerdict(verdict))) {
    return { ok: true, violations: [] };
  }
  const items = Array.isArray(evidence)
    ? evidence
    : evidence == null
      ? []
      : [evidence];
  if (items.some(_isCitation)) return { ok: true, violations: [] };
  return {
    ok: false,
    violations: ['false-positive/safe verdict requires a file:line citation'],
  };
}

/**
 * Classify a fix into FULL | MITIGATION | WORKAROUND, conservative-first.
 *
 * @param {object} signals
 * @param {boolean} signals.sinkSignatureChanged
 * @param {boolean} signals.allCallersRouted
 * @param {boolean} signals.testDiscriminates - a test that fails pre-fix, passes post-fix
 * @param {boolean} [signals.rateLimitOnly]
 * @param {boolean} [signals.docsOnly]
 * @param {boolean} [signals.logOnlyNoReject]
 * @param {boolean} [signals.partialSanitization]
 * @returns {'FULL'|'MITIGATION'|'WORKAROUND'}
 */
function computeFixTier(signals) {
  const s = signals && typeof signals === 'object' ? signals : {};
  if (s.rateLimitOnly || s.docsOnly || s.logOnlyNoReject) return 'WORKAROUND';
  const complete = s.sinkSignatureChanged && s.allCallersRouted && s.testDiscriminates;
  if (s.partialSanitization || !complete) return 'MITIGATION';
  return 'FULL';
}

/**
 * Compose the three gates for a single fix's output.
 *
 * ok = residual-honesty ok AND evidence-citation ok, further constrained by the
 * tier/residual consistency invariant:
 *   - a FULL tier must NOT carry a residual (a full fix has nothing left);
 *   - a non-FULL tier MUST document a residual (say what's still open).
 *
 * @param {{ residual?: string, verdict?: string, evidence?: any, signals?: object }} input
 * @returns {{ ok: boolean, tier: string, violations: string[] }}
 */
function gateFixOutput({ residual, verdict, evidence, signals } = {}) {
  const tier = computeFixTier(signals);
  const residualCheck = checkResidualHonesty(residual);
  const evidenceCheck = requireCitedEvidence(verdict, evidence);

  const violations = [...residualCheck.violations, ...evidenceCheck.violations];
  let ok = residualCheck.ok && evidenceCheck.ok;

  const residualEmpty = typeof residual !== 'string' || residual.trim() === '';
  if (tier === 'FULL' && !residualEmpty) {
    violations.push('FULL tier cannot carry a residual');
    ok = false;
  }
  if (tier !== 'FULL' && residualEmpty) {
    violations.push('non-FULL tier must document a residual');
    ok = false;
  }

  return { ok, tier, violations };
}

const _internals = Object.freeze({ BANNED_RESIDUAL_PHRASES, CITATION_RE, FP_VERDICTS });

;// CONCATENATED MODULE: ./src/posture/fix-verify.js
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
    scan = await (0,engine/* runFullScan */.wW)({ fileContents, depFileContents, scanRoot }, () => {});
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
  const has = (p) => { try { return external_node_fs_.existsSync(external_node_path_.join(scanRoot, p)); } catch { return false; } };
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
    r = (0,external_node_child_process_.spawnSync)(cmd, args, { cwd, encoding: 'utf8', timeout: 60_000 });
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
// Addition #7 — deterministic honesty gates on fix output. When the caller
// supplies `fixMeta` ({ residual, verdict, evidence, signals }) — e.g. the
// security-fixer agent's residual-risk text + completeness signals — the fix's
// claims are checked mechanically (no hand-wave residual prose, a cited
// file:line for any FP/safe verdict, and a FULL/MITIGATION/WORKAROUND tier). A
// dishonest or over-claiming fix fails the gate. When `fixMeta` is absent
// (the deterministic MCP write path, which has no claims to check) the honesty
// gate is skipped and behavior is unchanged.
async function verifyFix({
  scanRoot,
  originalFindingStableId,
  files,
  depFileContents,
  fixMeta,
} = {}) {
  const rescan = await verifyPatch({ scanRoot, originalFindingStableId, files, depFileContents });
  const lint = runProjectLinter(scanRoot, Object.keys(files || {}));
  let honesty = null;
  if (fixMeta && typeof fixMeta === 'object') {
    try { honesty = gateFixOutput(fixMeta); } catch { honesty = null; }
  }
  const ok = rescan.ok && (lint.ok || lint.skipped) && (honesty ? honesty.ok : true);
  const summary = [
    `re-scan: ${rescan.ok ? 'PASS' : 'FAIL — ' + rescan.reason}`,
    `linter:  ${lint.runner === 'none' ? 'skipped (no linter config)'
              : lint.skipped ? `${lint.runner} not installed`
              : lint.ok ? `${lint.runner} PASS`
              : `${lint.runner} FAIL (exit ${lint.exitCode})`}`,
    honesty ? `honesty: ${honesty.ok ? `PASS (${honesty.tier})` : 'FAIL — ' + honesty.violations.join('; ')}` : null,
  ].filter(Boolean).join('\n');
  return { ok, rescan, lint, honesty, summary };
}


/***/ })

};
