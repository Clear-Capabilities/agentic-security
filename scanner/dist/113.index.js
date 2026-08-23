export const id = 113;
export const ids = [113,238,526];
export const modules = {

/***/ 2238:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   I3: () => (/* binding */ recordFixAttempt),
/* harmony export */   fixDurationReport: () => (/* binding */ fixDurationReport),
/* harmony export */   renderFixDurationSummary: () => (/* binding */ renderFixDurationSummary)
/* harmony export */ });
/* unused harmony exports FIX_STAGES, loadFixAttempts, bucketOf, summarizeFixDurations, _internals, summarizeFixAxes, renderFixAxes */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(1174);
// Time-to-validated-fix (R5, the reporting half).
//
// `verifyFix` already RUNS the stages and `test-runner.js` already times the
// slowest one. What did not exist was anything durable to read afterwards, so
// "how long does a fix actually take to validate" had no answer from real runs
// — only an estimate (`time-to-fix.js` guesses engineering hours from family
// and patch shape, before anything runs). This module is the opposite: it
// records what the pipeline observed and reports the distribution.
//
// THE HONESTY RULES, which are most of why this file is longer than a mean:
//
//  1. A failed attempt is NOT a data point about how long a fix takes. Fixes
//     that fail verification fail fast (a re-scan that still sees the finding
//     never reaches the test suite), so blending them into one average makes
//     the pipeline look faster the worse it performs. Validated and failed
//     attempts are summarised separately and never merged.
//
//  2. "Tests skipped" is not "tests passed". A project with no detectable
//     suite can reach `ok:true` having run only the re-scan and the linter.
//     That is a weaker claim than a fix whose suite executed, and it is also
//     much faster, so counting the two together would quietly deflate the
//     headline. They get their own bucket: `validated` means the suite ran and
//     passed, `validatedWithoutTests` means there was no suite to run.
//
//  3. Every figure carries its `n`, and a percentile computed from too few
//     samples is labelled unreliable rather than omitted or silently reported.
//     Same precedent as the accuracy scorecard's `{n, d}` rates: a number
//     without its denominator is not a measurement.
//
// Storage is append-only JSONL at `<scanRoot>/.agentic-security/fix-metrics.jsonl`,
// one record per verification attempt. Nothing here throws (posture
// convention) — an unwritable or corrupt log degrades to "no metrics", never
// to a failed verification.





const LOG_FILE = 'fix-metrics.jsonl';

// Below this many samples a percentile is an artifact of the sample, not a
// property of the pipeline. Reported anyway (hiding it invites re-deriving it
// wrong downstream) but flagged, so a caller cannot quote it as settled.
const RELIABLE_N = 10;

// The stages verifyFix runs, in execution order. Kept here so the recorder and
// the summariser cannot drift apart on stage naming.
const FIX_STAGES = Object.freeze(['rescan', 'lint', 'tests', 'honesty', 'poc']);

function _logPath(scanRoot) {
  return (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .statePath */ .BQ)(scanRoot, LOG_FILE);
}

/**
 * Append one verification attempt. Best-effort and silent on failure: metrics
 * must never be able to fail a fix that otherwise verified.
 *
 * @returns {boolean} whether the record was written (for tests, not callers).
 */
function recordFixAttempt(scanRoot, record) {
  if (!scanRoot || !record || typeof record !== 'object') return false;
  try {
    const dir = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .stateDir */ .Pn)(scanRoot);
    if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.isSafeStateDir)(dir)) return false;
    if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.stateWritesEnabled)()) return false;
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(dir, { recursive: true });
    // One writeSync of one newline-terminated line: a concurrent reader sees
    // whole records or nothing, and a torn tail is dropped on read.
    node_fs__WEBPACK_IMPORTED_MODULE_0__.appendFileSync(_logPath(scanRoot), JSON.stringify(record) + '\n', 'utf8');
    return true;
  } catch { return false; }
}

/**
 * Read every well-formed attempt. A line that does not parse is skipped, not
 * fatal — the last line of an interrupted write is the expected case.
 */
function loadFixAttempts(scanRoot) {
  try {
    const raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(_logPath(scanRoot), 'utf8');
    const out = [];
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line);
        if (rec && typeof rec === 'object' && typeof rec.totalMs === 'number') out.push(rec);
      } catch { /* torn or hand-edited line — drop it, keep the rest */ }
    }
    return out;
  } catch { return []; }
}

// Nearest-rank percentile over an ascending array. Nearest-rank rather than
// interpolated because these are observed durations, and an interpolated p50
// reports a duration that no run actually took.
function _pct(sorted, p) {
  if (!sorted.length) return null;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))];
}

function _dist(values) {
  const v = values.filter(x => typeof x === 'number' && Number.isFinite(x) && x >= 0).sort((a, b) => a - b);
  if (!v.length) return { n: 0, minMs: null, p50Ms: null, p90Ms: null, maxMs: null, meanMs: null, reliable: false };
  const sum = v.reduce((a, b) => a + b, 0);
  return {
    n: v.length,
    minMs: v[0],
    p50Ms: _pct(v, 50),
    p90Ms: _pct(v, 90),
    maxMs: v[v.length - 1],
    meanMs: Math.round(sum / v.length),
    // Says whether the percentiles above may be quoted, not whether the count
    // is real. n and min/max/mean are exact at any sample size.
    reliable: v.length >= RELIABLE_N,
  };
}

// Which bucket an attempt belongs to. Deliberately total: every attempt lands
// in exactly one, so the bucket counts always sum to the attempt count and a
// mis-shaped record cannot silently vanish from the denominator.
function bucketOf(a) {
  if (!a?.ok) return 'failed';
  return a.testsRan ? 'validated' : 'validatedWithoutTests';
}

/**
 * Summarise a set of attempts into the reported distribution.
 *
 * `validated` is the headline: attempts that verified AND whose test suite
 * actually ran and passed. The other two buckets exist so that headline cannot
 * be inflated by counting weaker or faster outcomes inside it.
 */
function summarizeFixDurations(attempts) {
  const all = Array.isArray(attempts) ? attempts : [];
  const buckets = { validated: [], validatedWithoutTests: [], failed: [] };
  for (const a of all) buckets[bucketOf(a)].push(a);

  const byStage = {};
  for (const stage of FIX_STAGES) {
    // Per-stage timings come from validated runs only. A stage's duration in a
    // failed run is truncated by the failure (the pipeline stops), so mixing
    // them in would understate every stage after the first failure point.
    byStage[stage] = _dist(buckets.validated.map(a => a?.stages?.[stage]));
  }

  return {
    attempts: all.length,
    counts: {
      validated: buckets.validated.length,
      validatedWithoutTests: buckets.validatedWithoutTests.length,
      failed: buckets.failed.length,
    },
    timeToValidatedFix: _dist(buckets.validated.map(a => a.totalMs)),
    timeToValidatedFixWithoutTests: _dist(buckets.validatedWithoutTests.map(a => a.totalMs)),
    timeToFailure: _dist(buckets.failed.map(a => a.totalMs)),
    byStage,
    reliableAtOrAbove: RELIABLE_N,
  };
}

/** Read + summarise in one step. */
function fixDurationReport(scanRoot) {
  return summarizeFixDurations(loadFixAttempts(scanRoot));
}

function _ms(v) {
  if (v == null) return '—';
  return v >= 1000 ? `${(v / 1000).toFixed(1)}s` : `${v}ms`;
}

/**
 * One-paragraph human summary. Returns null when there is nothing measured —
 * callers print nothing rather than printing an empty table.
 */
function renderFixDurationSummary(sum) {
  if (!sum || !sum.attempts) return null;
  const d = sum.timeToValidatedFix;
  const parts = [];
  if (d.n) {
    parts.push(
      `time-to-validated-fix: median ${_ms(d.p50Ms)}, p90 ${_ms(d.p90Ms)} `
      + `(n=${d.n}${d.reliable ? '' : `, below ${sum.reliableAtOrAbove} — percentiles not yet reliable`})`,
    );
  } else {
    parts.push('time-to-validated-fix: no fix has both verified and had its test suite run yet');
  }
  if (sum.counts.validatedWithoutTests) {
    parts.push(`${sum.counts.validatedWithoutTests} verified with no detectable test suite (excluded from the median above)`);
  }
  if (sum.counts.failed) {
    parts.push(`${sum.counts.failed} failed verification, median ${_ms(sum.timeToFailure.p50Ms)} (counted separately)`);
  }
  return parts.join('; ') + '.';
}

const _internals = { _dist, _pct, RELIABLE_N };


// ── PRD F6.1 — score fixes on THREE AXES, not one ──────────────────────────
//
// The three axes the PRD names:
//   (a) does the finding disappear      — the rescan leg
//   (b) does the project's own suite pass — the tests leg
//   (c) does an independent verifier agree — the PoC re-check leg
//
// All three were already computed by verifyFixCore and then collapsed into one
// boolean, which is the problem: **(a) alone is satisfiable by deleting code.**
// A patch that removes the vulnerable function passes the rescan, has nothing
// left to fail, and — on a project with no detectable test suite — reaches
// ok:true having proven only that the detector went quiet.
//
// Reporting the axes separately makes that visible. `aOnly` is the number that
// matters most and the one nobody was publishing: attempts that satisfied ONLY
// the disappearance axis. A high aOnly with a high headline is the shape of a
// remediation feature that is deleting code and calling it a fix.
function summarizeFixAxes(attempts) {
  const list = Array.isArray(attempts) ? attempts.filter(Boolean) : [];
  const d = list.length;

  const rate = (pred) => ({ n: list.filter(pred).length, d });

  // Each axis is judged INDEPENDENTLY of the overall verdict, so a leg that
  // passed inside a failed attempt still counts for its own axis. Reading them
  // off `ok` would make the three axes three copies of the same number.
  const findingDisappeared = rate((a) => a.rescanOk === true || (a.ok === true && a.rescanOk !== false));
  const testsStillPass = rate((a) => a.testsRan === true && a.testsOk !== false);
  const verifierAgrees = rate((a) => a.pocOk === true);

  const satisfiesAll = rate((a) =>
    (a.rescanOk === true || (a.ok === true && a.rescanOk !== false))
    && a.testsRan === true && a.testsOk !== false
    && a.pocOk === true);

  // The honesty number: disappearance WITHOUT either corroborating axis.
  const aOnly = rate((a) => {
    const disappeared = a.rescanOk === true || (a.ok === true && a.rescanOk !== false);
    const corroborated = (a.testsRan === true && a.testsOk !== false) || a.pocOk === true;
    return disappeared && !corroborated;
  });

  return {
    total: d,
    findingDisappeared,
    testsStillPass,
    verifierAgrees,
    satisfiesAll,
    aOnly,
    meaning:
      'findingDisappeared = the detector went quiet; testsStillPass = the project suite ran AND passed; '
      + 'verifierAgrees = an independent PoC re-check confirmed the hole is shut. '
      + 'aOnly counts attempts that satisfied ONLY disappearance — the shape a code-deleting "fix" produces.',
    caveat: d === 0
      ? 'no attempts recorded; every rate is 0/0 and means nothing'
      : 'rates carry {n,d}; a small d is indicative, not settled',
  };
}

/** Markdown for a report. Denominators always attached. */
function renderFixAxes(sum) {
  if (!sum || !sum.total) return '_No fix attempts recorded._\n';
  const row = (label, r, note) => `| ${label} | ${r.n}/${r.d} | ${note} |`;
  return [
    '| Axis | Rate | Meaning |',
    '|---|---|---|',
    row('(a) finding disappeared', sum.findingDisappeared, 'the detector went quiet'),
    row('(b) project tests pass', sum.testsStillPass, 'the suite RAN and passed'),
    row('(c) verifier agrees', sum.verifierAgrees, 'an independent PoC re-check confirmed it'),
    row('all three', sum.satisfiesAll, 'the only row that means "fixed"'),
    row('(a) ALONE', sum.aOnly, 'satisfiable by deleting code — watch this number'),
    '',
  ].join('\n');
}


/***/ }),

/***/ 4113:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   verifyFixWithTests: () => (/* binding */ verifyFixWithTests)
/* harmony export */ });
/* unused harmony export runProjectTests */
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(1421);
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(6760);
/* harmony import */ var _fix_verify_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(3526);
// Closed-loop fix verification (v0.68).
//
// Existing `fix-verify.js` does scan + lint. This module adds the third
// leg: run the project's test suite against the patched file set. A fix
// is `verified-clean` only when:
//
//   1. Re-scan no longer fires the original finding's stableId
//   2. No new ≥medium findings introduced
//   3. Project linter (when present) passes on the patched files
//   4. Project test runner (when present) exits 0 within budget
//
// If the project has no detected test runner, we emit `untested-but-passes`
// rather than fail-closed — many small repos have no test suite and we
// don't want to refuse all fixes there. The verdict is honest.
//
// Design note: we run the tests against the WRITTEN patch, not an in-
// memory overlay — most real test runners can't be given an alternate
// filesystem cheaply. Callers are expected to apply the patch first
// (typically via fix-history.applyFix which creates a recovery backup),
// then call this. If verification fails, undoLast() rolls back.






const DEFAULT_TIMEOUT_MS = 120_000;

// Test-runner discovery. Each entry: a sentinel-file check + a command +
// args. Order matters — JS first (most common), then Python, Go, Rust,
// Java/Maven, Java/Gradle, Ruby.
function _detectRunner(scanRoot) {
  const has = (p) => { try { return node_fs__WEBPACK_IMPORTED_MODULE_1__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(scanRoot, p)); } catch { return false; } };
  const pkg = (() => {
    try {
      const raw = node_fs__WEBPACK_IMPORTED_MODULE_1__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(scanRoot, 'package.json'), 'utf8');
      return JSON.parse(raw);
    } catch { return null; }
  })();
  if (pkg && pkg.scripts && pkg.scripts.test && !/no test specified/.test(String(pkg.scripts.test))) {
    // --passWithNoTests is Jest-specific CLI syntax — appending it
    // unconditionally broke every non-Jest npm test script (mocha, vitest,
    // ava, tap, or a plain node script) with an "unrecognized option" exit,
    // failing verification for a reason that has nothing to do with
    // whether the patch actually broke anything. Only add it when Jest is
    // actually the configured runner.
    const usesJest = /\bjest\b/.test(String(pkg.scripts.test))
      || Boolean(pkg.devDependencies?.jest) || Boolean(pkg.dependencies?.jest);
    const args = usesJest ? ['test', '--silent', '--', '--passWithNoTests'] : ['test', '--silent'];
    return { runner: 'npm', cmd: 'npm', args };
  }
  if (has('pytest.ini') || has('pyproject.toml') || has('setup.cfg')) {
    return { runner: 'pytest', cmd: 'pytest', args: ['-q', '--no-header', '-x'] };
  }
  if (has('go.mod')) {
    return { runner: 'go-test', cmd: 'go', args: ['test', './...'] };
  }
  if (has('Cargo.toml')) {
    return { runner: 'cargo-test', cmd: 'cargo', args: ['test', '--quiet'] };
  }
  if (has('Gemfile')) {
    return { runner: 'rspec', cmd: 'bundle', args: ['exec', 'rspec', '--fail-fast'] };
  }
  if (has('pom.xml')) {
    return { runner: 'maven', cmd: 'mvn', args: ['-q', 'test', '-DfailIfNoTests=false'] };
  }
  if (has('build.gradle') || has('build.gradle.kts')) {
    return { runner: 'gradle', cmd: './gradlew', args: ['test', '--quiet', '--no-daemon'] };
  }
  return null;
}

// Run the detected test runner. Honors a walltime budget. Caller may pass
// `runnerOverride` to force a specific command (rare; mostly for tests).
function runProjectTests(scanRoot, opts = {}) {
  if (!scanRoot) return { ok: true, runner: 'none', skipped: true };
  const choice = opts.runnerOverride
    ? { runner: opts.runnerOverride.cmd, cmd: opts.runnerOverride.cmd, args: opts.runnerOverride.args || [] }
    : _detectRunner(scanRoot);
  if (!choice) return { ok: true, runner: 'none', skipped: true, reason: 'no-test-runner-detected' };
  const timeout = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  let r;
  try {
    r = (0,node_child_process__WEBPACK_IMPORTED_MODULE_0__.spawnSync)(choice.cmd, choice.args, {
      cwd: scanRoot,
      encoding: 'utf8',
      timeout,
      env: { ...process.env, CI: '1' },
    });
  } catch (e) {
    return { ok: false, runner: choice.runner, reason: 'spawn-failed', error: e.message };
  }
  if (r.error && r.error.code === 'ENOENT') {
    // Runner not installed — different from "tests failed". Don't fail-closed.
    return { ok: true, runner: choice.runner, skipped: true, reason: 'binary-missing' };
  }
  if (r.status === null) {
    return {
      ok: false, runner: choice.runner, reason: 'timed-out',
      output: ((r.stderr || '') + (r.stdout || '')).slice(-2000),
    };
  }
  return {
    ok: r.status === 0,
    runner: choice.runner,
    exitCode: r.status,
    output: ((r.stderr || '') + (r.stdout || '')).slice(-2000),
  };
}

// Closed-loop verification: scan + lint + tests. Returns a single verdict
// with per-leg detail so the caller can render a precise summary.
//
// Returns:
//   {
//     ok: bool,
//     verdict: 'verified-clean' | 'verification-failed' | 'untested-but-passes',
//     legs: { scan: …, lint: …, tests: … },
//     summary: '<human-readable line>',
//   }
//
// The `untested-but-passes` verdict is real and intentional: scan+lint
// passed, but no test runner was found. This is honest signal — callers
// (the security-fixer agent, downstream MCP tools) can decide whether to
// require a stronger verdict.
async function verifyFixWithTests({
  scanRoot,
  originalFindingStableId,
  files,
  depFileContents,
  runTests = true,
  testRunnerOverride,
  testTimeoutMs,
} = {}) {
  const scanLint = await (0,_fix_verify_js__WEBPACK_IMPORTED_MODULE_3__.verifyFix)({ scanRoot, originalFindingStableId, files, depFileContents });
  const legs = {
    scan: { ok: scanLint.rescan?.ok ?? scanLint.ok, detail: scanLint.rescan ?? scanLint },
    lint: { ok: scanLint.lint?.ok ?? true, detail: scanLint.lint ?? null },
    tests: { ok: true, detail: null, skipped: true, reason: 'not-run' },
  };
  if (!legs.scan.ok || !legs.lint.ok) {
    return {
      ok: false,
      verdict: 'verification-failed',
      legs,
      summary: _summarize(legs, 'verification-failed'),
    };
  }
  if (runTests) {
    const tests = runProjectTests(scanRoot, { runnerOverride: testRunnerOverride, timeoutMs: testTimeoutMs });
    legs.tests = { ok: tests.ok, detail: tests, skipped: !!tests.skipped, reason: tests.reason };
  }
  const allOk = legs.scan.ok && legs.lint.ok && legs.tests.ok;
  const verdict = !allOk
    ? 'verification-failed'
    : (legs.tests.skipped ? 'untested-but-passes' : 'verified-clean');
  return { ok: allOk, verdict, legs, summary: _summarize(legs, verdict) };
}

function _summarize(legs, verdict) {
  const bits = [];
  bits.push(`scan: ${legs.scan.ok ? 'pass' : 'fail'}`);
  bits.push(`lint: ${legs.lint.skipped ? 'skip' : legs.lint.ok ? 'pass' : 'fail'}`);
  bits.push(`tests: ${legs.tests.skipped ? 'skip' : legs.tests.ok ? 'pass' : 'fail'}`);
  return `${verdict} (${bits.join(' · ')})`;
}


/***/ }),

/***/ 3526:
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
// EXTERNAL MODULE: ./src/engine.js + 199 modules
var engine = __webpack_require__(6549);
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

;// CONCATENATED MODULE: ./src/posture/test-runner.js
// R5 (partial, roadmap) — the project's own test suite as a verification
// stage for `verifyFix()` (see `fix-verify.js`). Closes the gap where a
// "verified" fix only proved a finding's stableId stopped firing — a patch
// that deletes the feature entirely would satisfy that just as well as a
// real fix. Running the project's own tests is the cheapest available check
// that the application still works.
//
// Execution-safety note: this spawns the TARGET PROJECT's own test command
// in the target project's own directory. That is deliberately NOT routed
// through the R1 confinement sandbox (`../sandbox/`). That sandbox exists to
// contain untrusted proof-of-concept exploit code the scanner itself
// synthesizes — code nobody has vetted, being run for the first time. A
// project's pre-existing test suite is the opposite case: it is the
// project's own trusted source, already sitting on disk, and running it is
// exactly what a human developer does by hand before trusting a fix.
// Wrapping "npm test" / "pytest" / "go test" in the PoC sandbox's
// syscall/network/filesystem restrictions would break the large majority of
// real test suites (they bind local ports, spawn child processes, write temp
// fixtures, etc.) for no corresponding security benefit.





const DEFAULT_TIMEOUT_MS = 300_000;
const NPM_PLACEHOLDER = /Error: no test specified/i;

function _exists(scanRoot, rel) {
  try { return external_node_fs_.existsSync(external_node_path_.join(scanRoot, rel)); } catch { return false; }
}

function _isDir(scanRoot, rel) {
  try { return external_node_fs_.statSync(external_node_path_.join(scanRoot, rel)).isDirectory(); } catch { return false; }
}

function _binaryAvailable(cmd) {
  try {
    const r = (0,external_node_child_process_.spawnSync)(cmd, ['--version'], { timeout: 5_000, stdio: 'ignore' });
    return !(r.error && r.error.code === 'ENOENT');
  } catch {
    return false;
  }
}

// Detect the project's test command. Read-only — never spawns the actual
// test run, only (optionally) a cheap `--version` probe to confirm a tool
// like `pytest` is actually installed before committing to it. Returns
// `null` when nothing detectable is found — most scanned repos will hit
// this path, and that must not be treated as a failure by callers.
function detectTestCommand(scanRoot) {
  if (!scanRoot) return null;

  // JS/TS — package.json with a real (non-placeholder) `scripts.test`.
  let pkg = null;
  try { pkg = JSON.parse(external_node_fs_.readFileSync(external_node_path_.join(scanRoot, 'package.json'), 'utf8')); } catch { pkg = null; }
  const testScript = pkg && pkg.scripts && pkg.scripts.test;
  if (testScript && !NPM_PLACEHOLDER.test(String(testScript))) {
    if (_exists(scanRoot, 'pnpm-lock.yaml')) return { cmd: 'pnpm', args: ['test'], kind: 'pnpm' };
    if (_exists(scanRoot, 'yarn.lock')) return { cmd: 'yarn', args: ['test'], kind: 'yarn' };
    if (_exists(scanRoot, 'bun.lockb') || _exists(scanRoot, 'bun.lock')) return { cmd: 'bun', args: ['test'], kind: 'bun' };
    return { cmd: 'npm', args: ['test', '--silent'], kind: 'npm' };
  }

  // Python — pytest.ini / pyproject.toml / tox.ini / a tests/ dir, and the
  // `pytest` binary actually available. If pytest isn't installed we do NOT
  // report a python test command — falling through lets a later language
  // marker (e.g. go.mod in a polyglot repo) still be detected.
  const pyMarker = _exists(scanRoot, 'pytest.ini') || _exists(scanRoot, 'pyproject.toml') ||
    _exists(scanRoot, 'tox.ini') || _isDir(scanRoot, 'tests');
  if (pyMarker && _binaryAvailable('pytest')) {
    return { cmd: 'pytest', args: ['-q'], kind: 'pytest' };
  }

  // Go
  if (_exists(scanRoot, 'go.mod')) {
    return { cmd: 'go', args: ['test', './...'], kind: 'go' };
  }

  return null;
}

// Run the detected test command with a walltime budget. Always returns a
// result object — never throws. Distinguishes four outcomes:
//   - no detectable/runnable command  -> status: 'skipped'  (does NOT fail)
//   - ran and exited 0                -> status: 'passed'
//   - ran and exited non-zero         -> status: 'failed'
//   - ran past the timeout budget     -> status: 'failed', timedOut: true
function runProjectTests(scanRoot, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const startedAt = Date.now();
  const command = detectTestCommand(scanRoot);
  if (!command) {
    return {
      status: 'skipped', passed: null, skipped: true,
      reason: 'no-test-command-detected', exitCode: null, timedOut: false,
      durationMs: Date.now() - startedAt,
    };
  }

  let r;
  try {
    r = (0,external_node_child_process_.spawnSync)(command.cmd, command.args, {
      cwd: scanRoot,
      encoding: 'utf8',
      timeout: timeoutMs,
      env: { ...process.env, CI: '1' },
    });
  } catch (e) {
    // The spawn call itself threw (rare — e.g. cwd vanished). Treat as
    // "could not run", not "ran and failed".
    return {
      status: 'skipped', passed: null, skipped: true,
      reason: `spawn-error: ${e.message}`, exitCode: null, timedOut: false,
      durationMs: Date.now() - startedAt,
    };
  }
  const durationMs = Date.now() - startedAt;

  if (r.error && r.error.code === 'ENOENT') {
    // The detected tool isn't actually installed on this machine. Not a
    // test failure — the suite never ran.
    return {
      status: 'skipped', passed: null, skipped: true,
      reason: `${command.kind}-not-installed`, exitCode: null, timedOut: false, durationMs,
    };
  }

  if (r.status === null) {
    // spawnSync sets status:null both on timeout-kill and on being killed by
    // another signal; either way the run did not complete, which is a
    // verification failure, never a skip — we asked for a result and the
    // process was terminated before producing one.
    return {
      status: 'failed', passed: false, skipped: false,
      reason: 'timed-out', exitCode: null, timedOut: true, durationMs,
    };
  }

  return {
    status: r.status === 0 ? 'passed' : 'failed',
    passed: r.status === 0,
    skipped: false,
    reason: r.status === 0 ? null : 'test-failures',
    exitCode: r.status,
    timedOut: false,
    durationMs,
  };
}

// EXTERNAL MODULE: ./src/posture/fix-metrics.js
var fix_metrics = __webpack_require__(2238);
;// CONCATENATED MODULE: ./src/posture/fix-verify.js
// Closed-loop /fix verification (Sentinel-parity FR-L4-4, FR-L4-5).
//
// Given a candidate patch (the new file content + the finding stableId being
// fixed), verify it:
//
//   1. The original finding's stableId no longer fires on the patched file.
//   2. No new findings at severity ≥ medium were introduced by the patch.
//   3. The project's existing linter (when present) passes on the patched file.
//   4. The project's own test suite (when detectable) still passes. This is
//      the R5 gap-closer: a patch that silently deletes the feature would
//      satisfy (1) and (2) just as well as a real fix — only running the
//      tests catches that. See `test-runner.js` for detection + execution.
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
// R5 (partial) — the test-suite stage. Runs the target project's own tests,
// in the target project's own directory, against whatever is currently on
// disk there. See `test-runner.js`'s header comment for why that run is
// deliberately NOT routed through the R1 PoC-confinement sandbox: this is
// the project's own already-trusted suite, not untrusted synthesized code.
//
// Caveat that matters for callers: `verifyPatch` above re-scans the
// candidate patch purely in memory (no write to disk), but a test runner
// needs real files — there is no cheap way to hand a runner an in-memory
// overlay. So this leg reports on the CURRENT on-disk tree, not the
// candidate `files` map, when `verifyFix` is used as a pre-write preview
// (e.g. the `verify_fix` MCP tool). Callers that apply the patch first and
// then re-verify get the strongest signal; that ordering is not enforced
// here — it's the caller's responsibility, same as it already is for the
// closed-loop `fix-verify-loop.js` path.
// Does the caller's candidate patch differ from what is on disk right now?
// If so, any test run necessarily exercised the pre-patch tree. Compared by
// content so a patch that happens to match disk (already applied) is correctly
// treated as NOT pre-patch.
function _candidateDiffersFromDisk(scanRoot, files) {
  if (!files || typeof files !== 'object') return false;
  for (const [rel, content] of Object.entries(files)) {
    if (typeof content !== 'string') continue;
    try {
      const abs = external_node_path_.resolve(scanRoot, rel);
      if (external_node_fs_.readFileSync(abs, 'utf8') !== content) return true;
    } catch {
      return true; // candidate file absent on disk -> definitely not applied
    }
  }
  return false;
}

async function verifyFix({
  scanRoot,
  originalFindingStableId,
  files,
  depFileContents,
  fixMeta,
  testTimeoutMs,
  recordMetrics = true,
  poc,
} = {}) {
  // R5 (reporting half) — time each stage as it runs. Measured here rather
  // than inside each stage because only this function knows the boundaries of
  // one verification ATTEMPT, which is the unit the distribution is over.
  const stages = {};
  const t0 = Date.now();
  let mark = t0;
  const _lap = (name) => { const now = Date.now(); stages[name] = now - mark; mark = now; };

  const rescan = await verifyPatch({ scanRoot, originalFindingStableId, files, depFileContents });
  _lap('rescan');
  const lint = runProjectLinter(scanRoot, Object.keys(files || {}));
  _lap('lint');
  const tests = runProjectTests(scanRoot, testTimeoutMs != null ? { timeoutMs: testTimeoutMs } : {});
  _lap('tests');
  // True when a candidate patch was supplied but has not been written, so the
  // suite necessarily ran against the pre-patch tree. Surfaced in the summary
  // and on the result so a caller cannot mistake it for a verified patch.
  const _testedPrePatch = !tests.skipped && _candidateDiffersFromDisk(scanRoot, files);
  const testsOk = tests.skipped ? true : tests.passed === true;
  let honesty = null;
  if (fixMeta && typeof fixMeta === 'object') {
    try { honesty = gateFixOutput(fixMeta); } catch { honesty = null; }
  }
  _lap('honesty');

  // R5 — the PoC leg. Re-run the finding's proof-of-concept against the
  // CANDIDATE patch inside R1's sandbox. A patch that still lets the PoC
  // demonstrate the predicted effect has not fixed anything, however green the
  // re-scan looks: the re-scan only proves the DETECTOR stopped firing, which
  // a cosmetic edit can achieve. Execution is the stronger claim.
  //
  // Direction matters and is asymmetric on purpose. `execution-proven` after
  // the patch is a hard FAIL. Anything else is NOT a pass — a PoC that failed
  // to run, or a sandbox that could not start, is recorded as `inconclusive`
  // and left out of the verdict entirely. Treating "could not prove it" as
  // "fixed" is exactly the false confidence this leg exists to prevent.
  let pocLeg = { status: 'not-requested', reason: null, tier: null };
  if (poc?.code) {
    try {
      const { proveFinding } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 1291));
      const proved = await proveFinding({ ...(poc.finding || {}), poc }, { files });
      const tier = proved.proofTier;
      pocLeg = tier === 'execution-proven'
        ? { status: 'still-exploitable', tier, reason: proved.proofEvidence?.observed || null }
        : proved.proofEvidence?.ran
          ? { status: 'no-longer-proven', tier, reason: proved.proofEvidence?.reason || null }
          : { status: 'inconclusive', tier, reason: proved.proofEvidence?.reason || null };
    } catch (e) {
      pocLeg = { status: 'inconclusive', tier: null, reason: `proof harness error: ${e.message}` };
    }
  }
  _lap('poc');
  const pocOk = pocLeg.status !== 'still-exploitable';

  const ok = rescan.ok && (lint.ok || lint.skipped) && testsOk && pocOk && (honesty ? honesty.ok : true);
  const durations = { ...stages, totalMs: Date.now() - t0 };
  const summary = [
    `re-scan: ${rescan.ok ? 'PASS' : 'FAIL — ' + rescan.reason}`,
    `linter:  ${lint.runner === 'none' ? 'skipped (no linter config)'
              : lint.skipped ? `${lint.runner} not installed`
              : lint.ok ? `${lint.runner} PASS`
              : `${lint.runner} FAIL (exit ${lint.exitCode})`}`,
    // Say which tree the suite actually ran against. `files` is a candidate
    // patch held in memory; the runner needs real files, so it sees whatever is
    // on disk. Reporting a bare "PASS" here would let a caller believe the
    // PATCH passed the tests when the suite may have run on unpatched code.
    `tests:   ${tests.skipped ? `skipped (${tests.reason})`
              : tests.timedOut ? 'FAIL (timed out)'
              : tests.passed ? `PASS${_testedPrePatch ? ' — on the CURRENT on-disk tree, NOT the candidate patch' : ''}`
              : `FAIL (exit ${tests.exitCode})`}`,
    honesty ? `honesty: ${honesty.ok ? `PASS (${honesty.tier})` : 'FAIL — ' + honesty.violations.join('; ')}` : null,
    // Never render `inconclusive` as a pass — say plainly that nothing was proven.
    pocLeg.status === 'not-requested' ? null
      : pocLeg.status === 'still-exploitable' ? `poc:     FAIL — the proof-of-concept still demonstrates the vulnerability against the patch`
      : pocLeg.status === 'no-longer-proven' ? 'poc:     PASS (ran against the patch and no longer demonstrates the vulnerability)'
      : `poc:     inconclusive — not counted either way (${pocLeg.reason || 'no detail reported'})`,
  ].filter(Boolean).join('\n');
  // Persist the attempt so the distribution can be reported from real runs.
  // `testsRan` is the load-bearing field: it is what keeps "verified with no
  // test suite to run" out of the headline time-to-validated-fix bucket.
  // A patch that was never written to disk is recorded too, but flagged — its
  // suite ran against the pre-patch tree, so its timing is real while its
  // verdict is about a different tree.
  if (recordMetrics && scanRoot) {
    (0,fix_metrics/* recordFixAttempt */.I3)(scanRoot, {
      at: new Date().toISOString(),
      stableId: originalFindingStableId || null,
      ok,
      testsRan: !tests.skipped,
      testsPassed: tests.skipped ? null : tests.passed === true,
      testedPrePatch: _testedPrePatch,
      lintRan: !(lint.skipped || lint.runner === 'none'),
      honestyGated: honesty != null,
      pocStatus: pocLeg.status,
      files: Object.keys(files || {}).length,
      stages,
      totalMs: durations.totalMs,
    });
  }

  return { ok, rescan, lint, tests, testedPrePatch: _testedPrePatch, honesty, poc: pocLeg, durations, summary };
}


/***/ })

};
