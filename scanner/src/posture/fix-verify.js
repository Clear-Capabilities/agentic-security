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

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { runFullScan } from '../engine.js';
import { gateFixOutput } from './fix-honesty-gate.js';
import { runProjectTests } from './test-runner.js';
import { recordFixAttempt } from './fix-metrics.js';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Run a focused re-scan over just the patched file(s) using the in-memory
// engine. No filesystem write needed — we hand the new content in via the
// fileContents map.
export async function verifyPatch({
  scanRoot,
  originalFindingStableId,
  files,   // { [relPath]: newContent }
  depFileContents = {},
} = {}) {
  if (!files || typeof files !== 'object') return { ok: false, reason: 'no-files-provided' };
  const fileContents = { ...files };
  let scan;
  try {
    scan = await runFullScan({ fileContents, depFileContents, scanRoot }, () => {});
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
export function runProjectLinter(scanRoot, filePaths) {
  if (!scanRoot || !Array.isArray(filePaths) || filePaths.length === 0) {
    return { ok: true, runner: 'none' };
  }
  const has = (p) => { try { return fs.existsSync(path.join(scanRoot, p)); } catch { return false; } };
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
    r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 60_000 });
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
      const abs = path.resolve(scanRoot, rel);
      if (fs.readFileSync(abs, 'utf8') !== content) return true;
    } catch {
      return true; // candidate file absent on disk -> definitely not applied
    }
  }
  return false;
}

export async function verifyFix({
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
  //
  // Computed BEFORE the honesty gate (FR-308): a still-exploitable PoC is
  // MECHANICAL evidence, not a self-report, and gateFixOutput cross-checks a
  // self-reported FULL tier against it below — the ordering matters, not
  // just the value.
  let pocLeg = { status: 'not-requested', reason: null, tier: null };
  if (poc?.code) {
    try {
      const { proveFinding } = await import('./execution-proof.js');
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

  // FR-308: "a mitigation or workaround cannot be represented as a full
  // fix" — gateFixOutput's tier/residual check is a pure self-consistency
  // check (fixMeta.signals is agent-self-reported; see fix-honesty-gate.js's
  // header for why nothing there is server-computable). pocLeg IS
  // server-computable — a real execution result, not a claim — so it is
  // passed through as the one MECHANICAL cross-check available: a
  // self-reported FULL tier is refuted, not just internally inconsistent,
  // when the PoC still demonstrates the vulnerability against the patch.
  // D-0024: `fixMeta` is a shared envelope — FR-307/FR-1002's `approval`
  // key lives alongside FR-308's completeness self-report (`residual`/
  // `verdict`/`evidence`/`signals`). Gating on mere object-truthiness meant
  // a caller supplying ONLY `approval` (a real, common shape once the CLI's
  // --approved-by flag and the MCP schema fix made that reachable) got
  // silently gated on an UNRELATED FR-308 self-consistency check it never
  // engaged with — computeFixTier(undefined) defaults to MITIGATION, which
  // then demands a `residual` nobody was ever asked to supply, blocking an
  // otherwise-genuine, approved fix for a reason that has nothing to do
  // with completeness honesty. Scope the gate to fixMeta shapes that
  // actually make a completeness-adjacent claim.
  const hasHonestyClaim = fixMeta && typeof fixMeta === 'object' &&
    (fixMeta.residual !== undefined || fixMeta.verdict !== undefined ||
     fixMeta.evidence !== undefined || fixMeta.signals !== undefined);
  let honesty = null;
  if (hasHonestyClaim) {
    try { honesty = gateFixOutput(fixMeta, { pocLeg }); } catch { honesty = null; }
  }
  _lap('honesty');

  const ok = rescan.ok && (lint.ok || lint.skipped) && testsOk && pocOk && (honesty ? honesty.ok : true);

  // FR-305 (assurance-hardening PRD): `ok` alone conflates "every leg
  // genuinely ran and passed" with "passed, but a required leg was skipped
  // or unavailable" — `lint.ok`/`testsOk` are both true in the skipped case
  // by design (this codebase does not fail-closed just because a repo has
  // no linter or no detected test runner), so a caller checking only `ok`
  // cannot tell the difference. `lint.skipped` is only ever true when a
  // linter WAS configured but its binary could not be run (missing config
  // entirely returns `runner: 'none'` with no `skipped` field at all — that
  // is a genuine N/A, nothing was required, not a degradation). `verifiedFull`
  // is the honest label: true only when nothing that WAS required was
  // skipped. A caller must never present `ok: true, verifiedFull: false` as
  // "fully verified" — `degradedLegs` names exactly what was skipped so a
  // report can say so plainly instead of a bare pass.
  const degradedLegs = [];
  if (lint.skipped) degradedLegs.push(`lint: ${lint.runner} not installed`);
  if (tests.skipped) degradedLegs.push(`tests: skipped (${tests.reason})`);
  const verifiedFull = ok && degradedLegs.length === 0;

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
    // FR-305: never let a degraded pass read the same as a full one.
    ok && !verifiedFull ? `NOTE:    PASSED, but NOT fully verified — ${degradedLegs.join('; ')}` : null,
  ].filter(Boolean).join('\n');
  // Persist the attempt so the distribution can be reported from real runs.
  // `testsRan` is the load-bearing field: it is what keeps "verified with no
  // test suite to run" out of the headline time-to-validated-fix bucket.
  // A patch that was never written to disk is recorded too, but flagged — its
  // suite ran against the pre-patch tree, so its timing is real while its
  // verdict is about a different tree.
  if (recordMetrics && scanRoot) {
    recordFixAttempt(scanRoot, {
      at: new Date().toISOString(),
      stableId: originalFindingStableId || null,
      ok,
      verifiedFull,
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

  return { ok, verifiedFull, degradedLegs, rescan, lint, tests, testedPrePatch: _testedPrePatch, honesty, poc: pocLeg, durations, summary };
}
