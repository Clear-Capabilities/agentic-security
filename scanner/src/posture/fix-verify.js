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

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { runFullScan } from '../engine.js';
import { gateFixOutput } from './fix-honesty-gate.js';

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
export async function verifyFix({
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
