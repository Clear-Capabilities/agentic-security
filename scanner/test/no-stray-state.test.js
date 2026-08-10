// State-write seam guard (NON_MUTATING_SCAN_PRD S2).
//
// WHY THIS EXISTS
// ---------------
// `posture/state-dir.js` is the one place allowed to decide where
// `.agentic-security/` lives. It refuses to write outside a project root, and it
// now honours a global read-only switch so a scan can leave the scanned tree
// untouched.
//
// None of that helps if callers build the path themselves. Measured when this
// guard was written: 59 modules under `scanner/src/` constructed
// `.agentic-security` paths directly, against 5 that routed through the seam. A
// guard 8% of callers use is documentation, not a control.
//
// The consequences were not theoretical. `state-dir.js`'s own header records a
// user who uninstalled the plugin when stray state directories broke their
// build, and this project's independent benchmark was silently contaminated for
// weeks — 220 polluted trees, 544 state files carrying CWE identifiers, so the
// engine was partly grading itself.
//
// HOW THIS GUARD WORKS
// --------------------
// The ALLOWLIST below is a MIGRATION LEDGER, not a set of exemptions. It is
// seeded with the modules that already bypassed the seam, so the guard can be
// enforced from today: it cannot fix history, but it makes the list strictly
// non-growing. Every new violation fails the build.
//
// Entries come OFF this list as modules migrate. Nothing goes ON it without a
// written reason, reviewed — the same rule `no-dead-modules.test.js` uses, which
// has caught four real defects in this repository.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(HERE, '..', 'src');

/** The seam itself, plus modules awaiting migration. NON-GROWING. */
const ALLOWLIST = new Set([
  'posture/state-dir.js',       // the seam
  // --- migration ledger, seeded 2026-08-09: 59 modules ---
  'badge.js', 'dataflow/cross-service-taint.js', 'dataflow/ifds-precise.js',
  'dataflow/incremental.js', 'discovery/memory.js', 'engine.js',
  'integrations/tickets.js', 'leaderboard.js', 'llm-validator/consistency.js',
  'llm-validator/index.js', 'mcp/audit.js', 'mcp/tools.js',
  'posture/agents-memory.js', 'posture/auditor-walkthrough.js', 'posture/auth-posture-import.js',
  'posture/calibration-drift.js', 'posture/compliance-policy.js', 'posture/corpus-enroll.js',
  'posture/custom-rules.js', 'posture/cve-alert-daemon.js', 'posture/dep-add-guard.js',
  'posture/deterministic.js', 'posture/exploitability-probability.js', 'posture/feature-flags.js',
  'posture/findings-memory.js', 'posture/fix-history.js', 'posture/fix-metrics.js',
  'posture/fix-plan.js', 'posture/grader-calibration.js', 'posture/integrity.js',
  'posture/intent-context.js', 'posture/learning.js', 'posture/license-attributions.js',
  'posture/license-graph.js', 'posture/license-policy.js', 'posture/model-rescan.js',
  'posture/network-policy-import.js', 'posture/pqc-migration-plan.js', 'posture/pr-augment.js',
  'posture/risk-dollars.js', 'posture/router.js', 'posture/rule-overrides.js',
  'posture/rule-pack-signing.js', 'posture/rule-synthesis.js', 'posture/ruleset-version.js',
  'posture/runtime-correlation.js', 'posture/sbom-diff.js', 'posture/sca-policy.js',
  'posture/scan-checkpoint.js', 'posture/streak.js', 'posture/telemetry-ingest.js',
  'posture/threat-model-auto.js', 'posture/threat-model-grounding.js', 'posture/time-to-fix.js',
  'posture/triage-memory.js', 'posture/verifier-target.js', 'posture/waf-ingest.js',
  'posture/watch-mode.js', 'sca/dep-confusion.js',
]);

function offenders() {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules' && e.name !== '.git') walk(p); continue; }
      if (!e.name.endsWith('.js')) continue;
      const rel = path.relative(SRC, p);
      const src = fs.readFileSync(p, 'utf8');
      // A literal '.agentic-security' used to build a path.
      if (/['"`]\.agentic-security['"`/]/.test(src)) out.push(rel);
    }
  };
  walk(SRC);
  return out;
}

test('no NEW module constructs a .agentic-security path outside the seam', () => {
  const found = offenders().filter(f => !ALLOWLIST.has(f));
  assert.deepEqual(found, [],
    'These modules build state paths directly instead of using posture/state-dir.js.\n' +
    'Route the write through stateDir()/statePath()/safeWriteState(), which enforce the\n' +
    'project-root check AND the read-only scan switch. Adding to the ALLOWLIST is not the\n' +
    'fix — that list is a shrinking migration ledger, not a set of exemptions.');
});

test('the allowlist is a shrinking ledger — it never lists a module that is already clean', () => {
  // Stops the ledger rotting into permanent scaffolding: once a module is
  // migrated its entry MUST be removed, or the guard silently stops watching it.
  const current = new Set(offenders());
  const stale = [...ALLOWLIST].filter(f => f !== 'posture/state-dir.js' && !current.has(f));
  assert.deepEqual(stale, [],
    'These allowlist entries no longer violate anything — delete them so the guard covers them again.');
});

test('the guard actually detects a violation (proven, not assumed)', () => {
  // A guard demonstrated only in the passing direction has not been
  // demonstrated. This asserts the detection regex on a constructed sample
  // rather than trusting that a clean tree means it works.
  const sample = `const p = path.join(root, '.agentic-security', 'x.json');`;
  assert.ok(/['"`]\.agentic-security['"`/]/.test(sample), 'the detector must match a direct construction');
  assert.ok(!/['"`]\.agentic-security['"`/]/.test('const p = stateDir(root);'),
    'and must not match a call through the seam');
});
