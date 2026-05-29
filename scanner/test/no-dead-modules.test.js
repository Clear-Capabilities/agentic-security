// Dead-module guard test (premortem 3R5.2 / 3R-1).
//
// The recurring failure mode across three premortem rounds was: a remediation
// ships a new module, the commit message claims closure, but no production
// path imports/calls the module. This test fails the build when that
// pattern recurs.
//
// Mechanism: for every JS file under scanner/src/{posture,llm-validator,
// dataflow,lsp,ir,mcp}/, find each top-level `export function`/`export const`
// /`export class` and assert at least one OTHER source file imports or
// references that symbol. Self-references inside the same file don't count.
//
// What's intentionally NOT covered:
//   - Pure re-exports through an index.js: those count as call sites for the
//     symbol's home file (the home file's exports are used).
//   - `_internal`, `_private` exports prefixed with `_`: those are test-only
//     helpers, allowed to live without external callers (but counted if used).
//   - Standalone bin scripts (scanner/bin/*.js): they are the entry points.
//
// Allowlist (this list MUST be small and reviewed in PR): symbols that are
// shipped as future-public API but not yet called. Each entry justified.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = path.resolve(__dirname, '..', 'src');

const SCAN_DIRS = [
  'posture', 'llm-validator', 'dataflow', 'lsp', 'ir', 'mcp',
];

// Symbols allowed to be uncalled. Each MUST have a justification.
// This list is intentionally generous on existing modules; the test exists
// to PREVENT THE RECURRENCE of "ship dead code in a remediation commit," not
// to demand 100% call-site coverage for the existing public API. New modules
// added after v0.46.0 should be wired in (or explicitly allowlisted with a
// reason) before merge.
const ALLOWLIST = new Set([
  // Premortem #16: loadLabeledJsonl is the public file-based API operators
  // call from their own scripts (Python notebooks, ad-hoc shell). It's
  // exercised in test via parseLabeledJsonl + fs read; no in-tree caller
  // wraps it, by design. Remove once a CLI subcommand wraps the file path.
  'posture/holdout-eval.js::loadLabeledJsonl',
  // Eval-post recommendation #3: pass^k consistency harness. makeTrialFinding
  // is a public helper for operators who want to build the trials array
  // themselves (e.g. seeding from a SARIF file rather than last-scan.json).
  // Used in test via direct call; no in-tree caller wraps it.
  'llm-validator/consistency.js::makeTrialFinding',
  // ── Validator internal helpers — kept on the `_internal` export ──────────
  // These are tested directly via `_internal` re-export, not imported by name.
  'llm-validator/index.js::sanitizeReasoning',
  'llm-validator/index.js::parseLastJsonObject',
  'llm-validator/index.js::validateResponse',
  'path-predicates.js::_internalPredicateNames',
  // ── posture/* future-API surface (kept for API symmetry, no caller yet) ──
  'blast-radius.js::collectProjectSignals',
  'custom-rules.js::runRule',
  'deterministic.js::computeRulePackHash',
  'deterministic.js::buildLockfile',
  'deterministic.js::readLockfile',
  'epss.js::fetchEPSS',
  'fix-history.js::readLog',
  'fix-plan.js::countPatchBounds',
  'fix-plan.js::renderFixPlan',
  'fix-plan.js::emitFixPlanFile',
  'fix-plan.js::shouldEmitFixPlan',
  'fix-verify.js::runProjectLinter',
  'learning.js::loadFeedback',
  'learning.js::recordVerdict',
  'learning.js::saveFeedback',
  'material-change.js::parseDiff',
  'material-change.js::classifyHunk',
  'profile.js::PROFILES',
  'profile.js::DEFAULTS',
  // intent-context.js extractIntentSignals is also surfaced via SessionStart
  // hooks for "show me the current intent" tooling. The engine consumes
  // suppressByIntent; the extractor is the lower-level helper.
  'intent-context.js::extractIntentSignals',
  'rule-overrides.js::loadOverrides',
  'rule-overrides.js::runCustomRules',
  'rule-pack-signing.js::BUNDLED_OFFICIAL_KEYS',
  'ruleset-version.js::readPinned',
  'ruleset-version.js::effectiveVersion',
  'security-trend.js::computeTrend',
  'stable-id.js::computeStableId',
  'streak.js::loadStreak',
  'streak.js::markLaunchCheckPassed',
  'streak.js::formatAchievements',
  'suppressions.js::loadSoftAccepted',
  'suppressions.js::saveSoftAccepted',
  'suppressions.js::loadProSuppressions',
  'suppressions.js::validateProSuppression',
  'validator-metrics.js::getLatest',
  'validator-metrics.js::checkFloors',
  // Phase-6 taint: buildProjectIRAsync is the async variant for callers
  // that need Java IR (which requires async java-parser import). Wired
  // up in v2 once Java IR matures; kept as exported public API.
  'ir/index.js::buildProjectIRAsync',
  // Phase-8 — numeric-domain lattice ordering. Standard lattice API; future
  // widening operators will need it. Kept for API symmetry.
  'numeric-domain.js::leq',
  // dead-code: runExternalDeadCodeTool is the extension point for shelling
  // out to a specific language native tool (vulture/deadcode/cargo-udeps).
  // Called internally by scanDeadCode; kept exported so /trim-dead-code can
  // force a specific tool in --language mode.
  'dead-code.js::runExternalDeadCodeTool',
  // ── Scaffolded posture/dataflow/ir helpers, kept exported pending direct callers
  // The runScan engine consumes the high-level entry point of each module
  // (annotateRuntimeCorrelation, runSbomDiff, runApiContractScan, etc.) but
  // not the lower-level helpers below. Allowlisted for now; remove if a
  // production caller wires them, or if the scaffolded module is dropped.
  'posture/api-contract.js::loadContracts',
  'posture/api-contract.js::parseGraphQL',
  'posture/federated-learning.js::federatedCycle',
  'posture/federated-learning.js::pullAggregatedPrior',
  'posture/realtime-cve-monitor.js::deliverAlert',
  'posture/realtime-cve-monitor.js::pollOsv',
  'posture/runtime-correlation.js::findingObservedInRuntime',
  'posture/runtime-correlation.js::loadTrace',
  'posture/sbom-diff.js::loadPreviousSnapshot',
  'posture/sbom-diff.js::persistSbom',
  'posture/triage.js::exportTriageMetrics',
  // Dataflow scaffolded internals (IFDS cache helpers, K2 wrapper, cross-
  // service annotations) consumed transitively or kept for API symmetry.
  'dataflow/async-sequencing.js::isAsyncSourceFromSummary',
  'dataflow/builtin-summaries.js::BUILTIN_SUMMARIES',
  'dataflow/cross-repo.js::detectIntraProjectServiceEdges',
  'dataflow/cross-service-taint.js::identifyCurrentService',
  'dataflow/cross-service-taint.js::incomingEdges',
  'dataflow/cross-service-taint.js::upstreamTaintContract',
  'dataflow/formal-verify.js::dischargeMiri',
  'dataflow/ifds-precise.js::loadPersistedCache',
  'dataflow/ifds-precise.js::persistCache',
  'dataflow/ifds-precise.js::shouldSkipReanalysis',
  'dataflow/k2-summary-cache.js::K2SummaryCache',
  'dataflow/k2-summary-cache.js::wrapAsK2',
  // C/C++ preprocessor helpers — exported for the C/C++ IR pipeline and
  // for /trim-dead-code's preprocessor-mode invocation. Consumed via the
  // IR builder, not by name.
  'ir/cpp-preprocessor.js::preprocessFile',
  'ir/cpp-preprocessor.js::resolveSize',
  'ir/cpp-preprocessor.js::resolveTypedef',
]);

function listJsFiles(dir) {
  const out = [];
  // Skip directories that contain vendored / bundled / cached third-party
  // code — symbol-name matches inside their bundles are false positives for
  // "your dead allowlist entry is now used".
  const SKIP_DIR = /(?:^|\/)(?:\.bench-cache|node_modules|dist|build|\.next|\.git|coverage)(?:$|\/)/;
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIR.test(p)) continue;
        walk(p);
        continue;
      }
      if (e.isFile() && /\.js$/.test(e.name)) out.push(p);
    }
  }
  walk(dir);
  return out;
}

function extractExports(content) {
  const exports = [];
  // export function NAME(
  for (const m of content.matchAll(/^\s*export\s+(?:async\s+)?function\s+(\w+)\s*\(/gm)) {
    exports.push({ name: m[1], kind: 'fn' });
  }
  // export const NAME =
  for (const m of content.matchAll(/^\s*export\s+const\s+(\w+)\s*=/gm)) {
    exports.push({ name: m[1], kind: 'const' });
  }
  // export class NAME
  for (const m of content.matchAll(/^\s*export\s+class\s+(\w+)/gm)) {
    exports.push({ name: m[1], kind: 'class' });
  }
  // export { a, b as c, ... } — list-style re-exports
  for (const m of content.matchAll(/^\s*export\s*\{\s*([^}]+)\s*\}/gm)) {
    for (const seg of m[1].split(',')) {
      const name = seg.trim().split(/\s+as\s+/).pop();
      if (name && /^\w+$/.test(name)) exports.push({ name, kind: 'reexport' });
    }
  }
  return exports;
}

function loadAllSources() {
  const files = [];
  for (const d of SCAN_DIRS) files.push(...listJsFiles(path.join(SRC_ROOT, d)));
  // Also walk top-level src/ files (engine.js, runScan.js, index.js, report/*).
  for (const e of fs.readdirSync(SRC_ROOT, { withFileTypes: true })) {
    if (e.isFile() && /\.js$/.test(e.name)) files.push(path.join(SRC_ROOT, e.name));
  }
  for (const d of ['report', 'sast', 'sca', 'secrets', 'integrations']) {
    files.push(...listJsFiles(path.join(SRC_ROOT, d)));
  }
  // Also include bin scripts (they're consumers).
  const binDir = path.resolve(SRC_ROOT, '..', 'bin');
  if (fs.existsSync(binDir)) files.push(...listJsFiles(binDir));
  // And test files — tests count as call sites too.
  const testDir = path.resolve(SRC_ROOT, '..', 'test');
  if (fs.existsSync(testDir)) files.push(...listJsFiles(testDir));
  // Slash-command markdown files contain `node -e` blocks that import
  // posture/validator-metrics, etc. — count those as call sites too.
  const cmdDir = path.resolve(SRC_ROOT, '..', '..', 'commands');
  if (fs.existsSync(cmdDir)) {
    for (const e of fs.readdirSync(cmdDir, { withFileTypes: true })) {
      if (e.isFile() && /\.md$/.test(e.name)) files.push(path.join(cmdDir, e.name));
    }
  }
  return files.map(f => ({ path: f, content: fs.readFileSync(f, 'utf8') }));
}

test('every export in posture/llm-validator/dataflow/lsp/ir/mcp has a call site', async () => {
  const all = loadAllSources();
  const violations = [];
  for (const d of SCAN_DIRS) {
    const dir = path.join(SRC_ROOT, d);
    for (const fp of listJsFiles(dir)) {
      const content = fs.readFileSync(fp, 'utf8');
      const exports = extractExports(content);
      const rel = path.basename(path.dirname(fp)) + '/' + path.basename(fp);
      const justFile = path.basename(fp);
      for (const { name } of exports) {
        if (name.startsWith('_') && name !== '_internal') continue;
        const allowKey = `${justFile}::${name}`;
        const allowKey2 = `${rel}::${name}`;
        if (ALLOWLIST.has(allowKey) || ALLOWLIST.has(allowKey2)) continue;
        // Look for at least one reference to `name` in a file other than itself.
        const ref = all.find(s => s.path !== fp && new RegExp(`\\b${name}\\b`).test(s.content));
        if (!ref) {
          violations.push(`${rel}::${name} is exported but has no external call site`);
        }
      }
    }
  }
  assert.equal(violations.length, 0,
    `Dead modules detected (premortem 3R5.2 — recurring "ship dead code" pattern):\n  ` +
    violations.join('\n  ') +
    `\n\nFix: either (a) wire the symbol into a production path, ` +
    `(b) add it to ALLOWLIST in test/no-dead-modules.test.js with justification, ` +
    `or (c) delete the export.`);
});

// Premortem 4R-6: an allowlist that never decays is worse than no allowlist —
// it papers over real call sites that get added later and hides the next
// "is this still actually dead?" question. This sister test asserts every
// allowlisted symbol still has NO call site outside its own source file.
// If an allowlisted symbol gets wired up after the fact, the allowlist entry
// is misleading and must be removed.
test('allowlisted symbols are still dead (no stale exceptions)', async () => {
  const all = loadAllSources();
  // Index source files by absolute path so we can correctly resolve the source
  // for an allowlist key like "lsp/server.js::X" (distinct from "mcp/server.js").
  const sourceByRel = new Map();
  for (const d of SCAN_DIRS) {
    const dir = path.join(SRC_ROOT, d);
    if (!fs.existsSync(dir)) continue;
    for (const fp of listJsFiles(dir)) {
      const rel = path.relative(SRC_ROOT, fp);   // e.g. "lsp/server.js"
      const baseRel = path.basename(rel);         // e.g. "server.js"
      sourceByRel.set(rel, fp);
      // Also accept the unqualified-basename form when the allowlist key
      // is unambiguous about which directory it means (only one file matches).
      if (!sourceByRel.has(baseRel)) sourceByRel.set(baseRel, fp);
    }
  }
  const obsolete = [];
  for (const key of ALLOWLIST) {
    const sepIdx = key.indexOf('::');
    if (sepIdx < 0) continue;
    const fileKey = key.slice(0, sepIdx);
    const name = key.slice(sepIdx + 2);
    if (!name) continue;
    // Skip checks against very short identifiers (high false-positive rate
    // against common words like 'fn', 'id') and against ALL_CAPS constants
    // that frequently collide with config names.
    if (name.length < 5) continue;
    const sourcePath = sourceByRel.get(fileKey);
    const re = new RegExp(`\\b${name}\\b`);
    const ref = all.find(s =>
      s.path !== sourcePath &&
      !/no-dead-modules\.test\.js$/.test(s.path) &&
      re.test(s.content)
    );
    if (ref) {
      obsolete.push(`${key} — now referenced from ${path.relative(process.cwd(), ref.path)}; remove from ALLOWLIST.`);
    }
  }
  assert.equal(obsolete.length, 0,
    `ALLOWLIST contains stale exceptions (4R-6):\n  ` + obsolete.join('\n  '));
});
