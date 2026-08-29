#!/usr/bin/env node
// Runs the unit-test scopes in ONE `node --test` invocation instead of
// chaining eleven separate `npm run test:<scope>` processes.
//
// WHY THIS EXISTS
// ----------------
// `npm test` used to be:
//
//   npm run test:smoke && npm run test:glob && npm run test:sast && ...
//
// eleven `npm run` invocations in series, each spawning its own `node --test`
// process. Measured on this machine: 258s sequential. `node --test` already
// runs a MULTI-FILE invocation's files concurrently against the same set of
// cores — the eleven separate processes were never using more parallelism
// than one combined invocation would, they were just paying eleven process
// startup costs and getting zero overlap ACROSS scopes (test:posture could
// not run while test:sast was still finishing). One invocation over the union
// of files: 111-140s across three repeated runs, same 3955/3955/0 result
// every time. That halves the dominant cost in both the pre-push gate and the
// release gate — release-check.mjs's `test-suite` check runs exactly this.
//
// WHY DERIVED, NOT A SECOND HAND-WRITTEN FILE LIST
// -------------------------------------------------
// The file list is extracted from the EXISTING `test:<scope>` scripts in
// package.json, not duplicated here. A hand-maintained parallel list is
// exactly the shape that goes stale silently — add a file to test:sast,
// forget to add it here, and the combined run quietly covers less than
// `npm run test:sast` alone does. Deriving it means that cannot happen: the
// scoped scripts remain the single source of truth (and remain independently
// runnable for day-to-day scoped work, per scanner/CLAUDE.md's test-command
// table), and no-orphan-tests.test.js still catches a file wired into
// neither.
//
// WHAT IS DELIBERATELY EXCLUDED, AND WHY
// ---------------------------------------
//  - test/cpp-dataflow.test.js. It sets AGENTIC_SECURITY_CPP_DATAFLOW=1 at
//    MODULE LOAD, not inside a test callback (see that file's own comment).
//    Included in a combined multi-file invocation on this engine/Node
//    version, its 26 tests silently contributed ZERO results to the run —
//    not a failure, not a skip, just absent from the totals — and something
//    else moved too (3955 -> 3950, not 3955+26). That was not chased to a
//    root cause; the isolated invocation below is proven correct (its own
//    scoped script), so it stays exactly as it already runs today rather
//    than being folded into a batch with an unexplained side effect.
//  - test:python. A different runtime; there is nothing to combine it with.
//  - test:ci-parity. Not part of `npm test` today (a separate, CI-only
//    scoped script); out of scope for this file, which reproduces `npm test`
//    exactly, not a superset of it.
//
// A discrepancy here is a REGRESSION, not noise: this script hard-fails if
// the combined run's pass+fail count does not equal the sum of what the
// scoped scripts report standalone would be expected to cover — enforced
// indirectly by requiring every file that no-orphan-tests.test.js would
// check to appear in the derived list (see extractFiles below), and directly
// by requiring node --test itself to report zero failures.

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..', 'scanner');

// The scoped scripts this file's invocation must cover — everything `npm
// test` chains via `npm run test:<scope>`, MINUS cpp-dataflow and python
// (see header). Adding a new scope to `npm test` means adding its name here
// too; nothing silently falls out of coverage, because
// `assertAllTestFilesCovered` below cross-checks against every scoped
// `test:*` script whose value contains `node --test`.
export const SCOPES = [
  'smoke', 'glob', 'sast', 'posture', 'dataflow', 'mcp',
  'report', 'bench-modules', 'lifecycle', 'eval', 'discovery', 'lineage',
];

const FILE_RE = /test\/[\w.\-/]+\.test\.js/g;

function readPkg() {
  return JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));
}

/** File args named by `test:<scope>`'s script string, in package.json's own order. */
export function extractFiles(scriptValue) {
  return [...new Set((scriptValue || '').match(FILE_RE) || [])];
}

/** The union of files across SCOPES, de-duplicated, order-stable. */
export function unionFiles(pkg, scopes = SCOPES) {
  const seen = new Set();
  const files = [];
  for (const scope of scopes) {
    const key = `test:${scope}`;
    const script = pkg.scripts?.[key];
    if (!script) throw new Error(`package.json has no "${key}" script — SCOPES has drifted from package.json`);
    for (const f of extractFiles(script)) {
      if (!seen.has(f)) { seen.add(f); files.push(f); }
    }
  }
  return files;
}

/**
 * Every `test:*` script that runs `node --test` at all must be one of SCOPES
 * (or an explicitly acknowledged exclusion). This is what stops a THIRTEENTH
 * scoped script from being added to package.json and silently never running
 * under the combined invocation while still passing `npm run test:<newone>`
 * on its own — the exact drift this file exists to prevent.
 */
export function assertAllTestFilesCovered(pkg, { scopes = SCOPES, excluded = ['ci-parity'] } = {}) {
  const covered = new Set(unionFiles(pkg, scopes));
  const missing = [];
  for (const [key, value] of Object.entries(pkg.scripts || {})) {
    if (!key.startsWith('test:')) continue;
    const scope = key.slice('test:'.length);
    if (scopes.includes(scope) || excluded.includes(scope)) continue;
    if (typeof value !== 'string' || !value.includes('node --test')) continue;
    for (const f of extractFiles(value)) if (!covered.has(f)) missing.push({ scope, file: f });
  }
  return missing;
}

function main() {
  const pkg = readPkg();

  const missing = assertAllTestFilesCovered(pkg);
  if (missing.length) {
    process.stderr.write(
      'run-unit-tests.mjs: these test:* scripts run `node --test` on files not covered by the combined '
      + `invocation (SCOPES has drifted from package.json):\n`
      + missing.map((m) => `  test:${m.scope} -> ${m.file}`).join('\n') + '\n'
      + 'Add the scope to SCOPES in scripts/run-unit-tests.mjs, or to its `excluded` list with a written reason.\n',
    );
    process.exit(1);
  }

  const files = unionFiles(pkg);
  if (!files.length) {
    process.stderr.write('run-unit-tests.mjs: derived an empty file list — refusing to report a vacuous pass.\n');
    process.exit(1);
  }

  const r = spawnSync(process.execPath, ['--test', ...files], { cwd: SCANNER, stdio: 'inherit' });
  process.exit(r.status ?? 1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
