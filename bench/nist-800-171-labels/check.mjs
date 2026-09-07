#!/usr/bin/env node
// NIST SP 800-171 codeTestable label correctness gate — adversarial premortem
// P0.2 (2026-09-07).
//
// bench/self-scan/check.mjs exists because six false findings shipped on
// this repo's own code and "survived several task reviews before a human
// measured them by hand" (its own header). code-testability.json's 97
// hand-authored ratings shipped through the SAME single-author, no-second-
// review process, with no equivalent gate — this closes that gap for a
// curated anchor set (GOLDEN.json), not a full audit.
//
// This ALSO checks the corresponding mapsTo shape for each anchor where the
// framework file exists, so a mapping regression (like the module:integrity
// self-reference this same premortem pass found and removed from 03.03.08)
// gets caught structurally, not just by luck.
//
// Exit codes: 0 = every anchor matches. 1 = a rating drifted. 2 = the input
// files could not be read — an unrunnable check is a failure, never a skip.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');

function readJson(p, label) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    console.error(`FAIL: could not read ${label} (${p}): ${e.message}`);
    process.exit(2);
  }
}

const golden = readJson(path.join(HERE, 'GOLDEN.json'), 'GOLDEN.json');
const ratingsFile = readJson(
  path.join(REPO, 'scripts', 'nist-800-171', 'code-testability.json'),
  'code-testability.json',
);
const frameworkFile = readJson(
  path.join(REPO, 'scanner', 'src', 'posture', 'compliance-frameworks', 'nist-800-171-r3.json'),
  'nist-800-171-r3.json',
);

const ratings = ratingsFile.ratings || {};
const controlsById = new Map((frameworkFile.controls || []).map((c) => [c.id, c]));

let failures = 0;

for (const anchor of golden.anchors) {
  const rating = ratings[anchor.id];
  if (!rating) {
    console.error(`FAIL  ${anchor.id}: missing from code-testability.json entirely (was: ${anchor.expected})`);
    failures++;
    continue;
  }
  if (rating.code_testable !== anchor.expected) {
    console.error(
      `FAIL  ${anchor.id}: codeTestable is "${rating.code_testable}", golden set expects "${anchor.expected}"\n` +
      `      why the golden set expects this: ${anchor.why}`,
    );
    failures++;
    continue;
  }
  if (!rating.rationale || rating.rationale.trim().length < 40) {
    console.error(`FAIL  ${anchor.id}: rationale is missing or under 40 characters — not a real explanation`);
    failures++;
    continue;
  }
  console.log(`PASS  ${anchor.id}: ${rating.code_testable} (matches golden set)`);
}

// Structural check for the defect class this pass found: a module: mapping
// whose artifact is about THIS TOOL, not the scanned project. P2.8 (2026-09-
// 07) did the second pass over every OTHER module: mapping across all
// bundled frameworks — see `no bundled control maps to a module: artifact
// that evidences this scanner rather than the target` in
// scanner/test/compliance-mapping-liveness.test.js, which is the canonical,
// general-purpose version of this same check and found 9 more instances in 5
// other frameworks. This set is kept here too, scoped to 800-171 specifically,
// as defense-in-depth for this framework's own release gate.
const SELF_REFERENTIAL_MODULES = new Set([
  'integrity',           // last-scan.json.sig is this scanner signing its OWN scan output
  'mcp-audit',           // mcp-audit.log records calls to THIS tool's own MCP server
  'calibration',         // calibration-seed.json is this scanner's OWN ML calibration corpus
  'holdout-eval',        // holdout-eval.jsonl is this scanner's OWN held-out evaluation labels
  'mcp-tools',           // scanner/src/mcp/tools.js resolves only inside this repo
  'security-fixer',      // agents/security-fixer.md resolves only inside this repo
  'pre-edit-bodyguard',  // hooks/pre-edit-bodyguard.js resolves only inside this repo
]);
for (const c of frameworkFile.controls || []) {
  for (const m of c.mapsTo || []) {
    if (!m.startsWith('module:')) continue;
    const mod = m.slice('module:'.length);
    if (SELF_REFERENTIAL_MODULES.has(mod)) {
      console.error(`FAIL  ${c.id}: mapsTo includes module:${mod}, which evidences this SCANNER's own state, not the scanned project`);
      failures++;
    }
  }
}
if (failures === 0) console.log(`PASS  no self-referential module: mappings found (${SELF_REFERENTIAL_MODULES.size} known bad module(s) checked for)`);

console.log();
if (failures > 0) {
  console.error(`✗ ${failures} anchor(s)/check(s) failed — a rating or mapping drifted from a reviewed, unambiguous baseline.`);
  process.exit(1);
}
console.log(`✓ all ${golden.anchors.length} golden anchors hold; no self-referential module: mappings.`);
process.exit(0);
