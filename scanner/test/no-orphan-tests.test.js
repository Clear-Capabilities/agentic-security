// Orphan-test guard.
//
// Found live while wiring CMP-5's tests: test/world-class-batch2.test.js and
// test/world-class-modules.test.js (48 tests total, covering LLM-app
// security, mobile security, threat-model-auto, compliance-policy,
// sbom-diff, privacy-taint, and more) were never referenced by any npm
// script — `npm test` never ran them, so they provided zero regression
// protection despite passing cleanly on their own. no-dead-modules.test.js
// checks exported SYMBOLS; no-orphan-scripts.test.js checks scripts/ and
// bench/ tools. Neither one walks test/*.test.js itself, so a test file that
// nobody wired into package.json was invisible to both, the same shape gap
// no-orphan-scripts.test.js closed for scripts/.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER_ROOT = path.resolve(HERE, '..');

// Each entry needs a reason, same contract as no-dead-modules.js's ALLOWLIST.
const ALLOWLIST = new Set([
  // none yet — keep it that way
]);

test('every test/*.test.js file is referenced by some script in package.json', () => {
  const pkg = fs.readFileSync(path.join(SCANNER_ROOT, 'package.json'), 'utf8');
  const testFiles = fs.readdirSync(path.join(SCANNER_ROOT, 'test'))
    .filter((f) => f.endsWith('.test.js'));
  assert.ok(testFiles.length > 100, 'sanity check: expected hundreds of test files, something is wrong with the scan');

  const orphans = testFiles.filter((f) => !ALLOWLIST.has(f) && !pkg.includes(`test/${f}`));
  assert.deepEqual(orphans, [],
    `these test files exist but are not referenced by any npm script, so npm test never runs them: ${orphans.join(', ')}. ` +
    'Add each to the appropriate test:<scope> script in package.json, or add to ALLOWLIST with a written reason.');
});
