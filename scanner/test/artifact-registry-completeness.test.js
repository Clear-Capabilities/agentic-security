// Artifact registry completeness guard (assurance-hardening PRD, FR-701).
//
// Same spirit as no-dead-modules.test.js / no-stray-state.test.js: a registry
// nobody is forced to keep current is a snapshot, not a control. This scans
// every `statePath(root, 'literal', ...)` and `path.join(stateDir(root),
// 'literal')` call site under src/ and bin/ and asserts the FIRST literal
// segment (the actual top-level entry under `.agentic-security/`) is
// registered in artifact-registry.js as either 'generated' or
// 'operator-config'. A new state artifact added later without updating the
// registry fails this test — the exact drift that let cmdReset's old
// hardcoded WIPE list fall behind reality (A-10).
//
// This does NOT catch state paths built by string concatenation or template
// literals instead of statePath()/stateDir() — that class of bypass is
// test/no-stray-state.test.js's job (the write-seam guard), a different and
// already-covered concern.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isRegisteredArtifact } from '../src/posture/artifact-registry.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const ROOTS = ['src', 'bin'].map(d => path.join(SCANNER, d));

// The registry itself (naming its own artifacts in string form for
// documentation) and its completeness test are not "a caller" in the sense
// this guard checks.
const EXEMPT_FILES = new Set([
  'src/posture/artifact-registry.js',
  'src/posture/state-dir.js', // defines statePath/stateDir; doesn't call them with a literal artifact name
]);

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

// Matches statePath(<anything not containing a comma at paren-depth-0>, 'literal'
// and path.join(stateDir(<...>), 'literal' — capturing the first literal
// argument after the root, which is the top-level artifact name.
const PATTERNS = [
  /\bstatePath\(\s*[^,()]*(?:\([^()]*\))?[^,()]*,\s*['"]([^'"]+)['"]/g,
  /\bpath\.join\(\s*stateDir\([^)]*\)\s*,\s*['"]([^'"]+)['"]/g,
];

// A code comment can mention `statePath(scanRoot, 'literal')` as prose (e.g.
// auditor-walkthrough.js documents a hypothetical bad call as
// `statePath(scanRoot, '.../x')`) without it being a real call site. Strip
// comments first so the guard doesn't chase examples inside documentation.
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
}

function findLiterals(file) {
  const src = stripComments(fs.readFileSync(file, 'utf8'));
  const out = [];
  for (const re of PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(src))) out.push(m[1]);
  }
  return out;
}

test('every top-level statePath()/stateDir()-joined literal is registered in artifact-registry.js', () => {
  const missing = [];
  for (const root of ROOTS) {
    for (const file of walk(root)) {
      const rel = path.relative(SCANNER, file).replace(/\\/g, '/');
      if (EXEMPT_FILES.has(rel)) continue;
      for (const literal of findLiterals(file)) {
        if (!isRegisteredArtifact(literal)) {
          missing.push(`${rel}: '${literal}'`);
        }
      }
    }
  }
  assert.deepEqual(missing, [],
    `state artifact(s) referenced by statePath()/stateDir() but not registered in artifact-registry.js:\n${missing.join('\n')}`);
});

test('the completeness guard itself finds a non-trivial number of registered literals (sanity — proves the regex is not silently matching nothing)', () => {
  let found = 0;
  for (const root of ROOTS) {
    for (const file of walk(root)) {
      const rel = path.relative(SCANNER, file).replace(/\\/g, '/');
      if (EXEMPT_FILES.has(rel)) continue;
      found += findLiterals(file).length;
    }
  }
  assert.ok(found > 20, `expected the scan to find more than 20 statePath() literal call sites, found ${found} — the regex may have stopped matching`);
});
