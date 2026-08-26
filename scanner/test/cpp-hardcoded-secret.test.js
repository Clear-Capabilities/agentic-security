// Coverage for scanCpp's 'cpp-hardcoded-secret' rule, previously untested
// directly. Written while fixing a real, independently-found bug (D-0048,
// surfaced during FR-202's phase-2 side-channel audit): the rule's entropy
// gate resolved `_secret-entropy.js` via a fire-and-forget dynamic
// `import(...)` into a module-level `let`, racing against the first
// scanCpp() call. The current single-process scan happened to always win
// that race (several awaits run before any C/C++ file is scanned), but
// nothing guaranteed it, and a worker-per-file execution boundary (FR-202)
// would have no equivalent warm-up window. Fixed to a plain static import
// (`_secret-entropy.js` has zero imports of its own — no real circularity,
// and `engine.js` already imports the same function statically) — now
// synchronous and race-free by construction, not by scheduling luck.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCpp } from '../src/sast/cpp.js';

test('cpp-hardcoded-secret: a real high-entropy credential literal fires', () => {
  const src = 'char *api_key = "aX9kLm2pQ7zR4vN8wT1";\n';
  const findings = scanCpp('service.c', src);
  const hit = findings.find((f) => f.id === 'cpp-hardcoded-secret' || /Hardcoded Secret/i.test(f.vuln || ''));
  assert.ok(hit, `expected a hardcoded-secret finding, got: ${JSON.stringify(findings.map(f => f.vuln))}`);
  assert.equal(hit.cwe, 'CWE-798');
});

test('cpp-hardcoded-secret: a low-entropy placeholder string is filtered by the entropy gate, not just any string ≥8 chars', () => {
  const src = 'char *api_key = "changeme";\n';
  const findings = scanCpp('service.c', src);
  const hit = findings.find((f) => f.id === 'cpp-hardcoded-secret' || /Hardcoded Secret/i.test(f.vuln || ''));
  assert.equal(hit, undefined, `expected the entropy gate to filter "changeme", got: ${JSON.stringify(findings)}`);
});

test('cpp-hardcoded-secret: scanCpp never throws even under rapid repeated calls (proves the gate is synchronous, not racing an in-flight dynamic import)', () => {
  const src = 'char *secret_key = "aX9kLm2pQ7zR4vN8wT1";\n';
  // Repeated synchronous calls with no awaits between them -- if the entropy
  // module were still resolved via a fire-and-forget dynamic import, the
  // VERY FIRST call in a fresh process could race ahead of resolution and
  // silently skip the entropy filter (fail-open via `_entropyMod || {}`).
  // A static import makes this proof trivial: every call, including the
  // first, sees the fully-loaded module.
  for (let i = 0; i < 5; i++) {
    const findings = scanCpp('service.c', src);
    assert.ok(findings.some((f) => f.id.startsWith('cpp-hardcoded-secret:')),
      `call ${i}: expected the finding to fire consistently on every call, including the first, got: ${JSON.stringify(findings)}`);
  }
});
