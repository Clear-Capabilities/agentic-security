// Maintainer check, NOT part of test:loop or the release closure: the committed section-8 fixtures must still match the real PRD
// documents. Those documents are untracked by convention (this repository is public), so a clean checkout has neither and every test here
// skips with an explicit message; run it where the documents exist: `npm run test:loop-real-prd`.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePrd } from '../lib/prd-import.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const FIXTURES = join(REPO, 'scripts', 'loop-engineering', 'test', 'fixtures');
const shape = (p) => p.requirements.map((r) => ({ id: r.id, weight: r.weight, dependencies: r.dependencies, suite: r.suite, criteria: r.criteria.map((c) => c.id) }));

for (const [name, real, fixture, totals] of [
  ['Differentiation', 'AGENTIC_SECURITY_DIFFERENTIATION_PRD.md', 'assurance-prd-section8.md', { requirements: 70, criteria: 210, weight: 269 }],
  ['Haskell and Nix/NixOS', 'HASKELL_NIXOS_FULL_CAPABILITY_PRD.md', 'haskell-prd-section8.md', { requirements: 57, criteria: 202, weight: 220 }],
]) {
  test(`[real-prd] the committed ${name} fixture matches the real PRD structure`, (t) => {
    const file = join(REPO, real);
    if (!existsSync(file)) { t.skip(`${real} is not present in this checkout (untracked by convention); real-PRD parity NOT checked`); return; }
    const r = parsePrd(readFileSync(file, 'utf8'));
    const f = parsePrd(readFileSync(join(FIXTURES, fixture), 'utf8'));
    assert.deepEqual(r.totals, totals);
    assert.deepEqual(shape(f), shape(r), `the fixture ${fixture} drifted from ${real}; regenerate it`);
  });
}
