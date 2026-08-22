// Gate for the producer registry (PRD F10.2).
//
// The registry only means something if it is kept true. Three properties, each
// guarding a different way it can rot:
//
//   1. SOUNDNESS   — a declared family is one the module can really emit, not a
//                    name someone typed. Checked against observed evidence.
//   2. COMPLETENESS — a registered module never emits a family it did not
//                    declare. This is the drift check.
//   3. RATCHET     — the unregistered remainder must not grow. 287 modules
//                    exist; a gate that demanded all of them on day one would be
//                    disabled by week two.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  REGISTERED, PARSER_OF, declaredFamilies, producersOf, moduleForParser, undeclaredFrom,
} from '../src/posture/family-registry.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OBSERVED = JSON.parse(
  fs.readFileSync(path.join(HERE, '..', '..', 'bench', 'family-producers', 'OBSERVED.json'), 'utf8'),
).families;

test('every registered module declares at least one family', () => {
  const empty = Object.entries(REGISTERED).filter(([, list]) => !Array.isArray(list) || list.length === 0);
  assert.deepEqual(empty.map(([m]) => m), [], 'registered modules declaring nothing');
});

test('declarations are unique within a module and well-formed', () => {
  for (const [mod, list] of Object.entries(REGISTERED)) {
    const dupes = list.filter((f, i) => list.indexOf(f) !== i);
    assert.deepEqual(dupes, [], `${mod} declares duplicates`);
    const malformed = list.filter((f) => typeof f !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(f));
    assert.deepEqual(malformed, [], `${mod} declares malformed family names`);
  }
});

test('every registered module has a module-specific parser', () => {
  // Completeness is enforced by attributing a finding back to its module via
  // `parser`. A module whose parser is a shared label (REGEX covers 80 families,
  // STRUCTURAL 23) cannot be attributed, so registering it would create a rule
  // that silently never fires.
  const missing = Object.keys(REGISTERED).filter((m) => !PARSER_OF[m]);
  assert.deepEqual(missing, [], 'registered without a parser mapping — completeness would not be checkable');
});

test('a declared family that was OBSERVED is attributed to its declaring module', () => {
  // Soundness. Observation is a lower bound, so a family absent from the sweep
  // proves nothing and is skipped. But where a family WAS observed, the parser
  // that produced it must be the one its declaring module stamps — otherwise the
  // declaration names someone else's family.
  const wrong = [];
  for (const [mod, list] of Object.entries(REGISTERED)) {
    for (const fam of list) {
      const seen = OBSERVED[fam];
      if (!seen) continue;                       // never triggered; lower bound
      const parsers = Object.keys(seen.parsers || {});
      if (!parsers.includes(PARSER_OF[mod])) {
        wrong.push(`${mod} declares ${fam}, but it was observed from ${parsers.join('/') || '(no parser recorded)'}`);
      }
    }
  }
  assert.deepEqual(wrong, [], 'declarations contradicted by observed evidence');
});

test('a registered module emitting an undeclared family is caught', () => {
  // Completeness, proven in the failing direction with a synthetic finding —
  // the real corpus is (correctly) clean, which would make this vacuous.
  const clean = undeclaredFrom([
    { family: 'crypto-ecb', parser: 'CRYPTO-PROTO' },
    { family: 'aws-no-mfa', parser: 'CLOUD-IAM' },
  ]);
  assert.equal(clean.size, 0, 'declared families must not be reported as drift');

  const drifted = undeclaredFrom([{ family: 'crypto-brand-new-rule', parser: 'CRYPTO-PROTO' }]);
  assert.equal(drifted.size, 1, 'an undeclared family from a registered module must be caught');
  assert.deepEqual([...drifted.get('sast/crypto-protocol.js')], ['crypto-brand-new-rule']);
});

test('a finding from a NON-module-specific parser is not falsely attributed', () => {
  // REGEX covers 80 families across many modules. Attributing one of them to a
  // registered module would produce a confident, wrong answer — worse than none.
  assert.equal(moduleForParser('REGEX'), null);
  assert.equal(moduleForParser('STRUCTURAL'), null);
  assert.equal(undeclaredFrom([{ family: 'whatever', parser: 'REGEX' }]).size, 0);
});

test('producersOf answers for a declared family and is empty for an unknown one', () => {
  assert.deepEqual(producersOf('crypto-tls-version'), ['sast/crypto-protocol.js']);
  assert.deepEqual(producersOf('no-such-family-anywhere'), []);
});

test('the unregistered remainder does not grow (ratchet)', () => {
  // Every observed family not yet claimed by a registered module. This number
  // must fall as modules are registered, never rise. A NEW family from an
  // UNREGISTERED module is allowed through — that module has made no promise
  // yet — but the total is pinned so the backlog cannot quietly expand.
  const declared = declaredFamilies();
  const remainder = Object.keys(OBSERVED).filter((f) => !declared.has(f));

  // MEASURED, not estimated. 213 families observed; 6 modules declare 57, of
  // which 38 appear in the sweep (the other 19 are real but no fixture triggers
  // them — declaration is not bounded by observation, which is the point).
  // 213 - 38 = 175. A first guess of 158 was wrong here and the gate caught it;
  // a ratchet pinned to an estimate rather than a measurement is just a wish.
  const BASELINE = 175;
  assert.ok(
    remainder.length <= BASELINE,
    `undeclared families rose to ${remainder.length} (baseline ${BASELINE}). `
    + 'Register the module that emits the new family, or lower the baseline if this is expected.',
  );
});
