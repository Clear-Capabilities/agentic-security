// A compliance control mapped to a family NO detector can ever emit is worse
// than an unmapped one: the family bucket is always empty, so the evaluator
// pushes "✓ no open critical/high findings" and the control reads as evidenced.
// An auditor sees a pass that nothing ever checked.
//
// `COMPLIANCE_FAMILY_ALIAS` already fixes the cases where the compliance
// spelling and the detector spelling differ. What had no mechanism was the
// other case: a mapping with no detector behind it *at all*.
//
// A source comment claimed four families were in that state. Measurement said
// otherwise — all four have producers — so the gap registry is currently EMPTY
// and these tests guard the mechanism rather than a list. The rules cut both
// ways on purpose: a control with no possible evidence must never read
// 'present', AND a family that has a producer must never be declared a gap,
// because that silently caps a control that works.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  evaluateFramework,
  COMPLIANCE_FAMILY_GAPS,
  COMPLIANCE_FAMILY_ALIAS,
} from '../src/posture/auditor-walkthrough.js';


const HERE = path.dirname(fileURLToPath(import.meta.url));
const FRAMEWORK_DIR = path.join(HERE, '..', 'src', 'posture', 'compliance-frameworks');

// Families a real scan was OBSERVED to emit. A lower bound, so it can prove a
// family HAS a producer but never that it lacks one — which is exactly the
// asymmetry the gap rules below rely on.
const OBSERVED = JSON.parse(
  fs.readFileSync(path.join(HERE, '..', '..', 'bench', 'family-producers', 'OBSERVED.json'), 'utf8'),
).families;


function mappedFamilies() {
  const out = new Map(); // family -> [{framework, control}]
  for (const file of fs.readdirSync(FRAMEWORK_DIR).filter((f) => f.endsWith('.json'))) {
    const fw = JSON.parse(fs.readFileSync(path.join(FRAMEWORK_DIR, file), 'utf8'));
    for (const c of fw.controls || []) {
      for (const m of c.mapsTo || []) {
        if (!m.startsWith('family:')) continue;
        const fam = m.slice('family:'.length).split(':')[0];
        if (!out.has(fam)) out.set(fam, []);
        out.get(fam).push({ framework: file, control: c.id });
      }
    }
  }
  return out;
}

test('every declared gap carries a non-empty reason', () => {
  // A gap with no stated reason is indistinguishable from a typo somebody
  // silenced by adding it to the list.
  const unreasoned = Object.entries(COMPLIANCE_FAMILY_GAPS)
    .filter(([, reason]) => typeof reason !== 'string' || reason.trim().length < 20)
    .map(([fam]) => fam);
  assert.deepEqual(unreasoned, [], 'gaps needing a real reason');
});

test('a family is never both aliased and declared a gap', () => {
  // An alias means "a detector exists under another name" — the opposite of a
  // gap. Being in both means one of the two is wrong.
  const both = Object.keys(COMPLIANCE_FAMILY_GAPS).filter((f) => COMPLIANCE_FAMILY_ALIAS[f]);
  assert.deepEqual(both, [], 'families both aliased and declared missing');
});

test('every declared gap is actually referenced by some framework', () => {
  // Anti-rot: a gap for a family nothing maps to is dead weight, and it hides
  // whether the list is still describing reality.
  const mapped = mappedFamilies();
  const orphaned = Object.keys(COMPLIANCE_FAMILY_GAPS).filter((f) => !mapped.has(f));
  assert.deepEqual(orphaned, [], 'gap entries no framework references — delete them');
});

test('a declared gap must not name a family that has a producer', () => {
  // The check that would have caught the mistake this file was first committed
  // with: four families were declared gaps on the strength of a source comment,
  // and every one of them turned out to be emitted by a real detector. A gap
  // for a live family silently caps a control that actually works.
  COMPLIANCE_FAMILY_GAPS['nosql-injection'] = 'temporarily declared to prove this check bites';
  const wouldCatch = Object.keys(COMPLIANCE_FAMILY_GAPS).filter((f) => OBSERVED[f] != null);
  delete COMPLIANCE_FAMILY_GAPS['nosql-injection'];
  assert.deepEqual(wouldCatch, ['nosql-injection'], 'the check itself must detect a live family');

  const live = Object.keys(COMPLIANCE_FAMILY_GAPS).filter((f) => OBSERVED[f] != null);
  assert.deepEqual(
    live,
    [],
    'declared as unevidenceable but observed in a real scan — these are not gaps',
  );
});

test('an unevidenceable family caps its control below "present"', () => {
  // COMPLIANCE_FAMILY_GAPS is currently empty, and an empty registry would make
  // this assertion vacuous — so the MECHANISM is exercised with a synthetic
  // family injected for the duration of the test. The hazard being guarded is
  // structural (an empty family bucket rendering as a clean check), not tied to
  // whichever names happen to be listed today.
  const SYNTHETIC = '__test-family-no-detector-emits__';
  COMPLIANCE_FAMILY_GAPS[SYNTHETIC] = 'injected by the test suite to exercise the disclosure path.';
  try {
    const fw = {
      name: 'test-framework',
      controls: [{ id: 'T1', summary: 'mapped only to a family nothing emits', mapsTo: [`family:${SYNTHETIC}`] }],
    };
    const [result] = evaluateFramework(HERE, fw, { findings: [], secrets: [], logicVulns: [], supplyChain: [] });

    assert.notEqual(result.status, 'present', 'a control with no possible evidence must not read as evidenced');
    assert.ok(
      result.observations.some((o) => /no detector|cannot evidence|engine-gap/i.test(o)),
      `observations must disclose the gap, got ${JSON.stringify(result.observations)}`,
    );
  } finally {
    delete COMPLIANCE_FAMILY_GAPS[SYNTHETIC];
  }
});

test('a control on a real family with a clean scan still reads "present"', () => {
  // Negative control: the fix must not make everything unevidenceable. A
  // family a detector really does emit, with nothing open, is a genuine pass
  // and must keep reading as one.
  const fw = {
    name: 'test-framework',
    controls: [{ id: 'T2', summary: 'mapped to a real family', mapsTo: ['family:sql-injection'] }],
  };
  const [result] = evaluateFramework(HERE, fw, { findings: [], secrets: [], logicVulns: [], supplyChain: [] });
  assert.equal(result.status, 'present');
});

test('a control on a real family with an open critical finding does not read "present"', () => {
  // The other direction of the same control: the evaluator still reacts to
  // real findings.
  const fw = {
    name: 'test-framework',
    controls: [{ id: 'T3', summary: 'mapped to a real family', mapsTo: ['family:sql-injection'] }],
  };
  const scan = {
    findings: [{ family: 'sql-injection', severity: 'critical', file: 'a.js', line: 1 }],
    secrets: [], logicVulns: [], supplyChain: [],
  };
  const [result] = evaluateFramework(HERE, fw, scan);
  assert.notEqual(result.status, 'present');
});
