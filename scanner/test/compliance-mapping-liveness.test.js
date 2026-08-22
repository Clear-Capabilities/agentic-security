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

// Several detectors emit the family as `<family>-<rule-slug>` — the observed
// vocabulary contains `prompt-injection-http-user-input-in-llm-`,
// `xpath-injection-query-built-via-string-c` and similar. The evaluator looked
// the mapped name up as an exact Map key, so `family:prompt-injection` matched
// none of them.
//
// That silenced LLM01 — Prompt Injection, the first control of the OWASP LLM
// Top 10 — along with ASVS V5.1 and NIST AI 600-1 MG-3.2-005. Each read as
// evidenced no matter what the scan found.
test('a rule-slug-suffixed family satisfies the base family mapping', () => {
  const fw = {
    name: 'test-framework',
    controls: [{ id: 'LLM01', summary: 'prompt injection', mapsTo: ['family:prompt-injection'] }],
  };
  const scan = {
    findings: [{ family: 'prompt-injection-http-user-input-in-llm-', severity: 'critical', file: 'a.js', line: 1 }],
    secrets: [], logicVulns: [], supplyChain: [],
  };
  const [result] = evaluateFramework(HERE, fw, scan);
  assert.notEqual(result.status, 'present', 'an open critical prompt-injection finding must reach this control');
});

test('the suffix match requires a separator, so nosql-injection is not sql-injection', () => {
  // The boundary that keeps prefix resolution honest. `nosql-injection` must
  // never satisfy a `family:sql-injection` mapping — it is a different class,
  // and a substring match would silently merge them.
  const fw = {
    name: 'test-framework',
    controls: [{ id: 'V5.1', summary: 'sql injection', mapsTo: ['family:sql-injection'] }],
  };
  const scan = {
    findings: [{ family: 'nosql-injection', severity: 'critical', file: 'a.js', line: 1 }],
    secrets: [], logicVulns: [], supplyChain: [],
  };
  const [result] = evaluateFramework(HERE, fw, scan);
  assert.equal(result.status, 'present', 'a nosql finding must not be counted against the sql-injection control');
});

test('the compliance spelling `sqli` reaches the sql-injection detectors', () => {
  const fw = {
    name: 'test-framework',
    controls: [{ id: 'V5.1', summary: 'sql injection', mapsTo: ['family:sqli'] }],
  };
  const scan = {
    findings: [{ family: 'sql-injection', severity: 'critical', file: 'a.js', line: 1 }],
    secrets: [], logicVulns: [], supplyChain: [],
  };
  const [result] = evaluateFramework(HERE, fw, scan);
  assert.notEqual(result.status, 'present', 'family:sqli must resolve to the sql-injection family');
});

// PRD F10.3 — never claim a control the scanner cannot evidence.
//
// Two shapes were reaching 'present' without anything meaningful being checked:
// organisational controls (policy, training, governance), and controls whose
// only mappings are `module:` artifact-EXISTENCE checks. "threat-model.json is
// present" is evidence that a file exists, not that threat modelling happened.
//
// Across the bundled frameworks this caps 106 of 163 controls — EU AI Act went
// from 7 controls able to read 'present' to 1. That drop IS the honest picture.
test('an organisational control can never read "present"', () => {
  const fw = { name: 't', controls: [{ id: 'ORG', codeTestable: 'no', mapsTo: ['module:sbom-diff'] }] };
  const [r] = evaluateFramework(HERE, fw, { findings: [], secrets: [], logicVulns: [], supplyChain: [] });
  assert.notEqual(r.status, 'present');
  assert.ok(r.observations.some((o) => /organisational|not code-testable/i.test(o)), 'must say WHY, not just downgrade');
});

test('a control backed only by artifact existence can never read "present"', () => {
  const fw = { name: 't', controls: [{ id: 'ARTI', codeTestable: 'partial', mapsTo: ['module:sbom-diff'] }] };
  const [r] = evaluateFramework(HERE, fw, { findings: [], secrets: [], logicVulns: [], supplyChain: [] });
  assert.notEqual(r.status, 'present');
  assert.ok(r.observations.some((o) => /artifact-existence/i.test(o)));
});

test('a real detector-backed control still reaches "present"', () => {
  // Negative control. The cap must not swallow controls that genuinely check
  // something, or the whole compliance surface becomes uniformly useless.
  const fw = { name: 't', controls: [{ id: 'REAL', codeTestable: 'yes', mapsTo: ['family:sql-injection'] }] };
  const [r] = evaluateFramework(HERE, fw, { findings: [], secrets: [], logicVulns: [], supplyChain: [] });
  assert.equal(r.status, 'present');
});

test('every bundled control declares codeTestable', () => {
  // Anti-rot: a control added without the rating would silently regain the
  // ability to read 'present' on artifact existence alone.
  const missing = [];
  for (const file of fs.readdirSync(FRAMEWORK_DIR).filter((f) => f.endsWith('.json'))) {
    const fw = JSON.parse(fs.readFileSync(path.join(FRAMEWORK_DIR, file), 'utf8'));
    for (const c of fw.controls || []) {
      if (!['yes', 'partial', 'no'].includes(c.codeTestable)) missing.push(`${file}:${c.id}`);
    }
  }
  assert.deepEqual(missing, [], 'controls missing a codeTestable rating');
});
