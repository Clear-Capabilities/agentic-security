// PRD F5.5 — AI-BOM validates against CycloneDX ML-BOM, or is labelled proprietary.
//
// The AI-BOM carried `cyclonedxCompatible: '1.7-ml-bom'` and nothing checked it.
// The document has no `bomFormat`, no `specVersion` and no CycloneDX
// `components` array, so a consumer who trusted that field and fed it to a
// CycloneDX tool would have got a parse error, not a BOM. An unverified
// conformance claim on a supply-chain artifact is worse than no claim: it is
// the kind a procurement checklist accepts.
//
// Both halves of F5.5 are now taken — the proprietary document says it is
// proprietary, and a REAL ML-BOM view exists and is mechanically checked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAIBOM, toCycloneDXMLBOM, validateMLBOM } from '../src/posture/aibom.js';

const scanWith = (models) => ({
  components: [],
  findings: models.map((m, i) => ({ family: 'llm-app-security', file: `m${i}.js`, line: 1, vuln: 'model reference' })),
});

test('the proprietary AI-BOM no longer claims CycloneDX compatibility', () => {
  const ai = buildAIBOM(scanWith([]), {}, {});
  assert.equal(ai.proprietary, true, 'the proprietary document must say so');
  assert.equal(ai.cyclonedxCompatible, undefined, 'the unverified compatibility claim must be gone');
  assert.match(String(ai.cyclonedxMlBom), /toCycloneDXMLBOM/, 'it must point at the real ML-BOM view');
});

test('the ML-BOM view is a structurally valid CycloneDX document', () => {
  const doc = toCycloneDXMLBOM(buildAIBOM(scanWith([]), {}, {}), { engineVersion: 'test' });
  const v = validateMLBOM(doc);
  assert.equal(v.ok, true, `ML-BOM failed validation: ${v.errors.join('; ')}`);
  assert.equal(doc.bomFormat, 'CycloneDX');
  assert.match(doc.specVersion, /^1\.[4-9]$/);
});

test('the validator states that it is STRUCTURAL, not full schema validation', () => {
  // The claim this item removed was an unqualified one. Replacing it with a
  // different unqualified claim would repeat the mistake — so the validator
  // reports the strength of the check it actually performed.
  const v = validateMLBOM(toCycloneDXMLBOM(buildAIBOM(scanWith([]), {}, {}), {}));
  assert.match(v.checked, /NOT full JSON-Schema/);
});

test('the validator REJECTS a document that is not CycloneDX', () => {
  // Without this, a validator that returned ok for everything would satisfy the
  // test above and the conformance claim would be exactly as empty as before.
  const bad = validateMLBOM({ aibomFormat: 'agentic-security AI-BOM', version: '1' });
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.some((e) => /bomFormat/.test(e)), 'it must name the missing bomFormat');
});

test('the validator rejects a model component with no modelCard', () => {
  // The modelCard IS the ML-BOM extension. A machine-learning-model component
  // without one is a plain component wearing the type name.
  const doc = toCycloneDXMLBOM(buildAIBOM(scanWith([]), {}, {}), {});
  doc.components = [{ type: 'machine-learning-model', name: 'gpt-4o', 'bom-ref': 'model:x' }];
  const v = validateMLBOM(doc);
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => /modelCard/.test(e)));
});

test('the validator rejects a malformed serial number', () => {
  const doc = toCycloneDXMLBOM(buildAIBOM(scanWith([]), {}, {}), {});
  doc.serialNumber = 'not-a-urn';
  assert.equal(validateMLBOM(doc).ok, false);
});

test('the ML-BOM serial is deterministic under --deterministic', () => {
  // Same reasoning as toCycloneDX's serialNumber: an attestation over a BOM is
  // meaningless if the BOM changes every run.
  const prev = process.env.AGENTIC_SECURITY_DETERMINISTIC;
  process.env.AGENTIC_SECURITY_DETERMINISTIC = '1';
  try {
    const ai = buildAIBOM(scanWith([]), {}, {});
    const a = toCycloneDXMLBOM(ai, {});
    const b = toCycloneDXMLBOM(ai, {});
    assert.equal(a.serialNumber, b.serialNumber);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_DETERMINISTIC;
    else process.env.AGENTIC_SECURITY_DETERMINISTIC = prev;
  }
});

test('a null or non-object document is rejected rather than throwing', () => {
  for (const bad of [null, undefined, 'string', 42]) {
    assert.equal(validateMLBOM(bad).ok, false, `${String(bad)} must be rejected`);
  }
});
