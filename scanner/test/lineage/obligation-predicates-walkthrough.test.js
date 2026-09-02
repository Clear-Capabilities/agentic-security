import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadFramework, evaluateFramework } from '../../src/posture/auditor-walkthrough.js';
import { validateObligationMapping } from '../../src/lineage/obligation-mapping.js';

function _minimalGraph({ transitVerdict }) {
  return {
    graphId: 'dfg:test-repo:abc123:default',
    nodes: [
      { id: 'node:src1', kind: 'api' },
      { id: 'node:sink1', kind: 'external' },
    ],
    edges: [
      {
        id: 'edge:e1',
        from: 'node:src1', to: 'node:sink1',
        protection: { transit: { verdict: transitVerdict, evidenceGrade: 'code' }, atRest: { verdict: 'not_assessed', evidenceGrade: 'none' }, handling: { verdict: 'not_assessed', evidenceGrade: 'none' } },
        evidenceRefs: [],
      },
    ],
    dataElements: [
      { id: 'data:d1', name: 'patient_record', dataClasses: ['PHI'] },
    ],
    flows: [
      { id: 'flow:f1', dataElementIds: ['data:d1'], source: 'node:src1', sink: 'node:sink1', edgeIds: ['edge:e1'] },
    ],
  };
}

function _mkScanRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'obligation-walkthrough-'));
}

test('evaluateFramework: HIPAA §164.312(e) mints a real evidence_supported ObligationMapping when transit is protected', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    assert.ok(fw, 'the real hipaa-security-rule.json catalog must load');
    const graph = _minimalGraph({ transitVerdict: 'protected' });
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [], lineageGraph: graph };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const control = evaluation.find((e) => e.control.id === '§164.312(e)');
    assert.ok(control, 'the real §164.312(e) control must be present in the real catalog');
    assert.ok(Array.isArray(control.obligationMappings));
    const mapping = control.obligationMappings.find((m) => m.framework === 'hipaa-security-rule');
    assert.ok(mapping, 'a real graph: predicate must have produced a mapping for this control');
    assert.equal(mapping.state, 'evidence_supported');
    assert.equal(mapping.frameworkVersion, fw.controlsDigest);
    assert.equal(validateObligationMapping(mapping).valid, true);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('evaluateFramework: HIPAA §164.312(e) mints gap_detected when transit is unprotected (negative proof)', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const graph = _minimalGraph({ transitVerdict: 'unprotected' });
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [], lineageGraph: graph };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const control = evaluation.find((e) => e.control.id === '§164.312(e)');
    const mapping = control.obligationMappings.find((m) => m.framework === 'hipaa-security-rule');
    assert.equal(mapping.state, 'gap_detected');
    assert.equal(validateObligationMapping(mapping).valid, true);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('evaluateFramework: HIPAA §164.312(e) mints unknown when no lineage graph is present (the common, opt-in-off case)', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [] }; // no lineageGraph key at all
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const control = evaluation.find((e) => e.control.id === '§164.312(e)');
    const mapping = control.obligationMappings.find((m) => m.framework === 'hipaa-security-rule');
    assert.equal(mapping.state, 'unknown');
    assert.equal(validateObligationMapping(mapping).valid, true);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('evaluateFramework: the existing family:crypto-tls-* mappings on §164.312(e) still contribute to the ordinary present/partial/absent/manual status, unchanged', () => {
  // A real, disclosed regression guard: adding the graph: branch must not
  // change how the pre-existing family: mappings drive `status`.
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [] };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const control = evaluation.find((e) => e.control.id === '§164.312(e)');
    // Zero findings of either crypto-tls family -> both family: mappings
    // clear ("no open findings") -> allCleared stays true for THAT half;
    // status is still driven by the existing logic, not the new graph:
    // branch (which, with no lineageGraph, produces only a mapping, not a
    // status contribution of its own — see Task 2 Step 3's own ruling).
    assert.ok(['present', 'partial'].includes(control.status), `expected the pre-existing status logic to still produce present/partial, got ${control.status}`);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});
