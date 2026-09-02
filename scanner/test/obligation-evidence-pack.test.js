import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { loadFramework, evaluateFramework } from '../src/posture/auditor-walkthrough.js';
import {
  OBLIGATION_EVIDENCE_PACK_SCHEMA,
  buildObligationEvidencePack,
  signObligationEvidencePack,
  verifyObligationEvidencePack,
} from '../src/posture/obligation-evidence-pack.js';
import { buildFixtureGraph } from '../../bench/data-lineage/runner.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.join(__dirname, '../../bench/data-lineage/fixtures');

function _minimalGraph({ transitVerdict }) {
  return {
    graphId: 'dfg:test-repo:abc123:default',
    scope: { source: 'test' },
    limitations: ['Test fixture — not a real scan.'],
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
  return fs.mkdtempSync(path.join(os.tmpdir(), 'obligation-evidence-pack-'));
}

function _keys() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

test('buildObligationEvidencePack: a real evaluateFramework run over a protected HIPAA flow produces every PRD-named field, non-vacuously', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const graph = _minimalGraph({ transitVerdict: 'protected' });
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [], lineageGraph: graph, scanHealth: { overall: 'healthy' } };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const pack = buildObligationEvidencePack({
      graph, framework: fw, evaluation, scanHealth: scan.scanHealth,
      engineVersion: '9.9.9', rulesetVersion: 'r1', bundleSha: 'sha1', generatedAt: '2026-01-01T00:00:00.000Z',
    });

    assert.equal(pack.schema, OBLIGATION_EVIDENCE_PACK_SCHEMA);
    assert.equal(pack.framework.id, 'hipaa-security-rule');
    assert.equal(pack.framework.version, fw.controlsDigest);
    assert.deepEqual(pack.scope, { source: 'test' });
    assert.ok(pack.facts.length >= 1, 'must carry at least the HIPAA §164.312(e) graph: fact');
    const fact = pack.facts.find((f) => f.requirementId === '§164.312(e)');
    assert.ok(fact);
    assert.equal(fact.state, 'evidence_supported');

    // The evidence-index join: this fact's own contributingGraphIds must
    // resolve to a real, non-empty evidence entry pulled from the graph —
    // not the vestigial, always-empty record.evidence.
    const idx = pack.evidenceIndex.find((e) => e.obligationId === fact.id);
    assert.ok(idx);
    assert.equal(idx.evidence.length, 1);
    assert.equal(idx.evidence[0].flowId, 'flow:f1');
    assert.deepEqual(idx.evidence[0].dataClasses, ['PHI']);
    assert.equal(idx.evidence[0].transitVerdict, 'protected');
    assert.equal(idx.evidence[0].sink.kind, 'external');

    assert.deepEqual(pack.unknownItems, []);
    assert.deepEqual(pack.manualItems, []);
    assert.deepEqual(pack.acceptedExceptions, []);
    assert.deepEqual(pack.scanHealth, { overall: 'healthy' });
    assert.deepEqual(pack.limitations, ['Test fixture — not a real scan.']);
    assert.match(pack.graphDigest, /^[0-9a-f]{64}$/);
    assert.equal(pack.reproducibility.graphId, graph.graphId);
    assert.equal(pack.reproducibility.graphDigest, pack.graphDigest);
    assert.equal(pack.reproducibility.engineVersion, '9.9.9');
    assert.ok(pack.disclaimer.length > 0);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('buildObligationEvidencePack: an unassessed (not_assessed) flow is honestly unknown, and unknownItems/evidenceIndex agree', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const graph = _minimalGraph({ transitVerdict: 'not_assessed' });
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [], lineageGraph: graph };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const pack = buildObligationEvidencePack({ graph, framework: fw, evaluation });

    const fact = pack.facts.find((f) => f.requirementId === '§164.312(e)');
    assert.equal(fact.state, 'unknown');
    assert.equal(pack.unknownItems.length, 1);
    assert.equal(pack.unknownItems[0].id, fact.id);
    const idx = pack.evidenceIndex.find((e) => e.obligationId === fact.id);
    assert.equal(idx.evidence[0].transitVerdict, 'not_assessed');
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('buildObligationEvidencePack: a null graph degrades every graph-derived field honestly, never throws', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [] };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    let pack;
    assert.doesNotThrow(() => { pack = buildObligationEvidencePack({ graph: null, framework: fw, evaluation }); });
    assert.equal(pack.scope, null);
    assert.equal(pack.graphDigest, null);
    assert.deepEqual(pack.limitations, []);
    const fact = pack.facts.find((f) => f.requirementId === '§164.312(e)');
    assert.equal(fact.state, 'unknown');
    const idx = pack.evidenceIndex.find((e) => e.obligationId === fact.id);
    assert.deepEqual(idx.evidence, []);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('buildObligationEvidencePack: malformed inputs (undefined args, non-array evaluation) never throw', () => {
  assert.doesNotThrow(() => buildObligationEvidencePack());
  assert.doesNotThrow(() => buildObligationEvidencePack({ graph: 'not-a-graph', framework: null, evaluation: 'not-an-array' }));
  const pack = buildObligationEvidencePack({ graph: {}, framework: null, evaluation: [{ obligationMappings: null }, null] });
  assert.deepEqual(pack.facts, []);
});

test('sign/verify round trip: a genuine pack verifies with the matching public key', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const graph = _minimalGraph({ transitVerdict: 'protected' });
    const scan = { lineageGraph: graph };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const pack = buildObligationEvidencePack({ graph, framework: fw, evaluation });
    const { privateKeyPem, publicKeyPem } = _keys();
    const signed = signObligationEvidencePack(pack, privateKeyPem);
    assert.equal(signed.signature.algorithm, 'ed25519');
    const r = verifyObligationEvidencePack(signed, publicKeyPem);
    assert.equal(r.ok, true, r.reason);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('verify: tampering with any field invalidates the signature (EA-03 proof, not just a comment)', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const graph = _minimalGraph({ transitVerdict: 'protected' });
    const evaluation = evaluateFramework(scanRoot, fw, { lineageGraph: graph });
    const pack = buildObligationEvidencePack({ graph, framework: fw, evaluation });
    const { privateKeyPem, publicKeyPem } = _keys();
    const signed = signObligationEvidencePack(pack, privateKeyPem);

    const tamperedFact = JSON.parse(JSON.stringify(signed));
    // This graph is transitVerdict: 'protected', so facts[0].state is
    // already 'evidence_supported' — assert that as a precondition, then
    // flip it to a genuinely DIFFERENT value so this is real tampering,
    // not a same-value no-op that would make the assertion below vacuous.
    assert.equal(tamperedFact.facts[0].state, 'evidence_supported');
    tamperedFact.facts[0].state = 'gap_detected';
    assert.equal(verifyObligationEvidencePack(tamperedFact, publicKeyPem).ok, false);

    const stapledKey = { ...signed, injected: 'malicious' };
    const r = verifyObligationEvidencePack(stapledKey, publicKeyPem);
    assert.equal(r.ok, false);
    assert.match(r.reason, /unrecognised top-level key/);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('verify: an unsigned pack, a wrong-algorithm signature, and a missing public key all fail cleanly', () => {
  const pack = buildObligationEvidencePack({ graph: null, framework: null, evaluation: [] });
  assert.equal(verifyObligationEvidencePack(pack, 'anything').ok, false);
  assert.equal(verifyObligationEvidencePack({ ...pack, signature: { algorithm: 'rsa', value: 'x' } }, 'anything').ok, false);
  const { privateKeyPem, publicKeyPem } = _keys();
  const signed = signObligationEvidencePack(pack, privateKeyPem);
  assert.equal(verifyObligationEvidencePack(signed, null).ok, false);
  void publicKeyPem;
});

test('REAL PIPELINE: the AC-07 flagship fixture (PHI reaching anthropic.messages.create()) produces a valid, non-vacuous evidence index end to end', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fixtureId = 'js-ai-model-output-to-ai-model-provider-phi';
    const source = fs.readFileSync(path.join(FIXTURES_ROOT, fixtureId, 'source.js'), 'utf8');
    const graph = buildFixtureGraph(fixtureId, source);
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const evaluation = evaluateFramework(scanRoot, fw, { lineageGraph: graph });
    let pack;
    assert.doesNotThrow(() => { pack = buildObligationEvidencePack({ graph, framework: fw, evaluation }); });
    assert.match(pack.graphDigest, /^[0-9a-f]{64}$/);
    const fact = pack.facts.find((f) => f.requirementId === '§164.312(e)');
    assert.ok(fact, 'the real pipeline must still produce the 6b HIPAA fact on this fixture');
    // 6b's own final review pinned this fixture's real answer as 'unknown'
    // (an unresolved-but-real-category sink, never assessed for transit) —
    // if that regresses, this pack's own facts[] would silently ship a
    // wrong compliance state.
    assert.equal(fact.state, 'unknown');
    const idx = pack.evidenceIndex.find((e) => e.obligationId === fact.id);
    assert.ok(idx.evidence.length >= 1, 'the evidence index must resolve at least one real contributing flow from the real pipeline, not just a hand-built fixture');
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});
