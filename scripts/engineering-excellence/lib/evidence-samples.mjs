// Real sample records for the evidence inventory (E7-01): each is built by the product's own producer from a tiny fixed input, so the inventory reports what
// the producers emit and not what a document says they emit. A kind whose producer needs more than a small fixed input is reported as not exercised.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const src = (p) => import(path.join(ROOT, 'scanner', 'src', p));

const APP = "const express = require('express');\nconst { exec } = require('child_process');\nconst app = express();\napp.get('/run', (req, res) => { exec('ls ' + req.query.dir, () => res.end()); });\n";

export async function buildSamples() {
  const { runFullScan } = await src('engine.js');
  const { setStateWritesEnabled } = await src('posture/state-dir.js');
  setStateWritesEnabled(false);
  const scan = await runFullScan({ fileContents: { 'app.js': APP }, scanRoot: null, deep: true });
  const finding = scan.findings.find((f) => f.parser === 'IR-TAINT') || scan.findings[0];
  const out = {}; const notExercised = {};
  const attempt = async (kind, fn) => { try { const v = await fn(); if (v) out[kind] = v; else notExercised[kind] = 'the producer returned nothing for the fixed input'; } catch (e) { notExercised[kind] = `the producer needs more than the fixed input: ${String(e.message || e).slice(0, 120)}`; } };

  await attempt('finding', () => finding);
  await attempt('scan-health', () => scan.scanHealth);
  await attempt('finding-evidence', async () => (await src('posture/evidence-bundle.js')).buildEvidenceBundle(finding, { engineVersion: '0.0.0', rulesetVersion: '0.0.0', bundleSha: 'unavailable', commit: 'a'.repeat(40) }));
  await attempt('provenance-evidence', async () => (await src('posture/provenance-evidence-bundle.js')).buildProvenanceEvidenceBundle({ ...finding, findingProvenance: { status: 'complete', findingOrigin: { commit: 'b'.repeat(40), authorName: 'Example', authorDate: '2026-01-01T00:00:00Z', summary: 'init' }, evidenceAttribution: [], method: 'blame', confidence: { level: 'high', score: 0.9, reasons: [] }, limitations: [] } }, { engineVersion: '0.0.0', repoIdentity: 'example', head: 'b'.repeat(40) }));
  await attempt('fix-verification', async () => (await src('fix/verification-record.js')).buildFixVerificationRecord({ findingId: String(finding.id), mode: 'verify', route: 'deterministic', patchHash: 'sha256:' + 'c'.repeat(64), affectedFiles: ['app.js'], preCommit: 'a'.repeat(40) }));
  await attempt('verification', async () => (await src('posture/assurance/verification-record.js')).buildVerificationRecord({ hypothesisId: String(finding.stableId || finding.id), commit: 'a'.repeat(40), detectorOrigin: 'IR-TAINT', outcome: 'inconclusive', reason: 'no oracle ran', scope: { file: 'app.js' } }));
  await attempt('runtime-explanation', async () => (await src('posture/runtime-explanation.js')).buildRuntimeExplanation(finding, { pathKeys: ['route|/run|app.handler'], snapshotIdentity: { commit: 'a'.repeat(40) } }));
  await attempt('exploitability-evidence', async () => (await src('posture/exploitability-evidence.js')).withExploitabilityEvidence(finding).exploitabilityEvidence);
  await attempt('semantic-graph', async () => { const { buildProjectIR } = await src('ir/index.js'); return (await src('ir/semantic-graph.js')).buildSemanticGraph(buildProjectIR({ 'app.js': APP })); });
  await attempt('scorecard', () => JSON.parse(fs.readFileSync(path.join(ROOT, 'docs', 'scorecard.json'), 'utf8')));
  await attempt('sbom', async () => (await src('posture/sbom.js')).toCycloneDX(scan, {}));
  await attempt('ai-bom', async () => { const m = await src('posture/aibom.js'); return m.toCycloneDXMLBOM(m.buildAIBOM(scan, { 'app.js': APP }, {}), {}); });
  await attempt('dci-invariants', () => JSON.parse(fs.readFileSync(path.join(ROOT, 'scanner', 'test', 'fixtures', 'engineering-excellence', 'dci-invariants.example.json'), 'utf8')));
  await attempt('compliance-evidence', async () => { const m = await src('posture/compliance-evidence-signing.js'); const { generateKeyPairSync } = await import('node:crypto'); const k = generateKeyPairSync('ed25519'); return m.signComplianceEvidence({ '@context': 'x', framework: 'example', controls: [] }, k.privateKey.export({ type: 'pkcs8', format: 'pem' })); });
  await attempt('obligation-evidence-pack', async () => (await src('posture/obligation-evidence-pack.js')).buildObligationEvidencePack({ graph: { nodes: [], edges: [], flows: [] }, framework: { id: 'example', name: 'Example', controlsDigest: 'x' }, evaluation: [], scanHealth: scan.scanHealth, engineVersion: '0.0.0', rulesetVersion: '0.0.0', bundleSha: 'unavailable', generatedAt: '2026-01-01T00:00:00Z' }));
  notExercised['release-evidence'] = 'built only by the release-evidence validator tests; no producer is called from a scan';
  return { samples: out, notExercised, finding, scan };
}
