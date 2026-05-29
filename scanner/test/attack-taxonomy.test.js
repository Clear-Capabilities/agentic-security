// Tests for attack-taxonomy.js — MITRE ATT&CK / ATLAS / D3FEND / kill-chain
// stamping on findings.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { annotateAttackTaxonomy, summarizeTaxonomy, _internals as _t } from '../src/posture/attack-taxonomy.js';

const F = (family, extra = {}) => ({ family, file: 'a.js', line: 1, ...extra });

test('attack-tax: SQL injection mapped to T1190 + CAPEC-66', () => {
  const fs = [F('sqli'), F('sql-injection')];
  annotateAttackTaxonomy(fs);
  for (const f of fs) {
    assert.deepEqual(f.attck, ['T1190']);
    assert.ok(f.attckName.includes('Public-Facing'));
    assert.deepEqual(f.capec, ['CAPEC-66']);
    assert.equal(f.attckTactic, 'exploitation');
    assert.ok(Array.isArray(f.d3fend));
  }
});

test('attack-tax: XSS mapped to T1059.007 (JavaScript)', () => {
  const fs = [F('xss')];
  annotateAttackTaxonomy(fs);
  assert.deepEqual(fs[0].attck, ['T1059.007']);
  assert.ok(fs[0].attckName.includes('JavaScript'));
});

test('attack-tax: ML/LLM families get ATLAS technique IDs', () => {
  const fs = [
    F('prompt-injection'),
    F('hf-datasets-rce'),
    F('mlflow-untrusted-uri'),
    F('agent-tool-exec'),
    F('streaming-dataset-url'),
  ];
  annotateAttackTaxonomy(fs);
  for (const f of fs) {
    assert.ok(Array.isArray(f.atlas), `${f.family} missing atlas`);
    assert.ok(f.atlas.every(t => /^AML\.T\d+/.test(t)), `${f.family} atlas malformed: ${f.atlas}`);
  }
  // streaming-dataset-url maps to AML.T0019 (Publish Poisoned Datasets)
  const sd = fs.find(f => f.family === 'streaming-dataset-url');
  assert.deepEqual(sd.atlas, ['AML.T0019']);
});

test('attack-tax: attckTactic values are MITRE ATT&CK Enterprise tactics', () => {
  // attack.mitre.org/tactics/enterprise/ — the 14 Enterprise tactics, plus
  // 'exploitation' which we use as a remediation-side stage when a finding
  // doesn't cleanly fit a single ATT&CK tactic.
  const validStages = new Set([
    'reconnaissance', 'resource-development', 'initial-access',
    'execution', 'persistence', 'privilege-escalation', 'defense-evasion',
    'credential-access', 'discovery', 'lateral-movement', 'collection',
    'c2', 'exfiltration', 'impact', 'exploitation',
  ]);
  const fs = Object.keys(_t.FAMILY_MAP).map(family => F(family));
  annotateAttackTaxonomy(fs);
  for (const f of fs) {
    assert.ok(validStages.has(f.attckTactic), `${f.family}: invalid attckTactic "${f.attckTactic}"`);
  }
});

test('attack-tax: every mapping has attck + d3fend + capec + attckTactic', () => {
  for (const [family, map] of Object.entries(_t.FAMILY_MAP)) {
    assert.ok(Array.isArray(map.attck) && map.attck.length, `${family} missing attck`);
    assert.ok(typeof map.attckName === 'string' && map.attckName.length, `${family} missing attckName`);
    assert.ok(Array.isArray(map.d3fend) && map.d3fend.length, `${family} missing d3fend`);
    assert.ok(map.attckTactic, `${family} missing attckTactic`);
    assert.ok(Array.isArray(map.capec) && map.capec.length, `${family} missing capec`);
  }
});

test('attack-tax: aliases canonicalize before lookup', () => {
  const fs = [F('sql-inj'), F('cmd-injection'), F('pickle-rce'), F('sca')];
  annotateAttackTaxonomy(fs);
  // sql-inj → sqli → T1190
  assert.deepEqual(fs[0].attck, ['T1190']);
  // cmd-injection → command-injection → T1059.004
  assert.deepEqual(fs[1].attck, ['T1059.004']);
  // pickle-rce → deserialization → T1190
  assert.deepEqual(fs[2].attck, ['T1190']);
  // sca → vulnerable-dependency → T1195.001
  assert.deepEqual(fs[3].attck, ['T1195.001']);
});

test('attack-tax: unknown family is left unannotated (no guessing)', () => {
  const fs = [F('totally-made-up-family')];
  annotateAttackTaxonomy(fs);
  assert.equal(fs[0].attck, undefined);
  assert.equal(fs[0].atlas, undefined);
});

test('attack-tax: NO_ATTACK_TAX disables annotation', () => {
  process.env.AGENTIC_SECURITY_NO_ATTACK_TAX = '1';
  try {
    const fs = [F('sqli')];
    const r = annotateAttackTaxonomy(fs);
    assert.equal(r.annotated, 0);
    assert.equal(fs[0].attck, undefined);
  } finally { delete process.env.AGENTIC_SECURITY_NO_ATTACK_TAX; }
});

test('attack-tax: summarizeTaxonomy aggregates technique counts', () => {
  const fs = [
    F('sqli'), F('sqli'), F('xss'),
    F('prompt-injection'), F('hf-datasets-rce'),
    F('unmapped-thing'),
  ];
  annotateAttackTaxonomy(fs);
  const sum = summarizeTaxonomy(fs);
  assert.equal(sum.attckTechniques['T1190'], 2);  // both sqli
  assert.equal(sum.attckTechniques['T1059.007'], 1);  // xss
  assert.ok(sum.atlasTechniques['AML.T0051.000'] >= 1);  // prompt-injection
  assert.ok(sum.unmappedFamilies.includes('unmapped-thing'));
  assert.equal(sum.coverageRatio, '0.833', 'coverage = 5/6');
});

test('attack-tax: K8s pod-security families map to T1611 escape-to-host', () => {
  const fs = [
    F('k8s-pod-security-privileged'),
    F('k8s-pod-security-hostpid'),
    F('k8s-pod-security-hostpath'),
  ];
  annotateAttackTaxonomy(fs);
  for (const f of fs) {
    assert.deepEqual(f.attck, ['T1611']);
    assert.equal(f.attckTactic, 'privilege-escalation');
  }
});

test('attack-tax: cloud public-S3 maps to T1530 Data from Cloud Storage', () => {
  const fs = [F('aws-public-s3'), F('gcp-public-binding')];
  annotateAttackTaxonomy(fs);
  for (const f of fs) {
    assert.deepEqual(f.attck, ['T1530']);
    assert.equal(f.attckTactic, 'collection');
  }
});

test('attack-tax: empty / null inputs handled gracefully', () => {
  assert.deepEqual(annotateAttackTaxonomy([]), { annotated: 0, total: 0 });
  assert.deepEqual(annotateAttackTaxonomy(null), { annotated: 0, total: 0 });
  assert.deepEqual(annotateAttackTaxonomy(undefined), { annotated: 0, total: 0 });
});
