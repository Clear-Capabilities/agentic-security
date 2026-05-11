// Curated rule pack tests — verify --pack filters findings to the pack's
// CWE allowlist and that all four built-in packs load cleanly.
import { test } from 'node:test';
import * as assert from 'node:assert';
import { listPacks, loadPack, packsCweSet, applyPacks } from '../src/posture/rule-packs.js';

test('listPacks returns all four built-in packs with descriptions', () => {
  const packs = listPacks();
  const names = packs.map(p => p.name).sort();
  assert.deepEqual(names, ['cwe-top-25', 'llm-security', 'owasp-top-10', 'supply-chain']);
  for (const p of packs) {
    assert.ok(p.description && p.description.length > 0, `${p.name} has description`);
    assert.ok(p.cweCount > 0, `${p.name} has at least one CWE`);
  }
});

test('loadPack throws on unknown pack', () => {
  assert.throws(() => loadPack('not-a-real-pack'), /Unknown pack/);
});

test('packsCweSet unions CWEs across multiple packs', () => {
  const single = packsCweSet(['cwe-top-25']);
  const merged = packsCweSet(['cwe-top-25', 'llm-security']);
  assert.ok(merged.size >= single.size, 'merged is at least as large as single');
  // CWE-89 is in cwe-top-25 — must survive the union.
  assert.ok(merged.has('CWE-89'));
  // CWE-1427 is in llm-security but not cwe-top-25 — must appear after union.
  assert.ok(merged.has('CWE-1427'));
  assert.ok(!single.has('CWE-1427'));
});

test('applyPacks filters findings to pack CWEs', () => {
  const scan = {
    findings: [
      { cwe: 'CWE-89', vuln: 'SQL Injection', severity: 'critical', file: 'a.js', line: 1 },
      { cwe: 'CWE-999', vuln: 'Not in any pack', severity: 'low', file: 'b.js', line: 2 },
      { cwe: 'CWE-1427', vuln: 'LLM Prompt Injection', severity: 'high', file: 'c.js', line: 3 },
    ],
    secrets: [
      { cwe: 'CWE-798', vuln: 'Hardcoded Secret', severity: 'high', file: 'd.js', line: 4 },
      { cwe: null, vuln: 'No CWE', severity: 'low', file: 'e.js', line: 5 },
    ],
    logicVulns: [
      { cwe: 'CWE-778', vuln: 'Insufficient Logging', severity: 'medium', file: 'f.js', line: 6 },
    ],
    supplyChain: [
      { cwe: 'CWE-1104', vuln: 'Unmaintained dep', severity: 'medium', file: 'g.js', line: 7 },
    ],
  };

  const filtered = applyPacks(scan, ['llm-security']);
  // llm-security includes CWE-1427 and CWE-798; CWE-89, CWE-999, CWE-778, CWE-1104, null are out
  assert.equal(filtered.findings.length, 1);
  assert.equal(filtered.findings[0].cwe, 'CWE-1427');
  assert.equal(filtered.secrets.length, 1);
  assert.equal(filtered.secrets[0].cwe, 'CWE-798');
  assert.equal(filtered.logicVulns.length, 0); // CWE-778 not in llm-security
  assert.equal(filtered.supplyChain.length, 0); // CWE-1104 not in llm-security

  const sc = applyPacks(scan, ['supply-chain']);
  assert.equal(sc.supplyChain.length, 1); // CWE-1104 IS in supply-chain
  // findings array: CWE-89, CWE-999, CWE-1427 — none in supply-chain pack
  assert.equal(sc.findings.length, 0);

  // Cumulative pack: cwe-top-25 includes CWE-89; llm-security includes CWE-1427.
  // Union must include both findings.
  const merged = applyPacks(scan, ['cwe-top-25', 'llm-security']);
  assert.equal(merged.findings.length, 2);

  const noop = applyPacks(scan, []);
  assert.equal(noop, scan, 'empty packs returns scan unchanged');
});

test('applyPacks: findings without a CWE are dropped when any pack is active', () => {
  const scan = {
    findings: [
      { cwe: null, vuln: 'Unknown CWE', severity: 'high', file: 'a.js', line: 1 },
      { cwe: '',   vuln: 'Empty CWE',   severity: 'high', file: 'b.js', line: 2 },
    ],
  };
  const filtered = applyPacks(scan, ['owasp-top-10']);
  assert.equal(filtered.findings.length, 0);
});
