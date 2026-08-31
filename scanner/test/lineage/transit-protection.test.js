// Tests for transit-protection.js — Milestone 2, Sub-project B, increment 1
// (transit-protection plumbing skeleton). See
// src/lineage/DESIGN_TRANSIT_PROTECTION.md for the full design.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanTransitEvidence } from '../../src/lineage/transit-protection.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// Reuse the SAME real, already-proven fixture crypto-protocol.js's own
// test suite fires crypto-tls-no-verify against — per the plan's own
// instruction, not a newly invented shape.
const CRYPTO_FIX = path.join(__dirname, '..', 'fixtures', 'crypto-protocol');
const read = (p) => fs.readFileSync(p, 'utf8');

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

test('B1/1: scanTransitEvidence on a real rejectUnauthorized:false fixture returns a Map with that file, including a crypto-tls-no-verify finding', () => {
  const raw = read(path.join(CRYPTO_FIX, 'vulnerable', 'tls-config.js'));
  const result = scanTransitEvidence({ 'tls-config.js': raw });
  assert.ok(result instanceof Map);
  assert.equal(result.size, 1);
  assert.ok(result.has('tls-config.js'));
  const findings = result.get('tls-config.js');
  assert.ok(Array.isArray(findings) && findings.length > 0);
  const f = findings.find((x) => x.family === 'crypto-tls-no-verify');
  assert.ok(f, `expected crypto-tls-no-verify; got ${findings.map((x) => x.family).join(',')}`);
});

test('B1/2: scanTransitEvidence on a clean, crypto-relevant-but-safe fixture returns an empty Map', () => {
  const raw = read(path.join(CRYPTO_FIX, 'clean', 'safe.js'));
  const result = scanTransitEvidence({ 'safe.js': raw });
  assert.ok(result instanceof Map);
  // Measured directly against scanCryptoProtocol before asserting: the clean
  // fixture is crypto-relevant (mentions TLS/jwt/etc.) but triggers zero
  // findings, so scanTransitEvidence must have NO entry for it (never an
  // entry with an empty array — see the module's own header contract).
  assert.equal(result.size, 0);
  assert.equal(result.has('safe.js'), false);
});

test('B1/3: scanTransitEvidence({}) / scanTransitEvidence(undefined) return an empty Map, never throw', () => {
  for (const input of [{}, undefined]) {
    const result = scanTransitEvidence(input);
    assert.ok(result instanceof Map);
    assert.equal(result.size, 0);
  }
});

test('B1/4: scanTransitEvidence skips non-string values and never throws on malformed input', () => {
  const result = scanTransitEvidence({
    'a.js': 123,
    'b.js': null,
    'c.js': undefined,
    'd.js': { not: 'a string' },
  });
  assert.ok(result instanceof Map);
  assert.equal(result.size, 0);
});

test('B1/5: buildLineageGraph.graph is byte-identical with and without opts.fileContents; transitEvidence is present and non-empty only when supplied', () => {
  const cg = irOf({ 'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" });
  const vulnRaw = read(path.join(CRYPTO_FIX, 'vulnerable', 'tls-config.js'));

  const without = buildLineageGraph(cg, { repository: 'r', deterministic: true });
  const withFC = buildLineageGraph(cg, { repository: 'r', deterministic: true, fileContents: { 'tls-config.js': vulnRaw } });

  assert.equal(without.status, 'complete');
  assert.equal(withFC.status, 'complete');
  assert.deepEqual(without.graph, withFC.graph, 'graph must be byte-identical whether or not opts.fileContents is supplied');

  assert.ok(without.transitEvidence instanceof Map);
  assert.equal(without.transitEvidence.size, 0, 'no fileContents supplied -> empty transitEvidence');

  assert.ok(withFC.transitEvidence instanceof Map);
  assert.equal(withFC.transitEvidence.size, 1);
  assert.ok(withFC.transitEvidence.has('tls-config.js'));
  const fams = withFC.transitEvidence.get('tls-config.js').map((f) => f.family);
  assert.ok(fams.includes('crypto-tls-no-verify'));
});

test('B1/6: buildLineageGraph.transitEvidence defaults to an empty Map when opts.fileContents is omitted entirely', () => {
  const cg = irOf({ 'a.js': "function h(res){ res.send('x'); }" });
  const r = buildLineageGraph(cg, { repository: 'r' });
  assert.ok(r.transitEvidence instanceof Map);
  assert.equal(r.transitEvidence.size, 0);
});

test('B1/7: reuse boundary — transit-protection.js imports only crypto-protocol.js', async () => {
  const src = fs.readFileSync(new URL('../../src/lineage/transit-protection.js', import.meta.url), 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specifiers, ['../sast/crypto-protocol.js']);
});
