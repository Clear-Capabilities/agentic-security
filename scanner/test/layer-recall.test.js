// D1 — per-layer, per-language recall attribution.
//
// The corpus gate asks "was this CVE detected?" and never "by which layer?".
// That is how 20 green Ruby entries coexisted with a taint engine measured at
// zero IR-TAINT findings on Ruby: the regex layer carried them, and nothing in
// the gate could tell the difference.
//
// These tests cover the pure half — selecting the findings that actually match
// the corpus entry, and attributing them to the layer that produced them. The
// scan-driving half is bench/layer-recall/runner.mjs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matcherFor, matchingFindings } from '../src/posture/corpus-match.js';
import { layersOf, buildMatrix, LAYER_TAINT } from '../../bench/layer-recall/attribute.mjs';

const manifest = { cwe: 'CWE-89', expected: { vuln_match: 'SQL Injection' } };

test('matchingFindings returns only the findings that score the entry', () => {
  const scan = {
    findings: [
      { vuln: 'SQL Injection', cwe: 'CWE-89', parser: 'IR-TAINT' },
      { vuln: 'Weak Hash', cwe: 'CWE-328', parser: 'REGEX' },
    ],
  };
  const got = matchingFindings(scan, manifest, matcherFor(manifest));
  assert.equal(got.length, 1);
  assert.equal(got[0].vuln, 'SQL Injection');
});

test('matchingFindings consults every channel, not just findings', () => {
  // A CVE can land in secrets / supplyChain / logicVulns. Attribution that only
  // read `findings` would under-count exactly the channels the gate counts.
  const scan = {
    findings: [],
    logicVulns: [{ vuln: 'SQL Injection', cwe: 'CWE-89', parser: 'LOGIC' }],
  };
  assert.equal(matchingFindings(scan, manifest, matcherFor(manifest)).length, 1);
});

test('layersOf reports the distinct parsers that produced the matches', () => {
  const layers = layersOf([
    { parser: 'IR-TAINT' }, { parser: 'REGEX' }, { parser: 'IR-TAINT' },
  ]);
  assert.deepEqual(layers, ['IR-TAINT', 'REGEX']);
});

test('layersOf attributes a finding with no parser rather than dropping it', () => {
  // Silently discarding an unattributed finding would make the taint column
  // look better than it is — the same flattering direction the corpus matcher
  // was fixed to avoid.
  assert.deepEqual(layersOf([{}]), ['(unattributed)']);
});

test('buildMatrix counts, per language, how many entries each layer detected', () => {
  const m = buildMatrix([
    { language: 'ruby', detected: true, layers: ['REGEX'] },
    { language: 'ruby', detected: true, layers: ['REGEX', 'IR-TAINT'] },
    { language: 'php', detected: true, layers: ['IR-TAINT'] },
    { language: 'php', detected: false, layers: [] },
  ]);
  assert.equal(m.ruby.total, 2);
  assert.equal(m.ruby.detected, 2);
  assert.equal(m.ruby.byLayer['REGEX'], 2);
  assert.equal(m.ruby.byLayer[LAYER_TAINT], 1);
  assert.equal(m.php.total, 2);
  assert.equal(m.php.detected, 1);
  assert.equal(m.php.byLayer[LAYER_TAINT], 1);
});

test('an undetected entry contributes to the denominator, never to a layer', () => {
  const m = buildMatrix([{ language: 'go', detected: false, layers: [] }]);
  assert.equal(m.go.total, 1);
  assert.equal(m.go.detected, 0);
  assert.deepEqual(m.go.byLayer, {});
});

test('taintRecall is reported over all entries, not over detected ones', () => {
  // Dividing by "entries we detected" would report 100% taint recall for a
  // language where taint fired once and regex carried the other nineteen.
  const m = buildMatrix([
    { language: 'ruby', detected: true, layers: ['IR-TAINT'] },
    { language: 'ruby', detected: true, layers: ['REGEX'] },
  ]);
  assert.equal(m.ruby.taintRecall, 0.5);
});
