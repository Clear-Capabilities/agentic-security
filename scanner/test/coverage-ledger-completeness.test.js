// FR-203: guards coverage-ledger.js's ANALYZER_NAMES against drift from the
// REAL cascade in engine.js, the same "no-dead-modules.test.js"-style
// completeness pattern artifact-registry.js already uses. If a future cycle
// adds/removes a runDetector(...) call site in _runFileCascade without
// updating this registry, this test fails the build instead of the ledger
// silently going stale.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ANALYZER_NAMES, EXTENSION_GATED_ANALYZERS, POLICY_GATED_ANALYZERS } from '../src/pipeline/coverage-ledger.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_JS = path.join(HERE, '..', 'src', 'engine.js');

function extractRealAnalyzerNames() {
  const source = fs.readFileSync(ENGINE_JS, 'utf8');
  const startMarker = source.indexOf('export function _runFileCascade');
  assert.ok(startMarker !== -1, '_runFileCascade not found in engine.js — has it been renamed?');
  const endMarker = source.indexOf('return {content:c, pfr:ta', startMarker);
  assert.ok(endMarker !== -1, 'the cascade\'s return statement was not found — has its shape changed?');
  const body = source.slice(startMarker, endMarker);
  const names = new Set();
  const re = /runDetector\(_detectorErrors,p,'([A-Za-z0-9_]+)'/g;
  let m;
  while ((m = re.exec(body))) names.add(m[1]);
  return names;
}

test('ANALYZER_NAMES exactly matches every runDetector-wrapped call site currently in _runFileCascade', () => {
  const real = extractRealAnalyzerNames();
  const registered = new Set(ANALYZER_NAMES);
  const missing = [...real].filter(n => !registered.has(n));
  const stale = [...registered].filter(n => !real.has(n));
  assert.deepEqual(missing, [], `engine.js has new detector(s) not registered in coverage-ledger.js: ${missing.join(', ')}`);
  assert.deepEqual(stale, [], `coverage-ledger.js registers detector(s) no longer in engine.js's cascade: ${stale.join(', ')}`);
});

test('the completeness guard itself finds a non-trivial number of real analyzers (sanity — proves the regex is not silently matching nothing)', () => {
  const real = extractRealAnalyzerNames();
  assert.ok(real.size > 50, `expected 50+ real analyzer call sites, found ${real.size} — the extraction regex may be broken`);
});

test('every EXTENSION_GATED_ANALYZERS / POLICY_GATED_ANALYZERS key is a real, registered analyzer name (no typo\'d gate)', () => {
  const registered = new Set(ANALYZER_NAMES);
  for (const name of Object.keys(EXTENSION_GATED_ANALYZERS)) {
    assert.ok(registered.has(name), `EXTENSION_GATED_ANALYZERS has an unregistered name: ${name}`);
  }
  for (const name of Object.keys(POLICY_GATED_ANALYZERS)) {
    assert.ok(registered.has(name), `POLICY_GATED_ANALYZERS has an unregistered name: ${name}`);
  }
});
