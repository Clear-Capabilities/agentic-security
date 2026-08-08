import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LENSES, lensByKey, buildHunterPrompt } from '../src/discovery/lenses.js';

test('there are seven distinct lenses, each with a family and a cwe', () => {
  assert.equal(LENSES.length, 7);
  assert.equal(new Set(LENSES.map(l => l.key)).size, 7);
  for (const l of LENSES) {
    assert.ok(l.family, `${l.key} needs a family`);
    assert.match(String(l.cwe), /^CWE-\d+$/);
    assert.ok(l.brief.length > 20);
  }
});

test('lensByKey resolves and rejects', () => {
  assert.equal(lensByKey('authz').key, 'authz');
  assert.equal(lensByKey('nope'), null);
  assert.equal(lensByKey(undefined), null);
});

test('buildHunterPrompt embeds the lens brief, the file list, and the source', () => {
  const area = { id: 'abc123abc123', label: 'auth/', files: ['auth.js'], functions: ['auth.js::login@1'], size: 1 };
  const p = buildHunterPrompt(area, lensByKey('authz'), { fileContents: { 'auth.js': 'function login(){}' } });
  assert.ok(p.includes('auth.js'));
  assert.ok(p.includes('function login(){}'));
  assert.ok(p.includes(lensByKey('authz').brief));
  // The output contract must be stated, or the hunter returns prose.
  assert.ok(p.includes('candidates'));
});

test('buildHunterPrompt truncates oversized source and says so', () => {
  const big = 'x'.repeat(5000);
  const area = { id: 'a', label: 'a', files: ['big.js'], functions: [], size: 0 };
  const p = buildHunterPrompt(area, lensByKey('injection'), { fileContents: { 'big.js': big }, maxChars: 100 });
  assert.ok(p.length < 2000);
  assert.ok(p.includes('truncated'), 'truncation must be disclosed in the prompt');
});

test('buildHunterPrompt omits files with no content rather than emitting undefined', () => {
  const area = { id: 'a', label: 'a', files: ['gone.js'], functions: [], size: 0 };
  const p = buildHunterPrompt(area, lensByKey('crypto'), { fileContents: {} });
  assert.ok(!p.includes('undefined'));
});
