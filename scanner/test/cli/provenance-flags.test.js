import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseProvenanceFlags } from '../../bin/agentic-security.js';

test('parseProvenanceFlags: defaults to standard mode, nothing disabled', () => {
  const f = parseProvenanceFlags([]);
  assert.equal(f.mode, 'standard');
  assert.equal(f.disabled, false);
  assert.equal(f.includeEmail, false);
  assert.equal(f.requireProvenance, false);
});

test('parseProvenanceFlags: --no-provenance disables', () => {
  const f = parseProvenanceFlags(['--no-provenance']);
  assert.equal(f.disabled, true);
});

test('parseProvenanceFlags: --provenance deep is accepted but warns and stays standard', () => {
  const f = parseProvenanceFlags(['--provenance', 'deep']);
  assert.equal(f.mode, 'standard');
  assert.match(f.warning, /deep mode ships in a later release/);
});

test('parseProvenanceFlags: --provenance-since, --provenance-timeout, --include-author-email, --require-provenance', () => {
  const f = parseProvenanceFlags(['--provenance-since', 'v1.0.0', '--provenance-timeout', '30000', '--include-author-email', '--require-provenance']);
  assert.equal(f.since, 'v1.0.0');
  assert.equal(f.timeoutMs, 30000);
  assert.equal(f.includeEmail, true);
  assert.equal(f.requireProvenance, true);
});
