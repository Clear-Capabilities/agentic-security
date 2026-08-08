import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCandidates, runHunter } from '../src/discovery/hunter.js';
import { lensByKey } from '../src/discovery/lenses.js';

const AREA = { id: 'aaaaaaaaaaaa', label: 'auth/', files: ['auth.js'], functions: [], size: 1 };
const CTX = { fileContents: { 'auth.js': 'function login(u){ return db.query("select * from u where n=" + u); }' } };
const LENS = lensByKey('injection');

test('parseCandidates extracts a JSON block and stamps deterministic ids', () => {
  const raw = 'Here you go:\n{"candidates":[{"title":"SQLi in login","file":"auth.js","line":1,"rationale":"concat","entryPoint":"u","sink":"db.query"}]}';
  const a = parseCandidates(raw, AREA, LENS);
  const b = parseCandidates(raw, AREA, LENS);
  assert.equal(a.length, 1);
  assert.equal(a[0].family, 'injection');
  assert.equal(a[0].cwe, 'CWE-74');
  assert.equal(a[0].focusAreaId, AREA.id);
  assert.match(a[0].id, /^[0-9a-f]{12}$/);
  assert.equal(a[0].id, b[0].id, 'ids must be stable across parses');
});

test('parseCandidates drops entries with no file or no line', () => {
  const raw = '{"candidates":[{"title":"vague","rationale":"x"},{"title":"ok","file":"auth.js","line":1}]}';
  const out = parseCandidates(raw, AREA, LENS);
  assert.equal(out.length, 1);
  assert.equal(out[0].title, 'ok');
});

test('parseCandidates returns [] on unparseable output instead of throwing', () => {
  assert.deepEqual(parseCandidates('I could not find anything.', AREA, LENS), []);
  assert.deepEqual(parseCandidates('{"candidates": not-json', AREA, LENS), []);
  assert.deepEqual(parseCandidates(null, AREA, LENS), []);
});

test('runHunter degrades with no llmInvoke and no endpoint, and does not throw', async () => {
  const prev = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  try {
    const r = await runHunter(AREA, LENS, CTX, {});
    assert.equal(r.degraded, true);
    assert.deepEqual(r.candidates, []);
    assert.match(r.reason, /no llmInvoke/);
  } finally {
    if (prev !== undefined) process.env.AGENTIC_SECURITY_LLM_ENDPOINT = prev;
  }
});

test('runHunter returns candidates and a hash-chained transcript', async () => {
  const llmInvoke = async () => '{"candidates":[{"title":"SQLi","file":"auth.js","line":1,"rationale":"concat"}]}';
  const r = await runHunter(AREA, LENS, CTX, { llmInvoke });
  assert.equal(r.degraded, false);
  assert.equal(r.candidates.length, 1);
  assert.ok(r.transcript.length >= 2);
  for (let i = 1; i < r.transcript.length; i++) {
    assert.equal(r.transcript[i].prev, r.transcript[i - 1].hash);
  }
});

test('runHunter survives an llmInvoke that throws', async () => {
  const llmInvoke = async () => { throw new Error('429 rate limited'); };
  const r = await runHunter(AREA, LENS, CTX, { llmInvoke });
  assert.equal(r.degraded, true);
  assert.deepEqual(r.candidates, []);
  assert.match(r.reason, /429/);
});
