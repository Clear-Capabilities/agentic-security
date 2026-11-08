// Tests for posture/triage-memory.js — conversational triage memory.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { recordDecision, suppressByPastDecisions, loadMemory, queryMemory, _internals } from '../src/posture/triage-memory.js';

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'tm-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"tm-test"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

const F = (overrides = {}) => ({
  id: 'F-1', family: 'sqli', severity: 'high',
  file: 'src/routes/users.js', line: 10,
  vuln: 'SQL injection at users.js:10',
  confidence: 0.9,
  ...overrides,
});

test('triage-memory: recordDecision writes JSONL + AGENTS.md', async () => {
  const p = await mkProject();
  try {
    const entry = recordDecision(p.dir, F(), 'wont-fix', 'Internal admin tool — not exposed externally');
    assert.ok(entry);
    assert.equal(entry.decision, 'wont-fix');
    const mem = loadMemory(p.dir);
    assert.equal(mem.length, 1);
    assert.equal(mem[0].family, 'sqli');
    assert.match(mem[0].reason, /Internal admin/);
    const agentsBody = fs.readFileSync(path.join(p.dir, '.agentic-security', 'AGENTS.md'), 'utf8');
    assert.match(agentsBody, /Triage decision/);
    assert.match(agentsBody, /Internal admin/);
  } finally { await p.cleanup(); }
});

test('triage-memory: recordDecision ignores non-wontfix transitions', async () => {
  const p = await mkProject();
  try {
    const r = recordDecision(p.dir, F(), 'fixed', 'patched');
    assert.equal(r, null);
    assert.equal(loadMemory(p.dir).length, 0);
  } finally { await p.cleanup(); }
});

test('triage-memory: a same-bucket decision is advisory history and never demotes a distinct finding (threat-model TM-07)', async () => {
  const p = await mkProject();
  try {
    recordDecision(p.dir, F(), 'wont-fix', 'Admin-only route');
    const fresh = [F({ id: 'F-2', line: 25 })];  // same family + same dir, a DIFFERENT finding
    const r = suppressByPastDecisions(p.dir, fresh);
    assert.equal(r.applied, 0);
    assert.equal(r.advisory, 1);
    assert.equal(fresh[0].pastDecision.status, 'advisory');
    assert.equal(fresh[0].pastDecision.decision, 'wont-fix');
    assert.ok(fresh[0].tags.includes('past-decision-advisory'));
    assert.equal(fresh[0].confidence, 0.9, 'confidence is unchanged');
  } finally { await p.cleanup(); }
});

test('triage-memory: an exact decision on a medium finding applies, demotes confidence and tags', async () => {
  const p = await mkProject();
  try {
    recordDecision(p.dir, F({ severity: 'medium' }), 'wont-fix', 'Admin-only route');
    const fresh = [F({ severity: 'medium' })];
    const r = suppressByPastDecisions(p.dir, fresh);
    assert.equal(r.applied, 1);
    assert.equal(fresh[0].pastDecision.status, 'applied');
    assert.ok(fresh[0].tags.includes('past-decision'));
    assert.ok(fresh[0].confidence < 0.9, 'confidence demoted');
  } finally { await p.cleanup(); }
});

test('triage-memory: suppress does not affect different family', async () => {
  const p = await mkProject();
  try {
    recordDecision(p.dir, F({ family: 'sqli' }), 'wont-fix', 'admin');
    const fresh = [F({ id: 'F-2', family: 'xss' })];
    const r = suppressByPastDecisions(p.dir, fresh);
    assert.equal(r.applied, 0);
    assert.equal(fresh[0].pastDecision, undefined);
  } finally { await p.cleanup(); }
});

test('triage-memory: suppress does not affect different dir', async () => {
  const p = await mkProject();
  try {
    recordDecision(p.dir, F({ file: 'src/admin/users.js' }), 'wont-fix', 'admin');
    const fresh = [F({ id: 'F-2', file: 'src/public/users.js' })];  // different dir
    const r = suppressByPastDecisions(p.dir, fresh);
    assert.equal(r.applied, 0);
  } finally { await p.cleanup(); }
});

test('triage-memory: NO_TRIAGE_MEMORY env disables annotator', async () => {
  const p = await mkProject();
  try {
    recordDecision(p.dir, F(), 'wont-fix', 'admin');
    process.env.AGENTIC_SECURITY_NO_TRIAGE_MEMORY = '1';
    try {
      const fresh = [F({ id: 'F-2' })];
      const r = suppressByPastDecisions(p.dir, fresh);
      assert.equal(r.applied, 0);
      assert.equal(fresh[0].pastDecision, undefined);
    } finally { delete process.env.AGENTIC_SECURITY_NO_TRIAGE_MEMORY; }
  } finally { await p.cleanup(); }
});

test('triage-memory: queryMemory finds matching entries by keyword', async () => {
  const p = await mkProject();
  try {
    recordDecision(p.dir, F({ family: 'sqli' }), 'wont-fix', 'Internal admin tool — not exposed externally');
    recordDecision(p.dir, F({ id: 'F-2', family: 'xss', file: 'src/views/profile.js' }), 'false-positive', 'Output is HTML-escaped by template engine');
    recordDecision(p.dir, F({ id: 'F-3', family: 'csrf' }), 'wont-fix', 'GET-only endpoint, no state mutation');
    const r1 = queryMemory(p.dir, 'admin');
    assert.ok(r1.length >= 1);
    assert.match(r1[0].reason, /admin/i);
    const r2 = queryMemory(p.dir, 'template');
    assert.ok(r2.length >= 1);
    assert.equal(r2[0].family, 'xss');
  } finally { await p.cleanup(); }
});

test('triage-memory: queryMemory empty query returns most recent', async () => {
  const p = await mkProject();
  try {
    recordDecision(p.dir, F({ family: 'sqli' }), 'wont-fix', 'a');
    recordDecision(p.dir, F({ id: 'F-2', family: 'xss' }), 'false-positive', 'b');
    const r = queryMemory(p.dir, '');
    assert.equal(r.length, 2);
  } finally { await p.cleanup(); }
});

test('triage-memory: empty memory + suppress is a no-op', async () => {
  const p = await mkProject();
  try {
    const fresh = [F()];
    const r = suppressByPastDecisions(p.dir, fresh);
    assert.equal(r.applied, 0);
    assert.equal(fresh[0].pastDecision, undefined);
  } finally { await p.cleanup(); }
});

test('triage-memory: bucket key combines family + dir', () => {
  const a = _internals._bucketKey({ family: 'sqli', file: 'src/routes/users.js' });
  const b = _internals._bucketKey({ family: 'sqli', file: 'src/routes/admin.js' });
  const c = _internals._bucketKey({ family: 'xss', file: 'src/routes/users.js' });
  assert.equal(a, b, 'same family + same dir → same bucket');
  assert.notEqual(a, c, 'different family → different bucket');
});
