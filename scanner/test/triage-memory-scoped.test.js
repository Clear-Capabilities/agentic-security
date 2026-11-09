// Threat-model PRD FR-05 (TM-07): learned decisions are scoped. A bucket match is advisory; an exact decision applies to a critical
// or high finding only with a reviewer, an unexpired expiry, a matching scope, an unchanged source and this install's signature.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { mkTestTmp } from './helpers/tmp.js';
import { recordDecision, suppressByPastDecisions, loadMemoryWithDiagnostics, pastDecisionApplies } from '../src/posture/triage-memory.js';
import { stateDir } from '../src/posture/state-dir.js';

const NOW = Date.parse('2026-11-08T00:00:00Z');
const F = (o = {}) => ({ id: 'F-1', stableId: 'S-1', family: 'sqli', severity: 'high', file: 'src/routes/users.js', line: 10, cwe: 'CWE-89', snippet: 'db.query("..." + id)', confidence: 0.9, ...o });
const reviewed = { reviewer: 'appsec-lead', expires: '2026-12-01T00:00:00Z', scope: { repository: 'shop', environment: 'prod', tenant: 'acme' } };
const CTX = { now: NOW, repository: 'shop', environment: 'prod', tenant: 'acme' };
const judge = (dir, f) => { const fs2 = [f]; suppressByPastDecisions(dir, fs2, CTX); return fs2[0]; };

test('AC-05A: a new high finding in the same family and directory keeps its confidence and stays open', () => {
  const dir = mkTestTmp('tm-scope-');
  recordDecision(dir, F(), 'wont-fix', 'reviewed', reviewed);
  const other = judge(dir, F({ id: 'F-9', stableId: 'S-9', line: 40 }));
  assert.equal(other.confidence, 0.9);
  assert.equal(other.pastDecision.status, 'advisory');
  assert.equal(pastDecisionApplies(other.pastDecision), false, 'it still counts as open');
});

test('AC-05A: a valid exact scoped signed decision applies; expired, edited, copied, cross-tenant and unsigned ones do not', () => {
  const dir = mkTestTmp('tm-scope-');
  recordDecision(dir, F(), 'wont-fix', 'reviewed', reviewed);
  const ok = judge(dir, F());
  assert.equal(ok.pastDecision.status, 'applied'); assert.ok(ok.confidence < 0.9); assert.equal(pastDecisionApplies(ok.pastDecision), true);
  assert.equal(judge(dir, F({ snippet: 'db.query("..." + id + x)' })).pastDecision.status, 'stale', 'the code it was made on changed');
  const expiredDir = mkTestTmp('tm-scope-'); recordDecision(expiredDir, F(), 'wont-fix', 'r', { ...reviewed, expires: '2026-11-01T00:00:00Z' });
  assert.equal(judge(expiredDir, F()).pastDecision.status, 'expired');
  const tenantDir = mkTestTmp('tm-scope-'); recordDecision(tenantDir, F(), 'wont-fix', 'r', { ...reviewed, scope: { ...reviewed.scope, tenant: 'globex' } });
  assert.equal(judge(tenantDir, F()).pastDecision.status, 'out-of-scope');
  const unsignedDir = mkTestTmp('tm-scope-'); recordDecision(unsignedDir, F(), 'wont-fix', 'r');
  assert.equal(judge(unsignedDir, F()).pastDecision.status, 'advisory', 'no reviewer or expiry: cannot change a high finding');
  // a copied record: a signed decision edited to name another finding no longer verifies
  const copyDir = mkTestTmp('tm-scope-'); recordDecision(copyDir, F(), 'wont-fix', 'r', reviewed);
  const mem = path.join(stateDir(copyDir), 'triage-memory.jsonl');
  const e = JSON.parse(fs.readFileSync(mem, 'utf8').trim()); e.stableId = 'S-2'; fs.writeFileSync(mem, `${JSON.stringify(e)}\n`);
  const copied = judge(copyDir, F({ stableId: 'S-2' }));
  assert.equal(copied.pastDecision.status, 'rejected'); assert.equal(copied.pastDecision.reasonCode, 'signature-invalid'); assert.equal(copied.confidence, 0.9);
});

test('AC-05B: legacy entries stay readable, duplicates apply once, torn writes are counted, and no free text reaches the finding', () => {
  const dir = mkTestTmp('tm-scope-');
  recordDecision(dir, F({ severity: 'medium' }), 'wont-fix', 'Customer ACME said the internal admin route is fine', reviewed);
  recordDecision(dir, F({ severity: 'medium' }), 'wont-fix', 'Customer ACME said the internal admin route is fine', reviewed);
  const mem = path.join(stateDir(dir), 'triage-memory.jsonl');
  fs.appendFileSync(mem, '{"at":"2026-01-01T00:00:00Z","decision":"wont-fix","bucket":"sqli::src/routes","reason":"legacy"}\n{"torn": tr');
  const d = loadMemoryWithDiagnostics(dir);
  assert.equal(d.entries.length, 2, 'the retried decision was written once; the legacy entry is readable');
  assert.equal(d.malformed, 1, 'the torn line is counted, not fatal');
  const f = F({ severity: 'medium' }); const r = suppressByPastDecisions(dir, [f], CTX);
  assert.equal(r.applied, 1); assert.equal(r.diagnostics.malformed, 1);
  assert.ok(!JSON.stringify(f.pastDecision).includes('ACME'), 'the reason is a digest, not the text');
  assert.match(f.pastDecision.reasonDigest, /^[0-9a-f]{16}$/);
});
