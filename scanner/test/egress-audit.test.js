// Per-call egress audit log (assurance-hardening PRD FR-604).
//
// Mirrors mcp/audit.js's proven OWASP-MCP08 hash-chain technique for a
// different log (egress-audit.log) and a different entry shape (purpose,
// provider, model, region, policy, byte/token counts, content hash,
// outcome) — content is NEVER retained, only its size and hash.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { recordEgressCall, payloadMetrics, verifyEgressAuditLog, _internals } from '../src/egress/audit.js';

function mkProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-audit-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{}');
  return dir;
}

function logPathFor(dir) {
  return path.join(dir, '.agentic-security', _internals.LOG_FILE_NAME);
}

// ---------------------------------------------------------------------------
// payloadMetrics
// ---------------------------------------------------------------------------

test('payloadMetrics: byte count, token estimate, and content hash for real text', () => {
  const m = payloadMetrics('hello world');
  assert.equal(m.byteCount, 11);
  assert.equal(m.tokenCount, 3);
  assert.equal(typeof m.contentHash, 'string');
  assert.equal(m.contentHash.length, 64, 'sha256 hex digest');
});

test('payloadMetrics: empty/non-string input is a clean zero, not a crash', () => {
  assert.deepEqual(payloadMetrics(''), { byteCount: 0, tokenCount: 0, contentHash: null });
  assert.deepEqual(payloadMetrics(null), { byteCount: 0, tokenCount: 0, contentHash: null });
  assert.deepEqual(payloadMetrics(undefined), { byteCount: 0, tokenCount: 0, contentHash: null });
});

test('payloadMetrics: never returns the input text anywhere in its result', () => {
  const secret = 'sk-live-abcdefghijklmnopqrstuvwx0123456789';
  const m = payloadMetrics(secret);
  const serialized = JSON.stringify(m);
  assert.ok(!serialized.includes(secret), 'the raw payload must not appear in the metrics object');
});

// ---------------------------------------------------------------------------
// recordEgressCall
// ---------------------------------------------------------------------------

test('recordEgressCall: a denied call is logged with outcome/reason/provider/purpose, no byte/token/hash fields', () => {
  const dir = mkProject();
  try {
    const decision = { allowed: false, decision: 'deny', reason: "provider 'x' is in deniedProviders", provider: 'x', policySource: 'config', purpose: 'llm-validator' };
    recordEgressCall({ scanRoot: dir, decision, ctx: { model: 'gpt-4', region: 'us-east' } });
    const raw = fs.readFileSync(logPathFor(dir), 'utf8').trim();
    const entry = JSON.parse(raw);
    assert.equal(entry.purpose, 'llm-validator');
    assert.equal(entry.provider, 'x');
    assert.equal(entry.model, 'gpt-4');
    assert.equal(entry.region, 'us-east');
    assert.equal(entry.policy.policySource, 'config');
    assert.equal(entry.outcome, 'deny');
    assert.equal(entry.reason, "provider 'x' is in deniedProviders");
    assert.equal(entry.byteCount, null);
    assert.equal(entry.tokenCount, null);
    assert.equal(entry.contentHash, null);
    assert.equal(entry.prev, 'GENESIS');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('recordEgressCall: an allowed call carries byte/token counts and a content hash, never the payload text', () => {
  const dir = mkProject();
  try {
    const secretPrompt = 'the actual prompt containing a hardcoded key sk-live-abcdefghijklmnop';
    const decision = { allowed: true, decision: 'allow', provider: 'anthropic', policySource: 'default', purpose: 'llm-validator' };
    recordEgressCall({ scanRoot: dir, decision, ctx: { model: 'claude-sonnet' }, metrics: payloadMetrics(secretPrompt) });
    const raw = fs.readFileSync(logPathFor(dir), 'utf8').trim();
    assert.ok(!raw.includes('sk-live-abcdefghijklmnop'), 'the log line must never contain the raw payload text');
    assert.ok(!raw.includes('the actual prompt'), 'nor any fragment of it');
    const entry = JSON.parse(raw);
    assert.equal(entry.outcome, 'allow');
    assert.equal(entry.byteCount, Buffer.byteLength(secretPrompt, 'utf8'));
    assert.ok(entry.tokenCount > 0);
    assert.equal(typeof entry.contentHash, 'string');
    assert.equal(entry.region, null, 'region is null when the caller does not supply one — never fabricated');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('recordEgressCall: entries chain — each prev is the sha256 of the previous line', () => {
  const dir = mkProject();
  try {
    const decision = { allowed: true, decision: 'allow', provider: 'anthropic', policySource: 'default', purpose: 'llm-validator' };
    recordEgressCall({ scanRoot: dir, decision, metrics: payloadMetrics('first') });
    recordEgressCall({ scanRoot: dir, decision, metrics: payloadMetrics('second') });
    recordEgressCall({ scanRoot: dir, decision, metrics: payloadMetrics('third') });
    const result = verifyEgressAuditLog(logPathFor(dir));
    assert.deepEqual(result, { ok: true, entries: 3 });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('recordEgressCall: tampering with an entry breaks the chain from that point forward', () => {
  const dir = mkProject();
  try {
    const decision = { allowed: true, decision: 'allow', provider: 'anthropic', policySource: 'default', purpose: 'llm-validator' };
    recordEgressCall({ scanRoot: dir, decision, metrics: payloadMetrics('first') });
    recordEgressCall({ scanRoot: dir, decision, metrics: payloadMetrics('second') });
    const logFile = logPathFor(dir);
    const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
    const tampered = JSON.parse(lines[0]);
    tampered.outcome = 'deny'; // forge the first entry's outcome
    lines[0] = JSON.stringify(tampered);
    fs.writeFileSync(logFile, lines.join('\n') + '\n');
    const result = verifyEgressAuditLog(logFile);
    assert.equal(result.ok, false);
    assert.equal(result.brokenAt, 1, 'the SECOND entry is where the chain first fails to verify (its prev no longer matches the forged first line)');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('recordEgressCall: no scanRoot, no decision, or a scanRoot with no project marker -> silently a no-op, never throws', () => {
  assert.doesNotThrow(() => recordEgressCall({}));
  assert.doesNotThrow(() => recordEgressCall({ scanRoot: '/nonexistent/path/xyz' }));
  const bareDir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-audit-bare-'));
  try {
    const decision = { allowed: true, decision: 'allow', provider: 'anthropic', policySource: 'default', purpose: 'x' };
    recordEgressCall({ scanRoot: bareDir, decision });
    assert.equal(fs.existsSync(logPathFor(bareDir)), false, 'a scanRoot with no project marker must not accumulate an audit file');
  } finally { fs.rmSync(bareDir, { recursive: true, force: true }); }
});

test('verifyEgressAuditLog: no log file at all is a clean, valid empty chain', () => {
  assert.deepEqual(verifyEgressAuditLog('/nonexistent/egress-audit.log'), { ok: true, entries: 0 });
});
