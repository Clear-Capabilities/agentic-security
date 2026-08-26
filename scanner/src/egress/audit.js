// Per-call egress audit log (assurance-hardening PRD FR-604).
//
// FR-601 gives every outbound LLM call a machine-readable in-memory
// decision object. FR-604's acceptance criterion asks for more than that:
// a PERSISTED, per-call audit record — "purpose, provider, model, region if
// known, byte/token counts, policy, hashes, and outcome" — WITHOUT ever
// retaining the prohibited prompt content itself. This module is that
// record.
//
// Design: intentionally mirrors mcp/audit.js's proven OWASP-MCP08
// technique (append-only NDJSON, each entry's `prev` is the SHA-256 of the
// previous line, so tampering breaks the chain from that point forward) —
// same shape of guarantee this codebase already ships and tests for MCP
// tool calls, now for egress calls. Deliberately a SEPARATE, self-contained
// implementation rather than an import from mcp/audit.js: that module's
// public surface (`auditCall`) is shaped around {tool, args}, not
// {purpose, provider, model, region, policy, hashes}, and its hash-chain
// helpers are private (`_sha`/`_readLastEntryHash`/`_postRemote`, not
// exported) — reshaping that already-tested, security-relevant module to
// export shared primitives is a real, separate refactor, not something to
// fold into one FR cycle. The ~15 lines of hash-chaining logic duplicated
// here are a well-understood idiom (one sha256 call), not a place where
// drift risk between the two copies matters in practice.
//
// CONTENT NEVER RETAINED: this module accepts a byte count, a token
// estimate, and a content HASH — never the text itself. A caller that
// passes raw prompt text here has misused the API; there is no parameter
// that accepts it.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { stateDir } from '../posture/state-dir.js';

const GENESIS = 'GENESIS';
const LOG_FILE_NAME = 'egress-audit.log';
const SESSION_ID = `${process.pid}-${Date.now().toString(36).slice(-6)}`;

function _sha(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function _hasProjectMarker(sessionRoot) {
  const MARKERS = ['.git', 'package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'pom.xml', 'composer.json', 'Gemfile'];
  for (const m of MARKERS) {
    try { if (fs.existsSync(path.join(sessionRoot, m))) return true; } catch { /* keep checking */ }
  }
  return false;
}

// Read-first, not existsSync()-then-readFileSync() — ENOENT is the expected
// "no prior log" case (see this session's D-0012: every optional-file
// reader in this codebase follows this shape from the start).
function _readLastEntryHash(logFile) {
  let all;
  try {
    all = fs.readFileSync(logFile, 'utf8');
  } catch {
    return GENESIS;
  }
  const lines = all.split('\n').filter(Boolean);
  if (!lines.length) return GENESIS;
  return _sha(lines[lines.length - 1]);
}

/**
 * Compute the {byteCount, tokenCount, contentHash} triple for an outbound
 * payload WITHOUT the caller having to hash/measure it inline at every call
 * site. Never returns or logs the text itself.
 */
export function payloadMetrics(text) {
  if (typeof text !== 'string' || text.length === 0) {
    return { byteCount: 0, tokenCount: 0, contentHash: null };
  }
  return {
    byteCount: Buffer.byteLength(text, 'utf8'),
    tokenCount: Math.ceil(text.length / 4), // same rough estimate llm-validator/index.js's own R12 ceiling uses
    contentHash: _sha(text),
  };
}

/**
 * Append one audit entry for an evaluateEgress() decision.
 *
 * @param {object} opts
 * @param {string} opts.scanRoot - project root; entries are only written
 *   when it looks like a real project (same safety check mcp/audit.js
 *   uses) so a scratch/temp scanRoot never accumulates an audit file.
 * @param {object} opts.decision - the object evaluateEgress() returned:
 *   { allowed, decision, reason?, provider, policySource, purpose }.
 * @param {object} [opts.ctx] - the SAME ctx object passed to evaluateEgress
 *   — only `model` and `region` are read from it (if present); nothing
 *   else is retained.
 * @param {object} [opts.metrics] - the result of payloadMetrics(text), or
 *   omitted entirely for a denied call where no payload was ever built.
 */
export function recordEgressCall({ scanRoot, decision, ctx = {}, metrics = null } = {}) {
  if (!scanRoot || !decision) return;
  try {
    if (!_hasProjectMarker(scanRoot)) return;
    const dir = stateDir(scanRoot);
    fs.mkdirSync(dir, { recursive: true });
    const logFile = path.join(dir, LOG_FILE_NAME);
    const entry = {
      ts: new Date().toISOString(),
      sessionId: SESSION_ID,
      purpose: decision.purpose || ctx.purpose || 'unknown',
      provider: decision.provider || 'unknown',
      model: typeof ctx.model === 'string' ? ctx.model : null,
      region: typeof ctx.region === 'string' ? ctx.region : null,
      policy: { policySource: decision.policySource || 'default' },
      outcome: decision.decision || (decision.allowed ? 'allow' : 'deny'),
      ...(decision.reason ? { reason: decision.reason } : {}),
      byteCount: metrics ? metrics.byteCount : null,
      tokenCount: metrics ? metrics.tokenCount : null,
      contentHash: metrics ? metrics.contentHash : null,
      prev: _readLastEntryHash(logFile),
    };
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  } catch { /* audit failure must never break the call it is auditing */ }
}

// Verify the chain from start to end — same contract as mcp/audit.js's
// verifyAuditLog: { ok: true, entries: N } if intact, or
// { ok: false, brokenAt, expected, got } at the first broken link.
export function verifyEgressAuditLog(logFile) {
  // Read-first, not existsSync()-then-readFileSync() (D-0012) — the file can
  // vanish between those two calls; ENOENT is the expected "no log yet" case.
  let text;
  try {
    text = fs.readFileSync(logFile, 'utf8');
  } catch {
    return { ok: true, entries: 0 };
  }
  const lines = text.split('\n').filter(Boolean);
  let expectedPrev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let entry;
    try { entry = JSON.parse(lines[i]); }
    catch { return { ok: false, brokenAt: i, reason: 'not JSON' }; }
    if (entry.prev !== expectedPrev) {
      return { ok: false, brokenAt: i, expected: expectedPrev, got: entry.prev };
    }
    expectedPrev = _sha(lines[i]);
  }
  return { ok: true, entries: lines.length };
}

export const _internals = { LOG_FILE_NAME, GENESIS, _hasProjectMarker, _readLastEntryHash };
