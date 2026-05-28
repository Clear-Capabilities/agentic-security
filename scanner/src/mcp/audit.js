// Append-only audit log of MCP tool calls — OWASP MCP08.
//
// Format: one JSON object per line (NDJSON) at
//   <sessionRoot>/.agentic-security/mcp-audit.log
//
// Each entry carries `prev` — the SHA-256 of the previous entry's serialized
// form. The first entry's prev is "GENESIS". Tampering with any line breaks
// the chain from that point forward; a reader can detect partial truncation
// or in-place edits.
//
// REMOTE SINK (post-recommendation #10). The local file alone cannot detect
// a total rewrite — an attacker with FS write can re-author the whole log
// with fresh hashes. Closing that blind spot requires an off-host witness.
// Set $AGENTIC_SECURITY_AUDIT_WEBHOOK to a POST endpoint; every entry is
// fire-and-forget POSTed there in addition to the local append. Failures
// to reach the webhook are best-effort — they NEVER block a tool call,
// because that would let a network outage become a denial of service. They
// DO get recorded as `_remoteSinkErr` on the local entry, so an operator
// reviewing the log later can spot a forging attempt that targeted the
// remote (any gap between local-sequence and remote-sequence is evidence).
//
// Argument blobs are redacted (OWASP MCP01/MCP10) so credentials passed in
// arguments cannot leak via the audit trail OR via the remote sink.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { redactArgsBlob } from './redact.js';

const MAX_ARG_BYTES = 1024;
const GENESIS = 'GENESIS';
const REMOTE_TIMEOUT_MS = 1500;

// Per-process session ID (harness-anatomy #9). Stamped on every audit entry
// so downstream metrics can aggregate by session and surface outliers like
// "200 apply_fix calls in one session." The ID is `<pid>-<short-ts>` — not
// cryptographically unique, but enough to disambiguate concurrent runs on
// the same host. Stable for the lifetime of this Node process.
const SESSION_ID = `${process.pid}-${Date.now().toString(36).slice(-6)}`;

function _summarize(args) {
  let s;
  try { s = JSON.stringify(args); } catch { s = '<unserializable>'; }
  s = redactArgsBlob(s);
  if (s.length > MAX_ARG_BYTES) s = s.slice(0, MAX_ARG_BYTES) + `…(+${s.length - MAX_ARG_BYTES})`;
  return s;
}

function _sha(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function _readLastEntryHash(logFile) {
  if (!fs.existsSync(logFile)) return GENESIS;
  try {
    const all = fs.readFileSync(logFile, 'utf8');
    const lines = all.split('\n').filter(Boolean);
    if (!lines.length) return GENESIS;
    return _sha(lines[lines.length - 1]);
  } catch { return GENESIS; }
}

// Fire-and-forget POST to the remote sink. Resolves to null on success,
// to a short error string on failure. Never throws; never blocks longer
// than REMOTE_TIMEOUT_MS. The local audit append happens regardless.
async function _postRemote(url, entry) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), REMOTE_TIMEOUT_MS);
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry),
      signal: controller.signal,
    });
    clearTimeout(t);
    if (!r.ok) return `HTTP ${r.status}`;
    return null;
  } catch (e) {
    return String((e && e.message) || e).slice(0, 200);
  }
}

export function auditCall({ sessionRoot, tool, args, outcome, reason }) {
  if (!sessionRoot) return;
  try {
    // Safety: only write audit log if sessionRoot looks like a project root
    const MARKERS = ['.git', 'package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'pom.xml', 'composer.json', 'Gemfile'];
    let hasMarker = false;
    for (const m of MARKERS) { try { if (fs.existsSync(path.join(sessionRoot, m))) { hasMarker = true; break; } } catch {} }
    if (!hasMarker) return;
    const dir = path.join(sessionRoot, '.agentic-security');
    fs.mkdirSync(dir, { recursive: true });
    const logFile = path.join(dir, 'mcp-audit.log');
    const entry = {
      ts: new Date().toISOString(),
      sessionId: SESSION_ID,
      tool,
      outcome,
      ...(reason ? { reason } : {}),
      args: _summarize(args),
      prev: _readLastEntryHash(logFile),
    };
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
    // Remote sink (post-recommendation #10). Fire-and-forget. We don't await
    // the promise so the tool call returns immediately; the remote POST runs
    // on its own microtask. Failures get logged to a sidecar file so the
    // operator can detect when the sink is unreachable.
    const webhook = process.env.AGENTIC_SECURITY_AUDIT_WEBHOOK;
    if (webhook) {
      _postRemote(webhook, entry).then((err) => {
        if (!err) return;
        try {
          const errFile = path.join(dir, 'mcp-audit.remote-errors.log');
          fs.appendFileSync(errFile, JSON.stringify({
            ts: new Date().toISOString(), entryTs: entry.ts, tool, err,
          }) + '\n');
        } catch { /* nothing else to do */ }
      });
    }
  } catch { /* audit failure must never break a tool call */ }
}

// Verify the chain from start to end. Returns
//   { ok: true, entries: N } if intact
//   { ok: false, brokenAt: <line-index>, expected, got } if any link breaks
// Reader/operator-facing tool.
export function verifyAuditLog(logFile) {
  if (!fs.existsSync(logFile)) return { ok: true, entries: 0 };
  const text = fs.readFileSync(logFile, 'utf8');
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
