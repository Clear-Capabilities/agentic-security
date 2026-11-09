// Triage memory — conversational triage memory layer.
//
// When a finding transitions to wont-fix or false-positive (via the
// triage CLI / MCP tool / agent action), this module:
//
//   1. writes a structured entry to AGENTS.md so the lesson is captured
//      for next session (continual-learning surface),
//   2. records the decision shape (family + file-glob + reason) into
//      .agentic-security/triage-memory.jsonl for fast pattern matching,
//   3. provides suppressByPastDecisions() — an annotator that pre-demotes
//      findings whose (family, file-glob) was previously marked wont-fix
//      or false-positive in the same project.
//
// This is the dialogue-aware analogue to posture/triage-learning.js,
// which adjusts confidence calibration from triage counts. triage-memory
// works on the discrete narrative ("we decided this is fine, here's
// why") rather than on calibration math.
//
// Opt-out: AGENTIC_SECURITY_NO_TRIAGE_MEMORY=1
//
// Threat-model PRD FR-05 (TM-07): a family/directory bucket, and any legacy free-text record, is ADVISORY history. It is attached to
// a finding so a reviewer can see it, and it never changes the finding's confidence. Only an EXACT decision (the same stable finding
// id in the same file) applies, and for a critical or high finding it also needs a named reviewer, an expiry that has not passed, a
// scope that matches this scan, an unchanged source fingerprint and a signature made with this install's key. Each finding's
// `pastDecision.status` says which: applied, advisory, expired, stale, out-of-scope or rejected. The free-text reason stays in the
// memory file and is never copied into a report.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { signLastScan } from './integrity.js';

import { stateDir, stateWritesEnabled } from './state-dir.js';
const MEMORY_FILE = 'triage-memory.jsonl';
const AGENTS_FILE = 'AGENTS.md';

function _stateDir(scanRoot) { return stateDir(scanRoot); }
function _memPath(scanRoot)  { return path.join(_stateDir(scanRoot), MEMORY_FILE); }
function _agentsPath(scanRoot) { return path.join(_stateDir(scanRoot), AGENTS_FILE); }

function _bucketKey(finding) {
  const file = finding.file || finding.file_path || '';
  const dir = file.split('/').slice(0, -1).join('/') || '.';
  return `${finding.family || finding.parser || 'unknown'}::${dir}`;
}

/**
 * Record a triage decision into both AGENTS.md (narrative) and
 * triage-memory.jsonl (structured). Idempotent — repeated calls add a
 * single new line; existing entries are not deduped (history is a feature).
 */
export function recordDecision(scanRoot, finding, decision, reason, opts = {}) {
  if (!scanRoot || !finding || !decision) return null;
  if (!['wont-fix', 'false-positive'].includes(decision)) return null;
  if (!stateWritesEnabled()) return false;
  try { fs.mkdirSync(_stateDir(scanRoot), { recursive: true }); } catch {}
  // a retried call with the same decision for the same finding adds nothing (idempotent under retry)
  const sid = finding.stableId || finding.id || null;
  const prior = loadMemory(scanRoot).find((e) => e.stableId && e.stableId === sid && e.decision === decision && e.file === (finding.file || finding.file_path || '') && (e.reviewer || null) === (opts.reviewer || null) && (e.expires || null) === (opts.expires || null));
  if (prior) return prior;

  const entry = {
    at: new Date().toISOString(),
    decision,
    reason: String(reason || '').slice(0, 280),
    bucket: _bucketKey(finding),
    family: finding.family || null,
    severity: finding.severity || null,
    cwe: finding.cwe || null,
    vuln: (finding.vuln || finding.title || '').slice(0, 160),
    file: finding.file || finding.file_path || '',
    line: finding.line || 0,
    id: finding.id || finding.stableId || null,
    // exact binding (FR-05.1): the stable id, the source fingerprint the decision was made on, and its scope, reviewer and expiry
    stableId: sid,
    fingerprint: findingFingerprint(finding),
    ...(opts.reviewer ? { reviewer: String(opts.reviewer).slice(0, 120) } : {}),
    ...(opts.expires ? { expires: String(opts.expires) } : {}),
    ...(opts.scope ? { scope: pickScope(opts.scope) } : {}),
  };
  if (entry.reviewer && entry.expires) entry.sig = signEntry(entry);
  try { fs.appendFileSync(_memPath(scanRoot), JSON.stringify(entry) + '\n'); } catch {}

  // Narrative entry in AGENTS.md — short, human-readable, surfaced at SessionStart.
  const narrative = [
    `## Triage decision — ${entry.at.slice(0, 10)}  (${decision})`,
    `- Finding: ${entry.vuln || entry.family || 'unknown'} at ${entry.file}:${entry.line}`,
    `- Bucket: \`${entry.bucket}\``,
    reason ? `- Why: ${entry.reason}` : null,
    `- Advisory only: similar findings under this bucket are NOT reviewed by this decision; each new finding is judged on its own.`,
    '',
  ].filter(Boolean).join('\n');
  try { fs.appendFileSync(_agentsPath(scanRoot), '\n' + narrative); } catch {}

  return entry;
}

/**
 * Load past decisions from triage-memory.jsonl.
 */
export function loadMemory(scanRoot) { return loadMemoryWithDiagnostics(scanRoot).entries; }

const MAX_MEMORY_BYTES = 8 * 1024 * 1024;
/** Load past decisions with bounded diagnostics: malformed lines (a torn write) are counted and skipped, never fatal. */
export function loadMemoryWithDiagnostics(scanRoot) {
  const fp = _memPath(scanRoot);
  const out = { entries: [], malformed: 0, unreadable: false, truncated: false };
  let text;
  try {
    const st = fs.statSync(fp);
    if (st.size > MAX_MEMORY_BYTES) out.truncated = true;
    const fd = fs.openSync(fp, 'r');
    try { const buf = Buffer.alloc(Math.min(st.size, MAX_MEMORY_BYTES)); fs.readSync(fd, buf, 0, buf.length, 0); text = buf.toString('utf8'); } finally { fs.closeSync(fd); }
  } catch (e) { if (e && e.code !== 'ENOENT') out.unreadable = true; return out; }
  for (const l of text.split('\n')) {
    if (!l.trim()) continue;
    try { const e = JSON.parse(l); if (e && typeof e === 'object' && !Array.isArray(e)) out.entries.push(e); else out.malformed++; } catch { out.malformed++; }
  }
  return out;
}

// ── exact decisions (threat-model FR-05) ─────────────────────────────────────────────────────────────────────────────────────────────
const SCOPE_KEYS = ['repository', 'environment', 'tenant'];
function pickScope(s) { const o = {}; for (const k of SCOPE_KEYS) if (s && s[k]) o[k] = String(s[k]).slice(0, 120); return o; }
/** The source fingerprint a decision is bound to: the finding record's source hash when there is one, else its location and snippet. */
function findingFingerprint(f) {
  const h = f.findingRecord?.sourceHash || f.record?.sourceHash || f.sourceHash;
  if (h) return String(h);
  return crypto.createHash('sha256').update(JSON.stringify([f.file || '', f.line || 0, f.cwe || '', String(f.snippet || '').slice(0, 400)])).digest('hex');
}
const SIGNED_FIELDS = ['decision', 'stableId', 'file', 'fingerprint', 'reviewer', 'expires', 'scope'];
function canonicalEntry(e) { return JSON.stringify(SIGNED_FIELDS.map((k) => [k, e[k] ?? null])); }
function signEntry(e) { return signLastScan(canonicalEntry(e)); }
function signatureValid(e) {
  if (typeof e.sig !== 'string') return false;
  const want = signEntry(e);
  return want.length === e.sig.length && crypto.timingSafeEqual(Buffer.from(want, 'hex'), Buffer.from(e.sig, 'hex'));
}
const CONSEQUENTIAL = new Set(['critical', 'high']);

/** How one exact decision bears on one finding now: applied | expired | out-of-scope | stale | advisory | rejected, with a reason code. */
function judgeExact(e, f, ctx) {
  const now = ctx.now ?? Date.now();
  if (e.expires && !(Date.parse(e.expires) > now)) return { status: 'expired', code: 'expired' };
  for (const k of SCOPE_KEYS) if (e.scope && e.scope[k] && ctx[k] && e.scope[k] !== ctx[k]) return { status: 'out-of-scope', code: `${k}-differs` };
  if (e.fingerprint && e.fingerprint !== findingFingerprint(f)) return { status: 'stale', code: 'source-changed' };
  if (CONSEQUENTIAL.has(f.severity)) {
    if (!e.reviewer || !e.expires) return { status: 'advisory', code: 'unreviewed-or-unexpiring' };
    if (!signatureValid(e)) return { status: 'rejected', code: e.sig ? 'signature-invalid' : 'unsigned' };
  }
  return { status: 'applied', code: 'exact-match' };
}
const reasonDigest = (r) => (r ? crypto.createHash('sha256').update(String(r)).digest('hex').slice(0, 16) : null);

/**
 * Annotator: for each finding, check if its (family, file-glob) bucket
 * was previously marked wont-fix or false-positive in this project. If
 * so, attach `pastDecision` metadata and lower confidence.
 *
 * Does NOT remove findings — only annotates. UI / report layer decides
 * how to display.
 */
export function suppressByPastDecisions(scanRoot, findings, ctx = {}) {
  if (process.env.AGENTIC_SECURITY_NO_TRIAGE_MEMORY === '1') return { applied: 0 };
  if (!Array.isArray(findings) || findings.length === 0) return { applied: 0 };
  const diag = loadMemoryWithDiagnostics(scanRoot);
  const memory = diag.entries;
  if (!memory.length) return { applied: 0, diagnostics: { malformed: diag.malformed, unreadable: diag.unreadable, truncated: diag.truncated } };
  const exactById = new Map();
  for (const e of memory) {
    if (!e.stableId) continue;
    const k = `${e.stableId}\u0000${e.file || ''}`;
    if (!exactById.has(k) || exactById.get(k).at < e.at) exactById.set(k, e);
  }

  // Build bucket → most-recent decision map.
  const bucketDecision = new Map();
  for (const e of memory) {
    if (!bucketDecision.has(e.bucket) || bucketDecision.get(e.bucket).at < e.at) {
      bucketDecision.set(e.bucket, e);
    }
  }

  let applied = 0; let advisory = 0;
  const byStatus = {};
  for (const f of findings) {
    const exact = exactById.get(`${f.stableId || f.id || ''}\u0000${f.file || f.file_path || ''}`);
    const past = exact || bucketDecision.get(_bucketKey(f));
    if (!past) continue;
    const j = exact ? judgeExact(exact, f, ctx) : { status: 'advisory', code: 'family-directory-bucket' };
    byStatus[j.status] = (byStatus[j.status] || 0) + 1;
    // the reason is a digest here: the free text stays in the memory file and never reaches a report
    f.pastDecision = { status: j.status, basis: exact ? 'exact' : 'bucket', reasonCode: j.code, decision: past.decision, at: past.at, reasonDigest: reasonDigest(past.reason), ...(exact && exact.reviewer ? { reviewer: exact.reviewer } : {}), ...(exact && exact.expires ? { expires: exact.expires } : {}), sameBucket: !exact };
    f.tags = Array.isArray(f.tags) ? f.tags : [];
    if (j.status === 'applied') {
      // an exact, in-scope decision: the soft demote and tag, as before
      if (typeof f.confidence === 'number') f.confidence = Math.max(0.2, f.confidence * 0.5);
      if (!f.tags.includes('past-decision')) f.tags.push('past-decision');
      applied++;
    } else {
      if (!f.tags.includes('past-decision-advisory')) f.tags.push('past-decision-advisory');
      advisory++;
    }
  }
  return { applied, advisory, byStatus, total: findings.length, diagnostics: { malformed: diag.malformed, unreadable: diag.unreadable, truncated: diag.truncated } };
}

/** True only for a past decision that applies; an advisory, expired, stale, out-of-scope or rejected one leaves the finding open. */
export function pastDecisionApplies(pd) {
  if (pd === true) return true; // a legacy boolean marker set by an older caller
  return !!pd && typeof pd === 'object' && (pd.status === undefined || pd.status === 'applied');
}

/**
 * Search past triage decisions by natural-language query terms. Naive
 * keyword match for v1 — sufficient when memory is < 1000 entries.
 * Future: vector search against an embedding store.
 */
export function queryMemory(scanRoot, query) {
  const memory = loadMemory(scanRoot);
  if (!query || !memory.length) return memory.slice(-10);
  const terms = String(query).toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return memory.slice(-10);
  const scored = memory.map(e => {
    const haystack = [e.reason, e.vuln, e.family, e.file, e.bucket].join(' ').toLowerCase();
    const score = terms.reduce((s, t) => s + (haystack.includes(t) ? 1 : 0), 0);
    return { ...e, score };
  });
  return scored.filter(e => e.score > 0).sort((a, b) => b.score - a.score).slice(0, 10);
}

export const _internals = { _bucketKey, _memPath, _agentsPath };
