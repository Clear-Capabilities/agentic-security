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

import * as fs from 'node:fs';
import * as path from 'node:path';

import { stateWritesEnabled } from './state-dir.js';
const STATE_DIR = '.agentic-security';
const MEMORY_FILE = 'triage-memory.jsonl';
const AGENTS_FILE = 'AGENTS.md';

function _stateDir(scanRoot) { return path.join(scanRoot, STATE_DIR); }
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
export function recordDecision(scanRoot, finding, decision, reason) {
  if (!scanRoot || !finding || !decision) return null;
  if (!['wont-fix', 'false-positive'].includes(decision)) return null;
  if (!stateWritesEnabled()) return false;
  try { fs.mkdirSync(_stateDir(scanRoot), { recursive: true }); } catch {}

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
  };
  try { fs.appendFileSync(_memPath(scanRoot), JSON.stringify(entry) + '\n'); } catch {}

  // Narrative entry in AGENTS.md — short, human-readable, surfaced at SessionStart.
  const narrative = [
    `## Triage decision — ${entry.at.slice(0, 10)}  (${decision})`,
    `- Finding: ${entry.vuln || entry.family || 'unknown'} at ${entry.file}:${entry.line}`,
    `- Bucket: \`${entry.bucket}\``,
    reason ? `- Why: ${entry.reason}` : null,
    `- Future scans should treat similar findings under this bucket as already-reviewed.`,
    '',
  ].filter(Boolean).join('\n');
  try { fs.appendFileSync(_agentsPath(scanRoot), '\n' + narrative); } catch {}

  return entry;
}

/**
 * Load past decisions from triage-memory.jsonl.
 */
export function loadMemory(scanRoot) {
  const fp = _memPath(scanRoot);
  if (!fs.existsSync(fp)) return [];
  try {
    return fs.readFileSync(fp, 'utf8')
      .split('\n').filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
  } catch { return []; }
}

/**
 * Annotator: for each finding, check if its (family, file-glob) bucket
 * was previously marked wont-fix or false-positive in this project. If
 * so, attach `pastDecision` metadata and lower confidence.
 *
 * Does NOT remove findings — only annotates. UI / report layer decides
 * how to display.
 */
export function suppressByPastDecisions(scanRoot, findings) {
  if (process.env.AGENTIC_SECURITY_NO_TRIAGE_MEMORY === '1') return { applied: 0 };
  if (!Array.isArray(findings) || findings.length === 0) return { applied: 0 };
  const memory = loadMemory(scanRoot);
  if (!memory.length) return { applied: 0 };

  // Build bucket → most-recent decision map.
  const bucketDecision = new Map();
  for (const e of memory) {
    if (!bucketDecision.has(e.bucket) || bucketDecision.get(e.bucket).at < e.at) {
      bucketDecision.set(e.bucket, e);
    }
  }

  let applied = 0;
  for (const f of findings) {
    const key = _bucketKey(f);
    const past = bucketDecision.get(key);
    if (!past) continue;
    f.pastDecision = {
      decision: past.decision,
      at: past.at,
      reason: past.reason,
      sameBucket: true,
    };
    // Soft demote: drop confidence and add a tag explaining why.
    if (typeof f.confidence === 'number') f.confidence = Math.max(0.2, f.confidence * 0.5);
    f.tags = Array.isArray(f.tags) ? f.tags : [];
    if (!f.tags.includes('past-decision')) f.tags.push('past-decision');
    applied++;
  }
  return { applied, total: findings.length };
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
