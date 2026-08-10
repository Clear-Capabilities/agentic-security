// AGENTS.md — writable continual-learning memory (harness-anatomy #2).
//
// LangChain post:
//   "Harnesses support memory file standards like AGENTS.md which get
//    injected into context on agent start. As agents add and edit this file,
//    harnesses load the updated file into context. This is a form of
//    continual learning where agents durably store knowledge from one
//    session and inject that knowledge into future sessions."
//
// Distinct from CLAUDE.md:
//   - CLAUDE.md = human-authored project conventions, gotchas, layout.
//   - AGENTS.md = agent-authored notes ("what worked / didn't work / I'd try
//                  differently next time"). Append-only. Bounded.
//
// Lives at `<project>/.agentic-security/AGENTS.md`.
//
// Bounds:
//   - MAX_BYTES (default 20 KB) — past this, the oldest entries rotate to
//     `AGENTS.md.archive` (also bounded; oldest archive entries are dropped).
//   - MAX_ENTRY_BYTES (default 2 KB) — caps a single appendage.
//   - Entries are append-only with an ISO timestamp + section divider, so
//     readers can grep / slice by date without parsing.
//
// We deliberately avoid tying AGENTS.md to a session-id namespace. The post's
// recommendation is FLAT continual learning — the whole project's agents see
// each other's notes. Subagents that want session-scoped scratch use the
// agent-scratchpad surface instead.

import * as fs from 'node:fs';
import * as path from 'node:path';

import { statePath, stateWritesEnabled } from './state-dir.js';
const MEMORY_FILE = '.agentic-security/AGENTS.md';
const ARCHIVE_FILE = '.agentic-security/AGENTS.md.archive';
const MAX_BYTES = 20 * 1024;
const MAX_ENTRY_BYTES = 2 * 1024;
const ARCHIVE_MAX_BYTES = 200 * 1024;
const HEADER = '# AGENTS.md\n\nAgent-authored continual-learning notes. Each entry: timestamp + agent name + one short paragraph. New entries appended at the bottom; oldest entries rotate to AGENTS.md.archive when this file exceeds 20 KB.\n\n';

function _resolve(scanRoot) { return statePath(scanRoot, 'AGENTS.md'); }
function _archivePath(scanRoot) { return statePath(scanRoot, 'AGENTS.md.archive'); }

export function readAgentsMemory(scanRoot) {
  const fp = _resolve(scanRoot);
  if (!fs.existsSync(fp)) return '';
  try { return fs.readFileSync(fp, 'utf8'); } catch { return ''; }
}

export function appendAgentsMemory(scanRoot, { agent, body }) {
  if (typeof agent !== 'string' || !agent.length) {
    return { ok: false, reason: 'agent: required string' };
  }
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(agent)) {
    return { ok: false, reason: 'agent: must match [A-Za-z0-9_.-]{1,64}' };
  }
  if (typeof body !== 'string' || !body.trim().length) {
    return { ok: false, reason: 'body: required non-empty string' };
  }
  let snippet = body.trim();
  // Strip control chars and cap.
  snippet = snippet.replace(/[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]/g, ' ');
  if (snippet.length > MAX_ENTRY_BYTES) {
    snippet = snippet.slice(0, MAX_ENTRY_BYTES) + '…';
  }
  const ts = new Date().toISOString();
  const entry = `\n## ${ts}  agent: ${agent}\n\n${snippet}\n`;
  try {
    const fp = _resolve(scanRoot);
    if (!stateWritesEnabled()) return;
  fs.mkdirSync(path.dirname(fp), { recursive: true });
    if (!fs.existsSync(fp)) fs.writeFileSync(fp, HEADER);
    fs.appendFileSync(fp, entry);
    _maybeRotate(scanRoot);
    const stat = fs.statSync(fp);
    return { ok: true, entryBytes: entry.length, fileSize: stat.size };
  } catch (e) {
    return { ok: false, reason: `write-failed: ${e.message}` };
  }
}

function _maybeRotate(scanRoot) {
  const fp = _resolve(scanRoot);
  let body;
  try { body = fs.readFileSync(fp, 'utf8'); } catch { return; }
  if (body.length <= MAX_BYTES) return;
  // Split on the `## ` entry headers. Keep the most-recent N until the head
  // (everything before the cut) drops below MAX_BYTES/2; move the head to
  // the archive.
  const head = HEADER;
  const trailing = body.slice(head.length);
  const sections = trailing.split(/(?=\n## )/g).filter(s => s.length);
  // Walk from the end, accumulating until we have roughly MAX_BYTES/2 of
  // recent entries. Everything else goes to the archive.
  let kept = '', archive = '', accum = 0;
  for (let i = sections.length - 1; i >= 0; i--) {
    if (accum + sections[i].length <= MAX_BYTES / 2) {
      kept = sections[i] + kept;
      accum += sections[i].length;
    } else {
      archive = sections.slice(0, i + 1).join('') + archive;
      break;
    }
  }
  try {
    fs.writeFileSync(fp, head + kept);
    if (archive.length) {
      const arcFp = _archivePath(scanRoot);
      let existing = '';
      try { existing = fs.existsSync(arcFp) ? fs.readFileSync(arcFp, 'utf8') : ''; } catch {}
      let next = existing + archive;
      if (next.length > ARCHIVE_MAX_BYTES) {
        // Drop oldest entries until under cap.
        const oldestSplit = next.split(/(?=\n## )/g).filter(s => s.length);
        while (oldestSplit.length && next.length > ARCHIVE_MAX_BYTES) {
          oldestSplit.shift();
          next = oldestSplit.join('');
        }
      }
      fs.writeFileSync(arcFp, next);
    }
  } catch { /* best-effort rotation */ }
}

// Public summary helper for the SessionStart hook. Returns a tail aligned
// to a section header (no leading partial entry, no leading newline).
export function summarizeForSession(scanRoot, { maxBytes = 6 * 1024 } = {}) {
  const body = readAgentsMemory(scanRoot);
  if (!body) return null;
  if (body.length <= maxBytes) return body;
  const tail = body.slice(-maxBytes);
  const firstSection = tail.indexOf('\n## ');
  if (firstSection < 0) return tail;
  // Slice past the leading `\n` so the result starts with `## `.
  return tail.slice(firstSection + 1);
}

export const _internals = { MAX_BYTES, MAX_ENTRY_BYTES, MEMORY_FILE, ARCHIVE_FILE };
