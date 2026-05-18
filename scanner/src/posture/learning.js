// Active learning loop (FR-PREC-4).
//
// Consumes user triage decisions written by /triage to
// .agentic-security/triage-feedback.json and uses them as priors on the
// next scan:
//   - Findings whose `stableId` was previously marked false-positive get
//     suppressed (with a recorded reason).
//   - Findings whose `family + file-pattern + sink-pattern` matches a FP
//     pattern in past feedback also get suppressed.
//   - Findings whose stableId was previously marked true-positive get a
//     small confidence boost.
//
// File shape:
//   {
//     "entries": [
//       { "stableId": "...", "verdict": "tp" | "fp" | "wontfix", "reason": "...",
//         "family": "...", "filePattern": "src/auth/*.js", "sinkPattern": "...",
//         "at": "2026-05-18T..." }
//     ]
//   }

import * as fs from 'node:fs';
import * as path from 'node:path';

const FILE = '.agentic-security/triage-feedback.json';

export function loadFeedback(scanRoot) {
  if (!scanRoot) return { entries: [] };
  const fp = path.join(scanRoot, FILE);
  if (!fs.existsSync(fp)) return { entries: [] };
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')) || { entries: [] }; }
  catch { return { entries: [] }; }
}

export function saveFeedback(scanRoot, data) {
  if (!scanRoot) return;
  const fp = path.join(scanRoot, FILE);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, JSON.stringify(data, null, 2));
}

export function recordVerdict(scanRoot, finding, verdict, reason) {
  if (!['tp', 'fp', 'wontfix'].includes(verdict)) {
    throw new Error(`invalid verdict: ${verdict}`);
  }
  const data = loadFeedback(scanRoot);
  data.entries = data.entries || [];
  data.entries.push({
    stableId: finding.stableId || null,
    verdict,
    reason: reason || '',
    family: finding.family || null,
    file: finding.file || null,
    line: finding.line || null,
    vuln: finding.vuln || null,
    sinkSnippet: (finding.sink?.snippet || finding.snippet || '').slice(0, 200),
    at: new Date().toISOString(),
  });
  saveFeedback(scanRoot, data);
}

function matchesPattern(filePath, pattern) {
  if (!pattern) return true;
  // Very small glob — supports `*` and `**` only; sufficient for triage entries.
  const regex = new RegExp(
    '^' +
    pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '@@DOUBLE@@')
      .replace(/\*/g, '[^/]*')
      .replace(/@@DOUBLE@@/g, '.*') +
    '$'
  );
  return regex.test(filePath);
}

// Apply feedback to a freshly produced set of findings. Returns
// { kept: Finding[], suppressed: SuppressionLogEntry[] }.
//
// SAFETY (post-premortem R3.3):
//   - DEFAULT OFF: only consulted when AGENTIC_SECURITY_LEARN=1.
//   - QUORUM: a stableId is suppressed only after ≥ AGENTIC_SECURITY_LEARN_QUORUM
//     distinct fp entries (default 2).
//   - CAP: most-recent 500 entries by `at` timestamp are honored — bounds
//     the poisoning blast radius.
//   - PATTERN MATCHES require ≥ quorum entries with the same family+filePattern.
export function applyFeedback(scanRoot, findings) {
  const suppressed = [];
  // OPT-IN gate.
  if (process.env.AGENTIC_SECURITY_LEARN !== '1') return { kept: findings, suppressed };
  const data = loadFeedback(scanRoot);
  if (!data.entries || !data.entries.length) return { kept: findings, suppressed };
  const quorum = Math.max(1, parseInt(process.env.AGENTIC_SECURITY_LEARN_QUORUM || '2', 10));
  // Keep the most recent 500 entries by `at`.
  const sorted = [...data.entries].sort((a, b) => String(a.at || '').localeCompare(String(b.at || ''))).slice(-500);
  const fpCountById = new Map();
  const fpById = new Map();
  const tpById = new Set();
  const patternCounts = new Map();
  for (const e of sorted) {
    if (e.verdict === 'fp') {
      if (e.stableId) {
        fpCountById.set(e.stableId, (fpCountById.get(e.stableId) || 0) + 1);
        if (!fpById.has(e.stableId)) fpById.set(e.stableId, e);
      }
      if (e.family && (e.file || e.sinkSnippet)) {
        const k = `${e.family}|${e.file ? e.file.split('/').slice(0, -1).join('/') + '/*' : ''}|${(e.sinkSnippet || '').slice(0, 80)}`;
        patternCounts.set(k, (patternCounts.get(k) || 0) + 1);
      }
    } else if (e.verdict === 'tp') {
      if (e.stableId) tpById.add(e.stableId);
    }
  }
  // Drop stableIds below quorum.
  for (const [id, count] of fpCountById) {
    if (count < quorum) fpById.delete(id);
  }
  // Build pattern list — only patterns at quorum.
  const fpPatterns = [];
  for (const [key, count] of patternCounts) {
    if (count < quorum) continue;
    const [family, filePattern, sinkSnippet] = key.split('|');
    fpPatterns.push({
      family: family || null,
      filePattern: filePattern || null,
      sinkSnippet: sinkSnippet || '',
      reason: `quorum-${count}-fp-votes`,
    });
  }
  const kept = [];
  for (const f of findings) {
    if (!f) continue;
    // Direct stableId match → suppress
    if (f.stableId && fpById.has(f.stableId)) {
      suppressed.push({
        vuln: f.vuln, file: f.file, line: f.line, snippet: f.snippet,
        reason: 'learned-fp:' + (fpById.get(f.stableId).reason || 'past-triage'),
      });
      continue;
    }
    // Pattern match
    let patternHit = null;
    for (const p of fpPatterns) {
      if (p.family && f.family !== p.family) continue;
      if (p.filePattern && !matchesPattern(f.file || '', p.filePattern)) continue;
      const sinkText = (f.sink?.snippet || f.snippet || '').slice(0, 80);
      if (p.sinkSnippet && sinkText.includes(p.sinkSnippet.slice(0, 30))) {
        patternHit = p; break;
      }
    }
    if (patternHit) {
      suppressed.push({
        vuln: f.vuln, file: f.file, line: f.line, snippet: f.snippet,
        reason: 'learned-fp-pattern:' + (patternHit.reason || 'past-triage'),
      });
      continue;
    }
    // TP boost — small confidence bump.
    if (f.stableId && tpById.has(f.stableId)) {
      f.confidence = Math.min(1, (f.confidence || 0.5) + 0.10);
      f._learned = 'tp-prior';
    }
    kept.push(f);
  }
  return { kept, suppressed };
}
