// Findings memory — natural-language Q&A over the institutional knowledge
// the scanner has accumulated. Backs the MCP query_findings_memory tool.
//
// Sources searched, in this order:
//
//   1. .agentic-security/last-scan.json          current findings
//   2. .agentic-security/triage-memory.jsonl     past wont-fix / FP decisions
//   3. .agentic-security/scan-history/*.json     prior scans
//   4. .agentic-security/AGENTS.md               continual-learning narrative
//
// Naive keyword matching for v1. Each match has a `score` (count of query
// terms matched) and a `source` ('finding' | 'triage' | 'history' |
// 'agents-md'). Returns top-10 by score.

import * as fs from 'node:fs';
import * as path from 'node:path';

const STATE = '.agentic-security';

function _read(scanRoot, name) {
  try { return fs.readFileSync(path.join(scanRoot, STATE, name), 'utf8'); } catch { return null; }
}

function _readJson(scanRoot, name) {
  const raw = _read(scanRoot, name);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function _terms(query) {
  return String(query || '').toLowerCase().split(/\s+/).filter(t => t.length >= 2);
}

function _score(haystack, terms) {
  const lower = String(haystack || '').toLowerCase();
  let s = 0;
  for (const t of terms) if (lower.includes(t)) s++;
  return s;
}

function _findingHaystack(f) {
  return [f.vuln, f.family, f.file, f.severity, f.description, f.cwe, f.id]
    .filter(Boolean).join(' | ');
}

function _truncate(s, n = 160) {
  return String(s || '').replace(/\s+/g, ' ').slice(0, n);
}

/**
 * Run a natural-language query over the scanner's accumulated memory.
 */
export function queryFindingsMemory(scanRoot, query) {
  const terms = _terms(query);
  if (!terms.length) return { results: [], count: 0 };

  const results = [];

  // 1. Current findings.
  const scan = _readJson(scanRoot, 'last-scan.json');
  if (scan && Array.isArray(scan.findings)) {
    for (const f of scan.findings) {
      const hay = _findingHaystack(f);
      const score = _score(hay, terms);
      if (!score) continue;
      results.push({
        source: 'finding',
        score,
        finding_id: f.id || null,
        severity: f.severity,
        family: f.family,
        file: f.file,
        line: f.line,
        snippet: _truncate(f.vuln || f.description || f.family),
      });
    }
  }

  // 2. Triage memory (past decisions).
  const triageRaw = _read(scanRoot, 'triage-memory.jsonl');
  if (triageRaw) {
    const lines = triageRaw.split('\n').filter(Boolean);
    for (const ln of lines) {
      let entry; try { entry = JSON.parse(ln); } catch { continue; }
      const hay = [entry.decision, entry.reason, entry.family, entry.vuln, entry.file].join(' ');
      const score = _score(hay, terms);
      if (!score) continue;
      results.push({
        source: 'triage',
        score,
        decision: entry.decision,
        at: entry.at,
        family: entry.family,
        snippet: _truncate(entry.reason || entry.vuln),
        bucket: entry.bucket,
      });
    }
  }

  // 3. Scan history.
  try {
    const histDir = path.join(scanRoot, STATE, 'scan-history');
    if (fs.existsSync(histDir)) {
      const files = fs.readdirSync(histDir).filter(f => f.endsWith('.json')).slice(-10);
      for (const f of files) {
        try {
          const hist = JSON.parse(fs.readFileSync(path.join(histDir, f), 'utf8'));
          if (!Array.isArray(hist.findings)) continue;
          for (const x of hist.findings.slice(0, 50)) {
            const hay = _findingHaystack(x);
            const score = _score(hay, terms);
            if (!score) continue;
            results.push({
              source: 'history',
              score,
              from: f.replace(/\.json$/, ''),
              severity: x.severity,
              family: x.family,
              file: x.file,
              snippet: _truncate(x.vuln || x.description),
            });
          }
        } catch {}
      }
    }
  } catch {}

  // 4. AGENTS.md narrative.
  const agents = _read(scanRoot, 'AGENTS.md');
  if (agents) {
    const sections = agents.split(/^##\s+/m);
    for (const sec of sections) {
      const score = _score(sec, terms);
      if (!score) continue;
      const title = sec.split('\n')[0] || '';
      results.push({
        source: 'agents-md',
        score,
        title: _truncate(title, 80),
        snippet: _truncate(sec.replace(title, ''), 200),
      });
    }
  }

  // Top-10 by score, ties broken by source priority (finding > triage >
  // history > agents-md so live data wins).
  const PRI = { finding: 4, triage: 3, history: 2, 'agents-md': 1 };
  results.sort((a, b) => (b.score - a.score) || (PRI[b.source] - PRI[a.source]));
  return { results: results.slice(0, 10), count: results.length };
}

export const _internals = { _terms, _score, _findingHaystack };
