// PR-description auto-augmentation.
//
// Reads the current last-scan vs a baseline (git base branch or
// a stored snapshot), and produces a Markdown block suitable for
// injecting into a PR body via `gh pr edit --body` or chaining into
// `gh pr create`.
//
// Output sections:
//   1. Security delta summary (added / removed / changed by severity)
//   2. ATT&CK tactics covered by new findings
//   3. Suggested reviewers by class (auth changes → security; PII → privacy)
//   4. Links to relevant artifacts (threat-model, compliance-evidence,
//      PQC plan, exploit bundles) when present
//
// Pure render — does not call git or gh; caller orchestrates that.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { diffScans, summarizeDiff } from './baseline-compare.js';

const REVIEWER_TRIGGERS = [
  { family: /^auth/,                team: 'security', why: 'Auth-related findings' },
  { family: /^crypto/,              team: 'security', why: 'Cryptography findings' },
  { family: /^pii|gdpr|hipaa/i,     team: 'privacy',  why: 'PII / data-handling findings' },
  { family: /^iam|cloud|k8s/,       team: 'platform', why: 'Cloud / Kubernetes posture findings' },
  { family: /^supply|license|vuln/, team: 'platform', why: 'Supply-chain findings' },
  { family: /^llm|prompt|ml/,       team: 'ml',       why: 'LLM / ML supply-chain findings' },
  { family: /^web3|defi/,           team: 'security', why: 'Smart-contract findings' },
];

function _stateFile(scanRoot, name) {
  return path.join(scanRoot, '.agentic-security', name);
}

function _readJson(fp) {
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}

function _baselinePath(scanRoot, ref) {
  const safe = String(ref || 'main').replace(/[^\w.-]/g, '-');
  return path.join(scanRoot, '.agentic-security', 'scan-baselines', `${safe}.json`);
}

/**
 * Persist a scan snapshot under .agentic-security/scan-baselines/<ref>.json
 * so subsequent PRs can diff against it.
 */
export function persistBaseline(scanRoot, ref, scan) {
  const fp = _baselinePath(scanRoot, ref);
  try { fs.mkdirSync(path.dirname(fp), { recursive: true }); } catch {}
  try { fs.writeFileSync(fp, JSON.stringify({ ref, ts: new Date().toISOString(), findings: scan.findings || [] }, null, 2)); } catch {}
  return fp;
}

export function loadBaseline(scanRoot, ref) {
  return _readJson(_baselinePath(scanRoot, ref));
}

/**
 * Recommended reviewers derived from the diff's added-findings.
 */
function _suggestReviewers(addedFindings) {
  const hits = new Map();  // team → {why: Set, count: number}
  for (const f of addedFindings) {
    for (const t of REVIEWER_TRIGGERS) {
      if (t.family.test(f.family || '')) {
        if (!hits.has(t.team)) hits.set(t.team, { why: new Set(), count: 0 });
        const ent = hits.get(t.team);
        ent.why.add(t.why);
        ent.count++;
        break;
      }
    }
  }
  return Array.from(hits.entries()).map(([team, ent]) => ({
    team, count: ent.count, why: Array.from(ent.why),
  })).sort((a, b) => b.count - a.count);
}

/**
 * ATT&CK techniques surfaced by added findings (attack-taxonomy annotator
 * must have run for this to be populated).
 */
function _addedAttckSummary(addedFindings) {
  const map = new Map();
  for (const f of addedFindings) {
    for (const t of (f.attck || [])) {
      if (!map.has(t)) map.set(t, { count: 0, name: f.attckName || t });
      map.get(t).count++;
    }
  }
  return Array.from(map.entries())
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 8)
    .map(([id, v]) => ({ id, name: v.name, count: v.count }));
}

/**
 * Artifact links — pull file paths that exist under .agentic-security/.
 */
function _artifactLinks(scanRoot) {
  const candidates = [
    { name: 'Threat model',         file: 'threat-model.md' },
    { name: 'Compliance evidence',  file: 'compliance-evidence.md' },
    { name: 'PQC migration plan',   file: 'pqc-migration-plan.md' },
    { name: 'DPIA',                 file: 'dpia.md' },
    { name: 'ATTRIBUTIONS',         file: 'ATTRIBUTIONS.md' },
    { name: 'NOTICE',               file: 'NOTICE' },
  ];
  const out = [];
  for (const c of candidates) {
    const fp = path.join(scanRoot, '.agentic-security', c.file);
    if (fs.existsSync(fp)) out.push({ name: c.name, path: `.agentic-security/${c.file}` });
  }
  return out;
}

/**
 * Render a Markdown PR-body augmentation block.
 *
 * @param {string} scanRoot
 * @param {object} opts
 *   - baselineRef: string  (default 'main')
 *   - title: string        section title (default 'Security review')
 *   - blocking: bool       if true, prepend a 🛑 block-merge banner when new criticals added
 */
export function augmentPrBody(scanRoot, opts = {}) {
  const baselineRef = opts.baselineRef || 'main';
  const title = opts.title || 'Security review (automated)';
  const blocking = opts.blocking !== false;

  const current = _readJson(_stateFile(scanRoot, 'last-scan.json'));
  if (!current) return { ok: false, error: 'No .agentic-security/last-scan.json — run a scan first.' };

  const baseline = loadBaseline(scanRoot, baselineRef);
  const diff = baseline ? diffScans(baseline, current) : { added: current.findings || [], removed: [], changed: [], unchanged: 0 };
  const summary = summarizeDiff(diff);

  const lines = [];
  lines.push(`## ${title}`);
  lines.push('');

  if (!baseline) {
    lines.push(`> Baseline against \`${baselineRef}\` not found — showing the full current scan as added. Run \`/compliance --pr --persist-baseline ${baselineRef}\` from \`${baselineRef}\` to enable diff mode.`);
    lines.push('');
  }

  const newCriticals = summary.bySeverity.critical?.added || 0;
  const newHighs    = summary.bySeverity.high?.added || 0;

  if (blocking && newCriticals > 0) {
    lines.push(`> 🛑 **${newCriticals} new critical finding(s)** — recommend blocking merge until resolved.`);
    lines.push('');
  } else if (newHighs > 0) {
    lines.push(`> ⚠️  **${newHighs} new high-severity finding(s)** — review before merging.`);
    lines.push('');
  } else if (summary.addedCount === 0) {
    lines.push('> ✅ No new findings vs baseline.');
    lines.push('');
  }

  // Delta table
  lines.push('### Findings delta vs `' + baselineRef + '`');
  lines.push('');
  lines.push('| Severity | Added | Removed |');
  lines.push('|---|---:|---:|');
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    const s = summary.bySeverity[sev] || { added: 0, removed: 0 };
    lines.push(`| ${sev} | ${s.added} | ${s.removed} |`);
  }
  lines.push('');

  // ATT&CK tactics
  const attck = _addedAttckSummary(diff.added);
  if (attck.length) {
    lines.push('### MITRE ATT&CK techniques (new findings)');
    lines.push('');
    for (const t of attck) lines.push(`- \`${t.id}\` ${t.name} (${t.count})`);
    lines.push('');
  }

  // Suggested reviewers
  const reviewers = _suggestReviewers(diff.added);
  if (reviewers.length) {
    lines.push('### Suggested reviewers');
    lines.push('');
    for (const r of reviewers) lines.push(`- **${r.team}** — ${r.why.join('; ')} (${r.count})`);
    lines.push('');
  }

  // Top 5 added findings
  if (diff.added.length) {
    const top = diff.added
      .slice()
      .sort((a, b) => (sevRank(b.severity) - sevRank(a.severity)) || ((b.confidence || 0) - (a.confidence || 0)))
      .slice(0, 5);
    lines.push('### Top added findings');
    lines.push('');
    for (const f of top) {
      const where = `${f.file || '?'}:${f.line || 0}`;
      lines.push(`- **[${(f.severity || '?').toUpperCase()}]** ${f.vuln || f.family || 'finding'} — \`${where}\``);
    }
    lines.push('');
  }

  // Artifact links
  const arts = _artifactLinks(scanRoot);
  if (arts.length) {
    lines.push('### Posture artifacts');
    lines.push('');
    for (const a of arts) lines.push(`- [${a.name}](${a.path})`);
    lines.push('');
  }

  lines.push('_Generated by [agentic-security](https://github.com/Clear-Capabilities/agentic-security)._');

  return {
    ok: true,
    body: lines.join('\n'),
    summary: {
      newCriticals,
      newHighs,
      added: summary.addedCount,
      removed: summary.removedCount,
      reviewers,
    },
  };
}

function sevRank(s) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] || 0;
}

export const _internals = { _suggestReviewers, _addedAttckSummary, _artifactLinks, _baselinePath };
