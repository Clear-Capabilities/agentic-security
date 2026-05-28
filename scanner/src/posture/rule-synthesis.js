// Auto-rule synthesis from repeated FPs (FR-LEARN-6).
//
// Reads `.agentic-security/triage-feedback.json` (populated by the /triage
// slash command). When 5+ findings sharing a similar shape get marked FP,
// propose a YAML suppression rule and write it to
// `.agentic-security/rules-proposed/auto-<timestamp>.yml`. The operator
// reviews and either drops it into `rules/` (active) or deletes it.
//
// Honest scope:
//   - We propose, we don't auto-activate. The customer decides.
//   - Similar-shape = same (rule_id or vuln-family) AND same file glob root.
//   - Threshold = 5 occurrences by default (env override).

import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath, isSafeStateDir } from './state-dir.js';

const DEFAULT_FP_THRESHOLD = 5;

function _readTriage(scanRoot) {
  const fp = statePath(scanRoot, 'triage-feedback.json');
  if (!fs.existsSync(fp)) return null;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}

function _shapeKey(entry) {
  // Group by rule/family + the dir prefix (first two path segments) so we
  // suggest rules scoped to the same module — never project-wide.
  const fam = entry.family || entry.cwe || entry.vuln || 'unknown';
  const file = entry.file || '';
  const dir = file.split('/').slice(0, 2).join('/') || '.';
  return `${fam}::${dir}`;
}

function _summarizeGroup(entries) {
  const e0 = entries[0];
  return {
    family: e0.family || null,
    rule:   e0.cwe || e0.vuln || 'unknown',
    dirGlob: (e0.file || '').split('/').slice(0, 2).join('/') + '/**',
    count: entries.length,
    examples: entries.slice(0, 3).map(e => `${e.file}:${e.line}`),
  };
}

function _yamlProposal(group) {
  const ruleId = `auto-suppress-${group.family || group.rule}-${Date.now().toString(36)}`;
  return `# Auto-synthesised suppression proposal (FR-LEARN-6).
# Generated from ${group.count} false-positive verdicts on ${group.family || group.rule}
# in ${group.dirGlob}.
#
# Examples:
${group.examples.map(e => '#   - ' + e).join('\n')}
#
# Review carefully BEFORE moving into rules/. This is a PROPOSAL.

- id: ${ruleId}
  title: "Auto-suppress: ${group.family || group.rule}"
  description: "Repeated FP verdicts in ${group.dirGlob}"
  shadow: true                  # never blocks CI; safe by default
  match:
    family: ${group.family || group.rule}
    paths:
      - "${group.dirGlob}"
  action: suppress
`;
}

/**
 * Public entry: scan the triage history and emit a proposal YAML for any
 * group with ≥ threshold FP verdicts. Returns the list of proposals written.
 */
export function synthesizeRules(scanRoot, opts = {}) {
  const threshold = parseInt(opts.threshold || process.env.AGENTIC_SECURITY_RULE_SYNTHESIS_THRESHOLD || String(DEFAULT_FP_THRESHOLD), 10);
  const triage = _readTriage(scanRoot);
  if (!triage) return [];
  // triage format (per v0.46): { verdicts: [{file, line, vuln, family, verdict, ...}] }
  const verdicts = triage.verdicts || [];
  const fps = verdicts.filter(v => v.verdict === 'fp' || v.verdict === 'false-positive');
  if (!fps.length) return [];
  const groups = new Map();
  for (const e of fps) {
    const k = _shapeKey(e);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(e);
  }
  const proposals = [];
  const dir = statePath(scanRoot, 'rules-proposed');
  if (!opts.dryRun && !isSafeStateDir(path.dirname(dir))) return [];
  for (const [, group] of groups) {
    if (group.length < threshold) continue;
    const summary = _summarizeGroup(group);
    const yaml = _yamlProposal(summary);
    const name = `auto-${(summary.family || summary.rule).replace(/[^a-zA-Z0-9_-]/g, '-')}-${Date.now().toString(36)}.yml`;
    const fp = path.join(dir, name);
    if (!opts.dryRun) {
      try {
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(fp, yaml);
      } catch { /* non-fatal */ }
    }
    proposals.push({ ...summary, file: fp, yaml });
  }
  return proposals;
}

export const _internals = { DEFAULT_FP_THRESHOLD };
