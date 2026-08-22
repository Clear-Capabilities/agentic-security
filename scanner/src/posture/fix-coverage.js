// PRD F6.5 — publish the proportion of findings this engine DECLINES to fix.
//
// A remediation feature that silently attempts everything is less trustworthy
// than one that declines 40% and says so. Before this, the only visible number
// was about fixes that were attempted; a finding for which synthesis was never
// even tried simply did not appear, so the denominator quietly excluded every
// hard case.
//
// THE BUCKETS
//
//   deterministic — a context-independent literal swap exists (md5 -> sha256,
//                   TLS verify off -> on). Highest confidence: the patch does
//                   not depend on reading intent.
//   model         — no deterministic patch, but the finding is a shape a model
//                   can be asked to fix. Counted as ATTEMPTABLE, not as fixed:
//                   whether the attempt succeeds is fix-metrics.js's question.
//   declined      — synthesis refuses, with a reason. Not a failure; a limit
//                   stated up front.
//
// `declined` and `model` are kept apart for the same reason proof-coverage
// separates `indeterminate` from `unclassified`: "we will not try" and "we will
// try and might fail" are different promises, and merging them lets the weaker
// one borrow the stronger one's credibility.
import { synthesizeDeterministicPatch } from './deterministic-fix.js';

// Families where a patch cannot be synthesised from the finding alone, with the
// reason. Stated as DATA so a report can print why, rather than leaving a reader
// to assume the engine simply has not got round to it.
export const DECLINED_TO_FIX = Object.freeze({
  'broken-access-control': 'the correct authorisation rule is a product decision — a scanner that invents one is guessing at intent, and a wrong authz patch fails open.',
  'idor': 'same as broken-access-control: which identity may read which record is not recoverable from the code.',
  'broken-authz': 'the rule that was checked wrongly is a product decision; patching it from the code alone guesses at which roles may do what, and guessing fails open.',
  'business-logic': 'by definition the defect is a mismatch with intent, and intent is not in the file.',
  'concurrency-bug': 'the correct lock discipline depends on the whole call graph; a local patch can deadlock rather than fix.',
  'license-graph': 'a licence conflict is resolved by a policy or a dependency decision, not by editing code.',
  'vulnerable-dep': 'resolved by an upgrade, which is apply_sca_upgrade\'s job, not a source patch.',
});

/** Bucket a finding: 'deterministic' | 'model' | 'declined'. */
export function fixBucketOf(finding, fileContent) {
  const fam = (finding && finding.family) || '';
  for (const key of Object.keys(DECLINED_TO_FIX)) {
    if (fam === key || fam.startsWith(`${key}-`)) return 'declined';
  }
  if (typeof fileContent === 'string' && fileContent) {
    try {
      const p = synthesizeDeterministicPatch(finding, fileContent);
      if (p && p.ok !== false && (p.patch || p.replacement)) return 'deterministic';
    } catch { /* fall through — an erroring synthesiser is not a fix */ }
  }
  return 'model';
}

/**
 * Fix coverage over a finding set.
 *
 * Every share carries {n, d}. `fileContents` is optional: without it the
 * deterministic check cannot run, and rather than guessing, those findings fall
 * to `model` and `deterministicChecked` reports false so a reader knows the
 * split is a lower bound on deterministic coverage.
 */
export function fixCoverage(findings, fileContents = null) {
  const list = Array.isArray(findings) ? findings.filter(Boolean) : [];
  const d = list.length;
  const buckets = { deterministic: [], model: [], declined: [] };
  for (const f of list) {
    const src = fileContents && f.file ? fileContents[f.file] : null;
    buckets[fixBucketOf(f, src)].push(f);
  }

  const declinedByFamily = {};
  for (const f of buckets.declined) {
    const fam = f.family || '(none)';
    const key = Object.keys(DECLINED_TO_FIX).find(k => fam === k || fam.startsWith(`${k}-`)) || fam;
    if (!declinedByFamily[key]) declinedByFamily[key] = { n: 0, reason: DECLINED_TO_FIX[key] || 'declined' };
    declinedByFamily[key].n += 1;
  }

  return {
    total: d,
    deterministic: { n: buckets.deterministic.length, d },
    model: { n: buckets.model.length, d },
    declined: { n: buckets.declined.length, d, byFamily: declinedByFamily },
    deterministicChecked: !!fileContents,
    meaning: 'deterministic = a context-independent patch exists; model = attemptable by a model, NOT known to succeed; declined = synthesis refuses with a stated reason.',
  };
}

/** Markdown for the scorecard. Denominators always attached. */
export function renderFixCoverage(cov) {
  if (!cov || !cov.total) return '_No findings to report fix coverage over._\n';
  const pct = (n) => `${n}/${cov.total} (${Math.round((n / cov.total) * 100)}%)`;
  const lines = [
    '| Bucket | Share | Meaning |',
    '|---|---|---|',
    `| Deterministic patch | ${pct(cov.deterministic.n)} | context-independent literal swap |`,
    `| Model-attemptable | ${pct(cov.model.n)} | can be attempted; success not claimed here |`,
    `| Declined | ${pct(cov.declined.n)} | synthesis refuses — reasons below |`,
    '',
  ];
  if (!cov.deterministicChecked) {
    lines.push('_Source was not supplied, so the deterministic check could not run: the'
      + ' deterministic share is a LOWER bound and those findings are counted as'
      + ' model-attemptable._', '');
  }
  const entries = Object.entries(cov.declined.byFamily).sort((a, b) => b[1].n - a[1].n);
  if (entries.length) {
    lines.push('**Why each family is declined**', '');
    for (const [fam, { n, reason }] of entries) lines.push(`- \`${fam}\` (${n}): ${reason}`);
    lines.push('');
  }
  return lines.join('\n');
}
