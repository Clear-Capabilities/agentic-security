// PRD F7.2 — publish what CANNOT be proven, and how much of the finding set that is.
//
// The PoC generator declines whole vulnerability classes it cannot honestly
// prove. Those reasons were documented in poc-inprocess.js's header and nowhere
// else, so the only number a reader ever saw was the proof RATE — computed over
// the findings that happened to be provable. A high rate on a small provable
// subset reads as strength and is nearly meaningless.
//
// Publishing which classes are structurally unprovable, and what share of real
// findings they represent, is more credible than a high proof rate. It is also
// the harder number to publish, which is rather the point.
//
// THE THREE BUCKETS, and why "unclassified" is separate from "indeterminate":
//
//   provable       — a proof class exists and a PoC can be attempted.
//   indeterminate  — the class is DECLINED ON PURPOSE, with a stated reason.
//                    Not a gap in effort; a limit of what a single-shot harness
//                    can honestly assert.
//   unclassified   — no proof class covers it and no decision has been recorded.
//                    This is the genuine backlog, and it is kept apart so it can
//                    never hide inside the principled exclusions.
//
// Folding `unclassified` into `indeterminate` would let "we haven't looked at
// this" borrow the credibility of "we looked and it can't be done".
import { SUPPORTED } from './poc-inprocess.js';

// Declined on purpose. Reasons are the ones recorded in poc-inprocess.js — kept
// as DATA here so a report can print them, rather than living only in a comment
// nobody downstream can read.
export const INDETERMINATE_BY_CLASS = Object.freeze({
  'idor': 'proving it means showing user A read user B\'s record, which needs two authenticated identities and a populated data store. A single-shot harness would invent both, and a PoC built on invented state proves something about the invention.',
  'broken-access-control': 'same as idor — requires two identities and real state.',
  'broken-authz': 'same as idor — requires two identities and real state.',
  'ssrf': 'the proof is that the server fetched an attacker-named host. The sandbox denies egress by design, so a failed fetch is confinement talking, not the finding.',
  'xss': 'needs a browser to say whether the payload executed; a marker file cannot observe a DOM.',
  'mutation-xss': 'needs a DOM and a parser round-trip — same limit as xss.',
  'open-redirect': 'the effect is a Location header a browser would follow; nothing in a marker-file harness observes the follow.',
});

/** Bucket a single finding: 'provable' | 'indeterminate' | 'unclassified'. */
export function bucketOf(finding) {
  const fam = finding && typeof finding.family === 'string' ? finding.family : '';
  if (!fam) return 'unclassified';
  // Families are emitted as `<base>-<rule-slug>` in places, so match the base
  // too — the same resolution problem the compliance evaluator hit.
  const base = fam.split('-').slice(0, 2).join('-');
  for (const key of SUPPORTED) {
    if (fam === key || fam.startsWith(`${key}-`)) return 'provable';
  }
  for (const key of Object.keys(INDETERMINATE_BY_CLASS)) {
    if (fam === key || fam.startsWith(`${key}-`) || base === key) return 'indeterminate';
  }
  return 'unclassified';
}

/**
 * Proof coverage over a finding set.
 *
 * Every share carries {n, d} — a percentage without its denominator is exactly
 * the shape of claim this module exists to replace.
 */
export function proofCoverage(findings) {
  const list = Array.isArray(findings) ? findings.filter(Boolean) : [];
  const d = list.length;
  const buckets = { provable: [], indeterminate: [], unclassified: [] };
  for (const f of list) buckets[bucketOf(f)].push(f);

  const byClass = {};
  for (const f of buckets.indeterminate) {
    const fam = f.family || '(none)';
    const key = Object.keys(INDETERMINATE_BY_CLASS)
      .find(k => fam === k || fam.startsWith(`${k}-`) || fam.split('-').slice(0, 2).join('-') === k) || fam;
    if (!byClass[key]) byClass[key] = { n: 0, reason: INDETERMINATE_BY_CLASS[key] || 'declined' };
    byClass[key].n += 1;
  }

  const unclassifiedFamilies = {};
  for (const f of buckets.unclassified) {
    const fam = f.family || '(no family)';
    unclassifiedFamilies[fam] = (unclassifiedFamilies[fam] || 0) + 1;
  }

  return {
    total: d,
    provable: { n: buckets.provable.length, d },
    indeterminate: { n: buckets.indeterminate.length, d, byClass },
    unclassified: { n: buckets.unclassified.length, d, families: unclassifiedFamilies },
    provableClasses: [...SUPPORTED],
    meaning: 'provable = a proof class exists; indeterminate = declined on purpose with a stated reason; unclassified = no proof class and no decision yet (the real backlog).',
  };
}

/** Markdown for the scorecard. Every rate keeps its denominator. */
export function renderProofCoverage(cov) {
  if (!cov || !cov.total) return '_No findings to report proof coverage over._\n';
  const pct = (n) => `${n}/${cov.total} (${Math.round((n / cov.total) * 100)}%)`;
  const lines = [
    '| Bucket | Share | Meaning |',
    '|---|---|---|',
    `| Provable | ${pct(cov.provable.n)} | a proof class exists and a PoC can be attempted |`,
    `| Indeterminate by class | ${pct(cov.indeterminate.n)} | declined on purpose — see reasons below |`,
    `| Unclassified | ${pct(cov.unclassified.n)} | no proof class yet; the real backlog |`,
    '',
  ];
  const entries = Object.entries(cov.indeterminate.byClass).sort((a, b) => b[1].n - a[1].n);
  if (entries.length) {
    lines.push('**Why each class is declined**', '');
    for (const [cls, { n, reason }] of entries) lines.push(`- \`${cls}\` (${n}): ${reason}`);
    lines.push('');
  }
  return lines.join('\n');
}
