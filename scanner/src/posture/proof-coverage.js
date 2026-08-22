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
//   out-of-scope   — the in-process harness is JAVASCRIPT-ONLY. A Python, Java,
//                    C#, PHP, Kotlin, Go or Ruby finding cannot be proven by it
//                    at any effort, so it is not backlog — it is the CEILING.
//
// That fourth bucket is the "stated ceiling" Feature 7's exit gate asks for, and
// omitting it made the headline number mean two different things at once.
// Measured on the CVE corpus: 280 findings, of which only 76 are JS/TS. Proof
// coverage is 26% of ALL findings and 96% of the ones the harness can reach.
// Reporting the first alone understates the harness; reporting the second alone
// overstates the product. Both are published, with the denominator on each.
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

// The in-process harness only ever loads JavaScript (see poc-inprocess.js's
// JS_EXT and its "ES-module source" refusal). Anything else is unreachable by
// construction.
const HARNESS_LANGS = /\.(?:js|cjs|mjs|jsx|ts|tsx)$/i;

// Internal: `bucketOf` is the public surface for this question. Not exported —
// the dead-export guard is right that a second entry point with no caller is
// just surface area.
function outOfHarnessScope(finding) {
  const file = finding && typeof finding.file === 'string' ? finding.file : '';
  if (!file) return false;              // unknown file — do not claim a ceiling
  return !HARNESS_LANGS.test(file);
}

/** Bucket a finding: 'provable' | 'indeterminate' | 'unclassified' | 'out-of-scope'. */
export function bucketOf(finding) {
  // Language first: a Python SQL-injection finding is not "provable", however
  // good the SQL proof class is. Ordering this after the class check would
  // report a ceiling case as a capability.
  if (outOfHarnessScope(finding)) return 'out-of-scope';
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
  const buckets = { provable: [], indeterminate: [], unclassified: [], 'out-of-scope': [] };
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

  const reachable = d - buckets['out-of-scope'].length;
  const outLangs = {};
  for (const f of buckets['out-of-scope']) {
    const ext = (String(f.file || '').match(/\.[a-z0-9]+$/i) || ['(none)'])[0].toLowerCase();
    outLangs[ext] = (outLangs[ext] || 0) + 1;
  }

  return {
    total: d,
    // Reported BOTH ways on purpose. `provable.d` is every finding; `ofReachable`
    // is the share of what the harness can actually load. Publishing only one of
    // them is how a number ends up meaning whatever the reader assumes.
    provable: { n: buckets.provable.length, d, ofReachable: { n: buckets.provable.length, d: reachable } },
    ceiling: {
      reachable: { n: reachable, d },
      outOfScope: { n: buckets['out-of-scope'].length, d, byExtension: outLangs },
      reason: 'the in-process proof harness only loads JavaScript; findings in other languages cannot be execution-proven by it at any effort',
    },
    indeterminate: { n: buckets.indeterminate.length, d, byClass },
    unclassified: { n: buckets.unclassified.length, d, families: unclassifiedFamilies },
    provableClasses: [...SUPPORTED],
    meaning: 'provable = a proof class exists; indeterminate = declined on purpose with a stated reason; unclassified = no proof class and no decision yet (the real backlog); out-of-scope = a language the JS-only harness cannot load at all (the ceiling, not backlog).',
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
    `| Out of harness scope | ${pct(cov.ceiling.outOfScope.n)} | not JavaScript — the harness cannot load it at all |`,
    '',
    // Stated every time, because the two readings of "provable" differ by a lot
    // and a reader who sees only the first will draw the wrong conclusion.
    `**Ceiling.** ${cov.ceiling.reason}. Of ${cov.total} findings, ${cov.ceiling.reachable.n} are reachable by the harness; `
    + `proof coverage is ${cov.provable.n}/${cov.total} of ALL findings and `
    + `${cov.provable.ofReachable.n}/${cov.provable.ofReachable.d} of the reachable ones.`,
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
