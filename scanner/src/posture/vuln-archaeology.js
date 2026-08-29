// R14 — vulnerability archaeology.
//
// The engine scores the CURRENT tree, and `material-change.js` scores a diff.
// Neither reads history. But a repository's history holds a signal nothing in
// the present tree does: WHERE this team has introduced security bugs before,
// and how often those places needed fixing again.
//
// The output is not a finding. It is a per-file risk prior — "this file has
// been security-fixed four times in the last two years" — that ranks where
// attention is worth spending. Emitting archaeology as findings would be
// wrong twice over: the bugs are already fixed, and a historical fix is not
// evidence of a present defect.
//
// HOW A SECURITY FIX IS RECOGNISED, AND WHY THAT IS THE HARD PART. There is no
// reliable marker. Commit messages are the only broad signal, and they are
// written by humans in a hurry. So the classifier is deliberately conservative
// and every match carries the evidence that produced it:
//
//   - A CVE/GHSA identifier is strong evidence and is treated as such.
//   - A vocabulary of fix verbs paired with vulnerability nouns ("fix XSS",
//     "patch the traversal") is medium evidence.
//   - A bare vulnerability noun is weak: "add XSS tests", "refactor the auth
//     module" and "document CSRF" all mention the noun without fixing
//     anything. These are counted separately and never inflate the strong tier.
//
// FALSE POSITIVES ARE EXPECTED AND MUST STAY VISIBLE. A message-based
// classifier cannot be precise, so the module reports its tiers separately
// rather than collapsing them into one confident number, and every hotspot
// carries the commit subjects behind it so a human can dismiss a bad match in
// seconds. A single blended "risk score" would hide exactly the errors a
// reader needs to see.
//
// Offline and cheap: one `git log` invocation, bounded by commit count and a
// timeout, degrading to an empty result in a non-repository.

import { execFileSync } from 'node:child_process';
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';

const CVE_RE = /\b(?:CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b/i;

const FIX_VERBS = /\b(?:fix(?:e[sd])?|patch(?:e[sd])?|resolv(?:e[sd])|remediat(?:e[sd])|harden(?:ed)?|mitigat(?:e[sd])|prevent(?:ed)?|sanitiz(?:e[sd])|escap(?:e[sd])|clos(?:e[sd]))\b/i;

const VULN_NOUNS = new RegExp([
  'xss', 'cross[- ]site scripting', 'csrf', 'cross[- ]site request forgery',
  'sql[- ]?injection', 'sqli', 'command[- ]?injection', 'code[- ]?injection',
  'path[- ]?traversal', 'directory[- ]?traversal', 'ssrf', 'xxe',
  'deserializ', 'prototype[- ]pollution', 'open[- ]redirect', 'redos',
  'privilege escalation', 'auth(?:entication|orization)? bypass', 'idor',
  'insecure[- ]direct[- ]object', 'race condition', 'use[- ]after[- ]free',
  'buffer overflow', 'integer overflow', 'timing attack', 'security', 'vulnerab',
  'exploit', 'injection', 'sanitiz', 'unsafe[- ]eval', 'hardcoded (?:secret|password|key|credential)',
].join('|'), 'i');

// Messages that mention a vulnerability noun while plainly not fixing one.
// Checked BEFORE the verb pair, because "add tests for the XSS fix" contains
// both a fix verb and a noun yet fixes nothing.
//
// KEPT DELIBERATELY NARROW. Words like "comment", "format", "example", "spec"
// and "demo" look like chore markers but are ordinary code vocabulary — "fix
// XSS in the comment renderer" is a real fix, and an over-broad list demotes it
// to the weak tier. Every word here has to be one that describes the COMMIT'S
// PURPOSE and is unlikely to name a code component. When in doubt leave a word
// out: a missed demotion costs one over-counted hotspot, while a wrong one
// hides a real security fix from the ranking entirely.
const NON_FIX_RE = /\b(?:test(?:s|ing|ed)?|doc(?:s|ument(?:s|ed|ing|ation)?)?|readme|changelog|typo|rename[ds]?|lint|bump(?:ed)?|revert(?:ed)?|wip|todo)\b/i;

export const TIERS = Object.freeze(['identified', 'likely', 'mentioned']);

/**
 * Classify one commit subject.
 * @returns {{tier:string, evidence:string}|null}
 */
export function classifyCommit(subject) {
  if (typeof subject !== 'string' || !subject.trim()) return null;
  const s = subject.trim();

  const cve = s.match(CVE_RE);
  if (cve) return { tier: 'identified', evidence: `references ${cve[0]}` };

  const noun = s.match(VULN_NOUNS);
  if (!noun) return null;

  if (NON_FIX_RE.test(s)) {
    return { tier: 'mentioned', evidence: `mentions "${noun[0]}" but reads as test/doc/chore work` };
  }
  const verb = s.match(FIX_VERBS);
  if (verb) return { tier: 'likely', evidence: `"${verb[0]}" + "${noun[0]}"` };
  return { tier: 'mentioned', evidence: `mentions "${noun[0]}" with no fix verb` };
}

// `scanRoot` is the scanned project's repository, not this project's own
// trusted checkout — hardened per FR-PROV-024 / the second Finding
// Provenance PRD audit (same exposure class as
// provenance/git-evidence.js's `_run`). No `--no-textconv` needed: this
// invocation has no `-p`/`-L`, so no diff/blob content is rendered.
function _gitLog(scanRoot, { maxCommits, timeoutMs }) {
  // NUL-delimited records so subjects containing newlines cannot split a
  // record — a commit message is arbitrary user text and must not be able to
  // forge a record boundary.
  const out = execFileSync('git', hardenGitArgs([
    '-C', scanRoot, 'log', '-n', String(maxCommits), '--no-merges', '--no-color',
    '--name-only', '--format=%x00%H%x1f%aI%x1f%s',
  ]), { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv() });
  const commits = [];
  for (const block of out.split('\0')) {
    if (!block.trim()) continue;
    const nl = block.indexOf('\n');
    const header = nl === -1 ? block : block.slice(0, nl);
    const [sha, date, ...rest] = header.split('\x1f');
    if (!sha) continue;
    const files = nl === -1 ? [] : block.slice(nl + 1).split('\n').map(l => l.trim()).filter(Boolean);
    commits.push({ sha, date: date || null, subject: rest.join('\x1f') || '', files });
  }
  return commits;
}

/**
 * Mine history for security-relevant commits and turn them into per-file priors.
 *
 * @returns {{available:boolean, reason:string|null, commitsScanned:number,
 *            byTier:object, hotspots:Array, commits:Array}}
 */
export function mineVulnHistory(scanRoot, { maxCommits = 500, timeoutMs = 30000, maxHotspots = 25, minConcentration = 0.15 } = {}) {
  const empty = {
    available: false, reason: null, commitsScanned: 0,
    byTier: { identified: 0, likely: 0, mentioned: 0 }, hotspots: [], commits: [],
  };
  if (!scanRoot) return { ...empty, reason: 'no scan root' };

  let commits;
  try {
    commits = _gitLog(scanRoot, { maxCommits, timeoutMs });
  } catch (e) {
    // Not a repository, git absent, shallow clone, timeout — all "no history
    // available", never an error that fails a scan.
    return { ...empty, reason: `git history unavailable: ${String(e.message || e).split('\n')[0]}` };
  }

  const byTier = { identified: 0, likely: 0, mentioned: 0 };
  const perFile = new Map();
  const matched = [];

  const _file = (f) => {
    let e = perFile.get(f);
    if (!e) { e = { file: f, identified: 0, likely: 0, mentioned: 0, totalCommits: 0, subjects: [] }; perFile.set(f, e); }
    return e;
  };

  // Total touches first, across EVERY commit. Without this the ranking rewards
  // churn: a release commit whose subject says "fix XSS ..." also touches the
  // changelog, the manifest and the version file, so the most-edited files in
  // the repository float to the top of a raw count and the actual vulnerable
  // source is buried. Measured on this repository, the raw ranking returned
  // CLAUDE.md and package.json as the top two hotspots.
  for (const c of commits) for (const f of c.files) _file(f).totalCommits++;

  for (const c of commits) {
    const cls = classifyCommit(c.subject);
    if (!cls) continue;
    byTier[cls.tier]++;
    matched.push({ sha: c.sha.slice(0, 12), date: c.date, subject: c.subject, tier: cls.tier, evidence: cls.evidence, files: c.files.length });
    for (const file of c.files) {
      const e = _file(file);
      e[cls.tier]++;
      // Keep a bounded sample of the evidence, so a hotspot can be judged
      // without re-reading the log.
      if (e.subjects.length < 5) e.subjects.push({ sha: c.sha.slice(0, 12), tier: cls.tier, subject: c.subject });
    }
  }

  const hotspots = [...perFile.values()]
    // `mentioned` deliberately does NOT contribute to the ranking weight. It is
    // the tier most likely to be wrong, so letting it rank files would sort by
    // classifier error. It is still reported per file so a reader can see it.
    .map(e => {
      const weight = e.identified * 3 + e.likely;
      // What fraction of this file's history is security work. A file touched
      // by 200 commits of which 3 were security fixes is not a hotspot; one
      // touched 4 times, 3 of them security fixes, is.
      const concentration = e.totalCommits ? (e.identified + e.likely) / e.totalCommits : 0;
      return { ...e, weight, concentration: Number(concentration.toFixed(3)) };
    })
    .filter(e => e.weight > 0 && e.concentration >= minConcentration)
    // Rank by concentration first: it is the churn-corrected signal. Weight
    // breaks ties so that, among equally-concentrated files, more security
    // history ranks higher.
    .sort((a, b) => b.concentration - a.concentration || b.weight - a.weight || (a.file < b.file ? -1 : 1))
    .slice(0, maxHotspots);

  return {
    available: true,
    reason: null,
    commitsScanned: commits.length,
    // Stated so a reader knows whether they are looking at all of history.
    truncated: commits.length >= maxCommits,
    byTier,
    hotspots,
    commits: matched.slice(0, 100),
  };
}

/**
 * Attach the historical prior to findings whose file is a hotspot.
 * Advisory only: never changes severity, never removes anything.
 */
export function annotateHistoricalRisk(findings, history) {
  if (!Array.isArray(findings) || !history?.available) return 0;
  const byFile = new Map(history.hotspots.map(h => [h.file, h]));
  let n = 0;
  for (const f of findings) {
    const h = f && f.file ? byFile.get(f.file) : null;
    if (!h) continue;
    f.historicalRisk = {
      priorSecurityFixes: h.identified + h.likely,
      identified: h.identified,
      likely: h.likely,
      note: 'advisory prior from git history — not evidence about this finding',
    };
    n++;
  }
  return n;
}

/** One-line summary; null when there is no history to report. */
export function renderArchaeology(h) {
  if (!h) return null;
  if (!h.available) return `vulnerability archaeology: skipped (${h.reason}).`;
  const { identified, likely, mentioned } = h.byTier;
  if (!identified && !likely && !mentioned) {
    return `vulnerability archaeology: no security-relevant commits in the last ${h.commitsScanned}.`;
  }
  return `vulnerability archaeology: ${identified} CVE-identified, ${likely} likely and ${mentioned} `
    + `merely-mentioning commit(s) across ${h.commitsScanned} scanned${h.truncated ? ' (history truncated)' : ''}; `
    + `${h.hotspots.length} file hotspot(s). Ranking ignores the "mentioned" tier — it is the least reliable.`;
}

export const _internals = { CVE_RE, FIX_VERBS, VULN_NOUNS, NON_FIX_RE, _gitLog };
