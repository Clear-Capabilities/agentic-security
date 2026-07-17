// Advisor-tone PR comment renderer (v0.72).
//
// Replaces the typical "12 findings detected, see SARIF" wall of text
// with a single security-advisor's note:
//
//   "I noticed you added /api/admin/users in this PR. I checked 4 things:
//    ✓ auth (route is behind requireAdmin)
//    ⚠ rate-limit (no rateLimit() middleware found)
//    ✓ input validation (express-validator chain present)
//    ✓ audit log (logger.security() called on success path)
//
//    The rate-limit gap matters because /admin endpoints are common
//    credential-stuffing targets. A 5-line fix:
//
//    ```js
//    import rateLimit from 'express-rate-limit';
//    app.use('/api/admin', rateLimit({ windowMs: 15*60_000, max: 30 }));
//    ```"
//
// The pure-narrative format optimizes for SCREENSHOTABILITY — engineers
// share security-tool comments that read like a person, not a table.
//
// Generation is deterministic (no LLM) for the v1: we render from the
// delta + a per-CWE narrative template. A future v2 could optionally
// route through an LLM for richer prose when AGENTIC_SECURITY_LLM_ENDPOINT
// is configured.

import { escapeMarkdown } from './util/untrusted.js';

const SEVERITY_GLYPH = {
  critical: '🟥',
  high:     '🟧',
  medium:   '🟨',
  low:      '🟦',
  info:     '⬜',
};

const CWE_NARRATIVE = {
  'CWE-89':   { name: 'SQL injection',          why: 'A malicious payload like `1\' OR 1=1--` would dump every row.' },
  'CWE-79':   { name: 'XSS',                    why: 'An attacker who controls this string can execute JavaScript in another user\'s browser.' },
  'CWE-78':   { name: 'Command injection',      why: 'A `;rm -rf /` style payload would run with the privileges of your service account.' },
  'CWE-22':   { name: 'path traversal',         why: 'A `../../etc/passwd` style payload would read files outside the intended directory.' },
  'CWE-918':  { name: 'SSRF',                   why: 'An attacker can pivot to the cloud metadata endpoint (`169.254.169.254`) or internal services.' },
  'CWE-502':  { name: 'insecure deserialization', why: 'A crafted payload triggers gadget chains — typically remote code execution.' },
  'CWE-611':  { name: 'XXE',                    why: 'A malicious DOCTYPE can exfiltrate local files or trigger SSRF via entity expansion.' },
  'CWE-94':   { name: 'template injection',     why: 'A `{{7*7}}` style payload escapes to the template engine\'s expression evaluator (often RCE).' },
  'CWE-1321': { name: 'prototype pollution',    why: 'A `__proto__` injection can alter the behavior of every downstream object check.' },
  'CWE-352':  { name: 'CSRF',                   why: 'A cross-origin form can trigger authenticated state changes without the user\'s knowledge.' },
  'CWE-601':  { name: 'open redirect',          why: 'Trusted-domain bouncer for phishing — credentials get harvested on the second hop.' },
  'CWE-113':  { name: 'HTTP response splitting', why: 'CR/LF injection lets an attacker forge an entire response, including cache poisoning.' },
  'CWE-798':  { name: 'hardcoded secret',       why: 'Committed credentials are scraped by automated scanners minutes after a push.' },
  'CWE-327':  { name: 'weak crypto',            why: 'Modern adversaries can crack MD5/SHA-1/RC4/3DES at practical cost.' },
  'CWE-1333': { name: 'regex DoS',              why: 'A pathological input freezes the worker for seconds — DoS without much effort.' },
  'CWE-90':   { name: 'LDAP injection',         why: 'An attacker can extend the filter to enumerate users or bypass auth.' },
  'CWE-643':  { name: 'XPath injection',        why: 'A `\' or \'1\'=\'1` payload can return data the query never intended to expose.' },
  'CWE-1336': { name: 'prompt injection',       why: 'Untrusted text in the LLM context can override your system prompt.' },
  'CWE-269':  { name: 'privilege escalation',   why: 'A low-privilege actor can reach a higher-privilege capability through this surface.' },
};

function _topCwes(findings, n = 3) {
  const counts = new Map();
  for (const f of findings) {
    const k = f.cwe || 'unknown';
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

function _route(f) {
  // Best-effort: pull a route-ish string from the file path / vuln text.
  // Many SAST findings carry the route via `f.route` or in the vuln name.
  if (f.route) return f.route;
  const m = (f.vuln || '').match(/\b(GET|POST|PUT|DELETE|PATCH)\s+([\/\w:-]+)/i);
  if (m) return `${m[1].toUpperCase()} ${m[2]}`;
  return null;
}

/**
 * Top-level renderer. Takes a delta produced by `computePrDelta` and
 * emits a Markdown string suitable for posting as a single PR comment.
 *
 * Mode is chosen automatically:
 *   - "clean":     no introduced + (resolved > 0 || persistent > 0)
 *   - "trivial":   no introduced + nothing resolved
 *   - "needs-work": one or more introduced findings
 */
export function renderPrComment(delta, { repoName, prNumber, prTitle } = {}) {
  if (!delta) return '_no security delta available_';
  const intro = delta.introduced || [];
  const resolved = delta.resolved || [];
  const shifted = delta.shifted || [];
  const heading = repoName && prNumber
    ? `### 🛡 agentic-security on ${repoName}#${prNumber}`
    : `### 🛡 agentic-security`;
  if (intro.length === 0 && resolved.length === 0 && shifted.length === 0) {
    return [
      heading,
      ``,
      `No security delta from \`${delta.baseRef}\` → \`${delta.headRef}\`. ` +
      `${delta.changedFiles.length} file${delta.changedFiles.length === 1 ? '' : 's'} touched; ` +
      `nothing in those changes introduced or resolved a finding. **Safe to merge.**`,
      ``,
      `<sub>Scanned ${delta.head?.summary?.total ?? 0} pre-existing findings on the head ref ` +
      `(${delta.base?.summary?.total ?? 0} on base) — none of them moved in this PR.</sub>`,
    ].join('\n');
  }
  if (intro.length === 0 && (resolved.length || shifted.length)) {
    const r = delta.summary?.resolved || {};
    return [
      heading,
      ``,
      `This PR **resolves** ${resolved.length} finding${resolved.length === 1 ? '' : 's'}` +
      (r.critical || r.high ? ` (including ${r.critical} critical + ${r.high} high)` : '') +
      ` and introduces **none**. Nice cleanup work — safe to merge. ✨`,
      ``,
      `<sub>${delta.changedFiles.length} file${delta.changedFiles.length === 1 ? '' : 's'} ` +
      `touched between \`${delta.baseRef}\` and \`${delta.headRef}\`.</sub>`,
    ].join('\n');
  }
  // needs-work mode: narrative + per-finding paragraphs.
  const lines = [];
  lines.push(heading);
  lines.push('');
  const topCwes = _topCwes(intro);
  const cweSummary = topCwes.map(([cwe, n]) => {
    const meta = CWE_NARRATIVE[cwe];
    return meta ? `${n} ${meta.name}` : `${n} ${cwe}`;
  }).join(', ');
  const hint = prTitle ? ` in "${prTitle}"` : '';
  lines.push(`I looked at the ${delta.changedFiles.length} file${delta.changedFiles.length === 1 ? '' : 's'} ` +
    `you changed${hint} and noticed **${intro.length} new finding${intro.length === 1 ? '' : 's'}** ` +
    `that wasn't on \`${delta.baseRef}\`. Top concerns: ${cweSummary}.`);
  lines.push('');
  // Per-introduced-finding paragraph (cap at 5 for readability).
  const SHOW = intro.slice(0, 5);
  for (const f of SHOW) {
    const meta = CWE_NARRATIVE[f.cwe];
    const sev = SEVERITY_GLYPH[f.severity] || '⬜';
    const route = _route(f);
    const where = route ? `\`${route}\` (\`${f.file}:${f.line}\`)` : `\`${f.file}:${f.line}\``;
    lines.push(`${sev} **${meta?.name || escapeMarkdown(f.vuln)}** — ${where}`);
    if (meta) lines.push(`  > ${meta.why}`);
    if (f.remediation) {
      const onelineFix = String(f.remediation).split('\n')[0].slice(0, 240);
      lines.push(`  Suggested fix: ${onelineFix}`);
    }
    if (f.confidence != null && f.confidence < 0.7) {
      lines.push(`  <sub>Lower confidence (${(f.confidence * 100).toFixed(0)}%) — may be a false positive worth a quick look.</sub>`);
    }
    lines.push('');
  }
  if (intro.length > SHOW.length) {
    lines.push(`<sub>+${intro.length - SHOW.length} more new finding${intro.length - SHOW.length === 1 ? '' : 's'} — see the scan output for the full list.</sub>`);
    lines.push('');
  }
  if (resolved.length) {
    lines.push(`On the bright side: this PR **resolved ${resolved.length} pre-existing finding${resolved.length === 1 ? '' : 's'}**. 👏`);
    lines.push('');
  }
  const i = delta.summary?.introduced || {};
  const blockMerge = (i.critical || 0) + (i.high || 0) > 0;
  if (blockMerge) {
    lines.push(`---`);
    lines.push(`**Blocking merge:** ${i.critical || 0} critical + ${i.high || 0} high severity ` +
      `finding${(i.critical || 0) + (i.high || 0) === 1 ? '' : 's'} introduced. ` +
      `Fix or suppress with \`// agentic-security-ignore: <rule-id>\` before merging.`);
  } else {
    lines.push(`---`);
    lines.push(`Non-blocking: no critical/high severity findings introduced — but consider addressing the items above before this becomes harder to revisit.`);
  }
  return lines.join('\n');
}

export const _internal = { CWE_NARRATIVE, SEVERITY_GLYPH, _topCwes };
