// 0.6.0 Feat-3: Material change detection — scores git diff hunks by architectural risk.
// Score a git diff by architectural risk — separate "200-file rename" (low) from
// "3-line auth-removal in middleware" (critical).
//
// Inputs are diff hunks (lines starting with + or -). Output per hunk:
//   { kind, severity, file, hunkLines: {add: [...], del: [...]}, evidence: <string> }
//
// Aggregated per-PR: { totalRisk, perKindCounts, byFile, recommendation }.
//
// Pure function — no git invocation here. The runner (`scanner/src/posture/diff.js`
// or the command runner) collects the unified diff and feeds hunks into classifyHunk.

import * as cp from 'node:child_process';
import { loadPrivacyTaxonomy } from '../dataflow/privacy-taxonomy.js';

// Patterns that fire on the deletion side (auth/check removed).
const DEL_PATTERNS = [
  { re: /\b(?:authenticate|isAuthenticated|requireAuth|verifyToken|authMiddleware|checkAuth|isAuthorized|expressJwt|passport\.authenticate)\s*\(/i,
    kind: 'auth-removed', sev: 'critical', evidence: 'Authentication / authorization check removed' },
  { re: /\bif\s*\(\s*!\s*(?:req\.user|user|currentUser|session\.user)\b/i,
    kind: 'auth-removed', sev: 'critical', evidence: 'User-presence guard removed' },
  { re: /\bres\.cookie\s*\([^)]*?(?:secure|httpOnly|sameSite)\s*:\s*true/i,
    kind: 'cookie-flag-removed', sev: 'high', evidence: 'Cookie security flag removed' },
  { re: /\b(?:csrf|csurf|csrfProtection)\s*\(/i,
    kind: 'csrf-removed', sev: 'high', evidence: 'CSRF protection removed' },
  { re: /\b(?:helmet|cors)\s*\(/i,
    kind: 'security-middleware-removed', sev: 'medium', evidence: 'Security middleware removed' },
];

// FR-307: a new/modified PII/PHI-shaped field is one of the named
// high-impact categories ("PII" — see HIGH_IMPACT_CATEGORY_OF_KIND below).
// Reuses dataflow/privacy-taxonomy.js's FR-402 field-name vocabulary
// (built-in defaults only — this is a coarse architectural-risk signal,
// not the authoritative privacy classification egress/redact.js and
// dataflow/privacy-taint.js already own) rather than inventing a second,
// parallel PII field-name list that could drift from the first.
const _PII_FIELD_NAMES = [
  ...(loadPrivacyTaxonomy(null).taxonomy.PII?.patterns || []),
  ...(loadPrivacyTaxonomy(null).taxonomy.PHI?.patterns || []),
];
const PII_FIELD_RE = _PII_FIELD_NAMES.length
  ? new RegExp('(?:' + _PII_FIELD_NAMES.join('|') + ')\\s*[:=]', 'i')
  : /(?!)/; // never matches — degrades safely if the taxonomy import ever returns nothing

// Patterns that fire on the addition side (new attack surface introduced).
const ADD_PATTERNS = [
  { re: /\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*['"][^'"]+['"]/,
    kind: 'new-endpoint', sev: 'medium', evidence: 'New HTTP endpoint declared' },
  { re: /\b(?:exec|execSync|execFile|spawn|spawnSync)\s*\(/,
    kind: 'new-shell-call', sev: 'critical', evidence: 'New shell-execution call' },
  { re: /\b(?:eval|Function)\s*\(/,
    kind: 'new-dynamic-eval', sev: 'critical', evidence: 'New dynamic code evaluation' },
  { re: /\b(?:isAdmin|is_admin|admin|role|roles|permissions|scopes|tier)\s*[:=]\s*(?:req|request)\.body\b/i,
    kind: 'priv-from-body', sev: 'critical', evidence: 'Privilege field assigned from request body' },
  { re: /\$\{[^}]*\b(?:req|request)\.(?:body|query|params|headers)\b[^}]*\}\s*[`)]/,
    kind: 'new-template-injection', sev: 'high', evidence: 'User input interpolated into template literal' },
  { re: /\b(?:anthropic|openai|client)\.(?:messages|chat\.completions|completions)\.create\s*\([^)]*\b(?:req|request)\.(?:body|query|params)\b/,
    kind: 'new-prompt-with-user-input', sev: 'high', evidence: 'LLM call with user input' },
  { re: /\bsystem\s*:\s*[`'"`].*?\$\{[^}]*\b(?:req|request)\./,
    kind: 'new-prompt-injection', sev: 'critical', evidence: 'User input interpolated into LLM system prompt' },
  { re: /(?:dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\()/,
    kind: 'new-xss-sink', sev: 'high', evidence: 'New HTML/DOM sink' },
  { re: /(?:db|knex|sequelize|prisma)\.(?:raw|\$queryRaw|query)\s*\(\s*[`'"]\s*[^`'"]*\$\{/,
    kind: 'new-sql-injection', sev: 'critical', evidence: 'String-interpolated SQL query' },
  { re: /\b(?:fs|fsp)\.(?:writeFile|writeFileSync|unlink|unlinkSync|rmSync|rm)\s*\([^)]*\b(?:req|request)\./,
    kind: 'new-fs-write-from-req', sev: 'high', evidence: 'Filesystem write/delete fed by request input' },
  { re: /^\+\s*"[^"]+"\s*:\s*"\^?\d/,
    kind: 'new-dep', sev: 'medium', evidence: 'New dependency added (manifest)' },
  { re: /\bpermissions\s*:\s*write-all\b/i,
    kind: 'pipeline-perms-widened', sev: 'high', evidence: 'GitHub Actions permissions widened to write-all' },
  { re: /\buses\s*:\s*[\w-]+\/[\w-]+@(?:main|master|v?\d+|latest)\b/i,
    kind: 'pipeline-floating-tag', sev: 'medium', evidence: 'GitHub Actions step pinned to floating tag' },
  { re: /\bprivileged\s*:\s*true\b/i,
    kind: 'new-iac-privilege', sev: 'high', evidence: 'Container/pod marked privileged' },
  // FR-307: crypto, PII, and schema — the three named high-impact
  // categories the pre-existing kind taxonomy above did not yet cover.
  { re: /\b(?:md5|sha1)\s*\(/i,
    kind: 'weak-crypto-added', sev: 'high', evidence: 'Weak/deprecated hash primitive (MD5/SHA-1) referenced' },
  { re: /createCipheriv\s*\(\s*['"`](?:des|des-ede3|rc4|bf|rc2)/i,
    kind: 'weak-crypto-added', sev: 'critical', evidence: 'Weak/deprecated cipher algorithm referenced' },
  { re: /\b(?:createCipheriv|createDecipheriv|generateKeyPair(?:Sync)?|crypto\.subtle|jwt\.sign|jsonwebtoken)\s*[.(]/,
    kind: 'crypto-primitive-changed', sev: 'high', evidence: 'Cryptographic primitive or JWT signing usage added or changed' },
  { re: PII_FIELD_RE,
    kind: 'new-pii-field', sev: 'high', evidence: 'PII/PHI-shaped field introduced or modified' },
  { re: /\b(?:ALTER\s+TABLE|CREATE\s+TABLE|DROP\s+(?:TABLE|COLUMN)|ADD\s+COLUMN)\b/i,
    kind: 'schema-change', sev: 'medium', evidence: 'Database schema change (DDL)' },
];

// FR-307: which `kind`s constitute one of the PRD's named high-impact
// change classes ("Auth, authZ, crypto, PII, schema, infrastructure
// privilege, and public API changes cannot auto-apply without approval
// evidence"). A finding whose kind is NOT in this map is still scored for
// severity as before, but does not by itself trigger the approval gate —
// only these specific, named categories do.
export const HIGH_IMPACT_CATEGORY_OF_KIND = {
  'auth-removed': 'auth',
  'priv-from-body': 'authZ',
  'new-pii-field': 'pii',
  'weak-crypto-added': 'crypto',
  'crypto-primitive-changed': 'crypto',
  'schema-change': 'schema',
  'new-iac-privilege': 'infra-privilege',
  'pipeline-perms-widened': 'infra-privilege',
  'new-endpoint': 'public-api',
};

// Routine / low-risk patterns (NEVER classify higher than 'low').
const ROUTINE_PATTERNS = [
  /^\+\s*\/\//,                    // adding a comment
  /^\+\s*\*/,                      // doc-block line
  /^\+\s*$/,                       // blank line
  /^\+\s*import\s+/,               // import only (no usage)
  /^\+\s*\}/,                      // closing brace
];

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

// Parse a unified diff into per-file hunks. Each hunk is a contiguous block of
// '+ ' / '- ' / '  ' lines preceded by an '@@ ... @@' header.
export function parseDiff(diffText) {
  const out = [];
  let curFile = null;
  let curHunk = null;
  let inHunk = false;
  for (const line of diffText.split('\n')) {
    if (line.startsWith('+++ b/')) { curFile = line.slice(6); continue; }
    if (line.startsWith('+++ ')) { curFile = line.slice(4).replace(/^[ab]\//, ''); continue; }
    if (line.startsWith('@@')) {
      if (curHunk) out.push(curHunk);
      curHunk = { file: curFile, header: line, add: [], del: [] };
      inHunk = true;
      continue;
    }
    if (!inHunk || !curHunk) continue;
    if (line.startsWith('+++') || line.startsWith('---')) continue;
    if (line.startsWith('+') && !line.startsWith('+++')) curHunk.add.push(line.slice(1));
    else if (line.startsWith('-') && !line.startsWith('---')) curHunk.del.push(line.slice(1));
  }
  if (curHunk) out.push(curHunk);
  return out;
}

export function classifyHunk(hunk) {
  const matches = [];
  // Check deletion side
  for (const ln of hunk.del) {
    for (const p of DEL_PATTERNS) {
      if (p.re.test(ln)) matches.push({ kind: p.kind, severity: p.sev, evidence: p.evidence, side: '-', line: ln.trim() });
    }
  }
  // Check addition side
  for (const ln of hunk.add) {
    for (const p of ADD_PATTERNS) {
      if (p.re.test(ln)) matches.push({ kind: p.kind, severity: p.sev, evidence: p.evidence, side: '+', line: ln.trim() });
    }
  }
  if (!matches.length) {
    // All-additions pure-routine?
    const allRoutine = hunk.add.length > 0 && hunk.add.every(ln => ROUTINE_PATTERNS.some(re => re.test('+' + ln)));
    return [{ kind: 'routine', severity: allRoutine ? 'none' : 'low', evidence: 'No risk pattern matched', file: hunk.file, side: '~', line: '' }];
  }
  // Annotate file
  return matches.map(m => ({ ...m, file: hunk.file }));
}

export function classifyDiff(diffText) {
  const hunks = parseDiff(diffText);
  const findings = [];
  for (const h of hunks) {
    const cls = classifyHunk(h);
    findings.push(...cls);
  }
  return summarize(findings);
}

function summarize(findings) {
  const perKind = {};
  const byFile = {};
  let topSev = 'none';
  for (const f of findings) {
    perKind[f.kind] = (perKind[f.kind] || 0) + 1;
    (byFile[f.file] = byFile[f.file] || []).push(f);
    if (SEV_RANK[f.severity] > SEV_RANK[topSev]) topSev = f.severity;
  }
  // Material-risk tier: drive primarily by topSev, but escalate when multiple
  // critical-tier hunks pile up in the same diff (e.g., auth-removed + new-shell-call).
  const critCount = findings.filter(f => f.severity === 'critical').length;
  let materialRisk = topSev;
  if (critCount >= 2) materialRisk = 'critical';
  return {
    materialRisk,
    findings: findings.filter(f => f.kind !== 'routine' || f.severity !== 'none'),
    perKindCounts: perKind,
    byFile,
  };
}

// Convenience: invoke `git diff <ref>...HEAD` for the project and classify it.
export function classifyGitDiff(rootDir, ref) {
  let out;
  try {
    out = cp.execFileSync('git', ['diff', '--unified=0', `${ref}...HEAD`], {
      cwd: rootDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch (e) {
    return { materialRisk: 'unknown', error: 'git diff failed: ' + (e.message || e), findings: [], perKindCounts: {}, byFile: {} };
  }
  return classifyDiff(out);
}

/**
 * FR-307: classify a candidate FIX (not a committed diff) for high-impact
 * change classes. `files` is `{relPath: {before, after}}` — exactly the
 * before/after content shape fix/apply-fix-service.js already has on hand
 * for every candidate write, so no git invocation or unified-diff text is
 * needed here. A crude but sufficient line-set diff (lines only in `after`
 * are additions, lines only in `before` are deletions) is enough for
 * PATTERN matching — classifyHunk operates per-line regardless of hunk
 * boundaries, so an imprecise line-diff still detects the same risk
 * signals a real diff would.
 *
 * Returns the same shape classifyDiff() does, plus `highImpactCategories`
 * — the deduplicated, sorted list of named categories
 * (auth/authZ/crypto/pii/schema/infra-privilege/public-api) any finding in
 * this candidate belongs to. An empty list means nothing in the candidate
 * matched one of the PRD's named high-impact classes — the approval gate
 * in apply-fix-service.js is a no-op in that case, same
 * restricts-nothing-until-triggered default this codebase's other policy
 * gates (egress/policy.js, dataflow/privacy-sink-policy.js) already follow.
 */
export function classifyFixMaterialRisk(files) {
  const findings = [];
  for (const [file, pair] of Object.entries(files || {})) {
    const before = String(pair?.before ?? '');
    const after = String(pair?.after ?? '');
    if (before === after) continue;
    const beforeLines = before.split('\n');
    const afterLines = after.split('\n');
    const beforeSet = new Set(beforeLines);
    const afterSet = new Set(afterLines);
    const add = afterLines.filter(l => !beforeSet.has(l));
    const del = beforeLines.filter(l => !afterSet.has(l));
    if (!add.length && !del.length) continue;
    findings.push(...classifyHunk({ file, add, del }));
  }
  const result = summarize(findings);
  const categories = new Set();
  for (const f of result.findings) {
    const cat = HIGH_IMPACT_CATEGORY_OF_KIND[f.kind];
    if (cat) categories.add(cat);
  }
  return { ...result, highImpactCategories: [...categories].sort() };
}
