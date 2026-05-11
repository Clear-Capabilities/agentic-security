---
description: Pre-deploy checklist of the 10 things beginners typically miss before going live. Each item is green, yellow, or red with a one-line explanation.
---

Run a pre-launch checklist against your project. Designed for builders shipping their first production app.

```bash
node -e "
const fs = require('fs');
const path = require('path');

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
if (!scan) {
  console.log('No scan yet. Run /scan --all first, then /launch-check.');
  process.exit(0);
}

const findings = scan.findings || [];
const components = scan.components || [];
const routes = scan.routes || [];

// Helpers
function exists(p) { try { fs.accessSync(p); return true; } catch { return false; } }
function readMaybe(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }
function findingsMatching(matcher) {
  return findings.filter(f => matcher.test(f.vuln || '') || matcher.test(f.cwe || ''));
}
function depPresent(name) {
  return components.some(c => (c.name || '').toLowerCase() === name.toLowerCase());
}

// Read package.json once
const pkgRaw = readMaybe('package.json');
const pkg = pkgRaw ? (() => { try { return JSON.parse(pkgRaw); } catch { return null; } })() : null;
const allDeps = pkg ? { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) } : {};
const hasDep = (n) => Object.keys(allDeps).some(k => k.toLowerCase() === n.toLowerCase());

// .gitignore content
const gitignore = readMaybe('.gitignore') || '';

// .env in git?
const envInGit = (() => {
  try {
    const cp = require('child_process');
    const tracked = cp.execSync('git ls-files', { encoding: 'utf8', stdio: ['ignore','pipe','ignore'] });
    return tracked.split('\\n').some(l => /^\\.?env(\\..*)?$/.test(l.trim()));
  } catch { return null; }
})();

// Run the checklist
const checks = [];

// 1. Hardcoded secrets in source
const hardcoded = findingsMatching(/CWE-798|hardcoded.+(secret|key|token|password)/i).length;
checks.push({
  ok: hardcoded === 0,
  warn: false,
  label: 'No hardcoded secrets in source',
  detail: hardcoded === 0
    ? 'No API keys, tokens, or passwords found in code.'
    : hardcoded + ' hardcoded credential(s) detected. Move to env vars and rotate them now.',
});

// 2. .env in .gitignore
const envIgnored = /^\\s*\\.?env(\\..*)?$/m.test(gitignore) || /^\\s*\\*\\.env/m.test(gitignore);
checks.push({
  ok: envIgnored,
  warn: false,
  label: '.env is in .gitignore',
  detail: envIgnored ? '.env is excluded from git.' : 'Add .env to .gitignore — even one accidental commit puts secrets in git history forever.',
});

// 3. .env not in git history
checks.push({
  ok: envInGit === false,
  warn: envInGit === null,
  label: '.env not committed',
  detail: envInGit === false
    ? 'No .env files are tracked.'
    : envInGit === true
    ? '.env files ARE tracked in git. Run: git rm --cached .env && rotate every secret in it.'
    : 'Could not check (not a git repo?).',
});

// 4. Auth on routes that handle data
const totalRoutes = routes.length;
const unauthRoutes = routes.filter(r => !r.hasAuth).length;
const sensitiveUnauth = routes.filter(r => !r.hasAuth && r.method !== 'GET' && r.method !== 'HEAD').length;
checks.push({
  ok: sensitiveUnauth === 0,
  warn: sensitiveUnauth > 0 && sensitiveUnauth <= 2,
  label: 'State-changing routes require auth',
  detail: totalRoutes === 0
    ? 'No HTTP routes detected (might be a static site or library).'
    : sensitiveUnauth === 0
    ? totalRoutes + ' route(s), all state-changing endpoints have auth checks.'
    : sensitiveUnauth + ' POST/PUT/DELETE route(s) without auth. Anyone on the internet can call them.',
});

// 5. Rate limiting on the auth path
const rateLimit = findingsMatching(/rate.?limit/i).length;
const hasRL = hasDep('express-rate-limit') || hasDep('@upstash/ratelimit') || hasDep('rate-limiter-flexible') || hasDep('hono-rate-limiter');
checks.push({
  ok: hasRL || rateLimit === 0,
  warn: !hasRL && rateLimit > 0,
  label: 'Rate limiting on auth endpoints',
  detail: hasRL
    ? 'Rate-limit library detected.'
    : rateLimit > 0
    ? rateLimit + ' route(s) flagged as missing rate limits. Login/signup without limits = brute-force risk.'
    : 'No auth routes detected (might be intentional).',
});

// 6. Helmet / security headers
const hasHelmet = hasDep('helmet') || hasDep('@fastify/helmet');
const isWebApp = (allDeps.express || allDeps.koa || allDeps.fastify || allDeps.hono);
checks.push({
  ok: hasHelmet || !isWebApp,
  warn: !hasHelmet && isWebApp,
  label: 'Security headers (Helmet)',
  detail: hasHelmet
    ? 'Helmet is configured.'
    : !isWebApp
    ? 'Not a web app server (or using Next.js — has built-in headers).'
    : 'No helmet/CSP headers detected. Add `npm install helmet` and `app.use(helmet())`.',
});

// 7. Cookies set with Secure/HttpOnly/SameSite
const cookieIssues = findingsMatching(/cookie.+(secure|httponly|samesite|missing flag)/i).length;
checks.push({
  ok: cookieIssues === 0,
  warn: false,
  label: 'Cookies use Secure/HttpOnly/SameSite',
  detail: cookieIssues === 0
    ? 'No cookie flag issues detected.'
    : cookieIssues + ' cookie(s) missing security flags. Add { httpOnly: true, secure: true, sameSite: \"lax\" }.',
});

// 8. CORS allow-list (not *)
const permissiveCORS = findingsMatching(/cors.+(permissive|wildcard|origin.+\\*)/i).length;
checks.push({
  ok: permissiveCORS === 0,
  warn: false,
  label: 'CORS restricted to allow-list',
  detail: permissiveCORS === 0
    ? 'No permissive CORS detected.'
    : permissiveCORS + ' route(s) with CORS \"*\" or echoed Origin. Restrict to your domains only.',
});

// 9. No KEV-listed CVEs in deps
const kevFindings = findings.filter(f => f.kev === true).length;
checks.push({
  ok: kevFindings === 0,
  warn: false,
  label: 'No actively-exploited CVEs (CISA KEV)',
  detail: kevFindings === 0
    ? 'No KEV-listed dependency CVEs.'
    : kevFindings + ' CVE(s) being weaponized in the wild. Run /security-kev and update those packages first.',
});

// 10. No critical findings overall
const crit = findings.filter(f => f.severity === 'critical').length;
checks.push({
  ok: crit === 0,
  warn: false,
  label: 'No critical findings',
  detail: crit === 0
    ? 'Zero critical findings — safe to ship.'
    : crit + ' critical finding(s). Run /report-card for the bigger picture.',
});

// Render
const W = (s, code) => process.stdout.isTTY ? \`\\x1b[\${code}m\${s}\\x1b[0m\` : s;
const GREEN = '32', YELLOW = '33', RED = '31', BOLD = '1';

console.log('');
console.log(W('Pre-launch checklist (10 items)', BOLD));
console.log('');
let pass = 0, warn = 0, fail = 0;
for (const c of checks) {
  let icon, color;
  if (c.ok) { icon = '✓'; color = GREEN; pass++; }
  else if (c.warn) { icon = '⚠'; color = YELLOW; warn++; }
  else { icon = '✗'; color = RED; fail++; }
  console.log('  ' + W(icon, color) + '  ' + c.label);
  console.log('       ' + W(c.detail, '2'));
  console.log('');
}

console.log(W('Summary', BOLD));
const ratio = pass + '/' + checks.length;
const verdict = fail === 0 && warn === 0
  ? W('Ready to ship ✓', GREEN)
  : fail === 0
  ? W('Ship with caution', YELLOW) + ' — ' + warn + ' warning(s) to review'
  : W('Not ready', RED) + ' — ' + fail + ' blocker(s) to fix';
console.log('  Passing: ' + ratio + '. ' + verdict + '.');
console.log('');

// 0.14.0 — celebration on 10/10 + persist launch-ready achievement
if (fail === 0 && warn === 0) {
  console.log('  ' + W('🚀 SHIP IT', BOLD + ';' + GREEN));
  console.log('  ' + W('Every pre-launch check passed. You earned the Launch Ready achievement.', GREEN));
  console.log('');
  // Persist to streak.json
  try {
    const sp = '.agentic-security/streak.json';
    let s = {};
    try { s = JSON.parse(fs.readFileSync(sp, 'utf8')); } catch {}
    s.launchCheckPassedAt = new Date().toISOString();
    s.achievements = Array.from(new Set([...(s.achievements || []), 'launch-ready']));
    fs.mkdirSync('.agentic-security', { recursive: true });
    fs.writeFileSync(sp, JSON.stringify(s, null, 2));
  } catch {}
}
"
```

Print verbatim. The user wants a one-screen go/no-go decision before deploying.
