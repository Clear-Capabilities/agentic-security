// Open Redirect (CWE-601).
//
// Pattern: a redirect target is derived from user input without an allow-
// list check. Attacker uses the trusted domain to bounce a victim to a
// phishing page. The bug is invisible in the URL bar until *after* the
// redirect fires.
//
// We catch:
//   - Express:        res.redirect(req.query.x | req.body.x | …)
//   - Koa:            ctx.redirect(ctx.query.x)
//   - Flask (Python): flask.redirect(request.args.get(…)) / redirect(request.…)
//   - Django (Python):HttpResponseRedirect(request.GET[…])
//   - Spring (Java):  return new RedirectView(name);  return "redirect:" + name;
//   - PHP:            header("Location: " . $_GET[...])
//
// We suppress the flag when the value is checked against an allow-list
// before redirect — recognized patterns: `ALLOWED.has(x)`, `x in ALLOWED`,
// `ALLOWED_REDIRECTS.includes(x)`, `if (x.startsWith('/'))` (relative-only),
// or `urlparse(x).hostname == self_host`.

import { blankComments } from './_comment-strip.js';

const PATTERNS = [
  // Express/Koa-style: res.redirect(<expr>) or ctx.redirect(<expr>).
  ['js', /\b(?:res|ctx|reply|response)\s*\.\s*redirect\s*\(\s*([^)]+?)\s*\)/g, 'Express/Koa'],
  // Bare redirect() — Flask / Werkzeug.
  ['py', /\b(?:flask\.)?redirect\s*\(\s*([^)]+?)\s*\)/g, 'Flask'],
  // Django.
  ['py', /\bHttpResponseRedirect\s*\(\s*([^)]+?)\s*\)/g, 'Django'],
  // Spring controllers — `return "redirect:" + name;`
  ['java', /\breturn\s+"redirect:"\s*\+\s*(\w[\w.]*)/g, 'Spring (return redirect:)'],
  // Spring RedirectView
  ['java', /\bnew\s+RedirectView\s*\(\s*(\w[\w.]*)\s*\)/g, 'Spring RedirectView'],
  // PHP header("Location: " . $...)
  ['php', /\bheader\s*\(\s*['"]\s*Location\s*:\s*['"]\s*\.\s*(\$\w[\w\[\]'"]*)/g, 'PHP Location'],
];

// What counts as "user-derived" inside the captured target expression.
const TAINT_HINT_RE =
  /\b(?:req\.|request\.|params\.|query\.|body\.|ctx\.query|ctx\.request|ctx\.params|reply\.query|r\.URL\.Query|c\.Query|next\b|_GET|_POST|_REQUEST|getParameter|getHeader)\b/;

// What counts as an allow-list check earlier in the function. We look back
// up to 30 lines before the redirect call for any of these patterns.
const ALLOWLIST_PATTERNS = [
  /\bALLOW(?:ED|LIST)?(?:_[A-Z_]+)?\.(?:has|includes|contains|indexOf)\b/i,
  /\bin\s+ALLOW(?:ED|LIST)?\b/,
  /\bin\s+\{[^}]+\}/,                            // `target in {'/a','/b'}`
  /\.startsWith\s*\(\s*['"]\//,                  // x.startsWith('/')
  /^\s*if\s*\(\s*\w+\.startsWith\s*\(\s*['"]\//, // explicit prefix check
  /urlparse\([^)]+\)\.(?:hostname|netloc)/,      // host extraction
  /url\.parse\([^)]+\)\s*\.\s*host(?:name)?/,
  /new\s+URL\s*\(\s*[^)]+\)\s*\.\s*hostname/,
  /\bvalid_redirect_url\b/,                      // common helper name
  /allowedRedirectTargets/i,
  /\babort\s*\(\s*4\d\d/,                        // any abort(4xx) earlier
  /\bres\s*\.\s*status\s*\(\s*4\d\d\b/,
];

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _lang(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.py$/i.test(fp)) return 'py';
  if (/\.java$/i.test(fp)) return 'java';
  if (/\.php$/i.test(fp)) return 'php';
  return null;
}

function _allowListedPrior(raw, callLine, target) {
  const lines = raw.split('\n');
  const lo = Math.max(0, callLine - 30);
  const before = lines.slice(lo, callLine).join('\n');
  // Strip the target out of `before` so the regex isn't fooled by the
  // target literal itself appearing in an allow-list match.
  for (const p of ALLOWLIST_PATTERNS) if (p.test(before)) return true;
  return false;
}

export function scanOpenRedirect(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw, lang === 'py' ? 'py' : undefined);
  if (!/\bredirect\b|RedirectView|HttpResponseRedirect|Location\s*:/i.test(code)) return [];
  const findings = [];
  const seen = new Set();
  for (const [plang, pat, framework] of PATTERNS) {
    if (plang !== lang) continue;
    const re = new RegExp(pat.source, pat.flags);
    let m;
    while ((m = re.exec(code))) {
      const target = (m[1] || '').trim();
      if (!target) continue;
      if (!TAINT_HINT_RE.test(target)) continue;
      const line = _lineOf(raw, m.index);
      // Suppress if an allow-list check appears in the preceding window.
      if (_allowListedPrior(raw, line, target)) continue;
      const id = `open-redirect:${fp}:${line}:${framework}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id,
        file: fp, line,
        vuln: `Open Redirect (${framework})`,
        severity: 'medium',
        cwe: 'CWE-601',
        family: 'open-redirect',
        stride: 'Spoofing',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation:
          'Validate the redirect target against a server-side allow-list of paths or hosts before redirecting. ' +
          'Restrict to relative paths starting with a single `/` (and rejecting `//`), or check the hostname against an explicit allow-list set. ' +
          'Never round-trip an attacker-supplied URL through `res.redirect` / `flask.redirect` / `HttpResponseRedirect` / `Location: …` without that check.',
        parser: 'OPEN-REDIRECT',
        confidence: 0.8,
      });
    }
  }
  return findings;
}
