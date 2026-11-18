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
  // Go net/http: http.Redirect(w, r, <target>, code) — target is the 3rd arg
  // (may contain calls/parens); status is a digit or an http.Status* constant.
  ['go', /\bhttp\.Redirect\s*\(\s*[^,]+,\s*[^,]+,\s*([\s\S]+?)\s*,\s*(?:\d|http\.Status)/g, 'Go net/http'],
  // Ruby on Rails: redirect_to <target> (params/var).
  ['rb', /\bredirect_to\s+(?!.*\bonly_path:\s*true)([^\n,]+?)(?:\s+status:|\s*$|\n)/gm, 'Rails redirect_to'],
  // C#: Response.Redirect(<target>) / return Redirect(<target>) / RedirectPermanent.
  ['cs', /\b(?:Response\.Redirect|return\s+Redirect|return\s+RedirectPermanent|RedirectPermanent)\s*\(\s*([^)]+?)\s*\)/g, 'ASP.NET Redirect'],
  // Kotlin/Servlet: resp.sendRedirect(<target>).
  ['kt', /\.\s*sendRedirect\s*\(\s*([^)]+?)\s*\)/g, 'Servlet sendRedirect'],
];

// What counts as "user-derived" inside the captured target expression.
const TAINT_HINT_RE =
  /\b(?:req\.|request\.|params\.|params\s*\[|query\.|body\.|ctx\.query|ctx\.request|ctx\.params|reply\.query|r\.URL\.Query|c\.Query|c\.Param|next\b|_GET|_POST|_REQUEST|getParameter|getHeader|Request\.(?:Query|Form|Params|QueryString))\b|\b(?:params|query|cookies)\s*\[/;

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
  /\bin_array\s*\(/i,                            // PHP in_array(...) allow-list check
  /\bonly_path:\s*true/,                         // Rails redirect_to …, only_path: true
  /\bUrl\.IsLocalUrl\b|\bLocalRedirect\b/,       // ASP.NET local-only redirect
  /\bin\s+(?:allowed|allow|ALLOWED)\b/,          // Kotlin/Ruby `next in allowed`
  /\bstrings\.HasPrefix\s*\(\s*\w+\s*,\s*"\/"/,  // Go relative-path check
  /\bset(?:Of)?\s*\([^)]*\)\.contains\b/,        // Kotlin allowed.contains(next)
];

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _lang(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.py$/i.test(fp)) return 'py';
  if (/\.java$/i.test(fp)) return 'java';
  if (/\.(?:php|phtml)$/i.test(fp)) return 'php';
  if (/\.go$/i.test(fp)) return 'go';
  if (/\.rb$/i.test(fp)) return 'rb';
  if (/\.cs$/i.test(fp)) return 'cs';
  if (/\.kt$/i.test(fp)) return 'kt';
  return null;
}

// For C#/Kotlin/Go a bare-identifier redirect target is user-derived when it is
// a parameter of the enclosing method/handler (the single-file handler shape).
const _PARAM_LANGS = new Set(['cs', 'kt', 'go']);
function _isEnclosingParam(code, callIdx, target) {
  if (!/^[A-Za-z_]\w*$/.test(target)) return false;
  const before = code.slice(0, callIdx);
  const sigRe = /\b(?:fun\s+\w+|func\s+\w*|[A-Za-z_][\w<>\[\],.\s]*\b\w+)\s*\(([^)]*)\)\s*(?::[^={]+|[A-Za-z_][\w.<>\[\]* ]*)?\{/g;
  let sig = null, sm;
  while ((sm = sigRe.exec(before)) !== null) sig = sm;
  if (!sig) return false;
  const params = sig[1].split(',').map((p) => {
    const t = p.trim(); if (!t) return '';
    if (t.includes(':')) return t.split(':')[0].trim();      // Kotlin name: Type
    return (t.split(/\s+/)[t.includes(' ') ? (t.trim().split(/\s+/).length - 1) : 0] || '').trim();
  });
  // Go params are `name Type` (name first); JVM/C# are `Type name` (name last).
  const goParams = sig[1].split(',').map((p) => (p.trim().split(/\s+/)[0] || '').trim());
  return params.includes(target) || goParams.includes(target);
}

// A "starts with /" test alone is not a same-origin check: `//evil.example` and `/\\evil.example` start with `/` and browsers treat
// them as another host. The prefix patterns of ALLOWLIST_PATTERNS count only when the same code also rejects those.
const PREFIX_ONLY_PATTERNS = new Set([ALLOWLIST_PATTERNS[3], ALLOWLIST_PATTERNS[4], ALLOWLIST_PATTERNS[16]]);
const REJECTS_PROTOCOL_RELATIVE =
  /['"`]\/\/['"`]|\\\/\\\/|['"`]\/\\\\['"`]|\[\s*1\s*\]\s*[!=]==?\s*['"`]\/|charAt\s*\(\s*1\s*\)|\.host(?:name)?\b|\bnetloc\b|\bhost\.nil\?|\bnew\s+URL\s*\(|\burlparse\s*\(|\bparse_url\s*\(|\burl\.Parse\s*\(|\bURI\s*\(|url_has_allowed_host_and_scheme|is_safe_url|IsLocalUrl/;

const BARE_SLASH_PREFIX = /(?:startsWith\s*\(\s*['"]\/['"]\s*\)|HasPrefix\s*\(\s*\w+\s*,\s*"\/"\s*\))/;

function _allowListedPrior(raw, callLine, target) {
  const lines = raw.split('\n');
  const lo = Math.max(0, callLine - 30);
  const before = lines.slice(lo, callLine).join('\n');
  // Strip the target out of `before` so the regex isn't fooled by the
  // target literal itself appearing in an allow-list match.
  for (const p of ALLOWLIST_PATTERNS) {
    if (!p.test(before)) continue;
    // a longer fixed prefix (`startsWith('/app/')`) pins the path; a bare `/` does not pin the host
    if (PREFIX_ONLY_PATTERNS.has(p) && BARE_SLASH_PREFIX.test(before) && !REJECTS_PROTOCOL_RELATIVE.test(before)) continue;
    return true;
  }
  return false;
}

// A "local path" check used as the same-origin guard of a redirect that accepts anything starting with `/` (CWE-601): Ruby's
// URI ABS_PATH regexp, `start_with?('/')`, `startsWith('/')`, `startswith('/')`, `[0] === '/'`. `//host/x` and `/\host/x` pass all of
// them and leave the site. Reported at the check, in code about redirects, unless the same lines also reject `//` and `/\` or parse
// the host.
const LOCAL_PATH_TEST = {
  rb: /=~\s*URI(?:::DEFAULT_PARSER|::RFC2396_PARSER|::Parser\.new|::RFC2396_Parser\.new)?\.regexp\[\s*:ABS_PATH\s*\]|=~\s*URI::ABS_PATH\b|\.start_with\?\s*\(?\s*['"]\/['"]\s*\)?|=~\s*%r\{\\A\/\}|=~\s*\/\\A\\\/\//g,
  js: /\.startsWith\s*\(\s*['"`]\/['"`]\s*\)|\[\s*0\s*\]\s*===?\s*['"`]\/['"`]|\.charAt\s*\(\s*0\s*\)\s*===?\s*['"`]\/['"`]/g,
  py: /\.startswith\s*\(\s*['"]\/['"]\s*\)/g,
  php: /\bstr_starts_with\s*\(\s*\$\w+\s*,\s*['"]\/['"]\s*\)|\$\w+\s*\[\s*0\s*\]\s*===?\s*['"]\/['"]/g,
};
const REDIRECT_CONTEXT = /redirect|return_?to|returnUrl|same_?origin|next_?url|safe_?url|local_?url|callback_?url|continue_?url/i;

export function scanWeakLocalPathGuard(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  const re0 = LOCAL_PATH_TEST[lang];
  if (!re0 || !REDIRECT_CONTEXT.test(raw)) return [];
  const code = blankComments(raw, (lang === 'py' || lang === 'rb') ? 'py' : undefined);
  const lines = code.split('\n');
  const out = [];
  const seen = new Set();
  const re = new RegExp(re0.source, re0.flags);
  let m;
  while ((m = re.exec(code))) {
    const line = _lineOf(code, m.index);
    if (seen.has(line)) continue;
    const text = lines[line - 1] || '';
    // the test must decide something: a condition, a boolean expression, or a returned predicate
    if (!/\b(?:if|unless|elsif|elif|return|when|while)\b|&&|\|\||\?|\band\b|\bor\b/.test(text)
      && !/^\s*(?:\|\||&&|or\b|and\b)/.test(lines[line] || '') && !/(?:\|\||&&|\bor|\band)\s*$/.test(lines[line - 2] || '')) continue;
    // `p.startsWith('/') ? p : '/' + p` adds a missing slash; it is normalisation, not a guard
    if (/\?[^:]*:\s*(?:`\/\$\{|['"]\/['"]\s*[+.]|"\/#\{)/.test(text)) continue;
    const win = lines.slice(Math.max(0, line - 11), Math.min(lines.length, line + 10)).join('\n');
    if (!REDIRECT_CONTEXT.test(win)) continue;
    const near = lines.slice(Math.max(0, line - 6), Math.min(lines.length, line + 5)).join('\n');
    if (REJECTS_PROTOCOL_RELATIVE.test(near)) continue;
    seen.add(line);
    out.push({
      id: `open-redirect-weak-local-path:${fp}:${line}`,
      file: fp, line,
      vuln: 'Open Redirect: "local path" check accepts //host and /\\host',
      severity: 'medium', cwe: 'CWE-601', family: 'open-redirect', stride: 'Spoofing',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      description: 'A redirect target is accepted as same-site because it starts with `/` (or matches an absolute-path pattern). `//attacker.example/x` and `/\\attacker.example/x` pass that test, and browsers resolve both to another host, so the check lets an attacker send users off the site.',
      remediation: 'Also reject targets whose second character is `/` or `\\`, or parse the target and require that it has no host (or a host on your allow-list) before redirecting.',
      parser: 'OPEN-REDIRECT',
      confidence: 0.6,
    });
  }
  return out;
}

export function scanOpenRedirect(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw, (lang === 'py' || lang === 'rb') ? 'py' : undefined);
  if (!/\bredirect|RedirectView|HttpResponseRedirect|Location\s*:|sendRedirect|http\.Redirect/i.test(code)) return [];
  const findings = [];
  const seen = new Set();
  for (const [plang, pat, framework] of PATTERNS) {
    if (plang !== lang) continue;
    const re = new RegExp(pat.source, pat.flags);
    let m;
    while ((m = re.exec(code))) {
      const target = (m[1] || '').trim();
      if (!target) continue;
      // Literal-string target ("/home", "https://fixed") is never user-derived.
      if (/^["'`][^"'`]*["'`]$/.test(target)) continue;
      if (!TAINT_HINT_RE.test(target) &&
          !(_PARAM_LANGS.has(plang) && _isEnclosingParam(code, m.index, target))) continue;
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
