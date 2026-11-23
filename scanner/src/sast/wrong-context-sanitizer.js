// Wrong-context output encoding (roadmap #1, practical slice) — CWE-79.
//
// Context-aware sanitization is the single biggest XSS precision lever, but
// the full model (context-tagged taint through the lattice) is a core-engine
// change. This detector ships the most impactful, UNAMBIGUOUS case as a
// standalone pattern rule:
//
//   An HTML-ENTITY encoder (escapeHtml / htmlspecialchars / he.encode /
//   lodash.escape …) applied to a value that is then used as a URL
//   (`.href` / `.src` / `location` / a JSX `href=`/`src=` attribute).
//
// HTML-entity encoding is the right tool for HTML *body/attribute text*. It
// does NOT neutralize a dangerous URL SCHEME — `javascript:alert(1)` and
// `data:text/html,…` survive entity-encoding unchanged, so the value is still
// XSS-exploitable in a URL context. This is a textbook wrong-context bug and a
// false sense of safety (the code looks sanitized).
//
// Deliberately high precision: only HTML-entity encoders (not generic names
// like bare `escape`, not `encodeURIComponent`, which is a different — non-XSS
// — mistake in URLs), and suppressed when a scheme/allow-list check is nearby.

import { blankComments } from './_comment-strip.js';

// Distinctive HTML-entity encoder callees. Intentionally excludes bare
// `escape` (too generic) and `encodeURIComponent` (URL-encoding, not XSS).
const HTML_ENCODER = "(?:escapeHtml|escapeHTML|htmlspecialchars|htmlentities|he\\.encode|he\\.escape|_\\.escape|lodash\\.escape)";

const PATTERNS = [
  // Assignment to a URL-bearing property: el.href = …escapeHtml(url)…
  new RegExp("\\b(?:location(?:\\.href)?|[\\w$.]+\\.(?:href|src))\\s*=\\s*([^;\\n]*?\\b" + HTML_ENCODER + "\\s*\\([^;\\n]*)", "g"),
  // JSX / template attribute: href={ escapeHtml(url) } / src="...${he.encode(u)}..."
  new RegExp("\\b(?:href|src)\\s*=\\s*[{\"'`]?[^\"'`>;\\n]*?\\b" + HTML_ENCODER + "\\s*\\(", "g"),
];

// A nearby URL-scheme allow-list / validation makes the HTML-encoder a
// belt-and-suspenders choice rather than the sole (wrong) defense → suppress.
const SCHEME_GUARD = [
  /\bstartsWith\s*\(\s*['"]https?:/i,
  /\^https\?:/i,
  /\bnew\s+URL\s*\(/,
  /\ballow(?:ed|list)?\s*(?:schemes?|protocols?|hosts?)/i,
  /\bprotocol\s*===?\s*['"]https?:/i,
  /\bsanitizeUrl\b|\bisSafeUrl\b|\bvalidateUrl\b/i,
];

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

// True when the URL value starts with a literal prefix that already FIXES the
// scheme, so nothing the encoded value contributes can turn it into a
// `javascript:` or `data:` URL. A URL scheme is letters, digits, `+`, `.` and
// `-` up to the first `:`; a prefix holding any other character either ends a
// complete scheme (`data:`, `mailto:`, `https://host/`) or makes the URL
// relative (`/img/`, `./`, `?q=`, `#`). A prefix of scheme characters only
// (`foo`, or none) does not: `foo` + `javascript:x` is still attacker-chosen.
// `valueText` is the attribute or assignment value from just after `=`.
const _SCHEME_CHAR = /^[A-Za-z0-9+.\-]*$/;
const _ENC_NAME = new RegExp('\\b' + HTML_ENCODER);
function _literalPrefixFixesScheme(valueText) {
  let v = String(valueText || '').replace(/^\s*[{"'`]?/, '');
  // The literal part ends at the first interpolation, concatenation, JSX or
  // PHP expression, quote, or the encoder call itself.
  const stops = [v.indexOf('${'), v.indexOf('+'), v.indexOf('{'), v.indexOf('<?'),
    v.search(/["'`]/), v.search(_ENC_NAME)].filter(i => i >= 0);
  const prefix = (stops.length ? v.slice(0, Math.min(...stops)) : v).trim();
  return prefix.length > 0 && !_SCHEME_CHAR.test(prefix);
}

function isJsLike(fp) { return /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp); }
function isPhp(fp) { return /\.php$/i.test(fp); }

// R5 (PRD §5) — context-aware sanitizer ADEQUACY. The model: a sanitizer
// neutralizes a specific context; using it before a sink of a DIFFERENT context
// is a no-op that looks safe. The highest-signal mismatches beyond the URL case
// above: an HTML-entity encoder applied to a value that then reaches a SHELL or
// SQL sink — HTML-escaping does nothing for command/SQL injection.
const _SHELL_SINK = /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|system|popen|shell_exec|child_process\.\w+)\s*\(/;
const _SQL_SINK = /\.(?:query|execute|raw|exec)\s*\(|\bdb\.raw\s*\(|sequelize\.query\s*\(/i;
const _HTML_ENC_CALL = new RegExp(HTML_ENCODER + "\\s*\\(", "g");

export function scanSanitizerContextMismatch(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  if (!isJsLike(fp) && !isPhp(fp) && !/\.py$/i.test(fp)) return [];
  if (!/escapeHtml|escapeHTML|htmlspecialchars|htmlentities|he\.encode|he\.escape|_\.escape|lodash\.escape/i.test(raw)) return [];
  if (!_SHELL_SINK.test(raw) && !_SQL_SINK.test(raw)) return [];
  const code = blankComments(raw);
  const lines = code.split('\n');
  const findings = [];
  const seen = new Set();
  // Track vars assigned directly from an HTML encoder (one hop).
  const htmlVars = new Set();
  const VAR_ASSIGN = new RegExp("(?:\\b(?:const|let|var)\\s+)?([A-Za-z_$][\\w$]*)\\s*=\\s*" + HTML_ENCODER + "\\s*\\(", "g");
  let m;
  while ((m = VAR_ASSIGN.exec(code))) htmlVars.add(m[1]);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isShell = _SHELL_SINK.test(line);
    const isSql = !isShell && _SQL_SINK.test(line);
    if (!isShell && !isSql) continue;
    const argRegion = line.slice(line.search(isShell ? _SHELL_SINK : _SQL_SINK));
    _HTML_ENC_CALL.lastIndex = 0;
    const inline = _HTML_ENC_CALL.test(argRegion);
    const viaVar = !inline && [...htmlVars].some((v) => new RegExp(`\\b${v}\\b`).test(argRegion));
    if (!inline && !viaVar) continue;
    if (seen.has(i + 1)) continue;
    seen.add(i + 1);
    const ctx = isShell ? { cwe: 'CWE-78', kind: 'command', vuln: 'Command Injection' }
      : { cwe: 'CWE-89', kind: 'SQL', vuln: 'SQL Injection' };
    findings.push({
      id: `wrong-context-sanitizer:sink:${fp}:${i + 1}`,
      severity: 'high',
      file: fp,
      line: i + 1,
      vuln: `Wrong-context sanitizer (HTML-encoded value used in a ${ctx.kind} sink)`,
      cwe: ctx.cwe,
      family: ctx.kind === 'command' ? 'command-injection' : 'sql-injection',
      parser: 'SAST',
      description: `An HTML-entity encoder was applied to a value that then flows into a ${ctx.kind} sink. HTML escaping neutralizes HTML markup, NOT ${ctx.kind} metacharacters — the value is still ${ctx.vuln}-exploitable while appearing sanitized.`,
      remediation: ctx.kind === 'command'
        ? 'Use an argv-form API (execFile/spawn with an args array), never a shell string; HTML escaping is irrelevant here.'
        : 'Use parameterized queries / prepared statements; HTML escaping does not prevent SQL injection.',
    });
  }
  return findings;
}

export function scanWrongContextSanitizer(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  if (!isJsLike(fp) && !isPhp(fp)) return [];
  // Cheap pre-filter: must contain both an HTML encoder and a URL sink token.
  if (!/escapeHtml|htmlspecialchars|htmlentities|he\.|_\.escape|lodash\.escape/i.test(raw)) return [];
  if (!/\b(?:href|src)\b|location/i.test(raw)) return [];

  const code = blankComments(raw, isPhp(fp) ? undefined : undefined);
  const lines = code.split('\n');
  const findings = [];
  const seen = new Set();

  for (const re of PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code))) {
      const line = lineOf(code, m.index);
      if (seen.has(line)) continue;
      // A literal prefix that fixes the scheme (`src="data:${escapeHtml(t)}"`,
      // `href = '/u/' + escapeHtml(id)`): the value cannot pick the scheme,
      // so HTML-encoding it is the right tool for the attribute.
      const valueText = m[1] !== undefined ? m[1] : m[0].replace(/^[^=]*=/, '');
      if (_literalPrefixFixesScheme(valueText)) continue;
      // Suppress when a scheme guard appears within 5 lines above.
      const lo = Math.max(0, line - 6);
      const near = lines.slice(lo, line).join('\n');
      if (SCHEME_GUARD.some(g => g.test(near))) continue;
      seen.add(line);
      findings.push({
        id: `wrong-context-sanitizer:${fp}:${line}`,
        severity: 'medium',
        file: fp,
        line,
        vuln: 'Wrong-context output encoding (HTML-encoded value used as a URL)',
        cwe: 'CWE-79',
        family: 'xss',
        parser: 'SAST',
        description:
          'An HTML-entity encoder is applied to a value used in a URL context (href/src/location). ' +
          'HTML-entity encoding does not neutralize dangerous URL schemes such as `javascript:` or ' +
          '`data:`, so the value remains XSS-exploitable — while looking sanitized.',
        remediation:
          'Validate the URL scheme against an allow-list (e.g. only http/https) or build the URL with ' +
          'the URL API; reserve HTML-entity encoding for HTML body/attribute text, not URLs.',
      });
    }
  }
  return findings;
}

// URL scheme DENYLIST (CWE-79). The complement of the rule above: no encoder, a check that looks like URL validation and is not.
//
//   if (/^\s*(javascript|vbscript|data):/i.test(href)) return text;
//   out += '<a href="' + escapeHtml(href) + '">';
//
// A regular expression that names the dangerous schemes is bypassed by every scheme it does not name and by the characters browsers
// drop or tolerate before and inside a scheme: ASCII control characters (`java\x01script:`), which `\s` does not cover, newlines and
// tabs inside the scheme name, HTML entities in an attribute (`&#106;avascript:`). The accepted fix is the other polarity, an
// allow-list of the schemes the attribute may carry (`https?`, `mailto`, `tel`, relative), after stripping control characters, or
// the URL parser's `protocol`. The rule needs two things in one file: a regex whose alternation names `javascript` as a scheme
// (the hallmark of a denylist; an allow-list names `https?` and never `javascript`), used as a test, and, within the next forty
// lines, the value reaching a URL attribute (`href=`/`src=` in markup, `.href =`, `.src =`, `setAttribute('href'|'src'`, `href:`).
// Silent when the file also carries an allow-list check or a scheme-aware sanitizer (`isValidAttribute`, `sanitizeUrl`, `new URL`
// with `protocol`), because the denylist is then not the only defence. Reported at the test, where the fix replaces it.
// JavaScript and TypeScript, Python, PHP and Ruby (the regex is read from the literal, whichever delimiter the language uses).
//
// Found by reading one development-split advisory of the independent population (0.222.0), a Markdown renderer's link and image
// hooks; measured on the development split's trees before release (the commit that added it has the numbers).
const SCHEME_DENYLIST_RE = /(?:^|[\/'"\(\s])(?:\\A|\^)?(?:\\s[*+]?)?\s*\(?(?:\?:)?(?:[a-z-]+\|)*javascript(?:\|[a-z-]+)*\)?\s*\\?:/i;
const SCHEME_TEST_RE = /\.(?:test|match|exec|search)\s*\(|\bre\.(?:match|search|fullmatch)\s*\(|\bpreg_match\s*\(|=~|\bmatch\?\s*\(/;
const URL_ATTRIBUTE_RE = /\b(?:href|src)\s*=|\.(?:href|src)\s*=[^=]|setAttribute\s*\(\s*['"](?:href|src)['"]|\b(?:href|src)\s*:\s*[^:]/i;
const SCHEME_ALLOWLIST_RE = /\(\?:?\s*(?:f|ht)tps?\??\s*\||\^\s*\(?\s*https?\??\s*[|):]|\bisValidAttribute\s*\(|\bsanitizeUrl\b|\bsanitize_url\b|\bisSafeUrl\b|\bis_safe_url\b|\bprotocol\s*(?:===?|!==?|in\b|==)|\bALLOWED_(?:URL_)?(?:SCHEMES|PROTOCOLS)\b|\ballowed_schemes\b|\bSAFE_(?:URL_)?(?:SCHEMES|PROTOCOLS)\b/;

function isTextLang(fp) { return isJsLike(fp) || isPhp(fp) || /\.(?:py|rb)$/i.test(fp); }

export function scanUrlSchemeDenylist(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  if (!isTextLang(fp)) return [];
  if (!/javascript/i.test(raw) || !/\b(?:href|src)\b/i.test(raw)) return [];
  const code = blankComments(raw);
  if (SCHEME_ALLOWLIST_RE.test(code)) return [];
  const lines = code.split('\n');
  const findings = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!/javascript/i.test(line) || !SCHEME_DENYLIST_RE.test(line)) continue;
    // The regex must be USED as a test on this line or the next two (a pattern bound to a name and tested later is matched by the
    // test line carrying the name; keep to the literal's own vicinity for precision).
    const testArea = lines.slice(i, i + 3).join('\n');
    if (!SCHEME_TEST_RE.test(testArea)) continue;
    const after = lines.slice(i + 1, i + 41).join('\n');
    if (!URL_ATTRIBUTE_RE.test(after)) continue;
    findings.push({
      id: `url-scheme-denylist:${fp}:${i + 1}`,
      severity: 'medium',
      file: fp,
      line: i + 1,
      vuln: 'URL scheme denylist (bypassable check before a URL attribute)',
      cwe: 'CWE-79',
      family: 'xss',
      parser: 'SAST',
      description:
        'A regular expression that names dangerous URL schemes (javascript:, vbscript:, data:) is the check before the value reaches an ' +
        'href or src attribute. A denylist is bypassed by every scheme it does not name and by the control characters, tabs and newlines ' +
        'browsers drop or tolerate inside a scheme, which `\\s` does not cover.',
      remediation:
        'Strip ASCII control characters, then allow only the schemes the attribute may carry (https?, mailto, tel, or a relative URL), ' +
        'or parse with the URL API and compare `protocol`; a denylist of schemes is never complete.',
    });
  }
  return findings;
}

