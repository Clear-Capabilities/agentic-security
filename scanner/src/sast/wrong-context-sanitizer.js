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
