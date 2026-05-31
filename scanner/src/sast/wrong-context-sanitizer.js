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

function isJsLike(fp) { return /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp); }
function isPhp(fp) { return /\.php$/i.test(fp); }

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
