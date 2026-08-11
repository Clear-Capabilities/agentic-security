// Cross-language reflected-XSS structural detector — PRD Tier 1 (recall).
//
// JS/Python reflected XSS is handled by the flow engine + framework structural
// detectors; the second-tier languages had no XSS coverage. This module adds a
// taint-independent structural rule per language: user input written into an
// HTML response via concatenation / interpolation, without an output encoder.
//
// Precision: each language carries its own escaper exclusion (htmlspecialchars,
// HtmlEncode, html_escape, template.HTMLEscapeString, …). When an escaper is
// applied on the sink line the finding is suppressed — the parameterized/encoded
// form must NOT match. HTML context is required (an HTML tag literal, an HTML
// content-type, or a raw-superglobal echo) so plain-text responses don't fire.

import { blankComments } from './_comment-strip.js';

const lineOf = (raw, idx) => raw.substring(0, idx).split('\n').length;

const REMEDIATION =
  'HTML-encode user input before writing it into a response: htmlspecialchars (PHP), ' +
  'template/html.EscapeString (Go), ERB::Util.html_escape / avoid .html_safe (Ruby), ' +
  'HttpUtility.HtmlEncode (C#), or an auto-escaping template engine. Never concatenate ' +
  'request data straight into an HTML response.';

// Per-language: { ext, sinks:[RegExp], escaper:RegExp }. A line matches when a
// sink RegExp matches and the escaper RegExp does NOT.
const LANGS = {
  go: {
    ext: /\.go$/i,
    // fmt.Fprint*/io.WriteString to the ResponseWriter, or w.Write([]byte(...)),
    // building an HTML string ("<…") by concatenation.
    sinks: [
      /\b(?:fmt\.Fprintf?|fmt\.Fprintln|io\.WriteString)\s*\(\s*w\b[^)\n]*"<[^"\n]*"\s*\+/,
      /\bw\.Write\s*\(\s*\[\]byte\s*\(\s*"<[^"\n]*"\s*\+/,
    ],
    escaper: /\b(?:template\.HTMLEscapeString|html\.EscapeString|template\.HTMLEscaper)\s*\(/,
  },
  php: {
    ext: /\.(?:php|phtml)$/i,
    // echo/print of a request superglobal (directly or concatenated).
    sinks: [
      /\b(?:echo|print)\b[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
      /\bprintf\s*\([^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    ],
    escaper: /\b(?:htmlspecialchars|htmlentities|strip_tags|filter_var|urlencode|rawurlencode|json_encode|intval|floatval|htmlspecialchars_decode)\s*\(/,
  },
  ruby: {
    ext: /\.rb$/i,
    // render inline:/html: with #{} interpolation, raw(params…), params….html_safe
    sinks: [
      /\brender\s+(?:inline|html):\s*["'][^"'\n]*#\{/,
      /\braw\s*\(\s*(?:params|request|@\w+\.params)\b/,
      /\b(?:params|request)\b[^\n]*\.\s*html_safe\b/,
    ],
    escaper: /\b(?:ERB::Util\.html_escape|CGI\.escapeHTML|h\s*\(|sanitize\s*\()/,
  },
  csharp: {
    ext: /\.cs$/i,
    // Response.Write of Request data, or an HTML string concatenation.
    sinks: [
      /\bResponse\.Write\s*\([^)\n]*\bRequest\b/,
      /\bResponse\.Write\s*\(\s*"<[^"\n]*"\s*\+/,
    ],
    escaper: /\b(?:HttpUtility\.HtmlEncode|HtmlEncoder\.|Server\.HtmlEncode|WebUtility\.HtmlEncode|AntiXss\.)/,
  },
  kotlin: {
    ext: /\.kt$/i,
    // Ktor respondText building HTML by interpolation/concat.
    sinks: [
      /\brespondText\s*\(\s*"<[^"\n]*\$/,
      /\brespondText\s*\(\s*"<[^"\n]*"\s*\+/,
      /\brespondText\s*\(\s*"[^"\n]*\$[^"\n]*"\s*,\s*ContentType\.Text\.Html/,
    ],
    escaper: /\b(?:htmlEscape|escapeHtml|HtmlUtils\.htmlEscape|encodeHTML)\s*\(/,
  },
  java: {
    ext: /\.java$/i,
    // Servlet: response.getWriter().write/print/println(...) or a PrintWriter
    // `out`, building an HTML string ("<…") by concatenation. The concat (`"<…"
    // +`) is the reflected-XSS shape — a static literal has no `+`.
    sinks: [
      /\.\s*(?:getWriter\s*\(\s*\)\s*\.\s*)?(?:write|print|println|append|format|printf)\s*\(\s*"<[^"\n]*"\s*\+/,
      /\b(?:out|writer|pw|w)\s*\.\s*(?:write|print|println|append)\s*\(\s*"<[^"\n]*"\s*\+/,
    ],
    escaper: /\b(?:encodeForHTML|forHtml|forHtmlContent|htmlEscape|escapeHtml4?|StringEscapeUtils|HtmlUtils\.htmlEscape|Encode\.forHtml|ESAPI|OWASP)\b/,
  },
};

export function scanXssReflectedMultilang(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  let lang = null;
  for (const v of Object.values(LANGS)) { if (v.ext.test(fp)) { lang = v; break; } }
  if (!lang) return [];

  const code = blankComments(raw, /\.rb$/i.test(fp) ? 'py' : (/\.(?:php|phtml)$/i.test(fp) ? 'php' : undefined));
  const lines = code.split('\n');
  const findings = [];
  const seen = new Set();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (lang.escaper.test(line)) continue;
    if (!lang.sinks.some((re) => re.test(line))) continue;
    const ln = i + 1;
    const id = `xss-reflected:${fp}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id, file: fp, line: ln,
      vuln: 'Reflected XSS — user input written into an HTML response without output encoding',
      severity: 'high', cwe: 'CWE-79', family: 'xss', parser: 'XSS-ML', confidence: 0.62,
      snippet: (raw.split('\n')[ln - 1] || '').trim().slice(0, 200),
      remediation: REMEDIATION,
    });
  }
  return findings;
}
