// PHP: a variable interpolated, unescaped, into an HTML attribute of markup that is returned or echoed (CWE-79).
//
// xss-reflected-multilang.js needs a request superglobal on the line. Widget, list-column and template-helper code never touches the
// request: it renders a record's value or a URL derived from one, and the published advisories in that shape build an element in a
// double-quoted string, `return "<img src='$url' width='$w'>";`, where a value holding a quote closes the attribute and opens a new one
// (an event handler).
//
//   sink    a `return`, `echo` or `print` of a double-quoted string literal on one line that holds a tag with a `$var` (or `{$var}`)
//           inside an attribute value.
//   silent  a value escaped where it was last assigned in the enclosing 60 lines (htmlspecialchars, htmlentities, e(), esc_attr /
//           esc_html / esc_url, urlencode, rawurlencode) or forced to a number ((int), intval, floatval, count, number_format),
//           and markup built with sprintf/printf (its arguments are where the escape goes, and are not string interpolation).
//
// Element text (`"<td>$name</td>"`) is not a sink here: measured on the development split, view helpers interpolate values escaped
// further up into element text far more often than into attributes, and the attribute is where the published fixes landed.
// The rule does not decide whether the value can hold attacker text; the finding says so.

const FILE_RE = /\.(?:php|phtml)$/i;
const SAFE = /\b(?:htmlspecialchars|htmlentities|e|esc_attr|esc_html|esc_url|esc_textarea|urlencode|rawurlencode|intval|floatval|absint|count|number_format|strip_tags|json_encode)\s*\(|\(\s*(?:int|integer|float|double|bool)\s*\)|\b(?:Html|HTML)::\w+\s*\(/;
// a double-quoted literal (no unescaped `"` inside), returned or echoed
const STMT = /\b(?:return|echo|print)\s*\(?\s*"((?:[^"\\\n]|\\.)*)"\s*\)?\s*;/g;
// the text of each start tag, and an attribute value open at the end of a prefix: name='..., name=\"..., or unquoted name=
const TAG = /<[a-zA-Z][^<>]*/g;
const OPEN_ATTR_VALUE = /\s[\w:-]+\s*=\s*(?:'[^']*|\\"[^"]*|\{?)$/;

/** Variables interpolated inside an attribute value of a start tag in a double-quoted PHP string body. */
function attrVars(body) {
  const out = [];
  for (const t of body.matchAll(TAG)) {
    const tag = t[0];
    for (const v of tag.matchAll(/\$(\w+)/g)) if (OPEN_ATTR_VALUE.test(tag.slice(0, v.index))) out.push(v[1]);
  }
  return out;
}

const lineOf = (src, idx) => src.slice(0, idx).split('\n').length;

export function scanPhpHtmlAttrInterpolation(fp, raw) {
  if (!FILE_RE.test(fp) || typeof raw !== 'string' || raw.length > 500_000 || !raw.includes('<')) return [];
  if (/(?:^|\/)tests?\//i.test(fp) || /Test\.php$/.test(fp)) return [];
  const lines = raw.split('\n');
  const out = []; const seen = new Set();
  for (const m of raw.matchAll(STMT)) {
    const body = m[1];
    if (!/<[a-zA-Z]/.test(body)) continue;
    const line = lineOf(raw, m.index);
    const before = lines.slice(Math.max(0, line - 61), line - 1).join('\n');
    const bad = [];
    for (const v of attrVars(body)) {
      if (v === 'this') continue;
      const assigns = [...before.matchAll(new RegExp(`\\$${v}\\s*(?:\\.?=)(?![=>])([^;]*)`, 'g'))];
      if (assigns.length && SAFE.test(assigns[assigns.length - 1][1])) continue;
      bad.push(v);
    }
    if (!bad.length) continue;
    const id = `php-html-attr-interpolation:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const names = [...new Set(bad)].map((v) => `$${v}`).join(', ');
    out.push({
      id, file: fp, line,
      vuln: 'XSS: variable interpolated unescaped into an HTML attribute',
      severity: 'medium', cwe: 'CWE-79', family: 'xss',
      description: `Markup returned or printed here interpolates ${names} into an attribute value without escaping. A value holding a quote ends the attribute and can add an event handler or another element. Whether the value can hold text an attacker controls is not checked here.`,
      remediation: "Escape each value for the attribute where it is inserted: `sprintf(\"<img src='%s'>\", htmlspecialchars($url, ENT_QUOTES))` (or the framework's escaper, such as `e($url)`), and cast numeric attributes with (int).",
      snippet: (lines[line - 1] || '').trim().slice(0, 200), parser: 'PHP', confidence: 0.55,
    });
  }
  return out;
}
