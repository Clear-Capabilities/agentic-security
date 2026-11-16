// What a response-writing call actually reflects.
//
// A reflected-XSS shape needs two things on the same call: a value the REQUEST
// supplied, and that value reaching the response without HTML encoding. Matching
// the text `req.` anywhere in the arguments gets both wrong:
//
//   * `req` carries framework and application state next to the request's own
//     input. `req.session.count`, `req.user.name`, `req.app.locals.title` and
//     `req.pet.id` are server-side values (a session store, a database row an
//     earlier middleware loaded, the app's configuration). They are second-order
//     data at most, not something the current request typed. Only the properties
//     that carry the request's input count (REQUEST_INPUT_PROPS).
//   * `escapeHtml(req.params.id)` has the request value, but it is encoded before
//     it is written. A value inside an HTML-escaper call is not reflected raw.
//
// This decides ONLY "does the call reflect raw request input". It does not model
// a variable assigned earlier; callers that match only the call text use it as a
// precision gate, and a flow through a variable is the taint layer's job.

import { callArgumentsAt } from './_call-args.js';

/** Properties of the request object that hold what the client sent. */
const REQUEST_INPUT_PROPS = [
  'body', 'query', 'params', 'headers', 'header', 'get', 'param', 'cookies', 'signedCookies',
  'hostname', 'host', 'subdomains', 'path', 'url', 'originalUrl', 'baseUrl', 'files', 'file',
  'rawBody', 'ip', 'ips', 'vhost', 'rawHeaders', 'trailers',
];

const REQ_INPUT_RE = new RegExp(
  String.raw`\breq(?:uest)?\s*(?:\.\s*(?:${REQUEST_INPUT_PROPS.join('|')})\b|\[\s*['"](?:${REQUEST_INPUT_PROPS.join('|')})['"]\s*\])`
  + String.raw`|\.(?:body|query|params)\s*\.`,
);

// HTML output encoders whose result is safe to place in HTML text.
const ESCAPER_CALL_RE = /\b(?:escapeHtml|escape_html|escapeHTML|sanitizeHtml|sanitize_html|DOMPurify\s*\.\s*sanitize|he\s*\.\s*(?:encode|escape)|_\s*\.\s*escape|validator\s*\.\s*escape|xss|striptags|escape)\s*\(/g;

// A helper the FILE defines that HTML-encodes its argument, recognised by what its body does, not by its name: the definition maps the
// three characters that can open markup or an entity (&, <, >) to their entity forms. `const esc = (s) => String(s).replace(/[&<>"']/g, ...)`
// qualifies; a helper that replaces only `&`, or returns its argument, does not. Verified-remediation PRD M0-06: a correct fix that
// introduced such a helper was refused because only library escapers by name were recognised.
const DEF_RE = /(?:\bfunction\s+([A-Za-z_$][\w$]*)\s*\(|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:function\b[^(]*)?\(?[^)=]*\)?\s*=>|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*function\b)/g;
export function localHtmlEscapers(text) {
  const src = String(text || '');
  const names = new Set();
  for (const m of src.matchAll(DEF_RE)) {
    const name = m[1] || m[2] || m[3];
    // the definition: up to the next top-level definition, at most 12 lines
    const body = src.slice(m.index, m.index + 1200).split('\n').slice(0, 12).join('\n');
    const next = body.slice(m[0].length).search(/\n\s*(?:function\s|(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=|exports\.|module\.exports)/);
    const def = next >= 0 ? body.slice(0, m[0].length + next) : body;
    if (!/\.replace(?:All)?\s*\(/.test(def)) continue;
    if (/&amp;/.test(def) && /&lt;/.test(def) && /&gt;/.test(def)) names.add(name);
  }
  return [...names];
}

/** Remove every balanced `escaper(...)` call from an expression; `extra` names further escapers (see localHtmlEscapers). */
export function stripHtmlEscaperCalls(expr, extra = []) {
  let out = String(expr);
  const names = extra.filter((n) => /^[A-Za-z_$][\w$]*$/.test(n)).map((n) => n.replace(/\$/g, '\\$'));
  const re = names.length ? new RegExp(`${ESCAPER_CALL_RE.source.replace(/\)\\s\*\\\($/, '')}|${names.join('|')})\\s*\\(`, 'g') : ESCAPER_CALL_RE;
  for (let guard = 0; guard < 50; guard++) {
    re.lastIndex = 0;
    const m = re.exec(out);
    if (!m) return out;
    let i = m.index + m[0].length;
    let depth = 1;
    while (i < out.length && depth > 0) {
      const c = out[i];
      if (c === '"' || c === "'" || c === '`') {
        const q = c; i++;
        while (i < out.length && out[i] !== q) { if (out[i] === '\\') i++; i++; }
      } else if (c === '(') depth++;
      else if (c === ')') depth--;
      i++;
    }
    if (depth !== 0) return out; // unbalanced: leave it, the caller keeps the finding
    out = out.slice(0, m.index) + '/*escaped*/' + out.slice(i);
  }
  return out;
}

/** Does this expression text contain raw (unescaped) request input? */
export function reflectsRawRequestInput(exprText, extraEscapers = []) {
  return REQ_INPUT_RE.test(stripHtmlEscaperCalls(exprText, extraEscapers));
}

const RESPONSE_WRITE_RE = /\bres(?:ponse)?\s*\.\s*(?:send|write|end)\s*\(/;

/**
 * For a response-write call on or just after `line`: does it reflect raw
 * request input? Returns null when no such call is found (no opinion).
 */
export function responseReflectsRequestInputAt(lines, line) {
  const args = callArgumentsAt(lines, line, RESPONSE_WRITE_RE);
  if (!args || args.length === 0) return null;
  return reflectsRawRequestInput(args.join(','), localHtmlEscapers(Array.isArray(lines) ? lines.join('\n') : ''));
}
