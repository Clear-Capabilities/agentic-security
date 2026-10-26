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

/** Remove every balanced `escaper(...)` call from an expression. */
export function stripHtmlEscaperCalls(expr) {
  let out = String(expr);
  for (let guard = 0; guard < 50; guard++) {
    ESCAPER_CALL_RE.lastIndex = 0;
    const m = ESCAPER_CALL_RE.exec(out);
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
export function reflectsRawRequestInput(exprText) {
  return REQ_INPUT_RE.test(stripHtmlEscaperCalls(exprText));
}

const RESPONSE_WRITE_RE = /\bres(?:ponse)?\s*\.\s*(?:send|write|end)\s*\(/;

/**
 * For a response-write call on or just after `line`: does it reflect raw
 * request input? Returns null when no such call is found (no opinion).
 */
export function responseReflectsRequestInputAt(lines, line) {
  const args = callArgumentsAt(lines, line, RESPONSE_WRITE_RE);
  if (!args || args.length === 0) return null;
  return reflectsRawRequestInput(args.join(','));
}
