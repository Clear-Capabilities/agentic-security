// Open-redirect target shape (CWE-601): can the part of a redirect target the
// program does not control change the ORIGIN the browser is sent to?
//
// A redirect target is attacker-steerable to another origin only if the
// attacker controls the authority (scheme, host, port) of the resulting URL.
// A target that begins with a literal which already fixes the authority cannot
// be moved off-origin by whatever is appended after it:
//
//   '/user/' + id                   path-absolute, second character is a name
//                                   character: same origin, whatever `id` is
//   'https://app.example.com/' + p  the whole authority is in the literal and a
//                                   '/' closes it, so `p` is only path/query
//
// and these are NOT pinned, because the dynamic part decides the authority:
//
//   '/' + x                x = '/evil.example'  gives '//evil.example'
//   '//' + x, '/\\' + x    protocol-relative (browsers treat '\' as '/')
//   'https://app.example.com' + x   x = '.evil.example' or '@evil.example'
//   '' + x, x, x + '/path'          no literal prefix at all
//
// This is deliberately the ONLY thing decided here. It reads the text of the
// redirect call's first argument; it does not decide whether the dynamic part
// is attacker-controlled (that is the taint layer's question) and it never
// reads a file name, a fixture name or a label.

import { callArgumentsAt } from './_call-args.js';

const REDIRECT_CALL_RE = /\b(?:redirect|sendRedirect|Redirect|redirect_to|HttpResponseRedirect|RedirectResponse|redirectTo|permanentRedirect)\s*\(/;

/**
 * Leading literal text of an expression, and whether anything dynamic follows.
 * Handles 'a' + x, "a" + x + y, `a${x}`, and a lone literal.
 * `literal` is the decoded-enough prefix (escapes kept verbatim, which is safe
 * here because the checks below only look at slashes and the first characters).
 */
export function leadingLiteral(expr) {
  const s = String(expr).trim();
  let i = 0;
  let prefix = '';
  let dynamic = false;
  for (;;) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;
    const c = s[i];
    if (c === '"' || c === "'") {
      let j = i + 1; let body = '';
      while (j < s.length && s[j] !== c) { if (s[j] === '\\') { body += s[j] + (s[j + 1] || ''); j += 2; } else body += s[j++]; }
      if (j >= s.length) return { literal: prefix, dynamic: true, closed: false };
      prefix += body; i = j + 1;
    } else if (c === '`') {
      let j = i + 1; let body = '';
      while (j < s.length && s[j] !== '`') {
        if (s[j] === '\\') { body += s[j] + (s[j + 1] || ''); j += 2; continue; }
        if (s[j] === '$' && s[j + 1] === '{') { dynamic = true; break; }
        body += s[j++];
      }
      prefix += body;
      if (dynamic) return { literal: prefix, dynamic: true, closed: true };
      if (j >= s.length) return { literal: prefix, dynamic: true, closed: false };
      i = j + 1;
    } else {
      return { literal: prefix, dynamic: true, closed: true };
    }
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) return { literal: prefix, dynamic, closed: true };
    if (s[i] === '+') { i++; continue; }
    // anything else after a literal (a call suffix, `.concat`, `%`, ...): not a plain literal
    return { literal: prefix, dynamic: true, closed: true };
  }
  return { literal: prefix, dynamic, closed: true };
}

/** A literal prefix that fixes the origin of the URL it begins. */
export function prefixPinsOrigin(prefix) {
  // Path-absolute: '/' then a character that is neither '/' nor '\' (both are
  // read as a second slash, turning the reference into a network-path one).
  if (/^\/[^\/\\\s]/.test(prefix)) return true;
  // Absolute URL whose authority is complete: scheme://authority/ .
  if (/^[A-Za-z][A-Za-z0-9+.\-]*:\/\/[^\/?#\\\s]+\//.test(prefix)) return true;
  return false;
}

/**
 * Does the redirect argument keep the destination on a fixed origin?
 * `arg` is the first argument of the redirect call. A numeric first argument
 * (`res.redirect(302, url)`) is skipped by the caller, not here.
 */
export function redirectArgumentPinsOrigin(arg) {
  const { literal, dynamic, closed } = leadingLiteral(arg);
  if (!closed) return false;
  if (!dynamic) return literal.length > 0; // a fully static target
  return prefixPinsOrigin(literal);
}

/**
 * Inspect source lines starting at `line` (1-based) for a redirect call and
 * decide whether its target pins the origin. Returns null when no redirect
 * call is found (no opinion), else true/false.
 */
export function redirectTargetPinsOriginAt(lines, line) {
  const args = callArgumentsAt(lines, line, REDIRECT_CALL_RE);
  if (!args || args.length === 0) return null;
  // res.redirect(302, '/x'): the status code is not the target
  const target = args.length > 1 && /^\s*\d{3}\s*$/.test(args[0]) ? args[1] : args[0];
  return redirectArgumentPinsOrigin(target);
}
