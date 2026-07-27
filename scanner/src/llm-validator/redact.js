// R10 — secret redaction for the Layer-3 LLM validator prompt.
//
// The validator sends real source-code excerpts to a model API. Those
// excerpts can contain live credentials that were hardcoded in the scanned
// project (API keys, tokens, private keys, connection-string passwords).
// This module strips likely secret VALUES while preserving the surrounding
// code STRUCTURE (variable name, operator, quotes, call shape) so the
// validator can still reason about the finding.
//
// Design tension (this is the point of the module): redact too little and a
// live key leaves the machine; redact too aggressively and the validator
// loses the context it needs to judge a finding. We resolve it by only
// touching values that match a specific credential shape — never whole
// lines, never identifiers, never ordinary string literals — and by biasing
// every heuristic toward leaving normal code alone (see the exclusions on
// the entropy pass below).
//
// Pure function, no I/O, no logging of the redacted material itself (only a
// count is returned) — callers must not print the input/output around this
// call in a way that defeats the point.

const REDACTED_PLACEHOLDER = '[REDACTED-SECRET]';

// Case-insensitive names that, when assigned a quoted string, are treated as
// carrying a credential. Exact identifiers only (word-boundary matched) —
// e.g. `password_field` does NOT match `password` because `_` is a word
// character and blocks the trailing \b.
const SECRET_KEY_NAMES = [
  'apiKey',
  'api_key',
  'secret',
  'token',
  'password',
  'passwd',
  'client_secret',
  'access_key',
  'private_key',
  'authorization',
];

const KEY_VALUE_RE = new RegExp(
  '(\\b(?:' + SECRET_KEY_NAMES.join('|') + ')\\b)(\\s*[:=]\\s*)([\'"`])([^\'"`]+)\\3',
  'gi'
);

// `Authorization: Bearer <blob>` — the blob only, scheme word survives.
const BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;

// PEM private-key blocks, any key type (`RSA PRIVATE KEY`, `EC PRIVATE KEY`,
// `PRIVATE KEY`, …). BEGIN/END markers are preserved so the excerpt still
// reads as "a private key was here"; the body is collapsed to one placeholder.
const PEM_RE = /-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END\s+[A-Z0-9 ]*PRIVATE KEY-----/gi;

// `scheme://user:PASSWORD@host` — only the password segment is replaced;
// scheme, user, and host/path survive.
const CONN_STRING_RE = /(:\/\/[^:/\s'"@]+:)([^@/\s'"]+)(@)/g;

// Quoted string literals (single/double/backtick), escape-aware, so the
// entropy pass below can inspect literal contents without being fooled by
// an escaped quote inside the literal.
const QUOTED_STRING_RE = /'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`/g;

// Minimum length before a bare string literal is even considered for the
// entropy pass. Conservative on purpose — short strings are indistinguishable
// from ordinary code tokens.
const ENTROPY_MIN_LENGTH = 24;
const ENTROPY_MIN_BITS_PER_CHAR = 4.0;
// base64url-ish charset only. Anything outside this (colons, slashes,
// semicolons, spaces, commas — e.g. a `data:...;base64,...` URI or a
// sentence) is left alone by construction, not by a special-cased exclusion.
const ENTROPY_CHARSET_RE = /^[A-Za-z0-9+/_=-]+$/;
// Pure-hex strings (git SHAs, color codes, hash digests) are common in
// ordinary code and have materially lower entropy-per-symbol than a random
// base64 secret at the same bit strength; treat them as non-secret.
const HEX_ONLY_RE = /^[0-9a-fA-F]+$/;

function shannonEntropy(str) {
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  const len = str.length;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function looksLikeHighEntropySecret(inner) {
  if (inner === REDACTED_PLACEHOLDER) return false; // already redacted upstream
  if (inner.length < ENTROPY_MIN_LENGTH) return false;
  if (!ENTROPY_CHARSET_RE.test(inner)) return false;
  if (HEX_ONLY_RE.test(inner)) return false; // e.g. git SHA — leave alone
  return shannonEntropy(inner) >= ENTROPY_MIN_BITS_PER_CHAR;
}

// redactSecrets(text) -> { text, redactions }
//
// Runs a fixed sequence of passes, most-specific first (PEM blocks and
// connection strings have unambiguous shapes; the entropy pass is the most
// general and runs last so it never fights with a more specific rule over
// the same span). Order does not affect whether a real secret is caught —
// only how many passes independently flag it — so a slight redaction-count
// overlap on an already-redacted span is harmless (the value is still gone
// exactly once; see KEY_VALUE_RE + BEARER_RE interaction for the one case
// where both can fire on the same literal).
export function redactSecrets(text) {
  if (typeof text !== 'string' || text.length === 0) {
    return { text: typeof text === 'string' ? text : '', redactions: 0 };
  }

  let redactions = 0;
  let out = text;

  // 1. PEM private-key blocks.
  out = out.replace(PEM_RE, (m) => {
    redactions++;
    const begin = (m.match(/^-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY-----/i) || [])[0] || '-----BEGIN PRIVATE KEY-----';
    const end = (m.match(/-----END\s+[A-Z0-9 ]*PRIVATE KEY-----$/i) || [])[0] || '-----END PRIVATE KEY-----';
    return `${begin}\n${REDACTED_PLACEHOLDER}\n${end}`;
  });

  // 2. Connection-string passwords.
  out = out.replace(CONN_STRING_RE, (_m, pre, _pass, at) => {
    redactions++;
    return `${pre}${REDACTED_PLACEHOLDER}${at}`;
  });

  // 3. Bearer tokens.
  out = out.replace(BEARER_RE, () => {
    redactions++;
    return `Bearer ${REDACTED_PLACEHOLDER}`;
  });

  // 4. `secretName = "value"` / `secretName: "value"` assignments.
  //
  // Special case: `authorization: "Bearer <blob>"` — keep the `Bearer `
  // scheme word (already handled generically by BEARER_RE above; this just
  // keeps this pass from re-swallowing it when it runs on the same span).
  out = out.replace(KEY_VALUE_RE, (_m, keyName, opWs, quote, value) => {
    redactions++;
    const bearer = /^(Bearer\s+)(.+)$/i.exec(value);
    if (bearer) return `${keyName}${opWs}${quote}${bearer[1]}${REDACTED_PLACEHOLDER}${quote}`;
    return `${keyName}${opWs}${quote}${REDACTED_PLACEHOLDER}${quote}`;
  });

  // 5. Long high-entropy string literals not caught by a more specific rule.
  out = out.replace(QUOTED_STRING_RE, (m) => {
    const q = m[0];
    const inner = m.slice(1, -1);
    if (!looksLikeHighEntropySecret(inner)) return m;
    redactions++;
    return `${q}${REDACTED_PLACEHOLDER}${q}`;
  });

  return { text: out, redactions };
}
