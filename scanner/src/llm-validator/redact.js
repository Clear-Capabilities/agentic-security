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

// Case-insensitive names that, when assigned a string, are treated as
// carrying a credential. `[_-]?` between compound words so a real .env/shell
// naming convention (`DB_PASSWORD`, `STRIPE_API_KEY`) matches — those are
// two segments joined by `_`, not one identifier, so a plain `\b` (which
// treats `_` as a word character) would never see a boundary before
// `PASSWORD` in `DB_PASSWORD` at all. Handled below via lookaround, not \b.
const SECRET_KEY_NAMES = [
  'api[_-]?key',
  'secret',
  'token',
  'password',
  'passwd',
  'client[_-]?secret',
  'access[_-]?key',
  'private[_-]?key',
  'authorization',
];

// Asymmetric boundary, deliberately not a plain `\b` on either side:
//   BEFORE the name: anything non-alphanumeric counts as a boundary,
//     INCLUDING `_`/`-` — this is what lets `DB_PASSWORD`/`stripe-api-key`
//     match despite `_`/`-` being `\w` characters a real `\b` would treat
//     as "still inside the same word."
//   AFTER the name: only a non-alphanumeric, non-underscore char (or
//     string end) counts — this is a real `\b`-equivalent on the suffix
//     side, which is what keeps `password_field`/`tokenExpiry` from
//     matching (a field ABOUT a secret, not a secret itself). Losing this
//     asymmetry either direction reintroduces one of the two failure
//     modes this module exists to avoid (see the module header).
const NAME_BOUNDARY = (name) => `(?<![A-Za-z0-9])(?:${name})(?![A-Za-z0-9_])`;
const KEY_NAME_ALT = SECRET_KEY_NAMES.map(NAME_BOUNDARY).join('|');

// The optional quote group right after the key name handles a JSON/YAML
// QUOTED key (`"password": "value"`) — the boundary lookaheads in
// NAME_BOUNDARY already treat the closing quote as a valid non-alphanumeric
// "after" boundary, but without this group the operator match immediately
// following would fail to consume that quote char before `[:=]`.
const KEY_VALUE_RE = new RegExp(
  '(' + KEY_NAME_ALT + ')([\'"`]?\\s*[:=]\\s*)([\'"`])([^\'"`]+)\\3',
  'gi'
);

// Split-string-concatenation (adversarial-review fix, 2026-09, second pass):
// `const secret = "Super" +\n  "Secret123456";` used to redact only the
// FIRST segment — KEY_VALUE_RE matches one quoted literal, stops, and the
// second literal (joined by `+`, possibly on its own line) survives
// untouched, leaking the tail of the real value. Requires AT LEAST ONE `+`
// join (`+` one-or-more, not `*`) so this pass targets only the genuinely-
// concatenated case and never overlaps with — or double-processes — the
// plain single-literal case KEY_VALUE_RE already owns. The whole matched
// expression (every segment, every operator) is collapsed to ONE placeholder
// literal rather than trying to preserve per-segment structure: a
// concatenation is already an unusual enough shape that this codebase's
// "value gone, structure survives" ergonomic goal is secondary to just not
// leaking the tail half of a secret.
const CONCAT_KEY_VALUE_RE = new RegExp(
  '(' + KEY_NAME_ALT + ')([\'"`]?\\s*[:=]\\s*)([\'"`][^\'"`]*[\'"`](?:\\s*\\+\\s*[\'"`][^\'"`]*[\'"`])+)',
  'gi'
);

// camelCase compound identifiers (adversarial-review fix, 2026-09):
// `authToken`, `apiSecret`, `userPassword` all leaked through the original
// fix, which only generalized the `_`/`-`-delimited compound case
// (`DB_PASSWORD`). A plain `i` flag doesn't help here — case-insensitivity
// makes "Token" and "token" match the same NAME, but the boundary problem is
// separate: `(?<![A-Za-z0-9])` still fails when "Token" is preceded by the
// letters "auth", regardless of case. This is a SEPARATE, case-SENSITIVE
// regex specifically for "a capitalized key-name segment immediately
// preceded by a lowercase letter or digit" (the actual camelCase join
// point), run as its own pass — mixing this into the case-insensitive
// KEY_VALUE_RE would make it fire on the ALL-CAPS compound case too
// (`DB_PASSWORD`), which is already handled and correctly rejects the
// suffix-side `password_field` case using the case-insensitive boundary.
//
// Deliberately narrower than the full SECRET_KEY_NAMES list: "Key" alone
// (for `apiKey`/`accessKey`/`privateKey`) is too generic a camelCase suffix
// on its own (`primaryKey`, `cacheKey`, `sortKey` are not secrets) — those
// three stay as their full compound word here, matched case-flexibly on the
// FIRST letter of each segment only (`[Aa]pi[Kk]ey`, not full case-
// insensitivity, to keep this pass's own boundary logic exact).
const CAMEL_CASE_NAMES = [
  'Token', 'Secret', 'Password', 'Passwd', 'Authorization',
  '[Aa]pi[Kk]ey', '[Aa]ccess[Kk]ey', '[Pp]rivate[Kk]ey', '[Cc]lient[Ss]ecret',
];
const CAMEL_NAME_ALT = CAMEL_CASE_NAMES
  .map((name) => `(?<=[a-z0-9])(?:${name})(?![A-Za-z0-9_])`)
  .join('|');
const CAMEL_KEY_VALUE_RE = new RegExp(
  '(' + CAMEL_NAME_ALT + ')([\'"`]?\\s*[:=]\\s*)([\'"`])([^\'"`]+)\\3',
  'g' // NOT case-insensitive — the lowercase-then-uppercase transition IS the signal
);
// Same split-string-concatenation fix as CONCAT_KEY_VALUE_RE, for the
// camelCase name set.
const CONCAT_CAMEL_KEY_VALUE_RE = new RegExp(
  '(' + CAMEL_NAME_ALT + ')([\'"`]?\\s*[:=]\\s*)([\'"`][^\'"`]*[\'"`](?:\\s*\\+\\s*[\'"`][^\'"`]*[\'"`])+)',
  'g'
);

// `.env`/shell-export syntax: `KEY=value` with NO surrounding quotes at all
// — the shape secret-redaction.test.js already documented as evading
// KEY_VALUE_RE above (that test's own comment: "Standard .env syntax...
// evades the... catch-all, which requires a quoted value"). Anchored to
// the start of a line (optional leading whitespace/`export `) rather than
// matched anywhere, specifically so an ordinary code expression like
// `if (password == expected)` or `token = someFn()` embedded mid-statement
// is never a candidate — only a line whose FIRST token is the secret name
// itself, exactly the shape a real `.env` file or shell script uses. `(?!=)`
// after the operator blocks `==`/`===` from being read as `=` plus a
// leftover comparison; a bare `!=`/`<=`/`>=` already can't match because the
// operator class only accepts a literal `=`, not the character before it.
// The optional third group is a non-greedy compound-identifier prefix
// (`AWS_SECRET_` before `ACCESS_KEY`, `STRIPE_` before `API_KEY`) — the SAME
// compound-name problem NAME_BOUNDARY solves for a single leading segment,
// generalized to arbitrarily many, since real .env names commonly stack a
// vendor/namespace prefix ahead of the sensitive word.
const ENV_STYLE_RE = new RegExp(
  '^([ \\t]*(?:export\\s+)?)([A-Za-z0-9_-]*?[_-])?(' + KEY_NAME_ALT + ')(\\s*=(?!=)\\s*)([^\\r\\n]+)$',
  'gim'
);

// YAML `key: value` (adversarial-review fix, 2026-09): the SAME unquoted
// shape as .env, but YAML's operator is `:`, which ENV_STYLE_RE never
// accepted. Deliberately NOT just added to ENV_STYLE_RE's operator class —
// `:` collides with two extremely common non-secret shapes this codebase
// already has a pinned regression test for: a TypeScript type annotation
// (`password: string;`) and a JS object-literal key
// (`{ password: getSecret() }`). Neither of those is YAML, so this pattern
// is applied ONLY when the file extension says so (see redactSecrets'
// `filePath` option below) rather than unconditionally — the risk of the
// blanket approach is a regression in exactly the case this module's own
// header calls out ("redact too aggressively and the validator loses the
// context it needs").
const YAML_STYLE_RE = new RegExp(
  '^([ \\t]*(?:- )?)([A-Za-z0-9_-]*?[_-])?(' + KEY_NAME_ALT + ')(\\s*:\\s*)([^\\r\\n]+)$',
  'gim'
);
const YAML_EXT_RE = /\.ya?ml$/i;

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
export function redactSecrets(text, { filePath } = {}) {
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

  // 3.5. Split-string-concatenation values — MUST run before pass 4:
  // KEY_VALUE_RE matches the first quoted segment of a concatenation too
  // (it's a valid, if incomplete, match on its own), so if pass 4 ran first
  // it would already have consumed and "fixed" the first segment, leaving
  // this pass nothing to find and the second segment still exposed.
  out = out.replace(CONCAT_KEY_VALUE_RE, (_m, keyName, opWs) => {
    redactions++;
    return `${keyName}${opWs}"${REDACTED_PLACEHOLDER}"`;
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

  // 3.6. Split-string-concatenation, camelCase name set — same ordering
  // requirement as 3.5 (must run before 4a).
  out = out.replace(CONCAT_CAMEL_KEY_VALUE_RE, (_m, keyName, opWs) => {
    redactions++;
    return `${keyName}${opWs}"${REDACTED_PLACEHOLDER}"`;
  });

  // 4a. camelCase compound identifiers (`authToken = "..."`, `apiSecret: "..."`)
  // — a case-SENSITIVE pass, separate from pass 4's case-insensitive one for
  // exactly the reason CAMEL_KEY_VALUE_RE's own comment explains.
  out = out.replace(CAMEL_KEY_VALUE_RE, (_m, keyName, opWs, quote, value) => {
    redactions++;
    const bearer = /^(Bearer\s+)(.+)$/i.exec(value);
    if (bearer) return `${keyName}${opWs}${quote}${bearer[1]}${REDACTED_PLACEHOLDER}${quote}`;
    return `${keyName}${opWs}${quote}${REDACTED_PLACEHOLDER}${quote}`;
  });

  // 4.5. `.env`/shell-export syntax: `KEY=value`, no quotes at all. Must run
  // AFTER pass 4 (KEY_VALUE_RE): pass 4 already consumed every quoted
  // occurrence, so anything ENV_STYLE_RE still finds on a candidate line is,
  // by construction, unquoted — there is no double-redaction risk between
  // the two passes even though their key-name sets are identical.
  out = out.replace(ENV_STYLE_RE, (_m, lead, prefix, keyName, opWs, value) => {
    redactions++;
    const bearer = /^(Bearer\s+)(.+)$/i.exec(value);
    if (bearer) return `${lead}${prefix || ''}${keyName}${opWs}${bearer[1]}${REDACTED_PLACEHOLDER}`;
    return `${lead}${prefix || ''}${keyName}${opWs}${REDACTED_PLACEHOLDER}`;
  });

  // 4.6. YAML `key: value` — ONLY for a file the caller identifies as YAML
  // (see YAML_STYLE_RE's own comment for why this isn't unconditional).
  if (typeof filePath === 'string' && YAML_EXT_RE.test(filePath)) {
    out = out.replace(YAML_STYLE_RE, (_m, lead, prefix, keyName, opWs, value) => {
      redactions++;
      const bearer = /^(Bearer\s+)(.+)$/i.exec(value);
      if (bearer) return `${lead}${prefix || ''}${keyName}${opWs}${bearer[1]}${REDACTED_PLACEHOLDER}`;
      return `${lead}${prefix || ''}${keyName}${opWs}${REDACTED_PLACEHOLDER}`;
    });
  }

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
