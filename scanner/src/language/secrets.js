// Secrets parity for Haskell and Nix syntax (X-001).
//
// What the generic secret scanners already do for these files (known provider tokens, entropy next to a
// credential word) is kept as is. This module adds what is language-specific and was missing:
//
//   * comment/string-aware lexing: Haskell nested `{- {- -} -}` and `--` (an operator run such as `-->` is not a
//     comment), quasi-quotes, Nix `#`, `/* */`, `"..."` and indented `''...''` strings with their escapes. A
//     lexer, not a regex, decides what is a comment, so a nested comment cannot swallow or expose live code.
//   * split secrets: `"AKIA" ++ "..."` and `"ghp_" <> "..."` (Haskell), `"a" + "b"` (Nix)
//   * dependency-URL credentials in Cabal/Stack manifests, flake.lock and Nix `url`/`fetch*` attributes
//   * the provider and rotation guidance a response needs, derived from the secret's SHAPE only
//
// Nothing here verifies a credential, contacts a provider, or revokes anything: rotation guidance is text.
// Every finding carries a masked value only, never the secret.

const SECRET_PREFIX = /(?:sk_|sk-|AKIA|ASIA|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[abprs]-|AIza|ya29\.|eyJ[A-Za-z0-9_-]{8,}|-----BEGIN|glpat-|shpat_|shpss_|npm_|dop_v1_|SG\.[A-Za-z0-9_-]{10,})/;
const SECRET_NAME = /(?:api[_-]?key|secret|token|passwd|password|pwd|credential|private[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|psk)/i;
const PLACEHOLDER = /(?:placeholder|example|xxx+|your[_-]|changeme|<[A-Za-z_ -]+>|^MY_|INSERT_|REPLACE_|TODO|test_key|fake_|sample_|dummy_)/i;

// ── lexers ───────────────────────────────────────────────────────────────────
const HS_SYMBOL = /[!#$%&*+./<=>?@\\^|~:-]/;

/**
 * Replace comment characters with spaces, keeping every newline and every other offset. Strings and
 * quasi-quotes are skipped, never blanked.
 */
export function blankHaskell(src) {
  const n = src.length; const out = src.split('');
  const blank = (a, b) => { for (let i = a; i < b; i++) if (out[i] !== '\n' && out[i] !== '\r') out[i] = ' '; };
  let i = 0;
  while (i < n) {
    const c = src[i]; const d = src[i + 1];
    if (c === '{' && d === '-') {                     // nested block comment (also {-# pragmas #-})
      let depth = 1; let j = i + 2;
      while (j < n && depth > 0) { if (src[j] === '{' && src[j + 1] === '-') { depth++; j += 2; } else if (src[j] === '-' && src[j + 1] === '}') { depth--; j += 2; } else j++; }
      blank(i, j); i = j; continue;
    }
    if (c === '-' && d === '-') {                     // a run of >=2 dashes not part of a longer operator
      let j = i; while (src[j] === '-') j++;
      const prev = src[i - 1];
      if (!(prev && HS_SYMBOL.test(prev)) && !(src[j] && HS_SYMBOL.test(src[j]))) { let e = src.indexOf('\n', j); if (e < 0) e = n; blank(i, e); i = e; continue; }
      i = j; continue;
    }
    if (c === '"') { let j = i + 1; while (j < n) { if (src[j] === '\\') { j += 2; continue; } if (src[j] === '"' || src[j] === '\n') break; j++; } i = Math.min(j + 1, n); continue; }
    if (c === "'") {                                  // a char literal, never a prime after an identifier character
      const prev = src[i - 1];
      if (prev && /[A-Za-z0-9_']/.test(prev)) { i++; continue; }
      const m = /^'(?:[^'\\\n]|\\[^\n]{1,8}?)'/.exec(src.slice(i, i + 12));
      if (m) { i += m[0].length; continue; }
      i++; continue;
    }
    if (c === '[' && /[A-Za-z_][\w']*\|/.test(src.slice(i + 1, i + 40)) && /^\[[A-Za-z_][\w'.]*\|/.test(src.slice(i, i + 40))) {   // [quote| ... |]
      const e = src.indexOf('|]', i + 2); i = e < 0 ? n : e + 2; continue;
    }
    i++;
  }
  return out.join('');
}

export function blankNix(src) {
  const n = src.length; const out = src.split('');
  const blank = (a, b) => { for (let i = a; i < b; i++) if (out[i] !== '\n' && out[i] !== '\r') out[i] = ' '; };
  // The string states nest through ${ ... }, so scan with an explicit stack.
  const stack = []; // 'q' (double-quoted), 'i' (indented), '{' (interpolation / attrset brace)
  let i = 0;
  while (i < n) {
    const top = stack[stack.length - 1];
    const c = src[i]; const d = src[i + 1];
    if (top === 'q') {
      if (c === '\\') { i += 2; continue; }
      if (c === '"') { stack.pop(); i++; continue; }
      if (c === '$' && d === '{') { stack.push('{'); i += 2; continue; }
      i++; continue;
    }
    if (top === 'i') {
      if (c === "'" && d === "'") { if (src[i + 2] === "'" || src[i + 2] === '$' || src[i + 2] === '\\') { i += src[i + 2] === '\\' ? 4 : 3; continue; } stack.pop(); i += 2; continue; }
      if (c === '$' && d === '{') { stack.push('{'); i += 2; continue; }
      i++; continue;
    }
    // code context (top level or inside an interpolation)
    if (c === '#') { let e = src.indexOf('\n', i); if (e < 0) e = n; blank(i, e); i = e; continue; }
    if (c === '/' && d === '*') { let e = src.indexOf('*/', i + 2); e = e < 0 ? n : e + 2; blank(i, e); i = e; continue; }
    if (c === '"') { stack.push('q'); i++; continue; }
    if (c === "'" && d === "'") { stack.push('i'); i += 2; continue; }
    if (c === '{') { stack.push('{'); i++; continue; }
    if (c === '}') { if (stack.length) stack.pop(); i++; continue; }
    i++;
  }
  return out.join('');
}

export const blankFor = (fp) => (/\.l?hs(?:c|ig)?$|\.hs-boot$/i.test(fp) ? blankHaskell : /\.nix$/i.test(fp) ? blankNix : null);

// ── tokenizers (comments skipped, strings kept whole) ───────────────────────
/**
 * Ordered tokens {k:'s'|'i'|'o'|'x', v, start, end, interp?}. `s` is a string literal (its raw body in `v`),
 * `i` an identifier, `o` a run of operator characters, `x` anything else. Comments never become tokens.
 */
export function tokenizeHaskell(src) {
  const n = src.length; const toks = []; let i = 0;
  while (i < n) {
    const c = src[i]; const d = src[i + 1];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '{' && d === '-') { let depth = 1; let j = i + 2; while (j < n && depth > 0) { if (src[j] === '{' && src[j + 1] === '-') { depth++; j += 2; } else if (src[j] === '-' && src[j + 1] === '}') { depth--; j += 2; } else j++; } i = j; continue; }
    if (c === '-' && d === '-') { let j = i; while (src[j] === '-') j++; const prev = src[i - 1]; if (!(prev && HS_SYMBOL.test(prev)) && !(src[j] && HS_SYMBOL.test(src[j]))) { const e = src.indexOf('\n', j); i = e < 0 ? n : e; continue; } }
    if (c === '"') { let j = i + 1; while (j < n && src[j] !== '"' && src[j] !== '\n') { if (src[j] === '\\') j++; j++; } toks.push({ k: 's', v: src.slice(i + 1, j), start: i, end: j + 1 }); i = j + 1; continue; }
    if (/[A-Za-z_]/.test(c)) { let j = i + 1; while (j < n && /[\w']/.test(src[j])) j++; toks.push({ k: 'i', v: src.slice(i, j), start: i, end: j }); i = j; continue; }
    if (c === "'") { const m = /^'(?:[^'\\\n]|\\[^\n]{1,8}?)'/.exec(src.slice(i, i + 12)); if (m) { toks.push({ k: 'x', v: m[0], start: i, end: i + m[0].length }); i += m[0].length; continue; } }
    if (HS_SYMBOL.test(c)) { let j = i + 1; while (j < n && HS_SYMBOL.test(src[j])) j++; toks.push({ k: 'o', v: src.slice(i, j), start: i, end: j }); i = j; continue; }
    toks.push({ k: 'x', v: c, start: i, end: i + 1 }); i++;
  }
  return toks;
}

export function tokenizeNix(src) {
  const n = src.length; const toks = []; let i = 0;
  // read one string starting at i (either " or ''), returning {end, v, interp}
  const readString = (start) => {
    const indented = src[start] === "'";
    let j = start + (indented ? 2 : 1); let interp = false; const stack = [];
    for (; j < n; j++) {
      const c = src[j]; const d = src[j + 1];
      if (stack.length) { if (c === '{') stack.push('{'); else if (c === '}') stack.pop(); else if (c === '"') { j = readString(j).end - 1; } continue; }
      if (indented) {
        if (c === "'" && d === "'") { const e = src[j + 2]; if (e === "'" || e === '$') { j += 2; continue; } if (e === '\\') { j += 3; continue; } return { end: j + 2, v: src.slice(start + 2, j), interp }; }
      } else {
        if (c === '\\') { j++; continue; }
        if (c === '"') return { end: j + 1, v: src.slice(start + 1, j), interp };
      }
      if (c === '$' && d === '{') { interp = true; stack.push('{'); j++; }
    }
    return { end: n, v: src.slice(start + (indented ? 2 : 1)), interp };
  };
  while (i < n) {
    const c = src[i]; const d = src[i + 1];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '#') { const e = src.indexOf('\n', i); i = e < 0 ? n : e; continue; }
    if (c === '/' && d === '*') { const e = src.indexOf('*/', i + 2); i = e < 0 ? n : e + 2; continue; }
    if (c === '"' || (c === "'" && d === "'")) { const r = readString(i); toks.push({ k: 's', v: r.v, start: i, end: r.end, interp: r.interp }); i = r.end; continue; }
    if (/[A-Za-z_]/.test(c)) { let j = i + 1; while (j < n && /[\w'-]/.test(src[j])) j++; toks.push({ k: 'i', v: src.slice(i, j), start: i, end: j }); i = j; continue; }
    if (/[+=<>!&|-]/.test(c)) { let j = i + 1; while (j < n && /[+=<>!&|-]/.test(src[j])) j++; toks.push({ k: 'o', v: src.slice(i, j), start: i, end: j }); i = j; continue; }
    toks.push({ k: 'x', v: c, start: i, end: i + 1 }); i++;
  }
  return toks;
}

// ── split secrets ────────────────────────────────────────────────────────────
const HS_CONCAT_OPS = new Set(['++', '<>']);
const NIX_CONCAT_OPS = new Set(['+']);
const lineOf = (text, idx) => { let l = 1; for (let i = 0; i < idx; i++) if (text.charCodeAt(i) === 10) l++; return l; };
const mask = (v) => (v.length > 8 ? `${v.slice(0, 4)}…${v.slice(-4)}` : '••••');

export function scanLanguageSecretConcat(fp, raw) {
  const isNix = /\.nix$/i.test(fp); const isHs = /\.l?hs(?:c|ig)?$|\.hs-boot$/i.test(fp);
  if (!(isNix || isHs) || !raw || raw.length > 500_000) return [];
  const toks = isNix ? tokenizeNix(raw) : tokenizeHaskell(raw);
  const ops = isNix ? NIX_CONCAT_OPS : HS_CONCAT_OPS;
  const lines = raw.split('\n');
  const out = []; const seen = new Set();
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.k !== 's' || t.interp || !(toks[i + 1] && toks[i + 1].k === 'o' && ops.has(toks[i + 1].v) && toks[i + 2] && toks[i + 2].k === 's')) continue;
    if (i > 0 && toks[i - 1].k === 'o' && ops.has(toks[i - 1].v)) continue;                    // not the start of the chain
    const parts = [t]; let j = i;
    while (toks[j + 1] && toks[j + 1].k === 'o' && ops.has(toks[j + 1].v) && toks[j + 2] && toks[j + 2].k === 's' && !toks[j + 2].interp) { parts.push(toks[j + 2]); j += 2; }
    if (parts.length < 2) { i = j; continue; }
    const ident = toks[i - 1] && toks[i - 1].k === 'o' && /^(?:=|<-|:=)$/.test(toks[i - 1].v) && toks[i - 2] && toks[i - 2].k === 'i' ? toks[i - 2].v : '';
    const value = parts.map((p) => p.v).join('');
    i = j;
    if (PLACEHOLDER.test(value)) continue;
    const byPrefix = SECRET_PREFIX.test(value);
    const byName = SECRET_NAME.test(ident) && value.length >= 24 && /[A-Za-z]/.test(value) && /\d/.test(value);
    if (!byPrefix && !byName) continue;
    const line = lineOf(raw, parts[0].start);
    const id = `secret-concat:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const m8 = mask(value);
    let snippet = (lines[line - 1] || '').trim().slice(0, 200);
    for (const p of parts) if (p.v) snippet = snippet.split(p.v).join(m8);
    out.push({
      id, file: fp, line, language: isNix ? 'nix' : 'haskell',
      vuln: 'Hardcoded credential — secret split across concatenated literals to evade detection',
      severity: 'high', cwe: 'CWE-798', family: 'hardcoded-secret', parser: 'SECRET-CONCAT', confidence: 0.78,
      snippet, masked: m8, ...providerInfo(value),
      remediation: 'Load the secret from a runtime file or a secrets manager. Splitting the literal across a concatenation does not protect it: rotate the exposed credential.',
    });
  }
  return out;
}

// ── dependency-URL credentials ───────────────────────────────────────────────
const URL_CRED = /\b((?:https?|git\+https?|git|ssh|ftp|svn\+https?|hg\+https?):\/\/)([^\s/@:"']{1,100})(?::([^\s/@"']{1,200}))?@([A-Za-z0-9.-]+(?::\d+)?[^\s"']*)/g;
const BENIGN_USER = /^(?:git|hg|svn|anonymous|ftp|guest)$/i;
const BENIGN_HOST = /(?:^|\.)(?:localhost|example\.(?:com|org|net))(?::|$|\/)|^127\.|^0\.0\.0\.0|^::1/i;

const MANIFEST_RE = /(?:^|\/)(?:[^/]+\.cabal|cabal\.project(?:\.[a-z]+)?|stack\.yaml(?:\.lock)?|package\.yaml|flake\.(?:nix|lock)|[^/]+\.nix)$/i;
export const isSecretManifest = (p) => MANIFEST_RE.test(p);

/** Credentials embedded in a dependency or source URL. The value is never kept, only its mask. */
export function scanDependencyUrlCredentials(fp, raw) {
  if (!isSecretManifest(fp) || !raw || raw.length > 2_000_000) return [];
  const code = raw;   // a credential in a comment is still in the repository: comments are NOT blanked here
  const out = []; const seen = new Set(); const lines = raw.split('\n');
  const re = new RegExp(URL_CRED.source, 'g'); let m;
  while ((m = re.exec(code))) {
    const user = m[2]; const pass = m[3]; const host = m[4];
    const secretish = pass !== undefined ? pass : user;
    if (BENIGN_HOST.test(host) || (pass === undefined && BENIGN_USER.test(user)) || PLACEHOLDER.test(secretish) || /^\$\{|^%\w+%$|^\$\w+$/.test(secretish)) continue;
    if (pass === undefined && !(/^[A-Za-z0-9_-]{20,}$/.test(user) || SECRET_PREFIX.test(user))) continue;   // a bare user name is not a secret
    const line = lineOf(code, m.index);
    const id = `dep-url-credential:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const m8 = mask(secretish);
    const snippet = (lines[line - 1] || '').trim().slice(0, 200).split(secretish).join(m8);
    const hostOnly = host.replace(/[/?#].*$/, '');
    out.push({
      id, file: fp, line, language: /\.nix$|flake\./i.test(fp) ? 'nix' : 'haskell',
      vuln: 'Credential embedded in a dependency or source URL', severity: 'high', cwe: 'CWE-798', family: 'dependency-url-credential', parser: 'SECRET-DEPURL', confidence: 0.85,
      snippet, masked: m8, host: hostOnly, scheme: m[1].replace('://', ''),
      ...providerInfo(secretish, hostOnly),
      remediation: 'Remove the credential from the URL. Use a credential helper, netrc/ssh-agent or a CI secret that is not written into a manifest, then rotate the exposed token: it is in every clone and every lock.',
    });
  }
  return out;
}

// ── provider and rotation guidance (shape only; nothing is verified or called) ──
const PROVIDERS = [
  [/^AKIA[0-9A-Z]{16}$|^ASIA[0-9A-Z]{16}$/, 'AWS', 'https://console.aws.amazon.com/iam/home#/security_credentials', ['Deactivate the access key in IAM, then delete it.', 'Check CloudTrail for use of the key between its exposure and now.', 'Issue a replacement and update the consumers.']],
  [/^(?:ghp|gho|ghu|ghs|ghr)_|^github_pat_/, 'GitHub', 'https://github.com/settings/tokens', ['Revoke the token under Settings > Developer settings.', 'Review the audit log for use of the token.', 'Create a fine-scoped replacement.']],
  [/^glpat-/, 'GitLab', 'https://gitlab.com/-/user_settings/personal_access_tokens', ['Revoke the personal access token.', 'Review the audit events.']],
  [/^xox[abprs]-/, 'Slack', 'https://api.slack.com/apps', ['Revoke or rotate the token in the Slack app settings.']],
  [/^sk-ant-/, 'Anthropic', 'https://console.anthropic.com/settings/keys', ['Delete the API key in the console and create a new one.', 'Review usage for the exposure window.']],
  [/^sk-(?:proj-|live-)?[A-Za-z0-9_-]{16,}/, 'OpenAI', 'https://platform.openai.com/api-keys', ['Revoke the key and create a new one.', 'Check usage for the exposure window.']],
  [/^sk_live_|^rk_live_|^sk_test_/, 'Stripe', 'https://dashboard.stripe.com/apikeys', ['Roll the key in the Stripe dashboard.']],
  [/^AIza[0-9A-Za-z_-]{35}$/, 'Google', 'https://console.cloud.google.com/apis/credentials', ['Delete or regenerate the API key and restrict it.']],
  [/^SG\./, 'SendGrid', 'https://app.sendgrid.com/settings/api_keys', ['Delete the API key and create a new one.']],
  [/^npm_/, 'npm', 'https://www.npmjs.com/settings/~/tokens', ['Revoke the token.']],
  [/^dop_v1_/, 'DigitalOcean', 'https://cloud.digitalocean.com/account/api/tokens', ['Revoke the token.']],
  [/^-----BEGIN/, 'private-key', null, ['Treat the key as compromised: generate a new key pair, replace the public key everywhere it is trusted, and revoke the old one.']],
];
const HOST_PROVIDERS = [[/(^|\.)github\.com$/i, 'GitHub'], [/(^|\.)gitlab\.com$/i, 'GitLab'], [/(^|\.)bitbucket\.org$/i, 'Bitbucket'], [/(^|\.)hackage\.haskell\.org$/i, 'Hackage'], [/(^|\.)cachix\.org$/i, 'Cachix']];

/** Provider by SHAPE, plus rotation text. `host` names the provider only when the value's shape does not. */
export function providerInfo(value, host = null) {
  const v = String(value || '');
  for (const [re, provider, url, steps] of PROVIDERS) if (re.test(v)) return { provider, rotation: { provider, revokeUrl: url, steps, automatic: false, liveCheck: 'not performed' } };
  if (host) for (const [re, provider] of HOST_PROVIDERS) if (re.test(host)) return { provider, rotation: { provider, revokeUrl: null, steps: ['Revoke the token or password for this account at the provider, then update the consumers.'], automatic: false, liveCheck: 'not performed' } };
  return {};
}

/** Value-free description of where a secret is, for responders. */
export function redactSecret(v) { return mask(String(v || '')); }

export const SECRETS_LANGUAGE_VERSION = 'language-secrets/1';

// ── URL credential redaction for inventories and findings ────────────────────
const URL_USERINFO = /((?:https?|git\+https?|git|ssh|ftp|svn\+https?|hg\+https?):\/\/)[^\s/@"'`]*:[^\s/@"'`]+@/gi;
const URL_TOKEN_USER = /((?:https?|git\+https?):\/\/)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}@/gi;
/** `scheme://user:password@host` -> `scheme://***@host`; any string, never throws. */
export function stripUrlCredentials(str) {
  if (typeof str !== 'string' || str.indexOf('@') < 0) return str;
  return str.replace(URL_USERINFO, '$1***@').replace(URL_TOKEN_USER, '$1***@');
}
/** In-place deep redaction of URL credentials in every string of a plain object graph (cycle safe). */
export function redactUrlsDeep(value, seen = new WeakSet()) {
  if (typeof value === 'string') return stripUrlCredentials(value);
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  // Only a CHANGED string is written back, and a frozen container is never assigned to: shared constants (rule tables)
  // are frozen and contain no credential, so they are left exactly as they are.
  const frozen = Object.isFrozen(value);
  if (Array.isArray(value)) { for (let i = 0; i < value.length; i++) { const r = redactUrlsDeep(value[i], seen); if (r !== value[i] && !frozen) value[i] = r; } return value; }
  for (const k of Object.keys(value)) { const r = redactUrlsDeep(value[k], seen); if (r !== value[k] && !frozen) value[k] = r; }
  return value;
}

// ── redaction for text that leaves the machine (model prompts, exports) ─────────
const SECRET_BINDING = /^(?:[A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api_?key|apikey|auth|credential|private_?key|passphrase|signing_?key)[A-Za-z0-9_]*)$/i;
// camelCase and snake_case spellings of a key: stripeKey, signing_key, apiKey; `monkey` and `keyboard` are not
const isSecretBindingName = (n) => SECRET_BINDING.test(n) || /[a-z0-9]Key$|_key$|^key$|^[A-Z0-9_]*_KEY$/.test(n);
const CONCAT_OPS_HS = new Set(['++', '<>']);
const CONCAT_OPS_NIX = new Set(['+']);
const PLACEHOLDER_TEXT = '[REDACTED-SECRET]';

/**
 * Replaces the VALUE of a credential-named Haskell/Nix binding with a placeholder, including a value split across
 * several string literals joined by `++`, `<>` (Haskell) or `+` (Nix), which a single-literal pattern cannot see.
 * Token based: comments and the text of other strings are never touched. Returns {text, redactions}.
 */
export function redactLanguageSecrets(filePath, text) {
  if (typeof text !== 'string' || !text) return { text: typeof text === 'string' ? text : '', redactions: 0 };
  const isHs = /\.l?hs$|\.hs-boot$|\.hsc$/i.test(filePath || '');
  const isNix = /\.nix$/i.test(filePath || '');
  if (!isHs && !isNix) return { text, redactions: 0 };
  let toks;
  try { toks = isHs ? tokenizeHaskell(text) : tokenizeNix(text); } catch { return { text, redactions: 0 }; }
  const ops = isHs ? CONCAT_OPS_HS : CONCAT_OPS_NIX;
  const edits = [];
  for (let i = 0; i < toks.length - 2; i++) {
    const t = toks[i];
    if (t.k !== 'i' || !isSecretBindingName(t.v.replace(/^.*\./, ''))) continue;
    const eq = toks[i + 1];
    if (!(eq.k === 'o' && eq.v === '=')) continue;
    let j = i + 2; let total = 0; const pieces = [];
    while (j < toks.length && toks[j].k === 's') {
      pieces.push(toks[j]); total += toks[j].v.length;
      const next = toks[j + 1];
      if (next && next.k === 'o' && ops.has(next.v) && toks[j + 2] && toks[j + 2].k === 's') j += 2; else { j += 1; break; }
    }
    if (!pieces.length || total < 6) continue;
    for (const p of pieces) if (p.v !== PLACEHOLDER_TEXT && !p.interp) edits.push(p);
  }
  if (!edits.length) return { text, redactions: 0 };
  let out = text; let n = 0;
  for (const p of edits.sort((a, b) => b.start - a.start)) {
    const q = out[p.start] === "'" ? "''" : '"';
    out = out.slice(0, p.start) + q + PLACEHOLDER_TEXT + q + out.slice(p.end); n++;
  }
  return { text: out, redactions: n };
}
