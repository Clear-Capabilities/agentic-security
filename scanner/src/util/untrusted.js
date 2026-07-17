// Untrusted-content hardening primitives (addition #4: meta-security —
// self-hardening the agent surface).
//
// Attacker-authored code and finding text reach several LLM prompts, several
// rendered outputs (issue / PR / ticket bodies), and audit writers. This module
// is the single, tested place that neutralizes that content before it crosses a
// trust boundary. See docs/AGENT_THREAT_MODEL.md for the path→CWE map.
//
// Design notes:
//   - Pure + dependency-light (node:crypto, node:fs only). No network, no state.
//   - Fail-closed: unknown/adversarial input degrades to the safe value ('' or
//     `false`), never throws.
//   - Deterministic: fenceUntrusted derives its nonce from the content hash so
//     the wrapping is reproducible and testable (no Date.now / random source).
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

// ─── escapeMarkdown ──────────────────────────────────────────────────────────
// Neutralize markdown/HTML control characters so attacker-controlled finding
// text cannot inject markup, links, or code spans when interpolated into an
// issue / PR / ticket body. HTML-dangerous chars (& < >) are entity-encoded so
// no raw tag can render in any markdown flavour; markdown-structural chars
// (backtick [ ] ! and backslash) are backslash-escaped.
//
// Non-strings collapse to '' (fail-closed — a null vuln never becomes "null").
//
// Order is load-bearing: escape `&` before we emit `&amp;`/`&lt;`/`&gt;`, and
// escape literal `\` before we introduce our own backslashes, so nothing is
// double-consumed.
export function escapeMarkdown(s) {
  if (typeof s !== 'string') return '';
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]')
    .replace(/!/g, '\\!');
}

// ─── fenceUntrusted ──────────────────────────────────────────────────────────
// Wrap untrusted text in a clearly-delimited block whose delimiter carries a
// per-call nonce, so an injected close-delimiter inside the text cannot
// terminate the fence early (the classic prompt-injection "break out of the
// data block" move). Intended for the LLM-prompt paths (triage / dedup / fix)
// where the model must treat the wrapped span as inert data.
//
// The nonce is derived deterministically from a sha256 of the content (first 8
// hex). That makes it (a) reproducible/testable and (b) unguessable by the
// author of the content — an attacker cannot pre-compute the resulting nonce to
// forge a matching close-delimiter, because the nonce depends on the very bytes
// they would have to write.
//
// Returns { text, nonce }.
export function fenceUntrusted(s, label = 'untrusted') {
  const content = typeof s === 'string' ? s : '';
  const lbl = String(label || 'untrusted').replace(/[^A-Za-z0-9_-]/g, '');
  const nonce = createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 8);
  const open = `<<BEGIN ${lbl} ${nonce}>>`;
  const close = `<<END ${lbl} ${nonce}>>`;
  return { text: `${open}\n${content}\n${close}`, nonce };
}

// ─── isAllowedFetchHost ──────────────────────────────────────────────────────
// Guard for any outbound fetch whose URL can be influenced by untrusted finding
// data (e.g. a metadata/advisory URL lifted from a dependency manifest). Blocks
// SSRF against link-local / loopback / RFC1918 targets AND enforces an explicit
// allowlist — a host must be BOTH non-internal AND on the allowlist. Empty
// allowlist ⇒ nothing passes (fail-closed). Malformed URL ⇒ false.
export function isAllowedFetchHost(url, allowlist = []) {
  let host;
  try {
    host = new URL(String(url)).hostname.toLowerCase();
  } catch {
    return false;
  }
  if (!host) return false;
  // Strip IPv6 brackets: "[::1]" → "::1".
  const h = host.replace(/^\[/, '').replace(/\]$/, '');

  // Block internal / link-local / loopback destinations up front — these must
  // never be reachable even if an operator mistakenly allowlists one.
  if (h === 'localhost' || h.endsWith('.localhost')) return false;
  if (h === '::1' || h === '0.0.0.0') return false;
  if (h === '169.254.169.254' || h.startsWith('169.254.')) return false; // link-local + cloud metadata
  if (h.startsWith('127.')) return false;                                 // loopback /8
  if (h.startsWith('10.')) return false;                                  // RFC1918 /8
  if (h.startsWith('192.168.')) return false;                            // RFC1918 /16
  const m172 = h.match(/^172\.(\d{1,3})\./);                              // RFC1918 172.16-31/12
  if (m172) {
    const oct = Number(m172[1]);
    if (oct >= 16 && oct <= 31) return false;
  }

  const allow = Array.isArray(allowlist)
    ? allowlist.map((a) => String(a).toLowerCase())
    : [];
  if (allow.length === 0) return false; // fail-closed: no allowlist ⇒ deny all
  return allow.includes(h);
}

// ─── redactSecrets ───────────────────────────────────────────────────────────
// Mask token-shaped substrings before finding-adjacent text is written to an
// audit log or handed to an LLM. The provider/scheme prefix is preserved so a
// human triager can still tell WHAT kind of credential leaked without seeing
// its value. Non-strings collapse to ''.
const _REDACTED = '***REDACTED***';
export function redactSecrets(s) {
  if (typeof s !== 'string') return '';
  return s
    // URL basic-auth: scheme://user:password@ → keep user, mask password.
    .replace(/(\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)[^\s@/]+@/gi, `$1${_REDACTED}@`)
    // Authorization: Bearer <token>
    .replace(/\b(Authorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, `$1${_REDACTED}`)
    // ?access_token= / &token= / ?token= / &access_token=
    .replace(/([?&](?:access_token|token)=)[^&\s#]+/gi, `$1${_REDACTED}`)
    // Raw provider token prefixes (GitHub PATs, Anthropic keys). Keep prefix.
    .replace(/\b(ghp_|gho_|ghu_|ghs_|github_pat_|sk-ant-)[A-Za-z0-9_-]+/g, `$1${_REDACTED}`);
}

// ─── secure filesystem writes ────────────────────────────────────────────────
// Audit logs, scan state, and any file that may carry finding text or secrets
// must be owner-only. openSync's mode argument is still masked by the process
// umask, so writeSecure ALSO chmods explicitly — the file is 0600 regardless of
// the ambient umask. secureDirMode is the matching 0700 for any parent dir we
// have to create.
export const secureFileMode = 0o600;
export const secureDirMode = 0o700;

export function writeSecure(filePath, data) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: secureDirMode });
    try { fs.chmodSync(dir, secureDirMode); } catch { /* best-effort */ }
  }
  const fd = fs.openSync(filePath, 'w', secureFileMode);
  try {
    fs.writeSync(fd, typeof data === 'string' ? data : String(data ?? ''));
  } finally {
    fs.closeSync(fd);
  }
  // Force the mode down even if umask loosened it at creation time.
  fs.chmodSync(filePath, secureFileMode);
  return filePath;
}
