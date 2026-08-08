// R16 — specialist audit classes.
//
// Narrow, high-credibility crypto-hygiene checks that a general injection
// detector will never find, because nothing about the code is "tainted": every
// value here is already trusted, and the defect is in HOW it is handled.
//
// Two classes, chosen because each has an unambiguous correct form to point at,
// which is what keeps a specialist rule credible:
//
//   1. TIMING-UNSAFE COMPARISON (CWE-208). Comparing a secret with `===`,
//      `.equals()` or `memcmp` short-circuits on the first differing byte, so
//      the time taken leaks how many leading bytes were right. Repeated across
//      requests that recovers the secret a byte at a time. Every language here
//      ships a constant-time comparison; the fix is to call it.
//
//   2. NON-ZEROIZABLE SECRET MATERIAL (CWE-316). A secret in immutable storage
//      cannot be erased after use, so it lingers in memory until GC and lands
//      in heap dumps, core files and swap. Java's `String` is the classic case
//      — the reason `char[]` exists in the JCA password APIs.
//
// PRECISION DISCIPLINE. Both rules key on the SECRET-NESS of the identifier,
// not on the comparison or the type alone: `if (a === b)` is not a finding, and
// neither is every `String`. That keeps the rules narrow enough to be worth
// believing. The correct constant-time form must never match — each detector
// checks for the safe API first and stays silent when it is present.

import { blankComments } from './_comment-strip.js';

// Identifiers that denote a secret worth constant-time treatment. Deliberately
// specific: "token"/"key" alone are too common in ordinary code (a map key, a
// pagination token), so they are only counted with a qualifying prefix.
const SECRET_IDENT = /\b(?:hmac|signature|sig|mac|digest|password|passwd|pwd|secret|api_?key|apikey|auth_?token|access_?token|session_?token|csrf_?token|otp|totp|nonce_?hash|password_?hash|expected_?hash|challenge_?response)\b/i;

// Constant-time comparison APIs, per ecosystem. Presence of any of these on a
// line means the author already did the right thing.
const CONSTANT_TIME = /\b(?:timingSafeEqual|compare_digest|ConstantTimeCompare|hash_equals|MessageDigest\.isEqual|CryptographicOperations\.FixedTimeEquals|secure_compare|sodium_memcmp|CRYPTO_memcmp|NSData.*isEqualToData|constantTimeAreEqual|slowEquals)\b/;

// An unsafe comparison of two expressions, where at least one names a secret.
const UNSAFE_COMPARE = [
  // JS/TS, Python, Go, PHP, Ruby: ==, ===, !=, !==
  { re: /([A-Za-z_$][\w$.\[\]'"]*)\s*(?:===|==|!==|!=)\s*([A-Za-z_$][\w$.\[\]'"()]*)/g, form: 'equality operator' },
  // Java/C#/Kotlin/Scala: a.equals(b)
  { re: /([A-Za-z_$][\w$.]*)\s*\.\s*equals\s*\(\s*([A-Za-z_$][\w$.()]*)\s*\)/g, form: '.equals()' },
  // C/C++: memcmp / strcmp / strncmp
  { re: /\b(?:mem|str|strn)cmp\s*\(\s*([A-Za-z_][\w.\->\[\]]*)\s*,\s*([A-Za-z_][\w.\->\[\]]*)/g, form: 'memcmp/strcmp' },
];

const REMEDIATION = {
  js: 'Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) — it compares in constant time. Guard the length first, since it throws on a length mismatch.',
  py: 'Use hmac.compare_digest(a, b).',
  go: 'Use subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1.',
  java: 'Use MessageDigest.isEqual(a, b) on byte[].',
  cs: 'Use CryptographicOperations.FixedTimeEquals(a, b).',
  php: 'Use hash_equals($known, $user).',
  rb: 'Use ActiveSupport::SecurityUtils.secure_compare(a, b), or OpenSSL.secure_compare.',
  c: 'Use CRYPTO_memcmp (OpenSSL) or sodium_memcmp — never memcmp/strcmp on secrets.',
};

const EXT_LANG = {
  '.js': 'js', '.mjs': 'js', '.cjs': 'js', '.ts': 'js', '.tsx': 'js', '.jsx': 'js',
  '.py': 'py', '.go': 'go', '.java': 'java', '.kt': 'java', '.scala': 'java',
  '.cs': 'cs', '.php': 'php', '.rb': 'rb',
  '.c': 'c', '.h': 'c', '.cc': 'c', '.cpp': 'c', '.cxx': 'c', '.hpp': 'c',
};

function _lang(file) {
  const m = String(file).toLowerCase().match(/\.[a-z]+$/);
  return m ? EXT_LANG[m[0]] || null : null;
}

function _lineAt(text, index) {
  return text.slice(0, index).split('\n').length;
}

/**
 * CWE-208 — comparison of secret material in non-constant time.
 */
export function scanTimingUnsafeComparison(file, content) {
  const lang = _lang(file);
  if (!lang || typeof content !== 'string') return [];
  const body = blankComments(content, file);
  const out = [];
  const seen = new Set();

  for (const { re, form } of UNSAFE_COMPARE) {
    const rx = new RegExp(re.source, re.flags);
    let m;
    while ((m = rx.exec(body))) {
      const [whole, left, right] = m;
      if (!SECRET_IDENT.test(left || '') && !SECRET_IDENT.test(right || '')) continue;

      const line = _lineAt(body, m.index);
      const lineText = body.split('\n')[line - 1] || '';
      // Already constant-time on this line: the author did it right.
      if (CONSTANT_TIME.test(lineText)) continue;
      // A length check is not a secret comparison — `sig.length === 64` leaks
      // nothing an attacker cannot already measure.
      if (/\.(?:length|size|len)\b/i.test(whole) || /\blen\s*\(/i.test(whole)) continue;
      // Comparisons against a null/undefined/empty sentinel are presence
      // checks, not secret comparisons. Tested on the OPERANDS, not on the
      // whole match: the right-hand capture can swallow a trailing paren, and
      // an end-anchored test against the raw match then silently misses.
      const _sentinel = (x) => /^(?:null|nil|None|undefined|""|''|0|false|true)$/i
        .test(String(x || '').replace(/[)\s;,]+$/, '').trim());
      if (_sentinel(left) || _sentinel(right)) continue;

      const key = `${file}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);

      out.push({
        id: `timing-unsafe-compare-${file}-${line}`,
        severity: 'medium',
        file,
        line,
        vuln: 'Non-Constant-Time Comparison of Secret',
        cwe: 'CWE-208',
        family: 'timing-side-channel',
        parser: 'REGEX',
        description:
          `A secret is compared with ${form}, which returns as soon as two bytes differ. `
          + 'The time taken therefore depends on how many leading bytes matched, and an attacker '
          + 'who can measure it recovers the value one byte at a time.',
        remediation: REMEDIATION[lang],
      });
    }
  }
  return out;
}

// Java-family immutable secret storage. `String` cannot be overwritten, so a
// password held in one survives until GC and appears in heap dumps.
const JAVA_STRING_SECRET = /\bString\s+([A-Za-z_$][\w$]*)\s*(?:=|;)/g;

// C-family zeroization that the compiler is permitted to delete. A `memset`
// whose buffer is never read afterwards is a dead store, and optimisers remove
// it — the canonical reason `explicit_bzero`/`memset_s` exist.
const C_MEMSET_SECRET = /\bmemset\s*\(\s*([A-Za-z_][\w.\->\[\]]*)\s*,\s*0\s*,/g;
const C_SAFE_ZERO = /\b(?:explicit_bzero|memset_s|SecureZeroMemory|sodium_memzero|OPENSSL_cleanse)\b/;

/**
 * CWE-316 — secret material that cannot be erased after use.
 */
export function scanMissingZeroization(file, content) {
  const lang = _lang(file);
  if (!lang || typeof content !== 'string') return [];
  const body = blankComments(content, file);
  const out = [];

  if (lang === 'java') {
    let m;
    const rx = new RegExp(JAVA_STRING_SECRET.source, JAVA_STRING_SECRET.flags);
    while ((m = rx.exec(body))) {
      const name = m[1];
      if (!SECRET_IDENT.test(name)) continue;
      const line = _lineAt(body, m.index);
      out.push({
        id: `non-zeroizable-secret-${file}-${line}`,
        severity: 'low',
        file,
        line,
        vuln: 'Secret Held in Non-Zeroizable Storage',
        cwe: 'CWE-316',
        family: 'key-hygiene',
        parser: 'REGEX',
        description:
          `'${name}' holds secret material in a String. Strings are immutable, so the value cannot be `
          + 'overwritten after use: it stays readable in the heap until garbage collection and can '
          + 'surface in heap dumps, core files and swap. This is why the JCA password APIs take char[].',
        remediation: 'Hold the secret in a char[] or byte[] and overwrite it with java.util.Arrays.fill(buf, (char) 0) in a finally block once it is no longer needed.',
      });
    }
  }

  if (lang === 'c') {
    if (C_SAFE_ZERO.test(body)) return out; // the author already uses a guaranteed wipe
    let m;
    const rx = new RegExp(C_MEMSET_SECRET.source, C_MEMSET_SECRET.flags);
    while ((m = rx.exec(body))) {
      const name = m[1];
      if (!SECRET_IDENT.test(name)) continue;
      const line = _lineAt(body, m.index);
      out.push({
        id: `removable-zeroization-${file}-${line}`,
        severity: 'medium',
        file,
        line,
        vuln: 'Secret Wipe Removable by the Optimiser',
        cwe: 'CWE-316',
        family: 'key-hygiene',
        parser: 'REGEX',
        description:
          `'${name}' is zeroed with memset, but nothing reads the buffer afterwards. That makes the `
          + 'write a dead store, which an optimising compiler is entitled to delete outright — so the '
          + 'secret is left in memory in exactly the build where it matters most.',
        remediation: 'Use explicit_bzero (BSD/glibc), memset_s (C11 Annex K), SecureZeroMemory (Windows), sodium_memzero or OPENSSL_cleanse — each is guaranteed not to be optimised away.',
      });
    }
  }

  return out;
}

/** Both specialist classes in one call, for the engine. */
export function scanCryptoSpecialist(file, content) {
  return [...scanTimingUnsafeComparison(file, content), ...scanMissingZeroization(file, content)];
}
