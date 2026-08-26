// C / C++ memory-safety SAST module.
//
// Covers the OWASP C/C++ "banned-API" set: classic functions that are
// unsafe by design and have safer replacements. Patterns are syntactic —
// no taint analysis. Each rule has an optional `gate(ctx)` predicate that
// runs against the file/line context to suppress emissions outside the
// security-relevant context for that rule.
//
// Vuln families:
//   - buffer-overflow   strcpy, strcat, gets, sprintf (no `_s` / no `n`)
//   - format-string     printf/fprintf/syslog with a non-literal format arg
//   - command-injection system(<non-literal>) — userland exec via shell
//   - mem-unsafe        memcpy(dst, src, user_size) without bounds check
//                       alloca(user_size)
//   - rng-weak          rand() / srand(time(NULL)) for security
//   - hardcoded         hardcoded user/password in fopen / connect calls

import { blankComments } from './_comment-strip.js';
import { classifySecretCandidate as _entropyClassifySecret } from './_secret-entropy.js';

// ── context detectors ───────────────────────────────────────────────────────

// Files that #include any well-known crypto header — strong signal that
// rand()/srand() calls in this file are likely security-relevant.
const _CRYPTO_INCLUDE_RE = /#\s*include\s*[<"](?:openssl\/|sodium|sodium\.h|sodium\/|mbedtls\/|wolfssl\/|crypto\.h|gcrypt\.h|nettle\/|tomcrypt|bcrypt\.h|wincrypt\.h|bearssl|monocypher|s2n|botan)[^>"]*[>"]/i;

// Variable names that suggest the rand() output feeds something security-
// sensitive: tokens, keys, IVs, nonces, salts, session IDs, passwords.
// `\b` word boundaries so `iv` doesn't match `private`.
const _CRYPTO_VAR_RE = /\b(?:token|secret|password|passwd|pwd|cookie|session|sid|csrf|challenge|jwt|hmac|signature|sig|apikey|api_key|cryptoKey|cryptokey|encryption_key|cipher|nonce|salt|iv)\w*\b/i;

// Sensitive context for `rand()`: line-local evidence that the rand() value
// flows into a security-named target. Two acceptance conditions:
//   1. Same-line assignment: `token = ... rand()`, `key[i] = rand()`, etc.
//   2. Within 2 lines of the rand() call, a crypto-named variable receives
//      a value (handles `unsigned char *buf; for (...) buf[i] = rand();`
//      where `buf` is named cryptographically elsewhere).
//   3. File includes a crypto header AND window has crypto var hint.
// File-name signals are removed entirely — they over-fire on test corpora
// that happen to include "random"/"prng"/"crypto" in file or directory
// names, and they don't reflect whether THIS particular rand() call feeds
// crypto.
function _isCryptoContextRand(ctx) {
  const lines = ctx.raw.split('\n');
  // 5-line forward + 2-line back window from the rand() site. Forward
  // emphasis catches `int *buf = malloc(n); for (i=0;i<n;i++) buf[i] = rand();`
  // where the crypto-named target is declared above and used below.
  const startLine = Math.max(0, ctx.line - 3);
  const endLine = Math.min(lines.length, ctx.line + 5);
  const window = lines.slice(startLine, endLine).join('\n');
  // The rand call itself must appear in the window — sanity, since ctx.line
  // is 1-indexed.
  if (!/\b(?:rand|random|srand)\s*\(/.test(window)) return false;
  // Strong signal: an assignment in the window has a crypto-named LHS and
  // the same line also calls rand/random/srand. We check line-by-line.
  for (const line of window.split('\n')) {
    if (!/\b(?:rand|random|srand)\s*\(/.test(line)) continue;
    // Common shapes:
    //   token = rand();
    //   key[i] = rand() & 0xff;
    //   cookie = rand() % N;
    //   buf->token = rand();
    if (/\b(?:token|secret|password|passwd|pwd|cookie|session|sid|csrf|challenge|jwt|hmac|signature|sig|apikey|api_key|nonce|salt|iv|cipher|encryption_key|cryptoKey|cryptokey)\w*\s*(?:\[[^\]]*\]|\.\w+|->\w+)?\s*=/i.test(line)) {
      return true;
    }
  }
  // Medium signal: file includes a crypto header AND any crypto-named
  // identifier appears in the window (suggests flow into the crypto layer
  // even if not on the immediate lines).
  if (_CRYPTO_INCLUDE_RE.test(ctx.raw) && _CRYPTO_VAR_RE.test(window)) return true;
  return false;
}

// Defensive `sizeof(dst)` check on the destination of a strcpy/strcat. If the
// surrounding 3 lines guard the copy with `if (strlen(src) < sizeof(dst))` or
// equivalent, we can't say the call is unsafe.
const _SIZEOF_GUARD_RE = /\bsizeof\s*\(\s*\w+\s*\)|\bstrnlen\s*\(|\bsnprintf\s*\(/;
function _isStrcpyGuarded(ctx) {
  const lines = ctx.raw.split('\n');
  const start = Math.max(0, ctx.line - 4);
  const window = lines.slice(start, ctx.line).join(' ');
  return _SIZEOF_GUARD_RE.test(window);
}

// Destination-size guard — Recommendation #6 of the SCA/SAST improvement
// plan. Read the first arg of a strcpy/strcat/sprintf call site and look
// backwards in the function for a `char dest[N];` declaration. If found,
// classify the buffer as "small" (≤ 256 bytes) or "large" (> 256) — the
// large case suggests the developer sized intentionally and we downgrade
// to medium confidence; the small case keeps the high-confidence finding.
// If no fixed-size declaration is found at all (heap-allocated, struct
// member, function parameter), we keep the original finding shape.
const _CHAR_BUFFER_DECL_RE = /\b(?:char|unsigned\s+char|signed\s+char|wchar_t|int8_t|uint8_t)\s+(\w+)\s*\[\s*(\d+|\w+)\s*\]\s*;/g;
function _classifyDestBuffer(ctx, destName) {
  if (!destName) return { kind: 'unknown' };
  const lines = ctx.raw.split('\n');
  // Walk backwards from the current line; cap at file start.
  const before = lines.slice(0, ctx.line).join('\n');
  let bestSize = null;
  let m;
  const re = new RegExp(_CHAR_BUFFER_DECL_RE.source, 'g');
  while ((m = re.exec(before))) {
    if (m[1] !== destName) continue;
    const sizeTxt = m[2];
    if (/^\d+$/.test(sizeTxt)) bestSize = parseInt(sizeTxt, 10);
  }
  if (bestSize === null) return { kind: 'unknown' };
  if (bestSize <= 256) return { kind: 'small-fixed', size: bestSize };
  return { kind: 'large-fixed', size: bestSize };
}

// Format-string: only fire when the variable holding the format string was
// not assigned from a string literal earlier in the file.
function _isPrintfVarLiteral(ctx, varName) {
  if (!varName) return false;
  // Search for `varName = "literal"` or `const char *varName = "literal"` etc.
  const re = new RegExp(`\\b${varName}\\s*=\\s*"`, 'm');
  // Only consider assignments BEFORE the call (positional check).
  const before = ctx.raw.split('\n').slice(0, ctx.line - 1).join('\n');
  return re.test(before);
}

// ── rule table ──────────────────────────────────────────────────────────────

const FINDINGS = [
  // Banned string-handling: no upper bound. strcpy/strcat have safer _s
  // variants on Windows and strlcpy on BSD/macOS.
  {
    id: 'cpp-strcpy', severity: 'high', cwe: 'CWE-120', family: 'buffer-overflow',
    // Capture the destination identifier so we can apply the destination-size
    // guard (Recommendation #6) — large fixed buffers downgrade severity.
    re: /\b(strcpy|strcat|gets|stpcpy|sprintf)\s*\(\s*(\w+)/g,
    vuln: 'Banned API — unbounded string copy/format (potential buffer overflow)',
    remediation: 'Replace with the bounded variant: strcpy → strlcpy / strcpy_s; strcat → strlcat / strcat_s; gets → fgets(buf, sizeof(buf), stdin); sprintf → snprintf(buf, sizeof(buf), "%s", v). The unbounded form will silently overflow on attacker-controlled input.',
    gate: (ctx, m) => {
      if (_isStrcpyGuarded(ctx)) return false;
      // Destination classification — large fixed buffers are intentional
      // and we demote them to a less-noisy emission. Small fixed buffers
      // stay high-severity; unknown (heap / param) keeps the original behavior.
      const destName = m && m[2];
      ctx._destClass = _classifyDestBuffer(ctx, destName);
      return true;
    },
    severityFor: (ctx) => ctx._destClass && ctx._destClass.kind === 'large-fixed' ? 'medium' : 'high',
  },
  {
    // printf/warn-family: format string is ARG 1.
    //   printf(fmt, ...)            ← fmt at position 1
    //   vprintf(fmt, ap)            ← fmt at position 1
    //   warn(fmt, ...)              ← BSD libc, fmt at position 1
    //   err(fmt, ...) / errx(fmt)   ← BSD libc, fmt at position 1
    id: 'cpp-printf-fmt', severity: 'high', cwe: 'CWE-134', family: 'format-string',
    re: /\b(?:printf|vprintf|warn(?:x)?|err(?:x)?)\s*\(\s*([a-zA-Z_]\w*|argv\[\d+\])\s*[,)]/g,
    vuln: 'Format string vulnerability — non-literal format argument',
    remediation: 'Always pass a literal format string: `printf("%s", user_input)` instead of `printf(user_input)`. A user-controlled `%n` / `%s` chain can read or write arbitrary memory.',
    gate: (ctx, m) => !_isPrintfVarLiteral(ctx, m && m[1]),
  },
  {
    // f-family: format string is ARG 2 — first arg is a FILE* or fd.
    //   fprintf(FILE*, fmt, ...)
    //   dprintf(fd, fmt, ...)
    //   vfprintf(FILE*, fmt, ap)
    //   vdprintf(fd, fmt, ap)
    // Match: function(<any-arg>, <fmt-var>, ...). The first arg can include
    // nested calls like `getstream()` — match anything up to the first
    // non-nested comma.
    id: 'cpp-fprintf-fmt', severity: 'high', cwe: 'CWE-134', family: 'format-string',
    re: /\b(?:fprintf|dprintf|vfprintf|vdprintf)\s*\(\s*[^,()]*(?:\([^)]*\))?[^,]*,\s*([a-zA-Z_]\w*|argv\[\d+\])\s*[,)]/g,
    vuln: 'Format string vulnerability — non-literal format argument',
    remediation: 'For fprintf/dprintf, the format string is the SECOND argument: pass a literal like `fprintf(stderr, "%s", user_input)` instead of `fprintf(stderr, user_input)`. A user-controlled `%n` / `%s` chain can read or write arbitrary memory.',
    gate: (ctx, m) => !_isPrintfVarLiteral(ctx, m && m[1]),
  },
  {
    // syslog/vsyslog: format string is ARG 2 — first arg is priority (int).
    //   syslog(priority, fmt, ...)
    //   vsyslog(priority, fmt, ap)
    id: 'cpp-syslog-fmt', severity: 'high', cwe: 'CWE-134', family: 'format-string',
    re: /\b(?:syslog|vsyslog)\s*\(\s*[^,]+,\s*([a-zA-Z_]\w*|argv\[\d+\])\s*[,)]/g,
    vuln: 'Format string vulnerability — non-literal format argument',
    remediation: 'For syslog, the format string is the SECOND argument: pass a literal like `syslog(LOG_INFO, "%s", user_input)` instead of `syslog(LOG_INFO, user_input)`.',
    gate: (ctx, m) => !_isPrintfVarLiteral(ctx, m && m[1]),
  },
  {
    // s-family: format string is ARG 2 for sprintf, ARG 3 for snprintf.
    //   sprintf(buf, fmt, ...)
    //   snprintf(buf, n, fmt, ...)
    //   vsprintf(buf, fmt, ap)
    //   vsnprintf(buf, n, fmt, ap)
    id: 'cpp-sprintf-fmt', severity: 'high', cwe: 'CWE-134', family: 'format-string',
    re: /\b(?:s(?:n)?printf|vs(?:n)?printf)\s*\(\s*[^,]+,(?:\s*[^,]+,)?\s*([a-zA-Z_]\w*|argv\[\d+\])\s*[,)]/g,
    vuln: 'Format string vulnerability — non-literal format argument',
    remediation: 'For sprintf/snprintf, the format string is the second/third argument: pass a literal format with placeholders rather than user-controlled data as the format itself.',
    gate: (ctx, m) => !_isPrintfVarLiteral(ctx, m && m[1]),
  },
  {
    id: 'cpp-system', severity: 'critical', cwe: 'CWE-78', family: 'command-injection',
    re: /\bsystem\s*\(\s*(?!["'])\w/g,
    vuln: 'Command Injection — system() with non-literal argument',
    remediation: 'Replace `system(cmd)` with `execve(...)` + fork(), passing the program and arguments as separate strings (no shell interpretation). When using system() with concatenated input, attacker-controlled `; rm -rf /` becomes literal shell.',
  },
  {
    id: 'cpp-popen', severity: 'critical', cwe: 'CWE-78', family: 'command-injection',
    re: /\bpopen\s*\(\s*(?!["'])\w/g,
    vuln: 'Command Injection — popen() with non-literal command',
    remediation: 'popen() invokes the shell. Use a fork()+execve() pattern with pipes instead, or use posix_spawn() with `posix_spawnattr_setflags(...)` and no shell.',
  },
  {
    id: 'cpp-memcpy-usersz', severity: 'high', cwe: 'CWE-787', family: 'mem-unsafe',
    // memcpy(dst, src, var) where var ends in _len/size/count and was assigned from input
    re: /\b(?:memcpy|memmove|bcopy)\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+(?:_len|_size|_count|Len|Size|Count|len|size|count)\s*\)/g,
    vuln: 'Memory-safety risk — memcpy/memmove with externally-controlled size',
    remediation: 'Validate the size against the destination buffer before copying: `if (n > sizeof(dst)) return -1;`. Better: use std::span (C++20) or use a typed copy that carries length, like strncpy_s with explicit destmax.',
  },
  {
    id: 'cpp-alloca', severity: 'medium', cwe: 'CWE-770', family: 'mem-unsafe',
    re: /\balloca\s*\(/g,
    vuln: 'Stack-allocation with user-controllable size (DoS / stack exhaustion)',
    remediation: 'alloca() allocates on the stack with no fault behaviour — a large or attacker-influenced size crashes the process or jumps the guard page. Use malloc()/free() or std::vector instead.',
  },
  {
    id: 'cpp-rand', severity: 'medium', cwe: 'CWE-338', family: 'weak-rng',
    re: /\b(?:rand|random|srand)\s*\(/g,
    vuln: 'Cryptographically weak PRNG (rand/random/srand)',
    remediation: 'rand() is a linear-congruential generator — predictable from a few outputs. For security use cases (tokens, IVs, salts), use a CSPRNG: getrandom() / RAND_bytes() / std::random_device + std::mt19937_64 seeded from /dev/urandom.',
    // Only fire in plausibly-cryptographic contexts. Outside crypto: rand()
    // is a normal language facility (test data, branch selection, jitter).
    gate: (ctx) => _isCryptoContextRand(ctx),
  },
  {
    id: 'cpp-srand-time', severity: 'high', cwe: 'CWE-338', family: 'weak-rng',
    re: /\bsrand\s*\(\s*time\s*\(\s*(?:NULL|nullptr|0)?\s*\)/g,
    vuln: 'Cryptographic randomness seeded from time() (fully predictable)',
    remediation: 'time() seeds are guessable to within ±1 second. For any security-sensitive RNG, seed from /dev/urandom or use OS-provided CSPRNG (getrandom() / BCryptGenRandom).',
    // Same gate — `srand(time(NULL))` outside a crypto context is just a
    // common (bad) example pattern, not a real vulnerability.
    gate: (ctx) => _isCryptoContextRand(ctx),
  },

  // ── Recommendation #6/7: C/C++ family expansion ──────────────────────────

  // exec*-family with non-literal argument (CWE-78). Beyond system/popen.
  {
    id: 'cpp-exec-family', severity: 'critical', cwe: 'CWE-78', family: 'command-injection',
    re: /\b(?:execl|execle|execlp|execlpe|execv|execve|execvp|execvpe|posix_spawn)\s*\(\s*(?!["'])\w+/g,
    vuln: 'Command Injection — exec*() family with non-literal program path',
    remediation: 'Pin the program path to a constant and pass arguments as a separate argv. Never pass user-controlled data as the program path itself; an attacker can substitute any binary on $PATH.',
  },

  // Weak crypto — OpenSSL legacy / EVP_des / MD5 / SHA1 (CWE-327).
  {
    id: 'cpp-weak-crypto-md', severity: 'high', cwe: 'CWE-327', family: 'weak-crypto',
    re: /\b(?:MD5_(?:Init|Update|Final|MD5)|MD4_|MD2_|SHA1_(?:Init|Update|Final|SHA1)|RIPEMD160_)\s*\(/g,
    vuln: 'Weak Cryptography — legacy MD5/MD4/SHA1/RIPEMD160 hash primitive',
    remediation: 'Use SHA-256 or SHA-3 via the OpenSSL EVP interface (`EVP_sha256()` → `EVP_DigestInit_ex` → `EVP_DigestUpdate` → `EVP_DigestFinal_ex`). For password hashing use Argon2 (libsodium) or scrypt.',
  },
  {
    id: 'cpp-weak-crypto-des', severity: 'high', cwe: 'CWE-327', family: 'weak-crypto',
    re: /\b(?:DES_(?:set_key|ecb_encrypt|ncbc_encrypt|cbc_encrypt|ede3_cbc_encrypt)|RC2_|RC4_(?:set_key|encrypt|decrypt)|BF_(?:set_key|ecb_encrypt))\s*\(/g,
    vuln: 'Weak Cryptography — legacy DES/3DES/RC2/RC4/Blowfish primitive',
    remediation: 'Use AES-256 in GCM mode via the EVP interface (`EVP_aes_256_gcm()` → `EVP_EncryptInit_ex`). DES and RC4 are broken; 3DES is deprecated; Blowfish has a 64-bit block (Sweet32).',
  },
  {
    id: 'cpp-weak-crypto-evp', severity: 'high', cwe: 'CWE-327', family: 'weak-crypto',
    re: /\bEVP_(?:des_(?:ede3?)?_(?:cbc|ecb|cfb|ofb)|md5|md4|md2|sha1|rc4|rc2_(?:cbc|ecb|cfb|ofb)|bf_(?:cbc|ecb|cfb|ofb))\s*\(/g,
    vuln: 'Weak Cryptography — EVP factory for legacy primitive (MD5/SHA1/DES/3DES/RC2/RC4/BF)',
    remediation: 'Use a modern EVP factory: `EVP_aes_256_gcm()` for AEAD, `EVP_sha256()` / `EVP_sha3_256()` for hashing.',
  },

  // Hardcoded secret in C/C++ (CWE-798) — a string literal assigned to a
  // variable matching credential naming. Same idea as the Java/JS detector
  // but tuned to C idioms.
  {
    id: 'cpp-hardcoded-secret', severity: 'high', cwe: 'CWE-798', family: 'hardcoded-secret',
    // `static const char *password = "literal";`  or  `#define PASSWORD "literal"`
    re: /\b(?:const\s+)?char\s*(?:\*\s*)?(?:const\s+)?(\w*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|cred(?:ential)?s?|priv(?:ate)?[_-]?key)\w*)\s*\[?\s*\]?\s*=\s*"([^"]{8,})"/gi,
    vuln: 'Hardcoded Secret — credential-named char assigned a string literal',
    remediation: 'Load secrets at runtime from environment variables (`getenv("API_KEY")`), a secrets file with restricted permissions, or a vault SDK. Never compile a literal credential into the binary — `strings(1)` extracts every literal string and the binary ships with the secret embedded.',
    gate: (ctx, m) => {
      // Apply the same entropy filter to avoid the 468 FPs/1 TP problem.
      const val = m && m[2];
      if (!val) return false;
      try {
        const r = _entropyClassifySecret(val);
        if (r.skip) return false;
      } catch { /* fail open */ }
      return true;
    },
  },

  // Use-after-free / double-free — CWE-416 / CWE-415. Heuristic: same pointer
  // referenced in a free() call earlier in the function, then dereferenced
  // (or free'd again) later. Conservative on declared `nullptr`-after-free.
  {
    id: 'cpp-uaf-heuristic', severity: 'high', cwe: 'CWE-416', family: 'mem-unsafe',
    re: /\bfree\s*\(\s*(\w+)\s*\)\s*;[\s\S]{0,400}?\b\1\s*(?:->|\[|=\s*[^=])/g,
    vuln: 'Use-After-Free heuristic — free(p) followed by p->/p[ access in same function window',
    remediation: 'After `free(p)`, set `p = NULL;` immediately. The compiler can\'t catch UAF in general; explicit nulling means later derefs crash on a null check instead of executing on freed memory.',
  },
  {
    id: 'cpp-double-free', severity: 'high', cwe: 'CWE-415', family: 'mem-unsafe',
    re: /\bfree\s*\(\s*(\w+)\s*\)\s*;[\s\S]{0,400}?\bfree\s*\(\s*\1\s*\)/g,
    vuln: 'Double-free — free(p) followed by free(p) without nulling in between',
    remediation: 'After `free(p)`, set `p = NULL;`. `free(NULL)` is a defined no-op in C; `free(already_freed_p)` is undefined behavior that can corrupt the allocator and pivot to RCE.',
  },

  // Cookie / Session / token = rand() shape — when rand() is used to mint
  // session identifiers, even outside a strict "crypto" context. Distinct
  // from the gated rand() rule above to catch the obvious Juliet shape.
  {
    id: 'cpp-rand-session-token', severity: 'high', cwe: 'CWE-338', family: 'weak-rng',
    re: /\b(?:session_id|token|cookie|nonce|csrf|secret_key)\s*(?:=|\.|->)[\s\S]{0,200}?\b(?:rand|random)\s*\(/gi,
    vuln: 'Weak Randomness — session/token/cookie value derived from rand()/random()',
    remediation: 'Use getrandom() (Linux), RAND_bytes() (OpenSSL), or BCryptGenRandom() (Windows) for any identifier that has to be unguessable. rand() outputs are predictable to within 2^31 internal states.',
  },
];

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanCpp(fp, raw) {
  if (!/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  // Skip pure header files that only declare functions / contain typedefs.
  // A header with no function calls is unlikely to be a useful target.
  if (/\.(?:h|hh|hpp|hxx)$/i.test(fp) && !/[A-Za-z_]\w*\s*\([^)]*\)\s*\{/.test(code)) return [];
  const out = [];
  const seen = new Set();
  for (const rule of FINDINGS) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m;
    while ((m = re.exec(code))) {
      const line = lineOf(raw, m.index);
      const id = `${rule.id}:${fp}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      // Suppress when the match falls inside a #define macro line — those
      // are often re-declarations / wrappers in the same file.
      const lineText = (raw.split('\n')[line - 1] || '');
      if (/^\s*#\s*define\b/.test(lineText)) continue;
      // Per-rule contextual gate (Action 2). Suppress when the surrounding
      // file/line context shows the call is not security-relevant.
      const gateCtx = { file: fp, raw, line, lineText };
      if (typeof rule.gate === 'function') {
        try {
          if (!rule.gate(gateCtx, m)) continue;
        } catch { /* gate threw → fail open, keep finding */ }
      }
      // Per-finding severity override (Recommendation #6 — destination-size
      // classifier downgrades large-fixed-buffer strcpy to medium).
      let sev = rule.severity;
      if (typeof rule.severityFor === 'function') {
        try { sev = rule.severityFor(gateCtx, m) || sev; } catch { /* keep default */ }
      }
      out.push({
        id, file: fp, line,
        vuln: rule.vuln,
        severity: sev,
        cwe: rule.cwe,
        stride: rule.family === 'buffer-overflow' || rule.family === 'mem-unsafe' ? 'Tampering'
              : rule.family === 'command-injection' ? 'Elevation of Privilege'
              : rule.family === 'format-string' ? 'Information Disclosure'
              : 'Spoofing',
        snippet: lineText.trim().slice(0, 200),
        remediation: rule.remediation,
        confidence: 0.85,
        parser: 'CPP',
      });
    }
  }
  return out;
}
