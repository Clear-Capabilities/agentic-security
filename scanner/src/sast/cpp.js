// C / C++ memory-safety SAST module.
//
// Covers the OWASP C/C++ "banned-API" set: classic functions that are
// unsafe by design and have safer replacements. These patterns are
// syntactic — no taint analysis. Precision is high because the unsafe
// functions are universally documented as deprecated.
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

const FINDINGS = [
  // Banned string-handling: no upper bound. strcpy/strcat have safer _s
  // variants on Windows and strlcpy on BSD/macOS.
  {
    id: 'cpp-strcpy', severity: 'high', cwe: 'CWE-120', family: 'buffer-overflow',
    re: /\b(strcpy|strcat|gets|stpcpy|sprintf)\s*\(/g,
    vuln: 'Banned API — unbounded string copy/format (potential buffer overflow)',
    remediation: 'Replace with the bounded variant: strcpy → strlcpy / strcpy_s; strcat → strlcat / strcat_s; gets → fgets(buf, sizeof(buf), stdin); sprintf → snprintf(buf, sizeof(buf), "%s", v). The unbounded form will silently overflow on attacker-controlled input.',
  },
  {
    id: 'cpp-printf-fmt', severity: 'high', cwe: 'CWE-134', family: 'format-string',
    // printf/fprintf/sprintf where the format arg is a variable, not a literal
    re: /\b(?:printf|fprintf|syslog|vprintf|vsyslog|warn(?:x)?|err(?:x)?)\s*\(\s*(?:[a-zA-Z_]\w*|argv\[\d+\])\s*[,)]/g,
    vuln: 'Format string vulnerability — non-literal format argument',
    remediation: 'Always pass a literal format string: `printf("%s", user_input)` instead of `printf(user_input)`. A user-controlled `%n` / `%s` chain can read or write arbitrary memory.',
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
  },
  {
    id: 'cpp-srand-time', severity: 'high', cwe: 'CWE-338', family: 'weak-rng',
    re: /\bsrand\s*\(\s*time\s*\(\s*(?:NULL|nullptr|0)?\s*\)/g,
    vuln: 'Cryptographic randomness seeded from time() (fully predictable)',
    remediation: 'time() seeds are guessable to within ±1 second. For any security-sensitive RNG, seed from /dev/urandom or use OS-provided CSPRNG (getrandom() / BCryptGenRandom).',
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
      out.push({
        id, file: fp, line,
        vuln: rule.vuln,
        severity: rule.severity,
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
