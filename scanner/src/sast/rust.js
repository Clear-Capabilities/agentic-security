// Rust SAST module.
//
// Rust is memory-safe by default; the interesting attacks are:
//   - sqlx::query(&format!(...))             SQL injection via format! macro
//                                            (sqlx::query! is the safe macro)
//   - Command::new("sh").arg("-c").arg(user) shell-form command injection
//   - serde_json::from_str::<Value>(...)     type-confusion when downstream code
//                                            unwraps without validation
//   - unsafe { ... } blocks                  informational — counts and reports
//                                            location; not a finding by itself
//   - hardcoded crypto seed                  Rng::from_seed([0; 32]) or similar
//
// Patterns are syntactically distinctive and don't false-match in other languages.

import { blankComments } from './_comment-strip.js';

const FINDINGS = [
  {
    id: 'rust-sqlx-format', severity: 'high', cwe: 'CWE-89', family: 'sql-injection',
    // sqlx::query(&format!("...{}...", user))  — the format! macro disables
    // the compile-time placeholder check that sqlx::query! / query_as! enforce.
    re: /\bsqlx::(?:query|query_as|query_scalar)(?:_unchecked)?\s*\(\s*&?\s*format!\s*\(/g,
    vuln: 'SQL Injection — sqlx::query with format! macro',
    remediation: 'Use the compile-time-checked macros instead: `sqlx::query!("SELECT … WHERE id = $1", id)` (note the `!` and `$1` placeholder). `query(&format!(…))` interpolates user data into the SQL string at runtime, defeating sqlx\'s static SQL guarantee.',
  },
  {
    id: 'rust-cmd-shell', severity: 'critical', cwe: 'CWE-78', family: 'command-injection',
    // Command::new("sh").arg("-c").arg(user_input) — restrict to a single
    // statement by forbidding `;` between the segments.
    re: /\bCommand::new\s*\(\s*"(?:sh|bash|zsh|cmd|cmd\.exe|powershell)"\s*\)[^;]{0,200}\.\s*arg\s*\(\s*"-c"\s*\)[^;]{0,200}\.\s*arg\s*\(\s*(?!"[^"]*"\s*\))/g,
    vuln: 'Command Injection — Command::new("sh").arg("-c").arg(<dynamic>)',
    remediation: 'Drop the shell. Pass the program and arguments to Command::new directly: `Command::new("ls").arg("-l").arg(&user_dir)`. The shell-form (`sh -c "..."`) interprets metacharacters in user input.',
  },
  {
    id: 'rust-cmd-arg-format', severity: 'high', cwe: 'CWE-78', family: 'command-injection',
    // Command::new(...).arg(format!("--flag={}", user)) — restrict to a
    // single statement (no `;` between the call and the .arg).
    re: /\bCommand::new\s*\([^)]+\)[^;]{0,200}\.\s*arg\s*\(\s*format!\s*\(/g,
    vuln: 'Command Injection — Command::arg(format!(...)) interpolates user input',
    remediation: 'Pass each value as its own .arg(): `cmd.arg("--user").arg(&name)`. Building one argument with format!("…{user}…") loses the argv boundary and can be split by spaces / shell metachars depending on the program.',
  },
  {
    id: 'rust-rng-zero-seed', severity: 'high', cwe: 'CWE-338', family: 'weak-rng',
    // ChaCha20Rng::from_seed([0; 32]) or seed: [0u8; 32]
    re: /\b(?:ChaCha\d+Rng|StdRng|SmallRng|Hc128Rng|Pcg\d+|Isaac\d+Rng)::from_seed\s*\(\s*\[\s*0\s*[;u]/g,
    vuln: 'Weak randomness — RNG seeded with constant zeros',
    remediation: 'Seed from the OS CSPRNG: `let rng = ChaCha20Rng::from_entropy()` or `OsRng.fill_bytes(&mut seed)`. A constant seed makes the RNG output fully predictable.',
  },
  {
    id: 'rust-unsafe-block', severity: 'info', cwe: 'CWE-758', family: 'unsafe-block',
    // unsafe { ... } — informational, but counted so reviewers can flag densities
    re: /\bunsafe\s*\{/g,
    vuln: 'unsafe block — review for memory-safety invariants',
    remediation: 'Each `unsafe` block bypasses Rust\'s memory-safety guarantees. Verify the invariants documented for the unsafe operation hold (typically: aliasing rules, bounds, lifetime extension). Audit dense unsafe regions for buffer overflows, use-after-free, and data races.',
    infoOnly: true,
  },
  {
    id: 'rust-actix-extract-string', severity: 'medium', cwe: 'CWE-20', family: 'input-validation',
    // web::Path<String> / web::Query<String> — accepts arbitrary user-controlled
    // strings without a typed extractor. Often a precursor to SQL/path/cmd-injection.
    re: /\bweb::(?:Path|Query)<\s*String\s*>/g,
    vuln: 'Untyped Actix extractor — web::Path<String>/web::Query<String> accepts any input',
    remediation: 'Define a typed struct with serde for the extractor: `#[derive(Deserialize)] struct UserPath { id: i64 }`. Typed extractors reject malformed input at the framework boundary instead of bubbling raw strings into your handlers.',
    infoOnly: true,
  },
  {
    id: 'rust-tls-verify-disabled', severity: 'high', cwe: 'CWE-295', family: 'tls-verification',
    // reqwest::ClientBuilder::danger_accept_invalid_certs(true) /
    // danger_accept_invalid_hostnames(true) — the method name itself says
    // "danger"; this only fires on the literal `true` argument, since a
    // variable/computed argument might legitimately gate it off in prod.
    re: /\bdanger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)/g,
    vuln: 'TLS certificate/hostname verification disabled',
    remediation: 'Remove `danger_accept_invalid_certs`/`danger_accept_invalid_hostnames` (or pass a variable that is `false` in production). If a private CA is the real problem, add its root with `Certificate::from_pem` + `.add_root_certificate(...)` instead of disabling verification.',
  },
  {
    id: 'rust-weak-hash-md5', severity: 'medium', cwe: 'CWE-327', family: 'weak-crypto',
    re: /\b(?:md5::compute|Md5::new|Md5::default)\s*\(/g,
    vuln: 'Weak cryptographic hash — MD5',
    remediation: 'MD5 is broken for any security purpose (collision-resistance, password storage, integrity). Use `sha2::Sha256` for integrity/fingerprinting or `argon2`/`bcrypt` for password hashing.',
  },
  {
    id: 'rust-weak-hash-sha1', severity: 'medium', cwe: 'CWE-327', family: 'weak-crypto',
    re: /\b(?:Sha1::new|Sha1::default|sha1::Sha1)\s*[:(]/g,
    vuln: 'Weak cryptographic hash — SHA-1',
    remediation: 'SHA-1 has practical collision attacks. Use `sha2::Sha256`/`Sha512` (or `blake3`) for anything security-relevant.',
  },
  {
    id: 'rust-weak-cipher', severity: 'high', cwe: 'CWE-327', family: 'weak-crypto',
    // des::Des / des::TdesEde3 (DES/3DES) and rc4::Rc4 — broken/deprecated
    // ciphers still published as crates.
    re: /\b(?:des::Des\b|des::TdesEde[23]\b|Rc4::new)\s*[:(<]/g,
    vuln: 'Weak/broken cipher — DES/3DES/RC4',
    remediation: 'Use an AEAD cipher from the `aes-gcm` or `chacha20poly1305` crates (`Aes256Gcm`, `ChaCha20Poly1305`). DES, 3DES and RC4 are all broken or deprecated for new use.',
  },
  {
    id: 'rust-weak-rng-token', severity: 'high', cwe: 'CWE-338', family: 'weak-rng',
    // rand::random()/thread_rng() feeding an identifier that names a
    // token/secret/key/session — `rand`'s default RNG is NOT a CSPRNG-grade
    // guarantee for security tokens the way `getrandom`/`OsRng` are treated
    // in the ecosystem's own guidance; flag the security-sensitive naming
    // context, not `rand::random()` in general (rolling dice is fine).
    re: /\b(?:let|const)\s+(?:mut\s+)?\w*(?:token|secret|session|api_?key|password|nonce|salt|csrf)\w*\s*(?::[^=]+)?=\s*(?:rand::random|rand::thread_rng\s*\(\s*\)\.gen)\b/gi,
    vuln: 'Weak randomness for a security-sensitive value (rand::random/thread_rng)',
    remediation: 'Use `rand::rngs::OsRng` (or the `getrandom` crate) to seed tokens/session ids/keys — `rand::thread_rng()`/`rand::random()` are not documented as cryptographically secure. `let mut buf = [0u8; 32]; OsRng.fill_bytes(&mut buf);`',
  },
  {
    id: 'rust-unsafe-raw-memory', severity: 'medium', cwe: 'CWE-119', family: 'memory-safety',
    // transmute / from_raw_parts(_mut) / get_unchecked(_mut) — the classic
    // unsafe memory-reinterpretation and bounds-skipping primitives. Scoped
    // to occurrences that are themselves already inside an `unsafe` block
    // in practice (transmute/from_raw_parts require it to compile at all;
    // get_unchecked does not, so it's included for the same reason: it
    // skips the bounds check the safe `[]` indexing performs).
    re: /\b(?:std::mem::transmute|mem::transmute|std::slice::from_raw_parts(?:_mut)?|slice::from_raw_parts(?:_mut)?)\s*[:(<]|\.get_unchecked(?:_mut)?\s*\(/g,
    vuln: 'Unsafe raw-memory operation (transmute/from_raw_parts/get_unchecked)',
    remediation: 'Prefer safe alternatives where possible: `as` casts or `bytemuck`/`zerocopy` instead of `transmute`; `<[T]>::get(i)`/checked slicing instead of `get_unchecked`. If unsafe is unavoidable, document the exact invariant (length, alignment, lifetime) that makes it sound at this call site.',
  },
];

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanRust(fp, raw) {
  if (!/\.rs$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const out = [];
  const seen = new Set();
  for (const rule of FINDINGS) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m;
    let count = 0;
    while ((m = re.exec(code))) {
      const line = lineOf(raw, m.index);
      const id = `${rule.id}:${fp}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      // For informational rules, only emit the first 3 hits per file
      // (avoids drowning the output with low-signal `unsafe` blocks).
      if (rule.infoOnly && ++count > 3) break;
      out.push({
        id, file: fp, line,
        vuln: rule.vuln,
        severity: rule.severity,
        cwe: rule.cwe,
        stride: rule.family === 'sql-injection' ? 'Tampering'
              : rule.family === 'command-injection' ? 'Elevation of Privilege'
              : rule.family === 'weak-rng' ? 'Spoofing'
              : rule.family === 'weak-crypto' ? 'Information Disclosure'
              : rule.family === 'tls-verification' ? 'Spoofing'
              : rule.family === 'memory-safety' ? 'Denial of Service'
              : 'Information Disclosure',
        family: rule.family,
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: rule.remediation,
        confidence: 0.85,
        parser: 'RUST',
      });
    }
  }
  return out;
}

export function extractRustImportMap(code) {
  const map = new Map();
  const globs = new Set();
  const useRe = /\buse\s+([\w_][\w_:]*?)(?:::(\w+|\{[^}]+\}|\*))(?:\s+as\s+(\w+))?/g;
  for (const m of code.matchAll(useRe)) {
    const cratePath = m[1];
    const crate = cratePath.split('::')[0];
    const imported = m[2];
    const alias = m[3];
    if (imported === '*') {
      globs.add(crate);
      continue;
    }
    if (imported.startsWith('{')) {
      const items = imported.slice(1, -1).split(',').map(s => s.trim());
      for (const item of items) {
        const parts = item.split(/\s+as\s+/);
        map.set(parts[1] || parts[0], crate);
      }
      continue;
    }
    map.set(alias || imported, crate);
  }
  return { map, globs };
}
