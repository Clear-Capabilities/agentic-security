// Cross-language insecure randomness detector.
//
// Flags usage of non-cryptographic PRNGs when the result is assigned to a
// security-sensitive variable (token, session, nonce, key, secret, etc.).
//
// Coverage:
//   JS/TS: Math.random()
//   Python: random.random(), random.randint(), random.choice(), random.uniform()
//   Go: rand.Intn(), rand.Int(), rand.Float64(), rand.Int31(), rand.Int63()
//   Ruby: rand(), Random.rand, Random.new.rand
//   PHP: rand(), mt_rand(), array_rand(), shuffle()

const SECURITY_CONTEXT = /\b(token|session|nonce|key|secret|password|otp|csrf|salt|code|pin|auth|reset|verify|captcha|challenge|ticket)\b/i;
// camelCase carrier: a security term as the suffix of an identifier
// (`newToken`, `genSecret`, `sessionId`) — `\bword\b` misses these. Case
// sensitive so it only fires on the CamelCase boundary, not generic prose.
const SECURITY_CONTEXT_CAMEL = /[a-z](?:Token|Secret|Nonce|Salt|Otp|Password|Passwd|ApiKey|SessionId|Csrf|Cookie|Jwt|Nonce)\b/;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

const LANG_PATTERNS = {
  js: {
    ext: /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i,
    patterns: [
      { re: /\bMath\.random\s*\(\s*\)/g, label: 'Math.random()' },
    ],
  },
  py: {
    ext: /\.py$/i,
    patterns: [
      { re: /\brandom\.(?:random|randint|choice|uniform|randrange|sample|getrandbits)\s*\(/g, label: 'random module (non-crypto)' },
    ],
  },
  go: {
    ext: /\.go$/i,
    patterns: [
      { re: /\brand\.(?:Intn|Int|Float64|Float32|Int31|Int63|Int31n|Int63n|Uint32|Uint64)\s*\(/g, label: 'math/rand (non-crypto)' },
    ],
  },
  rb: {
    ext: /\.rb$/i,
    patterns: [
      { re: /\b(?:rand\s*\(|Random\.(?:rand|new\.rand)\s*\()/g, label: 'Kernel.rand / Random.rand' },
    ],
  },
  php: {
    ext: /\.(?:php|phtml)$/i,
    patterns: [
      { re: /\b(?:rand|mt_rand|array_rand)\s*\(/g, label: 'rand() / mt_rand()' },
    ],
  },
};

export function scanWeakRandomness(fp, raw) {
  if (!fp || !raw || typeof raw !== 'string') return [];
  if (raw.length > 500_000) return [];

  const findings = [];
  let lang = null;
  for (const [k, v] of Object.entries(LANG_PATTERNS)) {
    if (v.ext.test(fp)) { lang = v; break; }
  }
  if (!lang) return [];

  for (const { re, label } of lang.patterns) {
    re.lastIndex = 0;
    for (const m of raw.matchAll(re)) {
      const line = _line(raw, m.index);
      const lineStart = raw.lastIndexOf('\n', m.index) + 1;
      const lineEnd = raw.indexOf('\n', m.index);
      const lineText = raw.slice(lineStart, lineEnd > 0 ? lineEnd : raw.length);
      if (!SECURITY_CONTEXT.test(lineText) && !SECURITY_CONTEXT_CAMEL.test(lineText)) {
        // Widen the lookback to the enclosing block: the security keyword is
        // often on the function signature a few lines up (`function newToken()
        // { … Math.random() … }`), not the line immediately before the call.
        let winStart = lineStart;
        for (let k = 0; k < 6 && winStart > 0; k++) {
          winStart = raw.lastIndexOf('\n', winStart - 2) + 1;
        }
        const window = raw.slice(winStart, lineStart - 1);
        if (!SECURITY_CONTEXT.test(window) && !SECURITY_CONTEXT_CAMEL.test(window)) continue;
      }
      findings.push({
        id: `weak-rng:${fp}:${line}`,
        file: fp,
        line,
        vuln: `Insecure Randomness — ${label} used for security-sensitive value`,
        severity: 'high',
        family: 'weak-rng',
        // CWE-338 (cryptographically weak PRNG) — more specific than the
        // CWE-330 parent; every pattern here (Math.random / random.* / rand /
        // math.rand) is a non-CSPRNG used in a security context.
        cwe: 'CWE-338',
        parser: 'WEAK-RNG',
        confidence: 0.80,
        description: `${label} is not cryptographically secure. An attacker can predict the output and forge tokens, bypass OTP, or guess session identifiers.`,
        remediation: _remediation(fp),
        snippet: lineText.trim().slice(0, 80),
      });
    }
  }
  return findings;
}

function _remediation(fp) {
  if (/\.py$/i.test(fp)) return 'Use secrets.token_hex(32), secrets.token_urlsafe(32), or secrets.randbelow(n).';
  if (/\.go$/i.test(fp)) return 'Use crypto/rand: n, _ := rand.Int(rand.Reader, big.NewInt(999999)).';
  if (/\.rb$/i.test(fp)) return 'Use SecureRandom.hex(32) or SecureRandom.uuid.';
  if (/\.(?:php|phtml)$/i.test(fp)) return 'Use random_bytes(32) or random_int(0, $max).';
  return 'Use crypto.randomBytes(32).toString("hex") or crypto.getRandomValues().';
}
