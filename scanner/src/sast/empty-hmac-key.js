// Empty-string fallback for an HMAC or signing key: CWE-287.
//
// THE SHAPE. A missing key is replaced with an empty string and the result is used to compute or check a MAC or signature:
//
//     key ||= ''                                       # Ruby
//     key = opts.secret || ''                          // JavaScript
//     key = settings.secret_key or b''                 # Python
//     $key = $config['secret'] ?? '';                  // PHP
//     ... HMAC(digest, key, data) / sign(...) / verify(...)
//
// An HMAC keyed with the empty string is a public function: anyone can compute a valid tag, so a token, webhook signature or cookie
// "verified" with it authenticates nothing. The fallback turns a configuration mistake (no secret set) into silently accepting forged
// input, where the safe behaviour is to refuse. The fix rejects a missing or empty key before signing or verifying.
//
// WHAT MUST BE TRUE TO REPORT. The variable on either side of the fallback is named as a key or secret; the empty-string literal is the
// fallback; within the next lines of the same function the variable reaches an HMAC, sign or verify call; and nothing between the two
// rejects an empty value (`.empty?`, `len(x) == 0`, `!x`, `not x`, `x == ''` before the call). A check that only runs after the MAC was
// computed (a rescue clause) does not count.

const FILE_RE = /\.(?:rb|py|js|jsx|mjs|cjs|ts|tsx|php)$/i;
const PREFILTER = /hmac|sign|verify/i;
const KEYISH = /(?:key|secret)/i;

const FALLBACKS = [
  // Ruby `x ||= ''`
  /^\s*@?(\w+)\s*\|\|=\s*(['"])\2\s*$/,
  // `x = y || ''`, `x = y ?? ''`, `x = y or ''` / `b''`
  /^\s*(?:(?:const|let|var)\s+)?\$?@?([\w]+)\s*=\s*(\$?@?[\w.>\-[\]'"]+?)\s*(?:\|\||\?\?|\bor\b)\s*b?(['"])\3\s*;?\s*$/,
];

const SINK = /\bHMAC\b|\bHmac\b|createHmac\s*\(|\bhmac\.new\s*\(|\bhmac\.(?:digest|compare_digest)\b|hash_hmac\s*\(|\bsign\s*\(|\.sign\s*\(|\bverify\s*\(|\.verify\s*\(|\bsigner\b/;

const isTest = (f) => /(?:^|\/)(?:spec|specs|test|tests|__tests__)\//.test(f) || /(?:_spec|_test|\.test|\.spec)\.\w+$/.test(f) || /(?:^|\/)test_[^/]*\.py$/.test(f);

const lastSeg = (expr) => (String(expr).match(/(\w+)\W*$/) || [])[1] || '';

export function scanEmptyHmacKey(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || !PREFILTER.test(code) || isTest(file)) return [];
  if (!/(['"])\1/.test(code)) return [];
  const lines = code.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    let m = null; let which = -1;
    for (let k = 0; k < FALLBACKS.length && !m; k++) { m = lines[i].match(FALLBACKS[k]); which = k; }
    if (!m) continue;
    const target = m[1];
    const source = which === 0 ? target : lastSeg(m[2]);
    if (!KEYISH.test(target) && !KEYISH.test(source)) continue;
    const names = [...new Set([target, source].filter(Boolean))];
    const nameAlt = names.map((n) => n.replace(/[^\w]/g, '')).join('|');
    const mention = new RegExp(`(?<![\\w])(?:@|\\$)?(?:${nameAlt})(?![\\w])`);
    const empties = new RegExp(`(?:(?:${nameAlt})\\s*\\.\\s*(?:empty\\?|blank\\?|nil\\?|isEmpty\\(|length\\s*(?:===?|<)\\s*[01]\\b|size\\s*(?:==|<)\\s*[01]\\b|bytesize\\s*(?:==|<)\\s*[01]\\b)|len\\(\\s*(?:${nameAlt})\\s*\\)\\s*(?:==|<)\\s*[01]\\b|(?:!|\\bnot\\s+|\\bunless\\s+|empty\\(\\s*\\$?)(?:${nameAlt})\\b(?!\\s*\\.)|(?:${nameAlt})\\s*(?:===?|==)\\s*(['"])\\1|strlen\\(\\s*\\$?(?:${nameAlt})\\s*\\)\\s*(?:===?|<)\\s*[01]\\b)`);
    const indent = (lines[i].match(/^\s*/) || [''])[0].length;
    for (let r = i + 1; r < Math.min(lines.length, i + 30); r++) {
      const t = lines[r];
      // Leaving the function: a dedent past the fallback's own level onto a new definition, or a Ruby rescue/end at a shallower level.
      if (t.trim() && (t.match(/^\s*/) || [''])[0].length < indent && /^\s*(?:def\b|end\b|rescue\b|function\b|\}|(?:public|private|protected)\b)/.test(t)) break;
      if (empties.test(t)) break;
      if (SINK.test(t) && mention.test(t)) {
        out.push({
          id: `empty-hmac-key:${file}:${i + 1}`,
          file, line: i + 1,
          vuln: 'Signing or HMAC key falls back to an empty string',
          severity: 'high',
          cwe: 'CWE-287',
          family: 'key-hygiene',
          stride: 'Spoofing',
          description: `\`${target}\` becomes the empty string when no key is supplied, and line ${r + 1} uses it to sign or verify. An HMAC keyed with the empty string can be computed by anyone, so a signature or token checked with it authenticates nothing: a missing secret silently turns into accepting forged input.`,
          remediation: 'Refuse a missing or empty key instead of substituting the empty string: raise or return an error before signing or verifying (for example `raise ArgumentError, "key required" if key.nil? || key.empty?`).',
          snippet: lines[i].trim().slice(0, 200),
          parser: 'EMPTY-HMAC-KEY',
          confidence: 0.7,
        });
        break;
      }
    }
  }
  return out;
}
