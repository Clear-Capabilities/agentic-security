// A 32-bit string hash used as the cache key for request-derived data: CWE-328.
//
// THE SHAPE (JavaScript/TypeScript).
//
//     function hashOf(s) { let h = 0; for (const c of s) h = (Math.imul(31, h) + c.charCodeAt(0)) | 0; return String(h); }
//     function cacheKey(request) { return makeKey(hashOf([request.method, request.url, request.body].join('|'))); }
//
// A multiply-by-31 (or 33) rolling hash has 2^32 outputs and is trivially invertible, so an attacker can craft a second request whose
// key collides with someone else's, and be served (or poison) that entry. Lookup tables keyed this way need either the full key compared
// on hit, or a cryptographic digest. The rule does not fire on the same hash used for ids, colours or bucketing: only when its result
// becomes a cache, store or state key in a function that builds that key from a request.
//
// WHAT MUST BE TRUE TO REPORT. A function whose loop folds `charCodeAt` with a 31/33 multiplier (`Math.imul(31, h)`, `h * 31`,
// `(h << 5) - h`, `(h << 5) + h`); a call to it whose result, on the same or the next lines, is a cache/store/state key; and the
// function making that call takes or reads a request or URL. Reported at the hash's fold line, which is what the fix replaces.

const FILE_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const FOLD = /charCodeAt|codePointAt/;
const WEAK_MIX = /Math\.imul\(\s*3[13]\s*,|\*\s*3[13]\b|\b3[13]\s*\*|<<\s*5\s*\)\s*[-+]/;
const KEY_USE = /\b(?:make(?:State|Cache|Store)?Key|(?:state|cache|store|transfer)Key|cache\w*\s*\.\s*(?:set|get|has)|(?:store|cache|state)\s*\[)/i;
const REQUEST = /\b(?:req|request|url|requestUrl|mappedRequestUrl|httpRequest)\b/;

const isTest = (f) => /(?:^|\/)(?:tests?|specs?|__tests__)\//i.test(f) || /\.(?:test|spec)\.\w+$/.test(f);

export function scanWeakHashCacheKey(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || !FOLD.test(code) || !WEAK_MIX.test(code) || isTest(file)) return [];
  const lines = code.split('\n');
  const out = [];
  const DEF = /(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>))/;
  for (let i = 0; i < lines.length; i++) {
    const d = lines[i].match(DEF);
    if (!d) continue;
    const name = d[1] || d[2];
    // The hash body: the next 25 lines, looking for the fold.
    let fold = -1;
    for (let r = i; r < Math.min(lines.length, i + 25); r++) {
      if (r > i && DEF.test(lines[r])) break;
      if (WEAK_MIX.test(lines[r]) && (FOLD.test(lines[r]) || FOLD.test(lines[r - 1] || '') || FOLD.test(lines[r + 1] || ''))) { fold = r; break; }
    }
    if (fold < 0) continue;
    // A call whose result is used as a key, inside a function that handles a request.
    const callRe = new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}\\s*\\(`);
    let used = -1;
    for (let r = 0; r < lines.length && used < 0; r++) {
      if (r === i || !callRe.test(lines[r])) continue;
      const near = lines.slice(r, Math.min(lines.length, r + 4)).join('\n');
      if (!KEY_USE.test(near)) continue;
      const above = lines.slice(Math.max(0, r - 20), r + 1).join('\n');
      if (!REQUEST.test(above)) continue;
      used = r;
    }
    if (used < 0) continue;
    out.push({
      id: `weak-hash-cache-key:${file}:${fold + 1}`,
      file, line: fold + 1,
      vuln: `32-bit string hash \`${name}\` used as a cache key for request data`,
      severity: 'medium',
      cwe: 'CWE-328',
      family: 'weak-crypto',
      stride: 'Tampering',
      description: `\`${name}\` folds characters with a 31/33 multiplier into 32 bits; line ${used + 1} uses its result as a cache or state key built from a request. Collisions can be computed directly, so a crafted request can map to another request's entry and read or overwrite the cached response.`,
      remediation: 'Key the cache on the full canonical request string (or compare it on every hit), or use a cryptographic digest such as SHA-256 of that string.',
      snippet: lines[fold].trim().slice(0, 200),
      parser: 'WEAK-HASH-KEY',
      confidence: 0.5,
    });
  }
  return out;
}
