// Split-concatenation secret detector (language-agnostic) — PRD Tier 1.
//
// A hardcoded credential is frequently SPLIT across concatenated string
// literals specifically to slip past secret regexes that anchor on a
// contiguous token:  `AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'`,
// `GITHUB_TOKEN = 'ghp' + '_…'`, `STRIPE_KEY = 'sk' + '_live_…' + '…'`.
//
// We join the literals back together and match the *reassembled* value against
// known provider prefixes (high precision — these markers don't occur by
// accident) or, for a credential-named LHS, a long joined literal. The flow
// engine and the contiguous-token secrets scanner both miss the split shape;
// csharp-structural.js handles it for C# only. This covers JS/TS/Py/Rb/Go/
// Java/PHP via the `+` (and PHP `.`) concat operators.

import { blankComments } from './_comment-strip.js';

// Real provider markers — anchored, so a generic `'foo' + 'bar'` won't match.
const SECRET_PREFIX = /(?:sk_|sk-|AKIA|ASIA|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[abprs]-|AIza|ya29\.|eyJ[A-Za-z0-9_-]{8,}|-----BEGIN|glpat-|shpat_|shpss_|npm_|dop_v1_|SG\.[A-Za-z0-9_-]{10,})/;
// Credential-signalling LHS identifier.
const SECRET_NAME = /(?:api[_-]?key|secret|token|passwd|password|pwd|credential|private[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token)/i;

// LHS ident, then `=`/`:=`/`:`, then a concat of >=2 string literals joined by
// `+` (most langs) or `.` (PHP). Single or double quoted.
const ASSIGN_CONCAT = /([A-Za-z_$][\w$]*)\s*(?::?=|:)\s*((?:(?:'[^'\n]*'|"[^"\n]*")\s*[+.]\s*)+(?:'[^'\n]*'|"[^"\n]*"))/g;

const lineOf = (raw, idx) => raw.substring(0, idx).split('\n').length;
function joinLiterals(expr) {
  const parts = expr.match(/'[^'\n]*'|"[^"\n]*"/g) || [];
  return parts.map((p) => p.slice(1, -1)).join('');
}

export function scanSecretConcat(fp, raw) {
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py|rb|go|java|kt|php|phtml|cs|scala|groovy)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const findings = [];
  const seen = new Set();

  const re = new RegExp(ASSIGN_CONCAT.source, ASSIGN_CONCAT.flags);
  let m;
  while ((m = re.exec(code))) {
    const ident = m[1];
    const value = joinLiterals(m[2]);
    const byPrefix = SECRET_PREFIX.test(value);
    const byName = SECRET_NAME.test(ident) && value.length >= 24;
    if (!byPrefix && !byName) continue;
    const line = lineOf(code, m.index);
    const id = `secret-concat:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id, file: fp, line,
      vuln: 'Hardcoded credential — secret split across concatenated literals to evade detection',
      severity: 'high', cwe: 'CWE-798', family: 'secret', parser: 'SECRET-CONCAT', confidence: 0.78,
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Load the secret from the environment or a secrets manager (process.env / os.environ / Vault / AWS Secrets Manager). Splitting the literal across a concatenation does not protect it — rotate the exposed value, it must be considered compromised.',
    });
  }
  return findings;
}
