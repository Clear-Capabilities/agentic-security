// Secret redactor for MCP tool outputs and audit log argument summaries.
//
// OWASP MCP01 + MCP10: the scanner reads source code, and findings carry
// `snippet` / `description` / `trace` strings that may contain hardcoded
// credentials, API keys, JWTs, private keys, etc. When those flow back to
// the agent through tools/call responses they land in the agent's context
// — exposing the secret to model logs, transcripts, and any downstream tool
// the agent passes them to.
//
// We replace high-confidence secret shapes with [REDACTED:<kind>] before
// emitting them. The original full content is still on disk (scanner
// findings); the MCP surface is the bottleneck we control.
//
// Patterns deliberately stay narrow: high-precision so we don't garble
// non-secret long strings (UUIDs, SHAs, base64-encoded scan IDs).

const PATTERNS = [
  // Provider-specific high-entropy keys (anchored prefixes give very low FP)
  [/AKIA[0-9A-Z]{16}/g, 'aws-access-key'],
  [/ASIA[0-9A-Z]{16}/g, 'aws-temp-key'],
  [/gh[pousr]_[A-Za-z0-9]{36,255}/g, 'github-token'],
  [/xox[abprs]-[A-Za-z0-9-]{10,}/g, 'slack-token'],
  [/sk-ant-[A-Za-z0-9_-]{20,}/g, 'anthropic-key'],
  [/sk-proj-[A-Za-z0-9_-]{20,}/g, 'openai-project-key'],
  [/sk-[A-Za-z0-9]{32,}/g, 'openai-or-stripe-key'],
  [/sk_(?:live|test)_[A-Za-z0-9]{20,}/g, 'stripe-key'],
  [/rk_(?:live|test)_[A-Za-z0-9]{20,}/g, 'stripe-restricted-key'],
  [/SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, 'sendgrid-key'],
  [/AIza[0-9A-Za-z_-]{35}/g, 'google-api-key'],
  // JWT — three dot-separated b64url segments starting with eyJ
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'jwt'],
  // PEM-encoded private keys
  [/-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, 'private-key-block'],
  // Authorization headers — common copy-paste shape
  [/(?:Authorization|authorization)\s*:\s*Bearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}/g, 'bearer-token'],
  // Hardcoded password literals — assignment shape with quoted value
  [/(password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["'][^"'\n]{6,}["']/gi, 'hardcoded-credential'],
];

const SNIPPET_MAX = 2000;
// OWASP A03 — cap input before running 14 regex patterns over it. A forged
// last-scan.json could plant a 50MB description string; without this cap a
// single explain_finding/query_taint call would peg CPU. After truncation
// the snippet still gets the final SNIPPET_MAX trim downstream.
const INPUT_MAX = 100_000;

export function redactString(s) {
  if (typeof s !== 'string') return s;
  let out = s;
  if (out.length > INPUT_MAX) out = out.slice(0, INPUT_MAX) + `…(+${out.length - INPUT_MAX})`;
  for (const [re, kind] of PATTERNS) {
    out = out.replace(re, `[REDACTED:${kind}]`);
  }
  if (out.length > SNIPPET_MAX) out = out.slice(0, SNIPPET_MAX) + `…(+${out.length - SNIPPET_MAX})`;
  return out;
}

// Deep-redact every string in a finding-like object (mutates returned copy).
export function redactFinding(f) {
  if (!f || typeof f !== 'object') return f;
  const out = { ...f };
  for (const k of ['snippet', 'description', 'remediation', 'title', 'vuln', 'message']) {
    if (typeof out[k] === 'string') out[k] = redactString(out[k]);
  }
  if (out.trace) {
    try { out.trace = JSON.parse(redactString(JSON.stringify(out.trace))); }
    catch { /* keep as-is if not round-trippable */ }
  }
  return out;
}

// Redact a freeform JSON-stringified argument blob (used by audit log).
export function redactArgsBlob(s) {
  return redactString(s);
}
