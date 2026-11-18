import { blankComments } from './_comment-strip.js';
// SSRF cloud-metadata awareness.
//
// Two layers:
//   1. Hardcoded fetches of cloud metadata endpoints (likely intentional, but
//      flag for review — these endpoints leak instance credentials).
//   2. User-controlled URL into an HTTP client with no allow-list — separately
//      flagged by the general SSRF rule. This module adds a +severity bump
//      and a specific remediation note when the codebase shows no evidence of
//      blocking 169.254.169.254 / fd00:ec2:: / metadata.google.internal /
//      Azure IMDS in any allow-list / proxy / fetch wrapper.

const METADATA_LITERALS = [
  /169\.254\.169\.254/,           // AWS, Azure
  /fd00:ec2::254/i,               // AWS IPv6
  /metadata\.google\.internal/i,  // GCP
  /metadata\.azure\.com/i,        // Azure
];

const SSRF_CLIENT_RE = /\b(?:fetch|axios\.\w+|requests\.\w+|http\.get|http\.request|urllib\.request\.urlopen|new\s+URL\s*\(|HttpClient\.\w+)\s*\(\s*[^)]*?(req|request|ctx\.request|input|userInput|url)\s*\.\s*(?:body|query|params|url|host)/g;

const METADATA_GUARD_RE = /(?:169\.254\.169\.254|169\.254\.|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2|metadata\.aws\.amazon)/i;

// A metadata literal that appears inside an allow/deny-list or a host
// comparison is a GUARD (the remediation), not an SSRF — e.g.
// `DENY = Set.of("169.254.169.254", …)`, `if (u.Host == "169.254.169.254")
// throw`, `host !in setOf("169.254.169.254")`, `["169.254.169.254"].includes`.
// Flagging it makes the scanner cry wolf on correctly-hardened code.
const METADATA_GUARD_CONTEXT_RE = /\b(?:deny|denylist|blocklist|blocked?|allow(?:list|ed)?|forbidden|reject(?:ed)?|disallow|banned?)\b|[!=]==?\s*['"]|\.equals\s*\(|\.contains\b|\.includes\b|\.indexOf\b|\bin\s+\w|\bnot\s+in\b|!in\b|Set\s*\.\s*of|setOf|new\s+HashSet|\bthrow\b|SecurityException|\babort\b|getHost\s*\(|\.host\b|\.Host\b/i;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

// The guard words above are matched as whole words, so an identifier that
// carries one as a camelCase or snake_case PART (`blockedIMDSHosts`,
// `deny_hosts`, `allowedTargets`) was not recognised. Split identifiers into
// their parts and look for a guard word among them.
const _GUARD_PARTS = new Set(['deny', 'denied', 'denylist', 'block', 'blocked', 'blocklist', 'blocklisted',
  'allow', 'allowed', 'allowlist', 'forbidden', 'disallow', 'disallowed', 'banned', 'reject', 'rejected']);
function _identifierHasGuardPart(text) {
  const noStrings = String(text).replace(/"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`[^`]*`/g, '""');
  for (const id of noStrings.match(/[A-Za-z_][A-Za-z0-9_]*/g) || []) {
    const parts = id.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').toLowerCase().split('_');
    if (parts.length > 1 && parts.some(p => _GUARD_PARTS.has(p))) return true;
  }
  return false;
}

// `var imds = net.ParseIP("169.254.169.254")` names the address so that a
// check elsewhere can compare against it (`ip.Equal(imds)`, `host == imds`).
// When the variable the literal is assigned to is only ever used in such a
// comparison, the literal is the guard, not a request target.
function _assignedNameUsedAsComparison(code, lineText) {
  // Modifiers are peeled one at a time (a loop, not a repeated group), then the
  // name is either first or follows one type token (`static final String NAME =`).
  let rest = String(lineText).trimStart();
  for (let n = 0; n < 6; n++) {
    const k = /^(?:var|const|let|final|val|static|private|public)\s+/.exec(rest);
    if (!k) break;
    rest = rest.slice(k[0].length);
  }
  const a = /^([A-Za-z_]\w*)\s*(?::=|=)(?!=)/.exec(rest) || /^[\w<>[\].]+\s+([A-Za-z_]\w*)\s*=(?!=)/.exec(rest);
  if (!a) return false;
  const n = a[1].replace(/[$]/g, '');
  const uses = code.split(new RegExp(`\\b${n}\\b`)).length - 2; // occurrences other than the declaration
  if (uses < 1) return false;
  const cmp = new RegExp(
    `\\.\\s*(?:Equal|Equals|equals|Contains|contains|includes|has)\\s*\\(\\s*${n}\\b` +
    `|\\b${n}\\s*\\.\\s*(?:Equal|Equals|equals|Contains|contains|includes|has)\\s*\\(` +
    `|\\b${n}\\s*[!=]==?|[!=]==?\\s*${n}\\b`, 'g');
  const cmpUses = (code.match(cmp) || []).length;
  return cmpUses >= uses;
}

export function scanSSRFCloudMetadata(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);

  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  // 1. Hardcoded reference to a metadata endpoint.
  for (const re of METADATA_LITERALS) {
    const r = new RegExp(re.source, (re.flags || '') + 'g');
    let m;
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      // Guard recognition: if the metadata literal sits in an allow/deny-list
      // or host-comparison (this line ± 1), it's blocking the endpoint, not
      // calling it — suppress the false positive on hardened code.
      const lines = raw.split('\n');
      const ctx = lines.slice(Math.max(0, line - 2), line + 1).join('\n');
      if (METADATA_GUARD_CONTEXT_RE.test(ctx)) continue;
      const codeCtx = code.split('\n').slice(Math.max(0, line - 2), line + 1).join('\n');
      if (_identifierHasGuardPart(codeCtx)) continue;
      if (_assignedNameUsedAsComparison(code, code.split('\n')[line - 1] || '')) continue;
      push({
        id: `ssrf-meta-hardcoded:${fp}:${line}`,
        file: fp, line,
        vuln: 'SSRF: explicit reference to cloud instance-metadata endpoint',
        severity: 'medium',
        cwe: 'CWE-918',
        stride: 'Information Disclosure',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Cloud metadata endpoints (169.254.169.254 for AWS/Azure, metadata.google.internal for GCP) expose instance credentials and tokens. Calls *to* these endpoints are sometimes legitimate (the workload retrieving its own creds), but exposure *via* user-controlled requests is a primary cloud-takeover path. If this call is intentional, gate it behind a startup-only path. If not, drop it.',
        parser: 'SSRF-METADATA',
        confidence: 0.70,
      });
    }
  }

  // 2. User-controlled URL into an HTTP client, with no metadata guard nearby.
  const r = new RegExp(SSRF_CLIENT_RE.source, SSRF_CLIENT_RE.flags);
  let m;
  while ((m = r.exec(code))) {
    const line = lineOf(raw, m.index);
    // Skip if a guard appears in ±10 lines. A file-wide "does this file
    // contain a guard anywhere" check used to OR into this and blanket-
    // suppressed every unguarded call site once any one call site was
    // properly guarded — removed; proximity is what makes a guard actually
    // apply to a given call.
    const lines = raw.split('\n');
    const window = lines.slice(Math.max(0, line - 11), line + 10).join(' ');
    if (METADATA_GUARD_RE.test(window)) continue;
    push({
      id: `ssrf-meta-usercontrolled:${fp}:${line}`,
      file: fp, line,
      vuln: 'SSRF (metadata-aware): user-controlled URL into HTTP client without metadata allow-deny',
      severity: 'high',
      cwe: 'CWE-918',
      stride: 'Information Disclosure',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Reject hostnames that resolve into RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`, `::1`), link-local (`169.254.0.0/16`), and cloud-metadata DNS names (`metadata.google.internal`, `metadata.azure.com`). Resolve DNS yourself and re-check after the resolution — DNS rebinding will swap a public IP for `169.254.169.254` between resolution and connect. Use a vetted SSRF guard like `ssrf-req-filter` or a per-call HTTP proxy that enforces the allow-list.',
      parser: 'SSRF-METADATA',
      confidence: 0.75,
    });
  }

  return findings;
}
