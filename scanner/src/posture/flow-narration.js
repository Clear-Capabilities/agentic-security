// LLM-driven flow narration (FR-LOGIC-6).
//
// For each high-severity finding, produce a one-paragraph narrative of:
//   - how the attacker gets to this code path
//   - what they get if it works
//   - what it costs the business
//
// Two modes:
//   1. LLM mode (AGENTIC_SECURITY_LLM_ENDPOINT set): post the finding to
//      the configured LLM endpoint, get back a sanitized narrative.
//   2. Template mode (default): emit a deterministic template based on the
//      finding's family + cost-framing data from blast-radius.
//
// Fail-closed: any LLM error → template fallback, never a missing field.

const TEMPLATES = {
  'sql-injection': (f) =>
    `An unauthenticated attacker sends a crafted request containing UNION-style SQL syntax in the ${f.source?.variable || 'tainted'} field. The server's database driver executes the injected query verbatim, returning rows from any table the connection has read access to. Typical impact: full table dump of users (emails, password hashes), bypass of authentication via boolean-blind exfiltration. If the DB role has write privileges, the attacker can also INSERT/UPDATE arbitrary rows. Recovery cost: incident response, customer notification, password reset, regulatory reporting if PII leaked.`,
  'command-injection': (f) =>
    `The handler passes user-controlled input to a shell-spawning function. An attacker can append shell metacharacters (";", "$(...)", backticks) to execute arbitrary commands as the application's UID. Typical impact: read of /etc/passwd, /proc/self/environ (env vars including secrets), outbound connections to attacker-controlled hosts (data exfil). On unprivileged containers the blast radius is limited to that container; on privileged or root-owned processes, the attacker can pivot to the host.`,
  'xss': (f) =>
    `An attacker injects HTML/JS markup into user-controllable input. The server reflects (or stores) it without encoding, so when a victim browser renders the page, the attacker's script executes in the victim's session origin. Typical impact: session cookie theft, CSRF-bypass on internal endpoints, account takeover via API calls executed under the victim's auth. Cost: incident response, customer notification, potential data egress depending on what the victim's session can access.`,
  'ssrf': (f) =>
    `The handler fetches a URL constructed from user input. An attacker supplies a URL pointing at cloud-metadata endpoints (169.254.169.254 on AWS, metadata.google.internal on GCP) or internal services not exposed externally. Typical impact: theft of IAM credentials attached to the instance, fingerprinting / exploitation of internal services, port-scanning the VPC. Cost: full AWS account compromise in the worst case (IAM credential rotation, audit, blast-radius review of every action taken under the leaked credentials).`,
  'path-traversal': (f) =>
    `The handler opens a file at a path derived from user input without confining the resolved path to an intended directory. An attacker submits "../../etc/passwd" (or %-encoded variants) to read arbitrary files the application has access to. Typical impact: leakage of config files, secrets, source code, /etc/passwd. Cost: depends on what files are readable — usually low-to-medium unless secrets land in the readable set.`,
  'code-injection': (f) =>
    `User input is fed into a code-evaluation function (eval, new Function, exec). An attacker supplies arbitrary code that executes in the application's runtime context, with full access to the application's data, env, and outbound network. Typical impact: equivalent to remote code execution; same recovery cost as command-injection.`,
  'csrf': (f) =>
    `The state-changing endpoint doesn't validate that the request originated from your own application. An attacker hosts a page that issues a same-shape request from a logged-in victim's browser. Typical impact: state changes performed under the victim's identity — password change, money movement, role escalation. Cost: depends on what state can change; for billing endpoints, this is fraud-level.`,
  'open-redirect': (f) =>
    `The endpoint redirects to a URL the attacker controls. Used as part of phishing chains: victim clicks a legitimate-looking link to your domain, gets redirected to attacker.example, enters credentials thinking they're still on your site. Typical impact: phishing-amplified credential theft; reputational damage if your domain ends up on a phish-tracking list.`,
  'insecure-deserialization': (f) =>
    `The handler deserializes attacker-controlled bytes via pickle/yaml-load/Marshal. The deserialization callback invokes arbitrary code from class constructors / __reduce__ / __wakeup__. Typical impact: equivalent to remote code execution. Cost: full incident response, including investigating whether the attacker established persistence.`,
  'xxe': (f) =>
    `The XML parser resolves external entities. An attacker submits XML referencing file:///etc/passwd or http://internal/. Typical impact: file disclosure, SSRF, blind out-of-band exfiltration of secrets. Cost: similar to SSRF + path-traversal combined.`,
};

function _routeOf(f) {
  if (!f) return 'this endpoint';
  // Narration may run before the line is finalised; fall back to the file alone
  // (or a generic phrase) rather than emitting "file:undefined" / "file:?".
  const line = Number(f.line) || Number(f.source?.line) || 0;
  if (f.file && line) return `${f.file}:${line}`;
  if (f.file) return f.file;
  return 'this endpoint';
}

function _templateFor(f) {
  const fam = f.family;
  if (TEMPLATES[fam]) return TEMPLATES[fam](f);
  return `A finding of type "${f.vuln || fam || 'unknown'}" at ${_routeOf(f)}. Severity: ${f.severity || 'unknown'}. Review the remediation field for class-specific guidance.`;
}

// Render the narration without an LLM. Always available; used as the fallback
// when no LLM endpoint is configured.
function _renderTemplate(f) {
  return _templateFor(f);
}

// Optional LLM call. Disabled by default; opt-in via env. Falls back to the
// template on any error.
async function _renderLlm(f) {
  const endpoint = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  if (!endpoint) return null;
  const apiKey = process.env.AGENTIC_SECURITY_LLM_API_KEY;
  const headers = { 'Content-Type': 'application/json' };
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
  const prompt = `You are explaining a security finding to a developer in one paragraph.
Vuln: ${f.vuln}
CWE: ${f.cwe}
Severity: ${f.severity}
Location: ${_routeOf(f)}
Snippet: ${(f.snippet || '').slice(0, 200)}

Write ONE paragraph (5-7 sentences) covering: (1) how an attacker reaches this code, (2) what they get if exploited, (3) typical recovery cost. Plain English, no marketing language, no emoji.`;
  try {
    const r = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify({ prompt }) });
    if (!r.ok) return null;
    const j = await r.json().catch(() => null);
    const text = j && (j.response || j.text || j.content || j.output ||
                       j.choices?.[0]?.message?.content || j.message?.content);
    if (typeof text !== 'string' || text.length < 30) return null;
    // Sanitize: strip control chars, markdown fences, HTML metachars.
    return text.replace(/[\x00-\x1f\x7f]/g, ' ').replace(/[<>&]/g, ' ')
               .replace(/```/g, '').replace(/\s+/g, ' ').trim().slice(0, 1500);
  } catch { return null; }
}

/**
 * Annotate findings with f.narration. Default mode is template; opt-in to
 * LLM via AGENTIC_SECURITY_LLM_ENDPOINT.
 */
export async function annotateNarration(findings, opts = {}) {
  if (!Array.isArray(findings)) return;
  const useLlm = !!opts.useLlm || process.env.AGENTIC_SECURITY_FLOW_NARRATION_LLM === '1';
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    // Only narrate severity ≥ high to keep output tight on noisy projects.
    if (!/critical|high/i.test(f.severity || '')) {
      f.narration = null;
      continue;
    }
    let text = useLlm ? await _renderLlm(f) : null;
    if (!text) text = _renderTemplate(f);
    f.narration = text;
  }
}

export const _internals = { TEMPLATES, _renderTemplate, _templateFor };
