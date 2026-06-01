// R22 (PRD §5) — cross-service dataflow (contract-file-free).
//
// posture/cross-lang-* links services through a shared contract artifact
// (OpenAPI/proto). This infers the edge directly from CODE: an HTTP client call
// whose URL path matches a route registered in ANOTHER file is a service edge.
// When the client sends user-controlled data over that edge — especially to an
// UNAUTHENTICATED internal endpoint — data crosses a trust boundary unobserved.
//
// Pure cross-file analysis over the aggregated route inventory + file contents.
// Path matching normalizes dynamic segments (/:id, /{id}, numeric) so a literal
// client URL aligns with a parameterized route. Precision-first: requires a
// real route match AND user-controlled data in the client call.

const CLIENT_CALLS = [
  /\bfetch\s*\(\s*[`'"]([^`'"]+)[`'"]/g,
  /\baxios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*[`'"]([^`'"]+)[`'"]/g,
  /\baxios\s*\(\s*\{[^}]*?\burl\s*:\s*[`'"]([^`'"]+)[`'"]/g,
  /\b(?:got|ky|superagent|needle)\s*(?:\.\s*\w+)?\s*\(\s*[`'"]([^`'"]+)[`'"]/g,
  /\brequests\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*[`'"]([^`'"]+)[`'"]/g,
  /\bhttpClient\s*\.\s*\w+\s*\(\s*[`'"]([^`'"]+)[`'"]/g,
];
const USER_DATA = /\b(?:req\.(?:body|params|query|headers)|request\.(?:data|json|args)|ctx\.request|params|\.body\b|userInput|user_input|formData)\b/;

// Normalize a URL path: drop scheme+host, collapse dynamic segments to '*'.
export function normalizePath(url) {
  let p = String(url || '').trim();
  p = p.replace(/^[a-z]+:\/\/[^/]+/i, '');            // strip scheme://host
  p = p.replace(/[?#].*$/, '');                        // strip query/hash
  if (!p.startsWith('/')) p = '/' + p;
  const segs = p.split('/').map((s) => {
    if (/^(?::\w+|\{\w+\}|<\w+>|\*|\$\{[^}]+\}|\d+)$/.test(s)) return '*';
    return s.toLowerCase();
  });
  let out = segs.join('/').replace(/\/+$/, '');
  return out || '/';
}

function lineOf(text, idx) { return text.slice(0, idx).split('\n').length; }

/**
 * routes: aggregated route inventory (aR). fileContents: { file: text }.
 * Returns cross-service edge findings.
 */
export function scanCrossService(routes, fileContents) {
  if (!Array.isArray(routes) || !routes.length) return [];
  // Index server routes by normalized path → list of {route}.
  const byPath = new Map();
  for (const r of routes) {
    if (!r || r.path === '(file-based)' || !r.path || !r.path.startsWith('/')) continue;
    const np = normalizePath(r.path);
    if (!byPath.has(np)) byPath.set(np, []);
    byPath.get(np).push(r);
  }
  if (!byPath.size) return [];

  const findings = [];
  const seen = new Set();
  for (const [file, content] of Object.entries(fileContents || {})) {
    if (typeof content !== 'string') continue;
    for (const re of CLIENT_CALLS) {
      const rx = new RegExp(re.source, re.flags);
      let m;
      while ((m = rx.exec(content))) {
        const url = m[1];
        const np = normalizePath(url);
        const targets = byPath.get(np);
        if (!targets) continue;
        // Only a cross-FILE edge is interesting (same-file is a local call).
        const remote = targets.find((t) => t.file !== file);
        if (!remote) continue;
        const line = lineOf(content, m.index);
        // Is user-controlled data in the call's vicinity?
        const ctx = content.slice(m.index, m.index + 240);
        const carriesUserData = USER_DATA.test(ctx);
        if (!carriesUserData) continue; // precision: only flag tainted edges
        const key = `${file}:${line}:${np}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const unauthed = remote.hasAuth === false;
        findings.push({
          id: `cross-service:${file}:${line}`,
          severity: unauthed ? 'high' : 'medium',
          file, line,
          vuln: `Cross-service flow: user-controlled data sent to ${remote.method} ${remote.path}${unauthed ? ' (unauthenticated internal endpoint)' : ''}`,
          cwe: unauthed ? 'CWE-862' : 'CWE-668',
          family: 'cross-service',
          parser: 'XSERVICE',
          description: `This client call carries user-controlled data to ${remote.method} ${remote.path}, defined in ${remote.file}. Data crosses a service boundary here${unauthed ? ', and the target route enforces no authentication — an attacker-reachable internal endpoint' : ''}. Inferred from code (no shared contract file).`,
          remediation: unauthed
            ? 'Authenticate/authorize the internal endpoint and validate the forwarded payload at the receiving service; never trust cross-service input implicitly.'
            : 'Validate and authorize the forwarded payload at the receiving service; treat cross-service input as untrusted.',
          _edge: { from: file, to: remote.file, route: `${remote.method} ${remote.path}` },
        });
      }
    }
  }
  return findings;
}
