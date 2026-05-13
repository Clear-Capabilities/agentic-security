// Go SAST — extensions to the existing Go coverage in engine.js.
//
// Adds:
//   - text/template misuse           imported instead of html/template for HTML
//   - exec.Command shell-form        exec.Command("sh", "-c", <var>) vs argv-form
//   - http.Client custom-transport   http.Get(<var>) or http.NewRequest with
//                                    user-controlled URL and no allowlist
//
// These patterns are narrow and complement the existing regex-based Go rules
// (GORM raw SQL, source patterns for net/http, Echo, Chi, Gin).

import { blankComments } from './_comment-strip.js';

const FINDINGS = [
  {
    id: 'go-text-template-html', severity: 'high', cwe: 'CWE-79', family: 'xss',
    // import "text/template" AND ResponseWriter.Write in the same file
    re: /\b"text\/template"/g,
    vuln: 'XSS — text/template package used in an HTTP handler (no auto-escaping)',
    remediation: 'For HTML output, import `"html/template"` instead. text/template does not escape HTML — any user value placed in the template renders as raw HTML. The two packages have nearly identical APIs; the switch is usually one import line.',
    // Only fire when the file looks like an HTTP handler.
    requiresContext: /\bhttp\.(?:ResponseWriter|HandleFunc|Handler)\b|\bw\s*\.\s*Write\b|\bgin\.|\becho\.|\bchi\./,
    fileSafe: /\b"html\/template"/,
  },
  {
    id: 'go-exec-shell-form', severity: 'critical', cwe: 'CWE-78', family: 'command-injection',
    // exec.Command("sh", "-c", varExpr) — the explicit shell-invocation shape
    re: /\bexec\.Command\s*\(\s*"(?:sh|bash|zsh|\/bin\/sh|\/bin\/bash)"\s*,\s*"-c"\s*,\s*(?!"[^"]*"\s*\))/g,
    vuln: 'Command Injection — exec.Command shell-form with dynamic argument',
    remediation: 'Replace the shell form with the argv form: `exec.Command("ls", "-l", userDir)`. The shell form (`sh -c "<cmd>"`) interprets `;`, `&&`, `|`, `$()` etc. in user input.',
  },
  {
    id: 'go-http-user-url', severity: 'high', cwe: 'CWE-918', family: 'ssrf',
    // http.Get(varExpr) or http.NewRequest(method, varExpr, body) where the URL is a variable.
    // Already covered for fetch/axios in the engine, but the Go-specific shape
    // gets missed because the engine's pattern doesn't include http.Get/Post.
    re: /\bhttp\.(?:Get|Post|Head|PostForm)\s*\(\s*(?!"[^"]*"\s*\))[a-zA-Z_]\w*/g,
    vuln: 'SSRF — http.Get/Post with variable URL',
    remediation: 'Allowlist the destination host before any net/http call. Use `net/url.Parse(target)` then check `parsed.Host` against an explicit allowlist. Reject RFC1918 (10/8, 172.16/12, 192.168/16) and the cloud metadata addresses (169.254.169.254, fd00:ec2::254).',
  },
  {
    id: 'go-newrequest-user-url', severity: 'high', cwe: 'CWE-918', family: 'ssrf',
    re: /\bhttp\.NewRequest(?:WithContext)?\s*\(\s*[^,]+,\s*(?!"[^"]*"\s*[,)])[a-zA-Z_]\w*/g,
    vuln: 'SSRF — http.NewRequest with variable URL',
    remediation: 'Validate the URL before building the request. The standard pattern: `u, err := url.Parse(target); if err != nil || !allowlist[u.Host] { return forbidden }`. Reject schemes other than http/https up front.',
  },
];

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanGoExtended(fp, raw) {
  if (!/\.go$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const out = [];
  const seen = new Set();
  for (const rule of FINDINGS) {
    if (rule.fileSafe && rule.fileSafe.test(code)) continue;
    if (rule.requiresContext && !rule.requiresContext.test(code)) continue;
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m;
    while ((m = re.exec(code))) {
      const line = lineOf(raw, m.index);
      const id = `${rule.id}:${fp}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({
        id, file: fp, line,
        vuln: rule.vuln,
        severity: rule.severity,
        cwe: rule.cwe,
        stride: rule.family === 'xss' ? 'Tampering'
              : rule.family === 'command-injection' ? 'Elevation of Privilege'
              : rule.family === 'ssrf' ? 'Spoofing'
              : 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: rule.remediation,
        confidence: 0.85,
        parser: 'GO',
      });
    }
  }
  return out;
}
