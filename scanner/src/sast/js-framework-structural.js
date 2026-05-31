// JS/TS framework structural detectors — PRD Tier 1 (JS/Python recall).
//
// The weakest languages (JS/Python) miss framework-handler shapes where user
// input arrives via a framework source (@Query, ctx.query, req.query) and is
// concatenated into a sink. Taint-independent structural rules close them.
// SSRF/path findings (CWE-918/CWE-22) are emitted here too; the centralized
// guard pass (engine.js dropGuardedFindings) handles their hardened forms.

import { blankComments } from './_comment-strip.js';

const JS_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const lineOf = (raw, idx) => raw.substring(0, idx).split('\n').length;

// Skip an XSS finding when the value is HTML-escaped on the same line.
const XSS_ESCAPE = /\b(?:escape|escapeHtml|escape_html|sanitize|sanitizeHtml|DOMPurify\.sanitize|he\.encode|he\.escape|_\.escape|encodeURIComponent|xss)\s*\(/;
// Skip prototype pollution when the file filters forbidden keys.
const PROTO_GUARD = /(?:__proto__|constructor|prototype|FORBIDDEN_KEYS|DANGEROUS_KEYS|blocked?Keys)\b[\s\S]{0,80}?(?:continue|delete|\.has\s*\(|new\s+Set|\.includes\s*\(|skip|filter|reject|block|throw|return)/;

export function scanJsFrameworkStructural(fp, raw) {
  if (!JS_RE.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const lines = code.split('\n');
  const findings = [];
  const seen = new Set();
  const emit = (key, line, meta) => {
    const id = `js-fw-${key}:${fp}:${line}`;
    if (seen.has(id)) return;
    seen.add(id);
    findings.push({
      id, file: fp, line, vuln: meta.vuln, severity: meta.severity, cwe: meta.cwe,
      family: meta.family, parser: 'JS-FW', confidence: meta.confidence ?? 0.7,
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200), remediation: meta.remediation,
    });
  };

  // SQL Injection: db.query/.execute/.raw with template-literal ${} or concat.
  // (TypeORM Connection.query, mysql connection.query, etc.)
  const SQL_RE = /\.(?:query|execute|raw|prepare)\s*\(\s*(?:`[^`\n]*\$\{|"[^"\n]*"\s*\+|'[^'\n]*'\s*\+|"[^"\n]*\$\{)/g;
  let m;
  while ((m = SQL_RE.exec(code))) emit('sqli', lineOf(code, m.index), {
    vuln: 'SQL Injection — query built with template literal / concat (JS/TS)',
    severity: 'critical', cwe: 'CWE-89', family: 'sql-injection', confidence: 0.75,
    remediation: 'Use parameterized queries — pass `?`/`$1` placeholders and a values array (e.g. `conn.query("… WHERE name = ?", [name])`). Never interpolate or concatenate values into SQL.',
  });

  // NestJS / axios HttpService SSRF: http(.|Service|Client).get(<non-literal>).
  const SSRF_RE = /\b(?:http|httpService|httpClient|axios)\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*[A-Za-z_$][\w$.]*\s*[),]/g;
  while ((m = SSRF_RE.exec(code))) emit('ssrf', lineOf(code, m.index), {
    vuln: 'SSRF — HTTP client request to a non-literal URL (JS/TS)',
    severity: 'high', cwe: 'CWE-918', family: 'ssrf', confidence: 0.55,
    remediation: 'Validate the URL host against an allow-list and reject RFC1918 / link-local / metadata (169.254.169.254) addresses before requesting.',
  });

  // Koa path traversal: koa-send with a user-controlled path.
  const KOA_PATH_RE = /\bsend\s*\(\s*ctx\s*,\s*ctx\s*\.\s*(?:query|params|request)\b/g;
  while ((m = KOA_PATH_RE.exec(code))) emit('koa-path', lineOf(code, m.index), {
    vuln: 'Path Traversal — koa-send with user-controlled path',
    severity: 'high', cwe: 'CWE-22', family: 'path-traversal', confidence: 0.6,
    remediation: 'Resolve against an allow-listed root and reject paths that escape it; koa-send `root` alone does not stop `..` in all versions. Use `path.basename` or a canonicalize+containment check.',
  });

  // Koa reflected XSS: ctx.body assigned from ctx.query/params (unless escaped).
  const KOA_XSS_RE = /ctx\s*\.\s*body\s*=\s*([^;\n]*\bctx\s*\.\s*(?:query|params|request)\b[^;\n]*)/g;
  while ((m = KOA_XSS_RE.exec(code))) {
    if (XSS_ESCAPE.test(m[1])) continue;
    emit('koa-xss', lineOf(code, m.index), {
      vuln: 'Reflected XSS — ctx.body built from user input without encoding (Koa)',
      severity: 'high', cwe: 'CWE-79', family: 'xss', confidence: 0.65,
      remediation: 'HTML-encode user input before placing it in the response body (e.g. `escape-html`), or render via a template engine with auto-escaping.',
    });
  }

  // Prototype pollution: a deep-merge/extend of req/ctx user input, unless the
  // file filters __proto__/constructor/prototype keys.
  const PROTO_RE = /\b(?:deepMerge|deepExtend|mergeDeep|defaultsDeep|mergeWith|_\.merge|merge|extend|assignIn)\s*\([^)\n]*\b(?:req|request|ctx)\s*\.\s*(?:body|query|params)\b/g;
  const fileFiltersProto = PROTO_GUARD.test(code);
  while ((m = PROTO_RE.exec(code))) {
    if (fileFiltersProto) continue;
    emit('proto', lineOf(code, m.index), {
      vuln: 'Prototype Pollution — user input deep-merged without key filtering',
      severity: 'critical', cwe: 'CWE-1321', family: 'prototype-pollution', confidence: 0.6,
      remediation: 'Reject `__proto__`, `constructor`, and `prototype` keys before merging, or use a Map / Object.create(null) / structuredClone. Avoid merging request bodies into existing objects.',
    });
  }

  return findings;
}
