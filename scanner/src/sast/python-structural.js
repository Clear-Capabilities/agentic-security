// Python framework structural detectors — PRD Tier 1 (JS/Python recall).
//
// Closes Flask/Django handler FNs where user input is concatenated into a
// template or raw SQL. Taint-independent: the concat / f-string / %-format is
// the injection shape. Crucially, a Jinja `{{ name }}` placeholder is SAFE
// (auto-escaped), so `{` alone is NOT a signal — only `+`, f-strings, or
// `.format()`/`%`.

import { blankComments } from './_comment-strip.js';

const lineOf = (raw, idx) => raw.substring(0, idx).split('\n').length;

// Dynamic-string shape inside a sink call: concat (`"…" +`), f-string (`f"…"`),
// `.format(`, or `%`-format via the `%` OPERATOR after the string (`"…%s" % v`).
// NOT a plain literal, and NOT a `%s` placeholder followed by a params list —
// `execute("… %s", [v])` is the SAFE parameterized DB-API form.
const DYN = String.raw`(?:[fF]["']|["'][^"'\n]*["']\s*\+|["'][^"'\n]*["']\s*%\s*[(\w]|["'][^"'\n]*["']\s*\.\s*format\s*\()`;

export function scanPythonStructural(fp, raw) {
  if (!/\.py$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw, 'py');
  const findings = [];
  const seen = new Set();
  const emit = (key, line, meta) => {
    const id = `py-struct-${key}:${fp}:${line}`;
    if (seen.has(id)) return;
    seen.add(id);
    findings.push({
      id, file: fp, line, vuln: meta.vuln, severity: meta.severity, cwe: meta.cwe,
      family: meta.family, parser: 'PYTHON', confidence: meta.confidence ?? 0.7,
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200), remediation: meta.remediation,
    });
  };

  // Flask SSTI: render_template_string built from a dynamic string. A static
  // template with Jinja `{{ }}` placeholders is safe and must not match.
  const SSTI_RE = new RegExp(String.raw`\brender_template_string\s*\(\s*` + DYN, 'g');
  let m;
  while ((m = SSTI_RE.exec(code))) emit('flask-ssti', lineOf(code, m.index), {
    // render_template_string with a built string is both reflected XSS
    // (unescaped user input in the rendered HTML) and template injection
    // (`{{7*7}}` executes). Classified CWE-79 (the dominant, ground-truth
    // taxonomy); the remediation covers the SSTI aspect too.
    vuln: 'Reflected XSS / template injection (SSTI) via render_template_string (Flask)',
    severity: 'critical', cwe: 'CWE-79', family: 'xss', confidence: 0.7,
    remediation: 'Use a static template with `{{ }}` placeholders and pass values as named context (`render_template_string("Hi {{ name }}", name=name)`). Never build the template body from input.',
  });

  // Django raw SQL: .raw() / .extra() built from a dynamic string.
  const DJ_RE = new RegExp(String.raw`\.\s*(?:raw|extra)\s*\(\s*` + DYN, 'g');
  while ((m = DJ_RE.exec(code))) emit('django-sqli', lineOf(code, m.index), {
    vuln: 'SQL Injection — Django raw()/extra() built with string concat / format (Python)',
    severity: 'critical', cwe: 'CWE-89', family: 'sql-injection', confidence: 0.7,
    remediation: 'Use the ORM with an allow-list for column/order fields, or parameterize: `User.objects.raw("… WHERE name = %s", [name])`. Never concatenate into raw SQL.',
  });

  // DB-API cursor.execute built from a dynamic string.
  const EXEC_RE = new RegExp(String.raw`\.\s*execute(?:script)?\s*\(\s*` + DYN, 'g');
  while ((m = EXEC_RE.exec(code))) emit('cursor-sqli', lineOf(code, m.index), {
    vuln: 'SQL Injection — cursor.execute built with string concat / format (Python)',
    severity: 'critical', cwe: 'CWE-89', family: 'sql-injection', confidence: 0.7,
    remediation: 'Pass parameters as the second argument with `%s` placeholders: `cursor.execute("… WHERE id = %s", [id])`. Never concatenate or %-format values into the SQL string.',
  });

  return findings;
}
