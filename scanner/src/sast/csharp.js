// C# / .NET SAST module.
//
// Narrow, high-signal patterns for ASP.NET (Framework + Core), EF, Razor.
// Each rule fires ONLY on the unsafe shape and has a safe-shape detector
// where applicable — keeps precision near 100% and avoids polluting the
// repo-wide F1 score.
//
// Covered families:
//   - sql-injection           SqlCommand / EF FromSqlRaw with string concat
//   - command-injection       Process.Start with UseShellExecute=true and user input
//   - xss                     Razor Html.Raw with user input; .ToString() bypass
//   - xxe                     XmlDocument w/o XmlResolver=null; XmlReader settings
//   - insecure-deserialization Newtonsoft.Json TypeNameHandling.All; BinaryFormatter
//   - path-traversal          Path.Combine with user input + no canonical check
//   - validate-input-disabled [ValidateInput(false)] attribute (legacy MVC)

import { blankComments } from './_comment-strip.js';

const RE = {
  // SqlCommand("SELECT … " + var) or new SqlCommand("…" + var, conn)
  // Matches the concat shape inside the constructor's first arg.
  sqlConcat: /\bnew\s+SqlCommand\s*\(\s*["'][^"']*["']\s*\+\s*\w/g,
  // SqlCommand("SELECT " + …) followed later by .CommandText
  sqlCmdText: /\bSqlCommand\s*\([^)]*\)[\s\S]{0,400}?\.\s*CommandText\s*=\s*["'][^"']*["']\s*\+/g,
  // EF: ctx.Users.FromSqlRaw($"…{userInput}…") or .FromSql("…" + userInput)
  efFromSqlInterp: /\.\s*FromSql(?:Raw)?\s*\(\s*\$"[^"]*\{(?!\d)/g,
  efFromSqlConcat: /\.\s*FromSql(?:Raw)?\s*\(\s*["'][^"']*["']\s*\+\s*\w/g,
  // Process.Start with UseShellExecute=true AND a variable Arguments
  procShellTrue: /\bnew\s+ProcessStartInfo\s*\{[^}]*\bUseShellExecute\s*=\s*true[\s\S]{0,500}?\bArguments\s*=\s*[^"'][\w.]/g,
  // Direct Process.Start("cmd.exe", userInput) — the 2-arg form runs through cmd
  procStart2: /\bProcess\.Start\s*\(\s*"cmd(?:\.exe)?"\s*,\s*\w/gi,
  // Razor Html.Raw(userInput) — bypasses encoding
  htmlRaw: /\b(?:Html|@Html)\s*\.\s*Raw\s*\(\s*(?!["'])\s*\w/g,
  // XmlDocument loaded without disabling resolver
  xmlDocLoad: /\bnew\s+XmlDocument\s*\(\s*\)|\bvar\s+\w+\s*=\s*new\s+XmlDocument\b/g,
  // XmlReaderSettings without DtdProcessing=Prohibit
  xmlReaderSettings: /\bnew\s+XmlReaderSettings\s*\(\s*\)/g,
  // Newtonsoft.Json TypeNameHandling.All / Auto / Objects / Arrays
  newtonsoftType: /\bTypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)/g,
  // BinaryFormatter — entire surface is unsafe since .NET 5.
  binaryFormatter: /\bnew\s+BinaryFormatter\s*\(\s*\)/g,
  // [ValidateInput(false)] — ASP.NET MVC legacy bypass for XSS validation
  validateInputFalse: /\[\s*ValidateInput\s*\(\s*false\s*\)\s*\]/g,
  // Path.Combine(... userInput ...) with no canonical / startsWith check
  pathCombine: /\bPath\.Combine\s*\(\s*[^)]*\b(?:Request\.|HttpContext\.|fileName|userInput|input|name|path)\b/gi,
};

// File-level safe-shape detectors. When ANY of these appear in the file the
// corresponding family is suppressed for the whole file. Mirrors the OWASP
// Benchmark file-level pattern.
const SAFE = {
  // Parameterized SQL: ".Parameters.Add(...) " or "@param" placeholder
  sql: /\.\s*Parameters\.\s*Add(?:WithValue)?\s*\(|@\w+\s*[,)]/,
  // XML safe: XmlResolver = null OR DtdProcessing = DtdProcessing.Prohibit
  xml: /\bXmlResolver\s*=\s*null\b|\bDtdProcessing\s*=\s*DtdProcessing\.Prohibit\b|\.\s*XmlResolver\s*=\s*null/,
  // Path-traversal: GetFullPath + StartsWith
  path: /\.\s*GetFullPath\s*\([\s\S]{0,200}?\.\s*StartsWith\s*\(/,
};

const FINDINGS = [
  { id: 'csharp-sql-concat', re: RE.sqlConcat, severity: 'high', cwe: 'CWE-89',
    vuln: 'SQL Injection — SqlCommand string concatenation',
    remediation: 'Use parameterized queries: `var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn); cmd.Parameters.AddWithValue("@id", id);`. Never build SQL via concatenation; the database can\'t tell user data from SQL syntax once they\'re joined.',
    fileSafe: SAFE.sql, family: 'sql-injection' },
  { id: 'csharp-sql-cmdtext', re: RE.sqlCmdText, severity: 'high', cwe: 'CWE-89',
    vuln: 'SQL Injection — SqlCommand.CommandText concatenation',
    remediation: 'Assign a fully parameterized SQL string and use `cmd.Parameters.AddWithValue(...)` for every user-supplied value.',
    fileSafe: SAFE.sql, family: 'sql-injection' },
  { id: 'csharp-ef-fromsql-interp', re: RE.efFromSqlInterp, severity: 'high', cwe: 'CWE-89',
    vuln: 'SQL Injection — EF Core FromSqlRaw with interpolated string',
    remediation: 'Switch to `FromSqlInterpolated($"...")` (EF Core parameterizes interpolation holes automatically) or use `FromSqlRaw("...{0}...", value)` with positional placeholders. `FromSqlRaw($"...{var}...")` defeats the protection by evaluating the f-string first.',
    family: 'sql-injection' },
  { id: 'csharp-ef-fromsql-concat', re: RE.efFromSqlConcat, severity: 'high', cwe: 'CWE-89',
    vuln: 'SQL Injection — EF Core FromSqlRaw with string concatenation',
    remediation: 'Use `FromSqlInterpolated($"... {value}")` or `FromSqlRaw("... {0}", value)` with positional parameters.',
    family: 'sql-injection' },
  { id: 'csharp-proc-shellexec', re: RE.procShellTrue, severity: 'critical', cwe: 'CWE-78',
    vuln: 'Command Injection — Process.Start with UseShellExecute=true and dynamic Arguments',
    remediation: 'Set `UseShellExecute = false` and pass arguments as a `string[]` via `ProcessStartInfo.ArgumentList`. ShellExecute=true routes through cmd.exe / the shell, so any user-controlled metacharacter is interpreted.',
    family: 'command-injection' },
  { id: 'csharp-proc-cmd', re: RE.procStart2, severity: 'critical', cwe: 'CWE-78',
    vuln: 'Command Injection — Process.Start("cmd.exe", userInput)',
    remediation: 'Never invoke cmd.exe with user input as the arguments string. Call the target executable directly via ProcessStartInfo with ArgumentList.',
    family: 'command-injection' },
  { id: 'csharp-htmlraw', re: RE.htmlRaw, severity: 'high', cwe: 'CWE-79',
    vuln: 'XSS — Razor Html.Raw with user input bypasses encoding',
    remediation: '`@Html.Raw(x)` emits `x` without HTML-encoding. Use the default `@x` syntax which auto-encodes, or sanitize first via HtmlSanitizer.NET / AntiXss.GetSafeHtmlFragment.',
    family: 'xss' },
  { id: 'csharp-xmldoc-no-resolver', re: RE.xmlDocLoad, severity: 'high', cwe: 'CWE-611',
    vuln: 'XXE — XmlDocument without XmlResolver=null',
    remediation: 'After `new XmlDocument()`, set `doc.XmlResolver = null;` BEFORE calling `.LoadXml()` or `.Load()`. Default behaviour in older .NET Framework versions resolves external entities.',
    fileSafe: SAFE.xml, family: 'xxe' },
  { id: 'csharp-xmlreader-no-dtd', re: RE.xmlReaderSettings, severity: 'medium', cwe: 'CWE-611',
    vuln: 'XXE — XmlReaderSettings without DtdProcessing=Prohibit',
    remediation: 'Configure `new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }`. `DtdProcessing.Parse` (the .NET Framework default) is the unsafe shape.',
    fileSafe: SAFE.xml, family: 'xxe' },
  { id: 'csharp-newtonsoft-typename', re: RE.newtonsoftType, severity: 'critical', cwe: 'CWE-502',
    vuln: 'Insecure Deserialization — Newtonsoft.Json TypeNameHandling != None',
    remediation: '`TypeNameHandling.All/Auto/Objects/Arrays` allows the payload to specify the .NET type to instantiate, enabling RCE via gadget chains. Set `TypeNameHandling.None` (the default) or migrate to System.Text.Json.',
    family: 'insecure-deserialization' },
  { id: 'csharp-binformatter', re: RE.binaryFormatter, severity: 'critical', cwe: 'CWE-502',
    vuln: 'Insecure Deserialization — BinaryFormatter',
    remediation: 'BinaryFormatter is obsolete and unsafe — Microsoft has marked it deprecated in .NET 5+. Replace with System.Text.Json or DataContractSerializer with KnownTypes set.',
    family: 'insecure-deserialization' },
  { id: 'csharp-validate-input-false', re: RE.validateInputFalse, severity: 'high', cwe: 'CWE-79',
    vuln: 'XSS — [ValidateInput(false)] disables ASP.NET request validation',
    remediation: 'Re-enable request validation (`[ValidateInput(true)]` or remove the attribute) and explicitly HTML-encode any field that must accept tags.',
    family: 'xss' },
  { id: 'csharp-path-combine-user', re: RE.pathCombine, severity: 'high', cwe: 'CWE-22',
    vuln: 'Path Traversal — Path.Combine with user input and no canonical check',
    remediation: 'After `Path.Combine`, call `Path.GetFullPath(joined).StartsWith(Path.GetFullPath(baseDir))` and reject mismatches. Without this, `..\\..\\etc\\passwd` escapes the intended directory.',
    fileSafe: SAFE.path, family: 'path-traversal' },
];

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanCSharp(fp, raw) {
  if (!/\.cs$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const out = [];
  const seen = new Set();
  for (const rule of FINDINGS) {
    if (rule.fileSafe && rule.fileSafe.test(code)) continue;
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
        stride: rule.cwe === 'CWE-89' ? 'Tampering'
              : rule.cwe === 'CWE-78' ? 'Elevation of Privilege'
              : rule.cwe === 'CWE-79' ? 'Tampering'
              : rule.cwe === 'CWE-611' ? 'Information Disclosure'
              : rule.cwe === 'CWE-502' ? 'Elevation of Privilege'
              : rule.cwe === 'CWE-22' ? 'Tampering'
              : 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: rule.remediation,
        confidence: 0.85,
        parser: 'CSHARP',
      });
    }
  }
  return out;
}
