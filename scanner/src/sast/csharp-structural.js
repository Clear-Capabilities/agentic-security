// C# structural detectors — PRD Tier 1.
//
// The main csharp.js is flow/taint-based and misses two corpus shapes:
//   - a hardcoded secret in a const/static field, SPLIT across concatenated
//     literals ("sk_" + "live_…") specifically to evade secret regexes;
//   - SSRF via WebClient/HttpClient on a non-validated URL.
// Both are regex/structural and complement the flow engine.

import { blankComments } from './_comment-strip.js';
import { buildCSharpIR } from '../ir/csharp-ir.js';

const SECRET_PREFIX = /\b(?:sk_|sk-|AKIA|ghp_|gho_|xox[abps]-|AIza|eyJ|-----BEGIN|glpat-)/;
// A field whose name signals a credential, assigned a string (or concat of
// string literals — the splitting trick). The literal spans are bounded to a
// single line ([^"\r\n]*, not [^"]*): a keyword like "Password=" can appear
// as plain TEXT inside an unrelated connection-string literal (Juliet's own
// `"...;Password=" + password` shape), and since regex has no notion of
// string boundaries, that literal's own closing quote reads as the OPENING
// quote of this rule's capture group — with an unbounded [^"]*, the capture
// then runs across the following newline and swallows arbitrary subsequent
// code (across statements, even methods) until the next real `"` anywhere
// in the file, fabricating a bogus "secret value" out of unrelated source.
// Found via a real corpus false positive (CWE256/CWE319 Juliet fixtures)
// whose reported "secret" was several lines of try/catch code, not a value.
const SECRET_FIELD = /\b\w*(?:apikey|api_key|secret|token|password|passwd|pwd|credential|privatekey|connectionstring|accesskey)\w*\s*=\s*((?:"[^"\r\n]*"\s*\+\s*)*"[^"\r\n]*")/ig;

// A local variable assigned nothing but a string literal (`data = "…";` —
// no `const`/`static`, and often no credential-shaped NAME at all: Juliet's
// own CWE256/259 fixtures deliberately name it `data` to test detection
// independent of naming convention), where that SAME variable is later
// concatenated directly after a literal segment that itself ends in a
// credential keyword ("...;Password=" + data). SECRET_FIELD (above) only
// catches the credential NAME shape (`password = "literal"`); this catches
// the credential SINK shape — a hardcoded value reaching a password/token
// parameter through a one-hop variable copy, mirroring the same "literal
// reaches sink directly or via one-hop copy" principle already applied to
// LDAP filters (`ldap-injection.js`'s `_nearestAssignIsLiteral`).
const LITERAL_ASSIGN = /\b(\w+)\s*=\s*(?:"([^"\r\n]{6,})"|@"([^"\r\n]{6,})")\s*;/g;
const CREDENTIAL_SINK_USE = /["'][^"'\r\n]*?(?:password|passwd|pwd|secret|token|api[_-]?key|credential)\s*=\s*["']\s*\+\s*(\w+)\b/ig;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
// Join the contents of a concatenation of string literals.
function joinLiterals(expr) {
  const parts = expr.match(/"([^"]*)"/g) || [];
  return parts.map(p => p.slice(1, -1)).join('');
}
function looksLikePlaceholder(value) {
  if (/^(?:changeme|placeholder|todo|tbd|xxxxx|secret|password|your_?password)$/i.test(value)) return true;
  if (/^[A-Za-z]+$/.test(value) && value.length < 12) return true;
  return false;
}

export function scanCsharpStructural(fp, raw) {
  if (!/\.cs$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  // Hardcoded secret in a credential-named field. The joined literal value must
  // look like a real secret (length or known prefix) so header-name constants
  // (ApiKeyHeader = "X-Api-Key") are not flagged.
  let m;
  const sre = new RegExp(SECRET_FIELD.source, SECRET_FIELD.flags);
  while ((m = sre.exec(code))) {
    const value = joinLiterals(m[1]);
    if (value.length < 16 && !SECRET_PREFIX.test(value)) continue;
    const line = lineOf(code, m.index);
    push({
      id: `csharp-hardcoded-secret:${fp}:${line}`, file: fp, line,
      vuln: 'Hardcoded credential in a const/static field (C#)',
      severity: 'high', cwe: 'CWE-798', family: 'secret', parser: 'CSHARP', confidence: 0.7,
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Load the secret from the environment / a secrets manager (Environment.GetEnvironmentVariable, Azure Key Vault). Concatenating the literal to split it does not help — rotate the exposed value.',
    });
  }

  // Hardcoded literal reaching a credential-labeled sink through a one-hop
  // variable copy, SCOPED TO ONE METHOD BODY (via the shared C# IR's method
  // line ranges, not a whole-file scan). Juliet's Bad()/Good() convention
  // deliberately reuses the SAME generic variable name (`data`) across
  // sibling methods with UNRELATED meanings — a literal in Bad(), external
  // input (`Console.ReadLine()`) in GoodG2B() — so a whole-file, name-only
  // association would credit the Good() sink with the Bad() method's literal
  // (confirmed against the real corpus: CWE259_Hard_Coded_Password__
  // SqlConnection_01.cs's GoodG2B() reads `data` from the console, and a
  // whole-file version of this rule fired on its SqlConnection call anyway).
  // Scoping to one method is a deliberate precision/recall tradeoff: it
  // misses Juliet's own multi-method split (`Bad(){ data="lit"; BadSink(data); }`
  // with the sink in a separate `BadSink(string data)`), which needs real
  // interprocedural constant tracking to resolve safely, not a regex.
  let csharpIr;
  try { csharpIr = buildCSharpIR(code); } catch { csharpIr = null; }
  for (const meth of (csharpIr && csharpIr.methods) || []) {
    const startLine = meth.line, endLine = meth.endLine || meth.line;
    if (endLine < startLine) continue;
    const codeLines = code.split('\n');
    const methText = codeLines.slice(startLine - 1, endLine).join('\n');
    const literalVars = new Map();
    const lre = new RegExp(LITERAL_ASSIGN.source, LITERAL_ASSIGN.flags);
    let lm;
    while ((lm = lre.exec(methText))) {
      const value = lm[2] || lm[3] || '';
      if (looksLikePlaceholder(value)) continue;
      literalVars.set(lm[1], value);
    }
    if (!literalVars.size) continue;
    const cre = new RegExp(CREDENTIAL_SINK_USE.source, CREDENTIAL_SINK_USE.flags);
    let cm;
    while ((cm = cre.exec(methText))) {
      const varName = cm[1];
      if (!literalVars.has(varName)) continue;
      const line = startLine + lineOf(methText, cm.index) - 1;
      push({
        id: `csharp-hardcoded-secret-sink:${fp}:${line}`, file: fp, line,
        vuln: 'Hardcoded credential in a const/static field (C#)',
        severity: 'high', cwe: 'CWE-798', family: 'secret', parser: 'CSHARP', confidence: 0.65,
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Load the secret from the environment / a secrets manager (Environment.GetEnvironmentVariable, Azure Key Vault) instead of a hardcoded literal reaching a password/token parameter.',
      });
    }
  }

  // SSRF: WebClient/HttpClient fetch from a non-literal URL, unless a host
  // allow/deny guard is present.
  const SSRF_SINK = /\.(?:DownloadString|DownloadData|OpenRead|GetAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync)\s*\(\s*[A-Za-z_]\w*\s*\)/;
  const SSRF_GUARD = /169\.254\.169\.254|\.Host\b|allow(?:ed)?Hosts?|IsLoopback|deny(?:list)?|block(?:list|ed)/i;
  if (SSRF_SINK.test(code) && !SSRF_GUARD.test(code)) {
    const line = lineOf(code, code.search(SSRF_SINK));
    push({
      id: `csharp-ssrf:${fp}:${line}`, file: fp, line,
      vuln: 'SSRF — HTTP client fetch from a non-validated URL (C#)',
      severity: 'high', cwe: 'CWE-918', family: 'ssrf', parser: 'CSHARP', confidence: 0.55,
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Validate the URL host against an allow-list and reject RFC1918 / link-local / metadata (169.254.169.254) addresses before fetching.',
    });
  }

  return findings;
}
