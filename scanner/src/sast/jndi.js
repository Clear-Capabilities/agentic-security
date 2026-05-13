// JNDI injection (Log4Shell family) detection for Java.
//
// Vulnerable patterns:
//   - InitialContext.lookup(<varname>)              direct JNDI lookup w/ tainted name
//   - jndiTemplate.lookup(<varname>)                Spring's JndiTemplate.lookup
//   - new InitialDirContext().lookup(<varname>)
//   - ${jndi:...} string format / log4j pattern     hardcoded jndi: in logger calls
//   - Context.lookup(<varname>)                     generic javax.naming.Context
//
// Safe shapes:
//   - lookup() called with a string literal (jndi:ldap://localhost/...) is
//     still flagged because hardcoded jndi protocol use is itself unusual and
//     should be reviewed. We flag literal lookups at lower severity (medium)
//     vs variable lookups (high → critical when on log path).

const JNDI_LOOKUP_VAR_RE = /\b(?:(?:Initial(?:Dir)?Context|InitialLdapContext|jndiTemplate|JndiTemplate|context|ctx|namingContext|namingEnumeration)\s*\.\s*lookup\s*\(\s*([a-zA-Z_$][\w$.]*)\s*\))/g;
const JNDI_LOOKUP_LITERAL_RE = /\b(?:(?:Initial(?:Dir)?Context|InitialLdapContext|jndiTemplate|JndiTemplate|context|ctx)\s*\.\s*lookup\s*\(\s*["'](?:jndi:|ldap:|rmi:|dns:|iiop:|corbaname:)[^"']*["']\s*\))/gi;
// Log4j / SLF4J-style logger call where one of the args contains "${jndi:" — a
// post-Log4Shell self-recognition tell. Modern Log4j 2.17+ has neutralized
// JndiLookup, but ${jndi:...} hardcoded in logs is still a tell of test/POC
// code that should not ship.
const LOG4J_JNDI_RE = /\b(?:log(?:ger)?|LOG|LOGGER)\s*\.\s*(?:trace|debug|info|warn|error|fatal)\s*\(\s*["'`][^"'`]*\$\{jndi:[^"'`]*["'`]/gi;
// Method that builds a JNDI URI from user-controlled input — narrow shape:
// "jndi:..." or "ldap://" with string concatenation/interpolation of a request
// variable.
const JNDI_URI_BUILD_RE = /["'`](?:jndi:|ldap:\/\/|rmi:\/\/|dns:\/\/)[^"'`]*["'`]\s*\+\s*(?:req\.|request\.|params|query|body|input|user)/g;

import { blankComments } from './_comment-strip.js';

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanJNDI(fp, raw) {
  if (!/\.(?:java|kt|kts|scala|groovy|gradle)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const findings = [];
  const code = blankComments(raw);
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  let m;
  const varRe = new RegExp(JNDI_LOOKUP_VAR_RE.source, JNDI_LOOKUP_VAR_RE.flags);
  while ((m = varRe.exec(code))) {
    // Skip if the captured argument is literally a constant-looking identifier
    // declared as a string literal in the file (best-effort).
    const arg = m[1];
    // Heuristic: if the same line is also matched by the LITERAL regex, skip here.
    const lineStart = code.lastIndexOf('\n', m.index) + 1;
    const lineEnd = code.indexOf('\n', m.index);
    const ln = code.substring(lineStart, lineEnd === -1 ? code.length : lineEnd);
    if (/lookup\s*\(\s*["']/.test(ln)) continue;
    const line = _lineOf(raw, m.index);
    push({
      id: `jndi:${fp}:${line}:var`,
      file: fp, line,
      vuln: 'JNDI Injection: lookup() with variable argument (RCE)',
      severity: 'critical',
      cwe: 'CWE-917',
      stride: 'Elevation of Privilege',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: `JNDI lookup with a variable name is the Log4Shell-class vulnerability — an attacker controlling the lookup string can fetch a remote class file and run arbitrary code. Either (a) refuse lookups with non-allowlisted names, or (b) restrict the JNDI environment by setting com.sun.jndi.ldap.object.trustURLCodebase=false and com.sun.jndi.rmi.object.trustURLCodebase=false at startup. Best practice: replace JNDI with a static dependency-injection registry.`,
      confidence: 0.85,
      parser: 'JNDI',
      args: arg,
    });
  }

  // log4j-style ${jndi:...} literal in logger calls
  const log4Re = new RegExp(LOG4J_JNDI_RE.source, LOG4J_JNDI_RE.flags);
  while ((m = log4Re.exec(code))) {
    const line = _lineOf(raw, m.index);
    push({
      id: `jndi:${fp}:${line}:log4shell`,
      file: fp, line,
      vuln: 'JNDI Injection: ${jndi:...} pattern in logger call (Log4Shell test/POC)',
      severity: 'high',
      cwe: 'CWE-917',
      stride: 'Elevation of Privilege',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Remove hardcoded ${jndi:...} payloads from log statements. If this is test code, gate it behind a test profile and never let it reach production logs. Verify the runtime is Log4j 2.17.1+ (or the JndiLookup class is removed from the jar).',
      confidence: 0.9,
      parser: 'JNDI',
    });
  }

  // jndi:/ldap://... + user input concatenation
  const uriRe = new RegExp(JNDI_URI_BUILD_RE.source, JNDI_URI_BUILD_RE.flags);
  while ((m = uriRe.exec(code))) {
    const line = _lineOf(raw, m.index);
    push({
      id: `jndi:${fp}:${line}:uri-build`,
      file: fp, line,
      vuln: 'JNDI Injection: jndi:/ldap:// URI built from request input',
      severity: 'critical',
      cwe: 'CWE-917',
      stride: 'Elevation of Privilege',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Never construct a JNDI URI with user-controlled segments. If you must accept a hostname, restrict to an allowlist of fully-qualified internal names and reject anything containing `..`, `@`, or non-IDN characters.',
      confidence: 0.85,
      parser: 'JNDI',
    });
  }

  return findings;
}
