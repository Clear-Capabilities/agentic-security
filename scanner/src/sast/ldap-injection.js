import { blankComments } from './_comment-strip.js';
// LDAP injection (CWE-90).
//
// LDAP filters use a parens/operator syntax; concatenating user input into a
// filter lets a client smuggle additional `|(|(`-style clauses that return
// records they shouldn't see, or auth-bypass via `(uid=*)(uid=admin*)`.
//
// We catch:
//   - Node ldapjs:    client.search(base, { filter: "(uid=" + name + ")" })
//   - Java JNDI:      ctx.search(base, "(cn=" + name + ")", ...)
//   - Java w/ var:    String filter = "(uid=" + name + ")"; ctx.search(base, filter);
//   - Python ldap3:   conn.search(base, "(uid=" + name + ")")
//   - Python python-ldap: conn.search_s(base, scope, "(uid=" + name + ")")
//   - Python f-strings: conn.search_s(base, scope, f"(uid={name})")
//
// We require an LDAP context hint in the file (DirContext, javax.naming,
// ldap.initialize, ldapjs, etc.) so we don't fire on every `"foo=" + bar`
// concatenation in unrelated code.

const FILTER_INLINE_RE = {
  // Filter string concatenated INSIDE the .search call.
  js:   /\bfilter\s*:\s*[`"']?\([^`"')]*\b(?:uid|cn|mail|sAMAccountName|givenName|sn|memberOf)\s*=\s*[`"']?\s*(?:\+|\$\{)/g,
  java: /\.search(?:_s)?\s*\(\s*[^,]+,\s*"[^"]*\b(?:uid|cn|mail|sAMAccountName|givenName|sn|memberOf)\s*=[^"]*"\s*\+\s*\w+/g,
  py:   /\.(?:search|search_s|search_ext|paged_search)\s*\([^)]*\b(?:uid|cn|mail|sAMAccountName|givenName|sn|memberOf)\s*=[^)]*['"]?\s*\+\s*\w+/g,
};

// Filter built in a variable then passed to .search. The signal is the
// "(<attr>= + " pattern anywhere in the file.
const FILTER_VAR_RE =
  /["'`]\s*\(\s*(?:uid|cn|mail|sAMAccountName|givenName|sn|memberOf)\s*=\s*["'`]?\s*\+\s*[A-Za-z_][\w.]*|f["']\s*\(\s*(?:uid|cn|mail|sAMAccountName|givenName|sn|memberOf)\s*=\s*\{/g;

// LDAP context hint: at least one of these must be in the file before we
// trust the variable-form heuristic.
const LDAP_HINT_RE =
  /\b(?:DirContext|javax\.naming|ldap\.initialize|ldap3|ldapjs|LdapContext|InitialDirContext|SearchResult|conn\.search|client\.search|\.search_s|getLdapTemplate)\b/;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _lang(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.java$/i.test(fp)) return 'java';
  if (/\.py$/i.test(fp)) return 'py';
  return null;
}

function _emit(fp, raw, line, why) {
  return {
    id: `ldap-injection:${fp}:${line}:${why}`,
    file: fp, line,
    vuln: 'LDAP Injection: filter string built via concatenation',
    severity: 'high',
    cwe: 'CWE-90',
    family: 'ldap-injection',
    stride: 'Tampering',
    snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
    remediation: 'Escape LDAP filter metacharacters (`*`, `(`, `)`, `\\`, NUL) before substitution, or use a parameterized API. ' +
      'Node ldapjs: `new EqualityFilter({ attribute: "uid", value: name })`. ' +
      'Java JNDI: bind via search filter args — `ctx.search(base, "(uid={0})", new Object[]{ name }, controls)`. ' +
      'Python python-ldap: `ldap.filter.escape_filter_chars(name)`. ' +
      'Python ldap3: pass the value through a Connection bind-format helper.',
    parser: 'LDAP-INJECTION',
    confidence: 0.85,
  };
}

export function scanLDAPInjection(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw, lang === 'py' ? 'py' : undefined);
  const findings = [];
  const seen = new Set();
  // Path A — concatenation inside the .search call. High-confidence,
  // doesn't need the context hint.
  {
    const re = new RegExp(FILTER_INLINE_RE[lang].source, FILTER_INLINE_RE[lang].flags);
    let m;
    while ((m = re.exec(code))) {
      const line = lineOf(raw, m.index);
      const key = `inline:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(_emit(fp, raw, line, 'inline'));
    }
  }
  // Path B — filter built into a variable then passed downstream. Lower-
  // confidence so we gate on a file-level LDAP hint to suppress unrelated
  // string concatenations.
  if (LDAP_HINT_RE.test(code)) {
    const re = new RegExp(FILTER_VAR_RE.source, FILTER_VAR_RE.flags);
    let m;
    while ((m = re.exec(code))) {
      const line = lineOf(raw, m.index);
      const key = `var:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(_emit(fp, raw, line, 'var'));
    }
  }
  return findings;
}
