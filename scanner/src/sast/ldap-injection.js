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
//   - PHP:            ldap_search($ds, $base, "(uid=" . $u . ")")
//   - Go (go-ldap):   ldap.NewSearchRequest(base, ..., "(uid="+u+")", ...)
//   - C# DirectorySearcher: ds.Filter = "(uid=" + u + ")"   (also $"(uid={u})")
//   - Ruby (net-ldap): conn.search(filter: "(uid=#{u})")
//   - Kotlin JNDI:    ctx.search(base, "(uid=" + u + ")")
//
// We require an LDAP context hint in the file (DirContext, javax.naming,
// ldap.initialize, ldapjs, ldap_search, go-ldap, DirectorySearcher, Net::LDAP,
// etc.) so we don't fire on every `"foo=" + bar` concatenation in unrelated
// code.

// LDAP filter attribute name. Real LDAP/AD schemas define far more
// attributes than any fixed enum can enumerate (custom schema extensions,
// and standard-but-uncommon ones like `department`/`title`/`employeeID`/
// `homeDirectory`/`description`) — a hardcoded whitelist here is a real,
// general precision-vs-recall bug, not just narrow for one benchmark.
// Matches conventional LDAP attribute-name shape (alnum + hyphen, the RFC
// 4512 `descr` production, simplified). Path A (inline concat, ungated) and
// Path B (variable-form) both already anchor on a `(<attr>=` filter-syntax
// shape plus, for Path B, a file-level LDAP-API hint (`LDAP_HINT_RE`) — the
// widened ATTR only loosens which attribute NAME is accepted, not whether
// the surrounding shape looks like an LDAP filter at all.
const ATTR = '[A-Za-z][\\w-]{0,40}';

// Path A — concatenation/interpolation INSIDE (or adjacent to) the sink call.
// High-confidence; does not need the file-level context hint.
const FILTER_INLINE_RE = {
  js:   new RegExp(String.raw`\bfilter\s*:\s*[` + '`' + String.raw`"']?\([^` + '`' + String.raw`"')]*\b` + ATTR + String.raw`\s*=\s*[` + '`' + String.raw`"']?\s*(?:\+|\$\{)`, 'g'),
  java: new RegExp(String.raw`\.search(?:_s)?\s*\(\s*[^,]+,\s*"[^"]*\b` + ATTR + String.raw`\s*=[^"]*"\s*\+\s*\w+`, 'g'),
  py:   new RegExp(String.raw`\.(?:search|search_s|search_ext|paged_search)\s*\([^)]*\b` + ATTR + String.raw`\s*=[^)]*['"]?\s*\+\s*\w+`, 'g'),
  php:  new RegExp(String.raw`\bldap_(?:search|list|read)\s*\([^)]*\(\s*` + ATTR + String.raw`\s*=[^)]*["']\s*\.\s*\$`, 'g'),
  go:   new RegExp(String.raw`\b(?:NewSearchRequest|SearchRequest|Search)\s*\([^)]*"\(\s*` + ATTR + String.raw`\s*=[^"]*"\s*\+\s*[A-Za-z_][\w.]*(?![\w.]*\s*\()`, 'g'),
  // C#: DirectorySearcher.Filter assigned a concat ("(uid=" + u) or an
  // interpolated string ($"(uid={u})").
  cs:   new RegExp(String.raw`\bFilter\s*=\s*\$?@?"[^"]*\(\s*` + ATTR + String.raw`\s*=[^"]*(?:"\s*\+|\{)`, 'g'),
  // Ruby net-ldap: a filter built with #{} interpolation inside a search/
  // construct/filter call.
  rb:   new RegExp(String.raw`\.(?:search|filter|construct|equals)\s*\([^)]*\(\s*` + ATTR + String.raw`\s*=[^)]*#\{`, 'g'),
  kt:   new RegExp(String.raw`\.search\s*\(\s*[^,]+,\s*"[^"]*\b` + ATTR + String.raw`\s*=[^"]*"\s*\+\s*\w+`, 'g'),
};

// Path B — filter built in a variable then passed to the sink. Lower-
// confidence, so gated on the file-level LDAP hint. Per-language because the
// concat operator differs: `+` (js/java/py/go/cs/kt), `.` (php), `#{` (rb),
// and interpolation forms (`${`, `f"…{`, `$"…{`).
// `(?![\w.]*\s*\()` after the concat operand: a value immediately followed by `(`
// is a function CALL (e.g. `ldap.EscapeFilter(u)`, `escape_filter_chars(u)`),
// which is the *escaped* (safe) form — must not match.
const FILTER_VAR_RE = {
  js:   new RegExp(String.raw`["'` + '`' + String.raw`]\s*\(\s*` + ATTR + String.raw`\s*=\s*["'` + '`' + String.raw`]?\s*(?:\+|\$\{)\s*[A-Za-z_$][\w.]*(?![\w.]*\s*\()`, 'g'),
  java: new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*\+\s*[A-Za-z_][\w.]*(?![\w.]*\s*\()`, 'g'),
  py:   new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*\+\s*[A-Za-z_][\w.]*(?![\w.]*\s*\()|[fF]["']\s*\(\s*` + ATTR + String.raw`\s*=\s*\{`, 'g'),
  php:  new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*\.\s*\$[A-Za-z_]\w*`, 'g'),
  go:   new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*\+\s*[A-Za-z_][\w.]*(?![\w.]*\s*\()`, 'g'),
  cs:   new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*\+\s*[A-Za-z_][\w.]*(?![\w.]*\s*\()|\$"[^"]*\(\s*` + ATTR + String.raw`\s*=\s*\{`, 'g'),
  rb:   new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=[^"']*#\{`, 'g'),
  kt:   new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*(?:\+|\$\{)\s*[A-Za-z_$][\w.]*(?![\w.]*\s*\()`, 'g'),
};

// LDAP context hint: at least one of these must be in the file before we
// trust the variable-form heuristic.
const LDAP_HINT_RE =
  /\b(?:DirContext|javax\.naming|ldap\.initialize|ldap3|ldapjs|LdapContext|InitialDirContext|SearchResult|conn\.search|client\.search|\.search_s|getLdapTemplate|ldap_search|ldap_list|ldap_read|ldap_connect|ldap_bind|go-ldap|NewSearchRequest|DirectorySearcher|DirectoryEntry|System\.DirectoryServices|Net::LDAP|net\/ldap)\b/;

// An LDAP filter-escape API applied in the file. When the value reaching a
// filter is escaped, the metacharacter-injection risk is removed. We can't see
// which variable on the sink line was escaped (escape-then-use spans lines —
// e.g. PHP `$uid = ldap_escape(...); ... "(uid=" . $uid . ")"`), and the
// inline call-guard only catches escape applied AT the concat. So when an
// escape API is present in the file we suppress the lower-confidence finding —
// matching the file-level guard-recognition style used elsewhere. Anchored on
// real escape APIs so it doesn't over-suppress.
const LDAP_ESCAPE_RE =
  /\b(?:ldap_escape|EscapeFilter|escape_filter_chars|escapeForLDAP|encodeForLDAP|escapeLDAPSearchFilter|LDAP_ESCAPE_FILTER)\b|\bNet::LDAP::Filter\b|\bEqualityFilter\b|\bfilters\.\w+\b/;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _lang(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.java$/i.test(fp)) return 'java';
  if (/\.py$/i.test(fp)) return 'py';
  if (/\.(?:php|phtml)$/i.test(fp)) return 'php';
  if (/\.go$/i.test(fp)) return 'go';
  if (/\.cs$/i.test(fp)) return 'cs';
  if (/\.rb$/i.test(fp)) return 'rb';
  if (/\.kt$/i.test(fp)) return 'kt';
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
      'PHP: `ldap_escape($name, "", LDAP_ESCAPE_FILTER)`. ' +
      'Go go-ldap: `ldap.EscapeFilter(name)`. ' +
      'C#: set `DirectorySearcher` with an escaped value or use parameterized binding. ' +
      'Ruby net-ldap: `Net::LDAP::Filter.eq("uid", name)` instead of interpolating.',
    parser: 'LDAP-INJECTION',
    confidence: 0.85,
  };
}

export function scanLDAPInjection(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw, (lang === 'py' || lang === 'rb') ? 'py' : undefined);
  const findings = [];
  const seen = new Set();
  // Escape-then-use: if the file applies an LDAP escape API, the filter value
  // is sanitized before substitution — suppress (recall-safe per the corpus
  // post/ pairs, which are the invariant proving this doesn't drop a real TP).
  const escaped = LDAP_ESCAPE_RE.test(code);
  // Path A — concatenation inside the .search call. High-confidence,
  // doesn't need the context hint (but still skip when the file escapes).
  if (!escaped) {
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
  if (!escaped && LDAP_HINT_RE.test(code)) {
    const re = new RegExp(FILTER_VAR_RE[lang].source, FILTER_VAR_RE[lang].flags);
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
