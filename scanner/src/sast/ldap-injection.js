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
  //
  // SARD_80_F1 W4.C13 — this is the shape C#'s REAL Juliet corpus actually
  // uses (`search.Filter = "(...) " + data + "))";`, a property ASSIGNMENT,
  // not a call argument), confirmed via the public mirror
  // (CWE90_LDAP_Injection__Connect_tcp_01.cs) — meaning it's THIS regex,
  // not FILTER_VAR_RE.cs below, that needs the literal-suppression capture
  // group: the identical filter line appears verbatim in bad() and
  // GoodG2B(), only `data`'s source differs, same convention as every
  // other language's Path B fix. Split into two top-level alternatives
  // (concat form with a capturing group + trailing lookahead, vs.
  // interpolation form uncaptured) instead of the previous single regex
  // with an internal `"\s*\+|\{` alternation, since only the concat form's
  // trailing identifier is safely checkable this way.
  cs:   new RegExp(String.raw`\bFilter\s*=\s*\$?@?"[^"]*\(\s*` + ATTR + String.raw`\s*=[^"]*"\s*\+\s*([A-Za-z_][\w.]*)(?![\w.]*\s*\()(?=\s*(?:\+\s*["'][^"'\n]*["']\s*)?[);,])|\bFilter\s*=\s*\$?@?"[^"]*\(\s*` + ATTR + String.raw`\s*=[^"]*\{`, 'g'),
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
  // Captures the trailing identifier (group 1) so scanLdapInjection can check
  // whether it's PROVABLY a hardcoded literal — Juliet's own convention
  // (confirmed via the public mirror, CWE90_LDAP_Injection__Environment_01
  // .java) keeps the IDENTICAL `"(cn=" + data + ")"` filter line in both
  // bad() and goodG2B(), only swapping `data`'s source. The trailing
  // lookahead mirrors java-structural.js's CWE-89 fix: only a SINGLE
  // trailing term (optionally followed by one more literal segment, e.g.
  // the closing `+ ")"`) is eligible for suppression — a second variable
  // after it is left alone.
  java: new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*\+\s*([A-Za-z_][\w.]*)(?![\w.]*\s*\()(?=\s*(?:\+\s*["'][^"'\n]*["']\s*)?[);,])`, 'g'),
  py:   new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*\+\s*[A-Za-z_][\w.]*(?![\w.]*\s*\()|[fF]["']\s*\(\s*` + ATTR + String.raw`\s*=\s*\{`, 'g'),
  php:  new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*\.\s*\$[A-Za-z_]\w*`, 'g'),
  go:   new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*\+\s*[A-Za-z_][\w.]*(?![\w.]*\s*\()`, 'g'),
  // SARD_80_F1 W4.C13 — capture group added to the concat alternative
  // (mirroring `java`'s) so scanLDAPInjection can run the same
  // hardcoded-literal check; the C# public mirror confirms Juliet's
  // identical-line convention holds here too (CWE90_LDAP_Injection__
  // Connect_tcp_01.cs keeps `search.Filter = "(...employeename=" + data +
  // "))";` verbatim in both bad() and GoodG2B(), only data's source
  // differs). The interpolation alternative (`$"...{`) is left uncaptured
  // (m[1] undefined there is a no-op for `_nearestAssignIsLiteral`, which
  // returns false on a falsy varName) since Juliet's own corpus uses the
  // concat form exclusively for this shape.
  cs:   new RegExp(String.raw`["']\s*\(\s*` + ATTR + String.raw`\s*=\s*["']?\s*\+\s*([A-Za-z_][\w.]*)(?![\w.]*\s*\()(?=\s*(?:\+\s*["'][^"'\n]*["']\s*)?[);,])|\$"[^"]*\(\s*` + ATTR + String.raw`\s*=\s*\{`, 'g'),
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

// True when EVERY assignment to `varName` before `beforeIdx` (source order)
// is a plain string-literal RHS, and at least one such assignment exists.
// Same "backward assignment scan" shape as java-structural.js's
// `_trailingIdentIsLiteral` (itself modeled on java-bench-extras.js's
// CWE-259 check) — duplicated rather than imported, matching this
// codebase's established per-module convention for this small a helper.
//
// SARD_80_F1 W4.C13 — this USED to check only the TEXTUALLY NEAREST
// assignment, which is wrong for an if/else where each branch assigns the
// same variable: `if (cond) data = Environment.GetEnvironmentVariable(...);
// else data = "foo";` has its literal assignment (the else branch) textually
// LAST, so the old "nearest" check wrongly concluded `data` was provably a
// literal and suppressed a REAL vulnerability — found via a real corpus
// regression during THIS EXACT fix's own verification (C# CWE90_LDAP_
// Injection__Environment_12.cs's Bad() lost its true positive). Checking
// EVERY preceding assignment (failing closed the moment any one of them is
// non-literal) fixes that — but naively scanning the WHOLE FILE for prior
// assignments introduced a SECOND regression the same verification pass
// caught: Juliet's universal convention re-declares the source variable
// FRESH in every method (`string data;` in Bad(), a completely separate
// `string data;` in GoodG2B()), so a same-named variable in an EARLIER
// method (e.g. Bad()'s own non-literal source assignment) would incorrectly
// poison GoodG2B()'s own all-literal check. Scoping the scan to start at
// the variable's most recent DECLARATION before `beforeIdx` (a `Type
// varName;` or `Type varName = …;` statement) fixes both at once: within
// one method's scope, every assignment must be literal (catches the
// if/else case); across method boundaries, each method's own `data` is
// scanned independently (catches the cross-method case). Falls back to
// scanning from file-start when no declaration is found — strictly SAFER
// than before (fewer assignments end up in scope, never more).
// SARD_80_F1 W4.C17 — a bare-identifier RHS (`data = dataCopy;`) previously
// failed this check outright, even when `dataCopy` was itself provably a
// literal at that point — confirmed on the real corpus (C# Juliet's own
// "make a copy of data within the same method" flow variant,
// CWE90_LDAP_Injection__Environment_31.cs: GoodG2B() sets `data = "foo"` in
// one block, copies it to `dataCopy`, then re-declares `data = dataCopy` in
// a SECOND block before the sink — the one-hop copy defeated the
// literal-RHS check, which only recognized a DIRECT `"literal"` string).
// Now recurses ONE LEVEL (capped, cycle-guarded via `rhs !== varName`) into
// a bare-identifier RHS, applying the exact same fail-closed "every
// assignment must be literal" policy to the copied-from variable — this can
// only ADD suppression where the old code returned false, never introduce a
// new false negative the old code didn't already risk (a genuinely tainted
// `dataCopy` still fails its own scan and propagates the non-literal verdict
// back up).
function _nearestAssignIsLiteral(code, varName, beforeIdx, _depth) {
  if (!varName || varName.includes('.')) return false;
  const depth = _depth || 0;
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const declRe = new RegExp(`\\b[\\w<>[\\],.?]+\\s+${escaped}\\s*(?:=|;)`, 'g');
  let scopeStart = 0, dm;
  while ((dm = declRe.exec(code)) && dm.index < beforeIdx) scopeStart = dm.index;
  const anyAssignRe = new RegExp(`\\b${escaped}\\s*=\\s*([^;]+);`, 'g');
  anyAssignRe.lastIndex = scopeStart;
  const literalRhsRe = /^"[^"]*"$/;
  const bareIdentRe = /^[A-Za-z_]\w*$/;
  let sawAny = false, m;
  while ((m = anyAssignRe.exec(code)) && m.index < beforeIdx) {
    sawAny = true;
    const rhs = m[1].trim();
    if (literalRhsRe.test(rhs)) continue;
    // SARD_80_F1 W4.C37 — `null` is never attacker-controlled data (it is
    // the ABSENCE of a value, not a value), so an assignment of `data =
    // null;` can never make a later sink call injectable — treating it as a
    // disqualifying non-literal was always wrong, independent of any dead-
    // code/control-flow question. This exact shape is Juliet's own "if
    // (CONST) { data = <literal-or-source> } else { data = null; }" dead-
    // code idiom (confirmed via the public C# Juliet mirror's own
    // CWE90_LDAP_Injection__Connect_tcp_04.cs), but the fix is sound as a
    // general rule, not merely a benchmark-shape accommodation: BEFORE
    // this fix, `_nearestAssignIsLiteral` recursed into "null" as if it
    // might be a traceable bare-identifier variable (`bareIdentRe` matches
    // it — "null" is alphabetic), found no declaration or assignment for a
    // variable literally named `null`, and returned `false` from that dead
    // end — which then disqualified the WHOLE candidate as "not provably
    // literal" even when every OTHER real assignment was a hardcoded
    // literal. This bug PRE-DATES and is INDEPENDENT of this session's
    // parser-cs.js CFG work (confirmed via a direct, standalone call to
    // `scanLDAPInjection` bypassing runScan/parser-cs.js entirely) — it was
    // simply never exercised on a real corpus file until an unrelated CFG
    // fix elsewhere changed which findings survive `engine.js`'s own
    // downstream dedup, surfacing it. Skipping (not disqualifying, not
    // affirming) a `null` RHS can only ever ADD suppression where the old
    // code returned false, never remove a genuine tainted-source detection
    // — a real source assignment (`data = sr.ReadLine();`, `data =
    // Environment.GetEnvironmentVariable(...)`) is never itself `null`.
    if (rhs === 'null') continue;
    if (depth < 3 && rhs !== varName && bareIdentRe.test(rhs) && _nearestAssignIsLiteral(code, rhs, m.index, depth + 1)) continue;
    return false;
  }
  return sawAny;
}
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
      // SARD_80_F1 W4.C13 — C#'s DirectorySearcher.Filter shape goes
      // through THIS path (a property assignment), not FILTER_VAR_RE, so
      // the hardcoded-literal check belongs here for `cs`.
      if (lang === 'cs' && _nearestAssignIsLiteral(code, m[1], m.index)) continue;
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
      if ((lang === 'java' || lang === 'cs') && _nearestAssignIsLiteral(code, m[1], m.index)) continue;
      const line = lineOf(raw, m.index);
      const key = `var:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(_emit(fp, raw, line, 'var'));
    }
  }
  return findings;
}
