// Authorization check that does not dominate the action it protects: CWE-863.
//
// CWE-863 (Incorrect Authorization), not CWE-862 (Missing Authorization): the handler DOES perform a check, and performs it
// incorrectly, on some paths only. CWE-862 is for a handler with no check at all. Reported as 862 until 0.218.0.
//
// THE SHAPE (Python). A handler checks the caller's permission on an object, but the check sits inside a branch on a property of the
// DATA (a plugin flag, a format, a content type), and the action on the object runs after that branch on every path:
//
//     if exporter.needs_secret:            # data property, not the caller's identity
//         if not perm.can():               # the only permission check
//             return {"message": "forbidden"}, 403
//     result = exporter.run(record.body, record.secret)   # runs whether or not the check ran
//
// When the data takes the other branch, nothing checks the caller at all. The fix moves the check out of the branch so it guards the
// action on every path.
//
// WHAT MUST BE TRUE TO REPORT.
//   1. A denial guard: `if not <check>(...)` whose block returns a 401/403, aborts with one, or raises a permission error, where the
//      check is authorization-shaped (`.can()`, `has_permission`, `is_authorized`, `check_permission`, ...).
//   2. An enclosing `if` (between the guard and the function) whose condition reads an attribute or key of an object and says nothing
//      about who the caller is (no user, role, permission, owner, admin, auth or request-method words), and that has no `else`/`elif`
//      that could carry its own check.
//   3. After that branch, at its own indentation, the function calls something with an object the guard's block also mentions.
// Deliberately not modelled: brace languages (none seen yet on real code), checks in decorators, and dominance across functions.

const FILE_RE = /\.py$/i;
const PREFILTER = /\b(?:403|abort|Forbidden|PermissionDenied|Unauthori[sz]ed|NotAuthori[sz]ed)/;

const CHECK_CALL = /\bif\s+not\s+[\w.\[\]"']*?\b(?:can|allowed|has_perm|has_perms|has_permission|has_access|is_authori[sz]ed|is_allowed|check_permission|check_access|user_can|permitted)\s*\(/;
const DENIAL = /\b(?:401|403)\b|abort\s*\(\s*40[13]|raise\s+\w*(?:Forbidden|PermissionDenied|Unauthori[sz]ed|NotAuthori[sz]ed|AccessDenied)\w*/;
const IDENTITY = /\b(?:user|users|current_user|role|roles|permission|permissions|owner|admin|is_admin|auth\w*|identity|principal|session|request\.method|method|is_staff|is_superuser|creator|member|group)\b/i;

const indentOf = (s) => (s.match(/^[ \t]*/) || [''])[0].length;
const isBlank = (s) => !s.trim();

/** End (exclusive) of the block opened by the header at line `h`. */
function blockEnd(lines, h, limit) {
  const ind = indentOf(lines[h]);
  let e = h + 1;
  while (e < limit && (isBlank(lines[e]) || indentOf(lines[e]) > ind)) e++;
  return e;
}

const isTest = (f) => /(?:^|\/)(?:tests?|specs?)\//.test(f) || /(?:^|\/)test_[^/]*\.py$/.test(f) || /_test\.py$/.test(f);

export function scanNondominatingAuthzCheck(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || !PREFILTER.test(code) || isTest(file)) return [];
  const lines = code.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!CHECK_CALL.test(lines[i])) continue;
    const gEnd = blockEnd(lines, i, lines.length);
    const gBody = lines.slice(i + 1, gEnd).join('\n');
    if (!DENIAL.test(gBody)) continue;
    // Walk the enclosing headers up to the function definition.
    let cur = indentOf(lines[i]);
    let fnStart = -1; let fnInd = 0;
    const headers = [];
    for (let k = i - 1; k >= 0; k--) {
      if (isBlank(lines[k]) || indentOf(lines[k]) >= cur) continue;
      cur = indentOf(lines[k]);
      if (/^\s*(?:async\s+)?def\s/.test(lines[k])) { fnStart = k; fnInd = cur; break; }
      headers.push(k);
      if (cur === 0) break;
    }
    if (fnStart < 0) continue;
    const fnEnd = blockEnd(lines, fnStart, lines.length);
    // The object(s) the check is about: names the region from the outermost data branch to the denial mentions.
    for (const h of headers) {
      const t = lines[h];
      const cond = (t.match(/^\s*if\s+(.+?):\s*$/) || [])[1];
      if (!cond) continue;
      if (IDENTITY.test(cond)) continue;
      if (!/[\w)\]]\s*(?:\.\s*\w|\[)/.test(cond)) continue;          // reads a property of something
      const hEnd = blockEnd(lines, h, fnEnd);
      // An else/elif can carry its own check: leave that alone.
      let n = hEnd; while (n < fnEnd && isBlank(lines[n])) n++;
      if (n < fnEnd && indentOf(lines[n]) === indentOf(t) && /^\s*(?:else|elif)\b/.test(lines[n])) continue;
      // The branch must not end every path itself (a branch that returns is a different shape).
      const region = lines.slice(h, gEnd).join('\n');
      // The protected data: attributes the branch reads (`record.secret`), minus the ones that describe who owns it.
      const attrs = new Set([...region.matchAll(/\b([a-z_]\w*)\s*\.\s*([a-z_]\w*)\b(?!\s*\()/g)]
        .filter((x) => !['self', 'g', 'request', 'data', 'dict', 'x', 'log', 'logger'].includes(x[1]) && !IDENTITY.test(x[2]))
        .map((x) => `${x[1]}.${x[2]}`));
      if (!attrs.size) continue;
      // An action after the branch, at the branch's own level, that passes that same data to a call.
      for (let r = hEnd; r < fnEnd; r++) {
        if (isBlank(lines[r]) || indentOf(lines[r]) !== indentOf(t)) continue;
        const call = lines.slice(r, Math.min(fnEnd, r + 4)).join(' ');
        if (/^\s*(?:return\s+(?:dict|\{|\()|raise\b)/.test(lines[r])) break;
        if (!/\w\s*\(/.test(call)) continue;
        const used = [...attrs].find((a) => new RegExp(`\\b${a.replace('.', '\\s*\\.\\s*')}\\b(?!\\s*\\()`).test(call));
        if (!used) continue;
        out.push({
          id: `nondominating-authz-check:${file}:${i + 1}`,
          file, line: i + 1,
          vuln: 'Authorization check runs only on one branch; the action it protects runs on every path',
          severity: 'high',
          cwe: 'CWE-863',
          family: 'broken-access-control',
          stride: 'Elevation of Privilege',
          description: `The permission check at line ${i + 1} only runs when \`${cond.trim()}\` (line ${h + 1}) holds, a property of the data rather than of the caller. Line ${r + 1} acts on \`${used}\` after that branch on every path, so when the data takes the other branch the action runs with no permission check at all.`,
          remediation: 'Move the permission check out of the data branch so it runs before the action on every path, and keep the branch only for what genuinely depends on the data.',
          snippet: lines[i].trim().slice(0, 200),
          parser: 'AUTHZ-DOMINANCE',
          confidence: 0.55,
        });
        break;
      }
      break;
    }
  }
  return out;
}
