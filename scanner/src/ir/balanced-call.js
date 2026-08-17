// Shared by every hand-rolled regex IR parser (parser-cs.js, parser-go.js,
// parser-php.js, parser-rb.js) for extracting a call's callee + argument
// text without corruption when the call is followed by a chained member
// access (`Sanitize(x).Trim()`, `$obj->clean($x)->trim()`).
//
// The naive pattern every one of those files used —
// `/^(calleeRe)\s*\((.*)\)\s*$/s` — matches `(.*)` GREEDILY against the
// LAST `)` in the string, not the one balancing the FIRST `(`. For a
// chained call that swallows the chain's own parens into the argument
// text (`Sanitize(x).Trim()` produced argsText = "x).Trim("), which then
// fails to parse as any recognized expression shape in `_lowerExpr` and
// falls through to `{kind:'unknown'}` — silently losing whatever
// taint-relevant identifiers were inside the FIRST call's real argument
// list, exactly the shape a wrapped-and-then-methodcalled sanitizer or
// helper produces in real code.
//
// This scans forward from the first `(` tracking paren/bracket/brace
// depth and string-literal state (so a `)` or `,` inside a nested call or
// a string literal doesn't miscount) to find the REAL matching close
// paren. It deliberately does NOT require that close paren to be the end
// of the string — a trailing chain (`.Trim()`, `->trim()`, `::foo()`) is
// simply left unconsumed rather than corrupting anything. Recovering the
// first call's real signature is a strict improvement over the prior
// choice between silent corruption and no match at all.
export function matchBalancedCall(s, calleeRe) {
  if (typeof s !== 'string') return null;
  const m = calleeRe.exec(s);
  if (!m || m.index !== 0) return null;
  let i = m[0].length;
  while (s[i] === ' ' || s[i] === '\t') i++;
  if (s[i] !== '(') return null;
  const openIdx = i;
  let depth = 0;
  let inStr = null;
  let escape = false;
  for (; i < s.length; i++) {
    const c = s[i];
    if (escape) { escape = false; continue; }
    if (inStr) {
      if (c === '\\') { escape = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; continue; }
    if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) break;
      continue;
    }
  }
  if (depth !== 0 || s[i] !== ')') return null; // unbalanced — refuse to guess
  const callee = m[1] !== undefined ? m[1] : m[0];
  // Taint-recall PRD (80%): `endIdx` (the index right after the matched
  // closing paren) lets a caller detect and recurse into a CHAINED
  // continuation (`X(args).Y(args2)`) instead of silently leaving it
  // unconsumed. Additive — existing callers that only destructure
  // {callee, argsText} are unaffected. Confirmed via real corpus fixtures
  // that the outer call in a chain is frequently the one carrying the
  // actual sink and its tainted argument (`new DataTable().Compute(expr)`,
  // `template.New("page").Parse(userTemplate)`,
  // `w.Header().Set("X", tainted)`) — silently dropping it, not just
  // leaving it unconsumed, is what this field exists to let callers fix.
  return { callee, argsText: s.slice(openIdx + 1, i), endIdx: i + 1 };
}
