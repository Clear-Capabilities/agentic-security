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
export function matchBalancedCall(s, calleeRe, opts) {
  if (typeof s !== 'string') return null;
  const m = calleeRe.exec(s);
  if (!m || m.index !== 0) return null;
  let i = m[0].length;
  while (s[i] === ' ' || s[i] === '\t') i++;
  // SARD_80_F1 W2.3 follow-up (opt-in via `opts.skipGenerics`, used only by
  // parser-cs.js): C#'s `new List<string>()` / `new Dictionary<string,
  // int>()` has a generic type-argument list BETWEEN the class name and the
  // constructor's own `(`. Without this, `new\s+([\w.]+)` matches only
  // "List", the character right after it is `<` (not `(`), and the whole
  // match fails — the constructor call silently lowers to `{kind:'unknown'}`
  // instead of a proper `isNew:true` call, which is why `List<T>` (C#'s
  // dominant MODERN collection idiom, unlike the non-generic `ArrayList`
  // fixed alongside this) never even reached the collection-taint mutator
  // rule at all. Deliberately opt-in, not the default: `<`/`>` are also
  // comparison operators, and Go/PHP/Ruby (this helper's other three
  // callers) have no equivalent "generic-args-before-a-call" shape, so
  // widening the default here would be pure unvalidated risk for them.
  // Scans for BALANCED angle brackets only (handles nested generics like
  // `Dictionary<string, List<int>>`); if it doesn't find a clean balanced
  // `<...>` immediately here, this leaves `i` untouched and falls through
  // to the ordinary `(`-required check below, same as before this existed.
  if (opts && opts.skipGenerics && s[i] === '<') {
    let j = i + 1;
    let depth = 1;
    while (j < s.length && depth > 0) {
      if (s[j] === '<') depth++;
      else if (s[j] === '>') depth--;
      else if (s[j] === '(' || s[j] === ')' || s[j] === ';') { depth = -1; break; } // not a generic-args list — bail
      j++;
    }
    if (depth === 0) {
      let k = j;
      while (s[k] === ' ' || s[k] === '\t') k++;
      if (s[k] === '(') i = k;
    }
  }
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
