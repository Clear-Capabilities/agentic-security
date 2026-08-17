// PHP IR frontend.
//
// Regex-based, follows the parser-cs.js / parser-go.js pattern. Focused on
// PDO, mysqli, Laravel DB facade, and PHP superglobal taint surface.
//
// What we model:
//   - function / method declarations
//   - $var = expr assignments
//   - function calls and method calls ($obj->method(args))
//   - return
//   - foreach as loop-header + assign
//   - PHP superglobals ($_GET, $_POST, $_REQUEST, etc.) as ident sources
//   - control flow (R8): `if`/`else`/`while`/`foreach`/`try`/`catch`/
//     `finally`/`switch` bodies are recursed into — the statement splitter
//     now flushes on a closing `}` (see the `}`-flush comment near
//     `_splitStatements` below) instead of only on `;`, so a sink nested
//     inside a braced control-flow body is reachable rather than being
//     dropped or folded into a bogus call node. This took three fix rounds
//     to get line-number-exact (see the PRD R8 status entry in
//     `docs/DETECTION_GAP_REMEDIATION_PRD.md` for the full history) — the
//     CFG shape itself was correct from the first round. NOTE: C-style
//     `for` is deliberately NOT in this list — PHP has no `for`-loop
//     recognizer at all (never in R8's scope, still true today); a sink
//     inside `for ($i=0; $i<3; $i++) { ... }` still folds into a bogus
//     `call:for` node and is lost entirely, the exact failure mode R8
//     exists to fix, unfixed for this one construct.
//
// What we do NOT model:
//   - arrow functions (fn($x) => expr)
//   - traits / interfaces
//   - anonymous classes
//   - C-style `for` loops (see the note above — no recognizer exists)
//   - the PHP 8 `match` expression (analogous gap to Java's arrow-form
//     `switch` — this is the one modern control-flow SHAPE R8 did not
//     cover, as opposed to the R8 fix's own scope, which is bodies of
//     control-flow statements PHP already recognized)
//   - `elseif`/`else if` chains (pre-existing, not touched by R8)
//   - `if`/`else`'s pre-existing greedy-capture-group bug: the then-body
//     capture group unconditionally swallows through to the else-body's
//     own closing `}`, dropping the else-body's first statement
//     (pre-existing, confirmed present before R8, not fixed by it)

import * as crypto from 'node:crypto';
import { callSitesFromCfg } from './call-sites.js';
import { matchBalancedCall } from './balanced-call.js';

const FUNC_RE = new RegExp(
  '(?:^|[\\n;{}]|<\\?php|<\\?)\\s*' +
  '(?:(?:public|private|protected|static|abstract|final)\\s+)*' +
  'function\\s+' +
  '([A-Za-z_]\\w*)' +                  // function name (g1)
  '\\s*\\(([^)]*)\\)' +                // params (g2)
  '(?:\\s*:\\s*\\??[A-Za-z_]\\w*)?' +   // optional return type
  '\\s*\\{', 'g');

// Returns `{ text, line }[]` — `line` is the 1-indexed line, relative to the
// START of `body`, of the first non-whitespace character of that statement.
// This is computed from the ACTUAL scan position (a running `curLine`
// incremented on every physical `\n` encountered, including ones skipped
// inside a `//` comment) rather than by re-counting newlines inside the
// already-trimmed statement text afterwards — that reconstruction is lossy:
// `.trim()` discards any leading blank lines (or blanked-out characters —
// see parser-php.js's `_blankSpans`/`_buildCfg` module-level lowering) before
// a statement's real content, so a caller that tried to recover the line by
// counting embedded newlines would silently undercount by exactly the
// number of blank lines that preceded the statement. This was the root
// cause of PHP module-level findings reporting the wrong line and, in turn,
// making the line-scoped `agentic-security-ignore` suppression pragma inert
// for them (Finding 2 of the R14(b) final whole-branch review).
// True when the next non-whitespace, non-comment token starting at
// `body[i + 1]` is one of the `else`/`catch`/`finally` continuation
// keywords — the ones that must stay glued to a preceding `}` rather than
// starting a new split entry (see the R8 comment at the `}`-flush call
// site below). Both whitespace AND comments (`//` and `/* */`) are
// skipped, mirroring `_splitStatements`' own comment-skip logic.
//
// R8 fix round 3: whitespace-only skipping was a real regression this
// task introduced (not a pre-existing limitation, as an earlier version of
// this comment incorrectly claimed). `} /* mid */ else { ... }` or
// `}\n// explain\nelse { ... }` are unremarkable, real PHP shapes — a
// comment explaining WHY an else/catch/finally branch exists is a normal
// thing to write immediately above it. With whitespace-only skipping, the
// comment defeated the lookahead, the `}`-flush fired anyway, and the
// entire `else`/`catch`/`finally` body was silently dropped from the CFG.
// For `catch`/`finally` specifically this is confirmed a clean, provable
// fix (see the `catch`/`finally` regression tests in
// `test/parser-php-control-flow.test.js`, which fail without this change
// and pass with it) — `_scanTryCatchFinally`'s balanced-brace scanning has
// no competing bug to interact with. For `else` specifically, this
// lookahead fix is still correct and necessary, but its OUTCOME is masked
// in practice by `ifMatch`'s own separate, pre-existing, out-of-scope
// greedy-capture bug (the then-body group unconditionally swallows
// through to the else-body's own closing `}`, dropping the else body
// regardless of whether a comment was ever involved — confirmed by
// testing commit `735ef63`, before this task started, with an identical
// comment-free else fixture: already broken then, for an unrelated
// reason). `ifMatch` and `_scanTryCatchFinally` both already tolerate an
// ordinary `\s*`/whitespace gap between `}` and the keyword; skipping
// comments here too keeps this lookahead in sync with what those
// recognizers can actually parse once the flush is correctly suppressed.
function _continuationKeywordAhead(body, i) {
  let j = i + 1;
  let moved = true;
  while (moved) {
    moved = false;
    while (j < body.length && /\s/.test(body[j])) { j++; moved = true; }
    if (body[j] === '/' && body[j + 1] === '/') {
      while (j < body.length && body[j] !== '\n') j++;
      moved = true;
      continue;
    }
    if (body[j] === '/' && body[j + 1] === '*') {
      j += 2;
      while (j < body.length && !(body[j] === '*' && body[j + 1] === '/')) j++;
      if (j < body.length) j += 2; // past the closing '*/'
      moved = true;
      continue;
    }
  }
  for (const kw of ['else', 'catch', 'finally']) {
    if (body.startsWith(kw, j)) {
      const after = body[j + kw.length];
      if (after === undefined || !/\w/.test(after)) return true;
    }
  }
  return false;
}

function _splitStatements(body) {
  const out = [];
  let buf = '';
  let bufLine = null; // line of the first non-whitespace char seen in `buf` so far
  let curLine = 1;    // line of body[i], the character currently under the cursor
  let depth = 0;
  let inStr = null;
  let escape = false;
  const push = (c) => {
    buf += c;
    if (bufLine === null && !/\s/.test(c)) bufLine = curLine;
  };
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (escape) { push(c); escape = false; if (c === '\n') curLine++; continue; }
    if (inStr) {
      push(c);
      if (c === '\\') { escape = true; if (c === '\n') curLine++; continue; }
      if (c === inStr) inStr = null;
      if (c === '\n') curLine++;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; push(c); continue; }
    if (c === '/' && body[i + 1] === '/') {
      while (i < body.length && body[i] !== '\n') i++;
      // R8 fix round 2: push the newline that terminated the comment into
      // `buf` (not just bump `curLine`). Comment text itself is still
      // dropped (never pushed) — only the LINE it displaced is preserved,
      // same principle `_blankSpans`/`_blank` already use elsewhere in
      // this file (blank content out, keep line structure intact, don't
      // delete it outright). Without this, the flushed statement text
      // this comment lived inside ends up with FEWER newlines than the
      // real source has, so `_buildCfg`'s newline-counting line
      // computation for a nested body silently undercounts by exactly the
      // number of newlines lost to comments — the sink line reported to
      // the caller (and therefore the `agentic-security-ignore` pragma
      // line it must match) is wrong for any control-flow body containing
      // an otherwise-unrelated `//` comment.
      if (i < body.length) { push('\n'); curLine++; }
      continue;
    }
    // Taint-recall PRD (80%): PHP's THIRD line-comment form — `#`-comments
    // were entirely invisible to this splitter (only `//`/`/* */` were
    // handled), so a `#`-comment's text was treated as literal code:
    // string-toggling apostrophes, brace/paren/bracket depth corruption,
    // and — if it happened to contain a stray `;` — a bogus statement
    // boundary. PHP 8 attributes (`#[Attribute]`) use the same leading `#`
    // but are NOT a comment, so `#[` is excluded (checked via the next
    // character) exactly like `_extractBody`'s twin fix does.
    if (c === '#' && body[i + 1] !== '[') {
      while (i < body.length && body[i] !== '\n') i++;
      if (i < body.length) { push('\n'); curLine++; }
      continue;
    }
    if (c === '/' && body[i + 1] === '*') {
      // Block comment (incl. PHPDoc, e.g. `/** @param string $x */`).
      // Skip to the matching `*/`, counting any newlines crossed so line
      // tracking stays accurate for whatever follows — same contract the
      // `//` handling above upholds. Bounded even when unterminated (`i`
      // simply runs to `body.length` and the outer `for` loop ends).
      // R8 fix round 2: same newline-preservation fix as the `//` handler
      // above, but a block comment can span MANY lines — push one `\n`
      // into `buf` for every newline it displaces, not just one, or a
      // multi-line block comment inside a control-flow body would still
      // undercount by (newlines - 1).
      i += 2; // past the opening '/*'
      while (i < body.length && !(body[i] === '*' && body[i + 1] === '/')) {
        if (body[i] === '\n') { curLine++; push('\n'); }
        i++;
      }
      if (i < body.length) i++; // land on the '/' of '*/'; skipped, contributing no statement text
      continue;
    }
    if (c === '{' || c === '(' || c === '[') depth++;
    if (c === '}' || c === ')' || c === ']') {
      depth--;
      // R8: a `}` that returns the shared depth counter to 0 ends a
      // braced control-flow body (if/while/foreach/try/switch) — flush a
      // statement boundary here too, not just on `;` at depth 0. PHP has
      // no `{}`-based object/array-literal syntax (arrays use `[...]`,
      // tracked by the same counter but not this trigger), so this cannot
      // mis-fire mid-expression the way it would for a language with `{}`
      // object initializers. A `}` that closes a lambda/closure body
      // passed as a call argument (`usort($arr, function($a,$b){...})`)
      // does NOT trigger this — that `}` returns depth from 2 to 1 (still
      // inside usort's outer `(`), not to 0.
      //
      // EXCEPTION: do not flush when the next non-whitespace token is
      // `else`, `catch`, or `finally` — those must stay glued onto the
      // SAME statement as the preceding `}` for `ifMatch` and the
      // try/catch/finally recognizer in `_buildCfg` to see
      // `if (...) { ... } else { ... }` or
      // `try { ... } catch (...) { ... } finally { ... }` as one
      // contiguous blob (`ifMatch` is anchored end-to-end with `$` and
      // spans the whole construct; the try/catch/finally recognizer scans
      // the whole construct by hand for the same reason). A blind
      // flush-on-every-`}` here would silently split `if`/`else` and
      // multi-clause `try` into two statements each, which is a strictly
      // WORSE regression than the "must be last statement in scope" bug
      // this task fixes — an
      // `else`/`catch`/`finally` body would be dropped from the CFG
      // entirely, not just occasionally mis-split.
      if (c === '}' && depth === 0 && !_continuationKeywordAhead(body, i)) {
        push(c);
        const t = buf.trim();
        if (t) out.push({ text: t, line: bufLine ?? curLine });
        buf = '';
        bufLine = null;
        continue;
      }
    }
    if (c === ';' && depth === 0) {
      const t = buf.trim();
      if (t) out.push({ text: t, line: bufLine ?? curLine });
      buf = '';
      bufLine = null;
      continue;
    }
    // R8: a `switch` body's `case <expr>:` / `default:` labels are
    // terminated by `:`, not `;` or `}` — without this, the label text
    // stays glued onto whatever real statement follows it (no `;` or `}`
    // separates them), and that combined blob then fails BOTH the
    // assignment and call-statement shapes in `_lowerStmt` (neither
    // starts with `$var =` nor a bare identifier-call), silently
    // dropping the case body's first statement entirely — worse than the
    // brief's anticipated "label falls through to `_lowerStmt` and
    // returns null harmlessly" behavior. Scoped tightly (buf must be
    // EXACTLY `case <expr>` or `default`) so it can't mis-fire on a
    // ternary's `:`, which leaves buf holding something that never
    // matches either pattern.
    //
    // Excludes `::` (PHP's static-access / class-constant / PHP 8.1
    // enum-case operator, e.g. `case Foo::BAR:` or `case Status::Active:`)
    // via the adjacent-char check below — without it, `case Foo::BAR:`'s
    // FIRST `:` already makes buf read "case Foo", which matches the case
    // pattern just as eagerly as the real terminating `:` after `BAR`
    // does, mis-splitting mid-token and dropping that case's body. Both
    // colons of a `::` pair are skipped (checking one neighbor character
    // each is enough: the first colon sees `body[i+1] === ':'`, the
    // second sees `body[i-1] === ':'`), so only a genuine lone `:` can
    // ever terminate a label.
    if (c === ':' && depth === 0 && body[i + 1] !== ':' && body[i - 1] !== ':') {
      const t = buf.trim();
      if (/^case\s+[\s\S]+$/.test(t) || t === 'default') {
        out.push({ text: t, line: bufLine ?? curLine });
        buf = '';
        bufLine = null;
        continue;
      }
    }
    push(c);
    if (c === '\n') curLine++;
  }
  const t = buf.trim();
  if (t) out.push({ text: t, line: bufLine ?? curLine });
  return out;
}

// Taint-recall PRD (80%): same architectural fix as parser-cs.js/
// parser-go.js — a chained call (`sanitize($x)->encode()`, or a real sink
// shape like `$xp->query(...)` reached through a chain) previously stopped
// at the FIRST balanced call, leaving `->method(args)` unconsumed. `callee`
// arrives already normalized to dots (->/:: both become "."), so the
// continuation check looks for a literal "->" or "::" in the SOURCE text
// (PHP's own syntax) even though the join uses ".". Args from EVERY level
// are kept, outermost-first — see parser-cs.js's twin function for why
// (a first version that kept only the outermost broke a real chain shape
// where the tainted value sits on an INNER call).
function _followChain(s, endIdx, calleeSoFar, argsSoFar) {
  const rest = s.slice(endIdx);
  const m = rest.match(/^(?:->|::)(\w+)/);
  if (!m) return { kind: 'call', callee: calleeSoFar, args: argsSoFar };
  const outer = matchBalancedCall(rest, /^(?:->|::)(\w+)/);
  if (!outer) return { kind: 'call', callee: calleeSoFar, args: argsSoFar };
  const outerArgs = _splitTopLevelCommas(outer.argsText).map(_lowerExpr);
  return _followChain(rest, outer.endIdx, `${calleeSoFar}.${outer.callee}`, outerArgs.concat(argsSoFar));
}

function _lowerExpr(text) {
  const s = String(text || '').trim();
  if (!s) return { kind: 'unknown' };
  // Stage 3 correctness audit (detection depth, per-language-IR): PHP
  // double-quoted strings interpolate variables directly
  // ("SELECT ... WHERE id=$id", "hi {$user->name}") — single-quoted
  // strings never do. This must run BEFORE the generic string-literal
  // fallback just below, which otherwise treated ANY quoted string
  // (including a double-quoted one containing a live variable) as an
  // opaque clean literal — silently dropping the interpolated variable's
  // taint. This is exactly `"SELECT ... WHERE id=$id"`, one of the most
  // common real PHP SQL-injection shapes. Simple (`$var`, `$var->prop`,
  // `$var[key]`) and complex (`{$expr}`) interpolation forms are both
  // lowered into a template, same shape as the `.`-concat branch below.
  // Taint-recall PRD (80%): the old guard (`/^"/.test(s) && s.includes('$')`)
  // treated ANY string simply STARTING with `"` and containing a `$`
  // ANYWHERE as a self-contained double-quoted literal, then blindly sliced
  // off the first and last characters as its quotes (`s.slice(1, -1)`).
  // For a concat expression like `"SELECT ... id = " . $id` — arguably the
  // single most common real-world PHP SQL-injection shape — `s` starts
  // with `"` and contains a `$` (in `$id`, OUTSIDE the string, after the
  // `.`), so this branch fired and treated the WHOLE concat expression's
  // text as interpolation content: `inner` became `SELECT ... id = " . $i`
  // (sliced off the true FIRST character and the true LAST character,
  // neither of which bounds the actual string literal), corrupting both
  // the literal text and truncating `$id` to `$i`. Now requires the ENTIRE
  // trimmed expression to be exactly one closed double-quoted literal
  // (anchored start AND end) before treating it as interpolation-only —
  // `"literal" . $var` fails this (trailing ` . $var` breaks the end
  // anchor) and correctly falls through to the concat branch below instead.
  const dqLiteral = s.match(/^"((?:[^"\\]|\\.)*)"$/);
  if (dqLiteral && s.includes('$')) {
    const inner = dqLiteral[1];
    const re = /\{(\$[^}]+)\}|(\$[A-Za-z_]\w*(?:->[A-Za-z_]\w*|\[[^\]]+\])?)/g;
    let lastIndex = 0;
    const parts = [];
    let matched = false;
    let m;
    while ((m = re.exec(inner)) !== null) {
      matched = true;
      if (m.index > lastIndex) parts.push({ kind: 'literal', value: inner.slice(lastIndex, m.index) });
      parts.push(_lowerExpr(m[1] !== undefined ? m[1] : m[2]));
      lastIndex = re.lastIndex;
    }
    if (matched) {
      if (lastIndex < inner.length) parts.push({ kind: 'literal', value: inner.slice(lastIndex) });
      return { kind: 'tpl', parts };
    }
  }
  // Taint-recall PRD (80%): same unanchored-prefix defect as the
  // interpolation branch above, one layer down — `/^"/.test(s)` only checks
  // that `s` STARTS with a quote, not that it IS (only) a closed literal.
  // For `"literal" . $id`, this fallback used to catch what the (now fixed)
  // interpolation branch missed and swallow the ENTIRE concat expression —
  // trailing ` . $id` included — into one opaque literal `value` string,
  // silently dropping `$id`'s taint just as badly, only one level later.
  // Anchored at both ends so a genuinely unclosed/concatenated string falls
  // through to the concat branch below instead of being misread as whole.
  if (/^"(?:[^"\\]|\\.)*"$/.test(s) || /^'(?:[^'\\]|\\.)*'$/.test(s)) return { kind: 'literal', value: s };
  if (/^\d/.test(s)) return { kind: 'literal', value: s };
  if (/^(true|false|null|NULL)\b/.test(s)) return { kind: 'literal', value: s };
  // Superglobals
  if (/^\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION|ENV)\b/.test(s)) {
    const parts = s.split(/[\[\]'"]+/).filter(Boolean);
    if (parts.length === 1) return { kind: 'ident', name: parts[0] };
    let cur = { kind: 'ident', name: parts[0] };
    for (let i = 1; i < parts.length; i++) {
      cur = { kind: 'member', object: cur, prop: parts[i] || '[]' };
    }
    return cur;
  }
  // Variable
  if (/^\$[A-Za-z_]\w*$/.test(s)) return { kind: 'ident', name: s };
  // Method call: $obj->method(args) or ClassName::method(args).
  // matchBalancedCall finds the paren that actually balances the FIRST
  // '(' — not the greedy-to-end-of-string match the old `/\((.*)\)\s*$/`
  // used, which corrupted the argument text for a chained call
  // (`sanitize($x)->trim()` produced args="$x)->trim(", which then fell
  // through to {kind:'unknown'} and silently dropped $x).
  const methodCall = matchBalancedCall(s, /^(\$[\w]+(?:->[\w]+)*|[A-Za-z_][\w]*(?:::[\w]+)*)/);
  if (methodCall) {
    const callee = methodCall.callee.replace(/->/g, '.').replace(/::/g, '.');
    const args = _splitTopLevelCommas(methodCall.argsText).map(_lowerExpr);
    return _followChain(s, methodCall.endIdx, callee, args);
  }
  // Function call: func(args)
  const funcCall = matchBalancedCall(s, /^([A-Za-z_][\w]*)/);
  if (funcCall) {
    const args = _splitTopLevelCommas(funcCall.argsText).map(_lowerExpr);
    return _followChain(s, funcCall.endIdx, funcCall.callee, args);
  }
  // Concat with .
  //
  // The `parts.length > 1` guard is load-bearing, not defensive tidiness:
  // when every `.` in `s` is nested inside brackets or strings (e.g.
  // `s = '"y.z"'` in `["health" => "check.status"]`), `_splitTopLevelDot`
  // returns `[s]` — the input unchanged, as a single part — and mapping
  // `_lowerExpr` over it recurses on the IDENTICAL string forever (stack
  // overflow). Before R14(b) this was only reachable from inside function
  // bodies; the module-level lowering now feeds every top-level statement
  // through here too, so real files (e.g. a top-level array literal with a
  // dotted string value) hit it and the per-file catch in `ir/index.js`
  // silently dropped the whole file from Layer-2 analysis. Same shape as
  // parser-cs.js's `_splitTopLevelPlus` guard.
  if (s.includes('.') && /["'\$]/.test(s)) {
    const rawParts = _splitTopLevelDot(s);
    if (rawParts.length > 1) return { kind: 'tpl', parts: rawParts.map(_lowerExpr) };
  }
  // Member: $obj->prop
  if (/^\$[\w]+(?:->[\w]+)+$/.test(s)) {
    const parts = s.split('->');
    let cur = { kind: 'ident', name: parts[0] };
    for (let i = 1; i < parts.length; i++) cur = { kind: 'member', object: cur, prop: parts[i] };
    return cur;
  }
  return { kind: 'unknown' };
}

function _splitTopLevelCommas(s) {
  const out = [];
  let buf = '';
  let depth = 0;
  let inStr = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      buf += c;
      if (c === '\\') { i++; buf += s[i] || ''; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; buf += c; continue; }
    if (c === '(' || c === '{' || c === '[') depth++;
    if (c === ')' || c === '}' || c === ']') depth--;
    if (c === ',' && depth === 0) { out.push(buf.trim()); buf = ''; continue; }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

function _splitTopLevelDot(s) {
  const out = [];
  let buf = '';
  let depth = 0;
  let inStr = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      buf += c;
      if (c === '\\') { i++; buf += s[i] || ''; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; buf += c; continue; }
    if (c === '(' || c === '{' || c === '[') depth++;
    if (c === ')' || c === '}' || c === ']') depth--;
    if (c === '.' && depth === 0) { out.push(buf.trim()); buf = ''; continue; }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

function _lowerStmt(stmt, line) {
  const s = stmt.trim();
  if (!s || s.startsWith('//') || s.startsWith('#')) return null;
  if (/^return\b/.test(s)) {
    const rest = s.replace(/^return\s*/, '').trim();
    return { kind: 'return', line, value: rest ? _lowerExpr(rest) : null };
  }
  if (/^throw\b/.test(s)) {
    return { kind: 'throw', line, value: _lowerExpr(s.replace(/^throw\s+/, '')) };
  }
  // Taint-recall PRD (80%): `echo`/`print` are PHP LANGUAGE CONSTRUCTS, not
  // function calls — `echo "<div>" . $_GET['q'] . "</div>";` has no `(`
  // immediately after the keyword, so the statement-form call regex below
  // never matched it, and the entire echoed expression (including any
  // reflected taint) was silently dropped. `echo` can take multiple
  // comma-separated expressions; lowered to a synthetic call
  // (`__php_echo__`) carrying each as an argument, so a normal callee-keyed
  // catalog sink can target it exactly like any other call-shaped sink —
  // same convention as parser-rb.js's `__ruby_backtick_exec__`.
  if (/^(?:echo|print)\b/.test(s)) {
    const rest = s.replace(/^(?:echo|print)\s*/, '');
    return { kind: 'call', line, callee: '__php_echo__', args: _splitTopLevelCommas(rest).map(_lowerExpr) };
  }
  // Assignment: $var = expr
  const assign = s.match(/^(\$[\w]+(?:->[\w]+)*)\s*=\s*(.+)$/s);
  if (assign) {
    return { kind: 'assign', line, target: assign[1], source: _lowerExpr(assign[2]) };
  }
  // Statement-form call
  const call = matchBalancedCall(s, /^(\$[\w]+(?:->[\w]+)*|[A-Za-z_][\w]*(?:::[\w]+)*)/);
  if (call) {
    const callee = call.callee.replace(/->/g, '.').replace(/::/g, '.');
    const chained = _followChain(s, call.endIdx, callee, _splitTopLevelCommas(call.argsText).map(_lowerExpr));
    return { kind: 'call', line, callee: chained.callee, args: chained.args };
  }
  return null;
}

// Taint-recall PRD (80%): `_extractBody` used to have ZERO comment
// awareness — worse than `_splitStatements` below, which at least skips
// `//`/`/* */` (though not `#`). An apostrophe inside ANY comment (`//`,
// `#`, or `/* */`) — "don't", "it's", "won't", all extremely common in real
// PHP — toggled `inStr` exactly as if a string literal had started. Every
// `{`/`}` from that point on was then invisible to depth-tracking until a
// SECOND apostrophe was found (typically much later, or never), so `depth`
// either never returns to 0 (the function's body extraction fails outright,
// returning `null` — silently dropping the ENTIRE FILE's IR, since a single
// failed top-level function match corrupts every span downstream of it) or
// returns to 0 at the wrong `}` (extracting a truncated or over-extended
// body). Now skips all three PHP comment forms exactly like
// `_splitStatements` already does for `//`/`/* */`, plus `#` (PHP 8
// attributes `#[...]` are NOT a comment — checked via the next character).
function _extractBody(src, openBrace) {
  let depth = 1;
  let i = openBrace + 1;
  let inStr = null;
  let escape = false;
  while (i < src.length && depth > 0) {
    const c = src[i];
    if (escape) { escape = false; i++; continue; }
    if (inStr) {
      if (c === '\\') { escape = true; i++; continue; }
      if (c === inStr) inStr = null;
      i++; continue;
    }
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '#' && src[i + 1] !== '[') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++;
      if (i < src.length) i += 2;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; i++; continue; }
    if (c === '{') depth++;
    else if (c === '}') depth--;
    if (depth === 0) return { body: src.slice(openBrace + 1, i), end: i };
    i++;
  }
  return null;
}

function _lineAt(src, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < src.length; i++) if (src[i] === '\n') line++;
  return line;
}

function _qid(file, name, line, body) {
  const sha = crypto.createHash('sha256').update(body).digest('hex').slice(0, 8);
  return `${file}::${name}@${line}#${sha}`;
}

// FUNC_RE's leading alternation `(?:^|[\n;{}]|<\?php|<\?)` matches a single
// "boundary" character/token that belongs to whatever precedes the function
// (a statement terminator, a brace, or the PHP open tag) — not to the
// function itself. `m.index` always points at the START of that boundary,
// so including it verbatim in the function's span would blank away e.g. the
// `;` that terminates the PRECEDING top-level statement once the whole file
// is lowered in a single _buildCfg pass (see _blankSpans below), silently
// merging that statement with whatever gap text follows the function. This
// returns how many characters of the boundary token were actually consumed
// so the function's span can be made to start right after it.
function _funcBoundaryLen(code, idx) {
  if (idx > 0) {
    const c = code[idx];
    if (c === '\n' || c === ';' || c === '{' || c === '}') return 1;
  }
  if (/^<\?php/i.test(code.slice(idx, idx + 5))) return 5;
  if (/^<\?/.test(code.slice(idx, idx + 2))) return 2;
  return 0;
}

// Blank out every real function's span in a COPY of the full source
// (replace its characters with spaces, preserving every newline exactly).
// This lets the WHOLE file be lowered in a single _buildCfg call at
// startLine=1 for the module-level CFG, which keeps every remaining
// statement's reported line number exactly equal to its real source line —
// no character is ever deleted, only turned into a space, so nothing can
// shift. This replaces the old per-gap slicing + per-gap startLine
// re-derivation, which mis-tracked lines whenever a gap slice started with
// leading blank/newline characters and broke the line-scoped
// `agentic-security-ignore` suppression pragma for module-level findings.
function _blankSpans(code, spans) {
  let out = '';
  let cursor = 0;
  for (const span of spans) {
    if (span.start > cursor) out += code.slice(cursor, span.start);
    out += _blank(code.slice(span.start, span.end));
    cursor = span.end;
  }
  out += code.slice(cursor);
  return out;
}

function _blank(text) {
  return text.replace(/[^\n]/g, ' ');
}

// Blanks a leading PHP open tag (`<?php` or `<?`) if the file starts with
// one. Only the true start of the file is handled (matching the previous
// behavior's `cursor === 0` scope) — this is a real fix, not dead code:
// when top-level content sits between the open tag and the first function
// declaration (e.g. `<?php\n$x = [...];\nfunction f(){}`), the tag is NOT
// part of any function's span (the boundary FUNC_RE actually consumed
// before `function f` is the `;`, not the tag — see _funcBoundaryLen), so
// it survives into the blanked text as literal `<?php` characters. Left
// unblanked, that text glues onto the front of the first top-level
// statement (`<?php\n$x = [...]`), which then fails every `_lowerStmt`
// pattern (all anchored at the true start of the statement) and silently
// drops it. Blanking (not deleting) the tag keeps line numbers exact.
function _blankLeadingOpenTag(text) {
  const m = text.match(/^<\?(?:php)?/i);
  if (!m) return text;
  return _blank(m[0]) + text.slice(m[0].length);
}

let _nid = 0;
function _nextId() { return `pn${++_nid}`; }

function _addNode(nodes, node) {
  const id = _nextId();
  node.succ = node.succ || [];
  node.pred = node.pred || [];
  nodes[id] = node;
  return id;
}

function _linkNodes(nodes, src, dst) {
  if (!nodes[src] || !nodes[dst]) return;
  if (!nodes[src].succ.includes(dst)) nodes[src].succ.push(dst);
  if (!nodes[dst].pred.includes(src)) nodes[dst].pred.push(src);
}

// R8 fix round 1: counts `\n` in `s` up to (not including) `upTo`. `s` here
// is the RAW, untrimmed statement text `_buildCfg` is currently processing
// (not a `.trim()`-mangled reconstruction — the exact lossy pattern the
// module header comment above `_splitStatements` warns against), so a
// direct count is safe and exact, not an approximation.
function _countNewlines(s, upTo) {
  let n = 0;
  const end = Math.min(upTo, s.length);
  for (let i = 0; i < end; i++) if (s[i] === '\n') n++;
  return n;
}

// Scans a balanced `{ ... }` block starting at `s[openIdx] === '{'`.
// String-aware (a `{`/`}` inside a quoted string doesn't perturb depth),
// mirroring `_splitStatements`' own string handling. Returns the index
// just past the matching `}`, or -1 if unbalanced/not found.
function _matchBraceBlock(s, openIdx) {
  if (s[openIdx] !== '{') return -1;
  let depth = 0;
  let inStr = null;
  let escape = false;
  for (let i = openIdx; i < s.length; i++) {
    const c = s[i];
    if (escape) { escape = false; continue; }
    if (inStr) {
      if (c === '\\') { escape = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

// R8 fix round 1 (Important): manually scans a
// `try { ... } (catch (...) { ... })* (finally { ... })?` construct by hand
// rather than delegating to one greedy-capture-group regex. The regex this
// replaced (`^try\s*\{([\s\S]*)\}\s*catch\s*\(([^)]*)\)\s*\{([\s\S]*)\}
// (?:\s*finally\s*\{([\s\S]*)\})?\s*$`) has two real bugs: its catch-body
// group is GREEDY, so for `try{}catch(E $e){A}finally{B}` it swallows
// through to finally's OWN closing `}` (not catch's), making the trailing
// `(?:\s*finally...)?` group match nothing — `finally` bodies were dead
// code, never actually reachable. And it unconditionally REQUIRES a catch
// clause, so the equally-valid `try { ... } finally { ... }` (no catch) PHP
// shape was invisible entirely, both bodies dropped. Neither is fixable by
// tweaking the regex (lazy-matching the catch group just breaks nested-
// brace bodies the other way); balanced-brace scanning is the correct fix.
//
// Only the FIRST catch clause is modeled in the CFG (matches this task's
// brief scope — multi-catch BLOCK form, `catch(A){}catch(B){}`, was
// already an accepted, documented partial-capture degrade before this fix,
// confirmed non-crashing; union-type catches, `catch (A|B $e) {}`, are
// unaffected and fully supported, same as before). Every catch clause
// present is still scanned past correctly (not just the first) so a
// trailing `finally` is located at its real position rather than
// mismatched against a later catch's own content.
//
// Returns null if `s` isn't `try { ... }` shaped at all. Otherwise:
//   { tryBody, tryBodyOffset, catchBody, catchBodyOffset,
//     finallyBody, finallyBodyOffset }
// A body that isn't present is `null` with `-1` for its offset. Each
// `*Offset` is `s`'s own character offset of that body's first character —
// paired with `_countNewlines`, this gives the caller (`_buildCfg`) the
// EXACT absolute source line for each clause, not just the try-body's
// (which happens to share `line`'s value for ordinary K&R style, but
// catch/finally clauses generally start several lines later).
function _scanTryCatchFinally(s) {
  const head = /^try\s*/.exec(s);
  if (!head) return null;
  let i = head[0].length;
  if (s[i] !== '{') return null;
  const tryBodyOffset = i + 1;
  const tryEnd = _matchBraceBlock(s, i);
  if (tryEnd < 0) return null;
  const tryBody = s.slice(tryBodyOffset, tryEnd - 1);
  i = tryEnd;

  let catchBody = null;
  let catchBodyOffset = -1;
  let sawCatch = false;
  for (;;) {
    const rest = s.slice(i);
    const ws = /^\s*/.exec(rest)[0];
    i += ws.length;
    const cm = /^catch\s*\(/.exec(s.slice(i));
    if (!cm) break;
    const parenStart = i + cm[0].length - 1;
    const parenEnd = s.indexOf(')', parenStart);
    if (parenEnd < 0) return null;
    let j = parenEnd + 1;
    const ws2 = /^\s*/.exec(s.slice(j))[0];
    j += ws2.length;
    if (s[j] !== '{') return null;
    const bodyOffset = j + 1;
    const bodyEnd = _matchBraceBlock(s, j);
    if (bodyEnd < 0) return null;
    if (!sawCatch) {
      catchBody = s.slice(bodyOffset, bodyEnd - 1);
      catchBodyOffset = bodyOffset;
      sawCatch = true;
    }
    i = bodyEnd;
  }

  let finallyBody = null;
  let finallyBodyOffset = -1;
  {
    const ws = /^\s*/.exec(s.slice(i))[0];
    let j = i + ws.length;
    const fm = /^finally\s*/.exec(s.slice(j));
    if (fm) {
      j += fm[0].length;
      if (s[j] === '{') {
        const bodyOffset = j + 1;
        const bodyEnd = _matchBraceBlock(s, j);
        if (bodyEnd < 0) return null;
        finallyBody = s.slice(bodyOffset, bodyEnd - 1);
        finallyBodyOffset = bodyOffset;
        i = bodyEnd;
      }
    }
  }

  // PHP requires at least one of catch/finally; a bare `try {}` alone
  // isn't valid PHP and isn't a shape this recognizer should claim.
  if (!sawCatch && finallyBody === null) return null;
  // Whatever remains must be only trailing whitespace, or this wasn't a
  // clean try/catch/finally statement after all — fall through to the
  // generic `_lowerStmt` path (safe no-op) rather than claiming a bad
  // match.
  if (s.slice(i).trim() !== '') return null;

  return { tryBody, tryBodyOffset, catchBody, catchBodyOffset, finallyBody, finallyBodyOffset };
}

// `startLine` is the absolute source line of the FIRST character of
// `bodyText`. Each statement's absolute line is `startLine + stmt.line - 1`
// (`stmt.line` from _splitStatements is already 1-indexed and relative to
// `bodyText`), so — unlike the old incremental `line++`/`line += newlines+1`
// bookkeeping this replaced — no line is ever derived by re-counting
// newlines in already-trimmed text. That old scheme silently dropped any
// blank line (or, at module level, any blanked-out function span — see
// `_blankSpans`) that preceded a statement, which is exactly what made
// module-level PHP findings report the wrong source line.
function _buildCfg(bodyText, nodes, prevId, startLine, depth = 0) {
  if (depth > 12) return prevId;
  const stmts = _splitStatements(bodyText);
  let prev = prevId;
  for (const stmt of stmts) {
    const s = stmt.text;
    const line = startLine + stmt.line - 1;
    if (!s || s.startsWith('//') || s.startsWith('#')) continue;

    // R8 fix round 2: `line` (the absolute source line of `s`'s FIRST
    // character — the `if`/`while`/`foreach`/`switch` keyword itself) is
    // NOT a safe stand-in for a body's own start line in general. Fix
    // round 1 used flat `line` for these four recognizers on the
    // assumption that K&R-style `{` on the same physical line as the
    // keyword makes the body start on that same line — true only when
    // the header between the keyword and `{` is a single physical line
    // AND contains no comment that ate a newline without contributing one
    // back to `s` (fix round 1 also missed that a comment anywhere inside
    // `s` — not just inside the header — undercounts newlines the same
    // way; that half is fixed by `_splitStatements` now pushing a `\n`
    // for every newline a skipped comment displaces, above). A `d`-flagged
    // regex exposes each capture group's real character offset within
    // `s` via `.indices`, so `_countNewlines(s, offset)` gives the body's
    // EXACT absolute line regardless of how many lines the header itself
    // spans or how many comments precede the body — the same precise
    // per-clause technique the try/catch/finally recognizer below already
    // uses (there, offsets come from the balanced-brace scanner instead
    // of regex `.indices`, same principle).
    const ifMatch = s.match(/^if\s*\((.+?)\)\s*\{([\s\S]*)\}(?:\s*else\s*\{([\s\S]*)\})?\s*$/ds);
    if (ifMatch) {
      const ifNode = _addNode(nodes, { kind: 'if', cond: _lowerExpr(ifMatch[1]), line });
      _linkNodes(nodes, prev, ifNode);
      const join = _addNode(nodes, { kind: 'noop', line });
      const thenStartLine = line + _countNewlines(s, ifMatch.indices[2][0]);
      const thenTail = _buildCfg(ifMatch[2], nodes, ifNode, thenStartLine, depth + 1);
      _linkNodes(nodes, thenTail, join);
      if (ifMatch[3]) {
        const elseStartLine = line + _countNewlines(s, ifMatch.indices[3][0]);
        const elseTail = _buildCfg(ifMatch[3], nodes, ifNode, elseStartLine, depth + 1);
        _linkNodes(nodes, elseTail, join);
      } else {
        _linkNodes(nodes, ifNode, join);
      }
      prev = join;
      continue;
    }

    const whileMatch = s.match(/^while\s*\((.+?)\)\s*\{([\s\S]*)\}\s*$/ds);
    if (whileMatch) {
      const header = _addNode(nodes, { kind: 'loop-header', line });
      _linkNodes(nodes, prev, header);
      const bodyStartLine = line + _countNewlines(s, whileMatch.indices[2][0]);
      const bodyTail = _buildCfg(whileMatch[2], nodes, header, bodyStartLine, depth + 1);
      _linkNodes(nodes, bodyTail, header);
      const join = _addNode(nodes, { kind: 'noop', line });
      _linkNodes(nodes, header, join);
      prev = join;
      continue;
    }

    const foreachMatch = s.match(/^foreach\s*\((.+?)\s+as\s+(?:\$\w+\s*=>\s*)?(\$\w+)\)\s*\{([\s\S]*)\}\s*$/ds);
    if (foreachMatch) {
      const header = _addNode(nodes, { kind: 'loop-header', line });
      _linkNodes(nodes, prev, header);
      const assignId = _addNode(nodes, { kind: 'assign', target: foreachMatch[2], source: _lowerExpr(foreachMatch[1]), line });
      _linkNodes(nodes, header, assignId);
      const bodyStartLine = line + _countNewlines(s, foreachMatch.indices[3][0]);
      const bodyTail = _buildCfg(foreachMatch[3], nodes, assignId, bodyStartLine, depth + 1);
      _linkNodes(nodes, bodyTail, header);
      const join = _addNode(nodes, { kind: 'noop', line });
      _linkNodes(nodes, header, join);
      prev = join;
      continue;
    }

    const tryScan = /^try\s*\{/.test(s) ? _scanTryCatchFinally(s) : null;
    if (tryScan) {
      const tryNode = _addNode(nodes, { kind: 'noop', line });
      _linkNodes(nodes, prev, tryNode);
      const join = _addNode(nodes, { kind: 'noop', line });
      // Same exact-offset technique as the if/while/foreach/switch bodies
      // above, just fed by `_scanTryCatchFinally`'s balanced-brace-scan
      // offsets instead of a `d`-flagged regex's `.indices` (there's no
      // single regex to attach `.indices` to here — that's the whole
      // reason this recognizer scans by hand). catch/finally clauses
      // especially do NOT start on `line` (the `try` keyword's own line)
      // in general — they start wherever their own `catch (...) {` /
      // `finally {` happens to land, often several lines later.
      const tryStartLine = line + _countNewlines(s, tryScan.tryBodyOffset);
      const tryTail = _buildCfg(tryScan.tryBody, nodes, tryNode, tryStartLine, depth + 1);
      let tail = tryTail;
      if (tryScan.catchBody !== null) {
        const catchNode = _addNode(nodes, { kind: 'noop', line });
        _linkNodes(nodes, tail, catchNode);
        const catchStartLine = line + _countNewlines(s, tryScan.catchBodyOffset);
        tail = _buildCfg(tryScan.catchBody, nodes, catchNode, catchStartLine, depth + 1);
      }
      if (tryScan.finallyBody !== null) {
        const finallyNode = _addNode(nodes, { kind: 'noop', line });
        _linkNodes(nodes, tail, finallyNode);
        const finallyStartLine = line + _countNewlines(s, tryScan.finallyBodyOffset);
        tail = _buildCfg(tryScan.finallyBody, nodes, finallyNode, finallyStartLine, depth + 1);
      }
      _linkNodes(nodes, tail, join);
      prev = join;
      continue;
    }

    const switchMatch = s.match(/^switch\s*\((.+?)\)\s*\{([\s\S]*)\}\s*$/ds);
    if (switchMatch) {
      const switchNode = _addNode(nodes, { kind: 'if', cond: _lowerExpr(switchMatch[1]), line });
      _linkNodes(nodes, prev, switchNode);
      const join = _addNode(nodes, { kind: 'noop', line });
      // PHP switch/case bodies fall through by default (no per-case
      // braces) — lower the whole switchBlock body as ONE linear sequence
      // under the switch node, matching this plan's "linear-but-complete"
      // target rather than modeling per-case branch/skip semantics.
      const bodyStartLine = line + _countNewlines(s, switchMatch.indices[2][0]);
      const bodyTail = _buildCfg(switchMatch[2], nodes, switchNode, bodyStartLine, depth + 1);
      _linkNodes(nodes, bodyTail, join);
      prev = join;
      continue;
    }

    const node = _lowerStmt(s, line);
    if (!node) continue;
    const id = _addNode(nodes, node);
    _linkNodes(nodes, prev, id);
    prev = id;
  }
  return prev;
}

export function parsePhpFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  if (!/\.(?:php|phtml)$/i.test(file)) return null;
  if (code.length > 1_000_000) return null;

  const functions = [];
  const spans = []; // {start, end}: source ranges fully consumed by a matched function (signature through closing brace)
  FUNC_RE.lastIndex = 0;
  _nid = 0;
  let m;
  while ((m = FUNC_RE.exec(code)) !== null) {
    const name = m[1];
    const paramsText = m[2] || '';
    const params = paramsText.split(',').map(p => {
      const t = p.trim();
      if (!t) return null;
      const vm = t.match(/\$(\w+)/);
      return vm ? '$' + vm[1] : null;
    }).filter(Boolean);
    const braceIdx = code.indexOf('{', m.index + m[0].length - 1);
    if (braceIdx < 0) continue;
    const extracted = _extractBody(code, braceIdx);
    if (!extracted) continue;
    const startLine = _lineAt(code, m.index);
    const nodes = {};
    const entry = _addNode(nodes, { kind: 'entry', line: startLine });
    const exit = _addNode(nodes, { kind: 'exit', line: startLine });
    // R8 fix round 3: the function body's `startLine` must be derived from
    // `braceIdx` (the function's actual opening `{`), not from `startLine + 1`
    // (a flat one-line offset from `m.index`, the FUNC_RE match start —
    // typically a preceding boundary character/token, not the function
    // itself). `startLine + 1` is only correct when `{` sits on the very
    // next physical line after wherever `m.index` landed, which holds for
    // ordinary same-line-brace, single-line-signature functions but breaks
    // for: Allman brace style (`{` on its own line — off by 1), a
    // multi-line function signature (off by 2-3, one per extra signature
    // line), and a function preceded by blank lines (off by however many
    // blank lines precede it — a nearly universal real-world style). This
    // reproduces the exact same pragma-inert/wrong-line-suppresses symptom
    // fix rounds 1-2 already fixed for control-flow bodies, just at the
    // function-body base line instead of a nested recursion site — pre-
    // existing to this task (confirmed byte-identical across the original
    // commit and both prior fix rounds), not something this task's own
    // changes introduced, but it defeats the same user-facing goal so it's
    // fixed here rather than left for a separate task.
    const tail = _buildCfg(extracted.body, nodes, entry, _lineAt(code, braceIdx + 1));
    _linkNodes(nodes, tail, exit);
    const cfg = { entry, exit, nodes };
    functions.push({
      qid: _qid(file, name, startLine, extracted.body),
      name, line: startLine, params, file,
      cfg,
      calls: callSitesFromCfg(cfg),
    });
    // span.end is exclusive (points after the closing brace), so interior and trailing
    // gaps both work correctly without special casing. extracted.end points AT the brace,
    // so we add 1 to make it exclusive. We keep FUNC_RE.lastIndex at extracted.end
    // (the brace position) so subsequent function matches can use it as a boundary.
    // span.start is m.index PLUS the boundary token FUNC_RE consumed ahead of the
    // function itself (see _funcBoundaryLen) — the boundary char/tag belongs to
    // whatever precedes the function, not to the function's own blanked span.
    spans.push({ start: m.index + _funcBoundaryLen(code, m.index), end: extracted.end + 1 });
    // Don't skip past the closing brace: for `<?php function h(){...} function m(){...}`
    // that brace is the only boundary character available to anchor the next
    // function's match (there's no newline/semicolon between them), and advancing
    // past it here would make the following function declaration unmatchable.
    FUNC_RE.lastIndex = extracted.end;
  }

  // R14(b): lower top-level (module-scope) statements into a synthetic
  // <module> function, mirroring parser-js.js's Program-level lowering.
  // Every real function's span is blanked (see _blankSpans) in a copy of
  // the full source, and the WHOLE blanked text is lowered in a single
  // _buildCfg call at startLine=1 — this keeps every remaining statement's
  // reported line number exactly equal to its real source line, since no
  // character is ever deleted, only blanked to a space (newlines always
  // survive). No new statement-classification logic is needed.
  spans.sort((a, b) => a.start - b.start);
  const blanked = _blankLeadingOpenTag(_blankSpans(code, spans));
  const modNodes = {};
  const modEntry = _addNode(modNodes, { kind: 'entry', line: 1 });
  const modExit = _addNode(modNodes, { kind: 'exit', line: 1 });
  const modTail = _buildCfg(blanked, modNodes, modEntry, 1);
  _linkNodes(modNodes, modTail, modExit);
  const modHasContent = Object.values(modNodes).some(n => n.kind !== 'entry' && n.kind !== 'exit');
  let topLevel = null;
  if (modHasContent) {
    const moduleCfg = { entry: modEntry, exit: modExit, nodes: modNodes };
    const modQid = _qid(file, '<module>', 1, code);
    functions.push({
      qid: modQid,
      name: '<module>', line: 1, params: [], file,
      cfg: moduleCfg,
      calls: callSitesFromCfg(moduleCfg),
    });
    topLevel = modQid;
  }

  return functions.length ? { file, functions, topLevel } : null;
}
