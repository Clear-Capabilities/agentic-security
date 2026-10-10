// Does a guard actually DOMINATE the sink it is said to protect? (QA-005.AC02)
//
// `dropGuardedFindings` and the safe-sink-shape check recognise a guard by shape inside a window of source lines
// around the sink, then correlate on a shared identifier. That answers "is there guard-looking text near this sink",
// which is not the question that justifies dropping a finding: "is every path that reaches the sink forced through
// this guard". Text can be near a sink without protecting it:
//   - a guard written AFTER the sink (the window reaches several lines below it);
//   - a guard in a DIFFERENT function that happens to sit above;
//   - a guard inside a block that has already closed (`if (dev) { check(x); }  fetch(x)`);
//   - an `if (allowed(x)) { log() }` whose failing branch does not stop anything, followed by an unconditional sink;
//   - a membership test whose boolean result is computed and never branched on.
// This module decides that, over the same source lines, with no new dependency. It is deliberately conservative toward
// KEEPING a finding: when it cannot establish dominance it says so, and the caller leaves the finding in place. The
// cost of being wrong in that direction is a reviewable false positive; the other direction deletes a real defect.
//
// Pure: lines in, verdict out. It reads no file name beyond an extension, no label and no answer key, and works on text alone.
// It is NOT a control-flow graph: it recognises the structured shapes real handlers use (straight-line statements,
// early-exit checks, a sink nested in the guarded branch) and reports `unknown-shape` for anything else it cannot
// place, which counts as "not proven".

const TERMINATOR = /\b(?:return|throw|raise|continue|break|exit|abort|die|panic|halt|fail|next)\b|\b(?:sys\.exit|os\._exit|process\.exit|http\.Error|t\.Fatal|log\.Fatal)\b|\.\s*(?:status|sendStatus|abort|AbortWithStatus|AbortWithStatusJSON|Error)\s*\(/;
const CONDITIONAL_HEAD = /^\s*(?:\}\s*)?(?:else\s+)?(?:if|unless|elif|elsif|while|until|when|guard|switch)\b/;
const MODIFIER_EXIT = /^\s*(?:return|raise|throw|next|break|continue|abort|halt|fail|die)\b[^\n]*\b(?:if|unless)\b|\b(?:or|\|\|)\s+(?:raise|die|throw|return|abort|exit)\b/;
// A function or method DECLARATION line, across the languages this engine reads. A guard above one is in another function.
const NOT_A_DECL_HEAD = /^\s*(?:return|await|new|throw|else|yield|typeof|delete|case|if|for|while|switch|catch|try|do|elif|elsif|unless|until|when|guard|print|echo)\b/;
const MODIFIER = /^(?:public|private|protected|internal|static|final|abstract|override|async|export|default|virtual|sealed|extern|pub|suspend)\s+/;
const ANNOTATION = /^@\w+(?:\([^)]*\))?\s*/;
const DECL_START = /^(?:function\s*\*?\s*\w+\s*\(|def\s+\w+|fn\s+\w+|fun\s+\w+|func\s+(?:\([^)]*\)\s*)?\w+\s*\(|sub\s+\w+)/;
// A typed method header (`public String find(String q) throws E {`) or a bare class-method shorthand (`handle(req, res) {`): the head before the
// parenthesis is a few words, the opening brace ends the line. Written without nested quantifiers and capped in length, because these run per line.
const BRACE_METHOD = /^([^(){};=]{0,120}?)\(([^;)]{0,300})\)\s*(?:throws\s+[\w.,\s]{1,120})?\s*\{\s*$/;
const MAX_DECL_LINE = 400;
function isFunctionBoundary(line) {
  if (line.length > MAX_DECL_LINE || NOT_A_DECL_HEAD.test(line)) return false;
  // peel annotations and modifiers one at a time (a loop, not a repeated group)
  let rest = line.trimStart();
  for (let n = 0; n < 8; n++) { const m = ANNOTATION.exec(rest); if (!m) break; rest = rest.slice(m[0].length); }
  for (let n = 0; n < 8; n++) { const m = MODIFIER.exec(rest); if (!m) break; rest = rest.slice(m[0].length); }
  if (DECL_START.test(rest)) return true;
  const m = BRACE_METHOD.exec(line);
  if (!m) return false;
  const words = m[1].trim().split(/\s+/).filter(Boolean);
  // the last word is the method name; any earlier words are modifiers or a return type
  return words.length >= 1 && words.length <= 6 && /^\w+$/.test(words[words.length - 1]) && !/^(?:if|for|while|switch|catch|else|function|return)$/.test(words[words.length - 1]);
}
// A pure DATA declaration: a name bound to a literal, a collection or a constructor (`const ALLOWED = new Set([...])`, `DENY = ["a"]`,
// `static final Set<String> ALLOW = Set.of(...)`, `var allowed = map[string]bool{...}`). It defines the allow-list; it does not CHECK anything
// against it, so it cannot guard a sink however guard-shaped its name is.
const DATA_DECL = /^\s*(?:(?:export|public|private|protected|internal|static|final|readonly|const|let|var|val|def|pub|mut)\s+)*(?:[\w$.<>\[\],?:&* ]+?\s+)?[A-Za-z_$][\w$]*\s*(?::[^=\n]+)?(?::=|=)\s*(?:new\b|\[|\{|%[wi]|Set\.of|List\.of|Map\.of|Arrays\.asList|listOf|setOf|mapOf|hashSetOf|set\(|frozenset\(|list\(|dict\(|tuple\(|vec!|HashSet|map\[|[A-Z]\w*\{|["'`])(?!.*(?:=>|->|\bfunction\b))/;
// An assignment whose value is a membership/prefix/equality TEST: a boolean, which protects nothing until something branches on it.
const BOOLEAN_ASSIGN = /^\s*(?:(?:const|let|var|val|final|bool|boolean|auto)\s+)?([A-Za-z_$][\w$]*)\s*(?::=|=)\s*(?!.*\b(?:basename|abspath|realpath|resolve|normalize|secure_filename|safe_join|sanitize\w*|escape\w*)\b)[^=\n]*(?:\.\s*(?:has|includes|contains|startsWith|startswith|StartsWith|endsWith|HasPrefix|starts_with|match|test|matches)\s*\(|\bin\s|===|!==|==|!=)/;

/** Source line with string literals and trailing line comments blanked, so brace counting is not fooled by either. */
function code(line) {
  return String(line ?? '')
    .replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g, '""')
    .replace(/\/\/.*$/, '')
    .replace(/(^|\s)#.*$/, '$1');
}

const indentOf = (line) => { const m = /^[ \t]*/.exec(line)[0]; return m.replace(/\t/g, '    ').length; };
const countBraces = (s) => ({ open: (s.match(/\{/g) || []).length, close: (s.match(/\}/g) || []).length });
const blank = (s) => !/\S/.test(s);

// Block style of the file: indentation (Python, Ruby) or braces. The extension decides when known; otherwise the whole file votes, never just
// the few lines between guard and sink (two brace-free lines of JavaScript are not an indentation language).
function looksIndented(lines, file) {
  if (/\.(?:py|pyi|rb|rake|ru)$/i.test(file || '')) return true;
  if (/\.[A-Za-z0-9]+$/.test(file || '')) return false;
  let brace = 0; let colon = 0;
  for (const l of lines) {
    const c = code(l);
    if (/[{}]\s*$/.test(c)) brace++;
    else if (/^\s*(?:def|if|elif|else|for|while|class|try|except|finally|with)\b.*:\s*$/.test(c)) colon++;
  }
  return colon > brace;
}

function result(dominates, reason) { return { dominates, reason }; }

/**
 * @param {object} o
 * @param {string[]} o.lines     the file's source lines (original text)
 * @param {number} o.guardIdx    0-based index of the line the guard-shaped text matched on
 * @param {number} o.sinkIdx     0-based index of the sink line
 * @param {string} [o.file]      path, used ONLY to pick the block style (indentation vs braces) from its extension
 * @returns {{dominates: boolean, reason: string}}
 */
export function guardDominatesSink({ lines, guardIdx, sinkIdx, file = null, depth = 0 }) {
  if (!Array.isArray(lines) || !Number.isInteger(guardIdx) || !Number.isInteger(sinkIdx)) return result(false, 'unknown-shape');
  if (guardIdx < 0 || sinkIdx < 0 || guardIdx >= lines.length || sinkIdx >= lines.length) return result(false, 'unknown-shape');
  if (guardIdx > sinkIdx) return result(false, 'guard-after-sink');

  const indentStyle = looksIndented(lines, file);
  // Which named function holds the guard? A guard in a function that has ENDED before the sink protects the sink only through a call to
  // that function (a validator helper); a guard at module level does not reach into a function declared after it.
  const fn = enclosingFunction(lines, guardIdx, indentStyle);
  if (fn && sinkIdx > fn.endIdx) return calleeGuardDominates({ lines, guardIdx, sinkIdx, fn, file, depth });
  if (!fn) {
    for (let i = guardIdx + 1; i <= sinkIdx; i++) if (isFunctionBoundary(code(lines[i]))) return result(false, 'different-function');
  }
  const gl = code(lines[guardIdx]);

  // Same line: `if (!ok(x)) return; fetch(x)` or `x = safe(x); use(x)`. Order within the line is not tracked, but a guard that
  // shares the sink's line is positioned by the author as part of the same statement run.
  if (guardIdx === sinkIdx) return result(true, 'same-line');

  // A line that only DEFINES the allow-list is not a check.
  if (DATA_DECL.test(gl) && !/\.\s*(?:has|includes|contains|startsWith|startswith|StartsWith)\s*\(/.test(gl)) return result(false, 'data-declaration-not-a-check');

  // A membership/equality result that is computed and never branched on protects nothing.
  const boolAssign = BOOLEAN_ASSIGN.exec(gl);
  if (boolAssign && !CONDITIONAL_HEAD.test(gl)) {
    const v = boolAssign[1].replace(/[$]/g, '\\$');
    const used = new RegExp(`(?:\\b(?:if|unless|while|assert|require|ensure|guard)\\b|&&|\\|\\||\\?|\\bnot\\b|!)[^\\n]*\\b${v}\\b|\\b${v}\\b[^\\n]*(?:&&|\\|\\||\\?)`);
    let branched = false;
    for (let i = guardIdx + 1; i <= sinkIdx && !branched; i++) branched = used.test(code(lines[i]));
    if (!branched) return result(false, 'result-never-branched-on');
  }

  if (indentStyle) return indentDominates(lines, guardIdx, sinkIdx, gl);
  return braceDominates(lines, guardIdx, sinkIdx, gl);
}

function declaredName(declLine) {
  const c = code(declLine);
  const kw = /(?:function\s*\*?\s*|def\s+|fn\s+|fun\s+|func\s+(?:\([^)]*\)\s*)?|sub\s+)([A-Za-z_$][\w$]*)/.exec(c);
  if (kw) return kw[1];
  const typed = /([A-Za-z_$][\w$]*)\s*\(/.exec(c);
  return typed ? typed[1] : null;
}

/** The named function that contains line `idx`, as `{ declIdx, endIdx }`, or null at module level. */
function enclosingFunction(lines, idx, indentStyle) {
  if (indentStyle) return enclosingFunctionByIndent(lines, idx, indentOf(lines[idx]));
  let need = 0;
  for (let i = idx - 1; i >= 0; i--) {
    const c = code(lines[i]);
    for (let k = c.length - 1; k >= 0; k--) {
      if (c[k] === '}') need++;
      else if (c[k] === '{') {
        if (need > 0) { need--; continue; }
        const head = isFunctionBoundary(c) ? i : (/^\s*\{\s*$/.test(c) && i > 0 && isFunctionBoundary(code(lines[i - 1])) ? i - 1 : -1);
        if (head >= 0) {
          let depth = 0; let end = lines.length - 1;
          scan: for (let m = i; m < lines.length; m++) {
            const t = code(lines[m]);
            for (const ch of t) { if (ch === '{') depth++; else if (ch === '}') { depth--; if (depth === 0) { end = m; break scan; } } }
          }
          return { declIdx: head, endIdx: end };
        }
      }
    }
  }
  return null;
}

function enclosingFunctionByIndent(lines, idx, ind) {
  for (let i = idx - 1; i >= 0; i--) {
    if (blank(lines[i])) continue;
    const cur = indentOf(lines[i]);
    if (cur >= ind) continue;
    if (isFunctionBoundary(code(lines[i]))) {
      let end = i;
      for (let k = i + 1; k < lines.length; k++) { if (blank(lines[k])) continue; if (indentOf(lines[k]) <= cur) break; end = k; }
      return { declIdx: i, endIdx: end };
    }
    ind = cur;
  }
  return null;
}

/** The guard is in a helper function that ended before the sink. It protects the sink only if the sink's code calls that helper first and the guard cannot be skipped inside it. */
function calleeGuardDominates({ lines, guardIdx, sinkIdx, fn, file, depth }) {
  if (depth >= 3) return result(false, 'call-chain-too-deep');
  const name = declaredName(lines[fn.declIdx]);
  if (!name) return result(false, 'different-function');
  const call = new RegExp(`\\b${name.replace(/[$]/g, '\\$')}\\s*\\(`);
  let callIdx = -1;
  for (let i = fn.endIdx + 1; i <= sinkIdx; i++) { if (call.test(code(lines[i])) && !isFunctionBoundary(code(lines[i]))) { callIdx = i; break; } }
  if (callIdx < 0) return result(false, 'different-function');
  // 1. inside the helper the guard must be on every path to the helper's exit: at the function's own level, and either a straight-line
  //    statement or a check whose failing branch leaves. (The helper's exit is not a "sink", so this is judged on its own.)
  const forced = guardForcedBeforeExit(lines, guardIdx, fn, looksIndented(lines, file));
  if (!forced.ok) return result(false, `callee-guard-not-forced:${forced.reason}`);
  // 2. in the sink's code the call must itself run before the sink
  const outside = guardDominatesSink({ lines, guardIdx: callIdx, sinkIdx, file, depth: depth + 1 });
  if (!outside.dominates) return result(false, `callee-not-forced-before-sink:${outside.reason}`);
  return result(true, 'validator-helper-called-before-sink');
}

/** Is the guard on every path to the end of its own function? */
function guardForcedBeforeExit(lines, guardIdx, fn, indentStyle) {
  const gl = code(lines[guardIdx]);
  if (DATA_DECL.test(gl)) return { ok: false, reason: 'data-declaration-not-a-check' };
  // The guard must sit at the function body's own nesting level, not inside an `if`, loop or `try` of its own.
  if (indentStyle) {
    let bodyIndent = -1;
    for (let i = fn.declIdx + 1; i <= fn.endIdx; i++) if (!blank(lines[i])) { bodyIndent = indentOf(lines[i]); break; }
    if (indentOf(lines[guardIdx]) !== bodyIndent) return { ok: false, reason: 'guard-nested-in-helper' };
  } else {
    let depth = 0; let opened = false;
    for (let i = fn.declIdx; i < guardIdx; i++) {
      for (const ch of code(lines[i])) { if (ch === '{') { depth++; opened = true; } else if (ch === '}') depth--; }
    }
    if (!opened || depth !== 1) return { ok: false, reason: 'guard-nested-in-helper' };
  }
  const conditional = CONDITIONAL_HEAD.test(gl);
  if (!conditional) return { ok: true, reason: 'straight-line-in-helper' };
  if (branchExits(lines, guardIdx, indentStyle)) return { ok: true, reason: 'failing-branch-exits' };
  return { ok: false, reason: 'failing-branch-does-not-exit' };
}

const LITERAL_ASSIGN = /^\s*(?:[\w$.]+\s+)?([A-Za-z_$][\w$]*(?:\.[\w$]+)*)\s*=\s*(?:'[^']*'|"[^"]*"|`[^`]*`|""|null|None|nil|undefined|false|0)\s*;?\s*$/;
const identsOf = (text) => new Set((String(text).match(/[A-Za-z_$][\w$]*/g) || []).map((x) => x.replace(/^\$/, '')));

/**
 * Does the failing branch REPLACE the value the condition checked with a literal (`if (bad($next)) { $next = "/"; }`)? Then no path reaches
 * the sink carrying the unchecked value, which is what a guard is for. The assigned name must be one the condition names.
 */
function branchNeutralizes(lines, guardIdx, indentStyle) {
  const gl = code(lines[guardIdx]);
  const checked = identsOf(gl.replace(/^\s*(?:\}\s*)?(?:else\s+)?(?:if|unless|elif|elsif|while|until|when|guard)\b/, ''));
  const bodyIdx = [];
  if (indentStyle) {
    const gi = indentOf(lines[guardIdx]);
    for (let i = guardIdx + 1; i < lines.length; i++) { if (blank(lines[i])) continue; if (indentOf(lines[i]) <= gi) break; bodyIdx.push(i); }
  } else {
    const block = branchRange(lines, guardIdx);
    if (block) for (let i = block.start; i <= block.end; i++) bodyIdx.push(i);
  }
  for (const i of bodyIdx) {
    const stmt = code(lines[i]).replace(/^[^{]*\{/, '').replace(/\}\s*$/, '');
    for (const part of stmt.split(';')) {
      const m = LITERAL_ASSIGN.exec(part.trim());
      if (m && checked.has(m[1].replace(/^\$/, '').split('.')[0])) return true;
    }
  }
  return false;
}

/** Does the branch a conditional guard opens leave the function (throw, return, exit, abort)? Polarity is not judged. */
function branchExits(lines, guardIdx, indentStyle) {
  if (branchNeutralizes(lines, guardIdx, indentStyle)) return true;
  const gl = code(lines[guardIdx]);
  if (indentStyle) {
    if (MODIFIER_EXIT.test(gl)) return true;
    const gi = indentOf(lines[guardIdx]);
    if (/:\s*\S/.test(gl) && TERMINATOR.test(gl.slice(gl.lastIndexOf(':') + 1))) return true;
    const body = [];
    for (let i = guardIdx + 1; i < lines.length; i++) { if (blank(lines[i])) continue; if (indentOf(lines[i]) <= gi) break; body.push(i); }
    const inner = body.length ? indentOf(lines[body[0]]) : -1;
    return body.some((i) => indentOf(lines[i]) === inner && TERMINATOR.test(code(lines[i])));
  }
  const block = branchRange(lines, guardIdx);
  const afterCond = gl.replace(/^\s*(?:\}\s*)?(?:else\s+)?(?:if|unless|elif|elsif|while|until|when|guard)\b/, '');
  if (!block || block.start === guardIdx) {
    if (TERMINATOR.test(afterCond.replace(/^\s*\([^)]*\)/, '')) || /\breturn\b|\bthrow\b/.test(afterCond)) return true;
  }
  return !!(block && branchTerminates(lines, block));
}

function braceDominates(lines, guardIdx, sinkIdx, gl) {
  // Depth at the START of each line, relative to the guard line's own start.
  const depthStart = new Array(sinkIdx - guardIdx + 2).fill(0);
  let depth = 0;
  for (let i = guardIdx; i <= sinkIdx; i++) {
    depthStart[i - guardIdx] = depth;
    const c = code(lines[i]);
    const { open, close } = countBraces(c);
    depth += open - close;
  }
  // The guard's enclosing block must still be open at the sink: nothing between may dip below the guard's own level.
  for (let i = guardIdx + 1; i <= sinkIdx; i++) {
    if (depthStart[i - guardIdx] < 0) return result(false, 'guard-block-closed-before-sink');
  }

  if (!CONDITIONAL_HEAD.test(gl) && !/\?[^:]*:/.test(gl)) return result(true, 'straight-line-before-sink');
  if (/\?[^:]*:/.test(gl) && !CONDITIONAL_HEAD.test(gl)) return result(false, 'unknown-shape');

  // A conditional guard. Case 1: the sink sits INSIDE the branch the condition opens.
  const block = branchRange(lines, guardIdx);
  if (block && sinkIdx > block.start && sinkIdx <= block.end) return result(true, 'sink-inside-guarded-branch');
  // Case 2: the condition guards an early exit and the sink comes after it.
  const afterCond = gl.replace(/^\s*(?:\}\s*)?(?:else\s+)?(?:if|unless|elif|elsif|while|until|when|guard)\b/, '');
  if (!block || block.start === guardIdx) {
    // Single-line form: `if (!allowed(h)) return;` : an exit on the same line, after the condition.
    if (TERMINATOR.test(afterCond.replace(/^\s*\([^)]*\)/, '')) || /\breturn\b|\bthrow\b/.test(afterCond)) return result(true, 'early-exit-on-guard-line');
  }
  if (block && branchTerminates(lines, block)) return result(true, 'failing-branch-exits');
  if (branchNeutralizes(lines, guardIdx, false)) return result(true, 'failing-branch-neutralizes-value');
  return result(false, 'failing-branch-does-not-exit');
}

/** [start, end] line indices of the `{ ... }` block opened at or after `idx`, or null. */
function branchRange(lines, idx) {
  let depth = 0; let start = -1;
  for (let i = idx; i < Math.min(lines.length, idx + 40); i++) {
    const c = code(lines[i]);
    for (const ch of c) {
      if (ch === '{') { if (start < 0) start = i; depth++; }
      else if (ch === '}') { depth--; if (start >= 0 && depth === 0) return { start, end: i }; }
    }
    // A brace-less single statement ends the search at the next line that is not part of the condition.
    if (start < 0 && i > idx && !/[(&|,]\s*$/.test(code(lines[i - 1]))) return null;
  }
  return null;
}

function branchTerminates(lines, block) {
  let depth = 0;
  for (let i = block.start; i <= block.end; i++) {
    const c = code(lines[i]);
    // Only a statement at the branch's own top level counts: a `return` buried in a nested `if` inside it does not stop the branch.
    const startDepth = depth;
    depth += countBraces(c).open - countBraces(c).close;
    const topLevel = i === block.start ? true : startDepth === 1;
    if (topLevel && TERMINATOR.test(i === block.start ? c.slice(c.indexOf('{') + 1) : c)) return true;
  }
  return false;
}

function indentDominates(lines, guardIdx, sinkIdx, gl) {
  const gi = indentOf(lines[guardIdx]);
  // The guard's block must still enclose the sink: no non-blank line between may be LESS indented than the guard.
  for (let i = guardIdx + 1; i <= sinkIdx; i++) {
    if (blank(lines[i])) continue;
    if (indentOf(lines[i]) < gi) return result(false, 'guard-block-closed-before-sink');
  }
  if (MODIFIER_EXIT.test(gl)) return result(true, 'early-exit-on-guard-line');
  const head = CONDITIONAL_HEAD.test(gl) || /\bif\b|\bunless\b/.test(gl) && /:\s*$/.test(gl);
  if (!head) return result(true, 'straight-line-before-sink');

  // A conditional: collect the indented block that follows the header.
  const bodyLines = [];
  for (let i = guardIdx + 1; i < lines.length; i++) {
    if (blank(lines[i])) continue;
    if (indentOf(lines[i]) <= gi) break;
    bodyLines.push(i);
  }
  if (bodyLines.includes(sinkIdx) || (bodyLines.length && sinkIdx > bodyLines[0] && sinkIdx <= bodyLines[bodyLines.length - 1])) {
    return result(true, 'sink-inside-guarded-branch');
  }
  // One-liner `if not ok(x): raise ...`.
  const afterColon = gl.slice(gl.lastIndexOf(':') + 1);
  if (/:\s*\S/.test(gl) && TERMINATOR.test(afterColon)) return result(true, 'early-exit-on-guard-line');
  // Direct statements of the block (one indent level in) that exit.
  const inner = bodyLines.length ? indentOf(lines[bodyLines[0]]) : -1;
  if (bodyLines.some((i) => indentOf(lines[i]) === inner && TERMINATOR.test(code(lines[i])))) return result(true, 'failing-branch-exits');
  if (branchNeutralizes(lines, guardIdx, true)) return result(true, 'failing-branch-neutralizes-value');
  return result(false, 'failing-branch-does-not-exit');
}
