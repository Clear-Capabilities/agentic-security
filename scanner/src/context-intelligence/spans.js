//
// Source-span computation. The shared IR records where a function STARTS and the lines of its CFG nodes, but not where
// it ends, and a context bundle must quote whole declarations. Ends are therefore derived from the source text here,
// and every derived end says how it was derived (`precision`), because a bundle that quietly cut a function short
// would drop a guard without anyone being told.
//
//   brace        a balanced `{ ... }` body was found after the declaration start
//   indent       the body is the run of lines indented deeper than the declaration (Python, Haskell, Nix, Ruby-ish)
//   cfg-lower-bound  neither worked; the last CFG line is a LOWER bound and the span is flagged as uncertain

const BRACE_LANG = /\.(?:js|jsx|mjs|cjs|ts|tsx|java|cs|kt|go|php|phtml|rs|c|cc|cpp|cxx|h|hpp)$/i;
const INDENT_LANG = /\.(?:py|l?hs|nix|rb)$/i;

function indentOf(line) {
  const m = /^[ \t]*/.exec(line)[0];
  return m.replace(/\t/g, '    ').length;
}

/** Find the line of the `}` that closes the first `{` at or after startLine. Skips strings and comments. */
function braceEnd(lines, startLine) {
  let depth = 0;
  let opened = false;
  let inBlock = false;
  for (let i = startLine - 1; i < lines.length; i++) {
    const s = lines[i];
    let quote = null;
    for (let j = 0; j < s.length; j++) {
      const c = s[j];
      const n = s[j + 1];
      if (inBlock) { if (c === '*' && n === '/') { inBlock = false; j++; } continue; }
      if (quote) {
        if (c === '\\') { j++; continue; }
        if (c === quote) quote = null;
        continue;
      }
      if (c === '/' && n === '/') break;
      if (c === '/' && n === '*') { inBlock = true; j++; continue; }
      if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
      if (c === '{') { depth++; opened = true; }
      else if (c === '}') {
        depth--;
        if (opened && depth === 0) return i + 1;
      }
    }
    // A declaration with no brace on its first lines is not a braced body (an arrow expression, an abstract method).
    if (!opened && i - (startLine - 1) > 6) return null;
    // A statement that ended before any brace opened (`foo();`) has no body to close.
    if (!opened && /;\s*$/.test(s) && i >= startLine - 1) return null;
  }
  return null;
}

function indentEnd(lines, startLine) {
  const base = indentOf(lines[startLine - 1] || '');
  let end = startLine;
  for (let i = startLine; i < lines.length; i++) {
    const s = lines[i];
    if (s.trim() === '') continue;
    if (indentOf(s) > base) end = i + 1;
    else break;
  }
  return end;
}

/**
 * { startLine, endLine, precision } for a declaration that begins at `line`. `cfgMax` is the largest CFG line seen
 * for that function (or 0). Decorators / annotations / attributes immediately above the declaration are included in
 * the span: they ARE the guard on many frameworks (`@login_required`, `@PreAuthorize`).
 */
export function spanFor(file, lines, line, cfgMax = 0) {
  let start = Math.max(1, line);
  // pull in contiguous decorator/annotation lines directly above
  while (start > 1 && /^\s*(?:@[A-Za-z_]|\[[A-Z]\w*[\](,])/.test(lines[start - 2] || '')) start--;
  let end = null;
  let precision = 'cfg-lower-bound';
  if (BRACE_LANG.test(file)) {
    end = braceEnd(lines, line);
    if (end) precision = 'brace';
  }
  if (!end && INDENT_LANG.test(file)) {
    end = indentEnd(lines, line);
    precision = 'indent';
  }
  if (!end) end = Math.max(line, cfgMax || line);
  end = Math.min(end, lines.length);
  return { startLine: start, endLine: Math.max(end, start), precision };
}

/** Indentation block starting at a registration line: the line plus every following line indented deeper. */
export function inlineBlockSpan(lines, line) {
  return { startLine: line, endLine: indentEnd(lines, line), precision: 'indent' };
}

/** Balanced `( ... )` statement text starting at the first `(` on or after `line`. { text, endLine } or null. */
export function callStatement(lines, line, maxLines = 40) {
  let depth = 0;
  let opened = false;
  let quote = null;
  let text = '';
  for (let i = line - 1; i < Math.min(lines.length, line - 1 + maxLines); i++) {
    const s = lines[i];
    for (let j = 0; j < s.length; j++) {
      const c = s[j];
      text += c;
      if (quote) {
        if (c === '\\') { text += s[j + 1] || ''; j++; continue; }
        if (c === quote) quote = null;
        continue;
      }
      if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
      if (c === '(') { depth++; opened = true; }
      else if (c === ')') {
        depth--;
        if (opened && depth === 0) return { text, endLine: i + 1 };
      }
    }
    text += '\n';
  }
  return null;
}

/** Split the arguments of a call text at top-level commas. Returns trimmed argument strings. */
export function splitArgs(callText) {
  const open = callText.indexOf('(');
  if (open < 0) return [];
  const body = callText.slice(open + 1, callText.lastIndexOf(')') >= 0 ? callText.lastIndexOf(')') : undefined);
  const args = [];
  let depth = 0;
  let quote = null;
  let cur = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (quote) {
      cur += c;
      if (c === '\\') { cur += body[i + 1] || ''; i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; cur += c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) { args.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) args.push(cur.trim());
  return args;
}
