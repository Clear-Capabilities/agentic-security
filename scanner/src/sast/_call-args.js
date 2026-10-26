// Argument splitting for guard recognisers that must look at WHAT a call is
// given, not at the text around it. Quote- and bracket-aware; handles template
// literal substitutions. Not a parser: it answers "where does each top-level
// argument start and end" for text that begins right after a call's '('.

const isQuote = (c) => c === '"' || c === "'" || c === '`';

/**
 * Split the text that follows a call's opening paren into its top-level
 * arguments (source text, quotes intact). Returns null when the closing paren
 * is not in the text given, so a caller never reasons about a truncated call.
 */
export function callArguments(text) {
  const args = [];
  let depth = 0;
  let start = 0;
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (isQuote(c)) {
      const q = c;
      i++;
      while (i < text.length && text[i] !== q) {
        if (text[i] === '\\') { i += 2; continue; }
        if (q === '`' && text[i] === '$' && text[i + 1] === '{') {
          let d = 1; i += 2;
          while (i < text.length && d > 0) { if (text[i] === '{') d++; else if (text[i] === '}') d--; i++; }
          continue;
        }
        i++;
      }
      i++;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) {
        const last = text.slice(start, i);
        if (last.trim() !== '' || args.length > 0) args.push(last);
        return args;
      }
      depth--;
    } else if (c === ',' && depth === 0) {
      args.push(text.slice(start, i));
      start = i + 1;
    }
    i++;
  }
  // The window ended inside the call (a long callback, a wrapped call). The
  // arguments completed so far are still exactly what the call was given; the
  // unfinished last one is dropped rather than guessed. `partial` lets a caller
  // that needs the whole call refuse.
  if (args.length === 0) return null;
  args.partial = true;
  return args;
}

/**
 * Find the first call on or just after `line` (1-based) whose callee matches
 * `calleeRe` (which must end at the opening paren) and return its arguments.
 * Looks at the finding line and the next three, because a call is routinely
 * wrapped. Returns null when there is no such call or it is not closed.
 */
export function callArgumentsAt(lines, line, calleeRe) {
  if (!Array.isArray(lines) || !Number.isInteger(line) || line < 1) return null;
  const text = lines.slice(line - 1, line + 3).join('\n');
  const m = calleeRe.exec(text);
  if (!m) return null;
  return callArguments(text.slice(m.index + m[0].length));
}
