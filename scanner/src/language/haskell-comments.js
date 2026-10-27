// Haskell comments, found lexically. Used so that text a finding carries from the source (its snippet, and through it the identity and the
// clone-shape of the finding) is the CODE of the line and never a comment on it: a verdict, an id and a cluster must not change because someone
// edited, or lied in, a comment. Strings, character literals and pragmas are not comments; a run of dashes inside an operator (`-->`, `|--`) is
// not a comment; block comments nest.

const SYMBOL = new Set([...'!#$%&*+./<=>?@\\^|~:-']);
const IDENT = /[A-Za-z0-9_']/;

/** The comments of a Haskell source: [{start, end, kind}] with `end` exclusive. */
export function findComments(src) {
  const out = [];
  const n = src.length;
  let i = 0;
  while (i < n) {
    const c = src[i];
    if (c === '"') {   // string literal
      i++;
      while (i < n && src[i] !== '"') { if (src[i] === '\\') i++; i++; }
      i++;
      continue;
    }
    if (c === "'" && !(i > 0 && IDENT.test(src[i - 1]))) {   // character literal (a prime after an identifier character is part of the name)
      const m = /^'(?:\\(?:[^']|x[0-9A-Fa-f]+|[0-9]+|[A-Z]+)|[^'\\])'/.exec(src.slice(i, i + 12));
      if (m) { i += m[0].length; continue; }
    }
    if (c === '{' && src[i + 1] === '-' && src[i + 2] !== '#') {
      let depth = 1; const start = i; i += 2;
      while (i < n && depth > 0) {
        if (src[i] === '{' && src[i + 1] === '-') { depth++; i += 2; } else if (src[i] === '-' && src[i + 1] === '}') { depth--; i += 2; } else i++;
      }
      out.push({ start, end: i, kind: 'block' });
      continue;
    }
    if (c === '-' && src[i + 1] === '-') {
      let j = i; while (j < n && src[j] === '-') j++;
      const prevSym = i > 0 && SYMBOL.has(src[i - 1]) && src[i - 1] !== '-';
      const nextSym = j < n && SYMBOL.has(src[j]);
      if (!prevSym && !nextSym) {
        let e = j; while (e < n && src[e] !== '\n') e++;
        out.push({ start: i, end: e, kind: 'line' });
        i = e;
        continue;
      }
      i = j;
      continue;
    }
    i++;
  }
  return out;
}

const blank = (text) => text.replace(/[^\n]/g, ' ');

/** The source with every comment overwritten by spaces: same length, same line breaks, so locations do not move. */
export function stripComments(src) {
  let out = ''; let at = 0;
  for (const c of findComments(src)) { out += src.slice(at, c.start) + blank(src.slice(c.start, c.end)); at = c.end; }
  return out + src.slice(at);
}

/** One source line without its comments, trimmed. A block comment that opened on an earlier line is not known here; a line that is only a comment becomes ''. */
export function codeOfLine(line) {
  if (typeof line !== 'string') return '';
  return stripComments(line).trim();
}
