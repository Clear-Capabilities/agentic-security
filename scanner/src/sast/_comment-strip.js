// Replace comments with same-length whitespace (newlines preserved) so that
// character indices in the returned string match the original source one-to-one.
// Required by detectors that emit `line = lineOf(raw, m.index)` after running
// regexes against a comment-stripped view.
//
// Recognises:
//   - JS/TS/Java/Go/C/C++/Rust line comments  // ...
//   - JS/TS/Java/Go/C/C++/Rust block comments /* ... */
//   - Python line comments                    # ...
//
// Skips comment-like content inside string literals (single/double/backtick).
//
// The `lang` parameter is optional; pass 'py' to treat `#` as a line comment.

export function blankComments(s, lang) {
  let out = '';
  let inS = null;
  let i = 0;
  const isPy = lang === 'py';
  while (i < s.length) {
    const c = s[i];
    if (inS) {
      out += c;
      if (c === '\\' && i + 1 < s.length) { out += s[i+1]; i += 2; continue; }
      if (c === inS) inS = null;
      i++; continue;
    }
    if (c === "'" || c === '"' || c === '`') { inS = c; out += c; i++; continue; }
    if (!isPy && c === '/' && s[i+1] === '/') {
      while (i < s.length && s[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    if (!isPy && c === '/' && s[i+1] === '*') {
      const end = s.indexOf('*/', i + 2);
      const stop = end < 0 ? s.length : end + 2;
      while (i < stop) { out += (s[i] === '\n' ? '\n' : ' '); i++; }
      continue;
    }
    if (isPy && c === '#') {
      while (i < s.length && s[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    out += c; i++;
  }
  return out;
}
