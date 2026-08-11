// Replace comments with same-length whitespace (newlines preserved) so that
// character indices in the returned string match the original source one-to-one.
// Required by detectors that emit `line = lineOf(raw, m.index)` after running
// regexes against a comment-stripped view.
//
// Recognises:
//   - JS/TS/Java/Go/C/C++/Rust line comments  // ...
//   - JS/TS/Java/Go/C/C++/Rust block comments /* ... */
//   - Python line comments                    # ...
//   - PHP: all three of the above — `//`, `/* */`, AND `#` are all valid
//     PHP line/block comment forms simultaneously (unlike Python, which
//     only has `#`), so PHP needs its own mode rather than reusing 'py'
//     (which would strip `#` but silently leave `//`/`/* */` PHP comments
//     unstripped — a source of false positives on commented-out code).
//
// Skips comment-like content inside string literals (single/double/backtick).
//
// The `lang` parameter is optional; pass 'py' to treat `#` as a line comment
// (and skip `//`/`/* */`), or 'php' to strip all three comment forms.

export function blankComments(s, lang) {
  let out = '';
  let inS = null;
  let i = 0;
  const isPy = lang === 'py';
  const isPhp = lang === 'php';
  const stripSlashForms = !isPy || isPhp;
  const stripHash = isPy || isPhp;
  while (i < s.length) {
    const c = s[i];
    if (inS) {
      out += c;
      if (c === '\\' && i + 1 < s.length) { out += s[i+1]; i += 2; continue; }
      if (c === inS) inS = null;
      i++; continue;
    }
    if (c === "'" || c === '"' || c === '`') { inS = c; out += c; i++; continue; }
    if (stripSlashForms && c === '/' && s[i+1] === '/') {
      while (i < s.length && s[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    if (stripSlashForms && c === '/' && s[i+1] === '*') {
      const end = s.indexOf('*/', i + 2);
      const stop = end < 0 ? s.length : end + 2;
      while (i < stop) { out += (s[i] === '\n' ? '\n' : ' '); i++; }
      continue;
    }
    // PHP 8 attributes (`#[Route(...)]`) use the same `#` prefix as a line
    // comment — `#[` is never a comment, so don't blank it.
    if (stripHash && c === '#' && s[i+1] !== '[') {
      while (i < s.length && s[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    out += c; i++;
  }
  return out;
}
