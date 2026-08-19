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
//   - Ruby: `#` line comments PLUS `=begin` / `=end` block comments, which
//     must start at column 0. No other supported language has this form, so a
//     `#`-only pass leaves the whole block intact and every dangerous
//     construct inside it reads as live code.
//
// The `lang` parameter is optional; pass 'py' to treat `#` as a line comment
// (and skip `//`/`/* */`), 'rb' for Python's `#` handling plus Ruby's
// `=begin`/`=end` blocks, or 'php' to strip all three comment forms.

// PERFORMANCE. This runs on every scanned file, and `engine.js` calls it
// through `stripNoise` roughly fifteen times per file, so it sits directly on
// the hot path. The original implementation appended ONE CHARACTER AT A TIME
// (`out += c`) for the whole file, which measured a 19.7% end-to-end scan
// regression on a 307-file entry once it replaced the old native-regex
// stripper.
//
// This version keeps the identical state machine — it must still inspect every
// character to know whether a `//` sits inside a string literal — but emits
// output in BULK: untouched code is pushed as a single `slice()` of the input,
// and only the comment runs (a small minority of any real file) are rewritten,
// via a native regex for the newline-preserving cases. Characters are scanned;
// they are no longer individually concatenated.
export function blankComments(s, lang) {
  const parts = [];
  let verbatimFrom = 0;   // start of the run of input not yet emitted as-is
  let inS = null;
  let i = 0;
  const isRb = lang === 'rb';
  const isPy = lang === 'py' || isRb;
  const isPhp = lang === 'php';
  const stripSlashForms = !isPy || isPhp;
  const stripHash = isPy || isPhp;
  // Flush the pending verbatim run, then blank [start, end) with newlines kept
  // so every byte offset and line number in the output still matches the input.
  const blank = (start, end) => {
    if (start > verbatimFrom) parts.push(s.slice(verbatimFrom, start));
    parts.push(s.slice(start, end).replace(/[^\n]/g, ' '));
    verbatimFrom = end;
  };
  while (i < s.length) {
    const c = s[i];
    if (inS) {
      // A `'` or `"` string cannot span a line in any language handled here, so
      // a newline ends it. Without this reset an ODD number of quotes on one
      // line — which regex literals produce routinely, e.g.
      // `/"(?:sh|bash)"\s*,\s*(?!"[^"]*")/` — leaves the scanner stuck in
      // string mode for the WHOLE REST OF THE FILE, silently disabling comment
      // stripping from that point on. Measured on this repo's own
      // `sast/go-extended.js`, where it resurrected a false positive out of a
      // comment six lines below the regex.
      //
      // Backticks are exempt: JS template literals and Go raw strings are
      // genuinely multi-line. Erring toward "this is code" is the safe
      // direction — the failure it causes is a stripped comment, whereas the
      // opposite error hides every subsequent comment in the file.
      if (c === '\n' && inS !== '`') { inS = null; i++; continue; }
      if (c === '\\' && i + 1 < s.length) { i += 2; continue; }
      if (c === inS) inS = null;
      i++; continue;
    }
    // Ruby `=begin` … `=end`: only recognised at the start of a line, which is
    // what makes it distinguishable from an ordinary `=` assignment.
    if (isRb && c === '=' && (i === 0 || s[i - 1] === '\n') && s.startsWith('=begin', i)) {
      let end = i;
      for (;;) {
        const nl = s.indexOf('\n', end);
        if (nl < 0) { end = s.length; break; }
        if (s.startsWith('=end', nl + 1)) {
          const after = s.indexOf('\n', nl + 1);
          end = after < 0 ? s.length : after;
          break;
        }
        end = nl + 1;
      }
      blank(i, end);
      i = end;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { inS = c; i++; continue; }
    if (stripSlashForms && c === '/' && s[i+1] === '/') {
      const nl = s.indexOf('\n', i);
      const end = nl < 0 ? s.length : nl;
      blank(i, end);
      i = end;
      continue;
    }
    if (stripSlashForms && c === '/' && s[i+1] === '*') {
      const close = s.indexOf('*/', i + 2);
      const end = close < 0 ? s.length : close + 2;
      blank(i, end);
      i = end;
      continue;
    }
    // PHP 8 attributes (`#[Route(...)]`) use the same `#` prefix as a line
    // comment — `#[` is never a comment, so don't blank it.
    if (stripHash && c === '#' && s[i+1] !== '[') {
      const nl = s.indexOf('\n', i);
      const end = nl < 0 ? s.length : nl;
      blank(i, end);
      i = end;
      continue;
    }
    i++;
  }
  if (verbatimFrom < s.length) parts.push(s.slice(verbatimFrom));
  return parts.join('');
}
