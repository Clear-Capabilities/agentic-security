// The `address` a `listen` callback receives.
//
//   server.listen({ port }, (err, address) => console.log(`listening on ${address}`))
//
// `address` here is the socket address the server just bound (host and port),
// handed to the callback by the server. It is not a person's postal address, so a
// rule that classifies a value by the NAME `address` must not treat this binding
// as personal data. The rule is about the binding site, not about the word: the
// same name bound anywhere else (a form field, a column, a request property) is
// unaffected.

/** Index just past the paren that closes the one opened at `openIdx`, or -1 when the text ends first. */
function closeOfParen(text, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') {
      const q = c; i++;
      while (i < text.length && text[i] !== q) { if (text[i] === '\\') i++; i++; }
    } else if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return i + 1; }
  }
  return -1;
}

/**
 * Is the identifier at `idx` in `raw` a parameter declared by a callback passed
 * to a `.listen(` call? `idx` is any position at or after the callback header
 * (the use site); the header is searched backwards within a bounded window, and
 * must sit inside the listen call's own parentheses, so a function declared after
 * the call has closed does not count.
 */
export function isListenCallbackParam(raw, idx, name) {
  if (typeof raw !== 'string' || !name) return false;
  const from = Math.max(0, idx - 800);
  const at = raw.slice(from, idx).lastIndexOf('.listen(');
  if (at < 0) return false;
  const start = from + at;
  const openIdx = start + '.listen'.length;
  const windowEnd = idx + name.length + 80;
  const close = closeOfParen(raw.slice(start, windowEnd), openIdx - start);
  // the call closed before the use site: the use is not inside the callback
  if (close !== -1 && start + close <= idx) return false;
  const after = raw.slice(start, close === -1 ? windowEnd : Math.min(windowEnd, start + close));
  const id = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const arrow = new RegExp(String.raw`\([^)]*\b${id}\b[^)]*\)\s*=>|\b${id}\s*=>`);
  const fn = new RegExp(String.raw`\bfunction\b[^(]*\([^)]*\b${id}\b[^)]*\)`);
  return arrow.test(after) || fn.test(after);
}
