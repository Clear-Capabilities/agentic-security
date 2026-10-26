// Is a source position inside a function body, or at module/initialisation
// level? Some hazards exist only while the process is serving work: a blocking
// call made once at module load (reading a TLS key, a config file) delays
// startup once, and nothing is waiting on the event loop yet. The same call in
// a request callback stalls every connection.
//
// A position is inside a function when it is inside
//   * a `{ ... }` block opened by `=>`, a `function` header, a method or class
//     member header (`name(params) {`), or an async/generator form,
//   * the body of an expression-bodied arrow (`(p) => fs.readFileSync(p)`),
//     which runs when the arrow is CALLED, not where it is written, or
//   * a class body (field initialisers run per instance).
// Plain blocks (`if`, `for`, `try`, `else`) and object literals are not function scopes.
//
// Operates on a comment- and string-blanked view so braces in strings or
// comments never count. It is a lexical approximation (no parse). The one error
// that matters is calling a function body "module level", because that hides a
// finding, so a block is classed as a function unless it is positively a control
// block or a literal, and parameter lists are matched by bracket depth, not by a
// pattern that stops at a fixed nesting.

const CONTROL_KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'with', 'else', 'try', 'finally', 'do']);
const CLASS_HEAD = /\bclass\b\s*[\w$]*(?:\s+extends\s+[\w$.()]+)?\s*$/;

/** Index of the '(' matching the ')' at `closeIdx`, scanning backwards; -1 if unbalanced. */
function matchingOpenParen(text, closeIdx) {
  let depth = 0;
  for (let i = closeIdx; i >= 0; i--) {
    const c = text[i];
    if (c === ')') depth++;
    else if (c === '(') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function opensFunction(text, braceIdx) {
  let end = braceIdx;
  while (end > 0 && /\s/.test(text[end - 1])) end--;
  const before = text.slice(Math.max(0, end - 400), end);
  if (/=>$/.test(before)) return true;
  if (CLASS_HEAD.test(before)) return true;
  // `else {`, `try {`, `finally {`, `do {`, `catch {` carry no parenthesised head
  const bare = /(?:^|[^\w$.])([A-Za-z_$][\w$]*)$/.exec(before);
  if (bare && CONTROL_KEYWORDS.has(bare[1])) return false;
  // find the ')' that ends a parameter list, allowing a return type annotation `): Type {`
  let closeIdx = end - 1;
  if (text[closeIdx] !== ')') {
    const m = /\)\s*:\s*[^(){};=]*$/.exec(before);
    if (!m) return false;
    closeIdx = end - before.length + m.index;
  }
  const openIdx = matchingOpenParen(text, closeIdx);
  if (openIdx < 0) return true; // cannot match the head: keep findings, so call it a function
  const head = text.slice(Math.max(0, openIdx - 80), openIdx).replace(/\s+$/, '');
  const word = /([A-Za-z_$][\w$]*)$/.exec(head);
  if (word) return !CONTROL_KEYWORDS.has(word[1]); // `if (` `while (` ...: control; any other name( ... ) { is a function or method
  if (/\bfunction\s*\*?$/.test(head)) return true; // `function (` and `function* (`
  return false;
}

/**
 * @param {string} blanked  source with comments and string bodies blanked
 * @param {number} offset   index into `blanked`
 * @returns {boolean} true when `offset` is lexically inside a function body
 */
export function insideFunctionBody(blanked, offset) {
  // entries: 'F' function block, 'B' other block, 'P' paren/bracket, 'A' expression-bodied arrow
  const stack = [];
  const end = Math.min(offset, blanked.length);
  for (let i = 0; i < end; i++) {
    const c = blanked[i];
    if (c === '{') stack.push(opensFunction(blanked, i) ? 'F' : 'B');
    else if (c === '(' || c === '[') stack.push('P');
    else if (c === '}' || c === ')' || c === ']') {
      while (stack.length && stack[stack.length - 1] === 'A') stack.pop(); // an arrow body ends where its enclosing bracket closes
      stack.pop();
    } else if ((c === ',' || c === ';') && stack[stack.length - 1] === 'A') {
      stack.pop(); // ... or at a separator at its own nesting level
    } else if (c === '=' && blanked[i + 1] === '>') {
      let j = i + 2;
      while (j < blanked.length && /\s/.test(blanked[j])) j++;
      if (blanked[j] !== '{') stack.push('A');
      i++;
    }
  }
  return stack.some((e) => e === 'F' || e === 'A');
}
