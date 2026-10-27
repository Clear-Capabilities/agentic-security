// Helpers for the comment-invariance suite and the real-project invariance bench. Finding and blanking comments is production code
// (src/language/haskell-comments.js); this adds the adversarial rewrite: every comment replaced by text that lies about the code.
import { findComments, stripComments } from '../../src/language/haskell-comments.js';

export { findComments, stripComments };

/** Every comment becomes a lie of the given text (line breaks inside block comments are kept), and every code line gets a trailing lie. */
export function lieAboutComments(src, lie) {
  let out = ''; let at = 0;
  const comments = findComments(src);
  for (const c of comments) {
    out += src.slice(at, c.start);
    const body = src.slice(c.start, c.end);
    if (c.kind === 'line') out += `-- ${lie}`;
    else out += `{- ${lie} -}` + body.replace(/[^\n]/g, '').replace(/\n/g, '\n');
    at = c.end;
  }
  out += src.slice(at);
  // a trailing comment on every code line that has none
  const lineHasComment = new Set();
  for (const c of findComments(out)) { let l = 0; for (let k = 0; k < c.start; k++) if (out[k] === '\n') l++; lineHasComment.add(l); }
  return out.split('\n').map((line, idx) => (line.trim() && !line.trimStart().startsWith('--') && !lineHasComment.has(idx) && !/\{-|-\}/.test(line) && !/^\s*#/.test(line) ? `${line} -- ${lie}` : line)).join('\n');
}

