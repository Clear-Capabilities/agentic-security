// Inline suppression pragmas for Haskell and Nix (X-013).
//
//   Haskell   `-- agentic-security-ignore: rule-a, rule-b`    and    `{- agentic-security-ignore: rule-a -}`
//   Nix       `# agentic-security-ignore: rule-a`            and    `/* agentic-security-ignore: rule-a */`
//
// A pragma is recognised only INSIDE A COMMENT, so the same words in a string literal, an identifier or an operator
// (`-->` is an operator in Haskell, not a comment) never suppress anything. Comment boundaries come from a small
// scanner that knows each language's strings, nesting and interpolation, not from a regular expression over the line.
//
// Scope: LINE. A pragma applies to findings reported on the line it sits on, exactly like the pragmas of the other
// languages. With rule ids it suppresses only a finding whose rule, id, family, CWE or title slug EQUALS one of them
// (exact token match, never a substring: `cmd` must not silence `cmdi`). A bare pragma suppresses every finding on its
// line. A pragma whose rule list is malformed (anything other than ids separated by commas or spaces) suppresses
// nothing and is reported back as `malformed`, so it cannot silence an unrelated finding by accident.

const MARK = /agentic-security-ignore(?![A-Za-z0-9_-])/;
const RULE_ID = /^[A-Za-z0-9_.:/\-]+$/;

/**
 * Comment spans of a Haskell source: [{start, end, text}] in source offsets.
 * Strings ("..." with escapes, string gaps) and character literals are skipped; `--` starts a line comment only when
 * it is not part of a longer operator symbol; `{- -}` nests.
 */
export function haskellComments(src) {
  const out = []; const n = src.length; let i = 0;
  const SYM = /[!#$%&*+./<=>?@\\^|~:-]/;
  while (i < n) {
    const c = src[i]; const d = src[i + 1];
    if (c === '"') { i++; while (i < n && src[i] !== '"') { if (src[i] === '\\') i++; if (src[i] === '\n') break; i++; } i++; continue; }
    if (c === "'" && /^'(?:[^'\\\n]|\\[^\n]{1,8}?)'/.test(src.slice(i, i + 12)) && !/[A-Za-z0-9_']/.test(src[i - 1] || '')) { const m = /^'(?:[^'\\\n]|\\[^\n]{1,8}?)'/.exec(src.slice(i, i + 12)); i += m[0].length; continue; }
    if (c === '{' && d === '-' && src[i + 2] !== '#') {
      let depth = 1; let j = i + 2;
      while (j < n && depth > 0) { if (src[j] === '{' && src[j + 1] === '-') { depth++; j += 2; } else if (src[j] === '-' && src[j + 1] === '}') { depth--; j += 2; } else j++; }
      out.push({ start: i, end: j, text: src.slice(i, j) }); i = j; continue;
    }
    if (c === '-' && d === '-') {
      let j = i; while (src[j] === '-') j++;
      const before = src[i - 1]; const after = src[j];
      if (!(before && SYM.test(before)) && !(after && SYM.test(after)) ) { const e = src.indexOf('\n', i); const end = e < 0 ? n : e; out.push({ start: i, end, text: src.slice(i, end) }); i = end; continue; }
      i = j; continue;
    }
    i++;
  }
  return out;
}

/**
 * Comment spans of a Nix source: `#` to end of line, and slash-star block comments. Strings `"..."` and indented strings `''...''` are
 * skipped, including their `${ ... }` interpolations, whose inner code may itself contain comments and strings.
 */
export function nixComments(src) {
  const out = []; const n = src.length;
  function scan(i, stopAtBrace) {
    let depth = 0;
    while (i < n) {
      const c = src[i]; const d = src[i + 1];
      if (stopAtBrace) { if (c === '{') depth++; else if (c === '}') { if (depth === 0) return i + 1; depth--; } }
      if (c === '#') { const e = src.indexOf('\n', i); const end = e < 0 ? n : e; out.push({ start: i, end, text: src.slice(i, end) }); i = end; continue; }
      if (c === '/' && d === '*') { const e = src.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; out.push({ start: i, end, text: src.slice(i, end) }); i = end; continue; }
      if (c === '"') { i = skipString(i + 1, '"'); continue; }
      if (c === "'" && d === "'") { i = skipString(i + 2, "''"); continue; }
      i++;
    }
    return i;
  }
  function skipString(i, close) {
    while (i < n) {
      const c = src[i]; const d = src[i + 1];
      if (close === '"') { if (c === '\\') { i += 2; continue; } if (c === '"') return i + 1; }
      else {
        if (c === "'" && d === "'") { const e = src[i + 2]; if (e === "'" || e === '$') { i += 3; continue; } if (e === '\\') { i += 4; continue; } return i + 2; }
      }
      if (c === '$' && d === '{') { i = scan(i + 2, true); continue; }
      i++;
    }
    return i;
  }
  scan(0, false);
  return out;
}

const lineStarts = (src) => { const a = [0]; for (let i = 0; i < src.length; i++) if (src[i] === '\n') a.push(i + 1); return a; };
const lineOfOffset = (starts, off) => { let lo = 0; let hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= off) lo = mid; else hi = mid - 1; } return lo + 1; };

/** Strips the comment delimiters from a comment's text. */
function commentBody(text) {
  if (text.startsWith('{-')) return text.replace(/^\{-+/, '').replace(/-+\}$/, '');
  if (text.startsWith('/*')) return text.replace(/^\/\*+/, '').replace(/\*+\/$/, '');
  if (text.startsWith('#')) return text.replace(/^#+/, '');
  return text.replace(/^--+/, '');
}

/**
 * Parses the pragma inside ONE comment body. Returns null when there is none, else
 * {bare:boolean, rules:string[], malformed:string|null}.
 */
export function parsePragma(body) {
  const m = MARK.exec(body);
  if (!m) return null;
  let rest = body.slice(m.index + m[0].length);
  // only the first line of a multi-line comment body carries the list
  rest = rest.split('\n')[0];
  // a trailing block-comment closer is not part of the list
  rest = rest.replace(/(?:-\}|\*\/)\s*$/, '');
  const hasColon = /^\s*:/.test(rest);
  rest = rest.replace(/^\s*:?/, '').trim();
  if (!rest) return hasColon ? { bare: false, rules: [], malformed: 'a pragma with a colon needs at least one rule id' } : { bare: true, rules: [], malformed: null };
  if (!hasColon && /^[A-Za-z0-9_.:/-]/.test(rest) && !/^[,\s]/.test(rest)) return { bare: false, rules: [], malformed: 'rule ids follow a colon: "agentic-security-ignore: <rule>"' };
  const toks = rest.split(/[\s,]+/).filter(Boolean);
  const bad = toks.find((t) => !RULE_ID.test(t));
  if (bad) return { bare: false, rules: [], malformed: `"${bad}" is not a rule id` };
  return { bare: false, rules: toks, malformed: null };
}

/**
 * The pragma a source carries on `line`, or null. `file` selects the comment grammar (.hs/.lhs or .nix); any other
 * file type returns null (the generic pragma handles those).
 */
export function languagePragmaOnLine(file, src, line) {
  if (typeof src !== 'string' || !Number.isInteger(line) || line < 1) return null;
  const isHs = /\.l?hs$|\.hs-boot$|\.hsc$/i.test(file || '');
  const isNix = /\.nix$/i.test(file || '');
  if (!isHs && !isNix) return null;
  const comments = isHs ? haskellComments(src) : nixComments(src);
  const starts = lineStarts(src);
  const found = [];
  for (const c of comments) {
    if (!MARK.test(c.text)) continue;
    // the line the words sit on (a block comment may span several lines)
    const off = c.start + c.text.search(MARK);
    if (lineOfOffset(starts, off) !== line) continue;
    const p = parsePragma(commentBody(c.text));
    if (p) found.push(p);
  }
  if (!found.length) return null;
  const rules = []; let bare = false; let malformed = null;
  for (const p of found) { if (p.bare) bare = true; rules.push(...p.rules); if (p.malformed) malformed = p.malformed; }
  return { bare, rules, malformed, form: isHs ? 'haskell' : 'nix' };
}

const slug = (s) => String(s || '').replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase();

/** Whether a parsed language pragma suppresses finding `f`: bare, or an EXACT match on one of its identifiers. */
export function languagePragmaSuppresses(p, f) {
  if (!p || !f) return false;
  if (p.malformed && !p.bare && !p.rules.length) return false;
  if (p.bare) return true;
  const ids = new Set([f.rule, f.id, f.family, f.cwe, f.ruleId, slug(f.vuln), typeof f.id === 'string' ? f.id.split(':')[0] : null].filter(Boolean).map((x) => String(x).toLowerCase()));
  return p.rules.some((r) => ids.has(String(r).toLowerCase()));
}
