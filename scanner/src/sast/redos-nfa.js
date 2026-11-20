// ReDoS NFA analyzer — detects catastrophic backtracking in regex patterns.
//
// Builds a simplified NFA from a regex body string and detects superlinear
// ambiguity: two distinct paths through a quantifier cycle that accept the
// same character. This is the core condition for exponential backtracking.
//
// Scope: character classes, alternation, quantifiers (+*?{n,m}), groups,
// escapes, anchors. Unknown constructs → treated as safe (opaque atom).
// Body-length cap: 500 chars → skip (too complex for static analysis).
//
// Also exports extractors for Python re.compile() and Java Pattern.compile().

const MAX_BODY_LEN = 500;
// Every regular-expression metacharacter escaped, for a pattern built from a name found in the scanned source.
const reEscape = (t) => String(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Prefix marking a negated character set: NEG + 'abc' is every character except a, b and c.
const NEG = '\u0001';
// `\n` in a pattern is a line break, not the letter n.
const CONTROL_ESC = Object.freeze({ n: '\n', t: '\t', r: '\r', f: '\f', v: '\v' });
const range = (a, b) => { let o = ''; for (let c = a.codePointAt(0); c <= b.codePointAt(0); c++) o += String.fromCodePoint(c); return o; };
const DIGIT = range('0', '9');
const WORD = range('a', 'z') + range('A', 'Z') + DIGIT + '_';
const SPACE = ' \t\n\r\f\v';
// A range wider than this is not listed; the set is treated as any character (toward reporting).
const MAX_RANGE = 512;

// ── Regex parser ────────────────────────────────────────────────────────────

function parseRegex(body, { dotAll = false } = {}) {
  let pos = 0;
  const src = body;
  if (/^\(\?[a-z]*s[a-z]*\)/.test(body)) dotAll = true;

  function peek() { return pos < src.length ? src[pos] : null; }
  function advance() { return src[pos++]; }

  function parseAlternation() {
    const branches = [parseConcat()];
    while (peek() === '|') {
      advance();
      branches.push(parseConcat());
    }
    return branches.length === 1 ? branches[0] : { type: 'alt', branches };
  }

  function parseConcat() {
    const items = [];
    while (pos < src.length && peek() !== ')' && peek() !== '|') {
      items.push(parseQuantified());
    }
    return items.length === 1 ? items[0] : { type: 'concat', items };
  }

  function parseQuantified() {
    let atom = parseAtom();
    if (!atom) return { type: 'literal', ch: '' };
    while (pos < src.length) {
      const c = peek();
      if (c === '*') { advance(); atom = { type: 'star', child: atom }; }
      else if (c === '+') { advance(); atom = { type: 'plus', child: atom }; }
      else if (c === '?') { advance(); atom = { type: 'opt', child: atom }; }
      else if (c === '{') {
        const saved = pos;
        advance();
        let numStr = '';
        while (pos < src.length && /[\d,]/.test(peek())) numStr += advance();
        if (peek() === '}') {
          advance();
          const parts = numStr.split(',');
          const max = parts.length > 1 ? (parts[1] ? parseInt(parts[1]) : Infinity) : parseInt(parts[0]);
          // An exact count (`{2}`) has one way to match and is kept as its atom; a range (`{2,}`, `{1,5}`) can split
          // differently and is treated as a repetition.
          if ((parts.length > 1 && (max > 1 || max === Infinity)) || (parts.length === 1 && max > 1 && hasRepetition(atom))) {
            // A minimum of one or more keeps the repetition non-empty (`[ ]{4,}` cannot match nothing).
            atom = { type: parseInt(parts[0] || '0', 10) >= 1 ? 'plus' : 'star', child: atom };
          }
        } else {
          pos = saved;
          break;
        }
      } else break;
      if (peek() === '?') advance(); // lazy modifier
      // A possessive quantifier (`*+`, `++`, `?+`, `{n,}+`) never gives back what it matched: it is atomic, not a second `+`.
      else if (peek() === '+' && (atom.type === 'star' || atom.type === 'plus' || atom.type === 'opt')) { advance(); atom = { type: 'atomic', child: atom }; }
    }
    return atom;
  }

  function parseAtom() {
    const c = peek();
    if (c === null || c === ')' || c === '|') return null;
    if (c === '(') {
      advance();
      // A lookaround is ZERO-WIDTH: it constrains what may follow (or precede) without consuming it. It used to be read as an
      // ordinary consuming group, so `\*{2,}(?!\*)` looked like two stars in a row and the possessive-run idiom that FIXES a
      // nested quantifier was itself reported as one.
      // `(?>...)` is an atomic group: once it has matched, the engine never backtracks into it.
      if (src.slice(pos, pos + 2) === '?>') {
        pos += 2;
        const inner = parseAlternation();
        if (peek() === ')') advance();
        return { type: 'atomic', child: { type: 'group', child: inner } };
      }
      const look = src.slice(pos).match(/^\?(<?[=!])/);
      if (look) {
        pos += 1 + look[1].length;
        const inner = parseAlternation();
        if (peek() === ')') advance();
        return { type: 'assert', neg: look[1].endsWith('!'), behind: look[1].startsWith('<'), child: inner };
      }
      if (peek() === '?') {
        advance();
        // Non-capturing group, inline flags, or a named group — skip modifier chars
        while (pos < src.length && peek() !== ':' && peek() !== ')' && /[imsx<!=P]/.test(peek())) advance();
        if (peek() === ':' || peek() === ')') {
          if (peek() === ':') advance();
          if (peek() === ')') { advance(); return { type: 'literal', ch: '' }; }
        }
      }
      const inner = parseAlternation();
      if (peek() === ')') advance();
      return { type: 'group', child: inner };
    }
    if (c === '[') return parseCharClass();
    if (c === '\\') {
      advance();
      const esc = advance();
      if (!esc) return { type: 'literal', ch: '\\' };
      if (esc === 'd') return { type: 'class', chars: DIGIT };
      if (esc === 'w') return { type: 'class', chars: WORD };
      if (esc === 's') return { type: 'class', chars: SPACE };
      if (esc === 'D') return { type: 'class', chars: NEG + DIGIT };
      if (esc === 'W') return { type: 'class', chars: NEG + WORD };
      if (esc === 'S') return { type: 'class', chars: NEG + SPACE };
      if (esc === 'b' || esc === 'B') return { type: 'literal', ch: '' }; // anchor
      if (esc === 'A' || esc === 'G') return { type: 'bol' };
      if (esc === 'z' || esc === 'Z') return { type: 'eol' };
      if (/[1-9]/.test(esc)) return { type: 'backref' };
      if (CONTROL_ESC[esc]) return { type: 'literal', ch: CONTROL_ESC[esc] };
      return { type: 'literal', ch: esc };
    }
    // `.` does not match a line break unless dot-all is on (an option of the call, or an inline `(?s)`).
    if (c === '.') { advance(); return { type: 'class', chars: dotAll ? 'ANY' : NEG + '\n' }; }
    if (c === '^') { advance(); return { type: 'bol' }; }
    if (c === '$') { advance(); return { type: 'eol' }; }
    advance();
    return { type: 'literal', ch: c };
  }

  // One set member: a character, an escaped character (control, hex `\xNN`, `\uNNNN`, octal), or null for a shorthand,
  // which is added to `acc` directly.
  function classMember(acc) {
    if (peek() !== '\\') return advance();
    advance();
    const esc = advance();
    if (esc === 'd') { acc.chars += DIGIT; acc.shorthands += 1; return null; }
    if (esc === 'w') { acc.chars += WORD; acc.shorthands += 1; return null; }
    if (esc === 's') { acc.chars += SPACE; acc.shorthands += 1; return null; }
    if (esc === 'D' || esc === 'W' || esc === 'S') { acc.wide = true; acc.compl = esc; acc.shorthands += 1; return null; }
    if (esc === 'x' && /^[0-9a-fA-F]{2}/.test(src.slice(pos))) { const h = src.slice(pos, pos + 2); pos += 2; return String.fromCharCode(parseInt(h, 16)); }
    if (esc === 'u' && /^[0-9a-fA-F]{4}/.test(src.slice(pos))) { const h = src.slice(pos, pos + 4); pos += 4; return String.fromCharCode(parseInt(h, 16)); }
    if (esc && /[0-7]/.test(esc)) { let o = esc; while (o.length < 3 && /[0-7]/.test(peek() || '')) o += advance(); return String.fromCharCode(parseInt(o, 8)); }
    return CONTROL_ESC[esc] || esc || '';
  }

  function parseCharClass() {
    advance(); // [
    const acc = { chars: '', wide: false, compl: null, shorthands: 0 };
    let negated = false;
    if (peek() === '^') { negated = true; advance(); }
    if (peek() === ']') { acc.chars += advance(); }
    while (pos < src.length && peek() !== ']') {
      const lo = classMember(acc);
      if (lo == null) continue;
      // A range `a-z` lists its members; a range wider than MAX_RANGE is not listed and widens the set.
      if (peek() === '-' && src[pos + 1] !== undefined && src[pos + 1] !== ']') {
        advance();
        const hi = classMember(acc);
        if (hi == null) { acc.chars += lo + '-'; continue; }
        const span = hi.codePointAt(0) - lo.codePointAt(0);
        if (span < 0) { acc.chars += lo + hi; continue; }
        if (span > MAX_RANGE) { acc.wide = true; acc.bigRange = true; continue; }
        acc.chars += range(lo, hi);
        continue;
      }
      acc.chars += lo;
    }
    const { chars, wide, compl, shorthands } = acc;
    if (peek() === ']') advance();
    // A negated class keeps its excluded characters (`NEG` prefix) instead of widening to any character: `[^*]` and `\*` do
    // not overlap, and treating them as overlapping reported the standard disjoint-alternation fix as ambiguous.
    // `[^\W_]` is the word characters except `_`: a negated set whose only shorthand is one negated shorthand is listable
    // (the complement of a complement). Any other set mixing a negated shorthand is too wide to list and stays any character.
    if (wide && negated && compl && shorthands === 1 && !acc.bigRange) {
      const base = compl === 'W' ? WORD : compl === 'S' ? SPACE : DIGIT;
      const left = [...base].filter((ch) => !chars.includes(ch)).join('');
      return { type: 'class', chars: left || 'ANY' };
    }
    return { type: 'class', chars: wide ? 'ANY' : negated ? NEG + chars : chars };
  }

  try {
    const tree = markAtomicRuns(parseAlternation());
    return { ok: true, tree };
  } catch {
    return { ok: false, tree: null };
  }
}

function hasRepetition(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'star' || node.type === 'plus') return true;
  return hasRepetition(node.child) || (node.items || []).some(hasRepetition) || (node.branches || []).some(hasRepetition);
}

// A repetition immediately followed by a negative lookahead that forbids its own next character can only end at the end of a
// maximal run (`\*{2,}(?!\*)`, `\d+(?!\d)`): it has exactly one way to match, the possessive idiom of engines without
// possessive quantifiers. Such a run is marked `atomic` and is not a source of ambiguity.
function markAtomicRuns(node) {
  if (!node || typeof node !== 'object') return node;
  if (node.child) node.child = markAtomicRuns(node.child);
  if (node.branches) node.branches = node.branches.map(markAtomicRuns);
  if (node.type === 'concat' && Array.isArray(node.items)) {
    node.items = node.items.map(markAtomicRuns);
    for (let i = 0; i + 1 < node.items.length; i++) {
      const rep = node.items[i]; const nxt = node.items[i + 1];
      if ((rep.type === 'star' || rep.type === 'plus') && nxt.type === 'assert' && !nxt.behind) {
        const repChars = collectFirstChars(rep.child); const look = collectFirstChars(nxt.child);
        // (?!X) forbidding every run character, or (?=Y) requiring a character no run character is: the run must end
        // where the run of its characters ends.
        const ends = nxt.neg
          ? repChars.length && repChars.every((a) => a !== 'ANY' && !a.startsWith(NEG) && look.some((b) => b === 'ANY' || (!b.startsWith(NEG) && [...a].every((ch) => b.includes(ch)))))
          : repChars.length && look.length && !overlapsAny(repChars, look);
        if (ends) node.items[i] = { type: 'atomic', child: rep };
      }
    }
  }
  return node;
}

// ── Ambiguity detection ─────────────────────────────────────────────────────

function classOverlaps(a, b) {
  if (a === 'ANY' || b === 'ANY') return true;
  const na = a.startsWith(NEG); const nb = b.startsWith(NEG);
  if (na && nb) return true;
  // A negated set overlaps a positive one when the positive one holds a character the negation does not exclude.
  if (na) return [...b].some((ch) => !a.includes(ch));
  if (nb) return [...a].some((ch) => !b.includes(ch));
  for (const ch of a) {
    if (b.includes(ch)) return true;
  }
  return false;
}

function collectFirstChars(node, eolNl = false) {
  if (!node) return [];
  if (eolNl && node.type === 'eol') return ['\n'];
  switch (node.type) {
    case 'literal':
      return node.ch ? [node.ch] : [];
    case 'class':
      return [node.chars];
    case 'group':
      return collectFirstChars(node.child, eolNl);
    case 'concat': {
      // Every item up to and including the first one that cannot be empty can supply the first character: `(ab)?c` starts
      // with a or c. (It used to stop at the first item with any first character, so an optional prefix hid what follows.)
      const out = [];
      for (const item of (node.items || [])) {
        out.push(...collectFirstChars(item, eolNl));
        if (!canBeEmpty(item, eolNl)) return out;
      }
      return out;
    }
    case 'alt':
      return (node.branches || []).flatMap((b) => collectFirstChars(b, eolNl));
    case 'star':
    case 'plus':
    case 'opt':
    case 'atomic':
      return collectFirstChars(node.child, eolNl);
    default:
      return [];
  }
}

function canBeEmpty(node, eolNl = false) {
  if (!node) return true;
  if (eolNl && node.type === 'eol') return false;
  switch (node.type) {
    case 'literal': return !node.ch;
    case 'class': return false;
    case 'group': return canBeEmpty(node.child, eolNl);
    case 'concat': return (node.items || []).every((x) => canBeEmpty(x, eolNl));
    case 'alt': return (node.branches || []).some((x) => canBeEmpty(x, eolNl));
    case 'star': case 'opt': return true;
    case 'plus': case 'atomic': return canBeEmpty(node.child, eolNl);
    case 'assert': case 'bol': case 'eol': case 'backref': return true;
    default: return false;
  }
}

const overlapsAny = (as, bs) => as.some((a) => bs.some((b) => classOverlaps(a, b)));

/** For a branch that starts with one required literal character, that character and the sets that can come next; else null. */
function afterLeadingChar(node) {
  let n = node;
  while (n && n.type === 'group') n = n.child;
  if (!n || n.type !== 'concat' || n.items.length < 2) return null;
  const [first, second] = n.items;
  if (first.type !== 'literal' || !first.ch || first.ch.length !== 1) return null;
  if (canBeEmpty(second)) return null;
  return { lead: first.ch, next: collectFirstChars(second) };
}

/** The character sets a branch's leading positive lookbehind requires before it, or null. */
function leadingLookbehind(node) {
  let n = node;
  while (n && n.type === 'group') n = n.child;
  const first = n && n.type === 'concat' ? n.items[0] : n;
  if (first && first.type === 'assert' && first.behind && !first.neg) { const fc = collectFirstChars(first.child); return fc.length && !fc.includes('ANY') ? fc : null; }
  return null;
}

/** Is there a repetition inside `node` whose characters overlap what may follow it (`follow`, char sets)? */
function nestedRunAmbiguous(node, follow) {
  if (!node) return false;
  switch (node.type) {
    case 'group': case 'opt': return nestedRunAmbiguous(node.child, follow);
    case 'alt': return (node.branches || []).some((b) => nestedRunAmbiguous(b, follow));
    case 'concat': {
      const items = node.items || [];
      let f = follow;
      for (let i = items.length - 1; i >= 0; i--) {
        if (nestedRunAmbiguous(items[i], f)) return true;
        // An end anchor is zero-width but only holds before a line break or the end, so nothing else can follow it.
        const fc = collectFirstChars(items[i], true);
        f = canBeEmpty(items[i], true) ? [...fc, ...f] : fc;
      }
      return false;
    }
    case 'star': case 'plus': {
      const own = collectFirstChars(node.child);
      if (overlapsAny(own, follow)) return true;
      return nestedRunAmbiguous(node.child, [...own, ...follow]);
    }
    default: return false;   // atomic runs, assertions, literals, classes
  }
}

function detectSuperlinear(tree) {
  if (!tree) return { unsafe: false };
  const reasons = [];
  _walk(tree, reasons, 0);
  return reasons.length ? { unsafe: true, reason: reasons[0] } : { unsafe: false };
}

function _walk(node, reasons, quantifierDepth) {
  if (!node || reasons.length) return;
  switch (node.type) {
    case 'star':
    case 'plus': {
      if (quantifierDepth > 0) return;   // an inner repetition is judged by its loop's follow sets (nestedRunAmbiguous), below
      // A repetition nested inside this one is ambiguous only when the characters it consumes can also be consumed by what
      // follows it inside the loop (including the next iteration): then a run can be split between the inner and the outer
      // repetition in exponentially many ways (`(a+)+`, `(\w+\s?)+`). One that is closed by a character it cannot consume
      // (`(?:[^,"]|"[^"]*")*`: the quoted run ends at the quote) has one split and is linear. The old rule reported every
      // syntactic nesting.
      if (nestedRunAmbiguous(node.child, collectFirstChars(node.child))) { reasons.push('nested quantifier'); return; }
      _walk(node.child, reasons, quantifierDepth + 1);
      // Unwrap group to check inner structure
      const inner = node.child && node.child.type === 'group' ? node.child.child : node.child;
      if (inner && inner.type === 'alt') {
        const branches = inner.branches || [];
        for (let i = 0; i < branches.length; i++) {
          const fc_i = collectFirstChars(branches[i]);
          for (let j = i + 1; j < branches.length; j++) {
            const fc_j = collectFirstChars(branches[j]);
            // Two branches each guarded by a positive lookbehind over disjoint sets (`(?<=\w)\*+` and `(?<=\s)\*+`) can
            // never both apply at one position, whatever they consume.
            const lb_i = leadingLookbehind(branches[i]); const lb_j = leadingLookbehind(branches[j]);
            if (lb_i && lb_j && !overlapsAny(lb_i, lb_j)) continue;
            // Two branches opening with the same single character (`\\[0-9a-f]` and `\\[^0-9a-f]`) are told apart by the
            // next one: compare what each needs second.
            const s_i = afterLeadingChar(branches[i]); const s_j = afterLeadingChar(branches[j]);
            if (s_i && s_j && s_i.lead === s_j.lead && s_i.next.length && s_j.next.length && !overlapsAny(s_i.next, s_j.next)) continue;
            for (const a of fc_i) {
              for (const b of fc_j) {
                if (classOverlaps(a, b)) {
                  reasons.push('alternation ambiguity under quantifier');
                  return;
                }
              }
            }
          }
        }
      }
      if (inner && inner.type === 'concat') {
        const items = inner.items || [];
        if (items.length >= 2) {
          const first = collectFirstChars(items[0]);
          for (let k = 1; k < items.length; k++) {
            // Check if all items before k can be empty (nullable prefix)
            const prefixNullable = items.slice(0, k).every(canBeEmpty);
            // An assertion is zero-width but it is a constraint, not an optional consumer that lets two items trade characters.
            const prevNullable = items[k - 1].type !== 'assert' && (canBeEmpty(items[k - 1]) || items[k - 1].type === 'star' || items[k - 1].type === 'opt');
            if (prevNullable || prefixNullable) {
              const fc_k = collectFirstChars(items[k]);
              for (const a of first) {
                for (const b of fc_k) {
                  if (classOverlaps(a, b)) {
                    reasons.push('overlapping nullable prefix in quantifier');
                    return;
                  }
                }
              }
            }
          }
        }
      }
      break;
    }
    case 'opt':
      _walk(node.child, reasons, quantifierDepth);
      break;
    case 'atomic':
      // One way to match: not a quantifier an enclosing one can split differently. Its own inside is still checked.
      _walk(node.child, reasons, 0);
      break;
    case 'group':
      _walk(node.child, reasons, quantifierDepth);
      break;
    case 'concat':
      for (const item of (node.items || [])) _walk(item, reasons, quantifierDepth);
      break;
    case 'alt':
      for (const b of (node.branches || [])) _walk(b, reasons, quantifierDepth);
      break;
    default:
      break;
  }
}

// ── Quadratic backtracking under an unanchored search ─────────────────────────
//
// A pattern searched for at every position of the input (JavaScript `test`/`replace`/`split`, Ruby `=~`/`index`/`scan`,
// PHP `preg_*`, Python `re.search`/`sub`/`split`/`findall`) that STARTS with an unbounded repetition of a set C and then needs
// something no character of C can supply (a literal, a set disjoint from part of C, or the end of the input) is quadratic:
// on a long run of C characters with that something missing, the attempt at each of the n start positions consumes the rest
// of the run before failing. `/\s*;\s*q=/` searched in n spaces makes n(n+1)/2 steps; `/\s*$/` (a right trim) on n spaces
// followed by a letter does the same. This is polynomial, not exponential, and is reported as such, at medium severity.
// Not reported: an anchored pattern (`^`, `\A`, a sticky flag), a leading repetition the rest of the pattern can always
// satisfy with C characters, an unknown construct, and languages or calls whose matching mode this extractor cannot see
// (Java, Kotlin, C#, Go: RE2 is linear).
export function quadraticSearchRisk(body, opts = {}) {
  if (!body || typeof body !== 'string' || body.length > MAX_BODY_LEN) return { risk: false };
  const parsed = parseRegex(body, opts);
  if (!parsed.ok || !parsed.tree) return { risk: false };
  const tree = parsed.tree;
  if (tree.type === 'alt') return { risk: false };
  const items = tree.type === 'concat' ? tree.items : [tree];
  let lead = items[0];
  if (lead && lead.type === 'atomic') lead = lead.child;
  if (!lead || (lead.type !== 'star' && lead.type !== 'plus')) return { risk: false };
  const unit = lead.child && lead.child.type === 'group' ? lead.child.child : lead.child;
  if (!unit || (unit.type !== 'class' && !(unit.type === 'literal' && unit.ch))) return { risk: false };
  const C = unit.type === 'class' ? unit.chars : unit.ch;
  // A dot run (`.*x`) is quadratic too, but it is the most common way to write "anything up to x" in short, trusted strings;
  // it is not claimed, so this rule stays about character-set runs.
  if (C === 'ANY' || C === NEG + '\n') return { risk: false };
  for (const item of items.slice(1)) {
    if (item.type === 'eol') return { risk: true, reason: 'leading unbounded repetition before an end anchor' };
    if (item.type === 'backref' || item.type === 'assert' || item.type === 'bol') return { risk: false };
    if (canBeEmpty(item)) continue;
    const need = collectFirstChars(item);
    if (!need.length || need.includes('ANY')) return { risk: false };
    // A character of C that cannot start the required element. A negated C has infinitely many members; any positive
    // requirement leaves one out, and a negated requirement may cover all of them, so that case is not claimed.
    const cNeg = C.startsWith(NEG);
    if (cNeg) return need.every((n) => !n.startsWith(NEG)) ? { risk: true, reason: 'leading unbounded repetition before a required character it excludes' } : { risk: false };
    const witness = [...C].find((ch) => need.every((n) => (n.startsWith(NEG) ? n.includes(ch) : !n.includes(ch))));
    return witness !== undefined ? { risk: true, reason: 'leading unbounded repetition before a required character it excludes' } : { risk: false };
  }
  return { risk: false };
}

// ── Public API ──────────────────────────────────────────────────────────────

export function isUnsafeRegex(body, opts = {}) {
  if (!body || typeof body !== 'string') return { unsafe: false };
  if (body.length > MAX_BODY_LEN) return { unsafe: false };
  if (!/[*+{]/.test(body)) return { unsafe: false };
  const parsed = parseRegex(body, opts);
  if (!parsed.ok) return { unsafe: false };
  return detectSuperlinear(parsed.tree);
}

function extractJsRegexBodies(code) {
  const out = [];
  // Regex literals: /pattern/flags. `regexContext` records whether the slash stands where an expression starts (after `(`,
  // `,`, `=`, `:`, `[`, `!`, `&`, `|`, `?`, `{`, `;`, `return`, or a line start), which separates a literal from a division.
  for (const m of code.matchAll(/\/([^/\n]+)\/([gimsuyd]*)/g)) {
    const before = code.slice(Math.max(0, m.index - 12), m.index);
    const regexContext = /(?:^|[(,=:[!&|?{;}]|\breturn)\s*$/.test(before) || /\n\s*$/.test(before);
    out.push({ body: m[1], flags: m[2], regexContext, line: code.slice(0, m.index).split('\n').length });
  }
  // new RegExp("pattern")
  for (const m of code.matchAll(/new\s+RegExp\s*\(\s*['"]([^'"]+)['"]/g)) {
    out.push({ body: m[1], line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

export function extractPyRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bre\.(compile|match|search|sub|subn|findall|finditer|split|fullmatch)\s*\(\s*r?(['"])((?:\\.|(?!\2)[^\\\n])+)\2/g)) {
    const line = code.slice(0, m.index).split('\n').length;
    // Search mode: the call itself searches, or a pattern compiled into a name is used with a searching method.
    let search = /^(?:search|sub|subn|findall|finditer|split)$/.test(m[1]);
    if (m[1] === 'compile') {
      const name = (code.slice(code.lastIndexOf('\n', m.index) + 1, m.index).match(/([A-Za-z_][\w.]*)\s*=\s*$/) || [])[1];
      if (name) search = new RegExp(`\\b${reEscape(name)}\\s*\\.\\s*(?:search|sub|subn|findall|finditer|split)\\s*\\(`).test(code);
    }
    out.push({ body: m[3], line, search });
  }
  // A raw-string constant used by name elsewhere in the file (`STAR_EM = r'(\*)(...)+?'` handed to re.compile or to a
  // pattern-processor class): Python raw strings are how regular expressions are written. Single-line literals only.
  for (const m of code.matchAll(/^[ \t]*([A-Z_][A-Z0-9_]*)[ \t]*=[ \t]*r(['"])((?:\\.|(?!\2)[^\\\n])+)\2[ \t]*(?:#.*)?$/gm)) {
    const uses = code.match(new RegExp(`\\b${reEscape(m[1])}\\b`, 'g')) || [];
    if (uses.length < 2) continue;
    const search = new RegExp(`\\bre\\.(?:search|sub|subn|findall|finditer|split)\\s*\\(\\s*${reEscape(m[1])}\\b`).test(code);
    out.push({ body: m[3], line: code.slice(0, m.index).split('\n').length, search, constant: true });
  }
  return out;
}

export function extractJavaRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bPattern\.compile\s*\(\s*"((?:\\.|[^\\"\n])+)"/g)) {
    out.push({ body: m[1].replace(/\\\\/g, '\\'), line: code.slice(0, m.index).split('\n').length });
  }
  for (const m of code.matchAll(/\.matches\s*\(\s*"((?:\\.|[^\\"\n])+)"/g)) {
    out.push({ body: m[1].replace(/\\\\/g, '\\'), line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

// Go: regexp.MustCompile / Compile / MatchString("…") — Go string literals use
// "…" (interpreted) or `…` (raw). Both carry the pattern verbatim.
function extractGoRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bregexp\.(?:MustCompile|Compile|CompilePOSIX|MatchString|Match)\s*\(\s*"((?:\\.|[^\\"\n])+)"/g)) {
    out.push({ body: m[1].replace(/\\\\/g, '\\'), line: code.slice(0, m.index).split('\n').length });
  }
  for (const m of code.matchAll(/\bregexp\.(?:MustCompile|Compile|CompilePOSIX|MatchString|Match)\s*\(\s*`([^`]+)`/g)) {
    out.push({ body: m[1], line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

// PHP: preg_match / preg_match_all / preg_replace("/…/flags", …) — the regex is
// a delimited string; strip the delimiter + trailing flags.
function extractPhpRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bpreg_(?:match|match_all|replace|replace_callback|split)\s*\(\s*(['"])(.+?)\1/g)) {
    let lit = m[2];
    // delimited: first char is the delimiter (e.g. / # ~), trailing flags after it
    const delim = lit[0];
    const close = lit.lastIndexOf(delim);
    if (close > 0) lit = lit.slice(1, close);
    out.push({ body: lit, line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

// Ruby: a regex literal /…/ used with =~ / .match / .match? / Regexp.new("…").
// A StringScanner's `scan`, `check`, `skip` and `match?` match AT the scan position (anchored), unlike String#scan; in a file that
// builds a StringScanner, a pattern handed to one of those methods is not searched.
const SCANNER_ANCHORED = /^\.(?:scan|check|skip|match\?)$/;
function extractRubyRegexBodies(code) {
  const out = [];
  const usesScanner = /\bStringScanner\b/.test(code);
  for (const m of code.matchAll(/(=~|\.match\??|\.scan|\.check|\.skip|\.gsub|\.sub|grep)\s*\(?\s*\/((?:\\.|[^\\\/\n])+)\/([mixounse]*)/g)) {
    out.push({ body: m[2], line: code.slice(0, m.index).split('\n').length, anchoredUse: usesScanner && SCANNER_ANCHORED.test(m[1]), multiline: m[3].includes('m') });
  }
  for (const m of code.matchAll(/\bRegexp\.new\s*\(\s*['"]((?:\\.|[^\\'"\n])+)['"]/g)) {
    out.push({ body: m[1], line: code.slice(0, m.index).split('\n').length });
  }
  // A regular expression bound to a constant (`SEPARATOR = /\s*;\s*q="?/`) and used elsewhere (`header.index(SEPARATOR)`),
  // and the `%r{...}` form. Every Ruby matching method searches (`=~`, `match`, `index`, `scan`, `split`, `sub`).
  for (const m of code.matchAll(/^[ \t]*([A-Z][A-Z0-9_]*)[ \t]*=[ \t]*\/((?:\\.|[^\\\/\n])+)\/([mixounse]*)[ \t]*(?:#.*)?$/gm)) {
    const anchoredUse = usesScanner && new RegExp(`\\.(?:scan|check|skip|match\\?)\\s*\\(?\\s*${reEscape(m[1])}\\b`).test(code)
      && !new RegExp(`(?:=~|\\.(?:index|match|sub|gsub|split|scan_until|slice))\\s*\\(?\\s*${reEscape(m[1])}\\b`).test(code);
    out.push({ body: m[2], line: code.slice(0, m.index).split('\n').length, constant: true, anchoredUse, multiline: m[3].includes('m') });
  }
  for (const m of code.matchAll(/%r\{((?:\\.|[^\\}\n])+)\}[mixounse]*/g)) {
    out.push({ body: m[1], line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

// C#: new Regex("…") / Regex.IsMatch(s, "…") / Regex.Match / Regex.Replace.
function extractCsharpRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bnew\s+Regex\s*\(\s*@?"((?:\\.|""|[^\\"\n])+)"/g)) {
    out.push({ body: m[1].replace(/""/g, '"'), line: code.slice(0, m.index).split('\n').length });
  }
  for (const m of code.matchAll(/\bRegex\.(?:IsMatch|Match|Matches|Replace|Split)\s*\(\s*[^,]+,\s*@?"((?:\\.|""|[^\\"\n])+)"/g)) {
    out.push({ body: m[1].replace(/""/g, '"'), line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

// Kotlin: Regex("…") / "…".toRegex() / Pattern.compile("…").
function extractKotlinRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bRegex\s*\(\s*"((?:\\.|[^\\"\n])+)"/g)) {
    out.push({ body: m[1].replace(/\\\\/g, '\\'), line: code.slice(0, m.index).split('\n').length });
  }
  for (const m of code.matchAll(/"((?:\\.|[^\\"\n])+)"\s*\.\s*toRegex\s*\(/g)) {
    out.push({ body: m[1].replace(/\\\\/g, '\\'), line: code.slice(0, m.index).split('\n').length });
  }
  for (const m of code.matchAll(/\bPattern\.compile\s*\(\s*"((?:\\.|[^\\"\n])+)"/g)) {
    out.push({ body: m[1].replace(/\\\\/g, '\\'), line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

export function scanRegexReDoS(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (raw.length > 500_000) return [];
  const findings = [];
  let bodies = [];
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file)) bodies = extractJsRegexBodies(raw);
  else if (/\.py$/i.test(file)) bodies = extractPyRegexBodies(raw);
  else if (/\.java$/i.test(file)) bodies = extractJavaRegexBodies(raw);
  // NOTE: Go's regexp package uses RE2 (guaranteed linear time, no catastrophic
  // backtracking), so Go is intentionally NOT scanned for ReDoS — a "vulnerable"
  // pattern there is not actually exploitable. (extractGoRegexBodies is exported
  // for completeness / third-party regexp libs but not wired into the default.)
  else if (/\.(?:php|phtml)$/i.test(file)) bodies = extractPhpRegexBodies(raw);
  else if (/\.rb$/i.test(file)) bodies = extractRubyRegexBodies(raw);
  else if (/\.cs$/i.test(file)) bodies = extractCsharpRegexBodies(raw);
  else if (/\.kt$/i.test(file)) bodies = extractKotlinRegexBodies(raw);
  else return [];

  const isJs = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file);
  const isPy = /\.py$/i.test(file);
  const searchMode = (b) => (isJs ? b.regexContext && !String(b.flags || '').includes('y')
    : isPy ? b.search === true
    : /\.rb$/i.test(file) ? !b.anchoredUse
    : /\.(?:php|phtml)$/i.test(file));
  const seen = new Set();
  for (const b of bodies) {
    const { body, line } = b;
    if (seen.has(`${line}|${body}`)) continue;
    seen.add(`${line}|${body}`);
    // Dot-all: a JavaScript `s` flag, a Ruby `/m` literal, or a Python file that passes DOTALL anywhere (the flag is an argument
    // of a call the constant may be handed to, so the file is the unit; this only widens `.`, toward reporting).
    const dotAll = isJs ? String(b.flags || '').includes('s') : isPy ? /\bre\.(?:DOTALL|S)\b|\(\?[a-z]*s/.test(raw) : /\.rb$/i.test(file) ? !!b.multiline : false;
    const result = isUnsafeRegex(body, { dotAll });
    if (!result.unsafe && searchMode(b)) {
      const q = quadraticSearchRisk(body, { dotAll });
      if (q.risk) {
        findings.push({
          id: `redos-poly:${file}:${line}`,
          file,
          line,
          vuln: 'ReDoS: quadratic backtracking under an unanchored search',
          severity: 'medium',
          family: 'redos',
          cwe: 'CWE-1333',
          parser: 'NFA',
          confidence: 0.6,
          description: `Regex pattern has a ${q.reason}, and it is searched for at every position of the input. On a long run of the repeated characters without the required one, each start position scans to the end of the run: quadratic time in the input length.`,
          remediation: 'Anchor the pattern, start it with the required character (for example match the separator first and trim afterwards), or bound the input length before matching.',
          snippet: `/${body.slice(0, 60)}${body.length > 60 ? '...' : ''}/`,
        });
      }
      continue;
    }
    if (result.unsafe) {
      findings.push({
        id: `redos-nfa:${file}:${line}`,
        file,
        line,
        vuln: 'ReDoS — Catastrophic Backtracking (NFA analysis)',
        severity: 'high',
        family: 'redos',
        cwe: 'CWE-1333',
        parser: 'NFA',
        confidence: 0.85,
        description: `Regex pattern has ${result.reason}. A crafted input can cause exponential backtracking, consuming 100% CPU.`,
        remediation: 'Rewrite the regex to avoid nested quantifiers and overlapping alternation. Consider using the re2 library for guaranteed linear-time matching.',
        snippet: `/${body.slice(0, 60)}${body.length > 60 ? '...' : ''}/`,
      });
    }
  }
  return findings;
}
