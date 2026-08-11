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

// ── Regex parser ────────────────────────────────────────────────────────────

function parseRegex(body) {
  let pos = 0;
  const src = body;

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
          if (max > 1 || max === Infinity) {
            atom = { type: 'star', child: atom };
          }
        } else {
          pos = saved;
          break;
        }
      } else break;
      if (peek() === '?') advance(); // lazy modifier
    }
    return atom;
  }

  function parseAtom() {
    const c = peek();
    if (c === null || c === ')' || c === '|') return null;
    if (c === '(') {
      advance();
      if (peek() === '?') {
        advance();
        // Non-capturing group or lookahead — skip modifier chars
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
      if (esc === 'd') return { type: 'class', chars: '0123456789' };
      if (esc === 'w') return { type: 'class', chars: 'azAZ09_' };
      if (esc === 's') return { type: 'class', chars: ' \t\n\r' };
      if (esc === 'D' || esc === 'W' || esc === 'S') return { type: 'class', chars: 'ANY' };
      if (esc === 'b' || esc === 'B') return { type: 'literal', ch: '' }; // anchor
      return { type: 'literal', ch: esc };
    }
    if (c === '.') { advance(); return { type: 'class', chars: 'ANY' }; }
    if (c === '^' || c === '$') { advance(); return { type: 'literal', ch: '' }; }
    advance();
    return { type: 'literal', ch: c };
  }

  function parseCharClass() {
    advance(); // [
    let chars = '';
    let negated = false;
    if (peek() === '^') { negated = true; advance(); }
    if (peek() === ']') { chars += advance(); }
    while (pos < src.length && peek() !== ']') {
      if (peek() === '\\') {
        advance();
        const esc = advance();
        if (esc === 'd') chars += '0123456789';
        else if (esc === 'w') chars += 'azAZ09_';
        else if (esc === 's') chars += ' \t\n\r';
        else chars += (esc || '');
      } else {
        chars += advance();
      }
    }
    if (peek() === ']') advance();
    return { type: 'class', chars: negated ? 'ANY' : chars };
  }

  try {
    const tree = parseAlternation();
    return { ok: true, tree };
  } catch {
    return { ok: false, tree: null };
  }
}

// ── Ambiguity detection ─────────────────────────────────────────────────────

function classOverlaps(a, b) {
  if (a === 'ANY' || b === 'ANY') return true;
  for (const ch of a) {
    if (b.includes(ch)) return true;
  }
  return false;
}

function collectFirstChars(node) {
  if (!node) return [];
  switch (node.type) {
    case 'literal':
      return node.ch ? [node.ch] : [];
    case 'class':
      return [node.chars];
    case 'group':
      return collectFirstChars(node.child);
    case 'concat':
      for (const item of (node.items || [])) {
        const fc = collectFirstChars(item);
        if (fc.length) return fc;
        if (!canBeEmpty(item)) return fc;
      }
      return [];
    case 'alt':
      return (node.branches || []).flatMap(collectFirstChars);
    case 'star':
    case 'plus':
    case 'opt':
      return collectFirstChars(node.child);
    default:
      return [];
  }
}

function canBeEmpty(node) {
  if (!node) return true;
  switch (node.type) {
    case 'literal': return !node.ch;
    case 'class': return false;
    case 'group': return canBeEmpty(node.child);
    case 'concat': return (node.items || []).every(canBeEmpty);
    case 'alt': return (node.branches || []).some(canBeEmpty);
    case 'star': case 'opt': return true;
    case 'plus': return canBeEmpty(node.child);
    default: return false;
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
      if (quantifierDepth > 0) {
        reasons.push('nested quantifier');
        return;
      }
      _walk(node.child, reasons, quantifierDepth + 1);
      // Unwrap group to check inner structure
      const inner = node.child && node.child.type === 'group' ? node.child.child : node.child;
      if (inner && inner.type === 'alt') {
        const branches = inner.branches || [];
        for (let i = 0; i < branches.length; i++) {
          const fc_i = collectFirstChars(branches[i]);
          for (let j = i + 1; j < branches.length; j++) {
            const fc_j = collectFirstChars(branches[j]);
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
            const prevNullable = canBeEmpty(items[k - 1]) || items[k - 1].type === 'star' || items[k - 1].type === 'opt';
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

// ── Public API ──────────────────────────────────────────────────────────────

export function isUnsafeRegex(body) {
  if (!body || typeof body !== 'string') return { unsafe: false };
  if (body.length > MAX_BODY_LEN) return { unsafe: false };
  if (!/[*+{]/.test(body)) return { unsafe: false };
  const parsed = parseRegex(body);
  if (!parsed.ok) return { unsafe: false };
  return detectSuperlinear(parsed.tree);
}

function extractJsRegexBodies(code) {
  const out = [];
  // Regex literals: /pattern/flags
  for (const m of code.matchAll(/\/([^/\n]+)\/[gimsuy]*/g)) {
    out.push({ body: m[1], line: code.slice(0, m.index).split('\n').length });
  }
  // new RegExp("pattern")
  for (const m of code.matchAll(/new\s+RegExp\s*\(\s*['"]([^'"]+)['"]/g)) {
    out.push({ body: m[1], line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

export function extractPyRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bre\.(?:compile|match|search|sub|findall|fullmatch)\s*\(\s*r?['"]((?:\\.|[^'"\n])+)['"]/g)) {
    out.push({ body: m[1], line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

export function extractJavaRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bPattern\.compile\s*\(\s*"((?:\\.|[^"\n])+)"/g)) {
    out.push({ body: m[1].replace(/\\\\/g, '\\'), line: code.slice(0, m.index).split('\n').length });
  }
  for (const m of code.matchAll(/\.matches\s*\(\s*"((?:\\.|[^"\n])+)"/g)) {
    out.push({ body: m[1].replace(/\\\\/g, '\\'), line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

// Go: regexp.MustCompile / Compile / MatchString("…") — Go string literals use
// "…" (interpreted) or `…` (raw). Both carry the pattern verbatim.
function extractGoRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bregexp\.(?:MustCompile|Compile|CompilePOSIX|MatchString|Match)\s*\(\s*"((?:\\.|[^"\n])+)"/g)) {
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
function extractRubyRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/(?:=~|\.match\??|\.scan|\.gsub|\.sub|grep)\s*\(?\s*\/((?:\\.|[^\/\n])+)\//g)) {
    out.push({ body: m[1], line: code.slice(0, m.index).split('\n').length });
  }
  for (const m of code.matchAll(/\bRegexp\.new\s*\(\s*['"]((?:\\.|[^'"\n])+)['"]/g)) {
    out.push({ body: m[1], line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

// C#: new Regex("…") / Regex.IsMatch(s, "…") / Regex.Match / Regex.Replace.
function extractCsharpRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bnew\s+Regex\s*\(\s*@?"((?:\\.|""|[^"\n])+)"/g)) {
    out.push({ body: m[1].replace(/""/g, '"'), line: code.slice(0, m.index).split('\n').length });
  }
  for (const m of code.matchAll(/\bRegex\.(?:IsMatch|Match|Matches|Replace|Split)\s*\(\s*[^,]+,\s*@?"((?:\\.|""|[^"\n])+)"/g)) {
    out.push({ body: m[1].replace(/""/g, '"'), line: code.slice(0, m.index).split('\n').length });
  }
  return out;
}

// Kotlin: Regex("…") / "…".toRegex() / Pattern.compile("…").
function extractKotlinRegexBodies(code) {
  const out = [];
  for (const m of code.matchAll(/\bRegex\s*\(\s*"((?:\\.|[^"\n])+)"/g)) {
    out.push({ body: m[1].replace(/\\\\/g, '\\'), line: code.slice(0, m.index).split('\n').length });
  }
  for (const m of code.matchAll(/"((?:\\.|[^"\n])+)"\s*\.\s*toRegex\s*\(/g)) {
    out.push({ body: m[1].replace(/\\\\/g, '\\'), line: code.slice(0, m.index).split('\n').length });
  }
  for (const m of code.matchAll(/\bPattern\.compile\s*\(\s*"((?:\\.|[^"\n])+)"/g)) {
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

  for (const { body, line } of bodies) {
    const result = isUnsafeRegex(body);
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
