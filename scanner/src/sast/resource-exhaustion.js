// PRD T4.2 — resource exhaustion from an unbounded, externally-influenced size.
//
// The largest unimplemented class in the evidence table: 14 of the 96
// root-caused real-world misses. Distinct from ReDoS (redos-nfa.js covers
// regex backtracking only, and correctly returned "safe" for a real
// polynomial-split() DoS) and from injection — nothing is escaped or
// concatenated here. The bug is that a value which the caller controls is used
// as an ALLOCATION or ITERATION size with no upper bound on any path.
//
// Shapes drawn from the real entries:
//   pypdf   — a /W CID-width array's start..stop range expanded into a dict,
//             one key per index, with no cap (CWE-834).
//   pypdf   — a CMap token length with no ceiling (CWE-400).
//   thumbor — `new_width = source_width * value` from a URL filter argument
//             with no upper bound (CWE-400).
//   mermaid — an unbounded `ticks` from parsed diagram text driving render
//             geometry (CWE-606).
//
// PRECISION IS THE WHOLE GAME. "A number is used as a size" describes most
// code ever written, so this fires only when ALL of the following hold:
//   1. the size derives from a recognised EXTERNAL surface (a request/params
//      object, a parsed document field, or a function parameter that reaches
//      the operation unmodified) — never a local constant;
//   2. the value reaches a bounded-cost operation (range/repeat/allocation);
//   3. no comparison against an upper bound appears anywhere in the enclosing
//      window.
// Condition 3 is what keeps it quiet: a single `if (n > MAX)` silences it, and
// that is exactly the fix each of these advisories shipped — so the detector
// discriminates the fixed revision from the vulnerable one by construction.
import { blankComments } from './_comment-strip.js';

const PY_RE = /\.py$/i;
const JS_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;

/** External surfaces whose values a caller can choose. */
const EXTERNAL_RE = /\b(?:request|req|params|query|body|args|argv|options|opts|payload|form|headers|data|spec|config|input|user_input|kwargs)\b/;

/** An upper-bound check anywhere in the window — the mitigation. */
const BOUND_RE = new RegExp([
  '[<>]=?\\s{0,4}\\d',                       // n > 1000 / n <= LIMIT-ish
  '[<>]=?\\s{0,4}[A-Z_]{2,40}\\b',           // n > MAX_ENTRIES
  '\\bmin\\s{0,4}\\(', '\\bMath\\.min\\s{0,4}\\(',
  '\\bmax_\\w{1,40}\\b', '\\bMAX_\\w{1,40}\\b', '\\blimit\\b', '\\bcap\\b',
  '\\bclamp\\b', '\\bslice\\s{0,4}\\(', '\\bislice\\s{0,4}\\(',
  '\\braise\\b', '\\bthrow\\b',
].join('|'), 'i');

/** Bounded-cost operations: allocate or iterate proportional to a value. */
const PY_SIZE_OPS = [
  { re: /\brange\s*\(([^)]{1,200})\)/g, what: 'range()' },
  { re: /\b(\w{1,60})\s*\*\s*(\w{1,60})\b(?=\s*(?:\)|,|$|\n))/g, what: 'multiplication used as a size' },
  { re: /\[\s*[^\]]{0,60}\s*\]\s*\*\s*(\w{1,60})/g, what: 'list repetition' },
  { re: /\bbytearray\s*\(([^)]{1,120})\)/g, what: 'bytearray()' },
];
const JS_SIZE_OPS = [
  { re: /\bnew\s+Array\s*\(([^)]{1,120})\)/g, what: 'new Array()' },
  { re: /\.repeat\s*\(([^)]{1,120})\)/g, what: '.repeat()' },
  { re: /\bBuffer\.alloc\w{0,10}\s*\(([^)]{1,120})\)/g, what: 'Buffer.alloc()' },
  { re: /for\s*\([^;]{0,80};[^;]{0,80}<\s*([\w.]{1,60})\s*;/g, what: 'loop bound' },
];

const _lineOf = (raw, idx) => raw.slice(0, idx).split('\n').length;
const _window = (raw, line, half = 12) => {
  const l = raw.split('\n');
  return l.slice(Math.max(0, line - 1 - half), Math.min(l.length, line - 1 + half)).join('\n');
};

/**
 * Does this size expression trace to something a caller chooses, within the
 * enclosing window? Deliberately window-scoped rather than flow-sensitive:
 * this is a structural detector, and the taint engine already owns real flow.
 */
function _externallyInfluenced(sizeExpr, win) {
  const idents = String(sizeExpr).match(/[A-Za-z_$][\w$.]{0,60}/g) || [];
  for (const id of idents) {
    if (/^\d+$/.test(id)) continue;
    if (EXTERNAL_RE.test(id)) return id;                       // params.count
    // Assigned from an external surface nearby: `n = data["count"]`
    const assigned = new RegExp(`\\b${id.split('.')[0].replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}\\s{0,4}=[^=]{0,120}`, 'g');
    for (const m of win.match(assigned) || []) if (EXTERNAL_RE.test(m)) return id;
  }
  return null;
}

function _scan(file, raw, code, ops) {
  const out = [];
  const seen = new Set();
  for (const { re, what } of ops) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code))) {
      const sizeExpr = m[1] || m[2] || '';
      if (!sizeExpr || /^['"]/.test(sizeExpr.trim())) continue;
      const line = _lineOf(code, m.index);
      const key = `${line}`;
      if (seen.has(key)) continue;
      const win = _window(raw, line);
      const source = _externallyInfluenced(sizeExpr, win);
      if (!source) continue;                                    // not caller-chosen
      if (BOUND_RE.test(win)) continue;                         // already bounded — the fix
      seen.add(key);
      out.push({
        id: `resource-exhaustion:unbounded-size:${file}:${line}`,
        file, line,
        vuln: `Unbounded resource allocation — ${what} sized from caller-controlled '${source}' with no upper bound`,
        severity: 'medium',
        cwe: 'CWE-400',
        family: 'resource-exhaustion',
        parser: 'RESOURCE',
        confidence: 0.5,
        description:
          `The size of ${what} derives from '${source}', which a caller can choose, and no upper-bound check ` +
          'appears in the surrounding code. A large value forces proportional memory or CPU use, so a single ' +
          'request can exhaust the process — a denial of service that needs no injection and no malformed input, ' +
          'just a big number.',
        remediation:
          `Clamp the value before it is used as a size (e.g. \`n = min(n, MAX_${String(what).replace(/\\W/g, '').toUpperCase().slice(0, 12)})\`) ` +
          'or reject it with an explicit error when it exceeds the documented maximum.',
        checkedFor: 'an upper-bound comparison, min()/clamp, or an explicit raise/throw within 12 lines',
      });
    }
  }
  return out;
}

export function scanResourceExhaustion(file, raw) {
  if (!raw || typeof raw !== 'string' || raw.length > 500_000) return [];
  const isPy = PY_RE.test(file), isJs = JS_RE.test(file);
  if (!isPy && !isJs) return [];
  if (!EXTERNAL_RE.test(raw)) return [];                        // cheap relevance gate
  const code = blankComments(raw, isPy ? 'py' : null);
  try { return _scan(file, raw, code, isPy ? PY_SIZE_OPS : JS_SIZE_OPS); }
  catch { return []; }
}

export const _internals = { EXTERNAL_RE, BOUND_RE, _externallyInfluenced };
