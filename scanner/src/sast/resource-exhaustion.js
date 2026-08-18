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

/**
 * An upper-bound check that actually applies to the size-controlling
 * identifier — the mitigation. GHSA-phj3-59pf-cp83's PRE revision already
 * contains `if new_width < 1 or new_height < 1: return`, a lower-bound
 * sanity check on the DERIVED value, not a ceiling on the source `value`.
 * An identifier-agnostic `[<>]=?\s{0,4}\d` match treated that as the fix and
 * silenced the finding on both pre/ and post/. The comparison-based
 * alternatives now require the identifier itself; the keyword-based ones
 * (min/max/clamp/raise/...) stay window-scoped — those tokens are
 * distinctive enough on their own that binding them to one identifier would
 * just miss the common `n = min(n, MAX)` reassignment shape.
 */
const BOUND_KEYWORDS_RE = new RegExp([
  '\\bmin\\s{0,4}\\(', '\\bMath\\.min\\s{0,4}\\(',
  '\\bmax_\\w{1,40}\\b', '\\bMAX_\\w{1,40}\\b', '\\blimit\\b', '\\bcap\\b',
  '\\bclamp\\b', '\\bslice\\s{0,4}\\(', '\\bislice\\s{0,4}\\(',
  '\\braise\\b', '\\bthrow\\b',
].join('|'), 'i');
function _isBounded(id, win) {
  if (BOUND_KEYWORDS_RE.test(win)) return true;
  if (!id) return false;
  const esc = String(id).split('.')[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const named = new RegExp(
    `\\b${esc}\\b\\s{0,4}[<>]=?\\s{0,4}(?:\\d|[A-Z_]{2,40}\\b)|(?:\\d+|[A-Z_]{2,40})\\s{0,4}[<>]=?\\s{0,4}\\b${esc}\\b`,
    'i');
  return named.test(win);
}

/**
 * Bounded-cost operations: allocate or iterate proportional to a value.
 *
 * `candidates` returns every identifier the match could be sized from, when
 * more than one is plausible (a multiplication's two operands). Without it,
 * only the FIRST non-empty capture group was ever tested — GHSA-phj3-59pf-cp83
 * (`new_width = source_width * value`) happened to pass anyway because
 * `source_width`'s own assignment line mentions `request`, but a version with
 * the constant on the left (`n = CONSTANT * value`) would have silently
 * skipped `value`, the actual caller-controlled operand, forever.
 */
const PY_SIZE_OPS = [
  { re: /\brange\s*\(([^)]{1,200})\)/g, what: 'range()' },
  { re: /\b(\w{1,60})\s*\*\s*(\w{1,60})\b(?=\s*(?:\)|,|$|\n))/g, what: 'multiplication used as a size', candidates: m => [m[1], m[2]] },
  { re: /\[\s*[^\]]{0,60}\s*\]\s*\*\s*(\w{1,60})/g, what: 'list repetition' },
  { re: /\bbytearray\s*\(([^)]{1,120})\)/g, what: 'bytearray()' },
];
/**
 * A loop bounded by an input's OWN `.length`/`.size` iterates exactly what
 * the process already holds in memory — it allocates nothing beyond that, so
 * it isn't the CWE-400 shape this rule targets. Every parser in existence
 * loops `for (i = 0; i < input.length; i++)`; flagging that would make the
 * rule fire on essentially all parsing code. Exposed by the identifier-scoped
 * `_isBounded` fix above no longer being coincidentally silenced by an
 * unrelated comparison elsewhere in the window.
 */
const LENGTH_BOUND_RE = /\.(?:length|size|len|byteLength)$/i;
const JS_SIZE_OPS = [
  { re: /\bnew\s+Array\s*\(([^)]{1,120})\)/g, what: 'new Array()' },
  { re: /\.repeat\s*\(([^)]{1,120})\)/g, what: '.repeat()' },
  { re: /\bBuffer\.alloc\w{0,10}\s*\(([^)]{1,120})\)/g, what: 'Buffer.alloc()' },
  { re: /for\s*\([^;]{0,80};[^;]{0,80}<\s*([\w.]{1,60})\s*;/g, what: 'loop bound', skip: expr => LENGTH_BOUND_RE.test(expr.trim()) },
];

const _lineOf = (raw, idx) => raw.slice(0, idx).split('\n').length;
const _window = (raw, line, half = 12) => {
  const l = raw.split('\n');
  return l.slice(Math.max(0, line - 1 - half), Math.min(l.length, line - 1 + half)).join('\n');
};

/**
 * A generic (non-staticmethod/property/etc.) decorator marks a function as
 * invoked BY something else across a trust boundary — a route, a filter, a
 * task queue, a validator. Its parameters are as externally-influenced as a
 * literal `req`/`params` name, without needing to guess a naming convention.
 * GHSA-phj3-59pf-cp83's `value` (a `@filter_method`-decorated parameter) is
 * the case this exists for; EXTERNAL_RE's fixed vocabulary cannot express it.
 */
const NON_HANDLER_DECORATOR_RE = /^@(?:staticmethod|classmethod|property|dataclass|lru_cache|cached_property|abstractmethod|overload|wraps|final|override)\b/i;
/** Cheap top-level gate: any indented `@decorator` line at all. */
const HAS_DECORATOR_RE = /^[ \t]{0,20}@[A-Za-z_]/m;
const _handlerDefRe = () => /@([\w.]+)[^\n]{0,200}\n\s{0,20}(?:async\s{1,4})?def\s{1,4}\w{1,60}\s{0,4}\(([^)]{0,400})\)/g;
function _isHandlerParam(name, code, idx) {
  if (!name || /^(?:self|cls)$/.test(name)) return false;
  const re = _handlerDefRe();
  let last = null, m;
  while ((m = re.exec(code)) && m.index < idx) last = m;
  if (!last) return false;
  if (NON_HANDLER_DECORATOR_RE.test('@' + last[1])) return false;
  const params = String(last[2]).split(',').map(p => p.trim().split(/[:=]/)[0].replace(/^\*{1,2}/, '').trim());
  return params.includes(name);
}

/**
 * Does this size expression trace to something a caller chooses, within the
 * enclosing window? Deliberately window-scoped rather than flow-sensitive:
 * this is a structural detector, and the taint engine already owns real flow.
 */
function _externallyInfluenced(sizeExpr, win, code, matchIdx) {
  const idents = String(sizeExpr).match(/[A-Za-z_$][\w$.]{0,60}/g) || [];
  for (const id of idents) {
    if (/^\d+$/.test(id)) continue;
    // A BARE (unqualified) 'headers' is as likely to be a local variable —
    // a table's column headers, a config section name — as an HTTP request's
    // headers; scripts/nist-compliance/scan.py's ASCII-table renderer has
    // exactly this shape (`for i in range(len(headers))`). Requiring
    // qualification (`req.headers`) keeps the word useful without matching
    // every unrelated local var that happens to share its name.
    if (id !== 'headers' && EXTERNAL_RE.test(id)) return id;   // params.count / req.headers
    // Assigned from an external surface nearby: `n = data["count"]`
    const bare = id.split('.')[0];
    const assigned = new RegExp(`\\b${bare.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}\\s{0,4}=[^=]{0,120}`, 'g');
    for (const m of win.match(assigned) || []) if (EXTERNAL_RE.test(m)) return id;
    if (code && _isHandlerParam(bare, code, matchIdx)) return id;
  }
  return null;
}

function _scan(file, raw, code, ops) {
  const out = [];
  const seen = new Set();
  for (const { re, what, candidates, skip } of ops) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code))) {
      const exprCandidates = candidates ? candidates(m) : [m[1] || m[2] || ''];
      if (skip && exprCandidates.some(skip)) continue;
      const line = _lineOf(code, m.index);
      const key = `${line}`;
      if (seen.has(key)) continue;
      const win = _window(raw, line);
      let source = null;
      for (const sizeExpr of exprCandidates) {
        if (!sizeExpr || /^['"]/.test(sizeExpr.trim())) continue;
        source = _externallyInfluenced(sizeExpr, win, code, m.index);
        if (source) break;
      }
      if (!source) continue;                                    // not caller-chosen
      // Bounding EITHER operand bounds the product/size, so check every
      // candidate identifier, not just the one that proved external. GHSA-
      // phj3-59pf-cp83's fix caps `value`, but `source_width` (checked first
      // above, since its own assignment line visibly mentions `request`) is
      // what got identified as the external source — checking only that one
      // identifier for a bound would miss a fix applied to its sibling.
      const allIdents = exprCandidates.flatMap(c => String(c).match(/[A-Za-z_$][\w$.]{0,60}/g) || []);
      if (allIdents.some(id => _isBounded(id, win))) continue; // already bounded — the fix
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
  if (!EXTERNAL_RE.test(raw) && !(isPy && HAS_DECORATOR_RE.test(raw))) return []; // cheap relevance gate
  const code = blankComments(raw, isPy ? 'py' : null);
  try { return _scan(file, raw, code, isPy ? PY_SIZE_OPS : JS_SIZE_OPS); }
  catch { return []; }
}

export const _internals = { EXTERNAL_RE, BOUND_KEYWORDS_RE, _isBounded, _externallyInfluenced, _isHandlerParam, NON_HANDLER_DECORATOR_RE };
