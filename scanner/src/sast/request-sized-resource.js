// Request-sized resource consumption (CWE-770, CWE-400, CWE-407).
//
// A value the caller chooses, read from the request, used as the SIZE of an
// allocation or the BOUND of a loop with no upper-bound check first; and a
// collection the caller sends, scanned once per element of itself (quadratic
// work in the request size). JavaScript/TypeScript, Python, Java, Kotlin, C#,
// Go, PHP and Ruby.
//
// Why a structural pass and not catalog sinks in the taint engine. The engine
// treats every numeric conversion (parseInt, int(), Integer.parseInt,
// strconv.Atoi, ...) as a sanitizer for every family (`appliesTo: ['*']`),
// which is right for injection and exactly wrong here: `n = int(request.args
// ["n"])` is how a count reaches `range(n)`. Changing that would move every
// injection verdict. This module tracks request values through local
// assignments inside one function, the numeric conversions included, and asks
// one more question the engine never asks: was the value compared with an
// upper bound before the use.
//
// Precision rules (each refusing case is pinned in the test file):
//   1. Positive evidence of a request value: a framework request accessor
//      (req.query.x, request.args.get, getParameter, r.URL.Query().Get,
//      $_GET, params[:x], Request.Query[...], ...) or a parameter bound from
//      the request by its annotation or route decorator. A bare name is never
//      a source, whatever it is called.
//   2. Where the language would refuse a string as a size (Python, Ruby, and
//      the JavaScript constructors that treat one string as one element),
//      the value must have passed through a numeric conversion. Statically
//      typed languages prove that by compiling.
//   3. Silent when, before the use and in the same function, the value (or a
//      value it was computed from, or the request field itself) is compared
//      with anything other than a literal lower bound (0, 1, -1), clamped
//      (min, clamp, coerceAtMost, modulo), handed to a check/validate helper,
//      or declared bounded where it is bound (@Max, [Range], Query(le=...),
//      a schema line naming the field next to a max).
//   4. A loop bounded by an input's own length is not a finding: it walks what
//      the process already holds.
//   5. Body fields are silent in a file that uses a validation library, which
//      may bound them in a schema this file does not show.
//   6. Test code is skipped.

import { maskStrings, functionUnits, langOf } from './convention-deviation-values.js';
import { callArguments } from './_call-args.js';
import { scanResourceExhaustion } from './resource-exhaustion.js';

const TEST_PATH_RE = /(?:^|[\\/])(?:tests?|specs?|__tests__|__mocks__|testdata|fixtures?|e2e|bench(?:mark)?s?|examples?)[\\/]|[._-](?:test|spec)\.[a-z]{1,4}$|Tests?\.(?:java|kt|cs)$|_test\.go$|(?:^|[\\/])test_\w{1,80}\.py$|_spec\.rb$/i;

const MAX_FILE = 400_000;

// ---------------------------------------------------------------------------
// Request sources, per language. Each regex is matched on comment-free code
// and kept only when its first character is code (not a string interior).
// `key` captures the request field name when the accessor names one.
// `body: true` marks sources that a validation schema elsewhere could bound.
// ---------------------------------------------------------------------------

const Q = `['"\`]`;
const KEY = `([A-Za-z_][\\w-]{0,60})`;

const SOURCES = {
  js: [
    { re: new RegExp(`\\b(?:req|request|ctx\\.request|ctx)\\s*\\.\\s*(?:query|body|params|cookies)\\b(?:\\s*\\.\\s*([A-Za-z_$][\\w$]{0,60})|\\s*\\[\\s*${Q}${KEY}${Q}\\s*\\])?`, 'g'), body: true },
    { re: new RegExp(`\\bevent\\s*\\.\\s*(?:queryStringParameters|pathParameters|multiValueQueryStringParameters)\\b(?:\\s*\\.\\s*([A-Za-z_$][\\w$]{0,60})|\\s*\\[\\s*${Q}${KEY}${Q}\\s*\\])?`, 'g') },
    { re: new RegExp(`\\bsearchParams\\s*\\.\\s*get\\s*\\(\\s*${Q}${KEY}${Q}\\s*\\)`, 'g'), needsScope: /\b(?:req|request)\s*\.\s*(?:url|nextUrl)\b/ },
  ],
  py: [
    { re: new RegExp(`\\brequest\\s*\\.\\s*(?:args|form|values|GET|POST|query_params|path_params|json|cookies)\\b(?:\\s*\\.\\s*(?:get|getlist|get_one)\\s*\\(\\s*${Q}${KEY}${Q}|\\s*\\[\\s*${Q}${KEY}${Q}\\s*\\])?`, 'g'), body: true, needsFile: true },
    { re: new RegExp(`\\brequest\\s*\\.\\s*get_json\\s*\\([^()]{0,80}\\)(?:\\s*\\.\\s*get\\s*\\(\\s*${Q}${KEY}${Q}|\\s*\\[\\s*${Q}${KEY}${Q}\\s*\\])?`, 'g'), body: true, needsFile: true },
    { re: new RegExp(`\\bself\\s*\\.\\s*get_(?:query_|body_)?argument\\s*\\(\\s*${Q}${KEY}${Q}`, 'g'), needsFile: true },
  ],
  java: [
    { re: new RegExp(`\\b\\w{0,40}(?:request|req|Request)\\s*\\.\\s*get(?:Parameter|Header|IntHeader|ParameterValues)\\s*\\(\\s*"${KEY}"`, 'g') },
  ],
  kt: [
    { re: new RegExp(`\\bcall\\s*\\.\\s*(?:parameters|request\\s*\\.\\s*queryParameters|receiveParameters\\s*\\(\\s*\\))\\s*\\[\\s*"${KEY}"\\s*\\]`, 'g') },
    { re: new RegExp(`\\b\\w{0,40}(?:request|req)\\s*\\.\\s*get(?:Parameter|Header)\\s*\\(\\s*"${KEY}"`, 'g') },
  ],
  cs: [
    { re: new RegExp(`\\b(?:\\w+\\s*\\.\\s*)?Request\\s*\\.\\s*(?:Query|Form|Headers|Cookies|RouteValues)\\s*\\[\\s*"${KEY}"\\s*\\]`, 'g') },
  ],
  go: [
    { re: new RegExp(`\\b\\w+\\s*\\.\\s*URL\\s*\\.\\s*Query\\s*\\(\\s*\\)\\s*(?:\\.\\s*Get\\s*\\(\\s*${Q}${KEY}${Q}\\s*\\)|\\[\\s*${Q}${KEY}${Q}\\s*\\])`, 'g') },
    { re: new RegExp(`\\b\\w+\\s*\\.\\s*(?:FormValue|PostFormValue)\\s*\\(\\s*${Q}${KEY}${Q}\\s*\\)`, 'g') },
    { re: new RegExp(`\\b\\w+\\s*\\.\\s*(?:Form|PostForm|MultipartForm\\s*\\.\\s*Value)\\s*\\[\\s*${Q}${KEY}${Q}\\s*\\]`, 'g') },
    { re: new RegExp(`\\b\\w+\\s*\\.\\s*(?:Form|PostForm|Header)\\s*\\.\\s*Get\\s*\\(\\s*${Q}${KEY}${Q}\\s*\\)`, 'g') },
    { re: new RegExp(`\\bmux\\s*\\.\\s*Vars\\s*\\(\\s*\\w+\\s*\\)(?:\\s*\\[\\s*${Q}${KEY}${Q}\\s*\\])?`, 'g') },
    { re: new RegExp(`\\bchi\\s*\\.\\s*URLParam\\s*\\(\\s*\\w+\\s*,\\s*${Q}${KEY}${Q}\\s*\\)`, 'g') },
    // gin / echo / fiber context accessors, only where the function takes that context.
    { re: new RegExp(`\\b(\\w+)\\s*\\.\\s*(?:Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|QueryParam|FormValue|GetQuery)\\s*\\(\\s*${Q}${KEY}${Q}`, 'g'), ctxParam: true },
  ],
  php: [
    { re: new RegExp(`\\$_(?:GET|POST|REQUEST|COOKIE)\\s*\\[\\s*['"]${KEY}['"]\\s*\\]`, 'g') },
    { re: new RegExp(`\\$request\\s*->\\s*(?:input|query|get|post|integer|float|json|route|string)\\s*\\(\\s*['"]${KEY}['"]`, 'g'), body: true, formRequest: true },
    { re: new RegExp(`\\$request\\s*->\\s*(?:query|request)\\s*->\\s*(?:get|getInt|getDigits)\\s*\\(\\s*['"]${KEY}['"]`, 'g') },
    { re: new RegExp(`(?<![\\w$>:])request\\s*\\(\\s*['"]${KEY}['"]`, 'g'), body: true },
    { re: new RegExp(`\\bRequest::(?:input|get|query)\\s*\\(\\s*['"]${KEY}['"]`, 'g'), body: true },
    { re: new RegExp(`\\$this\\s*->\\s*request\\s*->\\s*(?:getQuery|getPost|getVar|getGet|getParam|getData|query|data)\\s*\\(\\s*['"]${KEY}['"]`, 'g') },
  ],
  rb: [
    { re: /(?<![\w@$.])params\s*\[\s*:?['"]?([A-Za-z_]\w{0,60})['"]?\s*\]/g, needsFile: true },
    { re: /(?<![\w@$.])params\s*\.\s*(?:fetch|dig)\s*\(\s*:?['"]?([A-Za-z_]\w{0,60})/g, needsFile: true },
    { re: /\brequest\s*\.\s*(?:params|query_parameters|request_parameters|GET|POST)\s*\[\s*:?['"]?([A-Za-z_]\w{0,60})['"]?\s*\]/g },
  ],
};

/** Ruby: `params[...]` means the request only in a controller or a routing DSL. */
const RB_REQUEST_FILE_RE = /<\s*(?:ApplicationController|ActionController::\w+|Sinatra::Base|Grape::API|Roda)\b|\bSinatra\b|^\s*(?:get|post|put|patch|delete)\s+['"]\//m;
/** Python: `request` is a server request only where a web framework is imported (a crawler's `request` is an outgoing one). */
const PY_WEB_IMPORT_RE = /^[ \t]*(?:from|import)[ \t]+(?:flask|django|fastapi|starlette|tornado|aiohttp|bottle|pyramid|falcon|sanic|quart|werkzeug|litestar|rest_framework)\b/m;
const RB_CONTROLLER_PATH_RE = /(?:^|[\\/])(?:controllers|routes|api)[\\/]|_controller\.rb$/;

/** Body fields may be bounded by a schema in another file when the file uses one. */
const VALIDATION_LIB_RE = /\b(?:joi|Joi|zod|yup|celebrate|express-validator|ajv|Ajv|class-validator|superstruct|valibot|typebox|marshmallow|pydantic|voluptuous|cerberus|jsonschema|wtforms|validate_request|FormRequest)\b/;

// ---------------------------------------------------------------------------
// Value transforms.
// ---------------------------------------------------------------------------

const NUMERIC_CONV_RE = /(?<![\w$.])(?:parseInt|parseFloat|Number|int|float|Integer|Float|BigInt|intval|floatval|abs)\s*\(|\b(?:Integer\s*\.\s*(?:parseInt|valueOf)|Long\s*\.\s*(?:parseLong|valueOf)|Short\s*\.\s*parseShort|Double\s*\.\s*(?:parseDouble|valueOf)|strconv\s*\.\s*(?:Atoi|ParseInt|ParseUint|ParseFloat)|(?:int|long|short|uint|ulong|Int32|Int64|UInt32|decimal|double)\s*\.\s*(?:Parse|TryParse)|Convert\s*\.\s*To(?:Int\d\d|UInt\d\d|Double|Decimal)|Math\s*\.\s*(?:floor|ceil|round|trunc|abs))\s*\(|\.\s*(?:to_i|to_f|toInt|toLong|toShort|toIntOrNull|toLongOrNull|toDouble|intValue|longValue|getInt|integer)\b|\(\s*(?:int|integer|float)\s*\)|\btype\s*=\s*int\b|->\s*(?:integer|getInt)\s*\(|(?:^|[=(,:?]\s{0,4})\+\s{0,4}(?=[A-Za-z_$])|~~\s*\w|\|\s*0\b/;
const CLAMP_RE = /(?<![\w$.])(?:Math\s*\.\s*[mM]in|min|clamp|Clamp|constrain|coerceAtMost|coerceIn|bound|limit\w*)\s*\(|\.\s*(?:clamp|coerceAtMost|coerceIn|Clamp)\s*\(|\]\s*\.\s*min\b|%(?!=)|&\s*0x/;
/** A member chain ending in a length accessor (`.length`, `.items.size()`): the size of held data. Walked by hand, one segment at a time. */
const SEGMENT_RE = /^\s{0,4}\.\s{0,4}([A-Za-z_$][\w$]{0,60})/;
const LENGTH_WORD_RE = /^(?:length|size|count|byteLength|Length|Count|len)$/;
const LEN_AFTER_RE = { test(after) {
  let t = after;
  for (let k = 0; k < 6; k++) {
    const m = SEGMENT_RE.exec(t);
    if (!m) return false;
    if (LENGTH_WORD_RE.test(m[1])) return true;
    t = t.slice(m[0].length);
  }
  return false;
} };

/**
 * Calls a request value passes through and stays the caller's number or
 * string: numeric conversions, string trims, request accessors. Any other
 * call's RESULT (a database row looked up by a request id, a computed object)
 * is not a value the caller chose, so taint does not cross it.
 */
const TRANSPARENT_CALL_RE = /^(?:parseInt|parseFloat|Number|int|float|Integer|Float|BigInt|intval|floatval|abs|floor|ceil|round|trunc|parseLong|parseShort|parseDouble|valueOf|Atoi|ParseInt|ParseUint|ParseFloat|Parse|TryParse|ToInt16|ToInt32|ToInt64|ToUInt32|ToDouble|ToDecimal|String|str|toString|trim|strip|Trim|decodeURIComponent|unquote|get|getlist|fetch|dig|getParameter|getHeader|Get|FormValue|PostFormValue|Query|DefaultQuery|Param|input|query|integer|toInt|toLong|max|Max|Some|Optional|of|orElse|getOrDefault|getOrElse)$/;

/** Is offset `i` of `text` inside the arguments of a call that is not transparent? */
function insideOpaqueCall(text, i) {
  let depth = 0;
  for (let k = i - 1; k >= 0; k--) {
    const ch = text[k];
    if (ch === ')' || ch === ']' || ch === '}') { depth++; continue; }
    if (ch === '(' || ch === '[' || ch === '{') {
      if (depth > 0) { depth--; continue; }
      if (ch !== '(') continue;
      const before = text.slice(Math.max(0, k - 80), k).replace(/\s+$/, '');
      const w = (before.match(/([A-Za-z_$][\w$]*)$/) || [])[1];
      if (!w) continue;                           // grouping parenthesis
      if (TRANSPARENT_CALL_RE.test(w)) continue;
      if (/^(?:if|while|for|switch|return|await|typeof|not|and|or|in|elif)$/.test(w)) continue;
      return true;
    }
  }
  return false;
}
const LEN_BEFORE_RE = /(?:\blen|\bcount|\bstrlen|\bmb_strlen|\bsizeof|\blength)\s*\(\s*$/;
const TYPED = new Set(['java', 'kt', 'cs', 'go']);

const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function nameRe(name, flags = 'g') {
  return name.startsWith('$')
    ? new RegExp(`(?<![\\w$])${escRe(name)}(?![\\w])`, flags)
    : new RegExp(`(?<![\\w$.])${escRe(name)}(?![\\w$])`, flags);
}

function lineStarts(code) {
  const s = [0];
  for (let i = 0; i < code.length; i++) if (code.charCodeAt(i) === 10) s.push(i + 1);
  return s;
}
function lineAt(starts, off) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= off) lo = mid; else hi = mid - 1; }
  return lo + 1;
}

const OPEN = { '(': ')', '[': ']', '{': '}' };
function matchClose(masked, i, limit = 200_000) {
  const o = masked[i], c = OPEN[o];
  if (!c) return -1;
  let depth = 0;
  const end = Math.min(masked.length, i + limit);
  for (let k = i; k < end; k++) {
    const ch = masked[k];
    if (ch === o) depth++;
    else if (ch === c) { depth--; if (depth === 0) return k; }
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Function scopes. Brace languages: every `{` whose header reads as a function
// (a `function`/`func`/`fun` keyword, an arrow, or a `)` that does not close a
// control statement). Python and Ruby: `def` units, plus Ruby routing blocks.
// The analysis region of a use is its OUTERMOST enclosing function, so a value
// read in a handler is still known inside a callback it defines.
// ---------------------------------------------------------------------------

const CONTROL_WORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'foreach', 'using', 'lock', 'synchronized', 'when', 'fixed', 'elseif', 'with', 'until', 'unless', 'return', 'typeof', 'sizeof']);

function headerIsFunction(lang, header) {
  const h = header.replace(/\s+$/, '');
  if (lang === 'go') return /\bfunc\b/.test(h);
  if (lang === 'php') return /\bfunction\b|\bfn\b/.test(h) && /\)\s*(?::\s*[?\w\\|]+)?\s*(?:use\s*\([^)]*\)\s*(?::\s*[?\w\\|]+)?)?$/.test(h);
  if (lang === 'js' && /=>$/.test(h)) return true;
  if (lang === 'kt' && /->$/.test(h)) return false;
  // `) {`, `): Type {`, `) throws X {`, `) where T : U {`
  const m = h.match(/\)\s*(?::\s*[\w<>\[\]?.,| ]{1,80}|throws\s+[\w., ]{1,120}|where\s+[^{}]{1,120})?$/);
  if (!m) return false;
  const closeIdx = h.lastIndexOf(')', m.index + 1);
  let depth = 0, k = closeIdx;
  for (; k >= 0; k--) {
    if (h[k] === ')') depth++;
    else if (h[k] === '(') { depth--; if (depth === 0) break; }
  }
  if (k < 0) return false;
  const before = h.slice(0, k).replace(/\s+$/, '');
  const word = (before.match(/([A-Za-z_]\w*)$/) || [])[1];
  if (!word) return lang === 'js' && /[=(,:]\s*$|^$/.test(before) ? false : false;
  if (CONTROL_WORDS.has(word)) return false;
  if (/\belse\s+if$/.test(before)) return false;
  return true;
}

function braceScopes(lang, masked) {
  const scopes = [];
  const stack = [];
  for (let i = 0; i < masked.length; i++) {
    const ch = masked[i];
    if (ch === '{') {
      let j = i - 1;
      const stop = Math.max(0, i - 600);
      while (j >= stop && masked[j] !== ';' && masked[j] !== '{' && masked[j] !== '}') j--;
      const header = masked.slice(j + 1, i);
      stack.push({ open: i, fn: headerIsFunction(lang, header), headerStart: j + 1 });
    } else if (ch === '}') {
      const top = stack.pop();
      if (top && top.fn) scopes.push({ start: top.open + 1, end: i, headerStart: top.headerStart, header: masked.slice(top.headerStart, top.open) });
    }
  }
  return scopes;
}

function indentScopes(lang, masked, code) {
  const units = functionUnits(lang, masked).map((u) => {
    // Header: decorator lines above the def through the def line's params.
    const st = lineStarts(masked);
    let hs = st[u.line - 1];
    for (let k = u.line - 2; k >= 0; k--) {
      const t = masked.slice(st[k], (st[k + 1] ?? masked.length) - 1).trim();
      if (t.startsWith('@')) hs = st[k]; else break;
    }
    return { start: u.start, end: u.end, headerStart: hs, header: code.slice(hs, u.start), params: u.params };
  });
  if (lang === 'rb') {
    const lines = masked.split('\n');
    const st = lineStarts(masked);
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^(\s*)(?:get|post|put|patch|delete)\b[^\n]*\bdo\b/);
      if (!m) continue;
      const ind = m[1].length;
      let end = masked.length;
      for (let k = i + 1; k < lines.length; k++) {
        const t = lines[k];
        if (!t.trim()) continue;
        if (t.length - t.trimStart().length <= ind) { end = st[k]; break; }
      }
      units.push({ start: st[i + 1] ?? masked.length, end, headerStart: st[i], header: lines[i] });
    }
  }
  return units;
}

// ---------------------------------------------------------------------------
// Parameter sources: bound from the request by annotation or route.
// ---------------------------------------------------------------------------

function splitTop(text) {
  const parts = [];
  let depth = 0, cur = '';
  for (const ch of text) {
    if ('([{<'.includes(ch)) depth++;
    else if (')]}>'.includes(ch)) depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts;
}

/** Parameters bound from the request by annotation, attribute, route decorator or binding call. */
const PARAM_HINT_RE = /@(?:RequestParam|PathVariable|QueryParam|PathParam|FormParam|RequestHeader|HeaderParam|CookieValue|QueryValue|PathValue|RequestBody)\b|\[\s*From(?:Query|Route|Form|Header)\b|@[\w.]{1,80}\.(?:get|post|put|patch|delete|route|api_route)\s*\(|\b(?:ShouldBind\w*|BindJSON|BindQuery|Bind)\s*\(|\bNewDecoder\s*\(/;
const JAVA_PARAM_ANN = /@(?:RequestParam|PathVariable|QueryParam|PathParam|FormParam|RequestHeader|HeaderParam|CookieValue|QueryValue|PathValue)\b/;
const JAVA_PARAM_BOUND = /@(?:Max|DecimalMax|Range|Size|Digits|Length)\b/;
const NUMERIC_TYPE_RE = /\b(?:int|long|short|Integer|Long|Short|Int|UInt|ULong|uint|ulong|double|float|Double|Float|BigInteger)\b/;
const COLLECTION_TYPE_RE = /\b(?:List|Set|Collection|Iterable|Array|IList|IEnumerable|ICollection|MutableList)\s*<|\[\]/;

function paramSources(lang, scope, code, rawHeader) {
  const out = [];
  const hdr = rawHeader;
  const open = hdr.indexOf('(');
  if (open === -1) return out;
  // The parameter list is the LAST balanced (...) before the body for most
  // languages; for Java/Kotlin/C# annotations it is the method's own list.
  let close = hdr.lastIndexOf(')');
  let depth = 0, k = close;
  for (; k >= 0; k--) {
    if (hdr[k] === ')') depth++;
    else if (hdr[k] === '(') { depth--; if (depth === 0) break; }
  }
  if (k < 0) return out;
  const plist = hdr.slice(k + 1, close);
  if (lang === 'java' || lang === 'kt' || lang === 'cs') {
    for (const p of splitTop(plist)) {
      let name = null;
      const t = p.trim();
      if (lang === 'kt') { const m = t.match(/([A-Za-z_]\w*)\s*:\s*[^:]+$/); name = m && m[1]; }
      else { const words = t.replace(/@\w+(?:\([^)]*\))?|\[[^\]]*\]/g, ' ').match(/[A-Za-z_]\w*/g) || []; name = words[words.length - 1]; }
      if (!name) continue;
      const typeText = t.replace(/@\w+(?:\([^)]*\))?|\[[^\]]*\]/g, ' ');
      if (lang === 'cs') {
        if (!/\[\s*From(?:Query|Route|Form|Header)\b/.test(t)) continue;
        out.push({ name, numeric: NUMERIC_TYPE_RE.test(typeText), collection: COLLECTION_TYPE_RE.test(typeText), bounded: /\[\s*(?:Range|MaxLength|StringLength)\b/.test(t), key: name });
        continue;
      }
      if (JAVA_PARAM_ANN.test(t)) {
        out.push({ name, numeric: NUMERIC_TYPE_RE.test(typeText), collection: COLLECTION_TYPE_RE.test(typeText), bounded: JAVA_PARAM_BOUND.test(t), key: name });
      } else if (/@RequestBody\b/.test(t)) {
        if (/@(?:Valid|Validated)\b/.test(t)) continue;      // bean validation runs on the body
        out.push({ name, numeric: false, collection: COLLECTION_TYPE_RE.test(typeText), object: true, key: null });
      }
    }
    return out;
  }
  if (lang === 'py') {
    // Route-decorated function: typed `int` parameters (FastAPI query/path,
    // Flask `<int:name>` converters) are request values.
    const deco = hdr.match(/@[\w.]{1,80}\.(?:get|post|put|patch|delete|route|api_route)\s*\(([^\n]*)/);
    if (!deco) return out;
    const conv = new Set([...deco[1].matchAll(/<\s*int\s*:\s*(\w+)\s*>/g)].map((m) => m[1]));
    for (const p of splitTop(plist)) {
      const m = p.trim().match(/^([A-Za-z_]\w*)\s*(?::\s*([^=]+))?(?:=\s*([\s\S]+))?$/);
      if (!m) continue;
      const [, name, ann = '', def = ''] = m;
      if (name === 'self' || name === 'request') continue;
      const isInt = /^\s*(?:int|Optional\[\s*int\s*\]|int\s*\|\s*None|Annotated\[\s*int\b)/.test(ann) || conv.has(name);
      if (!isInt) continue;
      const bounded = /\b(?:le|lt)\s*=/.test(ann + def) || /\bconint\s*\([^)]*\b(?:le|lt)\s*=/.test(ann);
      out.push({ name, numeric: true, bounded, key: name });
    }
    return out;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Taint replay inside one region.
// ---------------------------------------------------------------------------

function assignRegex(lang) {
  // Bounded, non-overlapping quantifiers throughout: these run over whole function bodies.
  if (lang === 'php') return /(?<![\w$>:])(\$[A-Za-z_]\w{0,60})[ \t]{0,8}(\.|\+|\*|-)?=(?![=>])/g;
  if (lang === 'py') return /^[ \t]{0,200}([A-Za-z_]\w{0,60})[ \t]{0,8}(?::[^=\n]{1,80})?(\+|\*|-)?=(?!=)/gm;
  if (lang === 'rb') return /^[ \t]{0,200}([a-z_]\w{0,60})[ \t]{0,8}(\+|\*|-|\|\|)?=(?![=~>])/gm;
  if (lang === 'go') return /(?<![\w$.])([A-Za-z_]\w{0,60})(?:[ \t]{0,8},[ \t]{0,8}([A-Za-z_]\w{0,60}))?[ \t]{0,8}(\+|\*|-)?:?=(?!=)/g;
  // js / java / kt / cs
  return /(?<![\w$.])([A-Za-z_$][\w$]{0,60})[ \t]{0,8}(?::[ \t]{0,8}[\w<>\[\]|.?]{1,60}[ \t]{0,8})?(\+|\*|-)?=(?![=>~])/g;
}

function rhsAfter(masked, from) {
  let depth = 0;
  const end = Math.min(masked.length, from + 600);
  for (let k = from; k < end; k++) {
    const ch = masked[k];
    if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) { if (depth === 0) return k; depth--; }
    else if ((ch === ';' || ch === '\n') && depth === 0) return k;
  }
  return end;
}

function findSources(ctx, from, to) {
  const { lang, code, masked } = ctx;
  const out = [];
  const text = code.slice(from, to);
  for (const src of SOURCES[lang] || []) {
    if (src.needsFile && !ctx.requestFile) continue;
    src.re.lastIndex = 0;
    let m;
    while ((m = src.re.exec(text))) {
      const at = from + m.index;
      if (masked[at] !== code[at]) continue;           // inside a string
      if (src.ctxParam && !ctx.goCtxNames.has(m[1])) continue;
      const key = src.ctxParam ? m[2] || m[3] : (m[1] || m[2] || m[3] || null);
      out.push({ at, end: at + m[0].length, text: m[0], key: key && !/^(?:get|getlist)$/.test(key) ? key : null, body: !!src.body, formRequest: !!src.formRequest, needsScope: src.needsScope });
    }
  }
  return out;
}

/**
 * Replay assignments in [region.start, upTo). Returns Map name -> info.
 * info = { numeric, keys:Set, family:Set, body, srcTexts:Set, line, collection, object }
 */
function taintAt(ctx, region, upTo) {
  const cacheKey = `${region.start}:${upTo}`;
  if (ctx.taintCache.has(cacheKey)) return ctx.taintCache.get(cacheKey);
  const { lang, code, masked } = ctx;
  const tainted = new Map();
  for (const p of region.params || []) {
    tainted.set(p.name, { numeric: p.numeric || TYPED.has(lang), conv: !!p.numeric, keys: new Set(p.key ? [p.key] : []), family: new Set([p.name]), body: false, srcTexts: new Set(), bounded: p.bounded, collection: !!p.collection, object: !!p.object, param: true });
  }
  const events = [];
  const re = assignRegex(lang);
  re.lastIndex = 0;
  const seg = masked.slice(region.start, upTo);
  let m;
  while ((m = re.exec(seg))) {
    const at = region.start + m.index;
    const eq = region.start + m.index + m[0].length;
    if (lang === 'go') {
      events.push({ at, names: [m[1], m[2]].filter(Boolean), op: m[3], rhsFrom: eq });
    } else {
      events.push({ at, names: [m[1]], op: m[2], rhsFrom: eq });
    }
  }
  // JS destructuring from a request object: `const { a, b: c, d = 1 } = req.query`.
  if (lang === 'js') {
    const dre = /\b(?:const|let|var)\s*\{([^{}]{1,300})\}\s*=(?!=)/g;
    while ((m = dre.exec(seg))) {
      const names = splitTop(m[1]).map((p) => { const t = p.split('=')[0].trim(); const c = t.indexOf(':'); return (c === -1 ? t : t.slice(c + 1)).trim().replace(/^\.\.\./, ''); }).filter((n) => /^[A-Za-z_$][\w$]*$/.test(n));
      events.push({ at: region.start + m.index, names, op: null, rhsFrom: region.start + m.index + m[0].length, destructure: true });
    }
  }
  // C#: `int.TryParse(src, out var n)`.
  if (lang === 'cs') {
    const tre = /\bTryParse\s*\(\s*([^,()]{1,200}(?:\([^()]*\))?[^,()]{0,40}),\s*out\s+(?:var\s+|int\s+|long\s+|short\s+|uint\s+|ulong\s+)?([A-Za-z_]\w*)\s*\)/g;
    while ((m = tre.exec(seg))) events.push({ at: region.start + m.index, names: [m[2]], op: null, rhsFrom: region.start + m.index, rhsText: code.slice(region.start + m.index, region.start + m.index + m[0].length), forceNumeric: true });
  }
  // Go request binding: Decode(&v), ShouldBindJSON(&v), Bind(&v).
  if (lang === 'go') {
    const bre = /(?:json\s*\.\s*NewDecoder\s*\(\s*\w+(?:\s*\.\s*Request)?\s*\.\s*Body\s*\)\s*\.\s*Decode|\b\w+\s*\.\s*(ShouldBindJSON|BindJSON|ShouldBind|Bind|ShouldBindQuery|BindQuery))\s*\(\s*&\s*([A-Za-z_]\w*)\s*\)/g;
    while ((m = bre.exec(seg))) {
      const v = m[2];
      if (m[1]) {
        // gin's binding applies struct tags: only trust a struct declared here.
        const decl = code.match(new RegExp(`\\bvar\\s+${escRe(v)}\\s+(\\w+)|\\b${escRe(v)}\\s*:?=\\s*&?(\\w+)\\s*\\{`));
        const T = decl && (decl[1] || decl[2]);
        if (!T || !new RegExp(`\\btype\\s+${escRe(T)}\\s+struct\\b`).test(code)) continue;
      }
      events.push({ at: region.start + m.index, names: [v], op: null, rhsFrom: -1, bind: true });
    }
  }
  events.sort((a, b) => a.at - b.at);
  for (const ev of events) {
    if (ev.bind) {
      tainted.set(ev.names[0], { numeric: true, keys: new Set(), family: new Set([ev.names[0]]), body: true, srcTexts: new Set(), object: true, line: lineAt(ctx.starts, ev.at) });
      continue;
    }
    const rhsEnd = ev.rhsText ? ev.rhsFrom + ev.rhsText.length : rhsAfter(masked, ev.rhsFrom);
    const rhs = ev.rhsText || code.slice(ev.rhsFrom, rhsEnd);
    const rhsMasked = masked.slice(ev.rhsFrom, ev.rhsFrom + rhs.length);
    const refs = refsIn(ctx, rhs, rhsMasked, ev.rhsFrom, tainted, region);
    const lhsKept = ev.op && ev.names.every((n) => tainted.has(n));
    if (!refs.any) {
      if (!lhsKept) for (const n of ev.names) tainted.delete(n);
      continue;
    }
    if (CLAMP_RE.test(rhsMasked) || refs.onlyLength) { for (const n of ev.names) tainted.delete(n); continue; }
    if (/(?<![<>=!-])(?:<=?|>=?)(?![<>=])/.test(rhsMasked.replace(/=>|->|<<|>>/g, '  ')) && !/<[A-Z]\w*>/.test(rhsMasked)) {
      // A ternary or boolean over the value: `n > MAX ? MAX : n` is a clamp.
      for (const n of ev.names) tainted.delete(n);
      continue;
    }
    const conv = !!ev.forceNumeric || NUMERIC_CONV_RE.test(rhsMasked) || refs.conv;
    const numeric = conv || refs.numeric || TYPED.has(lang);
    const fam = new Set(refs.family);
    const info = { numeric, conv, keys: refs.keys, family: fam, body: refs.body, srcTexts: refs.srcTexts, bounded: refs.bounded, collection: refs.collection, object: false, line: lineAt(ctx.starts, ev.at) };
    // Go `n, err := strconv.Atoi(...)`: only the first name is the value.
    const targets = lang === 'go' && ev.names.length === 2 ? [ev.names[0]] : ev.names;
    for (const n of targets) { info.family.add(n); tainted.set(n, { ...info, family: new Set(info.family) }); }
    if (lang === 'go' && ev.names.length === 2) tainted.delete(ev.names[1]);
  }
  ctx.taintCache.set(cacheKey, tainted);
  return tainted;
}

/**
 * Request references in `text` (a slice of code starting at `absFrom`):
 * direct sources and tainted names. A reference immediately measured by a
 * length accessor is a size of held data, not a chosen number.
 */
function refsIn(ctx, text, textMasked, absFrom, tainted, region) {
  const res = { any: false, numeric: false, conv: false, keys: new Set(), family: new Set(), body: false, srcTexts: new Set(), onlyLength: false, bounded: false, collection: false };
  let plain = 0, lengthOnly = 0;
  for (const s of findSources(ctx, absFrom, absFrom + text.length)) {
    if (s.needsScope && !s.needsScope.test(ctx.code.slice(region.start, region.end))) continue;
    if (s.formRequest && ctx.phpFormRequest) continue;
    const after = ctx.code.slice(s.end, s.end + 40);
    const before = ctx.code.slice(Math.max(0, s.at - 20), s.at);
    if (LEN_AFTER_RE.test(after) || LEN_BEFORE_RE.test(before)) { lengthOnly++; continue; }
    if (insideOpaqueCall(textMasked, s.at - absFrom)) continue;
    plain++;
    res.any = true;
    if (s.key) res.keys.add(s.key);
    res.srcTexts.add(s.text);
    if (s.body) res.body = true;
    res.collection = true;
  }
  for (const [name, info] of tainted) {
    const r = nameRe(name);
    let m;
    while ((m = r.exec(textMasked))) {
      const after = textMasked.slice(m.index + m[0].length, m.index + m[0].length + 40);
      const before = textMasked.slice(Math.max(0, m.index - 20), m.index);
      if (LEN_AFTER_RE.test(after) || LEN_BEFORE_RE.test(before)) { lengthOnly++; continue; }
      if (insideOpaqueCall(textMasked, m.index)) continue;
      plain++;
      res.any = true;
      if (info.numeric) res.numeric = true;
      if (info.conv) res.conv = true;
      for (const k of info.keys) res.keys.add(k);
      for (const f of info.family) res.family.add(f);
      for (const t of info.srcTexts) res.srcTexts.add(t);
      if (info.body) res.body = true;
      if (info.bounded) res.bounded = true;
      if (info.collection || info.object) res.collection = true;
      res.family.add(name);
    }
  }
  if (!plain && lengthOnly) res.onlyLength = true;
  return res;
}

// ---------------------------------------------------------------------------
// Guards.
// ---------------------------------------------------------------------------

/** Offsets covered by `for (...)` headers and Go `for ... {` clauses: their comparisons bound a counter, not the value. */
function loopHeaderRanges(lang, masked) {
  const ranges = [];
  const re = lang === 'go' ? /\bfor\b[^{\n]*\{/g : /\bfor\s*\(/g;
  let m;
  while ((m = re.exec(masked))) {
    if (lang === 'go') { ranges.push([m.index, m.index + m[0].length]); continue; }
    const open = m.index + m[0].length - 1;
    const close = matchClose(masked, open, 2000);
    if (close !== -1) ranges.push([m.index, close]);
  }
  if (lang === 'py' || lang === 'rb') {
    const r2 = /^\s*for\b[^\n]*/gm;
    while ((m = r2.exec(masked))) ranges.push([m.index, m.index + m[0].length]);
  }
  return ranges;
}
const inRanges = (ranges, i) => ranges.some(([a, b]) => i >= a && i < b);

const LOWER_LITERAL_RE = /^\s*-?\s*(?:0|1)(?:\.0+)?[lLuU]?\s*$/;
const VALIDATOR_CALL_RE = /(?<![\w$])(?:validate|check|assert|ensure|verify|require|limit|clamp|bound|cap|guard|enforce|restrict)\w{0,40}\s*\(/gi;

function guardedBefore(ctx, region, upTo, names, srcTexts) {
  const { masked } = ctx;
  const seg = masked.slice(region.start, upTo);
  const base = region.start;
  for (const name of names) {
    const n = escRe(name);
    const lb = name.startsWith('$') ? '(?<![\\w$])' : '(?<![\\w$.])';
    // name OP other
    const fwd = new RegExp(`${lb}${n}(?:\\s*\\.\\s*\\w+(?:\\(\\s*\\))?)?\\s*(<=|>=|<|>)(?![<>=])\\s*([^;\\n&|)?:,]{1,60})`, 'g');
    let m;
    while ((m = fwd.exec(seg))) {
      if (inRanges(ctx.loopHeaders, base + m.index)) continue;
      if (/^\s*[A-Z]\w*\s*>/.test(m[2]) && m[1] === '<') continue;        // generic type argument
      if (LOWER_LITERAL_RE.test(m[2])) continue;
      return { kind: 'comparison', line: lineAt(ctx.starts, base + m.index) };
    }
    // other OP name
    const rev = new RegExp(`([\\w$.)\\]]{1,60})\\s*(?<![<>=-])(<=|>=|<|>)(?![<>=])\\s*${n}(?![\\w$])`, 'g');
    while ((m = rev.exec(seg))) {
      if (inRanges(ctx.loopHeaders, base + m.index)) continue;
      if (LOWER_LITERAL_RE.test(m[1])) continue;
      if (m[2] === '<' && /^[A-Z]/.test(m[1]) && /^\s*[>,]/.test(seg.slice(m.index + m[0].length))) continue;   // List<n> style generics
      return { kind: 'comparison', line: lineAt(ctx.starts, base + m.index) };
    }
    // clamp(name ...), name.clamp(...), [name, MAX].min
    const clamp = new RegExp(`(?:(?<![\\w$.])(?:Math\\s*\\.\\s*[mM]in|min|clamp|Clamp|constrain|coerceAtMost|coerceIn)\\s*\\([^;\\n]{0,80}${lb}${n}(?![\\w$])|${lb}${n}\\s*\\.\\s*(?:clamp|coerceAtMost|coerceIn|Clamp)\\s*\\(|\\[[^\\]\\n]{0,60}${lb}${n}(?![\\w$])[^\\]\\n]{0,60}\\]\\s*\\.\\s*min\\b)`);
    if (clamp.test(seg)) return { kind: 'clamp' };
    VALIDATOR_CALL_RE.lastIndex = 0;
    while ((m = VALIDATOR_CALL_RE.exec(seg))) {
      const open = m.index + m[0].length - 1;
      const close = matchClose(seg, open, 400);
      if (close === -1) continue;
      if (nameRe(name, '').test(seg.slice(open + 1, close))) return { kind: 'validator' };
    }
  }
  for (const t of srcTexts) {
    const s = escRe(t.replace(/\s+/g, ' ')).replace(/ /g, '\\s*');
    const cmp = new RegExp(`${s}\\s*(<=|>=|<|>)(?![<>=])\\s*([^;\\n&|)?:]{1,60})|([\\w$.)]{1,60})\\s*(?<![<>=-])(?:<=|>=|<|>)(?![<>=])\\s*${s}`);
    const m = ctx.code.slice(region.start, upTo).match(cmp);
    if (m && !(m[2] && LOWER_LITERAL_RE.test(m[2])) && !(m[3] && LOWER_LITERAL_RE.test(m[3]))) return { kind: 'comparison' };
  }
  return null;
}

/** A schema line naming the request field next to a maximum: `n: Joi.number().max(100)`, `'n' => 'integer|max:100'`, `query('n').isInt({ max: 50 })`. */
function schemaBounded(ctx, keys) {
  for (const k of keys) {
    const re = new RegExp(`(?:['"\`]${escRe(k)}['"\`]|(?<![\\w$.])${escRe(k)}\\s*[:=])[^\\n]{0,160}(?:\\bmax\\b|\\bmax\\s*[:=(]|\\.max\\s*\\(|\\b(?:le|lt|lte|maximum|max_value|maxValue|between)\\b|@Max\\b|\\bRange\\b)`, 'i');
    if (re.test(ctx.code)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Sinks. Matched on the masked text; arguments read from the code.
// pick(args) returns the size argument(s).
// ---------------------------------------------------------------------------

const ONE = (a) => (a.length === 1 ? [a[0]] : []);
const FIRST = (a) => a.slice(0, 1);
const SECOND = (a) => a.slice(1, 2);
const SECOND_OR_ONLY = (a) => (a.length === 1 ? [a[0]] : a.slice(1, 2));

const SINKS = {
  js: [
    { re: /\bnew\s+Array\s*\(/g, pick: ONE, kind: 'alloc', what: 'new Array(n)', numeric: true },
    { re: /(?<![\w$.])Array\s*\(/g, pick: ONE, kind: 'alloc', what: 'Array(n)', numeric: true },
    { re: /\bArray\s*\.\s*from\s*\(/g, pick: (a) => { const m = (a[0] || '').match(/^\s*\{\s*length\s*:\s*([^,}]+)\}?/); return m ? [m[1]] : []; }, kind: 'alloc', what: 'Array.from({ length: n })', numeric: false },
    { re: /\.\s*repeat\s*\(/g, pick: ONE, kind: 'alloc', what: 'String.prototype.repeat(n)', numeric: false },
    { re: /\.\s*pad(?:Start|End)\s*\(/g, pick: FIRST, kind: 'alloc', what: 'padStart/padEnd(n)', numeric: false },
    { re: /\bBuffer\s*\.\s*alloc(?:Unsafe|UnsafeSlow)?\s*\(/g, pick: FIRST, kind: 'alloc', what: 'Buffer.alloc(n)', numeric: true },
    { re: /\bnew\s+(?:(?:Uint8|Int8|Uint16|Int16|Uint32|Int32|Float32|Float64|BigInt64|BigUint64|Uint8Clamped)Array|ArrayBuffer|SharedArrayBuffer)\s*\(/g, pick: ONE, kind: 'alloc', what: 'typed array of n elements', numeric: true },
    { re: /\bcrypto\s*\.\s*randomBytes\s*\(/g, pick: FIRST, kind: 'alloc', what: 'crypto.randomBytes(n)', numeric: false },
  ],
  py: [
    { re: /(?:\bin\s+|\b(?:list|tuple|set|sum|sorted)\s*\(\s*)range\s*\(/g, pick: SECOND_OR_ONLY, kind: 'iter', what: 'range(n)', numeric: true },
    { re: /\bbytearray\s*\(/g, pick: ONE, kind: 'alloc', what: 'bytearray(n)', numeric: true },
    { re: /(?<![\w.])bytes\s*\(/g, pick: ONE, kind: 'alloc', what: 'bytes(n)', numeric: true },
    { re: /\bos\s*\.\s*urandom\s*\(/g, pick: FIRST, kind: 'alloc', what: 'os.urandom(n)', numeric: true },
    { re: /\bsecrets\s*\.\s*token_(?:bytes|hex|urlsafe)\s*\(/g, pick: FIRST, kind: 'alloc', what: 'secrets.token_*(n)', numeric: true },
    { re: /\b(?:np|numpy)\s*\.\s*(?:zeros|ones|empty|full|arange)\s*\(/g, pick: FIRST, kind: 'alloc', what: 'a numpy array of n elements', numeric: true },
    { re: /\bitertools\s*\.\s*repeat\s*\(/g, pick: SECOND, kind: 'iter', what: 'itertools.repeat(x, n)', numeric: true },
  ],
  rb: [
    { re: /\bArray\s*\.\s*new\s*\(/g, pick: FIRST, kind: 'alloc', what: 'Array.new(n)', numeric: true },
    { re: /\.\s*(?:ljust|rjust|center)\s*\(/g, pick: FIRST, kind: 'alloc', what: 'ljust/rjust/center(n)', numeric: true },
    { re: /\bSecureRandom\s*\.\s*(?:hex|random_bytes|base64|urlsafe_base64|alphanumeric)\s*\(/g, pick: FIRST, kind: 'alloc', what: 'SecureRandom of n bytes', numeric: true },
    { re: /\b\d+\s*\.\s*upto\s*\(/g, pick: FIRST, kind: 'iter', what: 'upto(n)', numeric: true },
  ],
  java: [
    { re: /\bnew\s+(?:byte|char|short|int|long|float|double|boolean|[A-Z]\w*)\s*\[/g, bracket: true, kind: 'alloc', what: 'an array of n elements', numeric: false },
    { re: /\bnew\s+(?:ArrayList|HashMap|HashSet|LinkedHashMap|LinkedHashSet|ArrayDeque|Vector|StringBuilder|StringBuffer|PriorityQueue|ConcurrentHashMap)\s*(?:<[^<>()]{0,80}>)?\s*\(/g, pick: ONE, kind: 'alloc', what: 'a pre-sized collection', numeric: true },
    { re: /\bByteBuffer\s*\.\s*allocate(?:Direct)?\s*\(/g, pick: FIRST, kind: 'alloc', what: 'ByteBuffer.allocate(n)', numeric: false },
    { re: /\.\s*repeat\s*\(/g, pick: ONE, kind: 'alloc', what: 'String.repeat(n)', numeric: false },
    { re: /\bCollections\s*\.\s*nCopies\s*\(/g, pick: FIRST, kind: 'alloc', what: 'Collections.nCopies(n, x)', numeric: false },
    { re: /\bIntStream\s*\.\s*range(?:Closed)?\s*\(/g, pick: SECOND, kind: 'iter', what: 'IntStream.range(0, n)', numeric: false },
    { re: /\bArrays\s*\.\s*copyOf\s*\(/g, pick: SECOND, kind: 'alloc', what: 'Arrays.copyOf(a, n)', numeric: false },
  ],
  kt: [
    { re: /\b(?:Byte|Int|Long|Char|Short|Double|Float|Boolean)Array\s*\(/g, pick: FIRST, kind: 'alloc', what: 'a primitive array of n elements', numeric: false },
    { re: /\barrayOfNulls\s*<[^<>()]{1,60}>\s*\(/g, pick: FIRST, kind: 'alloc', what: 'arrayOfNulls(n)', numeric: false },
    { re: /(?<![\w.])(?:Array|MutableList|List)\s*\(/g, pick: (a) => (a.length <= 2 ? FIRST(a) : []), kind: 'alloc', what: 'a list of n elements', numeric: true },
    { re: /\.\s*repeat\s*\(/g, pick: ONE, kind: 'alloc', what: 'String.repeat(n)', numeric: false },
    { re: /(?<![\w.])repeat\s*\(/g, pick: ONE, kind: 'iter', what: 'repeat(n)', numeric: false },
    { re: /\bByteBuffer\s*\.\s*allocate(?:Direct)?\s*\(/g, pick: FIRST, kind: 'alloc', what: 'ByteBuffer.allocate(n)', numeric: false },
    { re: /\bStringBuilder\s*\(/g, pick: ONE, kind: 'alloc', what: 'StringBuilder(n)', numeric: true },
  ],
  cs: [
    { re: /\bnew\s+(?:byte|char|short|int|long|float|double|bool|string|object|[A-Z]\w*)\s*\[/g, bracket: true, kind: 'alloc', what: 'an array of n elements', numeric: false },
    { re: /\bnew\s+string\s*\(/g, pick: (a) => (a.length === 2 && /^\s*'/.test(a[0]) ? [a[1]] : []), kind: 'alloc', what: "new string(c, n)", numeric: false },
    { re: /\bEnumerable\s*\.\s*(?:Range|Repeat)\s*\(/g, pick: SECOND, kind: 'iter', what: 'Enumerable.Range/Repeat(…, n)', numeric: false },
    { re: /\bnew\s+(?:List|Dictionary|HashSet|StringBuilder|Queue|Stack)\s*(?:<[^<>()]{0,80}>)?\s*\(/g, pick: ONE, kind: 'alloc', what: 'a pre-sized collection', numeric: true },
    { re: /\.\s*Pad(?:Left|Right)\s*\(/g, pick: FIRST, kind: 'alloc', what: 'PadLeft/PadRight(n)', numeric: false },
    { re: /\bArrayPool\s*<[^<>()]{1,40}>\s*\.\s*Shared\s*\.\s*Rent\s*\(/g, pick: FIRST, kind: 'alloc', what: 'ArrayPool.Rent(n)', numeric: false },
  ],
  go: [
    { re: /\bmake\s*\(/g, pick: (a) => a.slice(1, 3), kind: 'alloc', what: 'make(…, n)', numeric: false },
    { re: /\b(?:strings|bytes)\s*\.\s*Repeat\s*\(/g, pick: SECOND, kind: 'alloc', what: 'strings.Repeat(s, n)', numeric: false },
  ],
  php: [
    { re: /(?<![\w$>:])str_repeat\s*\(/g, pick: SECOND, kind: 'alloc', what: 'str_repeat($s, $n)', numeric: false },
    { re: /(?<![\w$>:])array_fill\s*\(/g, pick: SECOND, kind: 'alloc', what: 'array_fill($start, $n, …)', numeric: false },
    { re: /(?<![\w$>:])array_pad\s*\(/g, pick: SECOND, kind: 'alloc', what: 'array_pad($a, $n, …)', numeric: false },
    { re: /(?<![\w$>:])range\s*\(/g, pick: SECOND, kind: 'alloc', what: 'range($a, $n)', numeric: false },
    { re: /(?<![\w$>:])str_pad\s*\(/g, pick: SECOND, kind: 'alloc', what: 'str_pad($s, $n)', numeric: false },
    { re: /\bnew\s+\\?SplFixedArray\s*\(/g, pick: FIRST, kind: 'alloc', what: 'SplFixedArray($n)', numeric: false },
    { re: /(?<![\w$>:])random_bytes\s*\(/g, pick: FIRST, kind: 'alloc', what: 'random_bytes($n)', numeric: false },
  ],
};

/** Loop bounds and repetition shapes found by a regex over the masked text: group 1 is the size expression. */
const SHAPES = {
  js: [{ re: /\bfor\s*\(\s*(?:let|var)?\s*([A-Za-z_$][\w$]*)\s*=[^;\n]{0,80};\s*\1\s*<=?\s*([^;\n]{1,80});/g, g: 2, kind: 'iter', what: 'a for loop bound', numeric: false }],
  java: [{ re: /\bfor\s*\(\s*(?:int|long|short|var)\s+([A-Za-z_]\w*)\s*=[^;\n]{0,80};\s*\1\s*<=?\s*([^;\n]{1,80});/g, g: 2, kind: 'iter', what: 'a for loop bound', numeric: false }],
  cs: [{ re: /\bfor\s*\(\s*(?:int|long|short|var)\s+([A-Za-z_]\w*)\s*=[^;\n]{0,80};\s*\1\s*<=?\s*([^;\n]{1,80});/g, g: 2, kind: 'iter', what: 'a for loop bound', numeric: false }],
  php: [{ re: /\bfor\s*\(\s*(\$[A-Za-z_]\w*)\s*=[^;\n]{0,80};\s*\1\s*<=?\s*([^;\n]{1,80});/g, g: 2, kind: 'iter', what: 'a for loop bound', numeric: false }],
  go: [
    { re: /\bfor\s+([A-Za-z_]\w*)\s*:=[^;{\n]{0,80};\s*\1\s*<=?\s*([^;{\n]{1,80});/g, g: 2, kind: 'iter', what: 'a for loop bound', numeric: false },
    { re: /\bfor\s+(?:[A-Za-z_]\w*\s*:=\s*)?range\s+([A-Za-z_][\w.]*)\s*\{/g, g: 1, kind: 'iter', what: 'range over an integer', numeric: true, needIntRange: true },
  ],
  kt: [{ re: /\bfor\s*\(\s*\w+\s+in\s+[^()\n]{0,40}?(?:\buntil\b|\.\.<?|\bdownTo\b)\s*([^()\n]{1,60})\)/g, g: 1, kind: 'iter', what: 'a for loop bound', numeric: false }],
  py: [
    { re: /(?:^|[=(,:\[]|\breturn)\s*(?:[bBrRuUfF]{0,2}(['"])[^'"\n]{0,40}\1|\[[^\[\]\n]{0,40}\])\s*\*\s*([A-Za-z_][\w.]*(?:\([^()\n]{0,60}\))?)/gm, g: 2, kind: 'alloc', what: 'sequence repetition', numeric: true },
    { re: /(?:^|[=(,:\[]|\breturn)\s*([A-Za-z_][\w.]*(?:\([^()\n]{0,60}\))?)\s*\*\s*(?:[bBrRuUfF]{0,2}(['"])|\[)/gm, g: 1, kind: 'alloc', what: 'sequence repetition', numeric: true },
  ],
  rb: [
    { re: /(?:^|[=(,\[]|\w:|\breturn)\s*(?:(['"])[^'"\n]{0,40}\1|\[[^\[\]\n]{0,40}\])\s*\*\s*([A-Za-z_][\w.]*(?:\([^()\n]{0,60}\))?)/gm, g: 2, kind: 'alloc', what: 'sequence repetition', numeric: true },
    { re: /(?<![\w.@$])([a-z_]\w*(?:\.to_i)?)\s*\.\s*times\b/g, g: 1, kind: 'iter', what: 'n.times', numeric: true },
    { re: /\(\s*\d+\s*\.\.\.?\s*([A-Za-z_][\w.]*)\s*\)\s*\.\s*(?:each|map|to_a|step|select|reject|sum|inject|reduce|each_with_object|each_slice|flat_map|collect)\b/g, g: 1, kind: 'iter', what: 'a range up to n', numeric: true },
  ],
};

function sinkSites(ctx) {
  const { lang, code, masked } = ctx;
  const out = [];
  for (const s of SINKS[lang] || []) {
    s.re.lastIndex = 0;
    let m;
    while ((m = s.re.exec(masked))) {
      const open = m.index + m[0].length - 1;
      let args;
      if (s.bracket) {
        const close = matchClose(masked, open, 400);
        if (close === -1) continue;
        args = [code.slice(open + 1, close)];
      } else {
        args = callArguments(code.slice(open + 1, open + 1 + 2000));
        if (!args || args.partial) continue;
      }
      // A function definition named like a sink (`function repeat(`) is not a call.
      if (/\b(?:function|def|func|fun)\s+$/.test(masked.slice(Math.max(0, m.index - 12), m.index))) continue;
      for (const a of s.bracket ? args : s.pick(args)) {
        if (!a || !a.trim()) continue;
        const rel = (s.bracket ? code.slice(open + 1) : code.slice(open + 1)).indexOf(a);
        out.push({ at: m.index, argText: a, argAt: rel >= 0 ? open + 1 + rel : open + 1, kind: s.kind, what: s.what, numeric: s.numeric });
      }
    }
  }
  for (const s of SHAPES[lang] || []) {
    s.re.lastIndex = 0;
    let m;
    while ((m = s.re.exec(masked))) {
      const expr = m[s.g];
      if (!expr || !expr.trim()) continue;
      const rel = m[0].lastIndexOf(expr);
      const argAt = m.index + rel;
      out.push({ at: m.index + (m[0].length - m[0].trimStart().length), argText: code.slice(argAt, argAt + expr.length), argAt, kind: s.kind, what: s.what, numeric: s.numeric, needIntRange: s.needIntRange });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Context.
// ---------------------------------------------------------------------------

function buildCtx(file, raw) {
  const lang = langOf(file);
  if (!lang) return null;
  const code = raw;
  const masked = maskStrings(code, lang);
  const starts = lineStarts(code);
  const scopes = (lang === 'py' || lang === 'rb') ? indentScopes(lang, masked, code) : braceScopes(lang, masked);
  const ctx = {
    file, lang, code, masked, starts, scopes,
    taintCache: new Map(),
    loopHeaders: loopHeaderRanges(lang, masked),
    requestFile: lang === 'rb' ? (RB_REQUEST_FILE_RE.test(code) || RB_CONTROLLER_PATH_RE.test(file)) : lang === 'py' ? PY_WEB_IMPORT_RE.test(code) : true,
    validationLib: VALIDATION_LIB_RE.test(code),
    phpFormRequest: lang === 'php' && /function\s+\w+\s*\([^)]*\b(?!Request\b)\w+Request\s+\$request\b/.test(code),
    goCtxNames: new Set(),
  };
  if (lang === 'go') {
    for (const m of code.matchAll(/\b([A-Za-z_]\w*)\s+(?:\*gin\.Context|echo\.Context|\*fiber\.Ctx)\b/g)) ctx.goCtxNames.add(m[1]);
  }
  return ctx;
}

/** Outermost function scope containing `pos`, with the parameters bound from the request by every enclosing header. */
function regionFor(ctx, pos) {
  const containing = ctx.scopes.filter((s) => pos >= s.start && pos < s.end).sort((a, b) => a.start - b.start);
  if (!containing.length) return { start: 0, end: ctx.code.length, params: [] };
  const outer = containing[0];
  const params = [];
  for (const s of containing) {
    if (!ctx.requestFile) break;
    const header = ctx.lang === 'py' || ctx.lang === 'rb' ? s.header : ctx.code.slice(s.headerStart, s.start - 1);
    params.push(...paramSources(ctx.lang, s, ctx.code, header));
  }
  return { start: outer.start, end: outer.end, params };
}

function mkFinding(ctx, line, rule, cwe, vuln, description, remediation, extra = {}) {
  const lines = ctx.code.split('\n');
  return {
    id: `request-resource:${rule}:${ctx.file}:${line}`,
    file: ctx.file, line,
    vuln, severity: 'medium', cwe,
    family: 'resource-exhaustion', parser: 'RESOURCE',
    stride: 'Denial of Service',
    confidence: 0.6,
    description, remediation,
    snippet: (lines[line - 1] || '').trim().slice(0, 200),
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// Rule 1: request-sized allocation or iteration.
// ---------------------------------------------------------------------------

function scanSized(ctx, skipLines) {
  const out = [];
  const seen = new Set();
  for (const site of sinkSites(ctx)) {
    const region = regionFor(ctx, site.at);
    const tainted = taintAt(ctx, region, site.at);
    const argMasked = ctx.masked.slice(site.argAt, site.argAt + site.argText.length);
    if (CLAMP_RE.test(argMasked)) continue;
    const refs = refsIn(ctx, site.argText, argMasked, site.argAt, tainted, region);
    if (!refs.any) continue;
    if (refs.bounded) continue;
    const typed = TYPED.has(ctx.lang);
    const numeric = refs.numeric || NUMERIC_CONV_RE.test(argMasked);
    if (site.numeric && !numeric) continue;
    if (site.needIntRange && !(refs.conv || NUMERIC_CONV_RE.test(argMasked))) continue;
    if (!typed && site.numeric === false && ctx.lang !== 'js' && ctx.lang !== 'php' && !numeric) continue;
    if (refs.body && ctx.validationLib) continue;
    if (schemaBounded(ctx, refs.keys)) continue;
    const names = [...refs.family];
    if (guardedBefore(ctx, region, site.at, names, refs.srcTexts)) continue;
    const line = lineAt(ctx.starts, site.at);
    const key = `${line}`;
    if (seen.has(key) || skipLines.has(line)) continue;
    seen.add(key);
    const shown = refs.keys.size ? [...refs.keys][0] : (names[0] || [...refs.srcTexts][0]);
    const alloc = site.kind === 'alloc';
    out.push(mkFinding(ctx, line, alloc ? 'alloc' : 'iteration', alloc ? 'CWE-770' : 'CWE-400',
      alloc
        ? `Allocation sized by a request value: ${site.what} with '${shown}' and no upper bound`
        : `Iteration bounded by a request value: ${site.what} with '${shown}' and no upper bound`,
      `The ${alloc ? 'size' : 'iteration count'} of ${site.what} comes from the request ('${shown}') and nothing before it compares the value with a maximum. ` +
      `One request with a large number makes the process ${alloc ? 'allocate memory' : 'spin'} in proportion to it, which takes the service down for everyone (CWE-${alloc ? '770' : '400'}).`,
      'Reject or clamp the value before using it: compare it with a documented maximum and return 400 when it is larger, or use min(value, MAX). Declaring the bound where the parameter is bound (@Max, [Range], Query(le=...), a schema max) also works.',
      { checkedFor: 'an upper-bound comparison, a clamp (min/clamp/coerceAtMost/modulo) or a validate/check call on the value, or a declared maximum, before the use' }));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Rule 2: quadratic work over a request collection (CWE-407).
// ---------------------------------------------------------------------------

function loopSites(ctx) {
  const { lang, masked } = ctx;
  const out = [];
  const add = (re, g, bodyOf) => {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(masked))) {
      const body = bodyOf(m);
      if (body) out.push({ at: m.index, coll: m[g].trim(), collAt: m.index + m[0].indexOf(m[g]), body });
    }
  };
  const braceBody = (m) => {
    const open = masked.indexOf('{', m.index + m[0].length - 1);
    if (open === -1 || open - (m.index + m[0].length) > 40) return null;
    const close = matchClose(masked, open);
    return close === -1 ? null : [open + 1, close];
  };
  const callBody = (m) => {
    const open = m.index + m[0].length - 1;
    const close = matchClose(masked, open);
    return close === -1 ? null : [open + 1, close];
  };
  const indentBody = (m) => {
    const ls = masked.lastIndexOf('\n', m.index) + 1;
    const ind = masked.slice(ls).match(/^[ \t]*/)[0].length;
    const lineEnd = masked.indexOf('\n', m.index);
    if (lineEnd === -1) return null;
    let k = lineEnd + 1;
    let end = masked.length;
    while (k < masked.length) {
      const e = masked.indexOf('\n', k);
      const t = masked.slice(k, e === -1 ? masked.length : e);
      if (t.trim()) {
        if (t.length - t.trimStart().length <= ind) { end = k; break; }
      }
      if (e === -1) break;
      k = e + 1;
    }
    return [lineEnd + 1, end];
  };
  // Anchored on an identifier start and capped at 6 segments: an unanchored
  // chain retried at every character of a long dotted expression made a
  // 170 KB generated parser take 24 s.
  const EXPR = '((?<![\\w$.])[A-Za-z_$][\\w$]{0,60}(?:\\s{0,4}\\.\\s{0,4}[A-Za-z_$][\\w$]{0,60}){0,6}(?:\\s{0,4}\\[[^\\[\\]\\n]{1,40}\\])?)';
  if (lang === 'js') {
    add(new RegExp(`\\bfor\\s*\\(\\s*(?:const|let|var)\\s+[^;()]{1,60}?\\s+of\\s+${EXPR}\\s*\\)`, 'g'), 1, braceBody);
    add(new RegExp(`${EXPR}\\s*\\.\\s*(?:forEach|map|filter|flatMap|reduce|some|every)\\s*\\(`, 'g'), 1, callBody);
  } else if (lang === 'py') {
    add(new RegExp(`^[ \\t]*for\\s+[^\\n:]{1,60}?\\s+in\\s+${EXPR}\\s*:`, 'gm'), 1, indentBody);
  } else if (lang === 'java' || lang === 'kt' || lang === 'cs') {
    add(new RegExp(`\\bfor(?:each)?\\s*\\(\\s*[^;()]{1,80}?\\s*(?::|\\bin\\b)\\s*${EXPR}\\s*\\)`, 'g'), 1, braceBody);
  } else if (lang === 'go') {
    add(new RegExp(`\\bfor\\s+[\\w, ]{0,40}:?=\\s*range\\s+${EXPR}\\s*\\{`, 'g'), 1, (m) => { const open = m.index + m[0].length - 1; const c = matchClose(masked, open); return c === -1 ? null : [open + 1, c]; });
  } else if (lang === 'php') {
    add(/\bforeach\s*\(\s*(\$[A-Za-z_]\w*(?:\s*\[[^\[\]\n]{1,40}\])?)\s+as\b/g, 1, (m) => { const open = matchClose(masked, m.index + m[0].indexOf('('), 400); return open === -1 ? null : braceBody({ index: open, 0: ')' }); });
  } else if (lang === 'rb') {
    add(new RegExp(`(?<![\\w@$.])${EXPR}\\s*\\.\\s*(?:each|map|each_with_index|select|reject|each_with_object|flat_map|collect)\\b[^\\n]*?(?:\\{|\\bdo\\b)`, 'g'), 1, indentBody);
  }
  return out;
}

function linearScanIn(ctx, body, coll, bodyAt) {
  const { lang } = ctx;
  const c = escRe(coll).replace(/\\\s\*/g, '\\s*');
  const lb = coll.startsWith('$') ? '(?<![\\w$])' : '(?<![\\w$.])';
  const pats = {
    js: [`${lb}${c}\\s*\\.\\s*(?:includes|indexOf|lastIndexOf|find|findIndex|findLast|findLastIndex|some|every|filter|forEach|map|reduce)\\s*\\(`, `\\bfor\\s*\\([^;()]{1,60}\\s+of\\s+${c}\\s*\\)`],
    py: [`\\bin\\s+${c}\\b`, `${lb}${c}\\s*\\.\\s*(?:index|count)\\s*\\(`],
    java: [`${lb}${c}\\s*\\.\\s*(?:contains|indexOf|lastIndexOf|remove|stream)\\s*\\(`, `\\bfor\\s*\\([^;()]{1,80}:\\s*${c}\\s*\\)`],
    kt: [`${lb}${c}\\s*\\.\\s*(?:contains|indexOf|lastIndexOf|find|filter|any|all|count|first|firstOrNull)\\s*[({]`, `\\bin\\s+${c}\\b`],
    cs: [`${lb}${c}\\s*\\.\\s*(?:Contains|IndexOf|Any|All|Where|First|FirstOrDefault|Count|Find)\\s*\\(`, `\\bforeach\\s*\\([^()]{1,80}\\bin\\s+${c}\\s*\\)`],
    go: [`\\brange\\s+${c}\\s*\\{`, `\\bslices\\s*\\.\\s*(?:Contains|Index|ContainsFunc|IndexFunc)\\s*\\(\\s*${c}\\b`],
    php: [`\\b(?:in_array|array_search|array_keys)\\s*\\([^;]{1,80},\\s*${c}\\b`, `\\bforeach\\s*\\(\\s*${c}\\s+as\\b`],
    rb: [`${lb}${c}\\s*\\.\\s*(?:include\\?|index|count|find|detect|select|any\\?|each|find_index)`],
  }[lang] || [];
  for (const p of pats) {
    const m = new RegExp(p).exec(body);
    if (m) return bodyAt + m.index;
  }
  return -1;
}

/** Lists declared as array literals and appended to inside the loop body: membership checks on them are linear. */
function builtListScan(ctx, region, loop) {
  const { lang, masked } = ctx;
  const body = masked.slice(loop.body[0], loop.body[1]);
  const pre = masked.slice(region.start, loop.at);
  const lists = new Set();
  const declRe = {
    js: /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]]+\s*)?=\s*\[\s*\]/g,
    py: /^[ \t]*([A-Za-z_]\w*)\s*(?::\s*[^=\n]+)?=\s*(?:\[\s*\]|list\(\s*\))/gm,
    php: /(\$[A-Za-z_]\w*)\s*=\s*(?:\[\s*\]|array\(\s*\))/g,
    rb: /^[ \t]*([a-z_]\w*)\s*=\s*(?:\[\s*\]|Array\.new\b)/gm,
    java: /\b([A-Za-z_]\w*)\s*=\s*new\s+(?:ArrayList|LinkedList)\s*</g,
    kt: /\b(?:val|var)\s+([A-Za-z_]\w*)\s*(?::\s*[\w<>]+\s*)?=\s*(?:mutableListOf|arrayListOf|ArrayList)\s*[<(]/g,
    cs: /\b([A-Za-z_]\w*)\s*=\s*new\s+List\s*</g,
    go: null,
  }[lang];
  if (!declRe) return -1;
  let m;
  while ((m = declRe.exec(pre))) lists.add(m[1]);
  for (const L of lists) {
    const e = escRe(L);
    const lb = L.startsWith('$') ? '(?<![\\w$])' : '(?<![\\w$.])';
    const appended = new RegExp({
      js: `${lb}${e}\\s*\\.\\s*(?:push|unshift)\\s*\\(`,
      py: `${lb}${e}\\s*\\.\\s*(?:append|insert|extend)\\s*\\(`,
      php: `${lb}${e}\\s*\\[\\s*\\]\\s*=|\\barray_push\\s*\\(\\s*${e}\\b`,
      rb: `${lb}${e}\\s*(?:<<|\\.\\s*(?:push|append)\\b)`,
      java: `${lb}${e}\\s*\\.\\s*add\\s*\\(`,
      kt: `${lb}${e}\\s*\\.\\s*add\\s*\\(|${lb}${e}\\s*\\+=`,
      cs: `${lb}${e}\\s*\\.\\s*Add\\s*\\(`,
    }[lang]);
    if (!appended.test(body)) continue;
    const hit = linearScanIn(ctx, body, L, loop.body[0]);
    if (hit !== -1 && !(lang === 'py' && /^\s*for\b/.test(masked.slice(masked.lastIndexOf('\n', hit) + 1, hit + 1)))) return hit;
  }
  return -1;
}

function sizeGuarded(ctx, region, upTo, coll) {
  const seg = ctx.masked.slice(region.start, upTo);
  const c = escRe(coll).replace(/\\\s\*/g, '\\s*');
  const sizeExpr = `(?:${c}\\s*\\.\\s*(?:length|size\\s*\\(\\s*\\)|size|Count|Length|count\\s*\\(\\s*\\))|(?:len|count|sizeof)\\s*\\(\\s*${c}\\s*\\))`;
  const re = new RegExp(`${sizeExpr}\\s*(<=|>=|<|>)(?![<>=])\\s*([^;\\n&|)?:]{1,60})|([\\w$.)]{1,60})\\s*(?:<=|>=|<|>)(?![<>=])\\s*${sizeExpr}`, 'g');
  let m;
  while ((m = re.exec(seg))) {
    if (inRanges(ctx.loopHeaders, region.start + m.index)) continue;
    if (m[2] && LOWER_LITERAL_RE.test(m[2])) continue;
    if (m[3] && LOWER_LITERAL_RE.test(m[3])) continue;
    return true;
  }
  return false;
}

function scanQuadratic(ctx) {
  const out = [];
  const seen = new Set();
  for (const loop of loopSites(ctx)) {
    const region = regionFor(ctx, loop.at);
    const tainted = taintAt(ctx, region, loop.at);
    const collMasked = ctx.masked.slice(loop.collAt, loop.collAt + loop.coll.length);
    const refs = refsIn(ctx, ctx.code.slice(loop.collAt, loop.collAt + loop.coll.length), collMasked, loop.collAt, tainted, region);
    if (!refs.any || !refs.collection) continue;
    const info = tainted.get(loop.coll);
    if (info && info.numeric && !info.collection && !info.object && !TYPED.has(ctx.lang)) continue;
    if (refs.body && ctx.validationLib) continue;
    const bodyText = ctx.masked.slice(loop.body[0], loop.body[1]);
    let hit = linearScanIn(ctx, bodyText, loop.coll, loop.body[0]);
    let how = 'scans the same collection again for every element';
    if (hit === -1) { hit = builtListScan(ctx, region, loop); how = 'checks membership in a list it is building from that collection'; }
    if (hit === -1) continue;
    if (sizeGuarded(ctx, region, loop.at, loop.coll)) continue;
    const names = [...refs.family, loop.coll];
    if (refs.keys.size && schemaBounded(ctx, refs.keys)) continue;
    // A truncation before the loop (`items = items.slice(0, MAX)`) untaints through CLAMP_RE in the replay.
    void names;
    const line = lineAt(ctx.starts, hit);
    if (seen.has(line)) continue;
    seen.add(line);
    const shown = refs.keys.size ? [...refs.keys][0] : loop.coll;
    out.push(mkFinding(ctx, line, 'quadratic', 'CWE-407',
      `Quadratic work over a request collection: a loop over '${shown}' ${how}`,
      `The loop at line ${lineAt(ctx.starts, loop.at)} walks '${loop.coll}', which comes from the request, and for each element this line ${how}. ` +
      'The work grows with the square of the number of elements the caller sends, so one request carrying a long list can hold a worker for minutes (inefficient algorithmic complexity, CWE-407).',
      'Cap the number of elements before the loop (reject requests whose list is longer than a documented maximum), and use a set or map for membership checks so each lookup is constant time.',
      { checkedFor: 'a comparison of the collection size with a maximum before the loop, or a schema maximum for the field' }));
  }
  // Java / Go / C# / Kotlin: a String grown with += inside a loop over a request collection.
  if (['java', 'go', 'cs', 'kt'].includes(ctx.lang)) {
    for (const loop of loopSites(ctx)) {
      const region = regionFor(ctx, loop.at);
      const tainted = taintAt(ctx, region, loop.at);
      const collMasked = ctx.masked.slice(loop.collAt, loop.collAt + loop.coll.length);
      const refs = refsIn(ctx, ctx.code.slice(loop.collAt, loop.collAt + loop.coll.length), collMasked, loop.collAt, tainted, region);
      if (!refs.any || !refs.collection) continue;
      if (sizeGuarded(ctx, region, loop.at, loop.coll)) continue;
      const pre = ctx.masked.slice(region.start, loop.at);
      const strs = new Set();
      const dre = { java: /\bString\s+([A-Za-z_]\w*)\s*=/g, cs: /\bstring\s+([A-Za-z_]\w*)\s*=/g, kt: /\bvar\s+([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*"/g, go: /\b([A-Za-z_]\w*)\s*:=\s*""|\bvar\s+([A-Za-z_]\w*)\s+string\b/g }[ctx.lang];
      let m;
      while ((m = dre.exec(pre))) strs.add(m[1] || m[2]);
      const body = ctx.masked.slice(loop.body[0], loop.body[1]);
      for (const s of strs) {
        const hm = new RegExp(`(?<![\\w$.])${escRe(s)}\\s*\\+=`).exec(body);
        if (!hm) continue;
        const line = lineAt(ctx.starts, loop.body[0] + hm.index);
        if (seen.has(line)) continue;
        seen.add(line);
        out.push(mkFinding(ctx, line, 'quadratic-concat', 'CWE-407',
          `Quadratic string building over a request collection: '${s}' grown with += in a loop over '${loop.coll}'`,
          `Each += copies the whole string built so far, and the loop runs once per element of '${loop.coll}', which comes from the request. The copying grows with the square of the input, so one large request burns CPU and memory out of proportion to its size (CWE-407).`,
          ctx.lang === 'go' ? 'Build the result with a strings.Builder (or collect parts and strings.Join them), and cap the number of elements accepted.' : 'Build the result with a StringBuilder (or collect parts and join them once), and cap the number of elements accepted.'));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

export function scanRequestSizedResource(file, raw) {
  if (!raw || typeof raw !== 'string' || raw.length > MAX_FILE) return [];
  if (TEST_PATH_RE.test(file)) return [];
  const lang = langOf(file);
  if (!lang) return [];
  // Cheap relevance gate: some request accessor must appear at all.
  if (!/\b(?:req|request|Request|ctx|event|params|searchParams|call|URL|FormValue|PostFormValue|mux|chi|RequestParam|PathVariable|QueryParam|PathParam|FromQuery|FromRoute|FromForm|FromHeader|RequestBody|get_argument|Query|Param|ShouldBind|Bind|Decode)\b|\$_(?:GET|POST|REQUEST|COOKIE)\b/.test(raw)) return [];
  const ctx = buildCtx(file, raw);
  if (!ctx) return [];
  // No request accessor and no request-bound parameter anywhere: nothing to track.
  if (!findSources(ctx, 0, raw.length).length && !PARAM_HINT_RE.test(raw)) return [];
  try {
    // The older window-scoped rule (resource-exhaustion.js) already reports some
    // JS/Python lines; never report one line twice.
    const skip = new Set();
    if (lang === 'js' || lang === 'py') for (const f of scanResourceExhaustion(file, raw)) skip.add(f.line);
    return [...scanSized(ctx, skip), ...scanQuadratic(ctx)];
  } catch {
    return [];
  }
}

export const _internals = { buildCtx, taintAt, regionFor, guardedBefore, sinkSites, loopSites, braceScopes, headerIsFunction, findSources, schemaBounded, NUMERIC_CONV_RE, CLAMP_RE };
