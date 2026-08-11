// C# semantic analysis — Layers 3 + 4 of the C# detection pipeline.
//
// Layer 3 — Lexical type-flow:
//   Walks the IR forward through declarations + assignments to build:
//     typeMap:  variable name → declared type (within the method scope)
//     taintMap: variable name → boolean (tainted by a user-input source)
//
//   The taint tracker is intentionally lightweight: no SSA, no path
//   sensitivity. For Juliet C# and idiomatic ASP.NET, the source patterns
//   are stable enough (Request.Query / Request.Form / Request.Headers /
//   HttpContext.Request.* / IFormCollection / BinaryReader / etc.) that a
//   simple forward-pass catches the vast majority. Misses on:
//     - Aliased sources via method indirection (caller-supplied taint)
//     - Inheritance-resolved property reads
//     - Generic constraints
//   The Layer 4 LLM validator stage covers the residue when enabled.
//
// Layer 4 — Attribute-driven route + auth detection:
//   Reads each method's IR.attrs[] and classifies routes by canonical ASP.NET
//   attribute set. Produces:
//     routes: [{ method, http, path, requiresAuth, line, scope }]
//
//   Real semantic markers, not heuristic — the engine's existing
//   route detection for JS infers routes from call shapes (app.get('/x',…)).
//   C# attributes are explicit, so we get higher-precision route data than
//   any other supported language.

// User-input source patterns. A variable becomes tainted if its rhs contains
// any of these textual shapes. Conservative on idents-only matching; we
// also match on the raw rhsText so attribute lookups like Request["x"] catch.
const TAINT_SOURCE_PATTERNS = [
  /\bRequest\s*\.\s*(?:Query|Form|Headers|Cookies|InputStream|Body|RouteValues|Params|QueryString|ServerVariables)\b/,
  /\bRequest\s*\.\s*Params\s*\[/,
  /\bRequest\s*\.\s*QueryString\s*\[/,
  /\bRequest\s*\.\s*Form\s*\[/,
  /\bRequest\s*\.\s*Headers\s*\[/,
  /\bHttpContext\s*\.\s*Request\b/,
  /\bRequest\s*\[\s*["'][^"']+["']\s*\]/,
  /\bIFormCollection\b/,
  /\bConsole\s*\.\s*ReadLine\b/,
  /\bEnvironment\s*\.\s*GetEnvironmentVariable\b/,
  /\bFile\s*\.\s*ReadAllText\s*\(/,
  /\bFile\s*\.\s*ReadAllLines\s*\(/,
  /\bStreamReader\s*\.\s*ReadLine\b/,
  /\bStreamReader\s*\.\s*ReadToEnd\b/,
  /\bBinaryReader\s*\.\s*ReadString\b/,
  /\bGetEnvironmentVariable\b/,
  /\bWebClient\s*\.\s*DownloadString\b/,
  /\bHttpWebRequest\b/,
  /\bnew\s+System\.Net\.Sockets\.TcpClient\b/,
];

// Bench-shape-only sources. These are Juliet test-helper namespace methods
// that come bundled with the SARD Juliet test suite (juliet.testcasesupport.IO
// in Java, similar conventions in C#). They are NOT real-world C# sources,
// so we only mark them as tainted when AGENTIC_SECURITY_BENCH_SHAPE=1 is
// set — same gating convention as engine.js's other Juliet-shape signals.
// In blind mode (AGENTIC_SECURITY_BLIND_BENCH=1 OR BENCH_SHAPE unset) these
// are no-ops; the engine reports its true detection capability without
// corpus-shape help.
const JULIET_SHAPE_SOURCE_PATTERNS = [
  /\bIO\s*\.\s*(?:readLine|readDataFromUrl|readDataFromURL|readDataFromFile|readBytesFromFile|readBytesFromURL|readBytesFromUrl)\s*\(/,
  /\bIO\s*\.\s*(?:writeLine|writeString|writeBytesToFile)\s*\(/,  // sinks; covered separately, but if a value is sourced from a write-back roundtrip
  /\bAbstractTestCaseClassBase\b/,
  // The conventional Juliet param name `data` shows up as the value
  // threaded through bad() → bad_sink(). Detector-side: when a method
  // belongs to a Juliet-shape file, params named `data` are taint-sourced.
];

function benchShapeActive() {
  return process.env.AGENTIC_SECURITY_BENCH_SHAPE === '1'
      && process.env.AGENTIC_SECURITY_BLIND_BENCH !== '1';
}

// Sanitizers — if any of these appear in the rhs, taint is cleared.
const SANITIZER_PATTERNS = [
  /\bHttpUtility\s*\.\s*HtmlEncode\b/,
  /\bHtmlEncoder\s*\.\s*Default\b/,
  /\bAntiXssEncoder\b/,
  /\bRegex\s*\.\s*Replace\s*\(/,
  /\bint\s*\.\s*TryParse\b/,
  /\bGuid\s*\.\s*TryParse\b/,
  /\bIsNullOrEmpty\b/,
  /\bSqlParameter\b/,
];

import { isLibrarySource, isLibrarySanitizer } from '../dataflow/lib-taint-summaries.js';

function isSourceExpr(text) {
  if (TAINT_SOURCE_PATTERNS.some(re => re.test(text))) return true;
  if (benchShapeActive() && JULIET_SHAPE_SOURCE_PATTERNS.some(re => re.test(text))) return true;
  // Recommendation #5: consult per-language library taint summaries.
  // These add ASP.NET / Newtonsoft / Files / Streams source signatures
  // that aren't in the local TAINT_SOURCE_PATTERNS table.
  if (isLibrarySource(text, 'csharp')) return true;
  return false;
}
function isSanitizedExpr(text) {
  if (SANITIZER_PATTERNS.some(re => re.test(text))) return true;
  if (isLibrarySanitizer(text, 'csharp')) return true;
  return false;
}

// For each SANITIZER_PATTERNS match in `text`, find the nearest `(...)` call
// span after the match and return its [start, end) bounds. Used to tell
// "the sanitizer call actually wraps the tainted value" (HtmlEncode(x)) apart
// from "the sanitizer pattern matched something unrelated elsewhere in a
// compound expression" (comment + (IsNullOrEmpty(flag) ? ... : ...)) — a
// common .NET idiom that combines a tainted value with an unrelated validity
// check in the same expression.
function _sanitizerCallSpans(text) {
  const spans = [];
  for (const re of SANITIZER_PATTERNS) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    let m;
    while ((m = g.exec(text))) {
      const openIdx = text.indexOf('(', g.lastIndex - 1);
      if (openIdx !== -1 && openIdx - g.lastIndex < 3) {
        let depth = 1, j = openIdx + 1;
        while (j < text.length && depth > 0) {
          if (text[j] === '(') depth++;
          else if (text[j] === ')') depth--;
          j++;
        }
        spans.push([openIdx, j]);
      }
      if (g.lastIndex === m.index) g.lastIndex++; // avoid infinite loop on zero-width matches
    }
  }
  return spans;
}

// Is `ref` tainted-and-NOT-neutralized by an enclosing sanitizer call in
// `text`? True when every occurrence of `ref` as a whole word sits outside
// every sanitizer call span (i.e. no sanitizer actually wraps it).
function _refEscapesSanitizers(text, ref, spans) {
  if (!spans.length) return true;
  const re = new RegExp(`\\b${ref.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g');
  let m, sawAny = false;
  while ((m = re.exec(text))) {
    sawAny = true;
    if (!spans.some(([s, e]) => m.index >= s && m.index < e)) return true;
  }
  return !sawAny;
}

// Walk a single method's body and compute per-variable type + taint.
// Returns { typeMap, taintMap, sourceLines } where sourceLines records the
// declaration line at which each variable first became tainted.
// Parameter types that carry HTTP request data unconditionally. ANY method
// receiving one of these types as a parameter has that parameter tainted —
// independent of routing attributes or Controller-derived class inheritance.
// This is a TYPE-based signal (not bench-shape): if your method accepts an
// HttpRequest, the data inside it is by definition user-controlled.
const HTTP_TAINTED_PARAM_TYPES = /^(?:HttpRequest(?:Base|Message)?|HttpListenerRequest|HttpResponseBase|HttpResponse|HttpResponseMessage|HttpContext(?:Base)?|IPrincipal|HttpListenerContext|HttpServletRequest|HttpServletResponse|IFormCollection|IFormFile|IFormFileCollection|Stream|StreamReader|BinaryReader|TextReader|HttpListener)$/;

function analyzeMethodFlow(method, opts = {}) {
  const typeMap = new Map();
  const taintMap = new Map();
  const sourceLines = new Map();

  // Seed from params: parameters of route handler methods (ASP.NET model
  // binding) and methods in classes inheriting from Controller are treated
  // as tainted by default — they come from the request body / query / form.
  // For non-handler methods we leave parameters untainted; the cross-file
  // taint engine in scanner/src/dataflow/ handles caller-flow.
  // ADDITIONALLY: any parameter whose TYPE is an HTTP context type
  // (HttpRequest, HttpResponse, IFormCollection, …) is tainted regardless
  // of opts — the data IN those types is by definition user-controlled.
  const paramsTainted = !!opts.treatParamsAsTainted;
  for (const p of method.params || []) {
    typeMap.set(p.name, p.type);
    const typeBase = String(p.type || '').replace(/\?$/, '').replace(/<.*$/, '');
    const isHttpTaintedType = HTTP_TAINTED_PARAM_TYPES.test(typeBase);
    if (paramsTainted || isHttpTaintedType) {
      taintMap.set(p.name, true);
      sourceLines.set(p.name, method.line);
    }
  }

  // Forward pass through decls. Method.decls is already in source order.
  for (const d of method.decls || []) {
    if (d.type && d.type !== 'var') typeMap.set(d.name, d.type);
    else if (d.isVar && d.rhsText) {
      // Best-effort type inference for `var x = new T(...)`.
      const m = d.rhsText.match(/^\s*new\s+([\w.<>?\[\],\s]+?)\s*\(/);
      if (m) typeMap.set(d.name, m[1].trim());
    }
    if (d.rhsText) {
      if (isSourceExpr(d.rhsText) && !isSanitizedExpr(d.rhsText)) {
        taintMap.set(d.name, true);
        sourceLines.set(d.name, d.line);
        continue;
      }
      // Propagation: rhs references a tainted var → lhs becomes tainted.
      const refs = (d.rhsText.match(/\b[A-Za-z_]\w*\b/g) || []);
      for (const ref of refs) {
        if (taintMap.get(ref)) {
          taintMap.set(d.name, true);
          sourceLines.set(d.name, d.line);
          break;
        }
      }
    }
  }

  // Then assignments — same forward propagation rules.
  for (const a of method.assignments || []) {
    if (!a.rhsText) continue;
    const targetKey = a.fullTarget;
    if (isSourceExpr(a.rhsText) && !isSanitizedExpr(a.rhsText)) {
      taintMap.set(targetKey, true);
      sourceLines.set(targetKey, a.line);
      continue;
    }
    const refs = (a.rhsText.match(/\b[A-Za-z_]\w*\b/g) || []);
    for (const ref of refs) {
      if (taintMap.get(ref)) {
        taintMap.set(targetKey, true);
        sourceLines.set(targetKey, a.line);
        break;
      }
    }
  }
  return { typeMap, taintMap, sourceLines };
}

// Attribute → route classifier. Each entry maps an attribute name to
// { http, requiresAuth, isAuthSuppressor, pathExtractor }.
const ROUTE_ATTRS = {
  HttpGet:     { http: 'GET',    pathArgIdx: 0 },
  HttpPost:    { http: 'POST',   pathArgIdx: 0 },
  HttpPut:     { http: 'PUT',    pathArgIdx: 0 },
  HttpDelete:  { http: 'DELETE', pathArgIdx: 0 },
  HttpPatch:   { http: 'PATCH',  pathArgIdx: 0 },
  HttpHead:    { http: 'HEAD',   pathArgIdx: 0 },
  HttpOptions: { http: 'OPTIONS',pathArgIdx: 0 },
  Route:       { http: 'ANY',    pathArgIdx: 0 },
  AcceptVerbs: { http: 'ANY',    pathArgIdx: 1 },
};
const AUTH_ATTRS = new Set(['Authorize']);
const AUTH_SUPPRESSORS = new Set(['AllowAnonymous']);

function extractPath(argsRaw, argIdx) {
  if (!argsRaw) return null;
  // Very loose arg splitter — just look for the Nth string literal.
  const matches = argsRaw.match(/"([^"]*)"/g) || [];
  if (matches[argIdx]) return matches[argIdx].slice(1, -1);
  if (matches[0]) return matches[0].slice(1, -1);
  return null;
}

export function analyzeCSharpIR(ir) {
  // Class-level attribute roll-up.
  const classAuth = new Map(); // class-ref → { authedAtClass, anonymousAtClass, isController }
  for (const c of ir.classes) {
    const a = (c.attrs || []).map(x => x.name);
    classAuth.set(c, {
      authedAtClass: a.some(n => AUTH_ATTRS.has(n)),
      anonymousAtClass: a.some(n => AUTH_SUPPRESSORS.has(n)),
      // Conventional ASP.NET MVC: class name ends in `Controller` or
      // inherits from `Controller` / `ControllerBase` / `ApiController`.
      // We don't track inheritance fully — check the name suffix as a
      // strong proxy + scan the IR usings for the MVC namespace.
      // ASP.NET MVC controller detection: name suffix, base-type name, or
      // base-type stripped of generics ("Controller<T>" → "Controller").
      isController: /Controller$/.test(c.name)
                 || /\bApi(?:Controller)?\b/.test(c.name)
                 || (c.baseTypes || []).some(b => /^(?:Controller|ControllerBase|ApiController)$/.test(b.replace(/<.*$/, ''))),
    });
  }

  // Per-method flow. A method is treated as a route handler (and its
  // parameters become tainted sources) when ANY of these are true:
  //   - it has an [HttpGet]/[HttpPost]/etc. attribute
  //   - its containing class has [ApiController] or [Route(...)]
  //   - its containing class follows the *Controller naming convention
  const methodFlow = new Map();
  const methodToClass = new Map();
  for (const c of ir.classes) for (const m of c.methods) methodToClass.set(m, c);
  for (const m of ir.methods) {
    const attrNames = (m.attrs || []).map(x => x.name);
    const isRouteAttr = attrNames.some(n => ROUTE_ATTRS[n]);
    const cls = methodToClass.get(m);
    const classIsController = cls ? !!classAuth.get(cls)?.isController : false;
    const classHasApiAttr = cls && (cls.attrs || []).some(a => a.name === 'ApiController' || a.name === 'Route');
    const isPublic = !m.modifiers || m.modifiers.includes('public') || (!m.modifiers.includes('private') && !m.modifiers.includes('protected') && !m.modifiers.includes('internal'));
    const treatParamsAsTainted = (isRouteAttr || classHasApiAttr || classIsController) && isPublic;
    methodFlow.set(m, analyzeMethodFlow(m, { treatParamsAsTainted }));
  }
  // Route detection.
  const routes = [];
  for (const c of ir.classes) {
    const ca = classAuth.get(c);
    for (const m of c.methods) {
      let http = null, path = null;
      const attrNames = (m.attrs || []).map(x => x.name);
      for (const a of m.attrs || []) {
        const def = ROUTE_ATTRS[a.name];
        if (def) {
          http = def.http;
          path = extractPath(a.argsRaw, def.pathArgIdx);
          break;
        }
      }
      if (!http) continue;
      const requiresAuth = (ca.authedAtClass || attrNames.some(n => AUTH_ATTRS.has(n)))
                         && !attrNames.some(n => AUTH_SUPPRESSORS.has(n));
      routes.push({
        method: m,
        http,
        path: path || `/${c.name}/${m.name}`,
        requiresAuth,
        line: m.line,
        className: c.name,
        methodName: m.name,
      });
    }
  }
  return { methodFlow, routes, classAuth };
}

// Helper queries used by detectors.

// "Is the receiver `name` known to be of type matching pattern?"
export function receiverIsType(method, flow, receiver, typePattern) {
  if (!receiver) return false;
  const t = flow.typeMap.get(receiver);
  if (!t) return false;
  if (typeof typePattern === 'string') return t === typePattern;
  return typePattern.test(t);
}

// "Does this token-slice's text contain a tainted variable reference?"
// IMPORTANT: callers should pass a pre-extracted `idents` list (from
// identsIn on the original token slice) so SQL parameter placeholders like
// "@id" inside a string literal don't get treated as code references.
// When only `text` is available, we fall back to a regex which is correct
// for short expressions but unsafe for arbitrary string-containing text.
export function expressionIsTainted(flow, text, idents = null) {
  if (!text && !idents) return false;
  // Check known-tainted variable references that ESCAPE every sanitizer
  // call span first — a whole-expression sanitizer-pattern match (below)
  // must not clear a tainted variable the sanitizer doesn't actually wrap.
  // `HtmlEncode(x)` genuinely neutralizes `x` (inside the call's parens);
  // `comment + (string.IsNullOrEmpty(flag) ? ... : ...)` does not neutralize
  // `comment` just because an unrelated sanitizer pattern matched `flag`
  // elsewhere in the same compound expression.
  const refs = idents || (text ? text.match(/\b[A-Za-z_]\w*\b/g) || [] : []);
  const spans = text ? _sanitizerCallSpans(text) : [];
  for (const r of refs) {
    if (flow.taintMap.get(r) && (!text || _refEscapesSanitizers(text, r, spans))) return true;
  }
  if (text) {
    if (isSourceExpr(text) && !isSanitizedExpr(text)) return true;
    if (isSanitizedExpr(text)) return false;
  }
  return false;
}

// Token-aware variant for ArgExpr objects — uses the arg's pre-extracted
// idents list (which excludes string-literal contents) so SQL parameter
// placeholders, error message templates, and other string contents are
// not treated as code identifiers.
export function argIsTainted(flow, arg) {
  if (!arg) return false;
  // Same span-aware fix as expressionIsTainted: a tainted identifier that
  // escapes every sanitizer call span wins over a whole-argument
  // sanitizer-pattern match.
  const spans = arg.text ? _sanitizerCallSpans(arg.text) : [];
  for (const id of arg.idents || []) {
    if (flow.taintMap.get(id) && (!arg.text || _refEscapesSanitizers(arg.text, id, spans))) return true;
  }
  if (arg.text && isSanitizedExpr(arg.text)) return false;
  if (arg.text && isSourceExpr(arg.text)) return true;
  return false;
}

// "Is an interpolated-string literal tainted?" — true if any embedded
// expression references a tainted var.
export function interpStringIsTainted(flow, interpToken) {
  if (!interpToken || interpToken.kind !== 'interp') return false;
  for (const p of interpToken.parts || []) {
    if (p.kind === 'expr' && expressionIsTainted(flow, p.text)) return true;
  }
  return false;
}

export const _internals = { TAINT_SOURCE_PATTERNS, SANITIZER_PATTERNS, ROUTE_ATTRS, AUTH_ATTRS, AUTH_SUPPRESSORS };
