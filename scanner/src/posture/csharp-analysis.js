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
//     - Aliased sources via method indirection (caller-supplied taint) —
//       SARD_80_F1 W4.C41 closed the SAME-FILE, SINGLE-HOP case (a value
//       tainted in a caller passed as an argument to a private/same-class
//       helper — Juliet's own "data passed as an argument from one method
//       to another in the same class" flow-variant idiom): see
//       `analyzeCSharpIR`'s post-pass below. Still deliberately NOT
//       modeled: a second hop (the helper passes it on to a THIRD method)
//       and any cross-FILE call, both out of scope for this lightweight
//       analyzer (the real, general interprocedural case is what the deep
//       taint engine in `dataflow/` exists for).
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

// SARD_80_F1 W3.x — `TAINT_SOURCE_PATTERNS`'s `StreamReader.ReadLine` /
// `BinaryReader.ReadString` entries require the LITERAL type name as the
// receiver, which real code never writes (`StreamReader.ReadLine()` isn't
// even a static method) — idiomatic C# always calls through an INSTANCE
// variable (`using (StreamReader sr = …) { sr.ReadLine() }`), so those
// patterns were effectively dead against this dominant shape. Exposed (not
// created) by the `resolveCalleeReturnTaint` precision fix above: the old
// identifier-name fallback used to accidentally re-taint the result via an
// unrelated already-tainted variable merely appearing in the call text
// (the exact over-tainting bug this fix removes), which happened to produce
// the right verdict here for the wrong reason. Mirrors
// `HTTP_TAINTED_PARAM_TYPES`'s type-based approach: a call through a
// variable whose DECLARED type is a reader class is a source regardless of
// the variable's name.
const READER_SOURCE_TYPES = /^(?:StreamReader|BinaryReader|TextReader)$/;
const READER_SOURCE_CALL_RE = /\b([A-Za-z_]\w*)\s*\.\s*(?:ReadLine|ReadToEnd|ReadString|ReadAllText|ReadAllLines)\s*\(/g;
// SARD_80_F1 W4.C34 — a second reader-shaped type/method pair, same class of
// gap as the StreamReader one above: `SqlDataReader dr = command.ExecuteReader();
// data = dr.GetString(1);` (Juliet's own idiomatic ADO.NET shape, confirmed
// via the public C# mirror, `CWE23_Relative_Path_Traversal__Database_01.cs`)
// is a real database-row read every bit as untrusted as a file/stream read,
// but `dataflow/catalog.js`'s OWN separate `cs-datareader-*` source entries
// (a completely different detector, the deep taint engine, not this file's
// lexical type-flow) require the LITERAL variable-name substring "reader" —
// investigated and found genuinely inert there too (W4.C32/W4.C33: giving
// THAT engine receiver-type confirmation is real but doesn't help here,
// since `classOfVar`'s CHA only resolves `new Foo()` allocations, never a
// factory-method return like `ExecuteReader()` — a separate, deeper
// limitation, not this file's concern). THIS detector already has exactly
// the right mechanism (declared-type lookup via `typeMap`, independent of
// variable name) — it just never had a DataReader entry.
const DATAREADER_SOURCE_TYPES = /^(?:Sql|OleDb|Odbc|MySql|Npgsql|Sqlite)DataReader$/;
const DATAREADER_SOURCE_CALL_RE = /\b([A-Za-z_]\w*)\s*\.\s*(?:GetString|GetValue|GetInt16|GetInt32|GetInt64|GetDateTime|GetDecimal|GetDouble|GetFloat|GetBoolean|GetGuid|GetChar|GetByte)\s*\(/g;
function _typedReaderSourceCall(text, typeMap) {
  if (!text) return false;
  READER_SOURCE_CALL_RE.lastIndex = 0;
  let m;
  while ((m = READER_SOURCE_CALL_RE.exec(text))) {
    if (READER_SOURCE_TYPES.test(typeMap.get(m[1]) || '')) return true;
  }
  DATAREADER_SOURCE_CALL_RE.lastIndex = 0;
  while ((m = DATAREADER_SOURCE_CALL_RE.exec(text))) {
    if (DATAREADER_SOURCE_TYPES.test(typeMap.get(m[1]) || '')) return true;
  }
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

// SARD_80_F1 W3.x — is `text` (the ENTIRE trimmed expression, not merely a
// substring) exactly one call `Name(args…)`, with nothing before the name
// (besides an optional `this.`) and nothing after the matching close-paren?
// Used to decide when a call-shaped RHS/return can be resolved against its
// OWN callee's return-taint verdict instead of the identifier-name fallback
// below (which cannot distinguish "the callee's return derives from this
// argument" from "this argument's tainted NAME merely appears in the call
// text", the latter being exactly W4.J17's documented `argIsTainted`
// over-tainting bug: `data = GoodG2BSource(req, resp);` taints `data`
// purely because `req`/`resp` are unconditionally-tainted HTTP-typed
// params, even though `GoodG2BSource` never reads them).
function _asBareCall(text) {
  if (!text) return null;
  const t = text.trim();
  const m = t.match(/^(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*\(/);
  if (!m) return null;
  const openIdx = t.indexOf('(', m[0].length - 1);
  let depth = 0;
  for (let i = openIdx; i < t.length; i++) {
    if (t[i] === '(') depth++;
    else if (t[i] === ')') {
      depth--;
      if (depth === 0) return i === t.length - 1 ? m[1] : null;
    }
  }
  return null;
}

// The pre-existing "any tainted identifier's name appears in the text"
// fallback, factored out so both the propagation loop and the return-taint
// computation below share one definition.
function _identRefTainted(text, taintMap) {
  const refs = (text.match(/\b[A-Za-z_]\w*\b/g) || []);
  for (const ref of refs) if (taintMap.get(ref)) return true;
  return false;
}

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
  // `opts.taintedParamNames` (SARD_80_F1 W4.C41, optional Set<string>) is
  // the SAME-FILE, single-hop caller-argument-taint case referenced above:
  // `analyzeCSharpIR`'s post-pass computes, from an ALREADY-computed
  // caller flow, which of THIS method's own parameter names were passed a
  // tainted argument at some real call site, and re-invokes this function
  // with that set so the normal forward pass below propagates it through
  // this method's body exactly as it would a route-handler-tainted param.
  const paramsTainted = !!opts.treatParamsAsTainted;
  const taintedParamNames = opts.taintedParamNames || null;
  for (const p of method.params || []) {
    typeMap.set(p.name, p.type);
    const typeBase = String(p.type || '').replace(/\?$/, '').replace(/<.*$/, '');
    const isHttpTaintedType = HTTP_TAINTED_PARAM_TYPES.test(typeBase);
    const isCallerArgTainted = !!(taintedParamNames && taintedParamNames.has(p.name));
    if (paramsTainted || isHttpTaintedType || isCallerArgTainted) {
      taintMap.set(p.name, true);
      sourceLines.set(p.name, method.line);
    }
  }

  // Single forward pass, in TRUE source-line order, over decls AND
  // assignments merged together.
  //
  // Previously this ran as two SEPARATE forward passes — all of
  // method.decls, then all of method.assignments — each individually in
  // source order, but with no ordering between the two lists. Juliet's own
  // universal C# convention (confirmed via the public Juliet C# mirror this
  // project's SARD manifest pins) declares a source variable bare, then
  // assigns it on the next line: `string data; data = Environment.
  // GetEnvironmentVariable("ADD");` — a plain decl (no rhsText, doesn't
  // taint) followed by a SEPARATE ASSIGNMENT (which does). Any LATER
  // declare-with-initializer that reads that variable (`string[] tokens =
  // data.Split(...);`) is a decl, processed in the FIRST loop — before the
  // assignment that actually taints `data` had run in the SECOND loop — so
  // the propagation check saw `data` as not-yet-tainted and the dependent
  // variable silently stayed clean, regardless of true source order.
  // Reproduced down to a minimal 100%-failing case (SARD_80_F1 W4.C8) and
  // confirmed real (not Juliet-specific): any C# code that separately
  // assigns a source, then derives a value from it in a later declared
  // variable, hits this. Fixing it can only ADD correctly-propagated taint
  // (this model has no un-taint step — a value that starts tainted stays
  // tainted — so re-ordering never removes a propagation that used to fire).
  const decls = (method.decls || []).map(d => ({ kind: 'decl', line: d.line, item: d }));
  const assigns = (method.assignments || []).map(a => ({ kind: 'assign', line: a.line, item: a }));
  const merged = decls.concat(assigns).sort((x, y) => x.line - y.line);
  for (const { kind, item } of merged) {
    const targetKey = kind === 'decl' ? item.name : item.fullTarget;
    const rhsText = item.rhsText;
    if (kind === 'decl') {
      if (item.type && item.type !== 'var') typeMap.set(item.name, item.type);
      else if (item.isVar && rhsText) {
        // Best-effort type inference for `var x = new T(...)`.
        const m = rhsText.match(/^\s*new\s+([\w.<>?\[\],\s]+?)\s*\(/);
        if (m) typeMap.set(item.name, m[1].trim());
      }
    }
    if (!rhsText) continue;
    if ((isSourceExpr(rhsText) || _typedReaderSourceCall(rhsText, typeMap)) && !isSanitizedExpr(rhsText)) {
      taintMap.set(targetKey, true);
      sourceLines.set(targetKey, item.line);
      continue;
    }
    // Propagation via a resolvable same-file call: consult the callee's OWN
    // return-taint verdict (SARD_80_F1 W3.x) instead of the identifier-name
    // fallback, which cannot tell "the callee's return actually derives
    // from this argument" apart from "this argument's tainted NAME merely
    // appears in the call text" — see `_asBareCall`'s header comment.
    const bareCallName = _asBareCall(rhsText);
    let resolved = null;
    if (bareCallName && opts.resolveCalleeReturnTaint) {
      resolved = opts.resolveCalleeReturnTaint(bareCallName);
    }
    if (resolved !== null) {
      if (resolved) { taintMap.set(targetKey, true); sourceLines.set(targetKey, item.line); }
      continue;
    }
    // Fallback: rhs references a tainted var → lhs becomes tainted. Reached
    // for non-call RHS shapes, and for calls the resolver couldn't resolve
    // (external/library callee, overload ambiguity, or a dependency cycle)
    // — recall-preserving: an unresolved call keeps the old, more liberal
    // behavior rather than silently going quiet.
    if (_identRefTainted(rhsText, taintMap)) {
      taintMap.set(targetKey, true);
      sourceLines.set(targetKey, item.line);
    }
  }
  // Per-return taint verdict, so a CALLER can resolve a call to THIS method
  // via the same mechanism (see `resolveCalleeReturnTaint` in
  // `analyzeCSharpIR`). Same three-way resolution as the propagation loop
  // above: an explicit source wins, then a resolvable nested call, then the
  // identifier-name fallback.
  const returns = (method.returns || []).map((r) => {
    let tainted;
    if ((isSourceExpr(r.exprText) || _typedReaderSourceCall(r.exprText, typeMap)) && !isSanitizedExpr(r.exprText)) {
      tainted = true;
    } else {
      const bareCallName = _asBareCall(r.exprText);
      const resolved = bareCallName && opts.resolveCalleeReturnTaint ? opts.resolveCalleeReturnTaint(bareCallName) : null;
      tainted = resolved !== null ? resolved : _identRefTainted(r.exprText, taintMap);
    }
    return { line: r.line, tainted };
  });
  return { typeMap, taintMap, sourceLines, returns };
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
  // SARD_80_F1 W3.x — resolve a same-file call's return-taint verdict
  // instead of letting `analyzeMethodFlow`'s identifier-name fallback treat
  // ANY tainted identifier appearing in the call text (including an
  // argument the callee never reads) as tainting the result. Bare-name
  // keyed (this codebase's call sites don't carry receiver/overload info to
  // disambiguate further); a name with 0 or 2+ candidates is unresolvable
  // (`null`, meaning "fall back to the old heuristic") rather than guessed.
  const methodsByName = new Map();
  for (const m of ir.methods) {
    if (!methodsByName.has(m.name)) methodsByName.set(m.name, []);
    methodsByName.get(m.name).push(m);
  }
  const treatParamsAsTaintedByMethod = new Map();
  for (const m of ir.methods) {
    const attrNames = (m.attrs || []).map(x => x.name);
    const isRouteAttr = attrNames.some(n => ROUTE_ATTRS[n]);
    const cls = methodToClass.get(m);
    const classIsController = cls ? !!classAuth.get(cls)?.isController : false;
    const classHasApiAttr = cls && (cls.attrs || []).some(a => a.name === 'ApiController' || a.name === 'Route');
    const isPublic = !m.modifiers || m.modifiers.includes('public') || (!m.modifiers.includes('private') && !m.modifiers.includes('protected') && !m.modifiers.includes('internal'));
    treatParamsAsTaintedByMethod.set(m, (isRouteAttr || classHasApiAttr || classIsController) && isPublic);
  }
  const calleeFlowCache = new Map();
  const calleeReturnTaintMemo = new Map();
  const resolvingStack = new Set();
  function computeFlow(m) {
    let flow = calleeFlowCache.get(m);
    if (!flow) {
      flow = analyzeMethodFlow(m, { treatParamsAsTainted: treatParamsAsTaintedByMethod.get(m), resolveCalleeReturnTaint });
      calleeFlowCache.set(m, flow);
    }
    return flow;
  }
  function resolveCalleeReturnTaint(name) {
    if (calleeReturnTaintMemo.has(name)) return calleeReturnTaintMemo.get(name);
    const candidates = methodsByName.get(name);
    if (!candidates || candidates.length !== 1) { calleeReturnTaintMemo.set(name, null); return null; }
    const callee = candidates[0];
    // Cycle guard (self- or mutually-recursive calls): unresolvable for
    // THIS resolution, deliberately not memoized so a later, non-cyclic
    // call to the same name can still resolve normally.
    if (resolvingStack.has(callee)) return null;
    resolvingStack.add(callee);
    const flow = computeFlow(callee);
    resolvingStack.delete(callee);
    const tainted = flow.returns && flow.returns.length ? flow.returns.some(r => r.tainted) : null;
    calleeReturnTaintMemo.set(name, tainted);
    return tainted;
  }
  for (const m of ir.methods) methodFlow.set(m, computeFlow(m));

  // SARD_80_F1 W4.C41 — same-file, single-hop caller-argument taint.
  // Every detector in csharp.js reads `analysis.methodFlow.get(m)` and
  // that flow's own `taintMap` only ever seeds from THIS method's own
  // params (route-handler convention / HTTP-typed param) — never from
  // what a CALLER actually passed it. Juliet's own "Flow Variant NN: data
  // passed as an argument from one method to another in the same class"
  // idiom (a route handler reads a source, then calls a private static
  // sink-wrapper helper with it) was therefore invisible to every
  // per-method detector here, confirmed via a standalone `runScan`
  // reproduction of the exact real-corpus shape (CWE36's own
  // `Params_Get_Web_41.cs`): the DIRECT single-method form of the same
  // sink already fired correctly; the moment the tainted value crossed a
  // same-file method-call boundary, it vanished with zero findings from
  // any detector, structural or deep-engine.
  //
  // Deliberately conservative, matching this analyzer's own "single
  // forward pass" simplicity rather than a full fixed point: (1) SINGLE
  // HOP only — a callee that itself forwards the value to a THIRD method
  // is not covered (mirrors `resolveCalleeReturnTaint`'s own scope, which
  // is the established precedent for interprocedural resolution in this
  // file); (2) SAME-FILE, unambiguous-name resolution only, via the same
  // `methodsByName` index `resolveCalleeReturnTaint` already uses — a
  // callee name with zero or 2+ same-named candidates project-wide is
  // left unresolved (permissive: the finding is simply not gained, never
  // a false suppression); (3) self-recursive calls are skipped (a
  // parameter's own taint state within its own body is already handled
  // by the normal forward pass, and re-seeding it from itself adds
  // nothing); (4) this recomputes the DIRECT callee's flow only — it does
  // NOT retroactively fix up `resolveCalleeReturnTaint`'s memo for any
  // caller further up a chain that already resolved this callee's
  // pre-this-pass return-taint verdict, an accepted, narrow gap given the
  // single-hop scope above.
  const taintedParamNamesByMethod = new Map();
  for (const caller of ir.methods) {
    const callerFlow = methodFlow.get(caller);
    if (!callerFlow) continue;
    for (const call of caller.calls || []) {
      if (call.receiver) continue; // same-file helper calls are bare (no receiver)
      const candidates = methodsByName.get(call.method);
      if (!candidates || candidates.length !== 1) continue;
      const callee = candidates[0];
      if (callee === caller) continue;
      for (let i = 0; i < (call.args || []).length; i++) {
        const param = (callee.params || [])[i];
        if (!param) continue;
        if (!argIsTainted(callerFlow, call.args[i])) continue;
        if (!taintedParamNamesByMethod.has(callee)) taintedParamNamesByMethod.set(callee, new Set());
        taintedParamNamesByMethod.get(callee).add(param.name);
      }
    }
  }
  for (const [callee, taintedParamNames] of taintedParamNamesByMethod) {
    methodFlow.set(callee, analyzeMethodFlow(callee, {
      treatParamsAsTainted: treatParamsAsTaintedByMethod.get(callee),
      resolveCalleeReturnTaint,
      taintedParamNames,
    }));
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
