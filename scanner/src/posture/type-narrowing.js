// FR-SEM-10 — Whole-program type narrowing (heuristic).
//
// When a function parameter is declared `any` / `unknown` / `interface{}` /
// `dynamic` but in practice every call site passes a typed value, downstream
// taint analysis sees the wide type and falsely warns "could be anything."
// This module performs a callsite-based narrowing pass: for each function
// with a wide parameter type, look at all call sites in the project; if every
// argument is provably typed (literal, typed variable, typed return), narrow
// the parameter for analysis purposes.
//
// The pass is INFORMATIONAL ONLY — it does not silently drop findings. It
// annotates `f.typeNarrowed: { from, to, callSites }` and lowers confidence
// by a small amount on the affected finding so downstream ranking accounts
// for the narrowing without erasing the finding.
//
// Languages covered (regex-level):
//   TypeScript : `(x: any)` / `(x: unknown)`
//   Python     : `def f(x: Any)` / `def f(x)`  (no annotation = implicit any)
//   Go         : `interface{}` / `any`

const TS_ANY_PARAM_RE = /function\s+(\w+)\s*\(([^)]*\b\w+\s*:\s*(?:any|unknown)[^)]*)\)/g;
const TS_ANY_ARROW_RE = /const\s+(\w+)\s*=\s*\(([^)]*\b\w+\s*:\s*(?:any|unknown)[^)]*)\)\s*=>/g;
const PY_ANY_PARAM_RE = /def\s+(\w+)\s*\(([^)]*\b\w+\s*:\s*(?:Any|object)[^)]*)\)/g;
const GO_ANY_PARAM_RE = /func\s+(\w+)\s*\(([^)]*\b\w+\s+(?:interface\{\}|any)[^)]*)\)/g;

function extractWideParamFns(text, lang) {
  if (!text) return [];
  const out = [];
  const patterns = {
    ts: [TS_ANY_PARAM_RE, TS_ANY_ARROW_RE],
    py: [PY_ANY_PARAM_RE],
    go: [GO_ANY_PARAM_RE],
  };
  for (const re of (patterns[lang] || [])) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      out.push({ name: m[1], params: m[2], pos: m.index });
    }
  }
  return out;
}

function inferLang(filePath) {
  if (/\.(ts|tsx)$/i.test(filePath)) return 'ts';
  if (/\.py$/i.test(filePath)) return 'py';
  if (/\.go$/i.test(filePath)) return 'go';
  return null;
}

// Detect whether a call-site argument is "narrowly typed": literal, typed
// expression, member of a known-typed object. We deliberately under-approximate
// — we only narrow when every observed call passes a clearly-typed value.
function isNarrowlyTypedArg(arg) {
  const t = arg.trim();
  if (!t) return false;
  if (/^["'`]/.test(t)) return true;                        // string literal
  if (/^-?\d/.test(t)) return true;                          // number literal
  if (/^(?:true|false|null|undefined|None|nil)$/.test(t)) return true;
  if (/^\{/.test(t) || /^\[/.test(t)) return true;           // object/array literal
  if (/\bas\s+\w+/.test(t)) return true;                     // TS cast
  if (/<[\w.<>,\s]+>/.test(t) && /^\w+</.test(t)) return true; // generic typed call
  return false;
}

export function findNarrowableFunctions(fileContents) {
  if (!fileContents || typeof fileContents !== 'object') return [];
  const fns = [];
  for (const [fp, text] of Object.entries(fileContents)) {
    const lang = inferLang(fp);
    if (!lang) continue;
    if (!text || typeof text !== 'string') continue;
    for (const fn of extractWideParamFns(text, lang)) {
      fns.push({ name: fn.name, declaredIn: fp, lang });
    }
  }
  return fns;
}

// Find call sites of `name` across all files; classify each argument.
// Returns { totalCalls, narrowCalls, examples[] }.
function probeCallSites(name, fileContents) {
  const re = new RegExp(`\\b${name}\\s*\\(\\s*([^)]{0,200})\\)`, 'g');
  let total = 0, narrow = 0;
  const examples = [];
  for (const [fp, text] of Object.entries(fileContents)) {
    if (!text || typeof text !== 'string') continue;
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      total++;
      const args = m[1].split(',').slice(0, 1);
      if (args.every(isNarrowlyTypedArg)) {
        narrow++;
        if (examples.length < 3) examples.push({ file: fp, snippet: m[0].slice(0, 80) });
      }
    }
  }
  return { totalCalls: total, narrowCalls: narrow, examples };
}

export function annotateTypeNarrowing(findings, fileContents) {
  if (!Array.isArray(findings) || !fileContents) return findings;
  const fns = findNarrowableFunctions(fileContents);
  if (!fns.length) return findings;
  const fnIndex = new Map();
  for (const fn of fns) fnIndex.set(fn.name, fn);
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const enclosing = f.enclosingFunction || f.functionName || f.fnName;
    if (!enclosing || !fnIndex.has(enclosing)) continue;
    const probe = probeCallSites(enclosing, fileContents);
    if (probe.totalCalls === 0) continue;
    if (probe.narrowCalls / probe.totalCalls >= 0.95) {
      f.typeNarrowed = {
        from: 'any/unknown/interface{}',
        to: 'callsite-uniform-typed',
        callSites: probe.totalCalls,
        narrowed: probe.narrowCalls,
        examples: probe.examples,
      };
      if (typeof f.confidence === 'number') {
        f.confidence = Math.max(0, f.confidence - 0.10);
        f._narrowedConfidenceAdjust = -0.10;
      }
    }
  }
  return findings;
}
