// Bounded structural mutation for ONE candidate rule's own corpus — not bench/mutation's engine-wide verdict-flip
// harness (a different scope: the whole deterministic+taint engine against curated adversarial cases). This module
// exists only to answer PRD 3's "unseen sibling" question for a single rule: does the candidate still fire on a
// structurally different variant of the same vulnerable shape, and does it still decline on a structurally
// different variant of a mitigated shape.
//
// Mutations are SYNTACTIC, deterministic, seed-free and language-agnostic: variable rename, wrap-in-function,
// reorder-adjacent-statements, insert-indirection (a pass-through local variable). No semantics are changed on
// purpose — a mutation that silently changed behavior would make a "same vulnerability, different shape" claim
// false.
const RESERVED = new Set(['if', 'else', 'for', 'while', 'return', 'function', 'const', 'let', 'var', 'import', 'from', 'def', 'class', 'req', 'res']);

function identifiers(code) {
  const seen = new Set();
  for (const m of code.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\b/g)) if (!RESERVED.has(m[1]) && !/^[A-Z_]+$/.test(m[1])) seen.add(m[1]);
  return [...seen];
}

function renameOne(code, from, to) {
  if (!from || code.includes(to)) return null;
  return code.replace(new RegExp(`\\b${from}\\b`, 'g'), to);
}

export function variableRename(code, { suffix = '_v2' } = {}) {
  const ids = identifiers(code);
  const target = ids.find((id) => id.length > 1);
  if (!target) return null;
  return renameOne(code, target, `${target}${suffix}`);
}

export function wrapInFunction(code, { name = 'wrapped_v2' } = {}) {
  if (!String(code).trim()) return null;
  const indented = code.split('\n').map((l) => (l ? `  ${l}` : l)).join('\n');
  return `function ${name}() {\n${indented}\n}\n${name}();\n`;
}

/** Insert a pass-through local for the first simple right-hand-side identifier assigned with `=` (indirection,
 * no behavior change): `x = y;` becomes `const indirectN = y; x = indirectN;`. */
function insertIndirection(code) {
  const m = /^(\s*)([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)\s*;/m.exec(code);
  if (!m) return null;
  const [whole, indent, lhs, rhs] = m;
  const varName = `indirect_${Math.abs(_hash(rhs)) % 1000}`;
  if (code.includes(varName)) return null;
  return code.replace(whole, `${indent}const ${varName} = ${rhs};\n${indent}${lhs} = ${varName};`);
}

function _hash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return h; }

// ---- the four mutators the PRD lists beyond rename / wrapper / indirection --------------------------------------------------
// Each is a deterministic, table-driven textual rewrite that returns null when it does not apply. Tables are deliberately
// small and conservative: an entry is here only when both sides are the same API family used the same way, so the claim "same
// vulnerability, different shape" stays true. They are applied to the vulnerable side (does the rule still fire?) and to the safe
// side (does it still decline?); the safe side is where a rule keyed to ONE sanitizer's name is caught.

// equivalent APIs: the same operation through a sibling entry point
const EQUIVALENT_APIS = Object.freeze([
  [/\bchild_process\.exec\(/, 'child_process.execSync('], [/\bexecSync\(/, 'exec('], [/\bos\.system\(/, 'os.popen('],
  [/\bdb\.query\(/, 'db.execute('], [/\bconnection\.query\(/, 'connection.execute('], [/\bcursor\.execute\(/, 'cursor.executemany('],
  [/\bfs\.readFile\(/, 'fs.readFileSync('], [/\bfs\.readFileSync\(/, 'fs.readFile('], [/\bfs\.writeFile\(/, 'fs.writeFileSync('],
  [/\bhttp\.get\(/, 'https.get('], [/\baxios\.get\(/, 'axios.request('], [/\bres\.send\(/, 'res.end('],
  [/\bos\.Open\(/, 'os.OpenFile('], [/\bsubprocess\.call\(/, 'subprocess.run('], [/\bsubprocess\.run\(/, 'subprocess.call('],
]);
export function equivalentApi(code) {
  for (const [from, to] of EQUIVALENT_APIS) if (from.test(code)) return code.replace(from, to);
  return null;
}

// alternate sanitizers: a different, equally valid way to neutralize the same input
const ALTERNATE_SANITIZERS = Object.freeze([
  [/\bescapeHtml\(/, 'validator.escape('], [/\bvalidator\.escape\(/, 'escapeHtml('], [/\bDOMPurify\.sanitize\(/, 'sanitizeHtml('], [/\bsanitizeHtml\(/, 'DOMPurify.sanitize('],
  [/\bshlex\.quote\(/, 'pipes.quote('], [/\bhtml\.escape\(/, 'markupsafe.escape('], [/\bhtml\.EscapeString\(/, 'template.HTMLEscapeString('],
  [/\bencodeURIComponent\(/, 'encodeURI('], [/\bpath\.basename\(/, 'path.parse('], [/\bparseInt\(/, 'Number('], [/\bNumber\(/, 'parseInt('],
  [/\bstrconv\.Atoi\(/, 'strconv.ParseInt('], [/\bint\(/, 'abs('],
]);
export function alternateSanitizer(code) {
  for (const [from, to] of ALTERNATE_SANITIZERS) if (from.test(code)) return code.replace(from, to);
  return null;
}

// framework variants: the same untrusted input reached through another framework's accessor
const FRAMEWORK_VARIANTS = Object.freeze([
  [/\breq\.body\./g, 'ctx.request.body.'], [/\breq\.query\./g, 'ctx.query.'], [/\breq\.params\./g, 'ctx.params.'],
  [/\brequest\.args\.get\(/g, 'request.form.get('], [/\brequest\.form\.get\(/g, 'request.args.get('], [/\$_GET\[/g, '$_REQUEST['], [/\$_POST\[/g, '$_REQUEST['],
  [/\br\.URL\.Query\(\)\.Get\(/g, 'r.FormValue('], [/\brequest\.getParameter\(/g, 'request.getHeader('],
]);
export function frameworkVariant(code) {
  for (const [from, to] of FRAMEWORK_VARIANTS) if (from.test(code)) { from.lastIndex = 0; return code.replace(from, to); }
  return null;
}

// reordering: swap the first pair of ADJACENT simple statements that share no identifier, so neither feeds the other. This is a
// syntactic independence test, not a data-flow proof; it is applied to rule-corpus snippets, where a swap of two unrelated
// statements is what a different author's version of the same code would plausibly look like.
const CONTROL = /^\s*(?:if|else|for|while|switch|case|return|try|catch|finally|do|break|continue|throw|function|def|class|import|from|package|\}|\{|@|\/\/|#)\b|^\s*[}{]\s*$/;
export function reorderStatements(code) {
  const lines = code.split('\n');
  const simple = (l) => l.trim() && !CONTROL.test(l) && /[;)]\s*$|^[^=]*=[^=].*[^{]$/.test(l.trim()) && !/[{]\s*$/.test(l);
  const ids = (l) => new Set([...l.matchAll(/\b[A-Za-z_][A-Za-z0-9_]*\b/g)].map((m) => m[0]).filter((x) => !RESERVED.has(x)));
  for (let i = 0; i + 1 < lines.length; i++) {
    if (!simple(lines[i]) || !simple(lines[i + 1])) continue;
    const a = ids(lines[i]); const b = ids(lines[i + 1]);
    if ([...a].some((x) => b.has(x))) continue;
    const out = [...lines]; [out[i], out[i + 1]] = [out[i + 1], out[i]];
    return out.join('\n');
  }
  return null;
}

const MUTATORS = Object.freeze({
  'variable-rename': variableRename, 'wrap-in-function': wrapInFunction, 'insert-indirection': insertIndirection,
  'equivalent-api': equivalentApi, 'reorder-statements': reorderStatements, 'alternate-sanitizer': alternateSanitizer, 'framework-variant': frameworkVariant,
});
export const MUTATOR_NAMES = Object.freeze(Object.keys(MUTATORS));

/** Every mutator applied to `code`; mutators that don't apply (return null) are omitted, never silently skipped without saying so. */
export function generateVariants(code) {
  const out = [];
  for (const [name, fn] of Object.entries(MUTATORS)) {
    let variant = null;
    try { variant = fn(code); } catch { variant = null; }
    if (variant && variant !== code) out.push({ mutator: name, code: variant });
  }
  return out;
}

/** Which of the seven mutators produced a variant for this code, and which did not (so a report can say what was not exercised). */
export function mutatorCoverage(code) {
  const applied = new Set(generateVariants(code).map((v) => v.mutator));
  return { applied: MUTATOR_NAMES.filter((n) => applied.has(n)), notApplicable: MUTATOR_NAMES.filter((n) => !applied.has(n)) };
}
