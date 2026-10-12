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

const MUTATORS = Object.freeze({ 'variable-rename': variableRename, 'wrap-in-function': wrapInFunction, 'insert-indirection': insertIndirection });

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
