export const id = 356;
export const ids = [356];
export const modules = {

/***/ 11106:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  oL: () => (/* binding */ computePatchScope),
  wN: () => (/* binding */ heuristicSymbols),
  fA: () => (/* binding */ jsSymbols),
  ni: () => (/* binding */ legacyBounds),
  nY: () => (/* binding */ pySymbols)
});

// UNUSED EXPORTS: DEFAULT_BOUNDS

// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
// EXTERNAL MODULE: ./node_modules/@babel/parser/lib/index.js
var lib = __webpack_require__(46411);
;// CONCATENATED MODULE: ./src/fix/line-diff.js
// Line diff for patch scope (verified-remediation PRD FR-03, GAP-03).
//
// The patch bound used to be |lines(after) - lines(before)|, so rewriting 150 lines into 150 different lines measured zero. This is a
// real line diff: Myers' O(ND) shortest edit script over whole lines, returning hunks with exact before/after line ranges.
//
// Bounded: the edit distance search stops at MAX_EDIT_DISTANCE. Past that the diff is reported `approximate: true` and every line of both
// sides that is not in the common prefix or suffix counts as changed. That fallback can only OVER-count, never under-count, so a policy
// that reads it can be too strict but never too lenient.
//
// Pure: no fs, no clock.

const MAX_EDIT_DISTANCE = 4000;

const splitLines = (text) => {
  if (text === null || text === undefined) return [];
  const s = String(text);
  if (s === '') return [];
  const lines = s.split('\n');
  if (lines[lines.length - 1] === '') lines.pop(); // a trailing newline does not add a line
  return lines;
};

// Myers forward search, returning the edit script as a list of ops over the trimmed middle.
function myers(a, b, maxD) {
  const n = a.length; const m = b.length; const max = n + m;
  const off = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace = [];
  for (let d = 0; d <= Math.min(max, maxD); d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x;
      if (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) x = v[off + k + 1];
      else x = v[off + k - 1] + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) { x++; y++; }
      v[off + k] = x;
      if (x >= n && y >= m) return backtrack(trace, a, b, off, d);
    }
  }
  return null;
}

function backtrack(trace, a, b, off, dEnd) {
  const ops = [];
  let x = a.length; let y = b.length;
  for (let d = dEnd; d > 0; d--) {
    const v = trace[d];
    const k = x - y;
    const prevK = (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) ? k + 1 : k - 1;
    const prevX = v[off + prevK]; const prevY = prevX - prevK;
    while (x > prevX && y > prevY) { ops.push(['=', x - 1, y - 1]); x--; y--; }
    if (x === prevX) ops.push(['+', x, y - 1]); else ops.push(['-', x - 1, y]);
    x = prevX; y = prevY;
  }
  while (x > 0 && y > 0) { ops.push(['=', x - 1, y - 1]); x--; y--; }
  return ops.reverse();
}

/**
 * @param {string|null} beforeText
 * @param {string|null} afterText
 * @returns {{additions:number, deletions:number, hunks:{beforeStart:number,beforeCount:number,afterStart:number,afterCount:number,added:string[],deleted:string[]}[], approximate:boolean}}
 *   Line numbers are 1-based. A hunk with beforeCount 0 is a pure insertion after line beforeStart-1.
 */
function diffLines(beforeText, afterText, { maxEditDistance = MAX_EDIT_DISTANCE } = {}) {
  const a = splitLines(beforeText); const b = splitLines(afterText);
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const am = a.slice(pre, a.length - suf); const bm = b.slice(pre, b.length - suf);
  if (!am.length && !bm.length) return { additions: 0, deletions: 0, hunks: [], approximate: false };
  let ops = am.length && bm.length ? myers(am, bm, maxEditDistance) : null;
  let approximate = false;
  if (!ops) {
    if (am.length && bm.length) approximate = true; // search bound hit: count the whole middle as replaced
    ops = [...am.map((_, i) => ['-', i, 0]), ...bm.map((_, j) => ['+', 0, j])];
  }
  const hunks = [];
  let cur = null; let ai = 0; let bi = 0;
  const flush = () => { if (cur) { hunks.push(cur); cur = null; } };
  for (const [op] of ops) {
    if (op === '=') { flush(); ai++; bi++; continue; }
    if (!cur) cur = { beforeStart: pre + ai + 1, beforeCount: 0, afterStart: pre + bi + 1, afterCount: 0, added: [], deleted: [] };
    if (op === '-') { cur.deleted.push(am[ai]); cur.beforeCount++; ai++; } else { cur.added.push(bm[bi]); cur.afterCount++; bi++; }
  }
  flush();
  const additions = hunks.reduce((s, h) => s + h.afterCount, 0);
  const deletions = hunks.reduce((s, h) => s + h.beforeCount, 0);
  return { additions, deletions, hunks, approximate };
}

// EXTERNAL MODULE: ./src/posture/material-change.js
var material_change = __webpack_require__(74629);
;// CONCATENATED MODULE: ./src/fix/patch-scope.js
// Actual patch scope (verified-remediation PRD FR-03, GAP-03): the ONE implementation every route uses to say how big a patch is.
//
// Before this module, fix-plan.js and the MCP synthesize_fix handler each measured |lines(after) - lines(before)|, so a 150-line rewrite
// into 150 different lines measured 0 and slipped under every size bound. computePatchScope measures what changed:
//
//   - additions and deletions from a real line diff (line-diff.js), changed ranges on both sides, and the file operation (add, modify,
//     delete, rename);
//   - `editedLines`, the size the bounds use: per hunk, max(added, deleted). A pure insertion or deletion counts its lines; a rewrite of
//     N lines into N different lines counts N, never 0;
//   - formatting-only versus semantic change (whitespace-normalized lines compared), reported separately and never made invisible: a
//     formatting-only file still counts toward `editedLines`;
//   - touched symbols: functions, methods, classes and route handlers whose span covers a changed line, from the Babel AST for JS/TS
//     (`structural: 'ast'`), an indentation heuristic for Python and a declaration heuristic elsewhere (`structural: 'heuristic'`, a named
//     fallback a policy can require review for);
//   - material categories, from posture/material-change.js's classifier (fed this diff, not a line set) plus the equal-length cases the
//     classifier does not see: a changed authorization condition, credentials, trust-boundary settings and TLS verification.
//
// Model-supplied counts are never an input. Pure: no fs, no clock.





const DEFAULT_BOUNDS = Object.freeze({ maxFiles: 3, maxEditedLines: 100 });

const JS_EXT = /\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i;
const PY_EXT = /\.py$/i;
const sha256 = (t) => (t === null || t === undefined ? null : `sha256:${(0,external_node_crypto_.createHash)('sha256').update(String(t)).digest('hex')}`);
const norm = (l) => l.replace(/\s+/g, '');

// The equal-length changes the hunk classifier misses. Tested on BOTH sides of a hunk: a condition that was edited shows up as one
// deleted and one added line of the same length, and either side carrying the vocabulary is enough.
const SCOPE_MATERIAL = [
  { category: 'authZ', kind: 'authz-condition-changed', re: /(?:\bif\b|\?|&&|\|\||\breturn\b|[!=]==?|\bwhere\b|\bfilter\b)[^\n]*\b(?:owner\w*|tenant\w*|role\w*|isAdmin|is_admin|admin|permission\w*|authori[sz]\w*|req\.user|request\.user|current_?user|userId|user_id|org(?:anization)?Id|scope\w*|acl)\b|\b(?:owner\w*|tenant\w*|role\w*|req\.user|userId|user_id)\b[^\n]*(?:[!=]==?|&&|\|\|)/i },
  { category: 'auth', kind: 'authn-changed', re: /\b(?:authenticate|isAuthenticated|requireAuth|verifyToken|passport|session\s*\.|jwt\s*\.\s*verify|login|logout|password\w*\s*(?:===?|!==?))\b/i },
  { category: 'crypto', kind: 'crypto-changed', re: /\b(?:createHash|createHmac|createCipheriv|createDecipheriv|randomBytes|pbkdf2|scrypt|bcrypt|argon2|hashlib\s*\.|MessageDigest|rejectUnauthorized|verify\s*=|checkServerIdentity|ca\s*:)\b/i },
  { category: 'credentials', kind: 'credential-changed', re: /\b(?:secret|api[_-]?key|access[_-]?key|private[_-]?key|token|credential\w*|passwd|password)\b\s*[:=]/i },
  { category: 'trust-boundary', kind: 'trust-boundary-changed', re: /\b(?:cors|origin|csrf|csurf|helmet|sameSite|httpOnly|allowlist|whitelist|denylist|blocklist|redirect)\b/i },
];

const range = (start, count) => (count > 0 ? [start, start + count - 1] : null);

/** Symbols (name, kind, 1-based inclusive span) from a JS/TS source, or null when it does not parse. */
function jsSymbols(text, file = 'x.js') {
  let ast;
  try {
    ast = (0,lib/* parse */.qg)(String(text), { sourceType: 'unambiguous', errorRecovery: true, allowReturnOutsideFunction: true, plugins: [/\.tsx?$|\.[mc]?ts$/i.test(file) ? 'typescript' : 'flow', 'jsx', 'classProperties', 'decorators-legacy'] });
  } catch { return null; }
  const out = [];
  const nameOf = (n) => {
    if (!n) return null;
    if (n.type === 'Identifier') return n.name;
    if (n.type === 'StringLiteral') return n.value;
    if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') { const o = nameOf(n.object); const p = n.computed ? (n.property.type === 'StringLiteral' ? n.property.value : '[computed]') : nameOf(n.property); return o && p ? `${o}.${p}` : p || o; }
    if (n.type === 'ThisExpression') return 'this';
    return null;
  };
  const isFn = (n) => n && /^(?:FunctionExpression|ArrowFunctionExpression|ClassExpression)$/.test(n.type);
  const add = (name, kind, node) => { if (name && node?.loc) out.push({ name, kind, start: node.loc.start.line, end: node.loc.end.line }); };
  const walk = (node, parent) => {
    if (!node || typeof node.type !== 'string') return;
    switch (node.type) {
      case 'FunctionDeclaration': add(nameOf(node.id), 'function', node); break;
      case 'ClassDeclaration': add(nameOf(node.id), 'class', node); break;
      case 'ClassMethod': case 'ClassPrivateMethod': case 'ObjectMethod': add(nameOf(node.key), 'method', node); break;
      case 'VariableDeclarator': if (isFn(node.init)) add(nameOf(node.id), node.init.type === 'ClassExpression' ? 'class' : 'function', node); break;
      case 'AssignmentExpression': if (isFn(node.right)) add(nameOf(node.left), 'function', node); break;
      case 'ObjectProperty': case 'ClassProperty': if (isFn(node.value)) add(nameOf(node.key), 'method', node); break;
      case 'CallExpression': {
        // app.get('/path', handler): the handler is named after its route
        const callee = node.callee;
        const verb = callee?.type === 'MemberExpression' && !callee.computed ? callee.property?.name : null;
        const first = node.arguments?.[0];
        if (verb && /^(?:get|post|put|patch|delete|del|all|use|options|head)$/i.test(verb) && first?.type === 'StringLiteral' && node.arguments.slice(1).some(isFn)) add(`${verb.toUpperCase()} ${first.value}`, 'route-handler', node);
        break;
      }
      default: break;
    }
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments' || key === 'extra') continue;
      const child = node[key];
      if (Array.isArray(child)) { for (const c of child) if (c && typeof c.type === 'string') walk(c, node); } else if (child && typeof child.type === 'string') walk(child, node);
    }
  };
  walk(ast.program, null);
  return out;
}

/** Python def/class blocks by indentation. A heuristic: decorators and continuation lines are approximate. */
function pySymbols(text) {
  const lines = splitLines(text); const out = []; const stack = [];
  const indent = (l) => l.match(/^[ \t]*/)[0].replace(/\t/g, '    ').length;
  lines.forEach((l, i) => {
    if (!l.trim() || /^\s*#/.test(l)) return;
    const ind = indent(l);
    while (stack.length && ind <= stack[stack.length - 1].indent) { const s = stack.pop(); s.sym.end = i; }
    const m = l.match(/^\s*(?:async\s+)?(def|class)\s+([A-Za-z_]\w*)/);
    if (m) { const sym = { name: stack.length ? `${stack.map((s) => s.sym.name).join('.')}.${m[2]}` : m[2], kind: m[1] === 'def' ? 'function' : 'class', start: i + 1, end: lines.length }; out.push(sym); stack.push({ indent: ind, sym }); }
  });
  for (const s of stack) s.sym.end = lines.length;
  return out;
}

// Two linear patterns, no overlapping repetition (an earlier single pattern backtracked catastrophically on long whitespace runs):
// a keyword declaration (function/def/class/...), and a C-family method header `mods type name(`.
const KEYWORD_DECL_RE = /\b(?:function|func|fn|def|sub|class|struct|impl|interface|module|trait|enum)[ \t]+([A-Za-z_][\w:.]*)/;
const MODIFIER_RE = /^(?:public|private|protected|internal|static|final|abstract|synchronized|override|virtual|async)[ \t]+/;
const METHOD_DECL_RE = /^([\w<>\[\],.?]+)[ \t]+([A-Za-z_]\w*)[ \t]*\(/;
const NOT_A_TYPE = new Set(['return', 'new', 'else', 'throw', 'await', 'yield', 'case', 'goto', 'delete', 'typeof', 'in', 'of']);
const declOf = (l) => {
  if (l.length > 400) return null;
  const k = l.match(KEYWORD_DECL_RE); if (k) return k[1];
  // modifiers are stripped one at a time (no nested quantifier), then `type name(` is matched once
  let rest = l.replace(/^[ \t]+/, '');
  for (let i = 0; i < 12; i++) { const mm = rest.match(MODIFIER_RE); if (!mm) break; rest = rest.slice(mm[0].length); }
  const m = rest.match(METHOD_DECL_RE); if (m && !NOT_A_TYPE.has(m[1]) && !/;\s*$/.test(l)) return m[2];
  return null;
};

/** Nearest preceding declaration line for each changed line. Used where no structural parser exists, and labelled as such. */
function heuristicSymbols(text) {
  const lines = splitLines(text); const decls = [];
  lines.forEach((l, i) => { const name = declOf(l); if (name) decls.push({ name, kind: 'declaration', start: i + 1 }); });
  decls.forEach((d, i) => { d.end = i + 1 < decls.length ? decls[i + 1].start - 1 : lines.length; });
  return decls;
}

function symbolsFor(file, text) {
  if (text === null || text === undefined) return { symbols: [], structural: 'none' };
  if (JS_EXT.test(file)) { const s = jsSymbols(text, file); if (s) return { symbols: s, structural: 'ast' }; return { symbols: heuristicSymbols(text), structural: 'heuristic', fallbackReason: 'the file did not parse as JavaScript/TypeScript' }; }
  if (PY_EXT.test(file)) return { symbols: pySymbols(text), structural: 'heuristic', fallbackReason: 'Python symbols come from an indentation heuristic, not a parser' };
  return { symbols: heuristicSymbols(text), structural: 'heuristic', fallbackReason: 'no structural parser for this file type' };
}

const touching = (symbols, lines) => {
  const hit = [];
  for (const s of symbols) if (lines.some((ln) => ln >= s.start && ln <= s.end)) hit.push(s);
  // keep the innermost symbol per changed line plus every enclosing one: the caller wants every scope whose behaviour moved
  return hit;
};

/**
 * @param {{before:Record<string,string|null>, after:Record<string,string|null>, renames?:{from:string,to:string}[], bounds?:{maxFiles?:number,maxEditedLines?:number}}} o
 *   `before[f] === null` (or absent) with `after[f]` set is an added file; `after[f] === null` is a deleted file.
 */
function computePatchScope({ before = {}, after = {}, renames = [], bounds = {} }) {
  const b = { ...DEFAULT_BOUNDS, ...bounds };
  const renameTo = new Map(renames.map((r) => [r.to, r.from]));
  const renamedFrom = new Set(renames.map((r) => r.from));
  const files = [];
  const materialInput = {};
  const scopeMaterial = [];
  let approximate = false;
  const names = [...new Set([...Object.keys(after), ...renames.map((r) => r.to)])].filter((f) => !renamedFrom.has(f) || f in after).sort();
  for (const file of names) {
    const src = renameTo.get(file) || file;
    const pre = before[src] ?? null;
    const post = after[file] ?? null;
    const operation = renameTo.has(file) ? 'rename' : pre === null && post !== null ? 'add' : pre !== null && post === null ? 'delete' : pre === post ? 'unchanged' : 'modify';
    const d = diffLines(pre, post);
    approximate = approximate || d.approximate;
    const editedLines = d.hunks.reduce((s, h) => s + Math.max(h.beforeCount, h.afterCount), 0);
    // formatting-only: the whitespace-normalized, blank-free line sequences agree
    const nb = splitLines(pre).map(norm).filter(Boolean); const na = splitLines(post).map(norm).filter(Boolean);
    const sd = diffLines(nb.join('\n'), na.join('\n'));
    const formattingOnly = operation === 'modify' && sd.additions === 0 && sd.deletions === 0 && editedLines > 0;
    const beforeLines = d.hunks.flatMap((h) => Array.from({ length: h.beforeCount }, (_, i) => h.beforeStart + i));
    const afterLines = d.hunks.flatMap((h) => Array.from({ length: h.afterCount }, (_, i) => h.afterStart + i));
    const sb = symbolsFor(file, pre); const sa = symbolsFor(file, post);
    // a pure insertion touches the symbol it was inserted into, found on the after side
    const touched = new Map();
    for (const s of touching(sb.symbols, beforeLines)) touched.set(`${s.kind}:${s.name}`, { name: s.name, kind: s.kind, side: 'before' });
    for (const s of touching(sa.symbols, afterLines)) { const k = `${s.kind}:${s.name}`; touched.set(k, { name: s.name, kind: s.kind, side: touched.has(k) ? 'both' : 'after' }); }
    const structural = [sb, sa].some((x) => x.structural === 'heuristic') ? 'heuristic' : [sb, sa].some((x) => x.structural === 'ast') ? 'ast' : 'none';
    files.push({
      file, ...(renameTo.has(file) ? { renamedFrom: src } : {}), operation,
      additions: d.additions, deletions: d.deletions, editedLines,
      changedRanges: d.hunks.map((h) => ({ before: range(h.beforeStart, h.beforeCount), after: range(h.afterStart, h.afterCount) })),
      formattingOnly, semanticEditedLines: formattingOnly ? 0 : sd.hunks.reduce((s, h) => s + Math.max(h.beforeCount, h.afterCount), 0),
      touchedSymbols: [...touched.values()].sort((x, y) => (x.name < y.name ? -1 : x.name > y.name ? 1 : 0)),
      structural, ...(structural === 'heuristic' ? { structuralFallback: sb.fallbackReason || sa.fallbackReason } : {}),
      beforeDigest: sha256(pre), afterDigest: sha256(post),
    });
    if (!formattingOnly && operation !== 'unchanged') {
      materialInput[file] = { before: pre ?? '', after: post ?? '' };
      for (const h of d.hunks) for (const [side, lines] of [['-', h.deleted], ['+', h.added]]) for (const line of lines) for (const p of SCOPE_MATERIAL) if (p.re.test(line)) scopeMaterial.push({ file, kind: p.kind, category: p.category, side, line: line.trim().slice(0, 200) });
    }
  }
  const cls = (0,material_change/* classifyFixMaterialRisk */.kz)(materialInput);
  const categories = [...new Set([...cls.highImpactCategories, ...scopeMaterial.map((m) => m.category)])].sort();
  const live = files.filter((f) => f.operation !== 'unchanged');
  const totals = {
    files: live.length, additions: live.reduce((s, f) => s + f.additions, 0), deletions: live.reduce((s, f) => s + f.deletions, 0),
    editedLines: live.reduce((s, f) => s + f.editedLines, 0), semanticEditedLines: live.reduce((s, f) => s + f.semanticEditedLines, 0),
    touchedSymbols: live.reduce((s, f) => s + f.touchedSymbols.length, 0),
    operations: Object.fromEntries(['add', 'modify', 'delete', 'rename'].map((op) => [op, live.filter((f) => f.operation === op).length])),
  };
  const exceeds = [];
  if (totals.files > b.maxFiles) exceeds.push(`touches ${totals.files} files (limit ${b.maxFiles})`);
  if (totals.editedLines > b.maxEditedLines) exceeds.push(`edits ${totals.editedLines} lines (limit ${b.maxEditedLines})`);
  return {
    schema: 'agentic-security/patch-scope', version: 1,
    files, totals, approximate,
    material: { categories, material: categories.length > 0, risk: cls.materialRisk, signals: [...cls.findings.filter((f) => f.kind !== 'routine').map((f) => ({ file: f.file, kind: f.kind, category: null, side: f.side, line: String(f.line || '').slice(0, 200) })), ...scopeMaterial] },
    structuralFallback: files.filter((f) => f.structural === 'heuristic').map((f) => f.file),
    bounds: b, exceedsBounds: exceeds.length > 0, exceedsReasons: exceeds,
  };
}

/** The legacy bound triple ({files, loc, exceedsBounds}) from the one scope computation, for callers that read the old field names. */
function legacyBounds(scope) {
  return { files: scope.totals.files, loc: scope.totals.editedLines, exceedsBounds: scope.exceedsBounds };
}


/***/ }),

/***/ 4370:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   El: () => (/* binding */ makeCandidate),
/* harmony export */   We: () => (/* binding */ checkCandidate),
/* harmony export */   uI: () => (/* binding */ queueProposer),
/* harmony export */   uf: () => (/* binding */ sqlParameterizeRecipe)
/* harmony export */ });
/* unused harmony exports RECIPE_SQL_PARAMETERIZE, matchesAny, parameterizeTemplateSql */
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(76760);
/* harmony import */ var _posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(41877);
/* harmony import */ var _fix_patch_scope_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(11106);
/* harmony import */ var _fix_test_results_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(69051);
/* harmony import */ var _schemas_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(68962);
// Candidate patches (verified-remediation PRD FR-07, section 6.3): proposers, identity and the scope gate.
//
// Proposers return file contents only. The trusted coordinator computes everything authoritative: the candidate id and patch digest,
// the actual diff (patch-scope.js), the edit-scope and protected-path checks and the test-surface check. A proposer's counts, claims or
// self-reported results are never read.
//
//   sqlParameterizeRecipe  deterministic recipe: `<db>.prepare(`...'${v}'...`).all|get|run|iterate()` becomes a prepared statement with
//                          `?` placeholders and the values passed as arguments. Preconditions, all required, or the recipe does not
//                          apply: every interpolation sits exactly inside a single-quoted SQL literal ('${v}'), the statement is called
//                          immediately with no arguments, and the file is one of the contract's allowed files. An interpolation in any
//                          other position (an identifier, a number, an ORDER BY) is refused: placeholders cannot carry it.
//   queueProposer          user-supplied candidates, consumed in order across rounds (a scripted refinement, or a person's patches).
//
// A model proposer is not part of this milestone; its absence is reported, never filled with a stand-in.






const RECIPE_SQL_PARAMETERIZE = Object.freeze({ id: 'sql-parameterize-template', version: '1' });

// ---------------------------------------------------------------- glob for protected paths

function globRe(pattern) {
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*' && pattern[i + 1] === '*') { re += pattern[i + 2] === '/' ? '(?:.*/)?' : '.*'; i += pattern[i + 2] === '/' ? 2 : 1; }
    else if (c === '*') re += '[^/]*';
    else re += c.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}
const matchesAny = (rel, patterns) => patterns.some((p) => globRe(p).test(rel));

// ---------------------------------------------------------------- the scope gate

// Primitives below the layer the application oracles observe: a raw binding, a child process, another thread, a datagram socket or a
// native addon could open a connection or touch a file the oracle never sees, so a candidate that verified with one would have
// verified nothing about it. A candidate may not INTRODUCE one (an original that already uses one is the operator's to declare).
const UNOBSERVED_PRIMITIVES = [
  [/\bprocess\.binding\s*\(|\binternalBinding\b|\bprocess\._linkedBinding\b/, 'a raw runtime binding'],
  [/['"](?:node:)?child_process['"]/, 'a child process'],
  [/['"](?:node:)?(?:worker_threads|cluster)['"]/, 'another thread or process'],
  [/['"](?:node:)?dgram['"]/, 'a datagram socket'],
  [/\bprocess\.dlopen\b|\.node['"]\s*\)/, 'a native addon'],
  [/^\s*(?:import\s+(?:subprocess|socket|ctypes|multiprocessing)\b|from\s+(?:subprocess|socket|ctypes|multiprocessing)\s+import\b)/m, 'a process, socket or foreign-function module'],
];
const count = (re, t) => (String(t || '').match(new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`)) || []).length;

/**
 * May this candidate be judged at all? Checked before anything executes.
 * @returns {{ok:boolean, reasons:string[], scope:object, changed:Record<string,string|null>}}
 */
function checkCandidate(contract, originalFiles, proposedFiles) {
  const reasons = [];
  const changed = {};
  for (const [rel, text] of Object.entries(proposedFiles || {})) {
    if (typeof rel !== 'string' || node_path__WEBPACK_IMPORTED_MODULE_0__.posix.normalize(rel) !== rel || rel.startsWith('/') || rel.startsWith('..')) { reasons.push(`${String(rel).slice(0, 80)}: not a confined relative path`); continue; }
    if (text !== null && typeof text !== 'string') { reasons.push(`${rel}: content must be text or null`); continue; }
    if ((originalFiles[rel] ?? null) !== text) changed[rel] = text;
  }
  for (const rel of Object.keys(changed)) {
    if (matchesAny(rel, contract.editScope.prohibited)) reasons.push(`${rel}: a protected path (verifier state, tests, runner configuration, dependencies); a candidate cannot change what judges it`);
    else if (!contract.editScope.allowed.includes(rel)) reasons.push(`${rel}: outside the contract's allowed edit scope`);
  }
  for (const [rel, text] of Object.entries(changed)) {
    for (const [re, what] of UNOBSERVED_PRIMITIVES) if (count(re, text) > count(re, originalFiles[rel])) reasons.push(`${rel}: introduces ${what}, which the application oracles cannot observe`);
  }
  const surface = (0,_fix_test_results_js__WEBPACK_IMPORTED_MODULE_3__/* .testSurfaceChanges */ .N)(changed, (rel) => originalFiles[rel] ?? null);
  for (const b of surface.blocked) reasons.push(`${b.file}: ${b.reason}`);
  const before = Object.fromEntries(Object.keys(changed).map((r) => [r, originalFiles[r] ?? null]));
  const scope = (0,_fix_patch_scope_js__WEBPACK_IMPORTED_MODULE_2__/* .computePatchScope */ .oL)({ before, after: changed, bounds: { maxFiles: contract.editScope.maxFiles, maxEditedLines: contract.editScope.maxEditedLines } });
  if (!Object.keys(changed).length) reasons.push('the candidate changes nothing');
  if (scope.exceedsBounds) reasons.push(...scope.exceedsReasons.map((r) => `over the contract's change budget: ${r}`));
  return { ok: reasons.length === 0, reasons, scope, changed };
}

/** The candidate record, with identities computed here. */
function makeCandidate(contract, originalFiles, proposal, checked) {
  const rec = {
    schema: _schemas_js__WEBPACK_IMPORTED_MODULE_4__/* .SCHEMAS */ .H6.candidate, schemaVersion: _schemas_js__WEBPACK_IMPORTED_MODULE_4__/* .SCHEMA_VERSION */ .f$,
    contractDigest: contract.contractDigest, baselineDigest: contract.sourceDigest,
    generator: proposal.generator, generatorIdentity: proposal.generatorIdentity, generationParameters: proposal.generationParameters || {},
    files: checked.changed,
    beforeDigests: Object.fromEntries(Object.keys(checked.changed).map((r) => [r, originalFiles[r] == null ? null : (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_1__/* .digestOf */ .ol)(originalFiles[r])])),
    afterDigests: Object.fromEntries(Object.entries(checked.changed).map(([r, t]) => [r, t == null ? null : (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_1__/* .digestOf */ .ol)(t)])),
    patchDigest: (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_1__/* .digestOf */ .ol)(checked.changed),
    scope: { totals: checked.scope.totals, material: checked.scope.material, touchedSymbols: checked.scope.files.flatMap((f) => (f.touchedSymbols || []).map((s) => `${f.file}:${s.name || s}`)).slice(0, 40) },
    strategy: proposal.strategy || null, rationale: proposal.rationale || null, assumptions: proposal.assumptions || [], proposedTests: [],
    accounting: { tokens: proposal.accounting?.tokens ?? null, calls: proposal.accounting?.calls ?? null, wallMs: proposal.accounting?.wallMs ?? null, usd: proposal.accounting?.usd ?? null },
  };
  rec.candidateId = (0,_schemas_js__WEBPACK_IMPORTED_MODULE_4__/* .candidateIdOf */ .qT)(rec);
  const v = (0,_schemas_js__WEBPACK_IMPORTED_MODULE_4__/* .validateCandidate */ .mu)(rec);
  return v.ok ? { candidate: rec, problems: [] } : { candidate: null, problems: v.errors.map((e) => `${e.path}: ${e.message}`) };
}

// ---------------------------------------------------------------- deterministic SQL recipe

/** Scan a template literal starting at the backtick index; returns {end, quasis, exprs} or null. */
function readTemplate(text, start) {
  const quasis = []; const exprs = [];
  let cur = ''; let i = start + 1;
  while (i < text.length) {
    const c = text[i];
    if (c === '\\') { cur += c + (text[i + 1] ?? ''); i += 2; continue; }
    if (c === '`') { quasis.push(cur); return { end: i, quasis, exprs }; }
    if (c === '$' && text[i + 1] === '{') {
      let depth = 1; let j = i + 2; let e = '';
      while (j < text.length && depth > 0) {
        const d = text[j];
        if (d === '`' || d === "'" || d === '"') return null; // nested strings: not a shape this recipe handles
        if (d === '{') depth++; else if (d === '}') depth--;
        if (depth > 0) e += d;
        j++;
      }
      if (depth) return null;
      quasis.push(cur); exprs.push(e.trim()); cur = ''; i = j; continue;
    }
    cur += c; i++;
  }
  return null;
}

const PREPARE_RE = /\.prepare\(\s*`/g;
const CALL_RE = /^\s*\)\s*\.(all|get|run|iterate)\(\s*\)/;

/** Apply the recipe to one file. Returns {text, applied, refused:[reasons]}. Pure. */
function parameterizeTemplateSql(text) {
  const refused = []; let applied = 0;
  let out = ''; let last = 0;
  PREPARE_RE.lastIndex = 0;
  let m;
  while ((m = PREPARE_RE.exec(text))) {
    const tick = m.index + m[0].length - 1;
    const t = readTemplate(text, tick);
    if (!t) { refused.push(`line ${text.slice(0, tick).split('\n').length}: the template could not be read safely`); continue; }
    if (!t.exprs.length) continue;
    const call = CALL_RE.exec(text.slice(t.end + 1));
    if (!call) { refused.push(`line ${text.slice(0, tick).split('\n').length}: the statement is not called immediately with no arguments`); continue; }
    let sql = ''; let ok = true;
    for (let k = 0; k < t.quasis.length; k++) {
      let q = t.quasis[k];
      if (k > 0) { if (!q.startsWith("'")) { ok = false; break; } q = q.slice(1); }
      if (k < t.exprs.length) { if (!q.endsWith("'")) { ok = false; break; } q = q.slice(0, -1) + '?'; }
      sql += q;
    }
    if (!ok || /\$\{/.test(sql)) { refused.push(`line ${text.slice(0, tick).split('\n').length}: an interpolation is not a quoted SQL value, so a placeholder cannot carry it`); continue; }
    const lit = `'${sql.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}'`;
    out += text.slice(last, tick) + lit + text.slice(t.end + 1, t.end + 1 + call[0].length - 1) + t.exprs.join(', ') + ')';
    last = t.end + 1 + call[0].length;
    PREPARE_RE.lastIndex = last;
    applied++;
  }
  out += text.slice(last);
  return { text: applied ? out : text, applied, refused };
}

/** The deterministic recipe as a proposer: one candidate, round 1 only, over the contract's allowed files. */
function sqlParameterizeRecipe() {
  return {
    id: `${RECIPE_SQL_PARAMETERIZE.id}@${RECIPE_SQL_PARAMETERIZE.version}`,
    async propose({ contract, files, round }) {
      if (round !== 1 || contract.family !== 'sql-injection') return { proposals: [], notes: [] };
      const out = {}; const notes = [];
      for (const rel of contract.editScope.allowed) {
        if (!/\.(?:m?js|cjs|ts)$/.test(rel) || typeof files[rel] !== 'string') continue;
        const r = parameterizeTemplateSql(files[rel]);
        if (r.applied) out[rel] = r.text;
        notes.push(...r.refused.map((x) => `${rel} ${x}`));
      }
      if (!Object.keys(out).length) return { proposals: [], notes: notes.length ? notes : ['the recipe matched no statement'] };
      return { proposals: [{ generator: 'deterministic-recipe', generatorIdentity: `${RECIPE_SQL_PARAMETERIZE.id}@${RECIPE_SQL_PARAMETERIZE.version}`, files: out, strategy: 'parameterize every quoted SQL value', rationale: 'bound parameters keep request values out of the SQL text' }], notes };
    },
  };
}

/**
 * User-supplied candidates, in order. `items` are {files, strategy?, rationale?, round?}. Items that name a `round` are offered together
 * in that round (a portfolio of strategies); items without one are offered one per round, in order.
 */
function queueProposer(items, identity = 'user-supplied') {
  const queue = [...items];
  const toProposal = (it) => ({ generator: 'user-supplied', generatorIdentity: identity, files: it.files, strategy: it.strategy || null, rationale: it.rationale || null });
  return {
    id: identity,
    async propose({ round, max }) {
      const grouped = queue.filter((it) => Number.isInteger(it.round));
      let take;
      if (grouped.length) {
        take = grouped.filter((it) => it.round === round).slice(0, Math.max(1, max || 1));
        for (const t of take) queue.splice(queue.indexOf(t), 1);
      } else take = queue.splice(0, 1);
      return { proposals: take.map(toProposal), notes: [] };
    },
    remaining: () => queue.length,
  };
}


/***/ }),

/***/ 20771:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  $B: () => (/* binding */ buildContract),
  NL: () => (/* binding */ obligationSummary),
  snapshotSource: () => (/* binding */ snapshotSource)
});

// UNUSED EXPORTS: CONTRACT_BUILDER_VERSION, PROTECTED_PATTERNS, SQL_PROBES

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:child_process"
var external_node_child_process_ = __webpack_require__(31421);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
// EXTERNAL MODULE: ./src/posture/oracles/registry.js + 2 modules
var registry = __webpack_require__(18357);
// EXTERNAL MODULE: ./src/repair/schemas.js
var schemas = __webpack_require__(68962);
// EXTERNAL MODULE: ./src/posture/assurance/schema-kit.js
var schema_kit = __webpack_require__(53353);
// EXTERNAL MODULE: ./src/posture/oracles/app-adapters.js
var app_adapters = __webpack_require__(50935);
;// CONCATENATED MODULE: ./src/repair/profile.js
// The application profile (verified-remediation PRD FR-04, FR-05): how to start the application and what its legitimate behaviour is.
//
// A profile is DECLARED by the operator; nothing here is inferred from code and presented as approved intent. It names the entry module
// and factory, the database schema and seed, the actors (with the request headers that authenticate each), and per family the inputs or
// objects the contract is built from. A profile file inside the repository is repository-supplied input: its facts are recorded as
// `declared`, never `approved`, and it cannot widen execution (it has no field that could: execution is enabled only by the operator).
//
// Closed world: an unknown field is an error. Identifiers that reach SQL (table and column names in generated state checks) must be plain
// identifiers. Validation never throws.




const PROFILE_SCHEMA = 'agentic-security/repair-profile';
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const SLUG = /^[a-z][a-z0-9-]{0,39}$/;
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
const POLICY_RULES = ['owner', 'same-tenant-admin', 'any-admin'];
const EFFECTS = ['read', 'update'];

const keysOnly = (errs, obj, allowed, where) => { for (const k of Object.keys(obj)) if (!allowed.includes(k)) errs.push(`${where}: unknown field '${k}'`); };

function checkRequestShape(errs, r, where) {
  if (!METHODS.includes(r.method)) errs.push(`${where}.method must be one of ${METHODS.join(', ')}`);
  if (typeof r.path !== 'string' || !r.path.startsWith('/') || r.path.length > 500) errs.push(`${where}.path must start with /`);
  if (r.body !== undefined && !(0,schema_kit/* isPlainObject */.Qd)(r.body)) errs.push(`${where}.body must be an object`);
}

/** One declared untrusted value input (sql, ssrf, filesystem): the request carrying {{value}} and its legitimate values. */
function checkValueInput(errs, inp, w, actorIds, { secrets }) {
  if (!(0,schema_kit/* isPlainObject */.Qd)(inp)) { errs.push(`${w} must be an object`); return; }
  keysOnly(errs, inp, ['id', 'actor', 'method', 'path', 'body', 'benign', ...(secrets ? ['protectedSecrets'] : [])], w);
  if (typeof inp.id !== 'string' || !SLUG.test(inp.id)) errs.push(`${w}.id must be a slug`);
  if (!actorIds.has(inp.actor)) errs.push(`${w}.actor must name a declared actor`);
  checkRequestShape(errs, inp, w);
  if (!JSON.stringify([inp.path, inp.body ?? null]).includes('{{value}}')) errs.push(`${w}: the path or body must mark the untrusted value with {{value}}`);
  if (!Array.isArray(inp.benign) || !inp.benign.length) errs.push(`${w}.benign must list at least one legitimate value with its expected response`);
  else for (const [j, b] of inp.benign.entries()) {
    if (!(0,schema_kit/* isPlainObject */.Qd)(b) || typeof b.value !== 'string') { errs.push(`${w}.benign[${j}].value must be a string`); continue; }
    keysOnly(errs, b, ['value', 'expectIncludes', 'expectStatus', 'originalMishandles'], `${w}.benign[${j}]`);
    if (!Array.isArray(b.expectIncludes) || !b.expectIncludes.length) errs.push(`${w}.benign[${j}].expectIncludes must list at least one expected value`);
  }
  if (secrets && (!Array.isArray(inp.protectedSecrets) || !inp.protectedSecrets.length || !inp.protectedSecrets.every((s) => SLUG.test(s)))) errs.push(`${w}.protectedSecrets must name the planted secrets another actor's data holds`);
}

function checkInputs(errs, sec, name, actorIds, opts) {
  if (!Array.isArray(sec.inputs) || !sec.inputs.length || sec.inputs.length > 8) { errs.push(`${name}.inputs must hold 1 to 8 inputs`); return; }
  for (const [i, inp] of sec.inputs.entries()) checkValueInput(errs, inp, `${name}.inputs[${i}]`, actorIds, opts);
}

/** Problems with a profile; an empty list means it can be used. */
function validateProfile(p) {
  const errs = [];
  if (!(0,schema_kit/* isPlainObject */.Qd)(p)) return ['the profile must be a JSON object'];
  keysOnly(errs, p, ['schema', 'schemaVersion', 'application', 'database', 'actors', 'sql', 'authorization', 'ssrf', 'filesystem', 'tests', 'approval'], 'profile');
  if (p.schema !== PROFILE_SCHEMA) errs.push(`schema must be '${PROFILE_SCHEMA}'`);
  if (!/^1\.\d+\.\d+$/.test(String(p.schemaVersion))) errs.push('schemaVersion must be 1.x.y');
  const a = p.application;
  if (!(0,schema_kit/* isPlainObject */.Qd)(a)) errs.push('application is required');
  else {
    keysOnly(errs, a, ['entry', 'export', 'files', 'runtime'], 'application');
    if (!(0,schemas/* isRelPath */.ji)(a.entry)) errs.push('application.entry must be a relative path');
    if (typeof a.export !== 'string' || !IDENT.test(a.export)) errs.push('application.export must be an identifier');
    if (!Array.isArray(a.files) || !a.files.length || a.files.length > 60 || !a.files.every(schemas/* isRelPath */.ji)) errs.push('application.files must list 1 to 60 relative paths');
    else if (!a.files.includes(a.entry)) errs.push('application.files must include the entry');
    if (a.runtime !== undefined && !['node', 'python'].includes(a.runtime)) errs.push("application.runtime must be 'node' or 'python'");
    if (a.runtime === 'python' && !/\.py$/.test(String(a.entry))) errs.push('application.entry must be a .py file for the python runtime');
  }
  const d = p.database;
  if (!(0,schema_kit/* isPlainObject */.Qd)(d)) errs.push('database is required');
  else {
    keysOnly(errs, d, ['engine', 'schemaSql', 'seed'], 'database');
    if (d.engine !== 'sqlite') errs.push("database.engine: only 'sqlite' is supported in this milestone");
    if (typeof d.schemaSql !== 'string' || !d.schemaSql.trim()) errs.push('database.schemaSql is required');
    if (!Array.isArray(d.seed)) errs.push('database.seed must be an array');
  }
  const actorIds = new Set();
  if (!Array.isArray(p.actors) || !p.actors.length) errs.push('actors must be a non-empty array');
  else for (const [i, ac] of p.actors.entries()) {
    if (!(0,schema_kit/* isPlainObject */.Qd)(ac)) { errs.push(`actors[${i}] must be an object`); continue; }
    keysOnly(errs, ac, ['id', 'tenant', 'role', 'headers', 'anonymous'], `actors[${i}]`);
    if (typeof ac.id !== 'string' || !SLUG.test(ac.id) || actorIds.has(ac.id)) errs.push(`actors[${i}].id must be a unique slug`);
    actorIds.add(ac.id);
    if (!(0,schema_kit/* isPlainObject */.Qd)(ac.headers || {})) errs.push(`actors[${i}].headers must be an object`);
  }
  if (!['sql', 'authorization', 'ssrf', 'filesystem'].some((k) => p[k] !== undefined)) errs.push('the profile needs a sql, authorization, ssrf or filesystem section');
  if ((p.ssrf !== undefined || p.filesystem !== undefined) && a?.runtime === 'python') errs.push('the ssrf and filesystem sections are supported for the node runtime only in this release');
  if (p.sql !== undefined) {
    if (!(0,schema_kit/* isPlainObject */.Qd)(p.sql)) errs.push('sql must be an object');
    else { keysOnly(errs, p.sql, ['inputs', 'stateChecks'], 'sql'); checkInputs(errs, p.sql, 'sql', actorIds, { secrets: true }); }
  }
  // Server-side request forgery: the network the application can reach is declared (hosts, their DNS answers, what each serves), with a
  // destination policy. Secrets planted in a forbidden host's responses show disclosure; the connection itself is the forbidden effect.
  if (p.ssrf !== undefined) {
    if (!(0,schema_kit/* isPlainObject */.Qd)(p.ssrf)) errs.push('ssrf must be an object');
    else {
      keysOnly(errs, p.ssrf, ['policy', 'approved', 'hosts', 'inputs'], 'ssrf');
      const n = (0,app_adapters/* validateNetwork */.jO)({ policy: p.ssrf.policy, approved: p.ssrf.approved, hosts: p.ssrf.hosts });
      if (n) errs.push(`ssrf: ${n}`);
      checkInputs(errs, p.ssrf, 'ssrf', actorIds, { secrets: false });
    }
  }
  // Path traversal: a real file tree with an allowed root; files outside it plant secrets; declared links are real symbolic links.
  if (p.filesystem !== undefined) {
    if (!(0,schema_kit/* isPlainObject */.Qd)(p.filesystem)) errs.push('filesystem must be an object');
    else {
      keysOnly(errs, p.filesystem, ['root', 'tree', 'links', 'inputs'], 'filesystem');
      const f = (0,app_adapters/* validateFiles */.kc)({ root: p.filesystem.root, tree: p.filesystem.tree, ...(p.filesystem.links !== undefined ? { links: p.filesystem.links } : {}) });
      if (f) errs.push(`filesystem: ${f}`);
      checkInputs(errs, p.filesystem, 'filesystem', actorIds, { secrets: false });
    }
  }
  if (p.authorization !== undefined) {
    const z = p.authorization;
    if (!(0,schema_kit/* isPlainObject */.Qd)(z)) errs.push('authorization must be an object');
    else {
      keysOnly(errs, z, ['table', 'idColumn', 'contentColumn', 'objects', 'operations', 'policy', 'controls'], 'authorization');
      // Declared legitimate workflows outside the actor matrix (a public page, a health route): they must keep working after a repair.
      if (z.controls !== undefined) {
        if (!Array.isArray(z.controls) || z.controls.length > 32) errs.push('authorization.controls must be an array of at most 32');
        else for (const [i, c] of z.controls.entries()) {
          const w = `authorization.controls[${i}]`;
          if (!(0,schema_kit/* isPlainObject */.Qd)(c)) { errs.push(`${w} must be an object`); continue; }
          keysOnly(errs, c, ['id', 'actor', 'method', 'path', 'body', 'expectStatus', 'expectIncludes'], w);
          if (typeof c.id !== 'string' || !SLUG.test(c.id)) errs.push(`${w}.id must be a slug`);
          if (!actorIds.has(c.actor)) errs.push(`${w}.actor must name a declared actor`);
          checkRequestShape(errs, c, w);
          if (c.expectIncludes !== undefined && (!Array.isArray(c.expectIncludes) || !c.expectIncludes.every((x) => typeof x === 'string' && x))) errs.push(`${w}.expectIncludes must list strings`);
        }
      }
      for (const k of ['table', 'idColumn', 'contentColumn']) if (typeof z[k] !== 'string' || !IDENT.test(z[k])) errs.push(`authorization.${k} must be an identifier`);
      if (!Array.isArray(z.objects) || !z.objects.length) errs.push('authorization.objects must be a non-empty array');
      else for (const [i, o] of z.objects.entries()) {
        if (!(0,schema_kit/* isPlainObject */.Qd)(o)) { errs.push(`authorization.objects[${i}] must be an object`); continue; }
        keysOnly(errs, o, ['id', 'owner', 'rowId', 'secret'], `authorization.objects[${i}]`);
        if (!actorIds.has(o.owner)) errs.push(`authorization.objects[${i}].owner must name a declared actor`);
        if (!(Number.isInteger(o.rowId) || (typeof o.rowId === 'string' && o.rowId.length <= 64))) errs.push(`authorization.objects[${i}].rowId must be an integer or short string`);
        if (typeof o.secret !== 'string' || !SLUG.test(o.secret)) errs.push(`authorization.objects[${i}].secret must name the planted secret the object holds`);
      }
      if (!Array.isArray(z.operations) || !z.operations.length) errs.push('authorization.operations must be a non-empty array');
      else {
        for (const [i, op] of z.operations.entries()) {
          if (!(0,schema_kit/* isPlainObject */.Qd)(op)) { errs.push(`authorization.operations[${i}] must be an object`); continue; }
          keysOnly(errs, op, ['id', 'effect', 'method', 'path', 'body', 'expectStatus'], `authorization.operations[${i}]`);
          if (!EFFECTS.includes(op.effect)) errs.push(`authorization.operations[${i}].effect must be one of ${EFFECTS.join(', ')} (other effects are not supported in this milestone)`);
          checkRequestShape(errs, op, `authorization.operations[${i}]`);
          if (!String(op.path).includes('{{id}}')) errs.push(`authorization.operations[${i}].path must mark the object id with {{id}}`);
          if (op.effect === 'update' && !JSON.stringify(op.body ?? null).includes('{{value}}')) errs.push(`authorization.operations[${i}]: an update body must mark the written value with {{value}}`);
        }
        if (!z.operations.some((op) => op?.effect === 'read')) errs.push('authorization.operations needs at least one read operation (the security run uses it to show the application works)');
      }
      const pol = z.policy;
      if (!(0,schema_kit/* isPlainObject */.Qd)(pol) || !Array.isArray(pol.allow) || !pol.allow.length || !pol.allow.every((r) => POLICY_RULES.includes(r))) errs.push(`authorization.policy.allow must list rules from ${POLICY_RULES.join(', ')}`);
    }
  }
  if (p.tests !== undefined) {
    if (!(0,schema_kit/* isPlainObject */.Qd)(p.tests) || typeof p.tests.command !== 'string' || !p.tests.command.trim()) errs.push('tests.command must be a string');
    else keysOnly(errs, p.tests, ['command', 'required', 'flaky'], 'tests');
  }
  if (p.approval !== undefined && !((0,schema_kit/* isPlainObject */.Qd)(p.approval) && typeof p.approval.approvedBy === 'string' && p.approval.approvedBy.trim() && typeof p.approval.reason === 'string' && p.approval.reason.trim())) errs.push('approval must be {approvedBy, reason}');
  return errs;
}

/** Which actors a policy allows to act on an object. Pure. */
function policyAllows(policy, actor, object, actorsById) {
  if (!actor || actor.anonymous) return false;
  const owner = actorsById[object.owner];
  for (const rule of policy.allow) {
    if (rule === 'owner' && actor.id === object.owner) return true;
    if (rule === 'same-tenant-admin' && actor.role === 'admin' && owner && actor.tenant === owner.tenant) return true;
    if (rule === 'any-admin' && actor.role === 'admin') return true;
  }
  return false;
}

;// CONCATENATED MODULE: ./src/repair/contracts.js
// Repair contracts (verified-remediation PRD FR-04, section 6.2): what a repair must establish, as declarative obligations over
// registered verifier operations.
//
// Inputs: a normalized finding, an operator-declared application profile (profile.js) and the exact source snapshot. Output: a closed,
// versioned RepairContract (schemas.js) whose identity covers the source, the configuration and dependency digests, the profile's policy
// facts, the oracle logic each obligation runs on, and the edit scope. Identical inputs give an identical contract id (no clock, no
// randomness); a change to any of them gives a different one (AC-04.1, AC-04.2).
//
// The family decides the required obligations, not which checks happen to be available (FR-04):
//   sql-injection          the declared untrusted inputs carry attack probes that must reach no planted secret (development set, plus
//                          a sealed held-out set), the declared legitimate values must still return their expected data, and legitimate
//                          values the original mishandles (a quote in a name) must work after the repair (AC-04.3). Behavioural
//                          equivalence is never required of attacker input (AC-04.7).
//   object-authorization   the full actor matrix: for every declared object and operation, each actor (owner, other member, another
//                          tenant, admin, anonymous) gets the outcome the declared policy gives it. A denied read must not disclose the
//                          object's planted secret; a denied update must not change durable state, whatever the HTTP status (a 403 that
//                          still wrote is a violation); allowed actors must keep working (AC-04.4).
// Project tests, the rescan and the footprint run through the central verifier as the `project-tests` obligation.
//
// A missing prerequisite (no seed secret to protect, no read operation, an application file that does not exist) makes the contract
// `blocked` with the reason: it is never weakened into a contract that could pass (AC-04.6).









const CONTRACT_BUILDER_VERSION = '1';

// Attack probes for a value placed in a SQL string literal. Split once, statically: the development set feeds back to candidate
// generation; the sealed set is run only on a candidate that passed everything else, and its content never leaves the coordinator.
const SQL_PROBES = Object.freeze({
  development: ["x' OR '1'='1", "x' OR 1=1 --"],
  sealed: ["zz' OR 'a'='a' --", "') OR ('1'='1", 'x" OR "1"="1'],
});

const DEFAULT_EDIT_BUDGET = Object.freeze({ maxFiles: 3, maxEditedLines: 100 });
// Paths a candidate may never touch, whatever the profile says: the verifier's own state, version control, dependency trees and the
// project's test and runner configuration (a candidate cannot weaken the checks that judge it).
const PROTECTED_PATTERNS = Object.freeze([
  '.agentic-security/**', '.git/**', 'node_modules/**', '**/*.test.*', '**/*.spec.*', 'test/**', 'tests/**', '__tests__/**',
  'package.json', 'package-lock.json', 'jest.config.*', 'vitest.config.*', '.mocharc*', '**/__oracle_*',
]);

const fill = (tpl, map, { encode }) => tpl.replace(/\{\{(value|id)\}\}/g, (_, k) => (encode ? encodeURIComponent(String(map[k])) : String(map[k])));
const fillBody = (body, map) => (body === undefined ? undefined : JSON.parse(JSON.stringify(body), (k, v) => (typeof v === 'string' ? fill(v, map, { encode: false }) : v)));
const reqOf = (r, actor, map) => ({ method: r.method, path: fill(r.path, map, { encode: true }), headers: { ...(actor?.headers || {}) }, ...(r.body !== undefined ? { body: fillBody(r.body, map) } : {}) });

/** Read the application files and the configuration that can change behaviour. Never follows a link out of the root. */
function snapshotSource(root, profile) {
  const files = {}; const missing = [];
  const realRoot = external_node_fs_.realpathSync(root);
  for (const rel of profile.application.files) {
    const abs = external_node_path_.resolve(realRoot, rel);
    try {
      const st = external_node_fs_.lstatSync(abs);
      if (!st.isFile() || st.isSymbolicLink() || !abs.startsWith(realRoot + external_node_path_.sep)) { missing.push(rel); continue; }
      files[rel] = external_node_fs_.readFileSync(abs, 'utf8');
    } catch { missing.push(rel); }
  }
  const configDigests = {};
  for (const rel of ['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', '.nvmrc']) {
    try { configDigests[rel] = (0,identity/* digestOf */.ol)(external_node_fs_.readFileSync(external_node_path_.join(realRoot, rel), 'utf8')); } catch { /* absent */ }
  }
  let python = null;
  if (profile.application.runtime === 'python') {
    for (const p of ['/usr/bin/python3', '/opt/homebrew/bin/python3', '/usr/local/bin/python3']) {
      try { if (external_node_fs_.statSync(p).isFile()) { python = String((0,external_node_child_process_.spawnSync)(p, ['-I', '-c', 'import sys, sqlite3; print(sys.version.split()[0], sqlite3.sqlite_version)'], { encoding: 'utf8', timeout: 5000 }).stdout || '').trim() || null; break; } } catch { /* next */ }
    }
  }
  configDigests.runtime = (0,identity/* digestOf */.ol)({ node: process.versions.node, sqlite: process.versions.sqlite || null, ...(profile.application.runtime === 'python' ? { python } : {}) });
  return { files, missing, sourceDigest: (0,identity/* digestOf */.ol)(files), configDigests };
}

function obligation(kind, id, inputs, { required = true, origin = 'generated-from-profile', scope }) {
  const k = schemas/* OBLIGATION_KINDS */.Xn[kind];
  const o = (0,registry.getOracle)(k.oracle);
  return {
    id, kind, required, oracleId: k.oracle, oracleVersion: o.version, oracleLogicDigest: o.logicDigest,
    scope, baselineExpectation: k.expectBaseline, patchedExpectation: k.expectPatched, evidenceOrigin: origin,
    inputs, inputsDigest: (0,identity/* digestOf */.ol)(inputs), description: k.description,
  };
}

const appInputs = (profile, requests, stateChecks = [], extra = {}) => ({
  ...(profile.application.runtime === 'python' ? { runtime: 'python' } : {}),
  export: profile.application.export, schemaSql: profile.database.schemaSql, seed: profile.database.seed, requests, stateChecks, ...extra,
});

function seedHasSecret(profile, name) {
  return JSON.stringify(profile.database.seed).includes(`{{secret:${name}}}`);
}

function sqlObligations(profile, actors, blocked) {
  const out = [];
  const controls = []; const after = []; const dev = []; const sealed = [];
  for (const inp of profile.sql.inputs) {
    const actor = actors[inp.actor];
    for (const s of inp.protectedSecrets) if (!seedHasSecret(profile, s)) blocked.push(`sql input ${inp.id}: the seed plants no {{secret:${s}}} value, so a disclosure could not be observed`);
    inp.benign.forEach((b, j) => {
      const r = { id: `${inp.id.replace(/-/g, '_')}_benign_${j}`, role: 'control', ...reqOf(inp, actor, { value: b.value }), expect: { status: b.expectStatus || [200], bodyIncludes: b.expectIncludes } };
      (b.originalMishandles ? after : controls).push(r);
    });
    const probe = (set, list) => SQL_PROBES[set].forEach((v, j) => list.push({ id: `${inp.id.replace(/-/g, '_')}_${set}_${j}`, role: 'attack', ...reqOf(inp, actor, { value: v }), forbid: { secrets: [...inp.protectedSecrets] }, probe: v }));
    probe('development', dev); probe('sealed', sealed);
  }
  if (!controls.length) blocked.push('sql: no benign value is declared that the original serves correctly; mark only quoted values originalMishandles');
  const stateChecks = (profile.sql.stateChecks || []).map((c) => ({ ...c, role: 'attack' }));
  const strip = (r) => { const { probe, ...rest } = r; return rest; };
  if (controls.length) {
    out.push(obligation('app-attack-blocked', 'sql-attacks-development', appInputs(profile, [...controls, ...dev.map(strip)], stateChecks), { scope: 'declared untrusted inputs, development probe set' }));
    out.push(obligation('app-attack-sealed', 'sql-attacks-sealed', appInputs(profile, [...controls, ...sealed.map(strip)], stateChecks), { scope: 'declared untrusted inputs, sealed probe set (never fed back)' }));
    out.push(obligation('app-behaviour-preserved', 'sql-legitimate-queries', appInputs(profile, controls), { scope: 'declared legitimate values' }));
  }
  if (after.length) out.push(obligation('app-behaviour-after', 'sql-legitimate-quoted-values', appInputs(profile, after), { scope: 'legitimate values the original mishandles' }));
  return out;
}

/** Controls (and the after-repair controls) from an input's declared legitimate values. Shared by every value-input family. */
function benignRequests(inp, actor, controls, after) {
  inp.benign.forEach((b, j) => {
    const r = { id: `${inp.id.replace(/-/g, '_')}_benign_${j}`, role: 'control', ...reqOf(inp, actor, { value: b.value }), expect: { status: b.expectStatus || [200], bodyIncludes: b.expectIncludes } };
    (b.originalMishandles ? after : controls).push(r);
  });
}

/** The obligations of a value-input family from its development and sealed attack values. */
function valueFamilyObligations(family, profile, actors, blocked, { probes, forbid, extra, scopeNoun }) {
  const out = []; const controls = []; const after = []; const dev = []; const sealed = [];
  for (const inp of profile[family].inputs) {
    const actor = actors[inp.actor];
    benignRequests(inp, actor, controls, after);
    for (const set of ['development', 'sealed']) probes[set].forEach((v, j) => (set === 'sealed' ? sealed : dev).push({ id: `${inp.id.replace(/-/g, '_')}_${set}_${j}`, role: 'attack', ...reqOf(inp, actor, { value: v }), forbid: forbid(v) }));
  }
  if (!controls.length) blocked.push(`${family}: no legitimate value is declared that the original serves correctly`);
  if (!dev.length) blocked.push(`${family}: the declaration yields no attack value, so no forbidden effect could be observed`);
  if (blocked.length) return out;
  out.push(obligation('app-attack-blocked', `${family}-attacks-development`, appInputs(profile, [...controls, ...dev], [], extra), { scope: `${scopeNoun}, development attack set` }));
  if (sealed.length) out.push(obligation('app-attack-sealed', `${family}-attacks-sealed`, appInputs(profile, [...controls, ...sealed], [], extra), { scope: `${scopeNoun}, sealed attack set (never fed back)` }));
  out.push(obligation('app-behaviour-preserved', `${family}-legitimate-requests`, appInputs(profile, controls, [], extra), { scope: 'declared legitimate values' }));
  if (after.length) out.push(obligation('app-behaviour-after', `${family}-legitimate-after`, appInputs(profile, after, [], extra), { scope: 'legitimate values the original mishandles' }));
  return out;
}

const SECRET_NAMES = (text) => [...String(text).matchAll(/\{\{secret:([a-z][a-z0-9-]{0,31})\}\}/g)].map((m) => m[1]);
const ipv4Int = (a) => a.split('.').reduce((n, o) => n * 256 + Number(o), 0);

/**
 * SSRF attack values, generated from the declared network. A host is forbidden when the policy does not permit every address it can
 * resolve to (an allowlist names the approved hosts; public-only forbids loopback, private, link-local and the other internal ranges,
 * so a host that rebinds from a public to a private address is forbidden). Development: each forbidden host by name and by address,
 * and every approved host's declared redirect that leaves the approved set. Sealed: the same destinations spelled differently
 * (decimal and IPv4-mapped IPv6 addresses, upper case with a trailing dot, an approved host as user information).
 */
function ssrfProbes(s) {
  const permittedAddr = (h, a) => (s.policy === 'public-only' ? !(0,app_adapters/* isPrivateAddress */.C0)(a) : s.approved.includes(h.name));
  const forbidden = s.hosts.filter((h) => !h.addresses.every((a) => permittedAddr(h, a)));
  const port = (h) => (h.port && h.port !== 80 ? `:${h.port}` : '');
  const pathOf = (h) => h.routes?.[0]?.path || '/';
  const development = []; const sealed = [];
  for (const h of forbidden) {
    development.push(`http://${h.name}${port(h)}${pathOf(h)}`);
    const v4 = h.addresses.find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a) && !permittedAddr(h, a));
    if (v4) {
      development.push(`http://${v4}${port(h)}${pathOf(h)}`);
      sealed.push(`http://${ipv4Int(v4)}${port(h)}${pathOf(h)}`, `http://[::ffff:${v4}]${port(h)}${pathOf(h)}`);
    }
    sealed.push(`http://${h.name.toUpperCase()}.${port(h)}${pathOf(h)}`);
    if (s.approved[0]) sealed.push(`http://${s.approved[0]}@${h.name}${port(h)}${pathOf(h)}`);
  }
  const forbiddenNames = new Set(forbidden.map((h) => h.name));
  const forbiddenAddrs = new Set(forbidden.flatMap((h) => h.addresses));
  for (const h of s.hosts.filter((x) => !forbiddenNames.has(x.name))) {
    for (const r of h.routes || []) {
      const loc = r.status >= 300 && r.status < 400 ? Object.entries(r.headers || {}).find(([k]) => k.toLowerCase() === 'location')?.[1] : null;
      if (!loc) continue;
      let target; try { target = new URL(loc, `http://${h.name}`); } catch { continue; }
      const host = target.hostname.replace(/^\[|\]$/g, '');
      if (forbiddenNames.has(host) || forbiddenAddrs.has(host)) development.push(`http://${h.name}${port(h)}${r.path}`);
    }
  }
  const secrets = [...new Set(forbidden.flatMap((h) => (h.routes || []).flatMap((r) => SECRET_NAMES(r.body || ''))))];
  return { development: [...new Set(development)], sealed: [...new Set(sealed)].filter((v) => !development.includes(v)), secrets, forbidden: forbidden.map((h) => h.name) };
}

function ssrfObligations(profile, actors, blocked) {
  const s = profile.ssrf;
  const p = ssrfProbes(s);
  if (!p.forbidden.length) blocked.push('ssrf: every declared host is permitted by the policy, so there is no forbidden destination to test');
  const network = { policy: s.policy, approved: s.approved, hosts: s.hosts };
  return valueFamilyObligations('ssrf', profile, actors, blocked, {
    probes: p, forbid: () => ({ ...(p.secrets.length ? { secrets: [...p.secrets] } : {}), connections: true }), extra: { network }, scopeNoun: 'declared untrusted URL inputs',
  });
}

/**
 * Path traversal attack values, generated from the declared tree. Every file outside the allowed root that plants a secret is a
 * target. Development: the relative escape, the absolute path, and every declared link inside the root that points outside it.
 * Sealed: an escape through a subdirectory and a `./` prefix (each must also disclose on the original, or it is quarantined).
 */
function traversalProbes(f) {
  const root = f.root.replace(/\/$/, '');
  const inside = (rel) => rel === root || rel.startsWith(`${root}/`);
  const development = []; const sealed = []; const secrets = new Set();
  const subdir = Object.keys(f.tree).filter(inside).map((r) => r.slice(root.length + 1).split('/')).find((parts) => parts.length > 1)?.[0] || null;
  for (const [rel, content] of Object.entries(f.tree)) {
    if (inside(rel)) continue;
    const names = SECRET_NAMES(content);
    if (!names.length) continue;
    names.forEach((n) => secrets.add(n));
    const up = external_node_path_.posix.relative(root, rel);
    development.push(up, `{{fs:abs}}/${rel}`);
    for (const [link, target] of Object.entries(f.links || {})) {
      if (!inside(link)) continue;
      const dest = external_node_path_.posix.normalize(external_node_path_.posix.join(external_node_path_.posix.dirname(link), target));
      if (inside(dest) || !(rel === dest || rel.startsWith(`${dest}/`))) continue;
      development.push(`${external_node_path_.posix.relative(root, link)}/${external_node_path_.posix.relative(dest, rel)}`);
    }
    sealed.push(`./${up}`);
    if (subdir) sealed.push(`${subdir}/../${up}`);
  }
  return { development: [...new Set(development)], sealed: [...new Set(sealed)], secrets: [...secrets] };
}

function filesystemObligations(profile, actors, blocked) {
  const f = profile.filesystem;
  const p = traversalProbes(f);
  if (!p.secrets.length) blocked.push('filesystem: no file outside the allowed root plants a {{secret:<name>}} value, so a disclosure could not be observed');
  const files = { root: f.root, tree: f.tree, ...(f.links ? { links: f.links } : {}) };
  return valueFamilyObligations('filesystem', profile, actors, blocked, {
    probes: p, forbid: () => ({ secrets: [...p.secrets] }), extra: { files }, scopeNoun: 'declared untrusted path inputs',
  });
}

function authzObligations(profile, actors, blocked) {
  const z = profile.authorization;
  const out = [];
  const reads = []; const readControls = []; const writeAttacks = []; const writeControls = []; const attackChecks = []; const controlChecks = [];
  const matrix = [];
  for (const obj of z.objects) {
    if (!seedHasSecret(profile, obj.secret)) blocked.push(`object ${obj.id}: the seed plants no {{secret:${obj.secret}}} value, so a disclosure could not be observed`);
    let lastWriter = null; const deniedWriters = [];
    for (const op of z.operations) {
      for (const actor of Object.values(actors)) {
        const allowed = policyAllows(z.policy, actor, obj, actors);
        const rid = `${op.id}_${obj.id}_${actor.id}`.replace(/-/g, '_');
        matrix.push({ object: obj.id, operation: op.id, effect: op.effect, actor: actor.id, role: actor.role ?? null, tenant: actor.tenant ?? null, owner: obj.owner, allowed });
        if (op.effect === 'read') {
          if (allowed) readControls.push({ id: rid, role: 'control', ...reqOf(op, actor, { id: obj.rowId }), expect: { status: op.expectStatus || [200], bodyIncludes: [`{{secret:${obj.secret}}}`] } });
          else reads.push({ id: rid, role: 'attack', ...reqOf(op, actor, { id: obj.rowId }), forbid: { secrets: [obj.secret] } });
        } else {
          const value = `${allowed ? 'written' : 'forged'}-by-${actor.id}-${obj.id}`;
          const r = reqOf(op, actor, { id: obj.rowId, value });
          if (allowed) { writeControls.push({ id: rid, role: 'control', ...r, expect: { status: op.expectStatus || [200, 201, 204] } }); lastWriter = value; }
          else { writeAttacks.push({ id: rid, role: 'attack', ...r, forbid: {} }); deniedWriters.push(rid); }
        }
      }
    }
    // One check per object: its content is still the planted value after every denied write. Several denied writes to one object would
    // overwrite each other, so a per-write check would see only the last; the object-level check sees any of them. `guards` names the
    // requests it judges (verifier-side metadata, never sent to the application).
    if (deniedWriters.length) attackChecks.push({ id: `${obj.id.replace(/-/g, '_')}_unchanged`, role: 'attack', sql: `SELECT count(*) AS n FROM ${z.table} WHERE ${z.idColumn} = ? AND ${z.contentColumn} = ?`, params: [obj.rowId, `{{secret:${obj.secret}}}`], expect: [{ n: 1 }], guards: deniedWriters });
    if (lastWriter) controlChecks.push({ id: `${obj.id.replace(/-/g, '_')}_written`, role: 'control', sql: `SELECT count(*) AS n FROM ${z.table} WHERE ${z.idColumn} = ? AND ${z.contentColumn} = ?`, params: [obj.rowId, lastWriter], expect: [{ n: 1 }] });
  }
  for (const c of z.controls || []) {
    writeControls.push({ id: `control_${c.id.replace(/-/g, '_')}`, role: 'control', ...reqOf(c, actors[c.actor], {}), expect: { status: c.expectStatus || [200], ...(c.expectIncludes ? { bodyIncludes: c.expectIncludes } : {}) } });
  }
  if (!readControls.length) blocked.push('authorization: no actor is allowed to read any declared object, so the application cannot be shown to work');
  if (!reads.length && !writeAttacks.length) blocked.push('authorization: the policy allows every actor everything, so there is nothing to deny');
  if (blocked.length) return { obligations: out, matrix };
  // The security run holds every denied attempt plus the allowed READS only: an allowed write would overwrite the state a denied write
  // must be judged by. Allowed writes are judged in the behaviour run. Order: allowed reads, denied reads, then denied writes, so a
  // write that succeeds on a vulnerable revision cannot make an earlier legitimate read look broken.
  out.push(obligation('app-attack-blocked', 'authz-denied-actors', appInputs(profile, [...readControls, ...reads, ...writeAttacks], attackChecks), { scope: 'every declared actor x object x operation the policy denies' }));
  out.push(obligation('app-behaviour-preserved', 'authz-allowed-workflows', appInputs(profile, [...readControls, ...writeControls], controlChecks), { scope: 'every declared actor x object x operation the policy allows' }));
  return { obligations: out, matrix };
}

/**
 * @param {{finding:object, profile:object, profileOrigin:'repository-file'|'operator-profile-outside-repository', source:{files,sourceDigest,configDigests,missing}, commit?:string|null, family:'sql-injection'|'object-authorization', editBudget?:{maxFiles:number,maxEditedLines:number}}} o
 * @returns {{contract:object|null, blocked:string[], problems:string[], matrix?:object[]}}
 */
function buildContract(o) {
  const problems = validateProfile(o.profile);
  if (problems.length) return { contract: null, blocked: [], problems };
  const profile = o.profile;
  const blocked = [];
  for (const m of o.source.missing || []) blocked.push(`application file ${m} is missing or not a regular file`);
  const actors = Object.fromEntries(profile.actors.map((a) => [a.id, a]));
  let obligations; let matrix = null;
  if (o.family === 'sql-injection') {
    if (!profile.sql) return { contract: null, blocked: ['the profile has no sql section for a sql-injection finding'], problems: [] };
    obligations = sqlObligations(profile, actors, blocked);
  } else if (o.family === 'object-authorization') {
    if (!profile.authorization) return { contract: null, blocked: ['the profile has no authorization section for an authorization finding'], problems: [] };
    ({ obligations, matrix } = authzObligations(profile, actors, blocked));
  } else if (o.family === 'ssrf') {
    if (!profile.ssrf) return { contract: null, blocked: ['the profile has no ssrf section for a server-side request forgery finding'], problems: [] };
    obligations = ssrfObligations(profile, actors, blocked);
  } else if (o.family === 'path-traversal') {
    if (!profile.filesystem) return { contract: null, blocked: ['the profile has no filesystem section for a path traversal finding'], problems: [] };
    obligations = filesystemObligations(profile, actors, blocked);
  } else return { contract: null, blocked: [`family ${o.family} has no registered repair contract in this milestone`], problems: [] };
  obligations.push({
    id: 'central-verifier', kind: 'project-tests', required: true, oracleId: null, oracleVersion: null, oracleLogicDigest: null,
    scope: profile.tests ? `rescan, new-finding delta, footprint and the per-test delta of '${profile.tests.command}'` : 'rescan, new-finding delta and footprint; no project test command was declared, so the test leg is not run and the record says so',
    baselineExpectation: null, patchedExpectation: 'passed', evidenceOrigin: 'registered-family', description: schemas/* OBLIGATION_KINDS */.Xn['project-tests'].description,
  });
  const approved = o.profileOrigin === 'operator-profile-outside-repository' && profile.approval;
  const policyFacts = [{
    id: 'application-profile', origin: o.profileOrigin, approval: approved ? 'approved' : 'declared',
    digest: (0,identity/* digestOf */.ol)({ actors: profile.actors, sql: profile.sql ?? null, authorization: profile.authorization ?? null, ssrf: profile.ssrf ?? null, filesystem: profile.filesystem ?? null, database: profile.database }),
    ...(approved ? { approvedBy: profile.approval.approvedBy } : {}),
  }];
  const knownUnknowns = [
    'only the declared requests, actors, objects and state checks are verified; behaviour outside them is not observed',
    'no call-graph slice beyond the declared application files is computed: callers outside them are not exercised',
    'requests run one at a time in a single process; no concurrency is exercised',
  ];
  if (!approved) knownUnknowns.push('the profile facts are declared, not approved: a verified result holds for the declared contract only');
  if (!profile.tests) knownUnknowns.push('no project test command was declared');
  const findingFile = o.finding?.locations?.[0]?.file || o.finding?.file || null;
  const contract = {
    schema: schemas/* SCHEMAS */.H6.contract, schemaVersion: schemas/* SCHEMA_VERSION */.f$,
    family: o.family,
    findingRefs: [o.finding.findingId || o.finding.stableId || o.finding.id],
    rootCauseGroup: (0,identity/* digestOf */.ol)({ family: o.family, file: findingFile }),
    sourceCommit: o.commit ?? null, sourceDigest: o.source.sourceDigest, configDigests: o.source.configDigests,
    profile: { application: profile.application, database: { engine: profile.database.engine }, runtime: profile.application.runtime || 'node', builder: CONTRACT_BUILDER_VERSION, ...(matrix ? { actorMatrix: matrix } : {}) },
    obligations, policyFacts,
    editScope: { allowed: [...profile.application.files], prohibited: [...PROTECTED_PATTERNS], ...(o.editBudget || DEFAULT_EDIT_BUDGET) },
    executionPolicy: { execution: 'trust-boundary', network: 'denied', model: 'none-unless-operator-configured' },
    knownUnknowns,
  };
  contract.contractId = (0,schemas/* contractIdOf */.JF)(contract);
  contract.contractDigest = (0,schemas/* contractDigestOf */.U_)(contract);
  const v = (0,schemas/* validateContract */.T7)(contract);
  if (!v.ok) return { contract: null, blocked, problems: v.errors.map((e) => `${e.path}: ${e.message}`) };
  return { contract, blocked, problems: [], ...(matrix ? { matrix } : {}) };
}

/** The obligations of a contract as a reader sees them: kind, scope, required, oracle. Used by CLI and MCP alike (AC-04.5). */
function obligationSummary(contract) {
  return contract.obligations.map((o) => ({ id: o.id, kind: o.kind, required: o.required, oracle: o.oracleId ? `${o.oracleId}@${o.oracleVersion}` : 'central-verifier', scope: o.scope, requests: o.inputs?.requests?.length ?? null, stateChecks: o.inputs?.stateChecks?.length ?? null }));
}




/***/ }),

/***/ 89330:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  dc: () => (/* binding */ EXIT),
  Pk: () => (/* binding */ isRunId),
  RZ: () => (/* binding */ planRepair),
  cI: () => (/* binding */ readRun),
  AX: () => (/* binding */ requestCancel),
  Lq: () => (/* binding */ runRepair),
  AM: () => (/* binding */ runsDir),
  tE: () => (/* binding */ validatePolicy)
});

// UNUSED EXPORTS: DEFAULT_BUDGETS, PLAN_SCHEMA, POLICY_SCHEMA, resolveBudgets

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
// EXTERNAL MODULE: ./src/posture/assurance/config.js
var config = __webpack_require__(90385);
// EXTERNAL MODULE: ./src/posture/oracles/registry.js + 2 modules
var registry = __webpack_require__(18357);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
// EXTERNAL MODULE: ./src/repair/schemas.js
var schemas = __webpack_require__(68962);
// EXTERNAL MODULE: ./src/repair/contracts.js + 1 modules
var contracts = __webpack_require__(20771);
// EXTERNAL MODULE: ./src/posture/oracles/oracle.js
var oracle = __webpack_require__(15991);
;// CONCATENATED MODULE: ./src/repair/lab.js
// The repair lab (verified-remediation PRD FR-05, FR-06): one obligation, one exact file set, executed through the oracle runner and
// therefore through the trust boundary only (network denied, process tree ended, harness digest-checked, verdict formed verifier-side).
//
// This module adds no execution path of its own. It builds the oracle request from the contract's obligation, binds the request to the
// exact tree being judged (the digest of the file set stands in for a commit, so `confirmed`/`refuted` are reachable for an uncommitted
// candidate), and then checks the receipt it got back: issued in this process by the oracle runner (a copied or deserialized receipt is not),
// for these files, these inputs and the oracle logic the contract pinned. A mismatch is `invalid`, never a pass (AC-06.5).



const OUTCOME_TO_STATUS = Object.freeze({ confirmed: 'confirmed', refuted: 'refuted', inconclusive: 'inconclusive', unsupported: 'unavailable', 'not-run': 'unavailable', error: 'error' });

/** The 64-hex binding of a file set, used where the oracle asks for an exact commit. */
const treeBinding = (files) => (0,identity/* digestOf */.ol)(files).slice('sha256:'.length);

/**
 * @param {object} obligation  a contract obligation with an oracle (not `project-tests`)
 * @param {Record<string,string>} files  the application files, original or patched
 * @param {{config:object, signal?:AbortSignal, entry:string, hypothesisId:string, inputs?:object, deps?:object, probeEnv?:object, runOracle?:Function}} o  (`runOracle` is a test seam: a stand-in cannot issue a receipt this module accepts)
 * @returns {Promise<{observed:'confirmed'|'refuted'|'inconclusive'|'unavailable'|'error'|'invalid', reason:string, receipt:object|null, details:object|null, filesDigest:string, inputsDigest:string}>}
 */
async function runObligation(obligation, files, o) {
  const inputs = o.inputs || obligation.inputs;
  const filesDigest = (0,identity/* digestOf */.ol)(files);
  const inputsDigest = (0,identity/* digestOf */.ol)(inputs);
  const res = await (o.runOracle || oracle/* runOracle */.qm)({
    oracleId: obligation.oracleId, hypothesisId: o.hypothesisId, commit: treeBinding(files), files, entry: o.entry, inputs,
  }, { config: o.config, signal: o.signal, ...(o.deps ? { deps: o.deps } : {}), ...(o.probeEnv ? { probeEnv: o.probeEnv } : {}) });
  if (res.status === 'rejected') return { observed: 'invalid', reason: `the oracle refused the request: ${(res.errors || []).join('; ').slice(0, 300)}`, receipt: null, details: null, filesDigest, inputsDigest };
  const base = { filesDigest, inputsDigest, receipt: res.receipt || null };
  if (!res.receipt) return { ...base, observed: res.status === 'cancelled' ? 'cancelled' : (OUTCOME_TO_STATUS[res.outcome] || 'error'), reason: res.reason, details: null };
  const r = res.receipt;
  const bindingProblems = [];
  if (!(0,oracle/* isIssuedReceipt */.AH)(r)) bindingProblems.push('the receipt was not issued by the oracle runner in this process');
  if (r.request.filesDigest !== filesDigest) bindingProblems.push('the receipt is for different files');
  if (r.request.inputsDigest !== inputsDigest) bindingProblems.push('the receipt is for different inputs');
  if (r.oracle.logicDigest !== obligation.oracleLogicDigest) bindingProblems.push('the oracle logic differs from the logic the contract pinned (re-plan the contract)');
  if (bindingProblems.length) return { ...base, observed: 'invalid', reason: bindingProblems.join('; '), details: null };
  return { ...base, observed: OUTCOME_TO_STATUS[r.settled.outcome] || 'error', reason: res.reason, details: r.observed || null };
}

/** Did an observed outcome meet the obligation's expectation for this revision? passed | failed | inconclusive | unavailable | invalid | cancelled */
function judge(observed, expectation) {
  if (['unavailable', 'invalid', 'error', 'cancelled'].includes(observed)) return observed === 'error' ? 'inconclusive' : observed;
  if (observed === 'inconclusive') return 'inconclusive';
  return observed === expectation ? 'passed' : 'failed';
}

;// CONCATENATED MODULE: ./src/repair/counterexamples.js
// Counterexamples (verified-remediation PRD FR-07): validate the generated checks against the original, turn a failed check into a
// minimal, structured counterexample, and keep the sealed set out of the feedback loop.
//
//   validateAgainstOriginal  A control whose expectation the original does not meet is a wrong expectation: it is QUARANTINED with the
//                            reason and removed from the obligation the candidates are judged by (AC-07.3). An attack (or a generated
//                            state check) that reaches no forbidden effect on the ORIGINAL cannot show that a patch repaired anything,
//                            but it can show that a patch removed a protection the original already had: it stays in the obligation as
//                            a REGRESSION GUARD, recorded with its reason, and does not count toward the obligation being meaningful.
//                            (Until 0.198.0 these were quarantined, so a candidate deleting an existing check was judged only by the
//                            attacks the original failed.) Both lists are recorded, never silent.
//   counterexampleFrom       A failed development obligation becomes {obligation, request, actor, preconditions, effect}: the request
//                            the verifier saw violate, the actor's identity, and the authoritative assertion it broke. A failed SEALED
//                            obligation yields only "a sealed check failed": no request, value or outcome detail reaches generation
//                            (AC-07.5).
//   shrinkCounterexample     Character-level reduction of the attack value (query parameters and string body fields), batched: every
//                            one-deletion variant is a separate attack request in ONE oracle run, and the shortest variant that still
//                            discloses THE SAME secret (or breaks the same state check) is kept, so the failed property is preserved
//                            (AC-07.4). Bounded by rounds and by the per-run request ceiling.


const REQ_CAP = 120; // the application oracles accept at most 128 requests per run

const idOf = (r) => r.id;

/** The obligation's inputs with quarantined requests and checks removed. Pure. */
function withoutQuarantined(inputs, quarantined) {
  const q = new Set(quarantined.map((x) => x.id));
  return { ...inputs, requests: inputs.requests.filter((r) => !q.has(r.id)), stateChecks: (inputs.stateChecks || []).filter((c) => !q.has(c.id)) };
}

/**
 * Run each oracle obligation on the original and quarantine the checks that cannot be meaningful.
 * @returns {{baseline: object[], quarantined: object[], effectiveInputs: Record<string, object>}}
 */
async function validateAgainstOriginal(contract, originalFiles, run) {
  const baseline = []; const quarantined = []; const regressionGuards = []; const effectiveInputs = {};
  for (const ob of contract.obligations.filter((x) => x.oracleId)) {
    const res = await run(ob, originalFiles, ob.inputs);
    const d = res.details || {};
    const q = []; const g = [];
    if (ob.kind === 'app-attack-blocked' || ob.kind === 'app-attack-sealed') {
      const violated = new Set((d.attackViolations || []).map((v) => v.id));
      if (res.observed === 'confirmed' || res.observed === 'refuted') {
        const reqs = ob.inputs.requests;
        for (const r of reqs.filter((x) => x.role === 'attack' && (x.forbid?.secrets?.length || x.forbid?.connections))) {
          if (!violated.has(r.id)) g.push({ id: r.id, obligation: ob.id, reason: r.forbid?.connections ? 'the original revision already blocks this attack (no forbidden destination, no planted secret): kept as a regression guard, it cannot show a repair' : 'the original revision already blocks this attack (no planted secret disclosed): kept as a regression guard, it cannot show a repair' });
        }
        // A generated state check names the write attacks it guards: if the original does not break it, the check and those writes stay
        // as regression guards. Profile-declared state checks (no `guards`) are regression guards by declaration.
        for (const c of (ob.inputs.stateChecks || []).filter((x) => Array.isArray(x.guards))) {
          if (violated.has(c.id)) continue;
          g.push({ id: c.id, obligation: ob.id, reason: 'the original revision makes no unauthorized change this check can see: kept as a regression guard, it cannot show a repair' });
          for (const w of c.guards) g.push({ id: w, obligation: ob.id, reason: 'this write attack does not change durable state on the original revision: kept as a regression guard' });
        }
        for (const c of (d.controlFailures || [])) q.push({ id: c.id, obligation: ob.id, reason: `the original revision does not meet this control's expectation (${c.reason}); the expectation is wrong or the application needs setup the profile lacks` });
      }
    } else if (ob.kind === 'app-behaviour-preserved') {
      for (const c of (d.controlFailures || [])) q.push({ id: c.id, obligation: ob.id, reason: `the original revision does not meet this legitimate expectation (${c.reason}); mark it originalMishandles if the repair should fix it` });
    }
    const seen = new Set();
    const uniq = q.filter((x) => (seen.has(x.id) ? false : seen.add(x.id)));
    quarantined.push(...uniq);
    const gseen = new Set();
    regressionGuards.push(...g.filter((x) => !seen.has(x.id) && (gseen.has(x.id) ? false : gseen.add(x.id))));
    effectiveInputs[ob.id] = withoutQuarantined(ob.inputs, uniq);
    baseline.push({ obligation: ob.id, kind: ob.kind, observed: res.observed, expectation: ob.baselineExpectation, status: ob.baselineExpectation ? judge(res.observed, ob.baselineExpectation) : 'recorded', reason: res.reason });
  }
  return { baseline, quarantined, regressionGuards, effectiveInputs };
}

/** Structured feedback for the next proposal from one failed obligation run. */
function counterexampleFrom(ob, inputs, res, actorsByHeader) {
  if (ob.kind === 'app-attack-sealed') return { obligation: ob.id, sealed: true, message: 'a sealed held-out check failed; its content is not disclosed to candidate generation' };
  const d = res.details || {};
  const byId = Object.fromEntries(inputs.requests.map((r) => [r.id, r]));
  const actorOf = (r) => actorsByHeader?.(r?.headers) ?? null;
  if (ob.kind === 'app-attack-blocked') {
    const v = (d.attackViolations || [])[0];
    if (!v) return { obligation: ob.id, message: res.reason };
    const req = byId[v.id] || null;
    const check = (inputs.stateChecks || []).find((c) => c.id === v.id) || null;
    const writer = check && Array.isArray(check.guards) ? check.guards.map((g) => byId[g]).find(Boolean) || null : null;
    return {
      obligation: ob.id, property: v.effect === 'durable-state' ? 'unauthorized-durable-change' : v.effect === 'forbidden-connection' ? 'forbidden-connection' : 'secret-disclosed',
      ...(v.destinations ? { destinations: v.destinations } : {}),
      request: req ? { method: req.method, path: req.path, body: req.body ?? null } : writer ? { method: writer.method, path: writer.path, body: writer.body ?? null } : null,
      actor: actorOf(req || writer), secrets: v.secrets || [], stateCheck: check ? check.sql : null, guardedRequests: check?.guards?.length ?? 0,
      violations: (d.attackViolations || []).length, message: res.reason,
    };
  }
  const f = (d.controlFailures || [])[0];
  const req = f ? byId[f.id] : null;
  return { obligation: ob.id, property: 'legitimate-behaviour', request: req ? { method: req.method, path: req.path, body: req.body ?? null } : null, actor: actorOf(req), expected: req?.expect ?? null, message: f ? f.reason : res.reason };
}

function reductions(req) {
  const out = [];
  const url = new URL(req.path, 'http://x.local');
  for (const [k, v] of url.searchParams) {
    for (let i = 0; i < v.length; i++) {
      const u = new URL(url); u.searchParams.set(k, v.slice(0, i) + v.slice(i + 1));
      out.push({ ...req, path: u.pathname + u.search });
    }
  }
  if (req.body && typeof req.body === 'object') {
    for (const [k, v] of Object.entries(req.body)) if (typeof v === 'string') for (let i = 0; i < v.length; i++) out.push({ ...req, body: { ...req.body, [k]: v.slice(0, i) + v.slice(i + 1) } });
  }
  return out;
}

// Size of the attacker-controlled values, decoded: the URL API re-encodes characters differently from the request builder, so the
// encoded path length would make a shorter value look longer.
const sizeOf = (r) => {
  let n = 0;
  for (const [, v] of new URL(r.path, 'http://x.local').searchParams) n += v.length;
  if (r.body && typeof r.body === 'object') for (const v of Object.values(r.body)) if (typeof v === 'string') n += v.length;
  return n;
};

/**
 * Shrink one violating attack request while it still discloses the same secret(s). `run(ob, files, inputs)` is the lab runner.
 * @returns {Promise<{request:object, original:object, runs:number, preserved:boolean}>}
 */
async function shrinkCounterexample(ob, inputs, files, violatingId, run, { maxRounds = 6, ...o } = {}) {
  const controls = inputs.requests.filter((r) => r.role === 'control');
  let best = inputs.requests.find((r) => r.id === violatingId);
  const original = best;
  const secrets = new Set(best?.forbid?.secrets || []);
  const destinations = new Set((o.destinations || []).map((d) => d.address).filter(Boolean));
  let runs = 0;
  if (!best || (!secrets.size && !destinations.size)) return { request: best, original, runs, preserved: true };
  for (let round = 0; round < maxRounds; round++) {
    const cands = reductions(best).slice(0, REQ_CAP - controls.length).map((r, i) => ({ ...r, id: `shrink_${round}_${i}` }));
    if (!cands.length) break;
    const res = await run(ob, files, { ...inputs, requests: [...controls, ...cands], stateChecks: [] });
    runs++;
    // The same property: the same planted secret, or (a forbidden connection) the same forbidden address.
    const same = (v) => (secrets.size && o.effect !== 'forbidden-connection' ? (v.secrets || []).some((s) => secrets.has(s)) : (v.destinations || []).some((d) => destinations.has(d.address)));
    const hits = new Set((res.details?.attackViolations || []).filter(same).map(idOf));
    const next = cands.filter((c) => hits.has(c.id)).sort((a, b) => sizeOf(a) - sizeOf(b))[0];
    if (!next || sizeOf(next) >= sizeOf(best)) break;
    best = { ...next, id: original.id };
  }
  return { request: best, original, runs, preserved: true };
}



// EXTERNAL MODULE: ./src/repair/candidates.js
var candidates = __webpack_require__(4370);
;// CONCATENATED MODULE: ./src/repair/portfolio.js
// Candidate portfolios (verified-remediation PRD FR-09, M2-01, M2-02): structural deduplication, cross-execution and deterministic ranking.
//
//   structuralKey     Two candidates that differ only in whitespace and comments are the same strategy: the key is a digest of each
//                     changed file with comments and whitespace removed. A structural duplicate consumes an attempt and is not run.
//   crossInputs       Every counterexample any candidate of the round produced (a development attack that disclosed a secret or
//                     broke a state check) becomes an extra attack request for every OTHER surviving candidate. A candidate that
//                     passed its own run but fails a sibling's counterexample is rejected before ranking (T-26). Sealed failures are
//                     never shared: their content does not leave the coordinator.
//   rankSurvivors     Deterministic order over candidates that passed every development obligation and the cross-execution:
//                     fewer material-risk categories, fewer files, fewer edited lines, generator preference (deterministic recipe,
//                     then user-supplied, then model), then candidate id. No model-supplied score is read.


const stripComments = (t) => String(t)
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1')
  .replace(/(^|\n)\s*#[^\n]*/g, '$1');

function structuralKey(files) {
  const norm = {};
  for (const [rel, t] of Object.entries(files || {}).sort(([a], [b]) => a.localeCompare(b))) norm[rel] = t === null ? null : stripComments(t).replace(/\s+/g, '');
  return (0,identity/* digestOf */.ol)(norm);
}

const GENERATOR_ORDER = { 'deterministic-recipe': 0, 'user-supplied': 1, 'configured-model': 2 };

function rankSurvivors(survivors) {
  const key = (s) => [
    s.candidate.scope?.material?.categories?.length ?? 0,
    s.candidate.scope?.totals?.files ?? 99,
    s.candidate.scope?.totals?.editedLines ?? 1e9,
    GENERATOR_ORDER[s.candidate.generator] ?? 9,
  ];
  return [...survivors].sort((a, b) => {
    const ka = key(a); const kb = key(b);
    for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] - kb[i];
    return a.candidate.candidateId.localeCompare(b.candidate.candidateId);
  });
}

/**
 * The attack requests that disclosed a planted secret in a failed run, as shareable requests (`cross_<n>` ids). Only disclosure attacks are
 * shared: a durable-state attack is judged by an object-level check the sibling runs anyway. Content stays inside the coordinator.
 */
function sharedAttacksFrom(inputs, details, extra = []) {
  const byId = Object.fromEntries(inputs.requests.map((r) => [r.id, r]));
  const out = [];
  for (const v of details?.attackViolations || []) {
    if (v.effect !== 'secret-disclosed' && v.effect !== 'forbidden-connection') continue;
    const r = byId[v.id];
    if (r && r.role === 'attack') out.push(r);
  }
  for (const r of extra) if (r && r.role === 'attack' && (r.forbid?.secrets?.length || r.forbid?.connections)) out.push(r);
  return out;
}

/** Inputs carrying ONLY the controls and the shared attacks (deduplicated by request shape), for the cross-execution run. */
function crossInputs(inputs, shared) {
  const seen = new Set(); const attacks = [];
  for (const r of shared) {
    const k = (0,identity/* digestOf */.ol)({ m: r.method, p: r.path, b: r.body ?? null, h: r.headers ?? {} });
    if (seen.has(k)) continue;
    seen.add(k);
    attacks.push({ ...r, id: `cross_${attacks.length}` });
  }
  return { ...inputs, requests: [...inputs.requests.filter((r) => r.role === 'control'), ...attacks], stateChecks: [] };
}

;// CONCATENATED MODULE: ./src/repair/coordinator.js
// The repair coordinator (verified-remediation PRD section 5.2, FR-06, FR-07, FR-17): one state machine for every route (CLI, MCP,
// headless callers, batch), calling the existing canonical services and adding none of its own.
//
//   plan      contract from finding + profile + exact source (contracts.js). No execution.
//   run       baseline validation on the original (quarantine), then bounded rounds: proposals -> scope gate -> development obligations
//             -> counterexample (shrunk) fed to the next round -> central verifier (rescan, footprint, project test delta) -> sealed
//             obligations -> promotion. Every oracle run goes through the oracle runner and the trust boundary (lab.js).
//   apply     only on request, only for a verified-for-contract candidate, only through applyVerifiedFix (signed scan, confinement,
//             material-change approval, concurrent-modification check, transactional write). A source that drifted from the contract
//             is refused before that (T-13).
//
// Trust rules this module enforces:
//   - Promotion needs, for every required oracle obligation, a result produced in THIS process whose receipt the oracle runner issued
//     for exactly the promoted files and the contract's inputs and oracle logic. Persisted records carry receipt digests only; `resume`
//     re-executes every leg and never turns stored JSON back into evidence (AC-17.4, T-16).
//   - Execution is enabled only by the operator (the assurance config the caller passes); a missing backend or a disabled feature is
//     `blocked` with the next prerequisite, never a downgraded pass (AC-04.6, AC-05.6).
//   - Budgets are enforced here, outside candidate code: rounds, strategies per round, attack cases per candidate, the whole-run wall
//     deadline (an AbortSignal that reaches the oracle runner, which ends the process tree), and identical candidates consume an attempt
//     without being re-run (AC-07.6). A budget stop is `partial`, never a proof.
//   - Sealed obligations run only on a candidate that passed everything else; their outcome is recorded but never fed back.














const PLAN_SCHEMA = 'agentic-security/repair-plan';
const POLICY_SCHEMA = 'agentic-security/repair-policy';
const DEFAULT_BUDGETS = Object.freeze({ strategiesPerRound: 3, rounds: 3, attackCasesPerCandidate: 64, wallMs: 15 * 60_000, testCommandMs: 120_000, workers: 1 });
const BUDGET_CEILINGS = Object.freeze({ strategiesPerRound: 3, rounds: 3, attackCasesPerCandidate: 120, wallMs: 60 * 60_000, testCommandMs: 120_000, workers: 2 });
const EXIT = Object.freeze({ ok: 0, failed: 1, usage: 2, blocked: 3, cancelled: 4 });

const runsDir = (root) => external_node_path_.join((0,state_dir/* stateDir */.Pn)(root), 'repair', 'runs');
const RUN_ID_RE = /^rrun-[0-9a-f]{16}$/;
const isRunId = (s) => typeof s === 'string' && RUN_ID_RE.test(s);

// ---------------------------------------------------------------- policy and budgets

/** Budgets within their ceilings. An unknown key or an out-of-range value is an error, never clamped silently. */
function resolveBudgets(requested = {}) {
  const errors = []; const b = { ...DEFAULT_BUDGETS };
  for (const [k, v] of Object.entries(requested || {})) {
    if (!(k in DEFAULT_BUDGETS)) { errors.push(`unknown budget '${k}'`); continue; }
    if (!Number.isInteger(v) || v < 1 || v > BUDGET_CEILINGS[k]) { errors.push(`budget ${k} must be an integer from 1 to ${BUDGET_CEILINGS[k]}`); continue; }
    b[k] = v;
  }
  return { budgets: b, errors };
}

/** A repair policy: budgets and the model setting. It cannot enable execution: only the operator's assurance config can. */
function validatePolicy(p) {
  const errs = [];
  if (p === undefined || p === null) return { policy: { schema: POLICY_SCHEMA, schemaVersion: '1.0.0', budgets: {}, model: 'none' }, errors: [] };
  if (typeof p !== 'object' || Array.isArray(p)) return { policy: null, errors: ['the policy must be a JSON object'] };
  for (const k of Object.keys(p)) if (!['schema', 'schemaVersion', 'budgets', 'model'].includes(k)) errs.push(`policy: unknown field '${k}'`);
  if (p.schema !== POLICY_SCHEMA) errs.push(`policy.schema must be '${POLICY_SCHEMA}'`);
  if (p.model !== undefined && p.model !== 'none') errs.push("policy.model: only 'none' is supported in this milestone (no model proposer is wired; a local-only policy never becomes a remote call)");
  const { errors } = resolveBudgets(p.budgets);
  return { policy: errs.length || errors.length ? null : { budgets: {}, model: 'none', ...p }, errors: [...errs, ...errors] };
}

// ---------------------------------------------------------------- plan

/**
 * @param {{root:string, finding:object, family:string, profile:object, profileOrigin:string, commit?:string|null}} o
 */
function planRepair(o) {
  const source = (0,contracts.snapshotSource)(o.root, o.profile);
  const built = (0,contracts/* buildContract */.$B)({ finding: o.finding, profile: o.profile, profileOrigin: o.profileOrigin, source, commit: o.commit ?? null, family: o.family });
  if (!built.contract) return { plan: null, blocked: built.blocked, problems: built.problems };
  const plan = {
    schema: PLAN_SCHEMA, schemaVersion: '1.0.0', contract: built.contract, finding: o.finding,
    blocked: built.blocked, entry: o.profile.application.entry, tests: o.profile.tests || null,
    actors: o.profile.actors.map((a) => ({ id: a.id, headersDigest: (0,identity/* digestOf */.ol)(a.headers || {}) })),
  };
  return { plan, blocked: built.blocked, problems: [] };
}

// ---------------------------------------------------------------- persistence

function writeJson(file, value) {
  external_node_fs_.mkdirSync(external_node_path_.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  external_node_fs_.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  external_node_fs_.renameSync(tmp, file);
}

function readRun(root, runId) {
  if (!isRunId(runId)) return { error: 'not a repair run id' };
  const dir = external_node_path_.join(runsDir(root), runId);
  try {
    const record = JSON.parse(external_node_fs_.readFileSync(external_node_path_.join(dir, 'record.json'), 'utf8'));
    const plan = JSON.parse(external_node_fs_.readFileSync(external_node_path_.join(dir, 'plan.json'), 'utf8'));
    const v = (0,schemas/* validateRepairRecord */.bY)(record);
    return { dir, record, plan, valid: v.ok, problems: v.ok ? [] : v.errors.map((e) => `${e.path}: ${e.message}`) };
  } catch (e) { return { error: `the run could not be read: ${String(e.message).slice(0, 160)}` }; }
}

/** Ask a running repair (in any process) to stop. It notices within a fraction of a second and records `cancelled`. */
function requestCancel(root, runId) {
  if (!isRunId(runId)) return { ok: false, reason: 'not a repair run id' };
  const dir = external_node_path_.join(runsDir(root), runId);
  try { JSON.parse(external_node_fs_.readFileSync(external_node_path_.join(dir, 'record.json'), 'utf8')); } catch { return { ok: false, reason: 'no such run' }; }
  external_node_fs_.writeFileSync(external_node_path_.join(dir, 'cancel'), new Date().toISOString());
  return { ok: true };
}

// ---------------------------------------------------------------- run

const actorLookup = (profileActors) => (headers) => {
  const d = (0,identity/* digestOf */.ol)(headers || {});
  return profileActors.find((a) => a.headersDigest === d)?.id ?? null;
};

function baseRecord(runId, plan) {
  const c = plan.contract;
  return {
    schema: schemas/* SCHEMAS */.H6.record, schemaVersion: schemas/* SCHEMA_VERSION */.f$, runId, contractId: c.contractId, contractDigest: c.contractDigest,
    findingRefs: c.findingRefs, sourceDigest: c.sourceDigest,
    disposition: 'proposed', application: 'not-applied', artifact: 'source-only', environment: 'not-checked', completion: 'partial',
    candidates: [], selected: null, rounds: 0, obligationResults: [], counterexamples: [], quarantined: [], regressionGuards: [],
    budget: null, accounting: { oracleRuns: 0, wallMs: 0, modelTokens: null, modelCalls: 0, usd: null }, reasons: [], nextPrerequisite: null,
    scope: `contract ${c.contractId} (${c.family}): ${c.obligations.length} obligations over ${c.editScope.allowed.length} application file(s); source-only, nothing built or deployed`,
    createdAt: new Date().toISOString(),
  };
}

/**
 * @param {{root:string, plan:object, policy?:object, config:object, proposers:object[], signal?:AbortSignal, runId?:string,
 *   apply?:{approval?:object}|null, deps?:{verifyPatch?:Function, applyVerifiedFix?:Function, runOracleDeps?:object, probeEnv?:object},
 *   onEvent?:(e:object)=>void, resumedFrom?:string}} o
 * @returns {Promise<{record:object, exitCode:number, runId:string, dir:string}>}
 */
async function runRepair(o) {
  const started = Date.now();
  const plan = o.plan;
  const runId = o.runId || `rrun-${external_node_crypto_.randomBytes(8).toString('hex')}`;
  const dir = external_node_path_.join(runsDir(o.root), runId);
  const record = baseRecord(runId, plan);
  const emit = (e) => { try { o.onEvent?.(e); } catch { /* observer errors never change the run */ } try { external_node_fs_.appendFileSync(external_node_path_.join(dir, 'events.jsonl'), JSON.stringify({ t: Date.now() - started, ...e }) + '\n'); } catch { /* best effort */ } };
  const { policy, errors: policyErrors } = validatePolicy(o.policy);
  if (o.resumedFrom) record.reasons.push(`resumed from ${o.resumedFrom}: every verification leg re-executed in this process`);
  writeJson(external_node_path_.join(dir, 'plan.json'), plan);
  const finish = (disposition, completion, exitCode, extra = {}) => {
    Object.assign(record, { disposition, completion, ...extra });
    record.accounting.wallMs = Date.now() - started;
    record.policyDigest = (0,identity/* digestOf */.ol)(policy || o.policy || null);
    const v = (0,schemas/* validateRepairRecord */.bY)(record);
    if (!v.ok) { record.disposition = 'blocked'; record.completion = 'invalid'; record.reasons.push(`the record failed its own schema: ${v.errors.map((e) => e.message).join('; ').slice(0, 300)}`); exitCode = EXIT.blocked; }
    writeJson(external_node_path_.join(dir, 'record.json'), record);
    emit({ kind: 'finished', disposition: record.disposition, completion: record.completion });
    return { record, exitCode, runId, dir };
  };
  writeJson(external_node_path_.join(dir, 'record.json'), record);
  if (policy) writeJson(external_node_path_.join(dir, 'policy.json'), policy);
  if (!policy) return finish('blocked', 'invalid', EXIT.usage, { reasons: policyErrors });
  const budgets = resolveBudgets(policy.budgets).budgets;
  record.budget = { ...budgets, used: { rounds: 0, proposals: 0, oracleRuns: 0 } };

  // 1. the contract still describes this source, and its oracle logic is still the registered logic
  const cv = (0,schemas/* validateContract */.T7)(plan.contract);
  if (!cv.ok) return finish('blocked', 'invalid', EXIT.usage, { reasons: cv.errors.map((e) => `${e.path}: ${e.message}`) });
  for (const ob of plan.contract.obligations.filter((x) => x.oracleId)) {
    if ((0,registry.getOracle)(ob.oracleId)?.logicDigest !== ob.oracleLogicDigest) return finish('blocked', 'invalid', EXIT.blocked, { reasons: [`obligation ${ob.id}: the oracle logic changed since the contract was planned`], nextPrerequisite: 'repair plan (re-plan the contract against the current verifier)' });
  }
  const profileStub = { application: plan.contract.profile.application };
  const now = (0,contracts.snapshotSource)(o.root, profileStub);
  if (now.sourceDigest !== plan.contract.sourceDigest) return finish('blocked', 'invalid', EXIT.blocked, { reasons: ['the application source changed since the contract was planned; its evidence would not describe this code'], nextPrerequisite: 'repair plan (re-plan against the current source)' });
  if (plan.blocked?.length) return finish('blocked', 'unavailable', EXIT.blocked, { reasons: plan.blocked, nextPrerequisite: 'complete the application profile' });
  const gate = (0,config/* featureStatus */.FX)(o.config, 'verification-oracles');
  if (gate.status !== 'ok') return finish('blocked', 'unavailable', EXIT.blocked, { reasons: [`execution is not enabled: ${gate.reason}`], nextPrerequisite: 'repair run --allow-execution (the operator enables sandboxed execution; a repository file cannot)' });

  // 2. cancellation and the wall deadline reach the oracle runner through one signal
  const ctl = new AbortController();
  const stop = (why) => { if (!ctl.signal.aborted) { record.reasons.push(why); ctl.abort(); } };
  o.signal?.addEventListener('abort', () => stop('cancelled by the caller'), { once: true });
  const timer = setTimeout(() => stop(`the whole-run wall budget of ${budgets.wallMs} ms ran out`), budgets.wallMs);
  const poll = setInterval(() => { if (external_node_fs_.existsSync(external_node_path_.join(dir, 'cancel'))) stop('cancelled by request'); }, 150);
  const cleanup = () => { clearTimeout(timer); clearInterval(poll); };
  const stopped = () => ctl.signal.aborted;
  const stoppedResult = () => { cleanup(); const byBudget = record.reasons.some((r) => r.includes('wall budget')); return finish(byBudget ? 'blocked' : 'cancelled', byBudget ? 'partial' : 'cancelled', EXIT.cancelled, { nextPrerequisite: `repair resume ${runId}` }); };

  const original = now.files;
  const entry = plan.entry;
  const run = async (ob, files, inputs) => {
    record.budget.used.oracleRuns++; record.accounting.oracleRuns++;
    return runObligation(ob, files, { config: o.config, signal: ctl.signal, entry, hypothesisId: `${plan.contract.contractId}:${ob.id}`, inputs, deps: o.deps?.runOracleDeps, probeEnv: o.deps?.probeEnv, runOracle: o.deps?.runOracle });
  };

  try {
    // 3. baseline: every generated check must mean something on the original
    emit({ kind: 'baseline' });
    const base = await validateAgainstOriginal(plan.contract, original, run);
    if (stopped()) return stoppedResult();
    record.quarantined = base.quarantined;
    record.regressionGuards = base.regressionGuards;
    record.obligationResults.push(...base.baseline.map((b) => ({ ...b, revision: 'original', required: false })));
    const unavailable = base.baseline.filter((b) => ['unavailable', 'invalid'].includes(b.observed));
    if (unavailable.length) { cleanup(); return finish('blocked', 'unavailable', EXIT.blocked, { reasons: unavailable.map((b) => `${b.obligation} on the original: ${b.reason}`), nextPrerequisite: 'a working confinement backend and node:sqlite on this host' }); }
    const attackObs = plan.contract.obligations.filter((x) => x.kind === 'app-attack-blocked');
    const reproduced = base.baseline.filter((b) => b.kind === 'app-attack-blocked' && b.observed === 'confirmed');
    const behaviourOk = base.baseline.filter((b) => b.kind === 'app-behaviour-preserved').every((b) => b.observed === 'refuted' || base.effectiveInputs[b.obligation].requests.length > 0);
    if (!reproduced.length) {
      cleanup();
      const refuted = base.baseline.filter((b) => b.kind === 'app-attack-blocked').every((b) => b.observed === 'refuted');
      if (refuted && behaviourOk) return finish('refuted-finding', 'complete', EXIT.ok, { reasons: ['no declared attack reaches a forbidden effect on the original revision while its legitimate requests work: the finding is not reproduced for this contract, and no patch is proposed'] });
      return finish('needs-review', 'partial', EXIT.blocked, { reasons: base.baseline.filter((b) => b.kind === 'app-attack-blocked').map((b) => `${b.obligation} on the original: ${b.reason}`), nextPrerequisite: 'a profile under which the original revision reproduces the finding and serves its legitimate requests' });
    }
    for (const ob of plan.contract.obligations.filter((x) => x.oracleId)) {
      const eff = base.effectiveInputs[ob.id];
      // Regression guards stay in the obligation but cannot show a repair: an attack obligation needs at least one check the original fails.
      const guard = new Set(base.regressionGuards.filter((x) => x.obligation === ob.id).map((x) => x.id));
      const meaningful = ob.kind.startsWith('app-attack') ? eff.requests.some((r) => r.role === 'attack' && !guard.has(r.id)) || (eff.stateChecks || []).some((c) => !guard.has(c.id)) : eff.requests.length;
      if (!meaningful) { cleanup(); return finish('needs-review', 'partial', EXIT.blocked, { reasons: [`required obligation ${ob.id} has no check left that is meaningful on the original revision (every attack is already blocked there, or quarantined)`], nextPrerequisite: 'review the quarantined checks, the regression guards and the profile' }); }
    }

    // attack-case budget per candidate
    const capped = {};
    for (const ob of plan.contract.obligations.filter((x) => x.oracleId)) {
      const eff = base.effectiveInputs[ob.id];
      const attacks = eff.requests.filter((r) => r.role === 'attack');
      if (attacks.length > budgets.attackCasesPerCandidate) {
        const keep = new Set(attacks.slice(0, budgets.attackCasesPerCandidate).map((r) => r.id));
        capped[ob.id] = attacks.length - keep.size;
        base.effectiveInputs[ob.id] = { ...eff, requests: eff.requests.filter((r) => r.role !== 'attack' || keep.has(r.id)) };
      }
    }
    if (Object.keys(capped).length) record.reasons.push(`attack cases over the per-candidate budget were omitted: ${Object.entries(capped).map(([k, n]) => `${k} ${n}`).join(', ')}; the verification is partial for those cases`);

    // 4. rounds. Each round is a portfolio (FR-09): every proposal is judged on the development obligations; counterexamples one
    // candidate produced are run against every other survivor (cross-execution, T-26); the survivors are ranked deterministically and
    // the sealed set runs in rank order on exactly one candidate at a time. Structural duplicates consume an attempt without running.
    const order = { 'app-behaviour-preserved': 0, 'app-behaviour-after': 1, 'app-attack-blocked': 2 };
    const devObs = plan.contract.obligations.filter((x) => x.oracleId && x.kind !== 'app-attack-sealed').sort((a, b) => order[a.kind] - order[b.kind]);
    const sealedObs = plan.contract.obligations.filter((x) => x.kind === 'app-attack-sealed');
    const attackOb = devObs.find((x) => x.kind === 'app-attack-blocked');
    const seen = new Set(); const seenStructure = new Set();
    let feedback = null; let selected = null; let anyInconclusive = false; let anyProposal = false;
    const resultOf = (ob, res, status, reason) => ({ obligation: ob.id, kind: ob.kind, observed: res.observed, status, reason: reason ?? res.reason, receiptDigest: res.receipt?.receiptDigest ?? null, filesDigest: res.filesDigest, inputsDigest: res.inputsDigest, live: res.receipt });
    for (let round = 1; round <= budgets.rounds && !selected; round++) {
      record.rounds = round; record.budget.used.rounds = round;
      const proposals = [];
      for (const p of o.proposers) {
        if (proposals.length >= budgets.strategiesPerRound) break;
        let got;
        try { got = await p.propose({ contract: plan.contract, files: original, round, feedback, max: budgets.strategiesPerRound - proposals.length }); }
        catch (e) { record.reasons.push(`proposer ${p.id} failed: ${String(e?.message || e).slice(0, 160)}`); continue; }
        for (const n of got.notes || []) record.reasons.push(`proposer ${p.id}: ${n}`);
        proposals.push(...(got.proposals || []).slice(0, budgets.strategiesPerRound - proposals.length));
      }
      if (!proposals.length) break;
      anyProposal = true;
      const survivors = []; const shared = []; const roundFeedback = [];
      // 4a. development obligations, every proposal
      for (const prop of proposals) {
        if (stopped()) return stoppedResult();
        record.budget.used.proposals++;
        const chk = (0,candidates/* checkCandidate */.We)(plan.contract, original, prop.files);
        const summary = { round, generator: prop.generator, generatorIdentity: prop.generatorIdentity, strategy: prop.strategy || null };
        if (!chk.ok) { record.candidates.push({ ...summary, status: 'refused', reasons: chk.reasons, scope: chk.scope.totals }); roundFeedback.push({ refused: chk.reasons }); emit({ kind: 'candidate-refused', reasons: chk.reasons }); continue; }
        const made = (0,candidates/* makeCandidate */.El)(plan.contract, original, prop, chk);
        if (!made.candidate) { record.candidates.push({ ...summary, status: 'refused', reasons: made.problems }); continue; }
        const cand = made.candidate;
        if (seen.has(cand.patchDigest)) { record.candidates.push({ ...summary, candidateId: cand.candidateId, patchDigest: cand.patchDigest, status: 'duplicate', reasons: ['an identical patch was already judged; it consumes an attempt and is not run again'] }); continue; }
        const skey = structuralKey(cand.files);
        if (seenStructure.has(skey)) { seen.add(cand.patchDigest); record.candidates.push({ ...summary, candidateId: cand.candidateId, patchDigest: cand.patchDigest, status: 'duplicate', reasons: ['structurally identical to a patch already judged (differs only in whitespace or comments); it consumes an attempt and is not run again'] }); continue; }
        seen.add(cand.patchDigest); seenStructure.add(skey);
        writeJson(external_node_path_.join(dir, 'candidates', `${cand.candidateId.replace(':', '-')}.json`), cand);
        const patched = { ...original };
        for (const [rel, t] of Object.entries(cand.files)) { if (t === null) delete patched[rel]; else patched[rel] = t; }
        const cs = { ...summary, candidateId: cand.candidateId, patchDigest: cand.patchDigest, structuralKey: skey, scope: cand.scope, status: 'pending', results: [] };
        record.candidates.push(cs);
        emit({ kind: 'candidate', candidateId: cand.candidateId, round });
        const t0 = Date.now();
        // Every development obligation runs, so the record attributes every failure; the counterexample fed back is the first security
        // failure, else the first behaviour failure.
        let verdict = 'passed'; const failures = [];
        for (const ob of devObs) {
          const inputs = base.effectiveInputs[ob.id];
          const res = await run(ob, patched, inputs);
          if (stopped()) return stoppedResult();
          const status = judge(res.observed, ob.patchedExpectation);
          cs.results.push(resultOf(ob, res, status));
          if (status === 'failed') failures.push({ ob, inputs, res });
          else if (status !== 'passed' && verdict === 'passed') verdict = status === 'cancelled' ? 'cancelled' : 'inconclusive';
        }
        if (failures.length) {
          verdict = 'failed';
          const { ob, inputs, res } = failures.find((f) => f.ob.kind === 'app-attack-blocked') || failures[0];
          let cx = counterexampleFrom(ob, inputs, res, actorLookup(plan.actors));
          const firstSecret = (res.details?.attackViolations || []).find((v) => v.effect === 'secret-disclosed' || v.effect === 'forbidden-connection');
          let shrunk = null;
          if (firstSecret && ob.kind === 'app-attack-blocked') {
            const sh = await shrinkCounterexample(ob, inputs, patched, firstSecret.id, run, { maxRounds: 4, effect: firstSecret.effect, destinations: firstSecret.destinations });
            if (stopped()) return stoppedResult();
            shrunk = sh.request;
            cx = { ...cx, request: { method: sh.request.method, path: sh.request.path, body: sh.request.body ?? null }, shrunkFrom: { method: sh.original.method, path: sh.original.path, body: sh.original.body ?? null }, shrinkRuns: sh.runs, propertyPreserved: sh.preserved };
          }
          cx.alsoFailed = failures.filter((f) => f.ob.id !== ob.id).map((f) => f.ob.id);
          record.counterexamples.push({ candidateId: cand.candidateId, ...cx });
          roundFeedback.push({ candidateId: cand.candidateId, counterexample: cx });
          for (const f of failures.filter((x) => x.ob.kind === 'app-attack-blocked')) shared.push(...sharedAttacksFrom(f.inputs, f.res.details, shrunk ? [shrunk] : []));
        }
        cs.wallMs = Date.now() - t0;
        if (verdict === 'inconclusive') anyInconclusive = true;
        if (verdict === 'passed') survivors.push({ cand, cs, patched });
        else cs.status = verdict === 'failed' ? 'rejected' : verdict;
      }
      // 4b. cross-execution: a survivor must also withstand every counterexample its siblings produced this round
      if (shared.length && attackOb && survivors.length) {
        const cin = crossInputs(base.effectiveInputs[attackOb.id], shared);
        for (const s of [...survivors]) {
          const res = await run(attackOb, s.patched, cin);
          if (stopped()) return stoppedResult();
          const status = judge(res.observed, attackOb.patchedExpectation);
          s.cs.crossExecution = { attacks: cin.requests.filter((r) => r.role === 'attack').length, status, reason: res.reason };
          if (status !== 'passed') {
            s.cs.status = status === 'failed' ? 'rejected' : 'inconclusive';
            if (status === 'failed') record.counterexamples.push({ candidateId: s.cand.candidateId, obligation: `${attackOb.id} (cross-execution)`, property: 'secret-disclosed', message: 'a counterexample found against a sibling candidate in this round also defeats this one' });
            else anyInconclusive = true;
            survivors.splice(survivors.indexOf(s), 1);
          }
        }
      }
      // 4c. rank, then the central verifier and the sealed set in rank order
      const ranked = rankSurvivors(survivors.map((s) => ({ ...s, candidate: s.cand })));
      ranked.forEach((s, i) => { s.cs.rank = i + 1; });
      for (const s of ranked) {
        if (selected) { s.cs.status = 'passed-not-selected'; continue; }
        const { cand, cs, patched } = s;
        let verdict = 'passed';
        const central = await centralVerify(o, plan, cand, budgets);
        cs.results.push(central);
        if (central.status !== 'passed') { verdict = central.status === 'failed' ? 'failed' : 'inconclusive'; if (central.status === 'failed') { record.counterexamples.push({ candidateId: cand.candidateId, obligation: 'central-verifier', property: 'central-verifier', message: central.reason }); roundFeedback.push({ candidateId: cand.candidateId, counterexample: { obligation: 'central-verifier', message: central.reason } }); } }
        if (verdict === 'passed') {
          for (const ob of sealedObs) {
            const res = await run(ob, patched, base.effectiveInputs[ob.id]);
            if (stopped()) return stoppedResult();
            const status = judge(res.observed, ob.patchedExpectation);
            cs.results.push(resultOf(ob, res, status, status === 'failed' ? 'a sealed held-out check failed' : undefined));
            if (status !== 'passed') { verdict = status === 'failed' ? 'failed' : 'inconclusive'; if (status === 'failed') { record.counterexamples.push({ candidateId: cand.candidateId, obligation: ob.id, sealed: true, message: 'a sealed held-out check failed; its content is not disclosed to candidate generation' }); roundFeedback.push({ candidateId: cand.candidateId, counterexample: { obligation: ob.id, sealed: true, message: 'a sealed held-out check failed' } }); } break; }
          }
        }
        if (verdict === 'inconclusive') anyInconclusive = true;
        if (verdict === 'passed' && promotable(plan.contract, cs, patched)) { cs.status = 'verified-for-contract'; selected = { cand, cs }; continue; }
        cs.status = verdict === 'passed' ? 'inconclusive' : verdict === 'failed' ? 'rejected' : verdict;
      }
      feedback = roundFeedback.length ? { round, items: roundFeedback, ...roundFeedback[roundFeedback.length - 1] } : feedback;
    }
    cleanup();
    for (const c of record.candidates) for (const r of c.results || []) delete r.live;
    if (!anyProposal) return finish('blocked', 'unavailable', EXIT.blocked, { reasons: [...record.reasons, 'no candidate generator produced a proposal'], nextPrerequisite: 'supply candidates (--candidates <file.json>) or a family with a deterministic recipe' });
    if (!selected) {
      const exhausted = record.rounds >= budgets.rounds;
      return finish(anyInconclusive ? 'needs-review' : 'rejected', exhausted ? 'partial' : 'complete', anyInconclusive ? EXIT.blocked : EXIT.failed, { reasons: [...record.reasons, exhausted ? `no candidate satisfied every required obligation within ${budgets.rounds} round(s); this is a budget stop, not a proof that no repair exists` : 'no candidate satisfied every required obligation'] });
    }
    record.selected = selected.cand.candidateId;
    record.patchDigest = selected.cand.patchDigest;
    record.exactPatch = { files: selected.cand.files, beforeDigests: selected.cand.beforeDigests, afterDigests: selected.cand.afterDigests };
    record.obligationResults.push(...selected.cs.results.map((r) => ({ obligation: r.obligation, kind: r.kind, revision: 'patched', required: true, status: r.status, observed: r.observed, receiptDigest: r.receiptDigest ?? null, reason: r.reason })));
    record.legacy = { ok: true, verified: true, fixCompleteness: selected.cs.results.find((r) => r.obligation === 'central-verifier')?.fixCompleteness ?? null, note: 'FULL in the legacy fields means the named contract passed, not universal correctness' };
    // 5. application, only on request and only through the canonical service
    if (o.apply) {
      const drift = (0,contracts.snapshotSource)(o.root, profileStub);
      if (drift.sourceDigest !== plan.contract.sourceDigest) return finish('verified-for-contract', 'complete', EXIT.blocked, { application: 'concurrent-change-refused', reasons: [...record.reasons, 'the source changed after verification; the verified patch was not applied'] });
      const apply = o.deps?.applyVerifiedFix || (await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 97730))).applyVerifiedFix;
      const a = await apply({ scanRoot: o.root, finding: { ...plan.finding, stableId: plan.finding.stableId || plan.contract.findingRefs[0], id: plan.finding.id || plan.contract.findingRefs[0] }, files: selected.cand.files, fixMeta: { approval: o.apply.approval || undefined, repairContract: plan.contract.contractId } });
      if (!a.applied) return finish('verified-for-contract', 'complete', EXIT.blocked, { application: a.reason && /changed on disk/.test(a.reason) ? 'concurrent-change-refused' : 'not-applied', reasons: [...record.reasons, `not applied: ${a.reason}`] });
      return finish('verified-for-contract', 'complete', EXIT.ok, { application: 'applied' });
    }
    return finish('verified-for-contract', 'complete', EXIT.ok);
  } catch (e) {
    cleanup();
    return finish('blocked', 'invalid', EXIT.blocked, { reasons: [...record.reasons, `the coordinator failed: ${String(e?.message || e).slice(0, 200)}`] });
  }
}

/** Every required oracle obligation passed on exactly these files, with a live receipt bound to them. */
function promotable(contract, cs, patched) {
  const fd = (0,identity/* digestOf */.ol)(patched);
  for (const ob of contract.obligations.filter((x) => x.required)) {
    const r = cs.results.find((x) => x.obligation === ob.id);
    if (!r || r.status !== 'passed') return false;
    if (ob.oracleId && (!r.live || r.filesDigest !== fd || r.live.request.filesDigest !== fd)) return false;
  }
  return true;
}

/** The project-tests obligation: the central verifier (verify-patch.js) on the exact candidate. */
async function centralVerify(o, plan, cand, budgets) {
  const verify = o.deps?.verifyPatch || (await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 2046))).verifyPatch;
  const finding = { id: plan.finding.id || plan.contract.findingRefs[0], stableId: plan.finding.stableId || plan.contract.findingRefs[0] };
  try {
    const files = Object.fromEntries(Object.entries(cand.files).filter(([, t]) => t !== null));
    const r = await verify({ scanRoot: o.root, finding, files, route: 'repair', mode: 'verify', testCommand: plan.tests?.command, testTimeoutMs: budgets.testCommandMs, requiredTests: plan.tests?.required || [], flakyTests: plan.tests?.flaky || [] });
    const legs = Object.fromEntries(['securityAfter', 'newFindingDelta', 'behaviorTests', 'behaviorPreservation'].map((k) => [k, r.fixVerification?.[k]?.status ?? null]));
    const ok = r.verdict?.ok === true && r.canonical?.ok === true;
    return { obligation: 'central-verifier', kind: 'project-tests', observed: ok ? 'passed' : 'failed', status: ok ? 'passed' : 'failed', reason: ok ? 'rescan, new-finding delta, footprint and test legs passed or were recorded as not run' : String(r.verdict?.summary || 'a central verification leg failed').slice(0, 400), legs, fixCompleteness: r.fixVerification?.fixCompleteness ?? null };
  } catch (e) {
    return { obligation: 'central-verifier', kind: 'project-tests', observed: 'error', status: 'inconclusive', reason: `the central verifier failed: ${String(e?.message || e).slice(0, 200)}` };
  }
}


/***/ }),

/***/ 30356:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Zn: () => (/* binding */ planFromInputs)
/* harmony export */ });
/* unused harmony exports familyForFinding, FAMILIES_SUPPORTED, signedFinding, insideRoot */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(31174);
/* harmony import */ var _posture_integrity_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(71130);
/* harmony import */ var _schemas_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(68962);
/* harmony import */ var _coordinator_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(89330);
// Plan inputs, resolved ONE way for every route (verified-remediation PRD AC-04.5): the CLI's `repair plan` and the MCP tool
// `repair_plan` both call `planFromInputs`, so the same finding, profile and source give the same contract and obligations.
//
// The finding comes from the SIGNED scan state only (an unsigned or tampered scan supplies nothing), or is declared by the operator
// with a family and a file, in which case its custody is `unresolved` and it says so. A profile file that resolves inside the
// repository is repository-supplied: its facts are `declared`, never `approved`.







const FAMILY_BY_CWE = { 'CWE-89': 'sql-injection', 'CWE-639': 'object-authorization', 'CWE-284': 'object-authorization', 'CWE-285': 'object-authorization', 'CWE-862': 'object-authorization', 'CWE-863': 'object-authorization', 'CWE-918': 'ssrf', 'CWE-22': 'path-traversal', 'CWE-23': 'path-traversal', 'CWE-36': 'path-traversal', 'CWE-73': 'path-traversal' };
const familyForFinding = (f) => FAMILY_BY_CWE[String(f?.cwe || '').toUpperCase().replace(/^(\d)/, 'CWE-$1')] || null;
const FAMILIES_SUPPORTED = Object.freeze(['sql-injection', 'object-authorization', 'ssrf', 'path-traversal']);

function signedFinding(root, id) {
  const file = node_path__WEBPACK_IMPORTED_MODULE_1__.join((0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .stateDir */ .Pn)(root), 'last-scan.json');
  let body;
  try { body = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8'); } catch { return { finding: null, reason: 'no scan state (run a scan first, or declare the family and file)' }; }
  if ((0,_posture_integrity_js__WEBPACK_IMPORTED_MODULE_3__/* .verifyLastScan */ .Ef)(body, `${file}.sig`) !== true) return { finding: null, reason: 'the scan state signature does not verify' };
  const scan = JSON.parse(body);
  const f = (scan.findings || []).find((x) => x.stableId === id || x.id === id);
  return f ? { finding: f, commit: scan.git?.commit || scan.commit || null } : { finding: null, reason: `finding ${id} is not in the signed scan` };
}

/** Is `p` inside `root` after resolving links? Unknown counts as inside (the weaker trust). */
function insideRoot(root, p) {
  try { const r = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(root); const f = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(p); return f === r || f.startsWith(r + node_path__WEBPACK_IMPORTED_MODULE_1__.sep); } catch { return true; }
}

/**
 * @param {{root:string, profilePath:string, findingId?:string, family?:string, file?:string}} o
 * @returns {{plan:object|null, blocked:string[], problems:string[], status:'ok'|'usage'|'blocked'}}
 */
function planFromInputs(o) {
  let profile;
  try { profile = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(o.profilePath, 'utf8')); } catch (e) { return { plan: null, blocked: [], problems: [`the profile could not be read: ${String(e.message).slice(0, 160)}`], status: 'usage' }; }
  if (o.family && !FAMILIES_SUPPORTED.includes(o.family)) return { plan: null, blocked: [], problems: [`family must be one of ${FAMILIES_SUPPORTED.join(', ')}`], status: 'usage' };
  let finding; let commit = null; let family = o.family || null;
  if (o.findingId) {
    const s = signedFinding(o.root, String(o.findingId));
    if (!s.finding) return { plan: null, blocked: [s.reason], problems: [], status: 'blocked' };
    finding = { ...(0,_schemas_js__WEBPACK_IMPORTED_MODULE_4__/* .normalizeFinding */ .vb)(s.finding, { commit: s.commit }), stableId: s.finding.stableId, id: s.finding.id };
    family = family || familyForFinding(s.finding);
    commit = typeof s.commit === 'string' && /^[0-9a-f]{40}$/.test(s.commit) ? s.commit : null;
  } else if (o.family && o.file) {
    finding = { ...(0,_schemas_js__WEBPACK_IMPORTED_MODULE_4__/* .normalizeFinding */ .vb)({ file: String(o.file), id: `declared:${o.family}:${o.file}` }, { custody: 'unresolved' }), declaredBy: 'operator' };
  } else return { plan: null, blocked: [], problems: ['name a finding id, or a family and a file for a finding the scanner did not report'], status: 'usage' };
  if (!family) return { plan: null, blocked: [`the finding has no repair family in this milestone; name one of ${FAMILIES_SUPPORTED.join(', ')}`], problems: [], status: 'blocked' };
  const origin = insideRoot(o.root, o.profilePath) ? 'repository-file' : 'operator-profile-outside-repository';
  const r = (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_5__/* .planRepair */ .RZ)({ root: o.root, finding, family, profile, profileOrigin: origin, commit });
  if (!r.plan) return { plan: null, blocked: r.blocked, problems: r.problems, status: r.problems.length ? 'usage' : 'blocked' };
  return { plan: r.plan, blocked: r.blocked, problems: [], status: r.blocked.length ? 'blocked' : 'ok' };
}


/***/ }),

/***/ 68962:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   H6: () => (/* binding */ SCHEMAS),
/* harmony export */   JF: () => (/* binding */ contractIdOf),
/* harmony export */   T7: () => (/* binding */ validateContract),
/* harmony export */   U_: () => (/* binding */ contractDigestOf),
/* harmony export */   Xn: () => (/* binding */ OBLIGATION_KINDS),
/* harmony export */   bY: () => (/* binding */ validateRepairRecord),
/* harmony export */   f$: () => (/* binding */ SCHEMA_VERSION),
/* harmony export */   ji: () => (/* binding */ isRelPath),
/* harmony export */   mu: () => (/* binding */ validateCandidate),
/* harmony export */   qT: () => (/* binding */ candidateIdOf),
/* harmony export */   vb: () => (/* binding */ normalizeFinding)
/* harmony export */ });
/* unused harmony exports DISPOSITIONS, APPLICATION_STATES, ARTIFACT_STATES, ENVIRONMENT_STATES, COMPLETION_STATES, CUSTODY, GENERATORS, FAMILIES, EVIDENCE_ORIGINS, CONTRACT_ID_FIELDS, CANDIDATE_ID_FIELDS, OBLIGATION_FIELDS, validateObligation, CONTRACT_FIELDS, RECORD_FIELDS */
/* harmony import */ var _posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(41877);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(31174);
/* harmony import */ var _posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(53353);
// Versioned, closed repair records (verified-remediation PRD section 6): NormalizedFinding, RepairContract, CandidatePatch,
// VerificationRun and the RepairRecord envelope.
//
// Built on the assurance schema kit (closed world: an unknown field is an error, never carried), with identities computed by the
// coordinator over an allowlist of semantic fields (assurance/identity.js), so no clock, run id or model-supplied count can move an id.
// Validation never throws. Migration policy: version 1.x readers accept 1.x; a 2.0 record is refused (UNSUPPORTED_MAJOR), and adding
// a field means a minor version and an allowlist entry, never a silently carried key.




const SCHEMAS = Object.freeze({
  finding: 'agentic-security/normalized-finding',
  contract: 'agentic-security/repair-contract',
  candidate: 'agentic-security/candidate-patch',
  run: 'agentic-security/verification-run',
  record: 'agentic-security/repair-record',
});
const SCHEMA_VERSION = '1.0.0';

// The registered obligation kinds. A contract naming any other kind is refused: obligations are declarative and run through registered
// verifier operations only, so a contract file cannot carry an assertion of its own.
const OBLIGATION_KINDS = Object.freeze({
  'app-attack-blocked': { oracle: 'application-security', expectBaseline: 'confirmed', expectPatched: 'refuted', set: 'development', description: 'the declared development attack requests reach no forbidden effect on the patched revision, after reproducing on the original' },
  'app-attack-sealed': { oracle: 'application-security', expectBaseline: 'confirmed', expectPatched: 'refuted', set: 'sealed', description: 'held-out attack variants, run only on a candidate that passed every development obligation; their content and outcome never reach candidate generation' },
  'app-behaviour-preserved': { oracle: 'application-behaviour', expectBaseline: 'refuted', expectPatched: 'refuted', set: 'development', description: 'the declared legitimate requests and state checks hold on the original and on the patched revision' },
  'app-behaviour-after': { oracle: 'application-behaviour', expectBaseline: null, expectPatched: 'refuted', set: 'development', description: 'legitimate requests the original mishandles (for example a quoted value) hold on the patched revision' },
  'project-tests': { oracle: null, expectBaseline: null, expectPatched: 'passed', set: 'development', description: 'the central verifier: rescan, new-finding delta, footprint and the per-test delta of the project suite' },
});

const DISPOSITIONS = Object.freeze(['proposed', 'refuted-finding', 'needs-review', 'verified-for-contract', 'mitigation', 'rejected', 'blocked', 'cancelled']);
const APPLICATION_STATES = Object.freeze(['not-applied', 'applied', 'reverted', 'concurrent-change-refused']);
const ARTIFACT_STATES = Object.freeze(['unbuilt', 'source-only', 'artifact-verified', 'artifact-mismatch', 'unavailable']);
const ENVIRONMENT_STATES = Object.freeze(['not-checked', 'staging-verified', 'deployment-observed', 'unavailable']);
const COMPLETION_STATES = Object.freeze(['complete', 'partial', 'cancelled', 'unavailable', 'invalid']);
const CUSTODY = Object.freeze(['internal-scan', 'imported', 'locally-corroborated', 'reproduced', 'refuted', 'unresolved']);
const GENERATORS = Object.freeze(['deterministic-recipe', 'configured-model', 'user-supplied']);
const FAMILIES = Object.freeze(['sql-injection', 'object-authorization', 'ssrf', 'path-traversal']);
const EVIDENCE_ORIGINS = Object.freeze(['generated-from-profile', 'operator-declared', 'approved-invariant', 'counterexample', 'registered-family']);

const REL_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\w@.\-/]{1,512}$/;
const isRelPath = (p) => typeof p === 'string' && REL_PATH.test(p) && !p.includes('\\') && p.split('/')[0] !== _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_1__/* .STATE_DIR_NAME */ .Ky;

// ---------------------------------------------------------------- identities (allowlisted fields only)

const CONTRACT_ID_FIELDS = ['findingRefs', 'rootCauseGroup', 'sourceCommit', 'sourceDigest', 'configDigests', 'profile', 'obligations', 'policyFacts', 'editScope', 'executionPolicy'];
const contractIdOf = (c) => (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__/* .semanticId */ .YN)('rcon', c, CONTRACT_ID_FIELDS);
const contractDigestOf = (c) => (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__/* .digestOf */ .ol)(Object.fromEntries(CONTRACT_ID_FIELDS.map((f) => [f, c[f] ?? null])));
const CANDIDATE_ID_FIELDS = ['contractDigest', 'baselineDigest', 'patchDigest'];
const candidateIdOf = (c) => (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__/* .semanticId */ .YN)('rcand', c, CANDIDATE_ID_FIELDS);

// ---------------------------------------------------------------- validators

const OBLIGATION_FIELDS = ['id', 'kind', 'required', 'oracleId', 'oracleVersion', 'oracleLogicDigest', 'scope', 'baselineExpectation', 'patchedExpectation', 'evidenceOrigin', 'inputs', 'inputsDigest', 'description'];

function validateObligation(ctx, o, i) {
  const p = `obligations[${i}]`;
  if (!(0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .isPlainObject */ .Qd)(o)) { ctx.err('BAD_TYPE', p, 'must be an object'); return; }
  for (const k of Object.keys(o)) if (!OBLIGATION_FIELDS.includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.${k}`, `field '${k}' is not part of an obligation`);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkString */ .Em)(ctx, `${p}.id`, o.id);
  if (!Object.hasOwn(OBLIGATION_KINDS, o.kind)) { ctx.err('UNKNOWN_ENUM', `${p}.kind`, `unknown obligation kind ${JSON.stringify(o.kind)}; registered kinds: ${Object.keys(OBLIGATION_KINDS).join(', ')}`); return; }
  if (typeof o.required !== 'boolean') ctx.err('BAD_TYPE', `${p}.required`, 'must be a boolean');
  const kind = OBLIGATION_KINDS[o.kind];
  if (kind.oracle && o.oracleId !== kind.oracle) ctx.err('RULE_VIOLATION', `${p}.oracleId`, `obligation kind ${o.kind} runs only on ${kind.oracle}`);
  if (kind.oracle) (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkDigest */ .H2)(ctx, `${p}.oracleLogicDigest`, o.oracleLogicDigest);
  if (o.inputs !== undefined) { if (!(0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .isPlainObject */ .Qd)(o.inputs)) ctx.err('BAD_TYPE', `${p}.inputs`, 'must be an object'); else if (o.inputsDigest !== (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__/* .digestOf */ .ol)(o.inputs)) ctx.err('RULE_VIOLATION', `${p}.inputsDigest`, 'does not match the inputs'); }
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkEnum */ .S1)(ctx, `${p}.evidenceOrigin`, o.evidenceOrigin, EVIDENCE_ORIGINS);
}

const CONTRACT_FIELDS = ['schema', 'schemaVersion', 'contractId', 'contractDigest', 'family', 'findingRefs', 'rootCauseGroup', 'sourceCommit', 'sourceDigest', 'configDigests', 'profile', 'obligations', 'policyFacts', 'editScope', 'executionPolicy', 'knownUnknowns', 'expiresAt', 'approval'];
const CONTRACT_REQUIRED = ['schema', 'schemaVersion', 'contractId', 'contractDigest', 'family', 'findingRefs', 'sourceDigest', 'profile', 'obligations', 'policyFacts', 'editScope', 'executionPolicy', 'knownUnknowns'];

function validateContract(rec) {
  const g = (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .guardObject */ .NW)(rec); if (!g.ok) return (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .result */ .Ke)(g.ctx);
  const ctx = g.ctx;
  if (!(0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkHeader */ .eb)(ctx, rec, SCHEMAS.contract)) return (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .result */ .Ke)(ctx);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkFields */ .oA)(ctx, rec, CONTRACT_FIELDS, CONTRACT_REQUIRED);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkEnum */ .S1)(ctx, 'family', rec.family, FAMILIES);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkCommit */ .su)(ctx, 'sourceCommit', rec.sourceCommit ?? null);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkDigest */ .H2)(ctx, 'sourceDigest', rec.sourceDigest);
  if (!Array.isArray(rec.findingRefs) || !rec.findingRefs.length) ctx.err('MISSING_FIELD', 'findingRefs', 'at least one finding reference');
  if (!Array.isArray(rec.obligations) || !rec.obligations.length) ctx.err('MISSING_FIELD', 'obligations', 'at least one obligation');
  else {
    const ids = new Set();
    rec.obligations.forEach((o, i) => { validateObligation(ctx, o, i); if (ids.has(o?.id)) ctx.err('DUPLICATE_ID', `obligations[${i}].id`, 'duplicate obligation id'); ids.add(o?.id); });
    if (!rec.obligations.some((o) => o?.required)) ctx.err('RULE_VIOLATION', 'obligations', 'a contract needs at least one required obligation');
  }
  const es = rec.editScope;
  if (!(0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .isPlainObject */ .Qd)(es) || !Array.isArray(es.allowed) || !es.allowed.every(isRelPath)) ctx.err('BAD_TYPE', 'editScope.allowed', 'must list confined relative paths');
  if ((0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .isPlainObject */ .Qd)(es) && es.prohibited !== undefined && (!Array.isArray(es.prohibited) || !es.prohibited.every((p) => typeof p === 'string'))) ctx.err('BAD_TYPE', 'editScope.prohibited', 'must list path patterns');
  if ((0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .isPlainObject */ .Qd)(es) && (!Number.isInteger(es.maxFiles) || es.maxFiles < 1 || es.maxFiles > 50 || !Number.isInteger(es.maxEditedLines) || es.maxEditedLines < 1 || es.maxEditedLines > 5000)) ctx.err('RULE_VIOLATION', 'editScope', 'maxFiles 1..50 and maxEditedLines 1..5000 are required');
  if (!Array.isArray(rec.policyFacts)) ctx.err('BAD_TYPE', 'policyFacts', 'must be an array');
  else rec.policyFacts.forEach((f, i) => { if (!(0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .isPlainObject */ .Qd)(f)) return ctx.err('BAD_TYPE', `policyFacts[${i}]`, 'must be an object'); (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkEnum */ .S1)(ctx, `policyFacts[${i}].origin`, f.origin, ['operator-profile-outside-repository', 'repository-file', 'inferred-from-code', 'approved-invariant']); (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkEnum */ .S1)(ctx, `policyFacts[${i}].approval`, f.approval, ['approved', 'declared', 'proposed']); });
  if (!Array.isArray(rec.knownUnknowns)) ctx.err('BAD_TYPE', 'knownUnknowns', 'must be an array');
  if (rec.contractId !== undefined && rec.contractId !== contractIdOf(rec)) ctx.err('ID_MISMATCH', 'contractId', 'does not match the contract content');
  if (rec.contractDigest !== undefined && rec.contractDigest !== contractDigestOf(rec)) ctx.err('ID_MISMATCH', 'contractDigest', 'does not match the contract content');
  return (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .result */ .Ke)(ctx);
}

const CANDIDATE_FIELDS = ['schema', 'schemaVersion', 'candidateId', 'contractDigest', 'baselineDigest', 'generator', 'generatorIdentity', 'generationParameters', 'files', 'beforeDigests', 'afterDigests', 'patchDigest', 'scope', 'strategy', 'rationale', 'assumptions', 'proposedTests', 'accounting', 'createdAt'];

function validateCandidate(rec) {
  const g = (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .guardObject */ .NW)(rec); if (!g.ok) return (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .result */ .Ke)(g.ctx);
  const ctx = g.ctx;
  if (!(0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkHeader */ .eb)(ctx, rec, SCHEMAS.candidate)) return (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .result */ .Ke)(ctx);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkFields */ .oA)(ctx, rec, CANDIDATE_FIELDS, ['schema', 'schemaVersion', 'candidateId', 'contractDigest', 'baselineDigest', 'generator', 'generatorIdentity', 'files', 'patchDigest', 'scope', 'accounting']);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkEnum */ .S1)(ctx, 'generator', rec.generator, GENERATORS);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkDigest */ .H2)(ctx, 'contractDigest', rec.contractDigest); (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkDigest */ .H2)(ctx, 'baselineDigest', rec.baselineDigest); (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkDigest */ .H2)(ctx, 'patchDigest', rec.patchDigest);
  if (!(0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .isPlainObject */ .Qd)(rec.files) || !Object.keys(rec.files).length || !Object.keys(rec.files).every(isRelPath)) ctx.err('BAD_TYPE', 'files', 'must map confined relative paths to contents');
  else for (const [k, v] of Object.entries(rec.files)) if (v !== null && typeof v !== 'string') ctx.err('BAD_TYPE', `files.${k}`, 'must be a string or null (deletion)');
  if ((0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .isPlainObject */ .Qd)(rec.files) && rec.patchDigest !== (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__/* .digestOf */ .ol)(rec.files)) ctx.err('RULE_VIOLATION', 'patchDigest', 'does not match the files');
  const a = rec.accounting;
  if (!(0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .isPlainObject */ .Qd)(a)) ctx.err('BAD_TYPE', 'accounting', 'must be an object');
  else for (const k of ['tokens', 'calls', 'wallMs', 'usd']) if (!(a[k] === null || (typeof a[k] === 'number' && a[k] >= 0))) ctx.err('BAD_TYPE', `accounting.${k}`, 'must be a non-negative number or null (unknown, never zero)');
  if (rec.candidateId !== undefined && rec.candidateId !== candidateIdOf(rec)) ctx.err('ID_MISMATCH', 'candidateId', 'does not match the candidate content');
  return (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .result */ .Ke)(ctx);
}

const RECORD_FIELDS = ['schema', 'policyDigest', 'sourceDigest', 'patchDigest', 'exactPatch', 'schemaVersion', 'runId', 'contractId', 'contractDigest', 'findingRefs', 'disposition', 'application', 'artifact', 'environment', 'completion', 'candidates', 'selected', 'rounds', 'obligationResults', 'counterexamples', 'quarantined', 'regressionGuards', 'budget', 'accounting', 'reasons', 'nextPrerequisite', 'legacy', 'scope', 'createdAt', 'source'];

function validateRepairRecord(rec) {
  const g = (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .guardObject */ .NW)(rec); if (!g.ok) return (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .result */ .Ke)(g.ctx);
  const ctx = g.ctx;
  if (!(0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkHeader */ .eb)(ctx, rec, SCHEMAS.record)) return (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .result */ .Ke)(ctx);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkFields */ .oA)(ctx, rec, RECORD_FIELDS, ['schema', 'schemaVersion', 'runId', 'contractId', 'disposition', 'application', 'artifact', 'environment', 'completion', 'reasons', 'scope']);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkEnum */ .S1)(ctx, 'disposition', rec.disposition, DISPOSITIONS);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkEnum */ .S1)(ctx, 'application', rec.application, APPLICATION_STATES);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkEnum */ .S1)(ctx, 'artifact', rec.artifact, ARTIFACT_STATES);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkEnum */ .S1)(ctx, 'environment', rec.environment, ENVIRONMENT_STATES);
  (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .checkEnum */ .S1)(ctx, 'completion', rec.completion, COMPLETION_STATES);
  // a verified-for-contract record needs a complete run with every required obligation passed
  if (rec.disposition === 'verified-for-contract') {
    if (rec.completion !== 'complete') ctx.err('RULE_VIOLATION', 'completion', 'verified-for-contract needs a complete run');
    const req = (rec.obligationResults || []).filter((o) => o.required);
    if (!req.length || req.some((o) => o.status !== 'passed')) ctx.err('RULE_VIOLATION', 'obligationResults', 'verified-for-contract needs every required obligation passed');
  }
  if (rec.artifact === 'artifact-verified' || rec.environment !== 'not-checked' && rec.environment !== 'unavailable') {
    if (!rec.source || !(0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .isDigest */ .Bc)(rec.source.artifactDigest)) ctx.err('RULE_VIOLATION', 'artifact', 'an artifact or environment state needs a bound artifact digest');
  }
  return (0,_posture_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_2__/* .result */ .Ke)(ctx);
}

/** A finding as the repair workflow sees it, from the internal scan (imported findings come through repair/importers). */
function normalizeFinding(f, { commit = null, treeDigest = null, sourceTool = 'agentic-security', sourceToolVersion = null, custody = 'internal-scan' } = {}) {
  const loc = { file: f.file, line: Number.isInteger(f.line) ? f.line : null, column: Number.isInteger(f.column) ? f.column : null };
  return {
    schema: SCHEMAS.finding, schemaVersion: SCHEMA_VERSION,
    findingId: f.stableId || f.id, sourceTool, sourceToolVersion,
    externalRuleId: f.ruleId || f.rule || null, externalArtifactDigest: null,
    repository: { commit, treeDigest },
    locations: [loc], cwe: f.cwe || null, family: f.family || null, vuln: f.vuln || null,
    severity: f.severity || null, confidence: f.confidence ?? null, reachability: f.relevanceTier || f.reachability || null,
    exploitEvidence: f.proofTier || null, disposition: 'open', custody,
    mappingLimitations: f.cwe ? [] : ['no CWE was reported; it is unknown, not inferred'],
  };
}


/***/ })

};
