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
import { createHash } from 'node:crypto';
import { parse as babelParse } from '@babel/parser';
import { diffLines, splitLines } from './line-diff.js';
import { classifyFixMaterialRisk } from '../posture/material-change.js';

export const DEFAULT_BOUNDS = Object.freeze({ maxFiles: 3, maxEditedLines: 100 });

const JS_EXT = /\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i;
const PY_EXT = /\.py$/i;
const sha256 = (t) => (t === null || t === undefined ? null : `sha256:${createHash('sha256').update(String(t)).digest('hex')}`);
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
export function jsSymbols(text, file = 'x.js') {
  let ast;
  try {
    ast = babelParse(String(text), { sourceType: 'unambiguous', errorRecovery: true, allowReturnOutsideFunction: true, plugins: [/\.tsx?$|\.[mc]?ts$/i.test(file) ? 'typescript' : 'flow', 'jsx', 'classProperties', 'decorators-legacy'] });
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
export function pySymbols(text) {
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
export function heuristicSymbols(text) {
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
export function computePatchScope({ before = {}, after = {}, renames = [], bounds = {} }) {
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
  const cls = classifyFixMaterialRisk(materialInput);
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
export function legacyBounds(scope) {
  return { files: scope.totals.files, loc: scope.totals.editedLines, exceedsBounds: scope.exceedsBounds };
}
