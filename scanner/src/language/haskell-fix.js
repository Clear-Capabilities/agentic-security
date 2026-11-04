// Haskell remediation and dependency upgrades (HS-010).
//
// Deterministic patches exist only for patterns where the rewrite is provably the same program minus the
// vulnerability (SQL parameterization, argv instead of a shell string, contextual HTML escaping, a stronger
// hash, redacting a sensitive log argument). Everything else returns `{ok:false, proposal:'model-assisted'}`:
// this module never invents a rewrite it cannot justify.
//
// A patch is APPLIED only after it passes every gate: syntax (no new parse errors), a rescan in which the
// original finding is gone and nothing at medium or above is new, and, strictly opt-in, an isolated compile.
// Default operation never starts GHC, cabal, stack or Setup.hs.
//
// Dependency proposals edit the user's declared constraint at the declaring line (scope, flags and
// conditionals untouched). Without a supported RESOLVED verification they are `unverified`, never `fixed`,
// and a generated plan is never edited.

import { mkdirSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { parseHaskell } from './haskell-parser.js';
import { SENSITIVE } from './haskell-security-rules.js';
import { stripComments } from './haskell-comments.js';
import { compareVersions, parseVersion, parseCabalFile, versionSatisfies } from './haskell-manifests.js';
import { runFixLifecycle, unifiedDiff, writeWithBackup, undoFix } from './fix-lifecycle.js';

export const HS_FIX_VERSION = 'haskell-fix/1';
export const LABELS = Object.freeze(['FULL', 'MITIGATION', 'WORKAROUND']);

// ── small expression reader ──────────────────────────────────────────────────
const STRING = /^"(?:[^"\\]|\\.)*"$/;
const IDENT = /^[a-z_][\w']*$/;

/** End index (exclusive) of the atom starting at i: identifier, string literal or balanced group. */
function atomEnd(s, i) {
  while (s[i] === ' ') i++;
  const c = s[i];
  if (c === '"') { let j = i + 1; while (j < s.length && (s[j] !== '"' || s[j - 1] === '\\')) j++; return j < s.length ? j + 1 : -1; }
  if (c === '(' || c === '[') {
    const close = c === '(' ? ')' : ']'; let depth = 0;
    for (let j = i; j < s.length; j++) {
      if (s[j] === '"') { j = atomEnd(s, j) - 1; if (j < 0) return -1; continue; }
      if (s[j] === c) depth++; else if (s[j] === close && --depth === 0) return j + 1;
    }
    return -1;
  }
  const m = /^[\w'.]+/.exec(s.slice(i));
  return m ? i + m[0].length : -1;
}
const trimParens = (e) => { let s = e.trim(); while (s[0] === '(' && atomEnd(s, 0) === s.length) s = s.slice(1, -1).trim(); return s; };

function topLevelSplit(s, sep) {
  const parts = []; let depth = 0; let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"') { const e = atomEnd(s, i); if (e < 0) return null; i = e - 1; continue; }
    if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (depth === 0 && s.startsWith(sep, i)) { parts.push(s.slice(start, i)); start = i + sep.length; i += sep.length - 1; }
  }
  parts.push(s.slice(start));
  return parts;
}
const litValue = (t) => t.slice(1, -1);

/** `"a" ++ n ++ "b"` -> [{lit:'a'},{var:'n'},{lit:'b'}], or null for anything we cannot prove simple. */
function concatParts(expr) {
  const e = trimParens(expr);
  let raw = topLevelSplit(e, '++');
  if (raw && raw.length === 1) { const t = topLevelSplit(e, '<>'); if (t && t.length > 1) raw = t; }   // a Text (Semigroup) concatenation
  else if (raw && topLevelSplit(e, '<>')?.length > 1) return null;                                     // both operators: not a shape this reads
  if (!raw) return null;
  const out = [];
  for (const r of raw) {
    const t = trimParens(r);
    if (STRING.test(t)) out.push({ lit: litValue(t) });
    else if (IDENT.test(t)) out.push({ var: t });
    else return null;
  }
  return out;
}

function unwrapQueryExpr(expr) {
  let e = trimParens(expr);
  for (;;) {
    const m = /^(?:fromString|Query)\b\s*(?:\$\s*)?([\s\S]+)$/.exec(e);
    if (!m) return e;
    e = trimParens(m[1]);
  }
}

// ── imports ──────────────────────────────────────────────────────────────────
function importInfo(text, module) {
  const re = new RegExp(`^import\\s+(qualified\\s+)?${module.replace(/\./g, '\\.')}(?:\\s+qualified)?(?:\\s+as\\s+(\\w+))?\\s*(?:\\((.*)\\))?\\s*(hiding\\b.*)?$`, 'm');
  const m = re.exec(text);
  if (!m) return null;
  return { index: m.index, line: m[0], qualified: !!(m[1] || /\bqualified\b/.test(m[0])), alias: m[2] || null, items: m[3] === undefined ? null : m[3].split(/,(?![^(]*\))/).map((x) => x.trim()).filter(Boolean), hiding: !!m[4] };
}
/** Make `names` usable from `module`; returns {text, prefix} or null when the import shape forbids it. */
function ensureImport(text, module, names) {
  const info = importInfo(text, module);
  if (!info) {
    const lines = text.split('\n');
    let at = -1; for (let i = 0; i < lines.length; i++) if (/^import\s/.test(lines[i])) at = i;
    if (at < 0) { const mi = lines.findIndex((l) => /\bwhere\b/.test(l)); at = mi < 0 ? 0 : mi; }
    lines.splice(at + 1, 0, `import ${module} (${names.join(', ')})`);
    return { text: lines.join('\n'), prefix: '' };
  }
  if (info.hiding) return null;
  if (info.qualified) return { text, prefix: `${info.alias || module}.` };
  if (info.items === null) return { text, prefix: '' };
  const have = new Set(info.items.map((i) => i.replace(/\(.*$/, '').trim()));
  const missing = names.filter((n) => !have.has(n.replace(/\(.*$/, '')));
  if (!missing.length) return { text, prefix: '' };
  const next = info.line.replace(/\((.*)\)/, (_, inner) => `(${[...info.items, ...missing].join(', ')})`);
  return { text: text.replace(info.line, next), prefix: '' };
}
const hasPragma = (text, name) => new RegExp(`\\{-#\\s*LANGUAGE[^#]*\\b${name}\\b`).test(text);

// ── deterministic fixers ─────────────────────────────────────────────────────
const lineBounds = (text, line) => { const ls = text.split('\n'); let off = 0; for (let i = 0; i < line - 1; i++) off += ls[i].length + 1; return { start: off, end: off + (ls[line - 1] || '').length, text: ls[line - 1] ?? '' }; };
const splice = (text, a, b, repl) => text.slice(0, a) + repl + text.slice(b);

/** callee atom position inside a line: optional qualifier + one of `names`. */
function findCall(lineText, names) {
  const re = new RegExp(`(?<![\\w'.])((?:[A-Z][\\w']*\\.)?)(${names.join('|')})(?![\\w'])`);
  const m = re.exec(lineText);
  return m ? { prefix: m[1], name: m[2], index: m.index, after: m.index + m[0].length } : null;
}

// The database driver whose `execute`/`query`/`Only` the rewrite uses is the one the FILE already imports: a hard-coded driver would add an
// import of a library the project may not depend on, and a patch that compiles against nothing is not a fix. Only the two drivers whose
// `execute_`/`query_`/`execute`/`query`/`Only` API is identical are rewritten; any other (mysql-simple, HDBC, persistent) or two at once is refused.
const SQL_DRIVERS = Object.freeze(['Database.PostgreSQL.Simple', 'Database.SQLite.Simple']);
const OTHER_SQL = /^import\s+(?:qualified\s+)?Database\.(?:MySQL|HDBC|Persist|Beam|Opaleye|Selda|Esqueleto|SQLite3|PostgreSQL\.LibPQ)/m;
export function sqlDriverOf(text) {
  const used = SQL_DRIVERS.filter((m) => importInfo(text, m));
  return used.length === 1 && !OTHER_SQL.test(text) ? used[0] : null;
}

function fixSql(text, f) {
  const driver = sqlDriverOf(text);
  if (!driver) return null;
  const lb = lineBounds(text, f.line);
  const call = findCall(lb.text, ['execute_', 'query_']);
  if (!call) return null;
  const connEnd = atomEnd(lb.text, call.after); if (connEnd < 0) return null;
  const qStart = (() => { let i = connEnd; while (lb.text[i] === ' ') i++; return i; })();
  const qEnd = atomEnd(lb.text, qStart); if (qEnd < 0) return null;
  const parts = concatParts(unwrapQueryExpr(lb.text.slice(qStart, qEnd)));
  if (!parts || !parts.some((p) => p.var)) return null;
  let sql = ''; const params = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (p.lit !== undefined) { sql += p.lit; continue; }
    const before = parts[i - 1], after = parts[i + 1];
    const q = before && before.lit !== undefined && /'$/.test(before.lit) && after && after.lit !== undefined && /^'/.test(after.lit);
    const halfQuoted = (before && before.lit !== undefined && /'$/.test(before.lit)) !== (after && after.lit !== undefined && /^'/.test(after.lit));
    if (halfQuoted) return null;                       // an unbalanced quote around the value: not a pattern we can prove
    if (q) { sql = sql.slice(0, -1); parts[i + 1] = { lit: after.lit.slice(1) }; }
    sql += '?'; params.push(p.var);
  }
  const imp = ensureImport(text, driver, ['execute', 'query', 'Only']);
  if (!imp) return null;
  const only = `${call.prefix || imp.prefix}Only`;
  const tuple = params.length === 1 ? `(${only} ${params[0]})` : `(${params.join(', ')})`;
  const fn = call.name === 'execute_' ? 'execute' : 'query';
  let lit = `"${sql}"`; let t2 = imp.text;
  if (!hasPragma(text, 'OverloadedStrings')) {
    const fs = ensureImport(imp.text, 'Data.String', ['fromString']); if (!fs) return null;
    t2 = fs.text; lit = `(${fs.prefix}fromString ${lit})`;
  }
  // splice on the ORIGINAL text first, then re-apply import edits via a line-count-stable approach
  const replaced = lb.text.slice(0, call.index) + `${call.prefix}${fn}` + lb.text.slice(call.after, connEnd) + ` ${lit} ${tuple}` + lb.text.slice(qEnd);
  const body = splice(text, lb.start, lb.end, replaced);
  const next = applyImportDelta(text, t2, body);
  return { ruleId: 'hs-sql-parameterize', label: 'FULL', text: next, explanation: `Moved ${params.length} interpolated value(s) out of the SQL text into ${fn} parameters.`, behavior: { kind: 'sql', sql, params } };
}
/** Import edits were computed on `orig`; carry them over to `body`, which differs only on one line. */
function applyImportDelta(orig, withImports, body) {
  if (orig === withImports) return body;
  const o = orig.split('\n'), w = withImports.split('\n'), b = body.split('\n');
  const origImports = o.filter((l) => /^import\s/.test(l)), newImports = w.filter((l) => /^import\s/.test(l));
  let out = b.slice();
  // replace changed import lines in place, insert genuinely new ones after the last import
  for (const l of origImports) if (!newImports.includes(l)) { const ch = newImports.find((n) => !origImports.includes(n) && n.split('(')[0].trim() === l.split('(')[0].trim()); if (ch) out = out.map((x) => (x === l ? ch : x)); }
  const added = newImports.filter((n) => !origImports.includes(n) && !origImports.some((l) => l.split('(')[0].trim() === n.split('(')[0].trim()));
  if (added.length) { let at = -1; out.forEach((l, i) => { if (/^import\s/.test(l)) at = i; }); out.splice(at + 1, 0, ...added); }
  return out.join('\n');
}

function fixProcess(text, f) {
  const lb = lineBounds(text, f.line);
  const call = findCall(lb.text, ['callCommand', 'system', 'spawnCommand']);
  if (!call) return null;
  let aStart = call.after; while (lb.text[aStart] === ' ') aStart++;
  let aEnd;
  if (lb.text[aStart] === '$') { aStart++; while (lb.text[aStart] === ' ') aStart++; aEnd = lb.text.length; }
  else aEnd = atomEnd(lb.text, aStart);
  if (aEnd < 0) return null;
  // Since 0.195.16: a Text command, `system (cs t)` / `(T.unpack t)`, whose Text is a `<>` concatenation on the line or in a one-line
  // `let` of the same function used nowhere else. The unpack is kept per piece, so each argument is still a String.
  let argText = trimParens(lb.text.slice(aStart, aEnd));
  let unpackFn = null; let letLine = -1;
  const um = /^(cs|(?:[A-Z][\w']*\.)*unpack)\s+(.+)$/.exec(argText);
  if (um) { unpackFn = um[1]; argText = trimParens(um[2]); }
  if (IDENT.test(argText)) {
    const ls = text.split('\n');
    let start = 0; for (let i = f.line - 1; i >= 0; i--) { const mm = TOP_DECL.exec(ls[i] || ''); if (mm && !NOT_A_DEF.has(mm[1])) { start = i; break; } }
    let end = ls.length; for (let i = f.line; i < ls.length; i++) { const mm = TOP_DECL.exec(ls[i] || ''); if (mm && !NOT_A_DEF.has(mm[1])) { end = i; break; } }
    const uses = new RegExp(`(?<![\\w'.])${argText}(?![\\w'])`, 'g');
    const body = ls.slice(start, end);
    let bound = null;
    for (let i = 0; i < body.length; i++) { const mm = new RegExp(`^\\s+let\\s+${argText}\\s*=\\s*(.+)$`).exec(body[i]); if (mm && start + i < f.line - 1) { bound = { i: start + i, expr: mm[1].trim() }; } }
    const count = (body.join('\n').match(uses) || []).length;
    if (bound && count === 2 && !/^\s+let\b/.test(ls[bound.i + 1] || '') && !/^\s{2,}\S/.test(ls[bound.i + 1] || '') || (bound && count === 2 && !(ls[bound.i + 1] || '').trim())) { argText = trimParens(bound.expr); letLine = bound.i; }
    else if (bound && count === 2) {
      // the binding has no continuation only when the next line is not indented deeper than `let`'s binding
      const letIndent = (/^\s*/.exec(ls[bound.i]) || [''])[0].length;
      const nextIndent = (/^\s*/.exec(ls[bound.i + 1] || '') || [''])[0].length;
      if ((ls[bound.i + 1] || '').trim() && nextIndent > letIndent) return null;
      argText = trimParens(bound.expr); letLine = bound.i;
    }
  }
  if (/(?<![\w'])(?:if|case|let|do)(?![\w'])/.test(argText)) return null;
  const parts = concatParts(argText);
  if (!parts || !parts.some((p) => p.var)) return null;       // a bare variable: no provable argv split
  if (unpackFn === null && parts.some((p) => p.var) && /\bcs\b|unpack/.test(argText)) return null;
  // tokenise into words; a word is a list of pieces
  const words = []; let cur = [];
  const flush = () => { if (cur.length) { words.push(cur); cur = []; } };
  for (const p of parts) {
    if (p.var) { cur.push(p); continue; }
    const segs = p.lit.split(/(\s+)/);
    for (const s of segs) { if (!s) continue; if (/^\s+$/.test(s)) flush(); else cur.push({ lit: s }); }
  }
  flush();
  if (!words.length || words[0].some((p) => p.var)) return null;      // the program itself must be a literal
  if (/[|&;<>`$*?()\\]/.test(words[0].map((p) => p.lit).join('')) || words.slice(1).some((w) => w.every((p) => p.lit !== undefined) && /[|&;<>`$*?()]/.test(w.map((p) => p.lit).join('')))) return null; // shell syntax in the literal: not an argv
  const prog = words[0].map((p) => p.lit).join('');
  const v = (name) => (unpackFn ? `${unpackFn} ${name}` : name);
  const argExpr = (w) => (w.length === 1 && w[0].lit !== undefined ? `"${w[0].lit}"` : (w.length === 1 ? v(w[0].var) : `(${w.map((p) => (p.lit !== undefined ? `"${p.lit}"` : v(p.var))).join(' ++ ')})`));
  let args = words.slice(1);
  // End option parsing before the first value-bearing argument, but only when no earlier literal is itself an
  // option (it might take a value, and "--" would then be consumed as that value). Otherwise leave it to the gate.
  const firstVar = args.findIndex((w) => w.some((p) => p.var));
  const optionBefore = args.slice(0, Math.max(firstVar, 0)).some((w) => w[0].lit !== undefined && /^-/.test(w[0].lit));
  const terminated = firstVar >= 0 && !optionBefore && !(args[firstVar][0].lit !== undefined);
  if (terminated) args = [[{ lit: '--' }], ...args];
  const whole = args.every((w) => w.length === 1);
  const fn = call.name === 'callCommand' ? 'callProcess' : 'rawSystem';
  const imp = ensureImport(text, 'System.Process', [fn]); if (!imp) return null;
  const repl = `${call.prefix || imp.prefix}${fn} "${prog}" [${args.map(argExpr).join(', ')}]`;
  const replaced = lb.text.slice(0, call.index) + repl + lb.text.slice(aEnd);
  let edited = splice(text, lb.start, lb.end, replaced);
  if (letLine >= 0) { const ls = edited.split('\n'); ls.splice(letLine, 1); edited = ls.join('\n'); }   // the one-line `let` is now unused: -Werror would reject it
  const next = applyImportDelta(text, imp.text, edited);
  return { ruleId: 'hs-process-argv', label: 'MITIGATION', text: next, explanation: `Replaced a shell command string with a direct ${fn} of "${prog}" and an argument list; no shell parses the value${whole ? '' : ' (a value fused into an argument is still passed as data)'}. ${terminated ? 'A "--" now ends option parsing before the value (assumes the program follows that convention).' : 'A value that starts with "-" can still be read as an option by the program: add "--" or validate it.'}`, behavior: { kind: 'process', program: prog, argv: args.map((w) => w.map((p) => (p.lit !== undefined ? { lit: p.lit } : { var: p.var }))) } };
}

function fixHtml(text, f) {
  // `preEscapedToHtml` and `toHtml` are blaze-html's pair (Yesod and the shakespeare packages re-export them); another library's raw-markup call has a
  // different name and a different escaping function, so a file that does not import blaze or one of its re-exporters is not rewritten.
  if (!/^import\s+(?:qualified\s+)?(?:Text\.Blaze|Yesod|Text\.Hamlet)/m.test(text)) return null;
  const lb = lineBounds(text, f.line);
  const m = /(?<![\w'.])((?:[A-Z][\w']*\.)?)preEscapedToHtml(?![\w'])/.exec(lb.text);
  if (!m) return null;
  const imp = ensureImport(text, 'Text.Blaze.Html', ['toHtml']); if (!imp) return null;
  const repl = lb.text.slice(0, m.index) + `${m[1]}toHtml` + lb.text.slice(m.index + m[0].length);
  const next = applyImportDelta(text, imp.text, splice(text, lb.start, lb.end, repl));
  return { ruleId: 'hs-html-escape', label: 'FULL', text: next, explanation: 'preEscapedToHtml trusts its argument as markup; toHtml escapes <, >, &, quotes. Same type, the value is now text.', behavior: { kind: 'html', from: 'preEscapedToHtml', to: 'toHtml' } };
}

function fixWeakHash(text, f) {
  const lb = lineBounds(text, f.line);
  const re = /(?<![\w'.])(MD5|SHA1)(?![\w'.])/g;
  if (!re.test(lb.text)) return null;
  // The algorithm is often a TYPE as well (`Digest MD5` in a signature, an annotation on another line): replacing it on one line only leaves a
  // type error behind. Any other mention outside the import list means the rewrite is not provably the same program, so it is not made.
  const elsewhere = text.split('\n').some((l, i) => i !== f.line - 1 && !/^import\s/.test(l) && /(?<![\w'.])(MD5|SHA1)(?![\w'.])/.test(l));
  if (elsewhere) return null;
  const imp = ensureImport(text, 'Crypto.Hash', ['SHA256(..)']); if (!imp) return null;
  const repl = lb.text.replace(/(?<![\w'.])(MD5|SHA1)(?![\w'.])/g, 'SHA256');
  const next = applyImportDelta(text, imp.text, splice(text, lb.start, lb.end, repl));
  return { ruleId: 'hs-hash-sha256', label: 'FULL', text: next, explanation: 'MD5/SHA-1 replaced by SHA-256. Digests change: anything that stored or compares old digests must be migrated.', behavior: { kind: 'hash', from: ['MD5', 'SHA1'], to: 'SHA256' } };
}


// ── path traversal ───────────────────────────────────────────────────────────
// `readFile ("/srv/data/" ++ name)` -> `readFile ("/srv/data/" ++ takeFileName name)` when `name` is a String/FilePath PARAMETER of the enclosing function.
// The rewrite is a mitigation, not an equivalence: a name that carried directories now keeps only its last segment, and `.` / `..` survive
// `takeFileName`, which is why directory operations are not rewritten (only operations on a file). Every other shape is a proposal.
const PATH_FILE_OPS = ['readFile', 'writeFile', 'appendFile', 'removeFile', 'doesFileExist', 'openFile', 'withFile', 'openBinaryFile', 'withBinaryFile', 'getFileSize', 'getModificationTime'];

/** Splits `a ++ b </> c` at its top-level `++` / `<>` / `</>` operators, keeping the operator text: [part, op, part, ...] or null. */
function splitOperators(expr) {
  const out = []; let depth = 0; let start = 0;
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i];
    if (c === '"') { const e = atomEnd(expr, i); if (e < 0) return null; i = e - 1; continue; }
    if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (depth === 0) {
      const m = /^\s*(\+\+|<>|<\/>)\s*/.exec(expr.slice(i));
      if (m && (i === start || /\s/.test(expr[i]) || true)) { out.push(expr.slice(start, i), m[0]); i += m[0].length - 1; start = i + 1; }
    }
  }
  out.push(expr.slice(start));
  return out;
}

/** The declared types of the parameters of the top-level function containing `line`: { name -> type text }, from its signature and first clause. */
function paramTypesAt(text, line) {
  const sig = signatureAt(text, line);
  if (!sig) return null;
  const out = {};
  sig.params.forEach((p, i) => { if (sig.types[i] !== undefined) out[p] = sig.types[i]; });
  return out;
}
/** The top-level clause enclosing `line` (1-based) and its signature: { name, params, types (the last is the result), clause (0-based line) }. */
function signatureAt(text, line) {
  const lines = text.split('\n');
  let clause = -1;
  for (let i = Math.min(line - 1, lines.length - 1); i >= 0; i--) if (/^[a-z_][\w']*\b[^:\n]*=/.test(lines[i]) && !/^[a-z_][\w']*\s*::/.test(lines[i])) { clause = i; break; }
  if (clause < 0) return null;
  const m = /^([a-z_][\w']*)([^=]*)=/.exec(lines[clause]);
  if (!m) return null;
  const name = m[1]; const params = m[2].trim() ? m[2].trim().split(/\s+/) : [];
  if (params.some((p) => !/^[a-z_][\w']*$/.test(p))) return null;      // a pattern, not a plain name: not judged
  const sigLine = lines.findIndex((l) => new RegExp(`^${name}\\s*::`).test(l));
  if (sigLine < 0) return null;
  let sig = lines[sigLine].replace(/^[^:]*::/, '');
  for (let j = sigLine + 1; j < lines.length && /^\s+\S/.test(lines[j]) && !/^[a-z_][\w']*\s*(::|=)/.test(lines[j]); j++) sig += ` ${lines[j].trim()}`;
  sig = sig.replace(/^.*=>/, '');
  const types = []; let depth = 0; let cur = '';
  for (let i = 0; i < sig.length; i++) {
    const c = sig[i];
    if (c === '(' || c === '[') depth++; else if (c === ')' || c === ']') depth--;
    if (depth === 0 && sig.startsWith('->', i)) { types.push(cur.trim()); cur = ''; i++; continue; }
    cur += c;
  }
  types.push(cur.trim());
  return { name, params, types, clause };
}

// hs-path-contain (0.195.16): a path parameter that reaches a file operation anywhere in its function (the sink may sit in a callee or a
// `where` helper: the two dhall test-server sites are a read and an existence test under one FilePath parameter). A guard CLAUSE is
// added before the function's first equation, rejecting a parent-directory segment or an absolute path, and falls through to the
// existing equations otherwise, so no line of the body moves. The check is the one the taint engine's guard recogniser already
// understands (`".." \`elem\` splitDirectories p`), so the rescan judges the same semantics, not a name. Only a function with exactly
// one String/FilePath parameter and a `Maybe` result (bare, or under one monad) is rewritten: `Nothing` is the only failure value the
// fixer can construct without inventing an error type. A MITIGATION: a symbolic link inside the base can still point outside it.
function fixPathContain(text, f) {
  const sig = signatureAt(text, f.line);
  if (!sig) return null;
  const pathParams = sig.params.filter((p, i) => /^(?:String|FilePath)$/.test(sig.types[i] || ''));
  if (pathParams.length !== 1) return null;
  const param = pathParams[0];
  const result = sig.types[sig.types.length - 1] || '';
  const rm = /^(?:(?:[A-Z][\w'.]*\s+)?\(\s*Maybe\s+[^()]+\)|Maybe\s+[^()\s]+(?:\s+[^()\s]+)*)$/.exec(result.trim());
  if (!rm) return null;
  const monadic = /^[A-Z]/.test(result.trim()) && !/^Maybe\b/.test(result.trim());
  const fail = monadic ? 'pure Nothing' : 'Nothing';
  const lines = text.split('\n');
  // the first equation of this function (the clause enclosing the line may be a later one)
  let first = sig.clause; for (let i = 0; i < sig.clause; i++) if (new RegExp(`^${sig.name}(?![\\w'])`).test(lines[i]) && !new RegExp(`^${sig.name}\\s*::`).test(lines[i])) { first = i; break; }
  if (new RegExp(`splitDirectories\\s+${param}(?![\\w'])`).test(stripComments(text))) return null;     // already checked somewhere
  const imp = ensureImport(text, 'System.FilePath', ['splitDirectories', 'isAbsolute']); if (!imp) return null;
  const guard = `${sig.name} ${param}\n    | ".." \`elem\` ${imp.prefix}splitDirectories ${param} || ${imp.prefix}isAbsolute ${param} = ${fail}`;
  lines.splice(first, 0, guard);
  const next = applyImportDelta(text, imp.text, lines.join('\n'));
  return {
    ruleId: 'hs-path-contain', label: 'MITIGATION', text: next,
    explanation: `Added a guard equation to \`${sig.name}\` that answers ${fail} when \`${param}\` has a ".." segment or is absolute, before any file operation runs; every other call falls through to the existing equations unchanged.`,
    consequences: [
      `A request naming a parent directory or an absolute path now gets the function's ${fail} (its not-found answer) instead of the file; a symbolic link inside the served directory can still point outside it (resolve with canonicalizePath and compare the prefix when links are possible).`,
      'The check is on the parameter as received: a path decoded or joined later inside the function is not re-checked.',
    ],
    behavior: { kind: 'path-contain', fn: sig.name, param },
    expectEffective: { kind: 'path-contain', fn: sig.name, param, fail },
  };
}

function fixPath(text, f) {
  const lb = lineBounds(text, f.line);
  const call = findCall(lb.text, PATH_FILE_OPS);
  if (!call) return null;
  let aStart = call.after; while (lb.text[aStart] === ' ') aStart++;
  let aEnd;
  if (lb.text[aStart] === '$') { aStart++; while (lb.text[aStart] === ' ') aStart++; aEnd = lb.text.length; }
  else aEnd = atomEnd(lb.text, aStart);
  if (aEnd < 0) return null;
  const arg = lb.text.slice(aStart, aEnd);
  const inner = trimParens(arg);
  const parts = splitOperators(inner);
  if (!parts || parts.length < 3) return null;
  const operands = parts.filter((_, i) => i % 2 === 0).map((x) => trimParens(x));
  if (!operands.some((o) => STRING.test(o))) return null;                       // no fixed part: a pass-through, not a construction
  const vars = operands.filter((o) => !STRING.test(o));
  if (!vars.length || vars.some((v) => !IDENT.test(v))) return null;
  const types = paramTypesAt(text, f.line);
  if (!types || vars.some((v) => !/^(?:String|FilePath)$/.test(types[v] || ''))) return null;   // takeFileName takes a String: any other type would not compile
  if (new RegExp(`(?<![\\w'.])takeFileName\\s+(?:${vars.join('|')})(?![\\w'])`).test(lb.text)) return null;
  const imp = ensureImport(text, 'System.FilePath', ['takeFileName']); if (!imp) return null;
  const fn = `${imp.prefix}takeFileName`;
  let rebuilt = '';
  parts.forEach((part, i) => { rebuilt += i % 2 === 1 ? part : (vars.includes(trimParens(part)) ? part.replace(trimParens(part), `${fn} ${trimParens(part)}`) : part); });
  const wrapped = arg.startsWith('(') && atomEnd(arg, 0) === arg.length ? `(${rebuilt})` : rebuilt;
  const replaced = lb.text.slice(0, aStart) + wrapped + lb.text.slice(aEnd);
  const next = applyImportDelta(text, imp.text, splice(text, lb.start, lb.end, replaced));
  return { ruleId: 'hs-path-takefilename', label: 'MITIGATION', text: next, explanation: `Applied takeFileName to ${vars.join(', ')} so only its last path segment is used under the fixed directory. A value that carried subdirectories now names a file directly inside it; "." and ".." survive takeFileName, so this is not applied to directory operations.`, behavior: { kind: 'path', sanitizer: 'takeFileName', vars } };
}

const LOG_CALLS = ['putStrLn', 'putStr', 'hPutStrLn', 'hPutStr', 'print', 'trace', 'traceShow', 'traceShowId', 'logInfoN', 'logDebugN', 'logWarnN', 'logErrorN', 'logInfo', 'logDebug', 'logWarn', 'logError'];
// hxt (0.195.16): `withSubstDTDEntities yes` (or `True`) on the reported line becomes `no` (`False`): the parser no longer substitutes
// entities declared in a DTD, which is the whole of the finding, so the label is FULL. `yes`/`no` come from Text.XML.HXT.Core (hxt
// 9.3.1.22 re-exports the XmlState type definitions); an explicit import list that names `yes` but not `no` gets `no` added.
function fixXmlEntities(text, f) {
  const lb = lineBounds(text, f.line);
  const m = /(?<![\w'.])((?:[A-Z][\w']*\.)?)withSubstDTDEntities\s+((?:[A-Z][\w']*\.)?)(yes|True)(?![\w'])/.exec(lb.text);
  if (!m) return null;
  const [, , qual, val] = m;
  const to = val === 'True' ? 'False' : `${qual}no`;
  let t = text;
  if (val === 'yes' && !qual) {
    const info = importInfo(text, 'Text.XML.HXT.Core');
    if (info && !info.qualified && info.items && !info.items.some((x) => x.trim() === 'no')) { const e = ensureImport(text, 'Text.XML.HXT.Core', ['no']); if (!e) return null; t = e.text; }
  }
  const shifted = t.split('\n').length - text.split('\n').length;
  const lb2 = lineBounds(t, f.line + shifted);
  if (lb2.text !== lb.text) return null;
  const at = lb2.start + m.index + m[0].length - val.length;
  const next = splice(t, at, at + val.length, to);
  return {
    ruleId: 'hs-xml-no-entity-substitution', label: 'FULL', text: next,
    explanation: `withSubstDTDEntities now reads ${to}: entities declared in a document's DTD are no longer substituted, so an external or recursive entity in untrusted XML is not expanded by this parser configuration.`,
    consequences: ['A document that relies on its own DTD entities for content now yields the entity references unexpanded; a document that needs them must be parsed with a separate, trusted configuration.'],
    behavior: { kind: 'hxt-entities', line: f.line + shifted },
    expectEffective: { kind: 'hxt-entities', line: f.line + shifted },
  };
}
function fixLogging(text, f) {
  const lb = lineBounds(text, f.line);
  const call = findCall(lb.text, LOG_CALLS);
  if (!call) return null;
  const head = lb.text.slice(0, call.after); let rest = lb.text.slice(call.after);
  let n = 0;
  // Only code is rewritten: a string literal is kept as it is (before 0.195.16 the word inside `" password="` was replaced too, which
  // produced an unparseable line; the guide's captured example showed it).
  rest = rest.split(/("(?:[^"\\]|\\.)*")/).map((seg, i) => (i % 2 === 1 ? seg : seg.replace(/(?<![\w'.])(?:show\s+)?((?:[A-Za-z_][\w']*\.)?[a-z_][\w']*)(?![\w'(])/g, (all, id) => {
    const bare = id.replace(/^.*\./, '');
    if (/^(?:show|pack|unpack|stderr|stdout)$/.test(bare) || !SENSITIVE.test(bare)) return all;
    n++; return '"[REDACTED]"';
  }))).join('');
  if (!n) return null;
  const next = splice(text, lb.start, lb.end, head + rest);
  return { ruleId: 'hs-log-redact', label: 'MITIGATION', text: next, explanation: `Replaced ${n} sensitive log argument(s) with "[REDACTED]". The value is no longer logged; the log line loses that detail.`, behavior: { kind: 'log', redacted: n } };
}

// ── TLS certificate validation (CWE-295) ─────────────────────────────────────
// One boolean literal: `TLSSettingsSimple True ..` / `{ settingDisableCertificateValidation = True }` of the `connection` package becomes False.
// API (checked against the package documentation): `data TLSSettings = TLSSettingsSimple { settingDisableCertificateValidation, settingDisableSession,
// settingUseServerName :: Bool } | TLSSettings ClientParams`. The OpenSSL `VerifyNone` shape is NOT rewritten: `VerifyPeer` needs a CA bundle to be
// loaded and a host-name check, which are deployment decisions (see CLASS_REASONS).
const TLS_FIELD = 'settingDisableCertificateValidation';
const TLS_CTOR_RE = /(?<![\w'.])(?:[A-Z][\w']*\.)?TLSSettingsSimple(?![\w'])/g;

/** Index after the `}` matching the `{` at s[i] (strings skipped), or -1. */
function braceEnd(s, i) {
  let depth = 0;
  for (let j = i; j < s.length; j++) {
    if (s[j] === '"') { const e = atomEnd(s, j); if (e < 0) return -1; j = e - 1; continue; }
    if (s[j] === '{') depth++; else if (s[j] === '}' && --depth === 0) return j + 1;
  }
  return -1;
}
/** Splits `a (b c) "d"` at top-level whitespace into atoms. */
function wordsOf(s) {
  const out = []; let i = 0;
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;
    const e = atomEnd(s, i);
    if (e < 0) return null;
    out.push(s.slice(i, e).trim()); i = e;
  }
  return out;
}

/**
 * The structural reading of every `TLSSettingsSimple` construction in `text`: [{start, form, disableCertificateValidation: true|false|null, others}].
 * null means "not a literal". This is the behavior model of the TLS fixer AND the independent reader its effective-change check uses.
 */
export function tlsSettingsOf(text) {
  const code = stripComments(text);
  const out = [];
  for (const m of code.matchAll(TLS_CTOR_RE)) {
    let i = m.index + m[0].length;
    while (/\s/.test(code[i] || '')) i++;
    const lit = (v) => { const t = trimParens(v); return t === 'True' ? true : t === 'False' ? false : null; };
    if (code[i] === '{') {
      const end = braceEnd(code, i);
      if (end < 0) { out.push({ start: m.index, form: 'record', disableCertificateValidation: null, others: [] }); continue; }
      const fields = {};
      for (const part of (topLevelSplit(code.slice(i + 1, end - 1), ',') || [])) { const kv = /^\s*([\w']+)\s*=\s*([\s\S]*?)\s*$/.exec(part); if (kv) fields[kv[1]] = kv[2]; }
      out.push({ start: m.index, form: 'record', disableCertificateValidation: fields[TLS_FIELD] === undefined ? null : lit(fields[TLS_FIELD]), others: ['settingDisableSession', 'settingUseServerName'].map((k) => fields[k] ?? null) });
    } else {
      const lineEnd = code.indexOf('\n', i); const rest = code.slice(i, lineEnd < 0 ? code.length : lineEnd);
      const ws = wordsOf(rest) || [];
      out.push({ start: m.index, form: 'positional', disableCertificateValidation: ws.length >= 1 ? lit(ws[0]) : null, others: ws.slice(1, 3) });
    }
  }
  return out;
}

// HsOpenSSL (0.195.16, from IHP's OpenAI client): `contextSetVerificationMode ctx VerifyNone` as a statement of a do block becomes
// `contextSetDefaultVerifyPaths ctx` (the system CA locations; HsOpenSSL 0.11.7.11 documents it as "the default locations from which CA
// certificates are loaded") followed by `contextSetVerificationMode ctx (VerifyPeer True True Nothing)` (a certificate is required,
// requested once, no callback). A MITIGATION: the chain is now verified against the system store, but HsOpenSSL checks the host name
// only through `enableHostnameValidation` on the SSL connection object, which this context-level code never sees, so a valid
// certificate for another host is still accepted; the consequence says so.
function fixOpenSslVerify(text, f) {
  const info = importInfo(text, 'OpenSSL.Session');
  if (!info || info.hiding) return null;
  const STMT = /^(\s+)((?:[A-Z][\w']*\.)?)contextSetVerificationMode\s+([a-z_][\w']*)\s+((?:[A-Z][\w']*\.)?)VerifyNone\s*$/;
  const lines = text.split('\n');
  const okQual = (qual, qual2) => (!qual || (info.qualified && (info.alias || 'OpenSSL.Session') + '.' === qual)) && (!qual2 || qual2 === qual);
  // a statement: the nearest less-indented preceding non-blank line opens a do block (`\ctx -> do`, `= do`, `do`)
  const isStatement = (i, indent) => { for (let j = i - 1; j >= 0; j--) { const l = lines[j]; if (!l.trim()) continue; const ind = (/^\s*/.exec(l) || [''])[0].length; if (ind < indent.length) return /\bdo\s*$/.test(stripComments(l)); } return false; };
  // The reported line first; every other VerifyNone statement of the same shape in the file is rewritten with it (one logical fix: the
  // rule reports the class once per file, so a second site left as it was would keep the finding and block the patch for a reason the
  // reader could not see). A VerifyNone the shape does not cover stays, and the rescan then says so.
  const m0 = STMT.exec(lines[f.line - 1] || '');
  if (!m0 || !okQual(m0[2], m0[4]) || !isStatement(f.line - 1, m0[1])) return null;
  const sites = [];
  lines.forEach((l, i) => { const m = STMT.exec(l); if (m && okQual(m[2], m[4]) && isStatement(i, m[1])) sites.push({ i, indent: m[1], ctx: m[3], qual: m[2] }); });
  let t = text; let prefix = m0[2];
  if (!m0[2]) { const e = ensureImport(text, 'OpenSSL.Session', ['contextSetDefaultVerifyPaths', 'contextSetVerificationMode', 'VerificationMode(..)']); if (!e) return null; t = e.text; prefix = e.prefix; }
  const shifted = t.split('\n').length - lines.length;
  const out = t.split('\n');
  for (const s of [...sites].reverse()) {
    if (out[s.i + shifted] !== lines[s.i]) return null;
    out.splice(s.i + shifted, 1, `${s.indent}${prefix}contextSetDefaultVerifyPaths ${s.ctx}`, `${s.indent}${prefix}contextSetVerificationMode ${s.ctx} (${prefix}VerifyPeer True True Nothing)`);
  }
  // the mode statement of each site in the patched file: the import shift, plus one line per site above it
  const modeLines = sites.map((s, k) => s.i + shifted + k + 2);
  const next = out.join('\n');
  const where = sites.length === 1 ? 'The OpenSSL context' : `Each of the ${sites.length} OpenSSL contexts set up in this file`;
  return {
    ruleId: 'hs-tls-validate', label: 'MITIGATION', text: next,
    explanation: `${where} now loads the system CA locations (contextSetDefaultVerifyPaths) and requires a peer certificate that verifies against them (VerifyPeer True True Nothing) instead of VerifyNone${sites.length > 1 ? ` (${sites.length} sites, one per client function; the rule reports the class once per file)` : ''}.`,
    consequences: [
      'Connections to a server whose certificate is self-signed, expired or issued by an authority missing from the system store now fail.',
      'The host name is NOT verified by this change: HsOpenSSL checks it only through enableHostnameValidation on the SSL connection object, which this context-level code does not have, so a valid certificate issued for another host is still accepted.',
    ],
    behavior: { kind: 'tls-openssl', sites: sites.map((s, k) => ({ ctx: s.ctx, line: modeLines[k] })) },
    expectEffective: { kind: 'tls-openssl', sites: sites.map((s, k) => ({ ctx: s.ctx, line: modeLines[k] })) },   // each mode statement; the paths statement is the line above it
  };
}
function fixTls(text, f) {
  if (!importInfo(text, 'Network.Connection') && !importInfo(text, 'Network.Connection.Types')) return fixOpenSslVerify(text, f);   // the detector's own precondition
  const lb = lineBounds(text, f.line);
  const m = new RegExp(TLS_CTOR_RE.source).exec(lb.text);
  if (!m) return null;
  let i = lb.start + m.index + m[0].length;
  while (/\s/.test(text[i] || '')) i++;
  let at = -1; let form;
  if (text[i] === '{') {
    const end = braceEnd(text, i); if (end < 0) return null;
    const hits = [...text.slice(i, end).matchAll(new RegExp(`(?<![\\w'.])${TLS_FIELD}\\s*=\\s*(True)(?![\\w'.])`, 'g'))];
    if (hits.length !== 1) return null;
    at = i + hits[0].index + hits[0][0].lastIndexOf('True'); form = 'record';
  } else {
    const p = /^(\(\s*)?True(?![\w'.])/.exec(text.slice(i, i + 40));
    if (!p) return null;
    at = i + (p[1] ? p[1].length : 0); form = 'positional';
  }
  const next = splice(text, at, at + 4, 'False');
  const before = tlsSettingsOf(text); const after = tlsSettingsOf(next);
  const ordinal = before.filter((s) => s.start <= at).length - 1;
  return {
    ruleId: 'hs-tls-validate', label: 'FULL', text: next,
    explanation: `Set ${TLS_FIELD} to False (${form} form): TLS certificate validation is on again for this connection; nothing else in the settings changed.`,
    consequences: ['Connections to a server whose certificate is self-signed, expired, issued by an authority missing from the system trust store, or issued for another host name now fail. A private certificate authority must be added to the system trust store (or the settings built with TLSSettings and an explicit ClientParams) before this is deployed.'],
    behavior: { kind: 'tls', form, setting: TLS_FIELD, from: true, to: false },
    expectEffective: { kind: 'tls', ordinal, siteCount: before.length, expectSites: after.length },
  };
}

// ── cookie attributes (CWE-1004) ──────────────────────────────────────────────
// Four framework shapes, each a table row: a hand-written Set-Cookie header literal, a `Web.Cookie` SetCookie record update, servant-auth's
// `cookieIsSecure = NotSecure`, and scotty's `setSimpleCookie` / `makeSimpleCookie` (which build a cookie with neither attribute).
// APIs (checked against the package documentation): cookie `SetCookie { setCookieHttpOnly, setCookieSecure :: Bool, .. }`;
// servant-auth-server `CookieSettings { cookieIsSecure :: IsSecure }`, `data IsSecure = Secure | NotSecure`; scotty's `Web.Scotty.Cookie` re-exports
// `setCookie`, `makeSimpleCookie`, `setCookieHttpOnly`, `setCookieSecure`. SameSite is NOT touched.
const COOKIE_CONSEQ_SECURE = 'Secure: the browser sends the cookie over HTTPS only. A plain-HTTP deployment (or local development over HTTP, in browsers that do not exempt localhost) stops keeping the session.';
const COOKIE_CONSEQ_HTTPONLY = 'HttpOnly: page scripts can no longer read the cookie through document.cookie; code that does must be changed.';
const SET_COOKIE_KEY = /^(?:(?:[\w.]*\.)?hSetCookie|"[Ss]et-[Cc]ookie"|(?:[\w.]*\.)?(?:pack|fromString)\s+"[Ss]et-[Cc]ookie")$/;

/** The module qualifier written just before `idx` (`C.` or `A.B.`), or ''. Walks back by hand: no nested-quantifier pattern. */
function qualifierBefore(s, idx) {
  let i = idx;
  while (i > 1 && s[i - 1] === '.') {
    let j = i - 1;
    while (j > 0 && /[\w']/.test(s[j - 1])) j--;
    if (j === i - 1 || !/[A-Z]/.test(s[j])) break;
    i = j;
  }
  return s.slice(i, idx);
}

/** Every place a cookie is configured, with what the code says about its attributes: [{kind, start, end, httpOnly, secure}] in source order. */
export function cookieSitesOf(text) {
  const code = stripComments(text);
  const sites = [];
  // 1. a Set-Cookie header tuple on one line
  for (const m of code.matchAll(/\(\s*((?:[\w.]*\.)?hSetCookie|"[Ss]et-[Cc]ookie"|(?:[\w.]*\.)?(?:pack|fromString)\s+"[Ss]et-[Cc]ookie")\s*,/g)) {
    const end = atomEnd(code, m.index); if (end < 0 || code.slice(m.index, end).includes('\n')) continue;
    const lits = [...code.slice(m.index, end).matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1]).join('');
    sites.push({ kind: 'header', start: m.index, end, httpOnly: /;\s*HttpOnly\b/i.test(lits), secure: /;\s*Secure\b/i.test(lits) });
  }
  // 2. a record update that names setCookieName
  for (const m of code.matchAll(/(?<![\w'])setCookieName\s*=/g)) {
    let open = -1; let depth = 0;
    for (let j = m.index - 1; j >= 0; j--) { if (code[j] === '}') depth++; else if (code[j] === '{') { if (depth === 0) { open = j; break; } depth--; } }
    if (open < 0) continue;
    const end = braceEnd(code, open); if (end < 0) continue;
    const body = code.slice(open, end);
    const flag = (name) => new RegExp(`(?<![\\w'])(?:[A-Z][\\w']*\\.)?${name}\\s*=\\s*True(?![\\w'.])`).test(body);
    if (!sites.some((s) => s.kind === 'record' && s.start === open)) sites.push({ kind: 'record', start: open, end, httpOnly: flag('setCookieHttpOnly'), secure: flag('setCookieSecure') });
  }
  // 3. servant-auth
  for (const m of code.matchAll(/(?<![\w'])cookieIsSecure\s*=\s*((?:[A-Z][\w']*\.)?(?:Not)?Secure)(?![\w'])/g)) sites.push({ kind: 'servant', start: m.index, end: m.index + m[0].length, httpOnly: true, secure: !/NotSecure$/.test(m[1]) });
  // 4. scotty helpers; a call wrapped as `(makeSimpleCookie a b) { setCookieHttpOnly = True, setCookieSecure = True }` is already secured
  for (const m of code.matchAll(/(?<![\w'.])((?:[A-Z][\w']*\.)?)(setSimpleCookie|makeSimpleCookie)(?![\w'])/g)) {
    const a1 = atomEnd(code, m.index + m[0].length); const a2 = a1 < 0 ? -1 : atomEnd(code, a1);
    if (a2 < 0) continue;
    let after = a2; while (code[after] === ' ') after++;
    let httpOnly = false; let secure = false; let end = a2;
    if (m[2] === 'makeSimpleCookie' && code[after] === ')') {
      let k = after + 1; while (code[k] === ' ') k++;
      if (code[k] === '{') { const be = braceEnd(code, k); if (be > 0) { const body = code.slice(k, be); httpOnly = /setCookieHttpOnly\s*=\s*True(?![\w'.])/.test(body); secure = /setCookieSecure\s*=\s*True(?![\w'.])/.test(body); end = be; } }
    }
    sites.push({ kind: 'scotty-helper', start: m.index, end, httpOnly, secure });
  }
  return sites.sort((a, b) => a.start - b.start);
}

function lastLiteralAppend(valueExpr, missing) {
  // `"a=" <> sid <> "; Path=/"` -> the final operand must be a string literal; the attributes are appended inside its quotes
  const ops = splitOperators(valueExpr);
  if (!ops || ops.length < 1) return null;
  const last = ops[ops.length - 1];
  const t = last.trim();
  if (!STRING.test(t)) return null;
  const body = litValue(t);
  if (/;\s*$/.test(body) || /\\$/.test(body)) return null;           // a trailing separator or escape: the join would be ambiguous
  const idx = last.lastIndexOf(t);
  const patchedLit = `"${body}${missing.map((a) => `; ${a}`).join('')}"`;
  const ls = ops.slice(0, -1).join('') + last.slice(0, idx) + patchedLit + last.slice(idx + t.length);
  return ls;
}

function fixCookie(text, f) {
  const before = cookieSitesOf(text);
  if (!before.length) return null;
  const lb = lineBounds(text, f.line);
  // the site the finding is on: the first insecure site that starts within the reported statement (the site may span lines)
  const lineOf = (off) => text.slice(0, off).split('\n').length;
  const site = before.filter((s) => (!s.httpOnly || !s.secure) && lineOf(s.end) >= f.line && lineOf(s.start) <= f.line + 8).sort((a, b) => a.start - b.start)[0];
  if (!site) return null;
  const missing = [];
  if (!site.httpOnly) missing.push('HttpOnly'); if (!site.secure) missing.push('Secure');
  const consequences = [...(missing.includes('Secure') ? [COOKIE_CONSEQ_SECURE] : []), ...(missing.includes('HttpOnly') ? [COOKIE_CONSEQ_HTTPONLY] : []), 'SameSite is not changed by this fix.'];
  let next = null; let editAt = site.start; let how = site.kind;
  if (site.kind === 'header') {
    const seg = text.slice(site.start, site.end);
    const inner = seg.slice(1, -1);
    const parts = topLevelSplit(inner, ',');
    if (!parts || parts.length !== 2 || !SET_COOKIE_KEY.test(parts[0].trim())) return null;
    const val = lastLiteralAppend(parts[1], missing); if (val === null) return null;
    next = splice(text, site.start, site.end, `(${parts[0]},${val})`);
  } else if (site.kind === 'servant') {
    const mm = /NotSecure/.exec(text.slice(site.start, site.end)); if (!mm) return null;
    const imp = importInfo(text, 'Servant.Auth.Server');
    if (!imp || imp.hiding || (imp.items !== null && !imp.items.some((x) => /^IsSecure\(\.\.\)$/.test(x.replace(/\s+/g, ''))))) return null;     // `Secure` must already be in scope
    next = splice(text, site.start + mm.index, site.start + mm.index + 'NotSecure'.length, 'Secure');
    editAt = site.start + mm.index;
  } else if (site.kind === 'record') {
    const body = text.slice(site.start, site.end);
    const q = qualifierBefore(body, body.search(/(?<![\w'])setCookieName\s*=/));
    let b2 = body; const adds = [];
    for (const [flag, field] of [[site.httpOnly, 'setCookieHttpOnly'], [site.secure, 'setCookieSecure']]) {
      if (flag) continue;
      const re = new RegExp(`(?<![\\w'])((?:[A-Z][\\w']*\\.)?${field})(\\s*=\\s*)(False)(?![\\w'.])`);
      if (re.test(b2)) b2 = b2.replace(re, '$1$2True');
      else if (new RegExp(`(?<![\\w'])(?:[A-Z][\\w']*\\.)?${field}\\s*=`).test(b2)) return null;     // set from an expression: not a literal we can judge
      else adds.push(field);
    }
    let t2 = text;
    if (adds.length) {
      // the new field names must be in scope where the update is written: a module that exports them and is already imported
      let ok = false; let imported = text;
      for (const mod of ['Web.Cookie', 'Web.Scotty.Cookie']) {
        const info = importInfo(text, mod); if (!info) continue;
        if (info.hiding) return null;
        const allFields = info.items && info.items.some((x) => /^SetCookie\(\.\.\)$/.test(x.replace(/\s+/g, '')));
        const r = allFields ? { text: imported, prefix: info.qualified ? `${info.alias || mod}.` : '' } : ensureImport(imported, mod, adds); if (!r) return null;
        if (q && r.prefix && r.prefix !== q) continue;
        imported = r.text; ok = true; break;
      }
      if (!ok) return null;
      t2 = imported;
      const closeAt = b2.lastIndexOf('}');
      const head = b2.slice(0, closeAt).replace(/\s+$/, '');
      b2 = `${head}, ${adds.map((a) => `${q}${a} = True`).join(', ')} ${b2.slice(closeAt)}`;
    }
    const patched = splice(text, site.start, site.end, b2);
    next = t2 === text ? patched : applyImportDelta(text, t2, patched);
  } else if (site.kind === 'scotty-helper') {
    if (!importInfo(text, 'Web.Scotty.Cookie') || /^module\s+Web\.Scotty\.Cookie\b/m.test(text) || /^setCookie\b/m.test(text)) return null;
    const head = text.slice(site.start, site.end);
    const m = /^((?:[A-Z][\w']*\.)?)(setSimpleCookie|makeSimpleCookie)\s+/.exec(head); if (!m) return null;
    const nameEnd = atomEnd(text, site.start + m[0].length); const valEnd = nameEnd < 0 ? -1 : atomEnd(text, nameEnd);
    if (valEnd < 0) return null;
    const tail = text.slice(valEnd, text.indexOf('\n', valEnd) < 0 ? text.length : text.indexOf('\n', valEnd)).trim();
    const lineStart = text.lastIndexOf('\n', site.start) + 1;
    // The helper is written out as the record update it is (scotty's `makeSimpleCookie n v = defaultSetCookie { setCookieName = encodeUtf8 n,
    // setCookieValue = encodeUtf8 v }`, read from the scotty source): the wrapped form `(makeSimpleCookie n v) { .. }` is a shape the rule cannot
    // see through, and a rescan that cannot confirm the cookie is secured is not a verification.
    const nameArg = text.slice(site.start + m[0].length, nameEnd).trim(); const valArg = text.slice(nameEnd, valEnd).trim();
    const needed = ['defaultSetCookie', 'setCookieName', 'setCookieValue', 'setCookieHttpOnly', 'setCookieSecure', ...(m[2] === 'setSimpleCookie' ? ['setCookie'] : [])];
    const imp = ensureImport(text, 'Web.Scotty.Cookie', needed); if (!imp) return null;
    if (/(?<![\w'.])AgenticTE\./.test(text)) return null;
    const px = m[1] || imp.prefix;
    const rec = `${px}defaultSetCookie { ${px}setCookieName = AgenticTE.encodeUtf8 ${nameArg}, ${px}setCookieValue = AgenticTE.encodeUtf8 ${valArg}, ${px}setCookieHttpOnly = True, ${px}setCookieSecure = True }`;
    let repl;
    if (m[2] === 'setSimpleCookie') {
      if (tail !== '' || text.slice(lineStart, site.start).trim() !== '') return null;       // only a whole statement: `setSimpleCookie name value`
      repl = `${px}setCookie (${rec})`;
    } else repl = `(${rec})`;
    const patched = splice(text, site.start, valEnd, repl);
    const withImports = applyImportDelta(text, imp.text, patched);
    const ls = withImports.split('\n'); let lastImp = -1; ls.forEach((l, i) => { if (/^import\s/.test(l)) lastImp = i; });
    ls.splice(lastImp + 1, 0, 'import qualified Data.Text.Encoding as AgenticTE');
    next = ls.join('\n');
    how = m[2];
  }
  if (!next || next === text) return null;
  const sitesAfter = cookieSitesOf(next);
  const ordinal = before.indexOf(site);
  return {
    ruleId: 'hs-cookie-attributes', label: 'FULL', text: next,
    explanation: `Set ${missing.join(' and ')} on the cookie (${how} form). SameSite is not changed.`,
    consequences,
    behavior: { kind: 'cookie', form: how, add: missing },
    expectEffective: { kind: 'cookie', ordinal, siteCount: before.length, expectSites: sitesAfter.length, httpOnly: true, secure: true, editAt },
  };
}

// ── predictable randomness (CWE-338) ──────────────────────────────────────────
// Attempted ONLY where the generator is the entire value of a one-line action whose declared type is `IO <fixed-width integer>`:
//   newCsrfToken :: IO Word64        ->    newCsrfToken = foldl' (\acc b -> acc * 256 + fromIntegral b) 0 <$> getEntropy 8
//   newCsrfToken = randomIO
// and ONLY when the file already imports System.Entropy (the dependency is therefore already declared). `randomRIO (lo, hi)`, a range, a generator
// threaded through other code, a non-integer result and every other shape are refused: the result type of an OS CSPRNG differs from System.Random's.
const FIXED_WIDTH = { Word8: 1, Word16: 2, Word32: 4, Word64: 8, Word: 8, Int8: 1, Int16: 2, Int32: 4, Int64: 8, Int: 8 };
// The three shapes of 0.195.16 (each from a real site labelled TP: scotty's session id, gitit's session key, hackage-server's digest nonce):
//   replicateM N (randomRIO ('a', 'z'))                       -> N bytes, each mapped into the character range
//   randomRIO (lo, hi)  (integer literals)                     -> 8 bytes decoded big-endian, reduced into the range
//   (take N . map f . randomRs (lo, hi)) <$> newStdGen         -> N bytes, each reduced into the range and mapped by f
// The reduction is `b mod (hi - lo + 1)`: for a range that does not divide the byte space (26 letters, 10^9) the low values are chosen slightly
// more often (at most 2% for 26 of 256, negligible for 10^9 of 2^64), stated in the consequences; a rejection loop would need a different
// program shape. `System.Entropy` is imported when missing, which makes the patch a MITIGATION: the `entropy` package must be declared by
// the component, and only a build checks that.
const ENT_DECODE = "AgenticBS.foldl' (\\acc b -> acc * 256 + fromIntegral b) (0 :: Integer)";
function fixRandomLine(text, f) {
  const lb = lineBounds(text, f.line);
  const line = lb.text;
  const chr = (s) => (s.length === 3 ? s[1] : s === "'\\''" ? "'" : null);
  let m; let repl = null; let bytes = 0; let what = '';
  const used = [];
  if ((m = /(?<![\w'.])replicateM\s+(\d+)\s+\(\s*(?:System\.Random\.)?randomRIO\s+\(\s*('(?:[^'\\]|\\.)')\s*,\s*('(?:[^'\\]|\\.)')\s*\)\s*\)/.exec(line)) && chr(m[2]) !== null && chr(m[3]) !== null) {
    bytes = Number(m[1]); used.push('randomRIO');
    repl = `(map (\\b -> toEnum (fromEnum ${m[2]} + fromIntegral b \`mod\` (fromEnum ${m[3]} - fromEnum ${m[2]} + 1))) . AgenticBS.unpack <$> getEntropy ${bytes})`;
    what = `${bytes} characters in the range ${m[2]} to ${m[3]}`;
  } else if ((m = /(?<![\w'.])(?:System\.Random\.)?randomRIO\s+\(\s*(-?\d+)\s*,\s*(-?\d+)\s*\)/.exec(line))) {
    const lo = BigInt(m[1]); const hi = BigInt(m[2]);
    if (hi <= lo) return null;
    bytes = 8; used.push('randomRIO');
    repl = `((\\w -> ${m[1]} + fromIntegral (w \`mod\` ${(hi - lo + 1n).toString()})) . ${ENT_DECODE} <$> getEntropy 8)`;
    what = `an integer in the range ${m[1]} to ${m[2]}`;
  } else if ((m = /(?:fmap\s+\(\s*take\s+(\d+)\s*\.\s*map\s+([a-z_][\w'.]*)\s*\.\s*(?:System\.Random\.)?randomRs\s+\(\s*(-?\d+)\s*,\s*(-?\d+)\s*\)\s*\)\s+newStdGen|\(\s*take\s+(\d+)\s*\.\s*map\s+([a-z_][\w'.]*)\s*\.\s*(?:System\.Random\.)?randomRs\s+\(\s*(-?\d+)\s*,\s*(-?\d+)\s*\)\s*\)\s*<\$>\s*newStdGen)/.exec(line))) {
    const n = m[1] || m[5]; const fn = m[2] || m[6]; const lo = BigInt(m[3] || m[7]); const hi = BigInt(m[4] || m[8]);
    if (hi <= lo) return null;
    bytes = Number(n); used.push('randomRs', 'newStdGen');
    repl = `(map (${fn} . (\\b -> ${lo.toString()} + fromIntegral b \`mod\` ${(hi - lo + 1n).toString()})) . AgenticBS.unpack <$> getEntropy ${bytes})`;
    what = `${bytes} values in the range ${lo} to ${hi} mapped by ${fn}`;
  }
  if (!repl || !(bytes > 0)) return null;
  if (/\bAgenticBS\b/.test(text)) return null;
  const entropyWasImported = !!importInfo(text, 'System.Entropy');
  const e1 = ensureImport(text, 'System.Entropy', ['getEntropy']); if (!e1) return null;
  let t2 = e1.text;
  const lines = t2.split('\n'); let at = -1; stripComments(t2).split('\n').forEach((l, i) => { if (/^import\s/.test(l)) at = i; });
  if (at < 0) return null;
  lines.splice(at + 1, 0, 'import qualified Data.ByteString as AgenticBS');
  t2 = lines.join('\n');
  const newLineNo = f.line + (entropyWasImported ? 1 : 2);   // the edited line moved down by the import(s) inserted above it
  const lb2 = lineBounds(t2, newLineNo);
  if (lb2.text !== line) return null;
  const newLine = line.slice(0, m.index) + repl + line.slice(m.index + m[0].length);
  let out = splice(t2, lb2.start, lb2.end, newLine);
  // drop the System.Random names the file no longer uses (an unused import is an error under -Werror); the import goes when nothing is left
  const code = () => out.split('\n').filter((l) => !/^import\s/.test(l)).join('\n');
  const ri = importInfo(out, 'System.Random');
  if (ri && !ri.qualified && ri.items) {
    const keep = ri.items.filter((x) => !used.includes(x.replace(/\(.*$/, '').trim()) || new RegExp(`(?<![\\w'])${x.replace(/\(.*$/, '').trim()}(?![\\w'])`).test(code()));
    if (!keep.length) out = out.replace(ri.line + '\n', '');
    else if (keep.length !== ri.items.length) out = out.replace(ri.line, ri.line.replace(/\((.*)\)/, `(${keep.join(', ')})`));
  }
  const fnName = (() => { const ls = stripComments(text).split('\n'); let name = null; for (let i = 0; i < f.line; i++) { const mm = TOP_DECL.exec(ls[i] || ''); if (mm && !NOT_A_DEF.has(mm[1])) name = mm[1]; } return name; })();
  const finalLine = out.split('\n').indexOf(newLine) + 1;   // where the edited line sits once the unused import above it may have gone
  if (finalLine < 1) return null;
  return {
    ruleId: 'hs-random-os-entropy', label: entropyWasImported ? 'FULL' : 'MITIGATION', text: out,
    explanation: `${fnName || 'the action'} now draws ${what} from the operating system CSPRNG (System.Entropy.getEntropy, ${bytes} byte(s)) instead of System.Random's deterministic generator.`,
    consequences: [
      `Requires the \`entropy\` and \`bytestring\` packages to be declared by the component${entropyWasImported ? ' (this file already imported System.Entropy, so the first is)' : ' (the import of System.Entropy was ADDED: add `entropy` to build-depends)'}; the build is not checked against the cabal file.`,
      'Values are reduced into the range with a modulus, so for a range that does not divide the byte space the low values are drawn slightly more often (at most 2% for 26 letters over 256, negligible for an integer range over 2^64); the generated value is no longer predictable from a seed, which is what the finding is about.',
    ],
    behavior: { kind: 'random-line', fn: fnName, line: finalLine, bytes },
    expectEffective: { kind: 'random-line', line: finalLine, bytes },
  };
}
function fixRandom(text, f) {
  const lb = lineBounds(text, f.line);
  const m = /^([a-z_][\w']*)\s*=\s*(?:System\.Random\.)?randomIO\s*$/.exec(lb.text);
  if (!m) return fixRandomLine(text, f);
  const name = m[1];
  const sig = new RegExp(`^${name}\\s*::\\s*IO\\s+(${Object.keys(FIXED_WIDTH).join('|')})\\s*$`, 'm').exec(text);
  if (!sig) return null;
  if ((text.match(new RegExp(`^${name}\\s*=`, 'gm')) || []).length !== 1) return null;
  const bytes = FIXED_WIDTH[sig[1]];
  // Since 0.195.16 the import is added when missing (a MITIGATION: `entropy` must then be declared by the component).
  const ent = importInfo(text, 'System.Entropy'); if (ent && ent.hiding) return null;
  const e1 = ensureImport(text, 'System.Entropy', ['getEntropy']); if (!e1) return null;
  if (/(?<![\w'.])AgenticBS\./.test(text)) return null;
  let t2 = e1.text;
  const lines = t2.split('\n'); let at = -1; lines.forEach((l, i) => { if (/^import\s/.test(l)) at = i; });
  lines.splice(at + 1, 0, 'import qualified Data.ByteString as AgenticBS');
  t2 = lines.join('\n');
  const body = `${name} = AgenticBS.foldl' (\\acc b -> acc * 256 + fromIntegral b) 0 <$> ${e1.prefix}getEntropy ${bytes}`;
  const replaced = t2.replace(new RegExp(`^${name}\\s*=\\s*(?:System\\.Random\\.)?randomIO\\s*$`, 'm'), body);
  if (replaced === t2) return null;
  // the System.Random import loses `randomIO` when nothing else in the file uses it (an unused import is an error under -Werror)
  let out = replaced;
  const stillUsed = new RegExp(`(?<![\\w'])randomIO(?![\\w'])`).test(out.split('\n').filter((l) => !/^import\s/.test(l)).join('\n'));
  const ri = importInfo(out, 'System.Random');
  if (!stillUsed && ri && !ri.qualified && ri.items && ri.items.length === 1 && ri.items[0] === 'randomIO') out = out.replace(ri.line + '\n', '');
  else if (!stillUsed && ri && !ri.qualified && ri.items && ri.items.includes('randomIO')) out = out.replace(ri.line, ri.line.replace(/\((.*)\)/, (_, inner) => `(${ri.items.filter((x) => x !== 'randomIO').join(', ')})`));
  return {
    ruleId: 'hs-random-os-entropy', label: ent ? 'FULL' : 'MITIGATION', text: out,
    explanation: `${name} now reads ${bytes} byte(s) from the operating system CSPRNG (System.Entropy.getEntropy) and decodes them big-endian into ${sig[1]}, instead of System.Random's deterministic generator.${ent ? '' : ' The import of System.Entropy was added: add `entropy` to the component\'s build-depends.'}`,
    consequences: [`Requires the \`entropy\` and \`bytestring\` packages to be declared by the component (this file already imports System.Entropy, so the first is); the build is not checked against the cabal file.`, 'The value is uniform over the full range of its type; a caller that relied on a smaller range or on a seeded sequence changes behavior.'],
    behavior: { kind: 'random', fn: name, type: sig[1], bytes },
    expectEffective: { kind: 'random', fn: name, bytes },
  };
}

// ── request body size (CWE-770) ───────────────────────────────────────────────
// `strictRequestBody req` reads the whole body into memory. The mitigation replaces the call with a bounded reader defined in the same file
// (getRequestBodyChunk until the end, or until a fixed byte limit is passed, in which case it throws). The limit is NOT derived from the service:
// it is a declared default (1 MiB), written as a named constant the operator must review. Only the wai `strictRequestBody <Request variable>` shape.
const BODY_LIMIT_DEFAULT = 1048576;
const BODY_HELPER = `-- Upper bound, in bytes, for a request body read by boundedRequestBody. This is a default chosen by the fixer, not a measured need: set it for this service.
requestBodyLimitBytes :: Int
requestBodyLimitBytes = ${BODY_LIMIT_DEFAULT}

-- Reads a request body chunk by chunk and throws once more than requestBodyLimitBytes have arrived, instead of buffering without limit.
boundedRequestBody req = go 0 []
  where
    go total acc = do
      chunk <- AgentcW.getRequestBodyChunk req
      if AgentcBS.null chunk
        then pure (AgentcLBS.fromChunks (reverse acc))
        else do
          let total' = total + AgentcBS.length chunk
          if total' > requestBodyLimitBytes
            then AgentcE.throwIO (userError "request body exceeds requestBodyLimitBytes")
            else go total' (chunk : acc)
`;
export { BODY_HELPER };
function fixBody(text, f) {
  // The rule reports one finding per function, so fixing only the reported call would leave the next call of the same function as "the" finding. Every
  // `strictRequestBody <variable>` call in the file is rewritten, and the plan says how many.
  const code = stripComments(text);
  const hits = [...code.matchAll(/(?<![\w'])strictRequestBody\s+([a-z_][\w']*)(?![\w'])/g)].map((h) => { const q = qualifierBefore(code, h.index); return { index: h.index - q.length, end: h.index + h[0].length, variable: h[1] }; });
  const lineAt = (off) => text.slice(0, off).split('\n').length;
  if (!hits.some((h) => lineAt(h.index) === f.line)) return null;
  if (!importInfo(text, 'Network.Wai') || !importInfo(text, 'Data.ByteString.Lazy')) return null;      // wai and bytestring are then declared by this component
  if (hasPragma(text, 'NoImplicitPrelude') || /^import\s+(?:qualified\s+)?Prelude\s*(?:\(|hiding\b|as\b)/m.test(text)) return null;   // the helper uses reverse, pure and userError from the Prelude
  if (importInfo(text, 'Network.Wai').hiding) return null;
  const hasHelper = text.includes(BODY_HELPER);
  if (!hasHelper && /(?<![\w'.])(?:boundedRequestBody|requestBodyLimitBytes)(?![\w'])/.test(code)) return null;      // a name of ours is already taken
  let next = text;
  for (const h of hits.slice().reverse()) next = splice(next, h.index, h.end, `boundedRequestBody ${h.variable}`);
  if (!hasHelper) {
    const lines = next.split('\n'); let at = -1; lines.forEach((l, i) => { if (/^import\s/.test(l)) at = i; });
    if (at < 0) return null;
    lines.splice(at + 1, 0, 'import qualified Network.Wai as AgentcW', 'import qualified Data.ByteString as AgentcBS', 'import qualified Data.ByteString.Lazy as AgentcLBS', 'import qualified Control.Exception as AgentcE');
    next = lines.join('\n').replace(/\n*$/, '\n') + '\n' + BODY_HELPER;
  }
  const n = hits.length;
  return {
    ruleId: 'hs-request-body-bound', label: 'MITIGATION', text: next,
    explanation: `Replaced ${n} strictRequestBody call${n === 1 ? '' : 's'} with boundedRequestBody, which stops reading and throws once the body passes requestBodyLimitBytes (${BODY_LIMIT_DEFAULT} bytes, a declared default, not a measured need).`,
    consequences: [`A request body larger than ${BODY_LIMIT_DEFAULT} bytes now raises an IOException in the ${n} rewritten call${n === 1 ? '' : 's'} (a 500 from the default handler, not a 413). Legitimate large uploads are rejected until requestBodyLimitBytes is raised.`, 'The limit applies only to the calls rewritten; every other body read keeps its old behavior.'],
    behavior: { kind: 'body-limit', limit: BODY_LIMIT_DEFAULT, replaced: n },
    expectEffective: { kind: 'body', replaced: n },
  };
}

// ── HTML from text (CWE-79): scotty's `html` of concatenated text ─────────────
// `html $ mconcat ["<h1>", v, "</h1>"]`: scotty's `html` sends lazy Text as text/html, so a value concatenated into the markup IS markup. The
// rewrite applies an escaper DEFINED IN THE FILE (the five characters that open markup or end a quoted attribute) to every non-literal part of
// the concatenation, or to the whole argument when it is one expression that contains no literal and no renderer. A MITIGATION: a value inside
// a <script>, a style, a URL or an unquoted attribute is not made safe by this escaping, and markup the value deliberately carried is now shown
// as text. Only in a file importing Web.Scotty (or Web.Scotty.Trans) and Data.Text.Lazy (so `text` is declared by the component). The rescan
// recognises the escaper by the entities it spells out, never by its name (`htmlEscapers` in haskell-guards.js).
const HTML_TEXT_HELPER = `-- Escapes the five characters that open HTML markup or end a quoted attribute, so a value is shown as text. Covers HTML text and quoted
-- attribute values; not a script, a style, a URL or an unquoted-attribute context.
agenticEscapeHtml :: AgenticTL.Text -> AgenticTL.Text
agenticEscapeHtml = AgenticTL.concatMap escapeChar
  where
    escapeChar '<' = AgenticTL.pack "&lt;"
    escapeChar '>' = AgenticTL.pack "&gt;"
    escapeChar '&' = AgenticTL.pack "&amp;"
    escapeChar '"' = AgenticTL.pack "&quot;"
    escapeChar '\\'' = AgenticTL.pack "&#39;"
    escapeChar c = AgenticTL.singleton c
`;
export { HTML_TEXT_HELPER };
const HTML_TEXT_ESCAPER = 'agenticEscapeHtml';
const RENDERER = /(?<![\w'])(?:render\w*|toHtml|preEscaped\w*|toMarkup|unsafeByteString|html\w*)(?![\w'])/;
function fixHtmlText(text, f) {
  if (!/^import\s+(?:qualified\s+)?Web\.Scotty(?:\.Trans)?(?:\s|$|\()/m.test(text)) return null;
  const tl = importInfo(text, 'Data.Text.Lazy'); if (!tl || tl.hiding) return null;
  if (hasPragma(text, 'NoImplicitPrelude') || /^import\s+(?:qualified\s+)?Prelude\s*(?:\(|hiding\b|as\b)/m.test(text)) return null;
  const code = stripComments(text);
  const hasHelper = text.includes(HTML_TEXT_HELPER);
  if (!hasHelper && (new RegExp(`(?<![\\w'.])${HTML_TEXT_ESCAPER}(?![\\w'])`).test(code) || /(?<![\w'.])AgenticTL\./.test(text))) return null;      // a name of ours is already taken
  const lb = lineBounds(text, f.line);
  const call = findCall(lb.text, ['html']);
  if (!call) return null;
  let aStart = call.after; while (lb.text[aStart] === ' ') aStart++;
  let aEnd; let dollar = false;
  if (lb.text[aStart] === '$') { dollar = true; aStart++; while (lb.text[aStart] === ' ') aStart++; aEnd = lb.text.length; }
  else aEnd = atomEnd(lb.text, aStart);
  if (aEnd < 0 || aEnd <= aStart) return null;
  const arg = lb.text.slice(aStart, aEnd).trim();
  if (/\$/.test(arg) && !dollar) return null;
  const inner = trimParens(arg);
  if (!inner || STRING.test(inner)) return null;                                              // a literal alone is not a flow
  const wrap = (e) => (IDENT.test(e) ? `${HTML_TEXT_ESCAPER} ${e}` : `${HTML_TEXT_ESCAPER} (${e})`);
  let rebuilt = null; const wrapped = [];
  const cat = /^(?:mconcat|(?:[A-Z][\w']*\.)?concat)\s*\[([\s\S]*)\]$/.exec(inner);
  if (cat) {
    const parts = topLevelSplit(cat[1], ','); if (!parts) return null;
    const out = [];
    let literals = 0;
    for (const raw of parts) {
      const e = raw.trim();
      if (!e) return null;
      if (STRING.test(e)) { literals++; out.push(e); continue; }
      if (/"/.test(e) || RENDERER.test(e)) return null;                                         // a nested construction or a renderer: not judged
      if (new RegExp(`^${HTML_TEXT_ESCAPER}\\s`).test(e)) { out.push(e); continue; }               // already escaped
      out.push(wrap(e)); wrapped.push(e);
    }
    if (!wrapped.length || !literals) return null;                                            // nothing raw, or no markup to be concatenated into
    rebuilt = `${inner.slice(0, inner.indexOf('['))}[${out.join(', ')}]`;
  } else {
    if (/"/.test(inner) || RENDERER.test(inner) || /\bagenticEscapeHtml\b/.test(inner)) return null;
    rebuilt = wrap(inner); wrapped.push(inner);
  }
  const replaced = lb.text.slice(0, aStart) + (dollar ? rebuilt : `(${rebuilt})`) + lb.text.slice(aEnd);
  let next = splice(text, lb.start, lb.end, replaced);
  if (!hasHelper) {
    const lines = next.split('\n'); let at = -1; lines.forEach((l, i) => { if (/^import\s/.test(l)) at = i; });
    if (at < 0) return null;
    lines.splice(at + 1, 0, 'import qualified Data.Text.Lazy as AgenticTL');
    next = lines.join('\n').replace(/\n*$/, '\n') + '\n' + HTML_TEXT_HELPER;
  }
  const n = wrapped.length;
  return {
    ruleId: 'hs-html-escape-text', label: 'MITIGATION', text: next,
    explanation: `Applied ${HTML_TEXT_ESCAPER}, defined in this file, to ${n} value${n === 1 ? '' : 's'} (${wrapped.join(', ')}) before ${call.prefix}html sends the text as HTML: <, >, &, " and ' become entities, so the value is shown as text.`,
    consequences: [
      'Markup the value deliberately contained is now shown as text.',
      'The escaping covers HTML text and quoted attribute values. A value placed inside a <script> or <style> element, in a URL or in an unquoted attribute is not made safe by it; those contexts need their own encoding.',
      'Requires the `text` package to be declared by the component (this file already imports Data.Text.Lazy, so it is); the build is not checked against the cabal file.',
    ],
    behavior: { kind: 'html-text', escaper: HTML_TEXT_ESCAPER, wrapped },
    expectEffective: { kind: 'html-text', line: replaced, wrapped: n },
  };
}

// ── password hashing (CWE-916): the migration shape ───────────────────────────
// A password hashed with a fast digest cannot be swapped for a KDF on its line: every stored hash was made by the old function, and a swap locks
// every user out. The rewrite that keeps them in is a MIGRATION, written out in the file: the old function is kept verbatim under `<name>Legacy`
// (verification of stored hashes only), `<name>` becomes PBKDF2-HMAC-SHA256 over the same salt and password with a tag in front of the hex
// (`pbkdf2-sha256$600000$...`, so a stored hash says how it was made), `<name>NeedsRehash` reads the tag, and `<name>Verify stored salt pw`
// checks either form. Every `stored == <name> salt pw` comparison in the file becomes `<name>Verify stored salt pw`; the caller re-hashes at
// the next successful login when `<name>NeedsRehash` says so (that write is the caller's, not the patch's). Recognised ONLY where the
// migration can be shown to keep behavior:
//   - a one-line, top-level, pure definition `name a b = ...` of two plain parameters, one password-shaped and one salt-shaped, with a
//     signature `T -> T -> T` for one T among String, Text and (strict) ByteString;
//   - the file imports a module of cryptonite / crypton (`Crypto.Hash`, `Crypto.KDF.*`, ...), so `Crypto.KDF.PBKDF2` is in a declared package,
//     and `Data.Text` (String and Text forms: the bytes are the UTF-8 encoding) or `Data.ByteString` (ByteString form);
//   - no other file compares with the function (a comparison the patch cannot rewrite would lock those users out), and the four names are free.
// The iteration count (600000, the OWASP figure for PBKDF2-HMAC-SHA256) is a declared default the operator reviews, not a measured cost.
// The API is cryptonite's / crypton's, from the package documentation: `fastPBKDF2_SHA256 :: (ByteArrayAccess password, ByteArrayAccess salt,
// ByteArray out) => Parameters -> password -> salt -> out`, `data Parameters = Parameters { iterCounts :: Int, outputLength :: Int }`.
const KDF_ITERATIONS = 600000;
const KDF_TAG = `pbkdf2-sha256$${KDF_ITERATIONS}$`;
const KDF_LIB_IMPORT = /^import\s+(?:qualified\s+)?Crypto\.(?:Hash|KDF|MAC|Random|Cipher|Error|PubKey|Number)(?:\.|\s|$)/m;
const PASSWORD_PARAM = /pass(?:word|wd|phrase)?|pwd|^pw$|secret/i;
const SALT_PARAM = /salt|nonce|pepper/i;
const KDF_TYPES = Object.freeze({
  String: { bytes: (v) => `AgenticTE.encodeUtf8 (AgenticT.pack ${v})`, hex: (h) => h, tag: `"${KDF_TAG}"`, prefix: 'AgenticList.isPrefixOf', needs: 'Data.Text' },
  Text: { bytes: (v) => `AgenticTE.encodeUtf8 ${v}`, hex: (h) => `AgenticT.pack (${h})`, tag: `AgenticT.pack "${KDF_TAG}"`, prefix: 'AgenticT.isPrefixOf', needs: 'Data.Text' },
  ByteString: { bytes: (v) => v, hex: (h) => `AgenticBC.pack (${h})`, tag: `AgenticBC.pack "${KDF_TAG}"`, prefix: 'AgenticBS.isPrefixOf', needs: 'Data.ByteString' },
});
const KDF_IMPORTS = ['import qualified Crypto.KDF.PBKDF2 as AgenticPBKDF2', 'import qualified Data.ByteString as AgenticBS', 'import qualified Data.ByteString.Char8 as AgenticBC', 'import qualified Data.Text as AgenticT', 'import qualified Data.Text.Encoding as AgenticTE', 'import qualified Data.List as AgenticList'];
// The same migration where the file hashes with the `SHA` package and imports no cryptonite/crypton module (gitit's shape): PBKDF2-HMAC-SHA256
// for one 32-byte block (RFC 8018 section 5.2) is written out in the file over that package's HMAC, documented at SHA 1.6.4.4 as
// `hmacSha256 :: ByteString -> ByteString -> Digest SHA256State` and `bytestringDigest :: Digest t -> ByteString`, both over LAZY bytes. The
// construction is checked against the RFC 7914 section 11 vectors (the first 32 bytes of each) by `test/haskell/haskell-remediation-kdf.test.js`
// where the package is installed. The bytes of a String come from utf8-string (`Data.ByteString.Lazy.UTF8.fromString`) when the file imports a
// module of that package, else from `text`; a Text's from `text`; a strict ByteString's from `fromStrict`. The package is pure Haskell, so one
// hash at the declared count costs seconds of CPU, not tenths; the consequences say so.
const KDF_SHA_IMPORTS = ['import qualified Data.Digest.Pure.SHA as AgenticSHA', 'import qualified Data.ByteString.Lazy as AgenticBL', 'import qualified Data.Bits as AgenticBits', 'import qualified Data.List as AgenticList'];
const KDF_ALIASES = ['AgenticPBKDF2', 'AgenticBS', 'AgenticBC', 'AgenticT', 'AgenticTE', 'AgenticList', 'AgenticSHA', 'AgenticBL', 'AgenticBits', 'AgenticUTF8', 'AgenticTL', 'AgenticTLE'];
const TEXT_IMPORT = /^import\s+(?:qualified\s+)?Data\.Text(?:\.|\s|$)/m;

/** `stored == name a b` / `name a b == stored` on one line of code (atoms only); returns the rewritten line or null. */
function rewriteHashComparisons(lineText, name, verify) {
  const atom = `(?:[A-Za-z_][\\w'.]*|"(?:[^"\\\\]|\\\\.)*"|\\([^()]*\\))`;
  const call = `${name}\\s+(${atom})\\s+(${atom})`;
  let n = 0;
  let out = lineText.replace(new RegExp(`(?<![\\w'.])(${atom})\\s*==\\s*(?:${call}|\\(${call}\\))(?![\\w'])`, 'g'), (_, stored, a1, b1, a2, b2) => { n++; return `${verify} ${stored} ${a1 || a2} ${b1 || b2}`; });
  out = out.replace(new RegExp(`(?<![\\w'.])(?:${call}|\\(${call}\\))\\s*==\\s*(${atom})(?![\\w'.])`, 'g'), (_, a1, b1, a2, b2, stored) => { n++; return `${verify} ${stored} ${a1 || a2} ${b1 || b2}`; });
  return n ? { text: out, n } : null;
}

function fixPasswordKdf(text, f) {
  const lb = lineBounds(text, f.line);
  const def = /^([a-z_][\w']*)\s+([a-z_][\w']*)\s+([a-z_][\w']*)\s*=\s*(\S.*)$/.exec(lb.text);
  if (!def) return null;
  const [, name, p1, p2, body] = def;
  if (/(?<![\w'])(?:do|unsafePerformIO)(?![\w'])|<-/.test(body)) return null;                      // not a pure one-line definition
  const pwIdx = [p1, p2].findIndex((p) => PASSWORD_PARAM.test(p) && !SALT_PARAM.test(p));
  const saltIdx = [p1, p2].findIndex((p) => SALT_PARAM.test(p));
  if (pwIdx < 0 || saltIdx < 0 || pwIdx === saltIdx) return null;
  const sig = new RegExp(`^${name}\\s*::\\s*(\\S+)\\s*->\\s*(\\S+)\\s*->\\s*(\\S+)\\s*$`, 'm').exec(text);
  if (!sig) return null;
  const tyOf = (t) => { const m = /^(?:[A-Z][\w']*\.)?(String|Text|ByteString)$/.exec(t); return m ? m[1] : null; };
  const T = tyOf(sig[1]);
  if (!T || tyOf(sig[2]) !== T || tyOf(sig[3]) !== T) return null;
  let ty = KDF_TYPES[T];
  const code = stripComments(text);
  if ((code.match(new RegExp(`^${name}\\s+[a-z_]`, 'gm')) || []).length !== 1) return null;            // one clause, defined once
  // the KDF comes from a declared package: cryptonite/crypton (Crypto.KDF.PBKDF2), or the SHA package's HMAC with the derivation written out
  const shaPkg = importInfo(text, 'Data.Digest.Pure.SHA');
  const backend = KDF_LIB_IMPORT.test(text) ? 'crypton' : (shaPkg && !shaPkg.hiding ? 'sha' : null);
  if (!backend) return null;
  if (T === 'ByteString' && importInfo(text, 'Data.ByteString.Lazy') && !importInfo(text, 'Data.ByteString')) return null;   // a lazy ByteString: not the strict type the KDF takes
  let typeImports = [];       // the imports the bytes conversion of this type needs, on top of the backend's
  let bytesPackage = null;    // the package that conversion requires the component to declare
  if (backend === 'crypton') {
    if (!importInfo(text, ty.needs) && !(T !== 'ByteString' && importInfo(text, 'Data.Text.Encoding'))) return null;
    const pb = importInfo(text, 'Crypto.KDF.PBKDF2'); if (pb && pb.hiding) return null;
  } else if (T === 'String') {
    if (importInfo(text, 'Data.ByteString.Lazy.UTF8') || importInfo(text, 'Data.ByteString.UTF8')) { ty = { ...ty, bytes: (v) => `AgenticUTF8.fromString ${v}` }; typeImports = ['import qualified Data.ByteString.Lazy.UTF8 as AgenticUTF8']; bytesPackage = 'utf8-string'; }
    else if (TEXT_IMPORT.test(text)) { ty = { ...ty, bytes: (v) => `AgenticTLE.encodeUtf8 (AgenticTL.pack ${v})` }; typeImports = ['import qualified Data.Text.Lazy as AgenticTL', 'import qualified Data.Text.Lazy.Encoding as AgenticTLE']; bytesPackage = 'text'; }
    else return null;                                                                                   // no declared package turns a String into UTF-8 bytes
  } else if (T === 'Text') {
    if (!TEXT_IMPORT.test(text)) return null;
    ty = { ...ty, bytes: (v) => `AgenticTLE.encodeUtf8 (AgenticTL.fromStrict ${v})` }; typeImports = ['import qualified Data.Text as AgenticT', 'import qualified Data.Text.Lazy as AgenticTL', 'import qualified Data.Text.Lazy.Encoding as AgenticTLE']; bytesPackage = 'text';
  } else {
    ty = { ...ty, bytes: (v) => `AgenticBL.fromStrict ${v}` }; typeImports = ['import qualified Data.ByteString as AgenticBS', 'import qualified Data.ByteString.Char8 as AgenticBC'];
  }
  if (hasPragma(text, 'NoImplicitPrelude') || /^import\s+(?:qualified\s+)?Prelude\s*(?:\(|hiding\b|as\b)/m.test(text)) return null;
  const legacy = `${name}Legacy`, verify = `${name}Verify`, needs = `${name}NeedsRehash`, tagName = `${name}Tag`, hexName = `${name}Hex`, kdfName = `${name}Pbkdf2`;
  for (const nm of [legacy, verify, needs, tagName, hexName, ...(backend === 'sha' ? [kdfName] : [])]) if (new RegExp(`(?<![\\w'.])${nm}(?![\\w'])`).test(code)) return null;
  if (new RegExp(`(?<![\\w'.])(?:${KDF_ALIASES.join('|')})\\.`).test(text)) return null;
  // every comparison with the function, in this file, is rewritten; one in another file would be left comparing against the new form
  const lines = text.split('\n');
  const sigLine = lines.findIndex((l) => new RegExp(`^${name}\\s*::`).test(l));
  let compared = 0;
  const useRe = new RegExp(`(?<![\\w'.])${name}(?![\\w'])`);
  for (let i = 0; i < lines.length; i++) {
    if (i === f.line - 1 || i === sigLine || /^import\s/.test(lines[i])) continue;
    const r = rewriteHashComparisons(lines[i], name, verify);
    if (r) { lines[i] = r.text; compared += r.n; continue; }
    if (useRe.test(stripComments(lines[i])) && /==/.test(lines[i])) return null;                     // a comparison of a shape the rewrite does not cover
  }
  for (const [other, t] of Object.entries(f._files || {})) {
    if (other === f.file || typeof t !== 'string' || !/\.l?hs$/i.test(other)) continue;
    if (t.split('\n').some((l) => !/^import\s/.test(l) && useRe.test(stripComments(l)) && /==/.test(l))) return null;
  }
  const pw = pwIdx === 0 ? p1 : p2, salt = saltIdx === 0 ? p1 : p2;
  const hexOf = backend === 'crypton'
    ? `${hexName} (AgenticPBKDF2.fastPBKDF2_SHA256 (AgenticPBKDF2.Parameters { AgenticPBKDF2.iterCounts = ${KDF_ITERATIONS}, AgenticPBKDF2.outputLength = 32 }) (${ty.bytes(pw)}) (${ty.bytes(salt)}))`
    : `${hexName} (${kdfName} (${ty.bytes(pw)}) (${ty.bytes(salt)}))`;
  const bytesModule = backend === 'crypton' ? 'AgenticBS' : 'AgenticBL';
  // the original signature stays where it is, above the new definition; the kept function gets its own
  const block = [
    `-- PBKDF2-HMAC-SHA256, ${KDF_ITERATIONS} iterations (a declared default: review the cost for this service), tagged so a stored hash says how it was made.`,
    `${name} ${p1} ${p2} = ${tagName} <> ${ty.hex(hexOf)}`,
    '',
    `${tagName} :: ${sig[3]}`,
    `${tagName} = ${ty.tag}`,
    '',
    ...(backend === 'sha' ? [
      `-- PBKDF2-HMAC-SHA256 (RFC 8018 section 5.2) for one 32-byte block, over the SHA package's HMAC: U1 = HMAC(password, salt || 00 00 00 01), U(i) = HMAC(password, U(i-1)), and the key is the xor of U1 .. U(${KDF_ITERATIONS}).`,
      `${kdfName} :: AgenticBL.ByteString -> AgenticBL.ByteString -> AgenticBL.ByteString`,
      `${kdfName} password salt = AgenticList.foldl' xorBytes u1 (take (${KDF_ITERATIONS} - 1) (tail (iterate prf u1)))`,
      '  where',
      '    prf = AgenticSHA.bytestringDigest . AgenticSHA.hmacSha256 password',
      '    u1 = prf (AgenticBL.append salt (AgenticBL.pack [0, 0, 0, 1]))',
      '    xorBytes a b = AgenticBL.pack (AgenticBL.zipWith AgenticBits.xor a b)',
      '',
    ] : []),
    `${hexName} :: ${bytesModule}.ByteString -> String`,
    `${hexName} = ${bytesModule}.foldr (\\w acc -> hexDigit (w \`div\` 16) : hexDigit (w \`mod\` 16) : acc) ""`,
    `  where hexDigit d = "0123456789abcdef" !! fromIntegral d`,
    '',
    `-- Kept, under a new name, for passwords stored before the migration: ${verify} checks a stored hash with it when ${needs} says so.`,
    `${legacy} :: ${sig[1]} -> ${sig[2]} -> ${sig[3]}`,
    `${legacy} ${p1} ${p2} = ${body}`,
    '',
    `-- True for a hash made by ${legacy}: verify it with ${verify}, then store ${name} of the password at the next successful login.`,
    `${needs} :: ${sig[3]} -> Bool`,
    `${needs} stored = not (${tagName} \`${ty.prefix}\` stored)`,
    '',
    `-- Checks a password against a stored hash of either form, in place of \`stored == ${name} ${salt} ${pw}\`.`,
    `${verify} :: ${sig[3]} -> ${sig[1]} -> ${sig[2]} -> Bool`,
    `${verify} stored ${p1} ${p2} = if ${needs} stored then stored == ${legacy} ${p1} ${p2} else stored == ${name} ${p1} ${p2}`,
  ];
  lines.splice(f.line - 1, 1, ...block);
  let at = -1; lines.forEach((l, i) => { if (/^import\s/.test(l)) at = i; });
  if (at < 0) return null;
  lines.splice(at + 1, 0, ...(backend === 'crypton' ? KDF_IMPORTS : [...KDF_SHA_IMPORTS, ...typeImports]));
  let next = lines.join('\n');
  // an export list that names the function exports the helpers too: a caller in another module needs the verify helper
  const hdr = /^module\s+[\w.']+\s*\(/m.exec(next);
  if (hdr) {
    const open = hdr.index + hdr[0].length - 1;
    const close = atomEnd(next, open);
    if (close > 0 && /^\s*where/.test(next.slice(close))) {
      const list = next.slice(open + 1, close - 1);
      if (useRe.test(list)) next = next.slice(0, open + 1) + list.replace(useRe, `${name}, ${legacy}, ${verify}, ${needs}`) + next.slice(close - 1);
    }
  }
  return {
    ruleId: 'hs-password-kdf-migrate', label: 'MITIGATION', text: next,
    explanation: `${name} now computes PBKDF2-HMAC-SHA256 (${KDF_ITERATIONS} iterations, 32 bytes, over the same salt and password${backend === 'sha' ? `, written out in ${kdfName} over the SHA package's hmacSha256` : ''}) and tags the result; the old function is kept as ${legacy} for verification only, ${verify} checks a stored hash of either form, and ${needs} says which hashes to re-hash at the next successful login. ${compared} comparison${compared === 1 ? '' : 's'} in this file now call${compared === 1 ? 's' : ''} ${verify}.`,
    consequences: [
      backend === 'crypton'
        ? `Requires cryptonite or crypton (Crypto.KDF.PBKDF2; this file already imports a module of that package), bytestring and text to be declared by the component; the build is not checked against the cabal file.`
        : `Requires the SHA package (Data.Digest.Pure.SHA; this file already imports it)${bytesPackage ? `, bytestring and ${bytesPackage}` : ' and bytestring'} to be declared by the component; the build is not checked against the cabal file. ${kdfName} is the RFC 8018 construction written out over that package's HMAC, not a library KDF: review it, or replace it with a KDF package once one is declared.`,
      `A new password is stored in the tagged PBKDF2 form; a stored hash of the old form still verifies through ${legacy}, so no user is locked out, and it stays in the old form until the caller re-hashes it (store ${name} of the password when ${needs} is True after a successful login). ${compared === 0 ? `No comparison with ${name} was found in this file: a caller elsewhere that compares with == must call ${verify} instead.` : ''}`.trim(),
      backend === 'crypton'
        ? `Each hash now costs ${KDF_ITERATIONS} HMAC-SHA256 iterations (tenths of a second per attempt, by design); the count is a declared default, not a measured cost for this service. The comparison in ${verify} is the same == the original used, not a constant-time one.`
        : `Each hash now costs ${KDF_ITERATIONS} HMAC-SHA256 iterations. The SHA package is pure Haskell, so at this count one hash costs seconds of CPU per attempt, not tenths (a C-backed KDF package is faster by an order of magnitude); the count is a declared default, not a measured cost for this service, and lowering it weakens the hash. The comparison in ${verify} is the same == the original used, not a constant-time one.`,
    ],
    behavior: { kind: 'kdf', fn: name, legacy, verify, needs, type: T, iterations: KDF_ITERATIONS, rewrittenComparisons: compared, backend, ...(backend === 'sha' ? { kdf: kdfName } : {}) },
    expectEffective: { kind: 'kdf', fn: name, legacy, verify, needs, type: T, rewrittenComparisons: compared, backend, ...(backend === 'sha' ? { kdf: kdfName } : {}) },
  };
}

// ── scotty request body limit (CWE-770) ───────────────────────────────────────
// scotty's `body` reads the whole request body. The bound scotty offers is application-wide: `setMaxRequestBodySize :: Kilobytes -> ScottyM ()`
// (scotty 0.12 and later; a request past it gets a 413 before any handler runs). The mitigation adds ONE call, as the first statement of the
// ScottyM block that builds the application this handler belongs to: the block that contains the read (an inline route), or the block in this
// file that names the handler function. The limit is a declared default (1 MiB) written as a named constant the operator must review. Refused:
// a block in another file (the rule can then only say "a limit exists somewhere"), a `do` that keeps a statement on its own line, a name of ours
// already taken, and a cabal file whose scotty bound excludes every version from 0.12 on.
const SCOTTY_LIMIT_KB = 1024;
const SCOTTY_LIMIT_CONST = 'agenticRequestBodyLimitKb';
const SCOTTY_LIMIT_ALIAS = 'AgenticScotty';
const SCOTTY_LIMIT_DEF = `-- Upper bound, in kilobytes, for any request body this application accepts: a request past it is answered 413 before a handler runs. This is a default chosen by the fixer, not a measured need: set it for this service.
${SCOTTY_LIMIT_CONST} :: Int
${SCOTTY_LIMIT_CONST} = ${SCOTTY_LIMIT_KB}
`;
export { SCOTTY_LIMIT_DEF, SCOTTY_LIMIT_KB };
const SCOTTY_VERSIONS_WITH_LIMIT = ['0.12', '0.12.1', '0.20', '0.21', '0.22', '0.30', '0.31'];
const TOP_DECL = /^([a-z_][\w']*)\b/;
const NOT_A_DEF = new Set(['import', 'module', 'data', 'type', 'newtype', 'class', 'instance', 'where', 'infix', 'infixl', 'infixr', 'foreign', 'default', 'deriving', 'pattern']);
// The ScottyM blocks of a file: `main = scotty 3000 $ do`, `app = scottyOpts opts $ do`, or `app :: ScottyM ()` with `app = do`. Each block:
// the top-level function that holds it, the line of its `do`, and the indentation of its first statement.
function scottyBlocksOf(code) {
  const ls = code.split('\n');
  const starts = []; ls.forEach((l, i) => { const m = TOP_DECL.exec(l); if (m && !NOT_A_DEF.has(m[1])) starts.push({ line: i, name: m[1] }); });
  const fnAt = (i) => { let cur = null; for (const s of starts) { if (s.line <= i) cur = s; else break; } return cur ? cur.name : null; };
  const sigs = new Set(); ls.forEach((l) => { const m = /^([a-z_][\w']*)\s*::\s*ScottyM\s*\(\)\s*$/.exec(l); if (m) sigs.add(m[1]); });
  const out = [];
  ls.forEach((l, i) => {
    const inline = /(?:^|[\s$(])(?:[A-Z][\w']*\.)?scotty(?:Opts|T|OptsT|App|AppT)?\b[^\n]*\$\s*do\s*$/.test(l);
    const named = (() => { const m = /^([a-z_][\w']*)\s*=\s*do\s*$/.exec(l); return !!(m && sigs.has(m[1])); })();
    if (!inline && !named) return;
    let j = i + 1; while (j < ls.length && ls[j].trim() === '') j++;
    if (j >= ls.length) return;
    const indent = /^(\s*)/.exec(ls[j])[1];
    if (!indent.length || ls[j].trim().startsWith('where')) return;
    out.push({ fn: fnAt(i), doLine: i, firstStatement: j, indent });
  });
  return { blocks: out, fnAt };
}
// The scotty bound every cabal file in the tree declares, judged against the versions that have the limit: null when no bound is declared.
function scottyBoundExcludesLimit(files) {
  for (const [name, text] of Object.entries(files || {})) {
    if (!/\.cabal$/i.test(name) || typeof text !== 'string') continue;
    let parsed = null; try { parsed = parseCabalFile(text); } catch { parsed = null; }
    for (const c of (parsed && parsed.components) || []) for (const d of c.dependencies || []) {
      if (!d || d.name !== 'scotty' || !d.range) continue;
      let admits = false;
      for (const v of SCOTTY_VERSIONS_WITH_LIMIT) { try { if (versionSatisfies({ ok: true, ast: d.range }, v)) { admits = true; break; } } catch { admits = true; break; } }
      if (!admits) return { file: name, rangeText: d.rangeText || '' };
    }
  }
  return null;
}
function fixScottyBody(text, f) {
  if (!/Web\.Scotty(?:\.Trans)?\.body\b/.test(String(f.description || f.detail || ''))) return null;
  const trans = !importInfo(text, 'Web.Scotty') && importInfo(text, 'Web.Scotty.Trans');
  if (!importInfo(text, 'Web.Scotty') && !trans) return null;
  const code = stripComments(text);
  if (new RegExp(`(?<![\\w'.])(?:${SCOTTY_LIMIT_CONST}|setMaxRequestBodySize)(?![\\w'])`).test(code) || new RegExp(`\\b${SCOTTY_LIMIT_ALIAS}\\b`).test(code)) return null;
  const { blocks, fnAt } = scottyBlocksOf(code);
  if (!blocks.length) return null;
  const holder = fnAt(f.line - 1);
  let block = blocks.find((b) => b.fn && b.fn === holder) || null;
  if (!block && holder) {
    const ls = code.split('\n');
    const starts = []; ls.forEach((l, i) => { const m = TOP_DECL.exec(l); if (m && !NOT_A_DEF.has(m[1])) starts.push(i); });
    const spanOf = (b) => { const s = b.doLine; let e = ls.length; for (const i of starts) if (i > s) { e = i; break; } return ls.slice(s, e).join('\n'); };
    const naming = blocks.filter((b) => new RegExp(`(?<![\\w'.])${holder}(?![\\w'])`).test(spanOf(b)));
    if (naming.length === 1) block = naming[0];
  }
  if (!block) return null;
  const excluded = scottyBoundExcludesLimit(f._files);
  if (excluded) return null;
  const lines = text.split('\n');
  const statement = `${block.indent}${SCOTTY_LIMIT_ALIAS}.setMaxRequestBodySize ${SCOTTY_LIMIT_CONST}`;
  lines.splice(block.firstStatement, 0, statement);
  // the last import of the CODE: an `import` inside a block comment (a commented-out alternative main) is not one
  let at = -1; stripComments(lines.join('\n')).split('\n').forEach((l, i) => { if (/^import\s/.test(l)) at = i; });
  if (at < 0) return null;
  lines.splice(at + 1, 0, `import qualified ${trans ? 'Web.Scotty.Trans' : 'Web.Scotty'} as ${SCOTTY_LIMIT_ALIAS}`);
  const next = lines.join('\n').replace(/\n*$/, '\n') + '\n' + SCOTTY_LIMIT_DEF;
  const insertedLine = block.firstStatement + 2;   // 1-based, after the import line added above it
  const bound = (() => { for (const [name, t] of Object.entries(f._files || {})) if (/\.cabal$/i.test(name) && typeof t === 'string' && /\bscotty\b/.test(t)) return name; return null; })();
  return {
    ruleId: 'hs-scotty-body-limit', label: 'MITIGATION', text: next,
    explanation: `Added setMaxRequestBodySize ${SCOTTY_LIMIT_CONST} (${SCOTTY_LIMIT_KB} KB, a declared default, not a measured need) as the first statement of the ScottyM block in \`${block.fn || 'the application'}\`, which ${block.fn === holder ? 'contains this body read' : `registers \`${holder}\``}.`,
    consequences: [
      `Every route of the application built in \`${block.fn || 'this block'}\` now answers a request whose body exceeds ${SCOTTY_LIMIT_KB} KB with a 413 before the handler runs; legitimate large uploads are rejected until ${SCOTTY_LIMIT_CONST} is raised.`,
      `Requires scotty 0.12 or later (setMaxRequestBodySize); ${bound ? `the bound declared in ${bound} admits such a version, and the build is not checked against it` : 'no cabal file in the tree declares a scotty bound, so the version is not checked'}.`,
    ],
    behavior: { kind: 'scotty-body-limit', fn: block.fn, kb: SCOTTY_LIMIT_KB, line: insertedLine },
    expectEffective: { kind: 'scotty-body-limit', line: insertedLine, statement },
  };
}

const FIXERS = [
  { id: 'hs-scotty-body-limit', applies: (f) => f.rule === 'hs-unbounded-request-body' && /Web\.Scotty(?:\.Trans)?\.body\b/.test(String(f.description || f.detail || '')), run: fixScottyBody, reportedLineOnly: true },
  { id: 'hs-password-kdf-migrate', applies: (f) => f.cwe === 'CWE-916' && (f.rule === 'hs-fast-password-hash' || f.rule === 'hs-pbkdf2-low-iterations' || /fast general-purpose hash|too few iterations/i.test(String(f.vuln || ''))), run: fixPasswordKdf },
  { id: 'hs-tls-validate', applies: (f) => f.cwe === 'CWE-295' || f.rule === 'hs-tls-validation-disabled', run: fixTls, reportedLineOnly: true },
  { id: 'hs-cookie-attributes', applies: (f) => f.cwe === 'CWE-1004' || f.rule === 'hs-insecure-cookie', run: fixCookie, reportedLineOnly: true },
  { id: 'hs-random-os-entropy', applies: (f) => f.cwe === 'CWE-338' || f.rule === 'hs-predictable-random', run: fixRandom, reportedLineOnly: true },
  { id: 'hs-request-body-bound', applies: (f) => f.rule === 'hs-unbounded-request-body' || (f.cwe === 'CWE-770' && /request body/i.test(String(f.vuln || ''))), run: fixBody, reportedLineOnly: true },
  { id: 'hs-sql-parameterize', applies: (f) => f.cwe === 'CWE-89', run: fixSql },
  { id: 'hs-process-argv', applies: (f) => f.cwe === 'CWE-78', run: fixProcess },
  { id: 'hs-html-escape', applies: (f) => f.cwe === 'CWE-79', run: fixHtml },
  { id: 'hs-html-escape-text', applies: (f) => f.cwe === 'CWE-79', run: fixHtmlText, reportedLineOnly: true },
  { id: 'hs-hash-sha256', applies: (f) => f.cwe === 'CWE-328' || f.rule === 'hs-weak-hash', run: fixWeakHash },
  { id: 'hs-log-redact', applies: (f) => f.cwe === 'CWE-532' || f.rule === 'hs-sensitive-logging', run: fixLogging },
  { id: 'hs-xml-no-entity-substitution', applies: (f) => f.cwe === 'CWE-611' || f.rule === 'hs-xml-entity-substitution', run: fixXmlEntities, reportedLineOnly: true },
  { id: 'hs-path-takefilename', applies: (f) => f.cwe === 'CWE-22', run: fixPath },
  { id: 'hs-path-contain', applies: (f) => f.cwe === 'CWE-22', run: fixPathContain, reportedLineOnly: true },
];
export const SUPPORTED_FIX_IDS = Object.freeze(FIXERS.map((x) => x.id));

/**
 * Plan a deterministic fix for one finding. Pure: reads `files`, returns the new text of the one file.
 * @returns {{ok:true,ruleId,label,file,before,after,explanation,behavior}|{ok:false,reason,proposal?}}
 */
/** Lines inside the bodies of top-level functions of `text` that are called on line `line` (1-based), nearest definition first. */
function calleeLines(text, line) {
  const lines = text.split('\n');
  const here = lines[line - 1] || '';
  const defs = new Map();                                     // name -> [first body line, last body line] (1-based)
  const isTop = (l) => /^[a-z_][\w']*\s+.*=|^[a-z_][\w']*\s*=|^[a-z_][\w']*\s*::/.test(l);
  for (let i = 0; i < lines.length; i++) {
    const m = /^([a-z_][\w']*)\b[^:\n]*=/.exec(lines[i]);
    if (!m || /^[a-z_][\w']*\s*::/.test(lines[i])) continue;
    let end = i; while (end + 1 < lines.length && (/^\s+\S/.test(lines[end + 1]) || lines[end + 1].trim() === '') && !isTop(lines[end + 1])) end++;
    if (!defs.has(m[1])) defs.set(m[1], [i + 1, end + 1]);
  }
  const out = [];
  for (const [name, [a, b]] of defs) {
    if (a <= line && line <= b) continue;                     // the function the finding is in
    if (new RegExp(`(?<![\\w'.])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w'])`).test(here)) for (let l = a; l <= b; l++) out.push(l);
  }
  return out;
}

export function planHaskellFix(finding, files) {
  if (!finding || !finding.file || !Number.isInteger(finding.line)) return { ok: false, reason: 'finding has no file and line' };
  const before = files[finding.file];
  if (typeof before !== 'string') return { ok: false, reason: `file ${finding.file} is not in the supplied tree` };
  if (!/\.l?hs$/i.test(finding.file)) return { ok: false, reason: 'not a Haskell source file' };
  if (/\{-#\s*LANGUAGE[^#]*\bCPP\b|^#\s*(?:if|define|include)\b/m.test(before)) {
    const cls = CLASS_REASONS[finding.cwe]; const marker = 'The decision needed:';
    const classDecision = cls && cls.includes(marker) ? cls.slice(cls.indexOf(marker) + marker.length).trim() : null;
    const decision = `${classDecision ? `${classDecision} Also, ` : ''}which build configuration (platform, compiler, flags) the patch is for, because a rewrite of a CPP file could change a branch that is not visible here.`;
    return { ok: false, tier: TIERS.guidance, reason: `the file uses CPP: a rewrite could change a branch that is not visible here. The decision needed: ${decision}`, decision, proposal: 'model-assisted' };
  }
  for (const fx of FIXERS) {
    let applies = false; try { applies = fx.applies(finding); } catch { /* ignore */ }
    if (!applies) continue;
    // The finding is reported where the tainted value ENTERS the code that reaches the sink: for a flow through a function of this
    // file that is the call, while the dangerous API call is inside the callee. Try the reported line first, then the bodies of
    // the same-file functions called on it.
    // An attribute, a generator or a limit is fixed where the finding says it is, never in the body of a function called on that line (that would change a
    // helper for all of its callers: the scotty cookie helpers, for instance, are the library's own definitions).
    for (const line of fx.reportedLineOnly ? [finding.line] : [finding.line, ...calleeLines(before, finding.line)]) {
      let r = null; try { r = fx.run(before, { ...finding, line, _files: files }); } catch { r = null; }
      if (r && r.text && r.text !== before) return { ok: true, tier: TIERS.edit, ruleId: r.ruleId, label: r.label, file: finding.file, before, after: r.text, explanation: r.explanation, consequences: r.consequences || DEFAULT_CONSEQUENCES[r.ruleId] || [], behavior: r.behavior, expectEffective: r.expectEffective || null, ...(line !== finding.line ? { fixedAtLine: line } : {}) };
    }
  }
  const reason = CLASS_REASONS[finding.cwe] || 'no deterministic fix is supported for this exact shape. The decision needed: what correct handling of this value is for this code (validate it, encode it for the sink it reaches, or stop it reaching the sink); the scanner has no verified rewrite for this shape.';
  const marker = 'The decision needed:';
  return { ok: false, tier: TIERS.guidance, reason, decision: reason.includes(marker) ? reason.slice(reason.indexOf(marker) + marker.length).trim() : null, proposal: 'model-assisted' };
}

export const TIERS = Object.freeze({ edit: 'full-source-edit', guidance: 'guidance-only', blocked: 'blocked' });
// What each rewrite changes for the running program, stated so a patch never silently alters behavior (the fixers added with the
// remediation work carry their own, which also name the build requirements).
const DEFAULT_CONSEQUENCES = Object.freeze({
  'hs-sql-parameterize': ['Interpolated values are now bound parameters. A splice that is not a value (a table or column name, an operator, a keyword) cannot be a parameter and needs an allow-list instead.'],
  'hs-process-argv': ['No shell parses the command any more: pipes, redirection, globbing, variable expansion and quoting in the old string no longer apply, and the program is found by name on PATH.'],
  'hs-html-escape': ['Markup the value deliberately contained is now shown as text.'],
  'hs-hash-sha256': ['Every digest this code produces changes. Anything that stored or compares the old digests (a stored hash, a cache key, a signature) must be migrated.'],
  'hs-log-redact': ['The redacted value no longer appears in the log; the line loses that detail.'],
  'hs-path-takefilename': ['A name that carried subdirectories now selects a file directly inside the fixed directory; "." and ".." survive takeFileName, so directory operations are not rewritten.'],
});

// Classes whose repair needs a choice the code does not contain (a policy, a library, a limit). The scanner reports them; it does not guess.
// Each reason ends with "The decision needed: ..." naming what the operator has to decide; planHaskellFix returns that part as `decision`.
export const CLASS_REASONS = Object.freeze({
  'CWE-918': 'server-side request forgery has no line-level repair: a check on the URL string is bypassed by redirects, alternate encodings and DNS. The decision needed: which hosts or networks this service may call (an allow-list of exact hosts, or an address policy that rejects loopback, link-local and private ranges after name resolution and on every redirect).',
  'CWE-78': 'a shell command string is replaced by a direct call of the program with an argument list. The recognised shape is callCommand/system/spawnCommand of a ++ or <> concatenation (String, or Text under cs/unpack, on the line or in a one-line let of the same function) whose first word is a string literal naming the program. The decision needed: when the program itself is a variable (an editor or tool chosen through an environment variable, say), how that value splits into a program and its own arguments, because a configured command such as "code --goto" is not one program name; and for an argument built with if/case or a function call, the exact argument list.',
  'CWE-88': 'argument injection is repaired by a rule about what the called program accepts; inserting "--" only helps programs that honour it, so no patch is made. The decision needed: the permitted values for this argument (a closed list or a strict pattern), or the option of that program that ends option parsing.',
  'CWE-916': 'password hashing needs a password KDF (Argon2id, scrypt, bcrypt, or PBKDF2 with a high iteration count) from a library the project may not declare as a dependency, and every stored hash was produced by the old function: swapping it makes every existing password fail to verify and locks the users out. The one shape rewritten is a migration: a pure one-line `name salt password = ...` of one text type (String, Text or strict ByteString) in a file that already imports cryptonite or crypton (with Data.Text or Data.ByteString), or the SHA package (with utf8-string or text for the bytes of a String), whose comparisons all sit in this file; it keeps the old function for verification, adds PBKDF2-HMAC-SHA256 (the library KDF, or the RFC 8018 construction written out over the SHA package\'s HMAC) and a verify helper, and this is not that shape. The decision needed: which KDF and library, with which cost parameters, and the migration (verify the old hash once, then re-hash with the new KDF at the next successful login, or force a password reset).',
  'CWE-248': 'a partial function on caller-supplied input (an index with !!, head, fromJust, read) has no rewrite that keeps the function\'s type: the total form needs a value for the failure, and the code does not say which. The decision needed: what the function returns when the input is out of range or does not parse (an error response from the handler that read the input, an unchanged result, a default), and where that check belongs (at the read, so the handler answers the caller, or before the index).',
  'CWE-327': 'a broken cipher or ECB mode is replaced by an AEAD (AES-GCM or ChaCha20-Poly1305), which changes the stored form: everything encrypted so far must be re-encrypted or read through the old cipher once, and the nonce and authentication tag need a place beside the ciphertext. The decision needed: the AEAD and key size, the migration of the ciphertext already stored, and where the nonce and tag are kept.',
  'CWE-329': 'a static IV or nonce is replaced by a fresh random one per message, which then has to travel with the ciphertext: the decrypting side must read it from there, and the messages encrypted so far carry none. The decision needed: where the IV is stored or sent (in front of the ciphertext, a separate field) and how the decrypting code tells an old message from a new one.',
  'CWE-338': 'a predictable generator is replaced by the operating system CSPRNG (System.Entropy or Crypto.Random), whose result type is bytes, not System.Random\'s: the surrounding code must change with it. Four shapes are rewritten (System.Entropy imported when missing, which makes the patch a MITIGATION until `entropy` is declared): a one-line action of type IO <fixed-width integer> equal to randomIO; `replicateM n (randomRIO (c1, c2))` over a character range; `randomRIO (lo, hi)` over integer literals; `(take n . map f . randomRs (lo, hi)) <$> newStdGen`. Any other shape (a generator threaded through other code, a non-literal range, a non-integer result) is not. The decision needed: the token\'s type and size (a 30-bit integer cannot be made unguessable by changing the generator) and the entropy library the project declares.',
  'CWE-1004': 'cookie attributes live in different places per framework. The recognised shapes are a Set-Cookie header string literal, a Web.Cookie SetCookie record update, servant-auth cookieIsSecure, and scotty setSimpleCookie/makeSimpleCookie; this is none of them, or an attribute is set from an expression. The decision needed: which attributes to send (Secure, HttpOnly, SameSite) and whether this cookie must work over plain HTTP.',
  'CWE-306': 'a missing authentication check needs a policy; the scanner reports the handler and does not invent the guard. The decision needed: which credential authenticates this route (session, token, API key) and what an unauthenticated caller receives (401, a redirect to login).',
  'CWE-770': 'a resource limit is a number only the operator can choose (how many bytes a body may have, how many requests, how large an allocation). Two shapes are recognised, each with a declared default: wai strictRequestBody of a Request variable in a file importing Network.Wai and Data.ByteString.Lazy, which gets a bounded reader, and scotty body in a file whose ScottyM block contains the read or names the handler, which gets setMaxRequestBodySize as that block\'s first statement (scotty 0.12 and later; refused when the block is in another file or a cabal bound excludes those versions); this is neither shape. The decision needed: the limit for this input, and what happens past it (reject with 413, truncate, spool to disk).',
  'CWE-295': 'enabling certificate validation can break connections the project depends on. Only the connection package\'s TLSSettingsSimple with a literal True is flipped. An HsOpenSSL `contextSetVerificationMode ctx VerifyNone` statement is rewritten to load the default CA locations and require a verified peer (a mitigation: the host name is still unchecked). The decision needed: the trust store (the system store, a pinned CA bundle, a private authority) and host-name verification.',
  'CWE-798': 'a hard-coded secret must be rotated and moved to a secret store; rewriting the line would leave the leaked value valid. The decision needed: where the secret is read from at run time (environment, a secrets manager, a file outside the repository) and rotating the exposed value, which no edit of this file can do.',
  'CWE-611': 'XML entity handling depends on the parser configuration in use. The decision needed: whether this document source is trusted and which entity and DTD features the parser may enable.',
  'CWE-22': 'path traversal is repaired by confining the final path to a base directory. takeFileName is applied only to a String/FilePath parameter spliced under a fixed directory in a file operation, and a guard equation rejecting ".." segments and absolute paths is added only to a function with exactly one String/FilePath parameter and a Maybe result (bare or under one monad); this shape (a base chosen at run time, several path parameters, a result with no not-found value, a path handed through other functions) is neither. The decision needed: the directory the files must stay in, and whether a name containing separators or ".." is rejected or reduced to its last segment.',
  'CWE-79': 'output encoding depends on the context the value is written into (HTML text, attribute, script, URL) and on the library that renders it; only blaze-html\'s preEscapedToHtml and scotty\'s html of concatenated text are rewritten (the latter with an escaper defined in the file, for HTML text and quoted attribute values). The decision needed: render the value through the project\'s escaping HTML library, or send it as text/plain.',
  'CWE-601': 'an open redirect is repaired by restricting where the redirect may go. The decision needed: the permitted destinations (an allow-list of hosts, or relative paths only).',
});

// ── gates ────────────────────────────────────────────────────────────────────
const key = (f) => `${f.file}|${f.cwe || ""}`;

/** Default rescan: the real scanner over the patched tree, in a scratch directory (never the user's). */
export async function defaultRescan(files) {
  const { runScan } = await import('../runScan.js');
  const dir = mkdtempSync(join(tmpdir(), 'hs-fix-'));
  try {
    for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
    const r = await runScan(dir, { deep: true });
    // a flow the proof gate discharged (a dominating guard, a sanitizer) is reported but is not still a finding, and neither is a finding the
    // engine LOWERED to information for a reason it states (`originalSeverity`: a recognised guard, an operator-controlled origin; the legacy
    // verifier of a password-hash migration): the same `actionable` rule the benches score by. A finding that is `info` in its own right (an MD5
    // whose use is not visible) is still counted, so a fix of it can still be shown to have removed it.
    const lowered = (f) => f.severity === 'info' && (f.originalSeverity || (f.evidence && f.evidence.legacyVerifier === true));
    return (r.scan.findings || []).filter((f) => !(f.proof && /^proven-/.test(f.proof.verdict)) && !lowered(f));
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

export function syntaxGate(file, before, after) {
  const a = parseHaskell(before, { file }); const b = parseHaskell(after, { file });
  const nb = (a.errors || []).length, na = (b.errors || []).length;
  return { ok: na <= nb, errorsBefore: nb, errorsAfter: na, detail: na <= nb ? 'no new syntax errors' : `${na - nb} new syntax error(s)` };
}

const _ghcProbe = new Map();
function probeGhc(ghc) {
  if (_ghcProbe.has(ghc)) return _ghcProbe.get(ghc);
  const probe = spawnSync(ghc, ['--numeric-version'], { encoding: 'utf8', timeout: 20000 });
  const ok = !probe.error && probe.status === 0;
  _ghcProbe.set(ghc, ok);
  return ok;
}

/** The `-i` root a file implies from its `module A.B.C` header and its path (src/A/B/C.hs -> src). */
function sourceRootOf(file, text) {
  const m = /^module\s+([A-Z][\w'.]*)/m.exec(String(text || ''));
  if (!m || /\.\.|\.$/.test(m[1])) return null;
  const tail = `${m[1].replace(/\./g, '/')}.hs`;
  return file === tail ? '.' : (file.endsWith(`/${tail}`) ? file.slice(0, file.length - tail.length - 1) : null);
}

function ghcTypeCheck(ghc, tree, targets, timeoutMs) {
  const dir = mkdtempSync(join(tmpdir(), 'hs-compile-'));
  try {
    for (const [f, t] of Object.entries(tree)) if (/\.l?hs$/i.test(f) && typeof t === 'string') { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
    const roots = new Set(['src', '.']);
    for (const f of targets) { const r = sourceRootOf(f, tree[f]); if (r) roots.add(r); }
    const r = spawnSync(ghc, ['-fno-code', ...[...roots].map((x) => `-i${x}`), ...targets], { cwd: dir, encoding: 'utf8', timeout: timeoutMs });
    return { status: r.status, stderr: String(r.stderr || '') };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

/**
 * Compile check is OPT-IN. `opts.compile` must be true AND a ghc must exist; otherwise the result says it did not run (never a pass).
 * `opts.targets` limits the files handed to GHC (their local imports are found through the source roots); default is every .hs file.
 * `opts.baseline` is the tree BEFORE the patch: a patched tree that fails to type-check is only a failure of the patch when the original
 * type-checks on this host. When the original does not (a package this host lacks, a source directory GHC was not told about), or when the
 * patch imports a module this host lacks, nothing can be concluded and the gate reports `ran:false`, not a pass and not a failure.
 */
export function compileGate(files, opts = {}) {
  if (opts.compile !== true) return { ran: false, ok: null, detail: 'not requested (default static scans never start GHC)' };
  const ghc = opts.ghc || 'ghc';
  if (!probeGhc(ghc)) return { ran: false, ok: null, detail: 'GHC is not available on this host; compile verification was not performed' };
  const hsAll = Object.keys(files).filter((f) => /\.hs$/i.test(f));
  const targets = (opts.targets && opts.targets.length ? opts.targets.filter((f) => /\.hs$/i.test(f) && f in files) : hsAll);
  if (!targets.length) return { ran: false, ok: null, detail: 'no .hs file to type-check' };
  const timeoutMs = opts.timeoutMs || 120000;
  const r = ghcTypeCheck(ghc, files, targets, timeoutMs);
  if (r.status === 0) return { ran: true, ok: true, detail: 'type-checked' };
  if (opts.baseline) {
    const missing = /Could not find module\s+[‘'`]([^’'`]+)[’'`]/.exec(r.stderr);
    const b = ghcTypeCheck(ghc, opts.baseline, targets.filter((f) => f in opts.baseline), timeoutMs);
    if (b.status !== 0) return { ran: false, ok: null, detail: `the original does not type-check on this host either (${(b.stderr.split('\n').find((l) => /error/i.test(l)) || b.stderr).trim().slice(0, 160)}), so the patch could not be judged by compiling` };
    if (missing) return { ran: false, ok: null, detail: `the patch uses module ${missing[1]}, which is not installed on this host; the patch was not type-checked` };
  }
  return { ran: true, ok: false, detail: r.stderr.slice(0, 400) };
}

// ── the effective-change check ────────────────────────────────────────────────
// A rescan going quiet proves only that the finding stopped being REPORTED. This reads the value back from the patched file with readers that
// are independent of the editor (`tlsSettingsOf`, `cookieSitesOf`, the call counts) and requires the intended attribute to be the one that changed.
export function haskellEffectiveCheck(plan, patched) {
  const want = plan.expectEffective;
  if (!want) return { ok: true, ran: false, detail: 'not an attribute fix' };
  const after = patched[plan.file];
  if (typeof after !== 'string') return { ok: false, ran: true, detail: 'the patched file is not in the tree' };
  const before = plan.before;
  if (want.kind === 'tls') {
    const b = tlsSettingsOf(before); const a = tlsSettingsOf(after);
    if (a.length !== b.length) return { ok: false, ran: true, detail: `the number of TLS settings changed (${b.length} to ${a.length})` };
    const at = want.ordinal;
    if (!(b[at] && b[at].disableCertificateValidation === true)) return { ok: false, ran: true, detail: 'the planned site did not disable validation before the patch' };
    if (a[at].disableCertificateValidation !== false) return { ok: false, ran: true, detail: `${TLS_FIELD} reads ${JSON.stringify(a[at].disableCertificateValidation)} after the patch, not False` };
    for (let i = 0; i < b.length; i++) if (i !== at && (b[i].disableCertificateValidation !== a[i].disableCertificateValidation || JSON.stringify(b[i].others) !== JSON.stringify(a[i].others))) return { ok: false, ran: true, detail: `another TLS setting changed (site ${i})` };
    if (JSON.stringify(b[at].others) !== JSON.stringify(a[at].others)) return { ok: false, ran: true, detail: 'the other settings of the edited site changed' };
    return { ok: true, ran: true, detail: `${TLS_FIELD} reads False at the edited site and nothing else changed` };
  }
  if (want.kind === 'cookie') {
    const b = cookieSitesOf(before); const a = cookieSitesOf(after);
    if (a.length !== b.length) return { ok: false, ran: true, detail: `the number of cookie sites changed (${b.length} to ${a.length})` };
    const at = want.ordinal;
    if (!a[at] || !(a[at].httpOnly && a[at].secure)) return { ok: false, ran: true, detail: `the edited cookie still reads HttpOnly=${a[at] && a[at].httpOnly} Secure=${a[at] && a[at].secure} after the patch` };
    for (let i = 0; i < b.length; i++) if (i !== at && (b[i].httpOnly !== a[i].httpOnly || b[i].secure !== a[i].secure || b[i].kind !== a[i].kind)) return { ok: false, ran: true, detail: `another cookie site changed (site ${i})` };
    return { ok: true, ran: true, detail: 'the edited cookie reads HttpOnly and Secure after the patch and no other cookie changed' };
  }
  if (want.kind === 'random') {
    const defLine = (t) => (stripComments(t).split('\n').find((l) => new RegExp(`^${want.fn}\\s*=`).test(l)) || '');
    const d = defLine(after);
    if (/randomIO|System\.Random/.test(d)) return { ok: false, ran: true, detail: 'the action still calls System.Random' };
    if (!new RegExp(`getEntropy\\s+${want.bytes}\\s*$`).test(d)) return { ok: false, ran: true, detail: `the action does not read ${want.bytes} entropy byte(s)` };
    return { ok: true, ran: true, detail: `${want.fn} reads ${want.bytes} byte(s) from getEntropy and no longer calls System.Random` };
  }
  if (want.kind === 'tls-openssl') {
    const ls = stripComments(after).split('\n');
    for (const s of want.sites) {
      const set = ls[s.line - 1] || ''; const paths = ls[s.line - 2] || '';
      if (!new RegExp(`contextSetVerificationMode\\s+${s.ctx}\\s+\\((?:[A-Z][\\w']*\\.)?VerifyPeer True True Nothing\\)\\s*$`).test(set)) return { ok: false, ran: true, detail: `line ${s.line}: the context is not set to VerifyPeer True True Nothing` };
      if (!new RegExp(`contextSetDefaultVerifyPaths\\s+${s.ctx}\\s*$`).test(paths)) return { ok: false, ran: true, detail: `line ${s.line}: the context does not load the default CA locations before the mode is set` };
    }
    const none = (t) => (stripComments(t).match(/(?<![\w'])VerifyNone(?![\w'])/g) || []).length;   // qualified uses count too
    if (none(after) !== none(before) - want.sites.length) return { ok: false, ran: true, detail: `the patch did not remove exactly ${want.sites.length} VerifyNone` };
    return { ok: true, ran: true, detail: `${want.sites.map((s) => s.ctx).join(', ')} load the default CA locations and require a verified peer certificate (${want.sites.length} site(s); host name not checked by this patch)` };
  }
  if (want.kind === 'hxt-entities') {
    const l = stripComments(after).split('\n')[want.line - 1] || '';
    if (!/(?<![\w'.])withSubstDTDEntities\s+(?:(?:[A-Z][\w']*\.)?no|False)(?![\w'])/.test(l)) return { ok: false, ran: true, detail: 'the line does not set withSubstDTDEntities to no' };
    const yes = (t) => (stripComments(t).match(/withSubstDTDEntities\s+(?:(?:[A-Z][\w']*\.)?yes|True)(?![\w'])/g) || []).length;
    if (yes(after) !== yes(before) - 1) return { ok: false, ran: true, detail: 'the patch did not turn off exactly one entity substitution' };
    return { ok: true, ran: true, detail: `line ${want.line} no longer substitutes DTD entities` };
  }
  if (want.kind === 'path-contain') {
    const re = new RegExp(`^${want.fn} ${want.param}\\n\\s+\\| "\\.\\." \`elem\` (?:[A-Z][\\w']*\\.)?splitDirectories ${want.param} \\|\\| (?:[A-Z][\\w']*\\.)?isAbsolute ${want.param} = ${want.fail.replace(/ /g, '\\s+')}\\s*$`, 'm');
    if (!re.test(stripComments(after))) return { ok: false, ran: true, detail: `no guard equation on ${want.fn} rejects a ".." segment or an absolute ${want.param}` };
    const eqs = (t) => stripComments(t).split('\n').filter((l) => new RegExp(`^${want.fn}(?![\\w'])`).test(l) && !new RegExp(`^${want.fn}\\s*::`).test(l)).length;
    if (eqs(after) !== eqs(before) + 1) return { ok: false, ran: true, detail: 'the patch did not add exactly one equation' };
    return { ok: true, ran: true, detail: `${want.fn} answers ${want.fail} for a ".." segment or an absolute ${want.param} before its body runs` };
  }
  if (want.kind === 'random-line') {
    const d = (stripComments(after).split('\n')[want.line - 1] || '');
    if (/randomRIO|randomRs|newStdGen|randomIO|System\.Random/.test(d)) return { ok: false, ran: true, detail: 'the line still calls System.Random' };
    if (!new RegExp(`getEntropy\\s+${want.bytes}(?![\\d])`).test(d)) return { ok: false, ran: true, detail: `the line does not read ${want.bytes} entropy byte(s)` };
    return { ok: true, ran: true, detail: `line ${want.line} reads ${want.bytes} byte(s) from getEntropy and no longer calls System.Random` };
  }
  if (want.kind === 'scotty-body-limit') {
    const count = (t, re) => (stripComments(t).match(re) || []).length;
    const limits = (t) => count(t, /(?<![\w'])(?:[A-Z][\w']*\.)?setMaxRequestBodySize(?![\w'])/g);
    const bodies = (t) => count(t, /(?<![\w'.])body(?![\w'])/g);
    if (limits(after) !== limits(before) + 1) return { ok: false, ran: true, detail: 'exactly one setMaxRequestBodySize call should have been added' };
    const ls = stripComments(after).split('\n');
    if (ls[want.line - 1] !== want.statement) return { ok: false, ran: true, detail: `the limit is not the statement at line ${want.line} as planned` };
    if (bodies(after) !== bodies(before)) return { ok: false, ran: true, detail: 'the body reads changed; the patch should only add the limit' };
    if (!new RegExp(`^${SCOTTY_LIMIT_CONST}\\s*=\\s*${SCOTTY_LIMIT_KB}\\b`, 'm').test(after)) return { ok: false, ran: true, detail: 'the declared limit is not the one the patch states' };
    return { ok: true, ran: true, detail: `setMaxRequestBodySize is the first statement of the application block, with the declared constant (${SCOTTY_LIMIT_KB} KB), and no body read changed` };
  }
  if (want.kind === 'body') {
    const count = (t, re) => (stripComments(t).match(re) || []).length;
    const calls = (t) => count(t, /(?<![\w'])(?:[A-Z][\w']*\.)?strictRequestBody(?![\w'])/g);
    if (calls(after) !== calls(before) - want.replaced) return { ok: false, ran: true, detail: `exactly ${want.replaced} strictRequestBody call(s) should have been replaced` };
    if (!after.includes(BODY_HELPER)) return { ok: false, ran: true, detail: 'the bounded reader is not defined in the patched file' };
    if (!new RegExp(`requestBodyLimitBytes\\s*=\\s*${BODY_LIMIT_DEFAULT}\\b`).test(after)) return { ok: false, ran: true, detail: 'the declared limit is not the one the patch states' };
    return { ok: true, ran: true, detail: `${want.replaced} strictRequestBody call(s) were replaced by the bounded reader, whose limit is the declared constant` };
  }
  if (want.kind === 'html-text') {
    const code = stripComments(after);
    if (!code.split('\n').includes(want.line)) return { ok: false, ran: true, detail: 'the rewritten html call is not in the patched file as planned' };
    if (!after.includes(HTML_TEXT_HELPER)) return { ok: false, ran: true, detail: 'the escaper is not defined in the patched file' };
    const uses = (t) => (stripComments(t).split('\n').filter((l) => !new RegExp(`^${HTML_TEXT_ESCAPER}\\s`).test(l)).join('\n').match(new RegExp(`(?<![\\w'.])${HTML_TEXT_ESCAPER}(?![\\w'])`, 'g')) || []).length;
    if (uses(after) - uses(before) !== want.wrapped) return { ok: false, ran: true, detail: `exactly ${want.wrapped} value(s) should have been wrapped; ${uses(after) - uses(before)} were` };
    return { ok: true, ran: true, detail: `${want.wrapped} value(s) pass through the file's escaper before the html call and the escaper spells out the entities` };
  }
  if (want.kind === 'kdf') {
    const code = stripComments(after); const ls = code.split('\n');
    const defs = (nm) => ls.filter((l) => new RegExp(`^${nm}\\s+[a-z_][\\w']*\\s+[a-z_][\\w']*\\s*=`).test(l));
    if (defs(want.legacy).length !== 1) return { ok: false, ran: true, detail: `${want.legacy} is not defined exactly once` };
    const oldBody = (stripComments(before).split('\n').find((l) => new RegExp(`^${want.fn}\\s+[a-z_][\\w']*\\s+[a-z_][\\w']*\\s*=`).test(l)) || '').replace(/^[^=]*=\s*/, '');
    if (!oldBody || defs(want.legacy)[0].replace(/^[^=]*=\s*/, '') !== oldBody) return { ok: false, ran: true, detail: `${want.legacy} is not the original definition kept verbatim` };
    const nd = defs(want.fn);
    // the written-out construction (SHA package): the function calls it, and its definition reads back as the iterated HMAC at the planned count
    const writtenOut = want.backend === 'sha' && nd.length === 1 && new RegExp(`(?<![\\w'.])${want.kdf}(?![\\w'])`).test(nd[0])
      && ls.some((l) => new RegExp(`^${want.kdf}\\s+password\\s+salt\\s*=\\s*AgenticList\\.foldl' xorBytes u1 \\(take \\(${KDF_ITERATIONS} - 1\\) \\(tail \\(iterate prf u1\\)\\)\\)\\s*$`).test(l))
      && ls.some((l) => /^\s+prf = AgenticSHA\.bytestringDigest \. AgenticSHA\.hmacSha256 password\s*$/.test(l));
    const library = want.backend !== 'sha' && nd.length === 1 && new RegExp(`fastPBKDF2_SHA256 .*iterCounts = ${KDF_ITERATIONS}\\b`).test(nd[0]);
    if (!writtenOut && !library) return { ok: false, ran: true, detail: `${want.fn} does not compute PBKDF2-HMAC-SHA256 with ${KDF_ITERATIONS} iterations` };
    const vd = ls.filter((l) => new RegExp(`^${want.verify}\\s+stored\\s`).test(l));
    if (vd.length !== 1 || !new RegExp(`${want.needs} stored then stored == ${want.legacy} .* else stored == ${want.fn} `).test(vd[0])) return { ok: false, ran: true, detail: `${want.verify} does not check both forms` };
    const comparisons = (t) => (stripComments(t).split('\n').filter((l) => !new RegExp(`^${want.verify}\\s`).test(l)).join('\n').match(new RegExp(`==\\s*\\(?${want.fn}\\s|${want.fn}\\s+\\S+\\s+\\S+\\)?\\s*==`, 'g')) || []).length;
    const verifyCalls = ls.filter((l) => !/^module\s/.test(l) && !new RegExp(`^${want.verify}\\s`).test(l) && new RegExp(`(?<![\\w'.])${want.verify}(?![\\w'])`).test(l)).length;
    if (comparisons(after) !== 0 || verifyCalls !== want.rewrittenComparisons) return { ok: false, ran: true, detail: `expected ${want.rewrittenComparisons} comparison(s) with ${want.fn} to call ${want.verify}; ${comparisons(after)} comparison(s) remain and ${verifyCalls} call it` };
    return { ok: true, ran: true, detail: `${want.legacy} keeps the original definition, ${want.fn} computes PBKDF2-HMAC-SHA256 with ${KDF_ITERATIONS} iterations, ${want.verify} checks both forms and the ${want.rewrittenComparisons} comparison(s) call it` };
  }
  return { ok: false, ran: true, detail: `unknown effective check ${want.kind}` };
}

/**
 * Validate (and optionally apply) a fix. Nothing is written unless every gate passes and `apply` is true.
 * @param {object} finding
 * @param {{files: Record<string,string>, root?: string, apply?: boolean, rescan?: Function, compile?: boolean, requireCompile?: boolean, behaviorCheck?: Function}} o
 */
export async function validateHaskellFix(finding, o) {
  const plan = planHaskellFix(finding, o.files);
  if (!plan.ok) return { status: 'unsupported', applied: false, ...plan };
  const res = await runFixLifecycle({
    plan, files: o.files, finding, matchKey: key, rescan: o.rescan || defaultRescan,
    syntax: (p) => syntaxGate(p.file, p.before, p.after), behaviorCheck: o.behaviorCheck, effectiveCheck: haskellEffectiveCheck, witness: o.witness, requireWitness: o.requireWitness,
    compile: (patched) => compileGate(patched, { ...o, baseline: o.files, targets: [plan.file] }), requireCompile: o.requireCompile, apply: o.apply, root: o.root,
  });
  return { ...res, consequences: plan.consequences || [], tier: res.status === 'blocked' ? TIERS.blocked : plan.tier, explanation: plan.explanation };
}

/**
 * Verify a patch SUPPLIED BY SOMEONE ELSE (a user, a model) through the same gates as a deterministic fix: path, syntax,
 * the original finding gone, no new medium-or-higher finding, and a compile check when asked. Nothing is written. `proposal` is the new text of
 * `file`. Reached from `agentic-security fix <id> --proposal <file>` (see `languageProposalPreview` in context.js).
 */
export async function verifyHaskellProposal(finding, { files, file, proposal, rescan, compile, requireCompile }) {
  const before = files[file];
  const plan = { file, before: typeof before === 'string' ? before : '', after: proposal, label: 'WORKAROUND' };
  return runFixLifecycle({
    plan, files, finding, matchKey: key, rescan: rescan || defaultRescan, syntax: (p) => syntaxGate(p.file, p.before, p.after),
    compile: (patched) => compileGate(patched, { compile, baseline: files, targets: [file] }), requireCompile, apply: false,
  });
}

export { unifiedDiff, writeWithBackup, undoFix };

// ── dependency upgrades ──────────────────────────────────────────────────────
const GENERATED = /(?:^|\/)(?:plan\.json|stack\.yaml\.lock|cabal\.project\.local|package-lock\.json)$|dist-newstyle\//;
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Propose an upgrade of ONE dependency to a version that fixes an advisory, by editing the declaring line.
 * `verifyResolved(files)` is the only way the proposal can become `fixed`: it must return
 * `{ok:true, resolvedVersion}` from a supported resolver run. With none, the proposal is `unverified`.
 */
export function planHaskellUpgrade(finding, files, { verifyResolved = null } = {}) {
  const fail = (status, reason, extra = {}) => ({ ok: false, status, reason, ...extra });
  const name = finding.name; const fixed = (finding.fixedIn || []).filter((v) => parseVersion(v)).sort(compareVersions)[0];
  if (!name || !fixed) return fail('blocked', finding.unfixed ? `no fixed version of ${name} is published` : 'the advisory names no fixed version');
  if (GENERATED.test(finding.file || '')) return fail('blocked', 'a generated plan/lock is evidence, not a source of truth: edit the declared constraint and re-resolve');
  const text = files[finding.file];
  if (typeof text !== 'string' || !Number.isInteger(finding.line)) return fail('blocked', 'the declaring line is unknown');
  const lb = lineBounds(text, finding.line);
  const re = new RegExp(`(?<![\\w-])(${escapeRe(name)})(?![\\w-])(\\s*)((?:\\^>=|>=|<=|==|<|>)[^,\\n]*)?`);
  const m = re.exec(lb.text);
  if (!m) return fail('blocked', `could not locate ${name} on line ${finding.line} of ${finding.file}`);
  const old = (m[3] || '').trim();
  let range;
  if (/^==\s*\d/.test(old) && !/\*/.test(old)) range = `== ${fixed}`;
  else {
    const upper = /<\s*(\d+(?:\.\d+)*)/.exec(old);
    if (upper && compareVersions(fixed, upper[1]) >= 0) return fail('blocked', `the fix ${fixed} is outside the declared upper bound < ${upper[1]}; the bound itself must be reviewed`);
    range = upper ? `>= ${fixed} && < ${upper[1]}` : `>= ${fixed}`;
  }
  const lead = lb.text.slice(0, m.index); const trail = lb.text.slice(m.index + m[0].length);
  const edited = `${lead}${m[1]} ${range}${trail}`;
  const next = splice(text, lb.start, lb.end, edited);
  const patched = { ...files, [finding.file]: next };
  const base = { ok: true, file: finding.file, line: finding.line, before: text, after: next, from: old || '(unbounded)', to: range, scopePreserved: true, preview: unifiedDiff(finding.file, text, next) };
  if (!verifyResolved) return { ...base, status: 'unverified', note: 'constraints-only edit: no resolved verification was supplied, so this is NOT a confirmed fix' };
  let v; try { v = verifyResolved(patched); } catch (e) { v = { ok: false, detail: e.message }; }
  if (v && v.ok && v.resolvedVersion && compareVersions(v.resolvedVersion, fixed) >= 0) return { ...base, status: 'fixed', resolvedVersion: v.resolvedVersion };
  return { ...base, status: 'unverified', note: `resolved verification did not confirm a fixed version${v && v.detail ? `: ${v.detail}` : ''}` };
}
