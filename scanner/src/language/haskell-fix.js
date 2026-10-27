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
import { compareVersions, parseVersion } from './haskell-manifests.js';
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
  const raw = topLevelSplit(e, '++');
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
  const call = findCall(lb.text, ['callCommand', 'system']);
  if (!call) return null;
  let aStart = call.after; while (lb.text[aStart] === ' ') aStart++;
  let aEnd;
  if (lb.text[aStart] === '$') { aStart++; while (lb.text[aStart] === ' ') aStart++; aEnd = lb.text.length; }
  else aEnd = atomEnd(lb.text, aStart);
  if (aEnd < 0) return null;
  const parts = concatParts(lb.text.slice(aStart, aEnd));
  if (!parts || !parts.some((p) => p.var)) return null;       // a bare variable: no provable argv split
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
  const argExpr = (w) => (w.length === 1 && w[0].lit !== undefined ? `"${w[0].lit}"` : (w.length === 1 ? w[0].var : `(${w.map((p) => (p.lit !== undefined ? `"${p.lit}"` : p.var)).join(' ++ ')})`));
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
  const next = applyImportDelta(text, imp.text, splice(text, lb.start, lb.end, replaced));
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
  const out = {};
  params.forEach((p, i) => { if (types[i] !== undefined) out[p] = types[i]; });
  return out;
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
function fixLogging(text, f) {
  const lb = lineBounds(text, f.line);
  const call = findCall(lb.text, LOG_CALLS);
  if (!call) return null;
  const head = lb.text.slice(0, call.after); let rest = lb.text.slice(call.after);
  let n = 0;
  rest = rest.replace(/(?<![\w'.])(?:show\s+)?((?:[A-Za-z_][\w']*\.)?[a-z_][\w']*)(?![\w'(])/g, (all, id) => {
    const bare = id.replace(/^.*\./, '');
    if (/^(?:show|pack|unpack|stderr|stdout)$/.test(bare) || !SENSITIVE.test(bare)) return all;
    n++; return '"[REDACTED]"';
  });
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

function fixTls(text, f) {
  if (!importInfo(text, 'Network.Connection') && !importInfo(text, 'Network.Connection.Types')) return null;   // the detector's own precondition
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
function fixRandom(text, f) {
  const lb = lineBounds(text, f.line);
  const m = /^([a-z_][\w']*)\s*=\s*(?:System\.Random\.)?randomIO\s*$/.exec(lb.text);
  if (!m) return null;
  const name = m[1];
  const sig = new RegExp(`^${name}\\s*::\\s*IO\\s+(${Object.keys(FIXED_WIDTH).join('|')})\\s*$`, 'm').exec(text);
  if (!sig) return null;
  if ((text.match(new RegExp(`^${name}\\s*=`, 'gm')) || []).length !== 1) return null;
  const bytes = FIXED_WIDTH[sig[1]];
  const ent = importInfo(text, 'System.Entropy'); if (!ent || ent.hiding) return null;
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
    ruleId: 'hs-random-os-entropy', label: 'FULL', text: out,
    explanation: `${name} now reads ${bytes} byte(s) from the operating system CSPRNG (System.Entropy.getEntropy) and decodes them big-endian into ${sig[1]}, instead of System.Random's deterministic generator.`,
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

const FIXERS = [
  { id: 'hs-tls-validate', applies: (f) => f.cwe === 'CWE-295' || f.rule === 'hs-tls-validation-disabled', run: fixTls, reportedLineOnly: true },
  { id: 'hs-cookie-attributes', applies: (f) => f.cwe === 'CWE-1004' || f.rule === 'hs-insecure-cookie', run: fixCookie, reportedLineOnly: true },
  { id: 'hs-random-os-entropy', applies: (f) => f.cwe === 'CWE-338' || f.rule === 'hs-predictable-random', run: fixRandom, reportedLineOnly: true },
  { id: 'hs-request-body-bound', applies: (f) => f.rule === 'hs-unbounded-request-body' || (f.cwe === 'CWE-770' && /request body/i.test(String(f.vuln || ''))), run: fixBody, reportedLineOnly: true },
  { id: 'hs-sql-parameterize', applies: (f) => f.cwe === 'CWE-89', run: fixSql },
  { id: 'hs-process-argv', applies: (f) => f.cwe === 'CWE-78', run: fixProcess },
  { id: 'hs-html-escape', applies: (f) => f.cwe === 'CWE-79', run: fixHtml },
  { id: 'hs-hash-sha256', applies: (f) => f.cwe === 'CWE-328' || f.rule === 'hs-weak-hash', run: fixWeakHash },
  { id: 'hs-log-redact', applies: (f) => f.cwe === 'CWE-532' || f.rule === 'hs-sensitive-logging', run: fixLogging },
  { id: 'hs-path-takefilename', applies: (f) => f.cwe === 'CWE-22', run: fixPath },
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
      let r = null; try { r = fx.run(before, { ...finding, line }); } catch { r = null; }
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
const CLASS_REASONS = Object.freeze({
  'CWE-918': 'server-side request forgery has no line-level repair: a check on the URL string is bypassed by redirects, alternate encodings and DNS. The decision needed: which hosts or networks this service may call (an allow-list of exact hosts, or an address policy that rejects loopback, link-local and private ranges after name resolution and on every redirect).',
  'CWE-88': 'argument injection is repaired by a rule about what the called program accepts; inserting "--" only helps programs that honour it, so no patch is made. The decision needed: the permitted values for this argument (a closed list or a strict pattern), or the option of that program that ends option parsing.',
  'CWE-916': 'password hashing needs a password KDF (Argon2id, scrypt, bcrypt, or PBKDF2 with a high iteration count) from a library the project may not declare as a dependency, and every stored hash was produced by the old function: swapping it makes every existing password fail to verify and locks the users out. The decision needed: which KDF and library, with which cost parameters, and the migration (verify the old hash once, then re-hash with the new KDF at the next successful login, or force a password reset).',
  'CWE-338': 'a predictable generator is replaced by the operating system CSPRNG (System.Entropy or Crypto.Random), whose result type is bytes, not System.Random\'s: the surrounding code must change with it. Only a one-line action of type IO <fixed-width integer> equal to randomIO, in a file that already imports System.Entropy, is rewritten. The decision needed: the token\'s type and size (a 30-bit integer cannot be made unguessable by changing the generator) and the entropy library the project declares.',
  'CWE-1004': 'cookie attributes live in different places per framework. The recognised shapes are a Set-Cookie header string literal, a Web.Cookie SetCookie record update, servant-auth cookieIsSecure, and scotty setSimpleCookie/makeSimpleCookie; this is none of them, or an attribute is set from an expression. The decision needed: which attributes to send (Secure, HttpOnly, SameSite) and whether this cookie must work over plain HTTP.',
  'CWE-306': 'a missing authentication check needs a policy; the scanner reports the handler and does not invent the guard. The decision needed: which credential authenticates this route (session, token, API key) and what an unauthenticated caller receives (401, a redirect to login).',
  'CWE-770': 'a resource limit is a number only the operator can choose (how many bytes a body may have, how many requests, how large an allocation). The one recognised shape is wai strictRequestBody of a Request variable in a file importing Network.Wai and Data.ByteString.Lazy, which gets a bounded reader with a declared default; this is not that shape. The decision needed: the limit for this input, and what happens past it (reject with 413, truncate, spool to disk).',
  'CWE-295': 'enabling certificate validation can break connections the project depends on. Only the connection package\'s TLSSettingsSimple with a literal True is flipped. The decision needed: the trust store (the system store, a pinned CA bundle, a private authority) and host-name verification; an OpenSSL VerifyNone is not rewritten because VerifyPeer verifies nothing until a CA bundle is loaded and does not check the host name.',
  'CWE-798': 'a hard-coded secret must be rotated and moved to a secret store; rewriting the line would leave the leaked value valid. The decision needed: where the secret is read from at run time (environment, a secrets manager, a file outside the repository) and rotating the exposed value, which no edit of this file can do.',
  'CWE-611': 'XML entity handling depends on the parser configuration in use. The decision needed: whether this document source is trusted and which entity and DTD features the parser may enable.',
  'CWE-22': 'path traversal is repaired by confining the final path to a base directory. takeFileName is applied only to a String/FilePath parameter spliced under a fixed directory in a file operation; this shape (several segments, a base chosen at run time, a directory operation, a path handed through other functions) is not that. The decision needed: the directory the files must stay in, and whether a name containing separators or ".." is rejected or reduced to its last segment.',
  'CWE-79': 'output encoding depends on the context the value is written into (HTML text, attribute, script, URL) and on the library that renders it; only blaze-html\'s preEscapedToHtml is rewritten. The decision needed: render the value through the project\'s escaping HTML library, or send it as text/plain.',
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
    // a flow the proof gate discharged (a dominating guard, a sanitizer) is reported but is not still a finding
    return (r.scan.findings || []).filter((f) => !(f.proof && /^proven-/.test(f.proof.verdict)));
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
  if (want.kind === 'body') {
    const count = (t, re) => (stripComments(t).match(re) || []).length;
    const calls = (t) => count(t, /(?<![\w'])(?:[A-Z][\w']*\.)?strictRequestBody(?![\w'])/g);
    if (calls(after) !== calls(before) - want.replaced) return { ok: false, ran: true, detail: `exactly ${want.replaced} strictRequestBody call(s) should have been replaced` };
    if (!after.includes(BODY_HELPER)) return { ok: false, ran: true, detail: 'the bounded reader is not defined in the patched file' };
    if (!new RegExp(`requestBodyLimitBytes\\s*=\\s*${BODY_LIMIT_DEFAULT}\\b`).test(after)) return { ok: false, ran: true, detail: 'the declared limit is not the one the patch states' };
    return { ok: true, ran: true, detail: `${want.replaced} strictRequestBody call(s) were replaced by the bounded reader, whose limit is the declared constant` };
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
