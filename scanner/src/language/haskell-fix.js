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

function fixSql(text, f) {
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
  const imp = ensureImport(text, 'Database.PostgreSQL.Simple', ['execute', 'query', 'Only']);
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
  const imp = ensureImport(text, 'Crypto.Hash', ['SHA256(..)']); if (!imp) return null;
  const repl = lb.text.replace(/(?<![\w'.])(MD5|SHA1)(?![\w'.])/g, 'SHA256');
  const next = applyImportDelta(text, imp.text, splice(text, lb.start, lb.end, repl));
  return { ruleId: 'hs-hash-sha256', label: 'FULL', text: next, explanation: 'MD5/SHA-1 replaced by SHA-256. Digests change: anything that stored or compares old digests must be migrated.', behavior: { kind: 'hash', from: ['MD5', 'SHA1'], to: 'SHA256' } };
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

const FIXERS = [
  { id: 'hs-sql-parameterize', applies: (f) => f.cwe === 'CWE-89', run: fixSql },
  { id: 'hs-process-argv', applies: (f) => f.cwe === 'CWE-78', run: fixProcess },
  { id: 'hs-html-escape', applies: (f) => f.cwe === 'CWE-79', run: fixHtml },
  { id: 'hs-hash-sha256', applies: (f) => f.cwe === 'CWE-328' || f.rule === 'hs-weak-hash', run: fixWeakHash },
  { id: 'hs-log-redact', applies: (f) => f.cwe === 'CWE-532' || f.rule === 'hs-sensitive-logging', run: fixLogging },
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
  if (/\{-#\s*LANGUAGE[^#]*\bCPP\b|^#\s*(?:if|define|include)\b/m.test(before)) return { ok: false, reason: 'the file uses CPP: a rewrite could change a branch that is not visible here', proposal: 'model-assisted' };
  for (const fx of FIXERS) {
    let applies = false; try { applies = fx.applies(finding); } catch { /* ignore */ }
    if (!applies) continue;
    // The finding is reported where the tainted value ENTERS the code that reaches the sink: for a flow through a function of this
    // file that is the call, while the dangerous API call is inside the callee. Try the reported line first, then the bodies of
    // the same-file functions called on it.
    for (const line of [finding.line, ...calleeLines(before, finding.line)]) {
      let r = null; try { r = fx.run(before, { ...finding, line }); } catch { r = null; }
      if (r && r.text && r.text !== before) return { ok: true, ruleId: r.ruleId, label: r.label, file: finding.file, before, after: r.text, explanation: r.explanation, behavior: r.behavior, ...(line !== finding.line ? { fixedAtLine: line } : {}) };
    }
  }
  return { ok: false, reason: 'no deterministic fix is supported for this exact shape', proposal: 'model-assisted' };
}

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

/** Compile check is OPT-IN. `opts.compile` must be true AND a ghc must exist; otherwise the result says it did not run. */
export function compileGate(files, opts = {}) {
  if (opts.compile !== true) return { ran: false, ok: null, detail: 'not requested (default static scans never start GHC)' };
  const ghc = opts.ghc || 'ghc';
  const probe = spawnSync(ghc, ['--numeric-version'], { encoding: 'utf8', timeout: 20000 });
  if (probe.error || probe.status !== 0) return { ran: false, ok: null, detail: 'GHC is not available on this host; compile verification was not performed' };
  const dir = mkdtempSync(join(tmpdir(), 'hs-compile-'));
  try {
    for (const [f, t] of Object.entries(files)) if (/\.l?hs$/i.test(f)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
    const hs = Object.keys(files).filter((f) => /\.hs$/i.test(f));
    const r = spawnSync(ghc, ['-fno-code', '-isrc', '-i.', ...hs], { cwd: dir, encoding: 'utf8', timeout: opts.timeoutMs || 120000 });
    return { ran: true, ok: r.status === 0, detail: r.status === 0 ? 'type-checked' : (r.stderr || '').slice(0, 400) };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

/**
 * Validate (and optionally apply) a fix. Nothing is written unless every gate passes and `apply` is true.
 * @param {object} finding
 * @param {{files: Record<string,string>, root?: string, apply?: boolean, rescan?: Function, compile?: boolean, requireCompile?: boolean, behaviorCheck?: Function}} o
 */
export async function validateHaskellFix(finding, o) {
  const plan = planHaskellFix(finding, o.files);
  if (!plan.ok) return { status: 'unsupported', applied: false, ...plan };
  return runFixLifecycle({
    plan, files: o.files, finding, matchKey: key, rescan: o.rescan || defaultRescan,
    syntax: (p) => syntaxGate(p.file, p.before, p.after), behaviorCheck: o.behaviorCheck, witness: o.witness, requireWitness: o.requireWitness,
    compile: (patched) => compileGate(patched, o), requireCompile: o.requireCompile, apply: o.apply, root: o.root,
  });
}

/**
 * Verify a patch SUPPLIED BY SOMEONE ELSE (a user, a model) through the same gates as a deterministic fix: path, syntax,
 * the original finding gone, no new medium-or-higher finding. Nothing is written. `proposal` is the new text of `file`.
 */
export async function verifyHaskellProposal(finding, { files, file, proposal, rescan, compile, requireCompile }) {
  const before = files[file];
  const plan = { file, before: typeof before === 'string' ? before : '', after: proposal, label: 'WORKAROUND' };
  return runFixLifecycle({
    plan, files, finding, matchKey: key, rescan: rescan || defaultRescan, syntax: (p) => syntaxGate(p.file, p.before, p.after),
    compile: (patched) => compileGate(patched, { compile }), requireCompile, apply: false,
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
