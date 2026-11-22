// Convention deviation, value form: a function that passes a value to the
// same primitive its siblings guard first, without the guard.
//
// THE SHAPE. Several functions in one file hand a caller-supplied value (a
// parameter, a field of one, or a local assigned from one) to the same
// primitive: the same `receiver.method(...)` call, a setter, or an assignment
// to the same field (`this.url = ...`). Most of them call a guard on that
// value first, `validateUrl(url)` / `check_path(opts.path)` /
// `authorize(user, doc)`, and one does not. Typical: `create()` validates a
// URL before storing it and `update()` stores it as it came.
//
// This is the general form of the option-bag rule in convention-deviation.js
// (which keeps its own, stricter thresholds and CWE-88 wording). It reports
// option-bag spreads (`**kwargs`, `...opts`) to neither: those belong to that
// rule.
//
// HOW UNITS ARE FOUND, AND WHAT IT DOES NOT PARSE. One small scanner for all
// eight languages, deliberately not the IR: the IR parsers here differ per
// language in what they keep (Python's comes from a subprocess, Java's from a
// vendored parser), and none of them records the three things this rule
// compares (callee chain, argument text and its offset, field assignment
// target) in a shared shape. So:
//   - string literal interiors are masked to spaces (same length, so offsets
//     and lines stay exact) before any structure is read; JS and Ruby regex
//     literals are masked too, so a quote inside `/["']/` cannot open a string;
//   - brace languages (JS/TS, Java, Kotlin, Go, PHP, C#): a declaration line
//     per language, parameters by balanced parentheses, the body by brace
//     matching on the masked text;
//   - Python: the body is every following line indented deeper than the `def`;
//   - Ruby: the body ends at the `end` at the `def`'s own indentation, which is
//     how Ruby is written in practice and is a documented limit, not a parser.
// Nothing here is a parser. A construct it misreads produces no unit or a
// smaller one, which loses a comparison and never invents one.
//
// REGEX DISCIPLINE. This module runs over untrusted code, so every pattern is
// bounded, no quantified group contains another quantifier, and no optional
// group sits between two whitespace runs. Receiver chains, accessor chains
// and assignment targets are walked by hand, character by character, rather
// than matched with repeated groups.
//
// PRECISION CONTROLS (each has a refusing test in
// test/sibling-guard-deviation.test.js):
//   - the value must be caller-supplied in every unit compared (a parameter, a
//     field of one, or a local assigned from one);
//   - the guard must take THAT value (or the object it is a field of, or a
//     field of it) as an argument, and come before the use;
//   - siblings are compared only on the same primitive AND the same value role;
//   - population: at least 2 guarded siblings and a strict majority guarded;
//     or exactly 1 guarded against 1 unguarded when the match is tight: the
//     guard takes exactly the value, and the guard's own name names the value
//     role or its concern (`validateWebhookUrl(url)` before `client.post(url)`);
//   - a hand-written check on the value that exits (`if ... throw/raise/
//     return`) counts as a guard; so does a same-file helper that guards its
//     own parameter, when the value is passed to it;
//   - null, emptiness, type and argument-shape checks are not guards
//     (`requireNonNull`, `checkArgument`, `assertEquals`): a population of
//     those says nothing about security handling;
//   - test files are skipped: assertions there are guard-shaped by name.
//
// WHAT A FINDING CLAIMS. Only that this site is inconsistent with its
// neighbours, with the neighbours named. Medium severity, always.

import { createStringMemo } from '../util/string-memo.js';

const LANG_BY_EXT = [
  [/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i, 'js'],
  [/\.py$/i, 'py'],
  [/\.java$/i, 'java'],
  [/\.(?:kt|kts)$/i, 'kt'],
  [/\.go$/i, 'go'],
  [/\.php$/i, 'php'],
  [/\.rb$/i, 'rb'],
  [/\.cs$/i, 'cs'],
];

export function langOf(file) {
  for (const [re, l] of LANG_BY_EXT) if (re.test(file)) return l;
  return null;
}

const TEST_PATH_RE = /(?:^|[\\/])(?:tests?|specs?|__tests__|testdata|fixtures?)[\\/]|[._-](?:test|spec)\.[a-z]{1,4}$|Tests?\.(?:java|kt|cs)$|_test\.go$|^test_\w{1,80}\.py$|[\\/]test_\w{1,80}\.py$/;

// ---------------------------------------------------------------------------
// Guard names.
// ---------------------------------------------------------------------------

// A guard verb at the start of the callee's last segment, followed by a word
// boundary of the naming convention (`_`, an uppercase letter, `!`/`?` in
// Ruby, or the end). That boundary is tested case-SENSITIVELY: under a
// case-insensitive match `[A-Z]` also accepts a lowercase letter, which reads
// `AssertionError`, `checkout` and `validated` as guards. Bare
// `validate`/`verify`/`sanitize`/`authorize` count; bare `check`/`require`/
// `ensure`/`assert`/`guard` do not (`require(x)` is a module import in JS,
// `assert` a statement in Python).
const GUARD_VERB_RE = /^(?:check|verify|validate|assert|require|ensure|guard|sanitize|sanitise|authorize|authorise|whitelist|allowlist)/i;
const GUARD_IS_RE = /^(?:is|can|has)(?:_|(?=[A-Z]))/;
const BARE_VERB_RE = /^(?:check|require|ensure|assert|guard)$/i;

// Words that make an `is_`/`can_`/`has_` predicate (and `ensure`, which in
// most code means "make it so", `ensure_dir`, `ensure_list`) a security check.
const SECURITY_WORDS = new Set(['safe', 'unsafe', 'allowed', 'allow', 'access', 'auth', 'authorized', 'authorised', 'authenticated',
  'permission', 'permissions', 'permitted', 'permit', 'owner', 'owns', 'admin', 'role', 'login', 'logged', 'member', 'trusted',
  'valid', 'inside', 'within', 'contained', 'url', 'uri', 'path', 'host', 'scheme', 'secure', 'sanitized', 'signed', 'csrf',
  'origin', 'domain', 'scope', 'whitelisted', 'allowlisted', 'privileged', 'authorize', 'authorise', 'can', 'filename',
  'redirect', 'webhook', 'command', 'cmd', 'sql', 'query', 'option', 'options', 'target']);
// `canEdit(user, doc)`: a capability check names an action on a resource.
const CAPABILITY_VERBS = new Set(['edit', 'view', 'read', 'write', 'delete', 'remove', 'update', 'manage', 'modify', 'see',
  'create', 'publish', 'share', 'invite', 'approve', 'execute', 'run', 'download', 'upload', 'transfer', 'impersonate']);
// Shape, type and data checks: a population of these says nothing about
// security handling (`check_array`, `requireNonNull`, `checkArgument`,
// `validate_matrix_shape`). Any one of these words in the name disqualifies it.
const DATA_WORDS = new Set(['null', 'none', 'nil', 'empty', 'blank', 'undefined', 'defined', 'present', 'state', 'argument',
  'arg', 'args', 'type', 'types', 'instance', 'equal', 'equals', 'true', 'false', 'that', 'length', 'size', 'count', 'index',
  'bounds', 'range', 'positive', 'negative', 'throws', 'same', 'called', 'calls', 'raises', 'array', 'arrays', 'shape',
  'dtype', 'axis', 'ndim', 'dim', 'dims', 'matrix', 'matrices', 'random', 'list', 'tuple', 'dict', 'scalar', 'vector',
  'numeric', 'finite', 'fitted', 'int', 'integer', 'float', 'bool', 'boolean', 'str', 'string', 'kind', 'version',
  'consistent', 'default', 'slice', 'nd', 'number', 'exists', 'loaded', 'initialized',
  'ready', 'open', 'closed', 'running', 'started', 'unique', 'sorted', 'format', 'encoding', 'not', 'nonnull']);
// Test-framework assertions, in case one appears outside a test path.
const TEST_ASSERT_RE = /^assert(?:Equals?|NotEquals?|True|False|Null|NotNull|Same|NotSame|That|Throws|Raises|In|NotIn|Is|IsNot|IsNone|IsNotNone|Contains|Match|Regex|Called|_called|_equal|_true|_false|_none|_raises)/;

/** Split an identifier into lowercase words: `validateRedirectURI` -> validate, redirect, uri. */
function nameWords(n) {
  return n.replace(/[!?]$/, '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z])([A-Z][a-z])/g, '$1 $2')
    .split(/[\s_]{1,8}/)
    .filter(Boolean)
    .map(w => w.toLowerCase());
}

export function isGuardName(name, lang) {
  if (!name) return false;
  const n = name.replace(/^[$@]/, '');
  if (TEST_ASSERT_RE.test(n)) return false;
  if (BARE_VERB_RE.test(n)) return false;
  // A guard-named factory returns a checker; calling it checks nothing yet.
  if (/(?:factory|Factory|builder|Builder|maker|Maker)$/.test(n)) return false;
  if (/^require_(?:relative|dependency)$/.test(n)) return false;
  const words = nameWords(n);
  if (words.some(w => DATA_WORDS.has(w))) return false;
  const rest = words.slice(1);
  const verb = n.match(GUARD_VERB_RE);
  if (verb) {
    const next = n[verb[0].length];
    if (next !== undefined && !/[_A-Z!?]/.test(next)) return false;   // case-sensitive boundary
    if (/^ensure$/i.test(verb[0])) return rest.some(w => SECURITY_WORDS.has(w));
    return true;
  }
  if (GUARD_IS_RE.test(n)) return rest.some(w => SECURITY_WORDS.has(w) || (words[0] === 'can' && CAPABILITY_VERBS.has(w)));
  // Ruby predicates: `safe_url?`, `allowed_host?`.
  if (lang === 'rb' && n.endsWith('?')) return words.some(w => w === 'safe' || w === 'allowed' || w === 'valid' || w === 'permitted' || w === 'authorized' || w === 'trusted');
  return false;
}

// ---------------------------------------------------------------------------
// Masking: string and regex literal interiors become spaces.
// ---------------------------------------------------------------------------

const REGEX_PREV = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '~', '+', '-', '*', '%', '<', '>', '']);

// Three detectors (this one, `request-sized-resource.js`, `authz-step-deviation.js`) mask the same file; the result is a pure function of
// the text and the language, so it is computed once per distinct text (`createStringMemo`, bounded and versioned).
export const maskStrings = createStringMemo((code, lang) => maskStringsUncached(code, lang === '' ? undefined : lang), { version: 'maskStrings@1', disableEnv: 'AGENTIC_SECURITY_NO_STRING_MEMO' });

function maskStringsUncached(code, lang) {
  const out = code.split('');
  const n = code.length;
  const multiline = lang === 'rb' || lang === 'php';
  const triple = lang === 'py' || lang === 'kt' || lang === 'cs';
  const backtick = lang === 'js' || lang === 'go';
  const regexLits = lang === 'js' || lang === 'rb';
  let prevSig = '';
  let i = 0;
  const blank = (a, b) => { for (let k = a; k < b; k++) if (out[k] !== '\n') out[k] = ' '; };
  while (i < n) {
    const c = code[i];
    if (triple && (c === '"' || c === "'") && code[i + 1] === c && code[i + 2] === c) {
      const end = code.indexOf(c + c + c, i + 3);
      const stop = end === -1 ? n : end;
      blank(i + 3, stop);
      i = stop + 3; prevSig = 'x'; continue;
    }
    if (c === '"' || c === "'" || (backtick && c === '`')) {
      const raw = (c === '`' && lang === 'go') || (c === '"' && lang === 'cs' && code[i - 1] === '@');
      let j = i + 1;
      while (j < n) {
        const d = code[j];
        if (!raw && d === '\\') { j += 2; continue; }
        if (d === c) break;
        if (d === '\n' && c !== '`' && !multiline && !raw) break;
        j++;
      }
      blank(i + 1, Math.min(j, n));
      i = j + 1; prevSig = 'x'; continue;
    }
    if (regexLits && c === '/' && code[i + 1] !== '/' && code[i + 1] !== '*' && REGEX_PREV.has(prevSig)) {
      let j = i + 1, inClass = false;
      while (j < n && code[j] !== '\n') {
        const d = code[j];
        if (d === '\\') { j += 2; continue; }
        if (d === '[') inClass = true;
        else if (d === ']') inClass = false;
        else if (d === '/' && !inClass) break;
        j++;
      }
      if (j < n && code[j] === '/') { blank(i + 1, j); i = j + 1; prevSig = 'x'; continue; }
    }
    if (!/\s/.test(c)) {
      prevSig = /[\w$)\]]/.test(c) ? 'x' : c;
      // `return /re/` and `when /re/`: a keyword, not a value, precedes.
      if (prevSig === 'x' && /[A-Za-z]/.test(c)) {
        let k = i; while (k < n && /\w/.test(code[k])) k++;
        const word = code.slice(i, k);
        if (/^(?:return|typeof|case|when|if|unless|and|or|not|in|of)$/.test(word)) prevSig = '';
        i = k; continue;
      }
    }
    i++;
  }
  return out.join('');
}

// ---------------------------------------------------------------------------
// Small structural helpers over the masked text.
// ---------------------------------------------------------------------------

const OPEN = { '(': ')', '[': ']', '{': '}' };

/** Index of the bracket closing the one at `i`, or -1. */
function matchClose(masked, i, limit = 200_000) {
  const o = masked[i], c = OPEN[o];
  if (!c) return -1;
  let depth = 0;
  const end = Math.min(masked.length, i + limit);
  for (let k = i; k < end; k++) {
    const ch = masked[k];
    if (ch === o) depth++;
    else if (ch === c) { depth--; if (depth === 0) return k; }
  }
  return -1;
}

/** Split on commas at bracket depth 0. */
function splitTop(text) {
  const parts = [];
  let depth = 0, cur = '';
  for (const ch of text) {
    if (ch === '(' || ch === '[' || ch === '{' || ch === '<') depth++;
    else if (ch === ')' || ch === ']' || ch === '}' || ch === '>') depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts;
}

function lineStarts(code) {
  const s = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') s.push(i + 1);
  return s;
}
function lineAt(starts, off) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= off) lo = mid; else hi = mid - 1; }
  return lo + 1;
}

const IDENT_START = /[A-Za-z_$]/;
const IDENT_CHAR = /[\w$]/;

// ---------------------------------------------------------------------------
// Parameters.
// ---------------------------------------------------------------------------

const PARAM_MODIFIERS = new Set(['final', 'const', 'readonly', 'public', 'private', 'protected', 'override', 'vararg', 'val', 'var', 'ref', 'out', 'in', 'params', 'this', 'scoped', 'noinline', 'crossinline', 'mut']);

export function paramNames(text, lang) {
  const names = [];
  for (let raw of splitTop(text)) {
    let p = raw.replace(/@\w{1,80}(?:\([^)]{0,200}\))?/g, ' ').trim();
    if (!p) continue;
    if (lang === 'php') { const m = p.match(/\$(\w{1,80})/); if (m) names.push('$' + m[1]); continue; }
    // Drop a default value. `=>` is not one.
    const eq = p.search(/=(?!>)/);
    if (eq !== -1) p = p.slice(0, eq).trim();
    p = p.replace(/^[*&.]{1,3}/, '').trim();
    if (p.startsWith('{') || p.startsWith('[') || p.startsWith('(')) continue;   // destructuring: no single name
    if (lang === 'go') { const m = p.match(/^([A-Za-z_]\w{0,80})/); if (m) names.push(m[1]); continue; }
    if (lang === 'java' || lang === 'cs') {
      const words = p.match(/[A-Za-z_]\w{0,80}/g) || [];
      if (words.length >= 2) names.push(words[words.length - 1]);
      continue;
    }
    // js/ts, py, kt, rb: `name`, `name: Type`, `name?: T`, `key:` (Ruby keyword arg).
    const colon = p.indexOf(':');
    const head = (colon === -1 ? p : p.slice(0, colon)).replace(/\?$/, '').trim();
    const words = head.split(/\s{1,8}/).filter(w => w && !PARAM_MODIFIERS.has(w));
    const w = words[words.length - 1];
    if (w && /^[A-Za-z_$][\w$]{0,80}$/.test(w)) names.push(w);
  }
  return names.filter(n => n !== 'self' && n !== 'cls' && n !== 'this');
}

// ---------------------------------------------------------------------------
// Function units.
// ---------------------------------------------------------------------------

const DECL_KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'typeof', 'new', 'else', 'do', 'try', 'throw', 'await', 'case', 'yield', 'using', 'lock', 'foreach', 'when', 'in', 'is', 'as', 'sizeof', 'nameof', 'synchronized', 'fixed', 'checked', 'unchecked', 'function', 'super', 'base', 'elif', 'with', 'match']);
const JS_MODIFIERS = /^(?:export|default|public|private|protected|static|async|readonly|override|abstract|declare|get|set|internal|virtual|sealed|final|extern|unsafe|partial|new|synchronized|native|transient|volatile|strictfp|open|suspend|inline|operator|infix|tailrec|external|data|const)\s{1,8}/;

function stripModifiers(s) {
  let t = s;
  for (let k = 0; k < 8; k++) {
    const r = t.replace(JS_MODIFIERS, '');
    if (r === t) break;
    t = r;
  }
  return t;
}

const GO_DECL = /^\s{0,40}func\s{1,4}(?:\([^)\n]{0,200}\)\s{0,4})?([A-Za-z_]\w{0,80})\s{0,4}(?:\[[^\]\n]{0,200}\]\s{0,2})?\(/;
const KT_DECL = /\bfun\s{1,4}(?:<[^>\n]{0,100}>\s{0,4})?(?:[A-Za-z_][\w.]{0,120}\.)?([A-Za-z_]\w{0,80})\s{0,4}\(/;
const PHP_DECL = /\bfunction\s{1,4}&?([A-Za-z_]\w{0,80})\s{0,4}\(/;
const JS_FUNC_DECL = /\bfunction\b\s{0,4}\*?\s{0,4}([A-Za-z_$][\w$]{0,80})\s{0,4}\(/;
const JS_ARROW_DECL = /^(?:(?:const|let|var)\s{1,4})?([A-Za-z_$][\w$]{0,80})\s{0,4}[:=]\s{0,4}(?:async\b\s{0,4})?(?:function\b\s{0,4})?\(/;
const JS_METHOD_DECL = /^([A-Za-z_$][\w$]{0,80})\s{0,4}(?:<[^>\n]{0,80}>)?\(/;

/** Declaration on one masked line: { name, parenIdx } (parenIdx absolute), or null. */
function declOnLine(lang, line, lineOff) {
  let m, idx;
  if (lang === 'go') { m = line.match(GO_DECL); if (!m) return null; idx = m.index + m[0].length - 1; return { name: m[1], parenIdx: lineOff + idx }; }
  if (lang === 'kt') { m = line.match(KT_DECL); if (!m) return null; idx = m.index + m[0].length - 1; return { name: m[1], parenIdx: lineOff + idx }; }
  if (lang === 'php') { m = line.match(PHP_DECL); if (!m) return null; idx = m.index + m[0].length - 1; return { name: m[1], parenIdx: lineOff + idx }; }
  const lead = line.length - line.trimStart().length;
  let a = line.trimStart();
  // Leading annotations, attributes and decorators: `@Get("/x")`, `[HttpPost]`.
  for (let k = 0; k < 6; k++) {
    const r = a.replace(/^@[\w.]{1,80}(?:\([^()\n]{0,200}\))? {0,8}/, '').replace(/^\[[^\]\n]{0,200}\] {0,8}/, '');
    if (r === a) break;
    a = r;
  }
  const t = stripModifiers(a);
  const hadModifier = t !== a;
  const shift = lineOff + lead + (line.trimStart().length - t.length);
  if (lang === 'js') {
    m = line.match(JS_FUNC_DECL);
    if (m) return { name: m[1], parenIdx: lineOff + m.index + m[0].length - 1 };
    m = t.match(JS_ARROW_DECL);
    if (m && !DECL_KEYWORDS.has(m[1])) return { name: m[1], parenIdx: shift + m.index + m[0].length - 1, arrow: true };
    m = t.match(JS_METHOD_DECL);
    if (m && !DECL_KEYWORDS.has(m[1])) return { name: m[1], parenIdx: shift + m.index + m[0].length - 1 };
    return null;
  }
  // java / cs: `<type tokens> name(` at the start of the statement.
  const p = t.indexOf('(');
  if (p <= 0) return null;
  const before = t.slice(0, p).replace(/\s{1,8}$/, '').replace(/<[^<>]{0,80}>$/, '');
  const nm = before.match(/([A-Za-z_]\w{0,80})$/);
  if (!nm) return null;
  const name = nm[1];
  const prefix = before.slice(0, before.length - name.length).trim();
  if (DECL_KEYWORDS.has(name)) return null;
  // A constructor has modifiers and no return type: `public Widget(String url) {`.
  if (!prefix) return hadModifier && /^[A-Z]/.test(name) ? { name, parenIdx: shift + p } : null;
  if (/[=.(;:,!&|+\-*/%?]$/.test(prefix) || /[=(;]/.test(prefix)) return null;
  const lastWord = (prefix.match(/([A-Za-z_]\w{0,80})[\]>?]{0,4}$/) || [])[1];
  if (!lastWord || DECL_KEYWORDS.has(lastWord) || lastWord === 'return') return null;
  return { name, parenIdx: shift + p };
}

/**
 * Function units of one file: { name, params, start, end, line }, where
 * [start, end) is the body's offset range in the file.
 */
export function functionUnits(lang, masked) {
  const units = [];
  const starts = lineStarts(masked);
  const lines = masked.split('\n');
  if (lang === 'py' || lang === 'rb') {
    for (let i = 0; i < lines.length; i++) {
      const L = lines[i];
      const m = lang === 'py'
        ? L.match(/^(\s{0,200})(?:async\s{1,8})?def\s{1,8}([A-Za-z_]\w{0,80})\s{0,8}\(/)
        : L.match(/^(\s{0,200})def\s{1,8}(?:self\.)?([A-Za-z_]\w{0,80}[?!]?)/);
      if (!m) continue;
      const indent = m[1].length;
      let params = [];
      let headerEnd = starts[i] + L.length;
      const pIdx = starts[i] + m[0].length - (lang === 'py' ? 1 : 0);
      if (masked[pIdx] === '(') {
        const close = matchClose(masked, pIdx, 4000);
        if (close === -1) continue;
        params = paramNames(masked.slice(pIdx + 1, close), lang);
        headerEnd = masked.indexOf('\n', close); if (headerEnd === -1) headerEnd = masked.length;
      } else if (lang === 'rb') {
        const rest = L.slice(m[0].length).trim();
        if (rest.startsWith('=')) continue;   // endless method
        params = paramNames(rest, lang);
      }
      // The body ends at the first non-blank line indented no deeper than the
      // declaration: Python's dedent, Ruby's `end` at the `def`'s indentation.
      const j = lineAt(starts, headerEnd);   // 1-based line of the header end = 0-based index of the next line
      let endOff = masked.length;
      for (let k = j; k < lines.length; k++) {
        const t = lines[k];
        if (!t.trim()) continue;
        const ind = t.length - t.trimStart().length;
        if (ind <= indent) { endOff = starts[k]; break; }
      }
      const bodyStart = headerEnd < masked.length ? headerEnd + 1 : headerEnd;
      if (endOff > bodyStart) units.push({ name: m[2], params, start: bodyStart, end: endOff, line: i + 1 });
    }
    return units;
  }
  for (let i = 0; i < lines.length; i++) {
    const d = declOnLine(lang, lines[i], starts[i]);
    if (!d || masked[d.parenIdx] !== '(') continue;
    const close = matchClose(masked, d.parenIdx, 4000);
    if (close === -1) continue;
    // Find the body's `{` before any `;` (a declaration without a body, or an
    // expression body, which is too short to carry a guard convention).
    let open = -1;
    for (let k = close + 1; k < Math.min(masked.length, close + 400); k++) {
      const ch = masked[k];
      if (ch === '{') { open = k; break; }
      if (ch === ';' || ch === '}') break;
      if (ch === '=' && masked[k + 1] !== '>') break;
      if (ch === '(') { const c2 = matchClose(masked, k, 400); if (c2 === -1) break; k = c2; }
    }
    if (open === -1) continue;
    const bodyEnd = matchClose(masked, open);
    if (bodyEnd === -1) continue;
    units.push({ name: d.name, params: paramNames(masked.slice(d.parenIdx + 1, close), lang), start: open + 1, end: bodyEnd, line: i + 1 });
  }
  return units;
}

// ---------------------------------------------------------------------------
// Calls, assignments and value references inside one body.
// ---------------------------------------------------------------------------

/** Walk back from `end` (exclusive) over a callee chain. Returns { segs, start } or null. */
function chainBefore(masked, end) {
  const segs = [];
  let k = end;
  for (let guard = 0; guard < 12; guard++) {
    let e = k;
    while (e > 0 && /[!?]/.test(masked[e - 1]) && segs.length === 0) e--;   // Ruby `name!(` / `name?(`
    let s = e;
    while (s > 0 && IDENT_CHAR.test(masked[s - 1])) s--;
    if (s > 0 && masked[s - 1] === '@') s--;
    if (s === e) break;
    segs.unshift(masked.slice(s, k));
    k = s;
    // accessor before it?
    if (masked[k - 1] === '.' ) { k -= 1; if (masked[k - 1] === '?' || masked[k - 1] === '!') { k -= 1; if (masked[k - 1] === '!') k -= 1; } continue; }
    if (masked[k - 1] === '>' && masked[k - 2] === '-') { k -= 2; continue; }
    if (masked[k - 1] === ':' && masked[k - 2] === ':') { k -= 2; continue; }
    break;
  }
  if (!segs.length) return null;
  // A chain that hangs off a call or index result: `a().b(` has no plain receiver.
  const prev = masked[k - 1];
  const broken = k > 0 && (prev === ')' || prev === ']');
  return { segs, start: k, broken };
}

/** Accessor chain forward from `i` (just after a root name). Returns { segs, end }. */
function accessorsAfter(src, masked, i) {
  const segs = [];
  let k = i;
  for (let guard = 0; guard < 6; guard++) {
    let a = k;
    if (masked[a] === '?' && masked[a + 1] === '.') a += 2;
    else if (masked[a] === '.' && IDENT_START.test(masked[a + 1] || '')) a += 1;
    else if (masked[a] === '-' && masked[a + 1] === '>') a += 2;
    else if (masked[a] === '[') {
      const close = matchClose(masked, a, 200);
      if (close === -1) break;
      const inner = src.slice(a + 1, close).trim();
      const lit = inner.match(/^(?:["'](\w{1,80})["']|:(\w{1,80}))$/);
      if (!lit) break;
      segs.push(lit[1] || lit[2]);
      k = close + 1;
      continue;
    } else break;
    let e = a;
    while (e < masked.length && IDENT_CHAR.test(masked[e])) e++;
    if (e === a) break;
    // `.method(` is a call on the value, not a field of it.
    let w = e; while (masked[w] === ' ') w++;
    if (masked[w] === '(') break;
    segs.push(src.slice(a, e));
    k = e;
  }
  return { segs, end: k };
}

/**
 * Every reference to a tracked root inside [from, to): { path, role, off }.
 * `spread` marks `**x` / `...x` / `*x` forwarding, which the option-bag rule owns.
 */
function valueRefs(src, masked, from, to, roots) {
  const refs = [];
  if (!roots.size) return refs;
  const text = masked.slice(from, to);
  const re = /[$@]?[A-Za-z_][\w$]{0,80}/g;
  let m;
  while ((m = re.exec(text))) {
    const word = m[0];
    if (!roots.has(word)) continue;
    const off = from + m.index;
    const p1 = masked[off - 1], p2 = masked[off - 2];
    if (p1 === '.' || (p1 === '>' && p2 === '-') || (p1 === ':' && p2 === ':')) continue;
    if (IDENT_CHAR.test(p1 || '')) continue;
    // `url:` as an object key or keyword label (after `{`, `,` or `(`) is not a read.
    const after = masked.slice(off + word.length, off + word.length + 3);
    let b = off - 1;
    while (b >= 0 && /\s/.test(masked[b])) b--;
    if (/^ {0,2}:(?!:)/.test(after) && (b < 0 || masked[b] === '{' || masked[b] === ',' || masked[b] === '(')) continue;
    if (/^ {0,2}=(?![=>~])/.test(after)) continue;   // an assignment to it, not a read
    const spread = p1 === '*';
    const acc = accessorsAfter(src, masked, off + word.length);
    const path = [roots.get(word), ...acc.segs].join('.');
    refs.push({ path, role: roleOf(path), off, end: acc.end, spread });
    re.lastIndex = Math.max(re.lastIndex, acc.end - from);
  }
  return refs;
}

function roleOf(path) {
  const last = path.split('.').pop() || '';
  return last.replace(/^[$@]/, '').replace(/_/g, '').toLowerCase();
}

/** Calls in [from, to): { segs, method, start, open, close, broken }. */
function callsIn(masked, from, to) {
  const calls = [];
  for (let i = from; i < to; i++) {
    if (masked[i] !== '(') continue;
    if (!IDENT_CHAR.test(masked[i - 1] || '') && !/[!?]/.test(masked[i - 1] || '')) continue;
    const ch = chainBefore(masked, i);
    if (!ch) continue;
    const close = matchClose(masked, i, Math.max(1, to - i + 1));
    if (close === -1) continue;
    const method = ch.segs[ch.segs.length - 1];
    if (DECL_KEYWORDS.has(method) && method !== 'new') continue;
    // `new Foo(...)` constructs; record it with a marker.
    const kw = masked.slice(Math.max(from, ch.start - 4), ch.start);
    calls.push({ segs: ch.segs, method, start: ch.start, open: i, close, broken: ch.broken, isNew: /new\s$/.test(kw) });
  }
  return calls;
}

/** Ruby paren-less calls: `name! arg` / `name arg` at statement start. Guards only. */
function rubyBareCalls(src, masked, from, to) {
  const out = [];
  const text = masked.slice(from, to);
  const re = /(^|\bunless\s|\bif\s|\band\s|\bor\s|[;!])\s{0,8}([a-z_]\w{0,80}[!?]?)[ \t]{1,4}(?=[$@A-Za-z_:])([^\n]{1,200})/gm;
  let m;
  while ((m = re.exec(text))) {
    const name = m[2];
    if (!isGuardName(name, 'rb')) continue;
    const argStart = from + m.index + m[0].length - m[3].length;
    out.push({ segs: [name], method: name, start: from + m.index + m[1].length, open: argStart - 1, close: argStart + m[3].length, bare: true });
  }
  return out;
}

/** Field assignments `recv.field = rhs` / `@field = rhs` / `$this->field = rhs` in [from, to). */
function fieldAssignmentsIn(masked, from, to) {
  const out = [];
  for (let i = from; i < to; i++) {
    if (masked[i] !== '=') continue;
    const nx = masked[i + 1], pv = masked[i - 1];
    if (nx === '=' || nx === '>' || nx === '~') continue;
    const walrus = pv === ':' && masked[i - 2] !== ':';   // Go `x := v`
    if (!walrus && /[=!<>:+\-*/%&|^?.]/.test(pv)) continue;
    let e = walrus ? i - 1 : i; while (e > from && masked[e - 1] === ' ') e--;
    let ch = chainBefore(masked, e);
    if (!ch || ch.broken) continue;
    // `val url: String = ...` / `let url: string = ...`: the name is before the colon.
    let q = ch.start; while (q > from && masked[q - 1] === ' ') q--;
    if (ch.segs.length === 1 && masked[q - 1] === ':' && masked[q - 2] !== ':') {
      let e2 = q - 1; while (e2 > from && masked[e2 - 1] === ' ') e2--;
      const ch2 = chainBefore(masked, e2);
      if (ch2 && ch2.segs.length === 1) ch = ch2;
    }
    const before = masked[ch.start - 1];
    if (before === '.' || before === '>') continue;
    // RHS: to the end of the statement at depth 0.
    let r = i + 1, depth = 0;
    const lim = Math.min(to, i + 400);
    for (; r < lim; r++) {
      const c = masked[r];
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') { if (depth === 0) break; depth--; }
      else if ((c === ';' || c === '\n') && depth === 0) break;
    }
    const isIvar = ch.segs.length === 1 && ch.segs[0].startsWith('@');
    if (ch.segs.length >= 2 || isIvar) {
      const recv = isIvar ? 'this' : normRecv(ch.segs.slice(0, -1));
      const field = isIvar ? ch.segs[0].slice(1) : ch.segs[ch.segs.length - 1];
      out.push({ kind: 'field', recv, field, start: ch.start, rhsFrom: i + 1, rhsTo: r });
    } else {
      out.push({ kind: 'local', name: ch.segs[0], start: ch.start, rhsFrom: i + 1, rhsTo: r });
    }
  }
  return out;
}

function normRecv(segs) {
  const s = segs.map(x => (x === 'self' || x === '$this' || x === 'this' || x === '@' ? 'this' : x));
  return s.join('.');
}

// ---------------------------------------------------------------------------
// Primitive vocabulary.
// ---------------------------------------------------------------------------

// Calls that consume a value without acting on it: logging, formatting,
// conversion, collection bookkeeping. Without this every guarded function's
// `logger.info(url)` would be a "primitive" its siblings also reach.
const NOISE_METHOD_RE = /^(?:log|logf|debug|info|warn|warning|error|errorf|trace|fatal|print|println|printf|sprintf|fprintf|puts|p|pp|format|append|push|add|addAll|unshift|includes|contains|containsKey|has|hasOwnProperty|equals|equal|startsWith|endsWith|startswith|endswith|toString|to_s|toLowerCase|toUpperCase|lower|upper|trim|strip|len|length|size|str|int|float|bool|String|Number|Boolean|parseInt|parseFloat|isinstance|type|typeof|isEmpty|isBlank|empty|isset|is_null|count|join|split|replace|sub|gsub|indexOf|index|get|keys|values|items|map|filter|forEach|each|reduce|then|catch|resolve|reject|emit|send_message|assert\w{0,40}|expect|t|_|__|gettext|i18n|translate|notify|freeze|dup|clone|copy|deepcopy|hash|hashCode|hash_code|compare|compareTo|min|max|abs|round|sorted|sort|reverse|set|put|setdefault|update_attribute|tap|inspect|class|super|repr|id)$/;
const NOISE_RECV_RE = /^(?:log|logger|LOG|LOGGER|Log|Logger|_log|_logger|log\.\w{1,40}|this\.log|this\.logger|console|fmt|System\.out|System\.err|Console|Debug|Trace|Rails\.logger|logging|slog|zap|klog|glog|Timber|Sentry|metrics|stats|statsd|tracer|span|json|JSON|Json|Math|math|strings|String|Integer|Long|Objects|Arrays|Collections|List|Map|Set|Object|Array|Number|Date|Time|time|strconv|errors|assert|t|expect|self\.assert\w{0,40}|i18n|I18n)$/;

// Bare (receiver-less) callees that are primitives on their own.
const BARE_PRIMITIVE_RE = /^(?:fetch|open|urlopen|exec|execSync|execFile|execFileSync|spawn|spawnSync|system|popen|eval|readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|rmSync|createReadStream|createWriteStream|file_get_contents|file_put_contents|fopen|readfile|unlink|curl_init|curl_setopt|shell_exec|passthru|proc_open|mkdir|rmdir|rename|send_file|send_from_directory|redirect|redirect_to|query|execute|render|include|require_once|include_once|axios|got|request|move_uploaded_file|copy)$/;

const CONCERNS = [
  [/command|cmd|shell|exec|spawn|popen|system|argv|subprocess/, 'CWE-78', 'command'],
  [/sql|query|cursor|statement/, 'CWE-89', 'SQL'],
  [/url|uri|host|endpoint|webhook|callback|origin|domain|fetch|http|request|axios|curl/, 'CWE-918', 'outbound URL'],
  [/path|file|dir|folder|upload|unlink|fopen|mkdir|rename|^open$|\.open$/, 'CWE-22', 'filesystem path'],
];
const AUTHZ_GUARD_RE = /authori[sz]|permission|permit|access|owner|role|admin|policy|privilege|^can_|^can[A-Z]|allowedTo|allowed_to|ensure_?user|require_?(?:user|login|auth)|check_?auth/i;

/** CWE from the guard name first, then the value role, then the primitive. */
export function concernOf(guardName, role, primitive) {
  const g = String(guardName || '');
  if (AUTHZ_GUARD_RE.test(g)) return { cwe: 'CWE-862', concern: 'authorization' };
  for (const hay of [g.toLowerCase(), String(role || '').toLowerCase(), String(primitive || '').toLowerCase()]) {
    if (!hay) continue;
    for (const [re, cwe, concern] of CONCERNS) if (re.test(hay)) return { cwe, concern };
  }
  return { cwe: 'CWE-20', concern: 'input' };
}

// ---------------------------------------------------------------------------
// Per-unit facts.
// ---------------------------------------------------------------------------

/** Inline hand-written checks that exit: `if (... v ...) throw/raise/return`. */
const EXIT_RE = /\b(?:throw|raise|return|abort|panic|halt|die|exit|fail|head)\b/;

// A hand-written check on the value that leaves the function:
//   prefix:  `if (<cond>) { throw ... }`, `if <cond>:\n    raise ...`, `unless <cond> ... return`
//   postfix: `raise X unless <cond>`, `return head(:forbidden) if <cond>`
// Only the condition's text is searched for the value, and the exit must be
// in the condition's own consequence (the next line or the braces that
// follow), so an exit further down the function does not make a check of an
// unrelated `if`.
function inlineExitChecks(src, masked, u, roots) {
  const out = [];
  const body = masked.slice(u.start, u.end);
  const re = /\b(?:if|unless|guard)\b/g;
  let m;
  while ((m = re.exec(body))) {
    const at = u.start + m.index;
    const lineStart = masked.lastIndexOf('\n', at - 1) + 1;
    let lineEnd = masked.indexOf('\n', at); if (lineEnd === -1 || lineEnd > u.end) lineEnd = u.end;
    const headText = masked.slice(lineStart, at);
    let condFrom = at + m[0].length, condTo, consequence;
    if (EXIT_RE.test(headText)) {                    // postfix form
      condTo = lineEnd; consequence = headText;
    } else {
      let k = condFrom; while (k < u.end && masked[k] === ' ') k++;
      if (masked[k] === '(') {
        const close = matchClose(masked, k, 2000);
        if (close === -1) continue;
        condTo = close;
      } else {
        // `if cond:` / `if cond {` / `unless cond`: to the end of the line.
        condTo = lineEnd;
        const brace = masked.indexOf('{', condFrom);
        if (brace !== -1 && brace < lineEnd) condTo = brace;
      }
      const nextNl = masked.indexOf('\n', lineEnd + 1);
      consequence = masked.slice(condTo, Math.min(u.end, nextNl === -1 ? u.end : nextNl));
    }
    if (!EXIT_RE.test(consequence)) continue;
    for (const r of valueRefs(src, masked, condFrom, condTo, roots)) out.push({ path: r.path, off: at, name: '<inline check>', exact: false, kind: 'inline' });
  }
  return out;
}

function analyseUnit(src, masked, u, lang, unitNames, guardingHelpers, starts) {
  const roots = new Map();
  for (const p of u.params) roots.set(p, p);
  const assigns = fieldAssignmentsIn(masked, u.start, u.end);
  // Locals assigned from a tracked root become roots themselves (one pass, in order).
  for (const a of assigns) {
    if (a.kind !== 'local' || roots.has(a.name)) continue;
    if (valueRefs(src, masked, a.rhsFrom, a.rhsTo, roots).length) roots.set(a.name, a.name);
  }
  if (!roots.size) return null;

  const calls = callsIn(masked, u.start, u.end);
  if (lang === 'rb') for (const c of rubyBareCalls(src, masked, u.start, u.end)) calls.push(c);
  const guards = [];
  const uses = [];
  for (const c of calls) {
    const name = c.method;
    const argRefs = () => valueRefs(src, masked, c.open + 1, c.close, roots).filter(r => !r.spread);
    const isHelper = guardingHelpers.has(name) && (c.segs.length === 1 || /^(?:this|self|\$this|@)$/.test(c.segs[0]));
    if (isGuardName(name, lang) || isHelper) {
      const argText = src.slice(c.open + 1, c.close).trim();
      const single = splitTop(argText).length === 1;
      for (const r of argRefs()) {
        const exact = isGuardName(name, lang) && single && src.slice(r.off, r.end).trim() === argText;
        guards.push({ path: r.path, off: c.start, name, exact, kind: isGuardName(name, lang) ? 'call' : 'helper' });
      }
      continue;
    }
    if (c.isNew || c.bare) continue;
    const recvSegs = c.segs.slice(0, -1);
    let key, label = null;
    if (/^set[A-Z_]\w{0,60}$/.test(name) && recvSegs.length) {
      // A setter is the same primitive as assigning the field it sets.
      key = `assign:${name.slice(3).replace(/^_/, '').replace(/^[A-Z]/, x => x.toLowerCase())}`;
      label = `${normRecv(recvSegs)}.${name}`;
    } else if (recvSegs.length) {
      if (c.broken) continue;
      const recv = normRecv(recvSegs);
      if (recv === 'this' && unitNames.has(name)) continue;   // delegation to a sibling
      const httpVerb = name === 'get' || name === 'put';
      const pathJoin = name === 'join' && /(?:^|\.)(?:path|filepath|Path|File|Paths)$/.test(recv);
      if (NOISE_METHOD_RE.test(name) && !httpVerb && !pathJoin) continue;
      if (NOISE_RECV_RE.test(recv) || NOISE_RECV_RE.test(recvSegs[0])) continue;
      if (httpVerb && !/(?:http|client|session|request|axios|requests|api|got|fetch|rest|web|conn|curl|agent)/i.test(recv)) continue;
      key = `call:${recv}.${name}`;
    } else {
      if (unitNames.has(name) || !BARE_PRIMITIVE_RE.test(name)) continue;
      key = `call:${name}`;
    }
    for (const r of valueRefs(src, masked, c.open + 1, c.close, roots)) {
      if (r.spread) continue;
      uses.push({ key, path: r.path, role: r.role, off: r.off, line: lineAt(starts, c.start), primitive: label || key.slice(key.indexOf(':') + 1) });
    }
  }
  for (const a of assigns) {
    if (a.kind !== 'field') continue;
    for (const r of valueRefs(src, masked, a.rhsFrom, a.rhsTo, roots)) {
      if (r.spread) continue;
      uses.push({ key: `assign:${a.field.replace(/^_/, '')}`, path: r.path, role: r.role, off: r.off, line: lineAt(starts, a.start), primitive: `${a.recv}.${a.field} =` });
    }
  }
  for (const g of inlineExitChecks(src, masked, u, roots)) guards.push(g);
  return { guards, uses, params: new Set(u.params), called: new Set(calls.map(c => c.method)) };
}

function covers(g, path) {
  return g === path || path.startsWith(g + '.') || g.startsWith(path + '.');
}

function guardFor(facts, use) {
  let best = null;
  for (const g of facts.guards) {
    if (g.off >= use.off) continue;
    if (!covers(g.path, use.path)) continue;
    if (!best || (g.kind === 'call' && best.kind !== 'call')) best = g;
  }
  return best;
}

// ---------------------------------------------------------------------------
// Thresholds.
// ---------------------------------------------------------------------------

/** Guarded siblings needed in the general case. */
export const MIN_GUARDED_VALUE_SIBLINGS = 2;

// One guarded sibling against one unguarded is a convention only when the
// pairing is unambiguous: the guard takes exactly the value (one argument,
// nothing else), the value is a parameter in both functions (not a local
// that merely shares a name), and the guard is named for the value role, or
// for the same concern the value and primitive have (`validateUrl(target)`
// before `http.get(target)`).
function tightPair(guarded, unguarded, role) {
  const g = guarded.guard;
  if (!g || g.kind !== 'call' || !g.exact) return false;
  if (!guarded.fromParam || !unguarded.fromParam) return false;
  const gname = g.name.replace(/[_!?]/g, '').toLowerCase();
  if (role.length >= 3 && gname.includes(role)) return true;
  const c = concernOf(g.name, '', '');
  return c.cwe !== 'CWE-20' && c.cwe === concernOf('', role, unguarded.use.primitive).cwe;
}

/**
 * Pure per-file analysis over units with facts. Returns deviation records.
 */
export function analyseValueGuardsInFile(file, src, lang) {
  const masked = maskStrings(src, lang);
  const units = functionUnits(lang, masked);
  if (units.length < 2) return [];
  const starts = lineStarts(src);
  const unitNames = new Set(units.map(u => u.name));
  // Same-file helpers that apply a guard to their own parameter count as a
  // guard when a value is handed to them.
  const guardingHelpers = new Set();
  for (const u of units) {
    if (isGuardName(u.name, lang)) { guardingHelpers.add(u.name); continue; }
    const calls = callsIn(masked, u.start, u.end);
    const roots = new Map(u.params.map(p => [p, p]));
    if (calls.some(c => isGuardName(c.method, lang) && valueRefs(src, masked, c.open + 1, c.close, roots).length)) guardingHelpers.add(u.name);
  }
  const groups = new Map();
  // Names called from a function that applies a named guard: such a callee is
  // that function's helper, and its caller guarded the value one hop up.
  const calledFromGuarded = new Set();
  for (const u of units) {
    if (isGuardName(u.name, lang)) continue;   // the guard's own definition
    const facts = analyseUnit(src, masked, u, lang, unitNames, guardingHelpers, starts);
    if (facts && facts.guards.some(g => g.kind === 'call')) for (const n of facts.called) calledFromGuarded.add(n);
    if (!facts || !facts.uses.length) continue;
    // Per (key, role): a unit is guarded when every use is covered, unguarded when none is.
    const per = new Map();
    for (const use of facts.uses) {
      const k = `${use.key}|${use.role}`;
      if (!per.has(k)) per.set(k, []);
      per.get(k).push({ use, guard: guardFor(facts, use) });
    }
    for (const [k, list] of per) {
      const covered = list.filter(x => x.guard);
      const byCall = covered.filter(x => x.guard.kind === 'call');
      // A hand-written check, or a hand-off to a same-file helper that
      // guards, silences a unit but never votes for a convention: there is
      // no named guard at this site to compare others with.
      const state = covered.length === 0 ? 'unguarded'
        : byCall.length === list.length ? 'guarded'
        : covered.length === list.length ? 'neutral' : 'mixed';
      if (state === 'mixed' || state === 'neutral') continue;
      if (!groups.has(k)) groups.set(k, { guarded: [], unguarded: [] });
      const g = groups.get(k);
      const use = list[0].use;
      const row = {
        name: u.name, defLine: u.line, use, guard: covered[0]?.guard || null,
        fromParam: facts.params.has(use.path.split('.')[0]),
      };
      // Overloads and re-declarations: one vote per name.
      const bucket = state === 'guarded' ? g.guarded : g.unguarded;
      if (!bucket.some(x => x.name === u.name)) bucket.push(row);
    }
  }
  const out = [];
  for (const [k, g] of groups) {
    if (!g.unguarded.length || !g.guarded.length) continue;
    // A name that is both guarded and unguarded (overloads) is not evidence either way.
    const gNames = new Set(g.guarded.map(x => x.name));
    // A unit a guarded sibling calls is that sibling's helper: its caller
    // already applied the guard, one hop up. It neither deviates nor votes.
    const ung = g.unguarded.filter(x => !gNames.has(x.name) && !calledFromGuarded.has(x.name));
    if (!ung.length) continue;
    const role = k.slice(k.lastIndexOf('|') + 1);
    const nG = g.guarded.length, nU = ung.length;
    let ok = nG >= MIN_GUARDED_VALUE_SIBLINGS && nG > nU;
    let tight = false;
    if (!ok && nG === 1 && nU === 1 && tightPair(g.guarded[0], ung[0], role)) { ok = true; tight = true; }
    if (!ok) continue;
    const tally = new Map();
    for (const x of g.guarded) { const n = x.guard?.name || '?'; tally.set(n, (tally.get(n) || 0) + 1); }
    const consensusGuard = [...tally.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))[0][0];
    for (const x of ung) {
      const c = concernOf(consensusGuard, role, x.use.primitive);
      out.push({
        file, name: x.name, line: x.use.line, defLine: x.defLine, value: x.use.path, role,
        primitive: x.use.primitive, key: k, consensusGuard, cwe: c.cwe, concern: c.concern, tight,
        guardedSiblings: g.guarded.map(s => ({ name: s.name, line: s.use.line, guard: s.guard?.name })),
        ratio: nG / (nG + nU),
      });
    }
  }
  // One finding per unguarded function: prefer a concrete concern, then the
  // earliest line. Two roles of one object (`image`, `image.dtype`) are one omission.
  const best = new Map();
  for (const d of out) {
    const k = `${d.name}|${d.defLine}`;
    const cur = best.get(k);
    const rank = x => (x.cwe === 'CWE-20' ? 1 : 0);
    if (!cur || rank(d) < rank(cur) || (rank(d) === rank(cur) && d.line < cur.line)) best.set(k, d);
  }
  return [...best.values()].sort((a, b) => a.line - b.line || (a.name < b.name ? -1 : 1));
}

// Cheap per-file relevance gate: no guard-shaped identifier, no comparison.
const ANY_GUARD_TOKEN_RE = /\b(?:check|verify|validate|assert|require|ensure|guard|sanitiz|sanitis|authori[sz]|is_?safe|is_?allowed|is_?valid|isSafe|isAllowed|isValid|can_?[A-Za-z]|whitelist|allowlist|Check|Verify|Validate|Assert|Require|Ensure|Guard|Sanitiz|Authori[sz])\w{0,80}[!?]?\s{0,4}[( ]/;

export function isRelevantFile(file, raw) {
  if (!langOf(file)) return false;
  if (TEST_PATH_RE.test(file.replace(/\\/g, '/'))) return false;
  return ANY_GUARD_TOKEN_RE.test(raw);
}

export function valueGuardFinding(d) {
  const siblings = d.guardedSiblings.map(s => `${s.name}() (line ${s.line})`);
  return {
    id: `convention-deviation:value-guard-omitted:${d.file}:${d.line}:${d.name}:${d.role}`,
    file: d.file, line: d.line,
    vuln: `Convention deviation: ${d.name}() passes ${d.value} to ${d.primitive} without the ${d.consensusGuard}() check ${d.guardedSiblings.length === 1 ? 'its sibling applies' : 'its siblings apply'}`,
    severity: 'medium',
    cwe: d.cwe,
    family: 'convention-deviation',
    parser: 'CONVENTION',
    confidence: d.tight ? 0.5 : 0.55,
    description:
      `In this file, ${siblings.slice(0, 6).join(', ')} call${d.guardedSiblings.length === 1 ? 's' : ''} ${d.consensusGuard}() on ` +
      `the ${d.role} value before passing it to ${d.primitive}, and ${d.name}() passes its ${d.value} there without it. ` +
      `This is an inconsistency with the file's own ${d.concern} handling, not a proof of exploitability.`,
    remediation:
      `Call ${d.consensusGuard}() on ${d.value} in ${d.name}() before line ${d.line}, as its sibling${d.guardedSiblings.length === 1 ? ' does' : 's do'}, ` +
      'or document why this path does not need it.',
    checkedFor: `a guard on ${d.value} before ${d.primitive} in ${d.name}(); compared against ${d.guardedSiblings.length} guarded sibling(s)` +
      (d.tight ? ' (one-to-one: the guard takes exactly this value and is named for it)' : ''),
    evidenceSiblings: d.guardedSiblings.map(s => s.name),
    siblingEvidence: d.guardedSiblings,
  };
}

export const _valueInternals = { maskStrings, functionUnits, paramNames, callsIn, fieldAssignmentsIn, valueRefs, concernOf, isGuardName, chainBefore };
