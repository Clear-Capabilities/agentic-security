// The library threat model, narrowed (`js:caller-controlled`).
//
// A parameter of a function a module exports is supplied by whoever calls the library. Treating every such parameter as attacker input and
// every sink as dangerous reports, mostly, a library doing what it was written to do: a process runner runs the command it is handed, a template
// engine compiles the template it is handed, a file utility opens the path it is handed. This module holds the rules that decide which of those
// flows is worth a finding. It is pure policy: the IR states which parameters are exported (`ir/parser-js.js`), the catalog states that the
// annotation is a source (`dataflow/catalog.js`), the engine records where each finding's taint came from and how many calls separate the sink from
// that origin (`dataflow/engine.js`), and `judgeLibraryFinding` below decides.
//
// Modes (AGENTIC_SECURITY_LIBRARY_SOURCES):
//   unset / anything else  off: the annotation is emitted by the IR and is inert.
//   1 | narrow             the narrowed model below.
//   broad                  the original model: every exported parameter, every sink, any call depth. Kept for comparison only.
//
// The narrowed model reports a finding that rests ONLY on caller-controlled parameters when ALL of these hold:
//   1. the sink is in a dangerous class (command, code evaluation, file path, SQL or query, server-side request, deserialization, prototype
//      pollution, regular-expression construction); output encoding, headers, redirects, logging and the like are a caller's concern;
//   2. the sink is in the exported function itself or in a function it calls directly (one call away); a flow through deeper helpers is
//      not attributed to the exported parameter;
//   2b. the sink call is the API its class names and the parameter is that API's operand (`sinkPlausible`): a command sink is a function of
//      a process module the file imports (not a regex's `.exec`), a code sink is the global `eval`/`Function`, a timer given a built string,
//      or a function of `vm` or a template module (not a validator's `.compile`), a SQL sink is a method of some object (not a local function
//      named `execute`), a path sink receives the value as the path (argument 0, not the data written), a request sink lets the value choose
//      the start of the URL (not a path appended to a fixed host), and a regular expression embeds the value in a larger pattern (a pattern
//      handed over whole is a pattern by design);
//   3. no sanitizer covering the sink's class was observed on the value;
//   4. the parameter is not, by its name, the very thing the sink consumes (a `cmd` reaching a process call, a `url` reaching a request, a
//      `filePath` reaching a file read, a `sql` reaching a query), and is not code or a callback by design (`fn`, `callback`, `template`, ...);
//      for pattern, path and code sinks an `options`/`config` parameter is configuration by design (`isConfigParamName`);
//      parameters typed as functions or numbers in TypeScript or JSDoc are dropped earlier, by the IR;
//   5. the package that holds the file does not, by its own manifest (name, description, keywords) or by the name of its main export, exist to
//      perform that class of operation on what it is given (a process runner for command sinks, a template engine or compiler for code and
//      file sinks, a query builder or database client for SQL sinks, an HTTP client for request sinks, a file utility for path sinks, a matcher
//      for regular-expression sinks, a serializer for deserialization sinks).
// A finding with any other origin (request input, environment, ...) beside the caller-controlled parameter is not judged here at all.
//
// Origins are not always recorded: a value that crossed a loop variable, a destructuring or a summarised return can reach a sink with no
// origin in its trace. Such a finding cannot be attributed to a parameter, so none of the rules above can be checked for it. The narrowed
// model therefore runs the engine once with the library source held off (dataflow/index.js `runLibraryDifferential`): every finding of that
// run is reported as it would be without the flag, and of the findings that appear only with the source on, exactly those this module judged
// and kept (`_librarySource`) are added. A finding that the source created but that cannot be attributed is dropped (fails closed). The
// cost is a second engine pass, paid only while the narrowed model is on and only when the project exports a function.
// Nothing here reads a path pattern, a repository name or a label: every input is the scanned project's own code and its own package.json.
import path from 'node:path';

export const LIBRARY_SOURCE_ID = 'js-src-caller-controlled-param';

// The narrowed model runs the engine twice (dataflow/index.js): once with the library source held off, to know which findings exist without
// it, then with it. `withLibrarySourcesSuppressed` is how the first run holds it off without touching the environment.
let _suppressed = 0;
export function withLibrarySourcesSuppressed(fn) {
  _suppressed++;
  try { return fn(); } finally { _suppressed--; }
}
export function librarySourcesSuppressed() { return _suppressed > 0; }

export function libraryMode(env = process.env) {
  if (_suppressed > 0 && env === process.env) return 'off';
  const v = env.AGENTIC_SECURITY_LIBRARY_SOURCES;
  if (v === '1' || v === 'narrow') return 'narrow';
  if (v === 'broad') return 'broad';
  return 'off';
}

// ── sink classes ────────────────────────────────────────────────────────────
const CWE_CLASS = {
  'CWE-78': 'cmd', 'CWE-77': 'cmd', 'CWE-88': 'cmd',
  'CWE-94': 'code', 'CWE-95': 'code', 'CWE-1336': 'code',
  'CWE-22': 'path', 'CWE-23': 'path', 'CWE-36': 'path', 'CWE-73': 'path',
  'CWE-89': 'sql', 'CWE-943': 'sql',
  'CWE-918': 'ssrf',
  'CWE-502': 'deser',
  'CWE-1321': 'proto', 'CWE-915': 'proto',
  'CWE-1333': 'regex', 'CWE-730': 'regex', 'CWE-185': 'regex',
};
export function sinkClassOf(cwe) { return CWE_CLASS[String(cwe || '')] || null; }

// ── parameter names ─────────────────────────────────────────────────────────
// Split a parameter name into lower-case words: `filePath` -> [file, path], `shell_cmd` -> [shell, cmd], `$url` -> [url].
export function nameWords(name) {
  return String(name || '')
    .replace(/^[_$]+/, '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

// Code, commands and callbacks by design, whatever sink they reach: the name's LAST word decides (`userCallback`, `shellCommand`, `onDone` are;
// `commandName`, `codeLength` are not).
const BY_DESIGN_ANY = new Set([
  'cmd', 'cmds', 'command', 'commands', 'script', 'scripts', 'code', 'template', 'templates', 'tmpl', 'tpl',
  'fn', 'func', 'function', 'callback', 'callbacks', 'cb', 'handler', 'handlers', 'listener', 'listeners', 'hook', 'hooks',
  'expression', 'expressions', 'expr', 'exprs', 'iteratee', 'predicate', 'comparator', 'reviver', 'replacer', 'middleware', 'next', 'done',
]);
export function isByDesignParamName(name) {
  const w = nameWords(name);
  return w.length > 0 && BY_DESIGN_ANY.has(w[w.length - 1]);
}

// The operand a sink class consumes, named: ANY word of the parameter's name in the set marks it as that operand.
const ROLE_WORDS = {
  cmd: new Set(['cmd', 'command', 'commands', 'script', 'shell', 'bin', 'binary', 'exe', 'executable', 'program', 'prog', 'args', 'argv', 'arguments']),
  code: new Set(['code', 'source', 'src', 'script', 'js', 'body', 'template', 'tmpl', 'tpl', 'expression', 'expr', 'formula', 'snippet', 'program', 'module', 'fn', 'func']),
  path: new Set(['path', 'paths', 'pathname', 'filepath', 'file', 'files', 'filename', 'filenames', 'dir', 'dirs', 'dirname', 'directory', 'directories',
    'folder', 'dest', 'destination', 'cwd', 'root', 'src', 'location', 'base', 'basedir', 'tmp', 'temp', 'cache', 'p']),
  sql: new Set(['sql', 'query', 'queries', 'statement', 'statements', 'stmt', 'raw', 'clause', 'q']),
  ssrf: new Set(['url', 'urls', 'uri', 'uris', 'href', 'endpoint', 'link', 'host', 'hostname', 'origin', 'address', 'addr', 'domain', 'proxy',
    'remote', 'server', 'registry', 'base', 'api', 'location', 'target', 'webhook', 'redirect']),
  deser: new Set(['serialized', 'yaml', 'yml', 'json', 'pickle', 'marshal', 'marshalled', 'payload', 'encoded']),
  regex: new Set(['pattern', 'patterns', 'regex', 'regexp', 'regexes', 're', 'rx', 'glob', 'globs', 'matcher', 'match', 'mask', 'wildcard', 'expression', 'expr']),
  proto: new Set(),
};
export function isRoleParamName(name, cls) {
  const roles = ROLE_WORDS[cls];
  if (!roles || !roles.size) return false;
  const w = nameWords(name);
  if (!w.length) return false;
  if (roles.has(w.join(''))) return true;
  return w.some((x) => roles.has(x));
}

// An options or configuration object configures the library's own behaviour and is written by the developer who integrates it, not passed
// per call as data. For the classes where a configured value is the normal way to steer the operation (which pattern to build, which
// directory to use, which template or module to evaluate), a value read from such a parameter is configuration by design. For commands,
// queries, requests, deserialization and prototype writes it is still judged: an option spliced into a shell command is a real defect.
const CONFIG_WORDS = new Set(['options', 'opts', 'option', 'config', 'configuration', 'cfg', 'conf', 'settings', 'setting', 'preferences', 'prefs', 'defaults']);
const CONFIG_CLASSES = new Set(['regex', 'path', 'code']);
export function isConfigParamName(name, cls) {
  if (!CONFIG_CLASSES.has(cls)) return false;
  const w = nameWords(name);
  return w.length > 0 && CONFIG_WORDS.has(w[w.length - 1]);
}

// ── package purpose ─────────────────────────────────────────────────────────
// Vocabulary a package uses to say what it does. Matched against `name description keywords` of the nearest package.json, as words.
const PURPOSE = [
  { cls: ['cmd'], re: /\b(?:exec|execa|execute[sd]?|executing|spawn(?:s|ing)?|child[ _-]?process(?:es)?|subprocess(?:es)?|shell|shelljs|run(?:s|ning)? (?:a |shell |system )?commands?|command runner|process runner)\b/i },
  { cls: ['code', 'path'], re: /\b(?:template engine|templating|templates?|compil(?:e|er|ers|es|ing)|transpil(?:e|er|es|ing)|interpreter|evaluat(?:e|es|or|ion)|eval|sandbox|vm|expression (?:parser|evaluator|language)|code ?gen(?:erator|eration)?|bundler|minif(?:y|ier)|loader)\b/i },
  { cls: ['sql'], re: /\b(?:query builder|sql builder|sql|orm|database|db|mysql|postgres(?:ql)?|sqlite|mssql|mongodb|mongo|redis|knex)\b/i },
  { cls: ['ssrf'], re: /\b(?:http client|https? requests?|request library|fetch|ajax|xhr|http|https|proxy|download(?:er|s)?|crawler|scraper|websocket|rest client|api client|url)\b/i },
  { cls: ['path'], re: /\b(?:file ?system|fs|files?|director(?:y|ies)|glob(?:s|bing)?|mkdirp?|rimraf|rm -rf|copy|move|remove|delete|watch(?:er|ing)?|path|paths|tar|zip|archive|archiver|extract|static|send|serve|upload)\b/i },
  { cls: ['regex'], re: /\b(?:glob(?:s|bing)?|regex|regexp|regular expressions?|pattern(?:s| matching)?|wildcard|matcher|match(?:ing)?|minimatch|router|routing|route)\b/i },
  { cls: ['deser'], re: /\b(?:yaml|serializ(?:e|er|ation)|deserializ(?:e|er|ation)|marshal(?:l?ing)?|pickle|parser|parse)\b/i },
];
// The name of the package's main export, when it is a function or a binding the main file names.
const MAIN_NAME_PURPOSE = [
  { cls: ['cmd'], re: /^(?:exec|execa|execute|execSync|run|runner|spawn|shell|sh|cmd|command)/i },
  { cls: ['code', 'path'], re: /^(?:eval|evaluate|compile|compiler|render|template|interpret|transpile|transform)/i },
  { cls: ['sql'], re: /^(?:query|knex|sql|db|database)/i },
  { cls: ['ssrf'], re: /^(?:fetch|request|got|axios|http|download)/i },
];

const MAIN_EXPORT_RES = [
  /module\.exports\s*=\s*(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/,
  /module\.exports\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$/m,
  /export\s+default\s+(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/,
  /export\s+default\s+([A-Za-z_$][\w$]*)\s*;?\s*$/m,
  /export\s*\{[^}]*?\b([A-Za-z_$][\w$]*)\s+as\s+default\b/,
];
export function mainExportName(code) {
  if (typeof code !== 'string' || !code) return null;
  for (const re of MAIN_EXPORT_RES) {
    const m = re.exec(code);
    if (m && m[1] && !/^(?:class|function|async|require|new|exports|module)$/.test(m[1])) return m[1];
  }
  return null;
}

function _mainEntry(pkg) {
  const pick = (v) => {
    if (typeof v === 'string') return v;
    if (v && typeof v === 'object') {
      for (const k of ['.', 'require', 'import', 'node', 'default']) { const r = pick(v[k]); if (r) return r; }
    }
    return null;
  };
  return pick(pkg && pkg.exports) || (pkg && typeof pkg.main === 'string' ? pkg.main : null) || 'index.js';
}

// Classes of sink a package exists to perform on what it is given. `pkg` is a parsed package.json, `mainCode` the text of its main file.
export function packagePurpose(pkg, mainCode) {
  const out = new Set();
  if (!pkg || typeof pkg !== 'object') return out;
  const name = String(pkg.name || '').replace(/^@[^/]+\//, '');
  const nameText = name.split(/[^A-Za-z0-9]+/).map((w) => w.replace(/js$/i, '')).join(' ');
  const text = [nameText, typeof pkg.description === 'string' ? pkg.description : '', Array.isArray(pkg.keywords) ? pkg.keywords.join(' ') : ''].join(' ');
  for (const p of PURPOSE) if (p.re.test(text)) for (const c of p.cls) out.add(c);
  const main = mainExportName(mainCode);
  if (main) for (const p of MAIN_NAME_PURPOSE) if (p.re.test(main)) for (const c of p.cls) out.add(c);
  return out;
}

// Per-scan policy: resolves the nearest package.json of a file and caches its purpose. It reads only the scan's own maps, keyed by path
// relative to the scan root (`fileContents` for code, `manifestContents` for package.json files), so nothing outside the scanned project, and
// nothing on disk, is consulted.
export function createLibraryPolicy({ fileContents = null, manifestContents = null } = {}) {
  const read = (rel) => {
    if (manifestContents && typeof manifestContents[rel] === 'string') return manifestContents[rel];
    if (fileContents && typeof fileContents[rel] === 'string') return fileContents[rel];
    return null;
  };
  const norm = (rel) => path.posix.normalize(String(rel).replace(/\\/g, '/')).replace(/^\.\//, '');
  const join = (dir, name) => norm(dir === '.' || dir === '' ? name : `${dir}/${name}`);
  const byDir = new Map();
  const purposeOfDir = (dir) => {
    if (byDir.has(dir)) return byDir.get(dir);
    let result = new Set();
    const txt = read(join(dir, 'package.json'));
    if (txt != null) {
      let pkg = null;
      try { pkg = JSON.parse(txt); } catch { pkg = null; }
      if (pkg) {
        const entry = _mainEntry(pkg);
        let main = read(join(dir, entry));
        if (main == null && !/\.[cm]?[jt]s$/.test(entry)) main = read(join(dir, `${entry}.js`)) ?? read(join(dir, `${entry}/index.js`));
        result = packagePurpose(pkg, main);
      }
    } else if (dir !== '.' && dir !== '' && !dir.startsWith('..')) {
      result = purposeOfDir(path.posix.dirname(dir));
    }
    byDir.set(dir, result);
    return result;
  };
  const bindings = new Map();
  return {
    bindingsOf(file) {
      if (!file) return new Map();
      const rel = norm(file);
      if (bindings.has(rel)) return bindings.get(rel);
      const b = moduleBindings(read(rel) || '');
      bindings.set(rel, b);
      return b;
    },
    purposeOf(file) {
      if (!file || path.isAbsolute(String(file))) return new Set();
      return purposeOfDir(path.posix.dirname(norm(file)));
    },
  };
}

// ── what a sink call is bound to ────────────────────────────────────────────
// Local names a file binds to modules: `const cp = require('child_process')`, `const { exec } = require('child_process')`,
// `import cp from 'node:child_process'`, `import * as vm from 'vm'`, `import { execSync as run } from 'child_process'`. Map local -> module.
// Each pattern is a plain sequence of bounded classes (no optional group between two whitespace runs).
const REQ_DEFAULT = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"\n]+)['"]\s*\)/g;
const REQ_DESTRUCT = /\b(?:const|let|var)\s*\{([^{}]*)\}\s*=\s*require\(\s*['"]([^'"\n]+)['"]\s*\)/g;
const IMP_NS = /\bimport\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s+from\s*['"]([^'"\n]+)['"]/g;
const IMP_DEFAULT = /\bimport\s+([A-Za-z_$][\w$]*)\s+from\s*['"]([^'"\n]+)['"]/g;
const IMP_DEFAULT_AND_NAMED = /\bimport\s+([A-Za-z_$][\w$]*)\s*,\s*\{([^{}]*)\}\s*from\s*['"]([^'"\n]+)['"]/g;
const IMP_NAMED = /\bimport\s*\{([^{}]*)\}\s*from\s*['"]([^'"\n]+)['"]/g;
const IMP_TS_EQ = /\bimport\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"\n]+)['"]\s*\)/g;
function _namedLocals(list, sep) {
  return String(list).split(',').map((x) => x.trim()).filter(Boolean).map((x) => x.split(sep).pop().trim()).filter((x) => /^[A-Za-z_$][\w$]*$/.test(x));
}
export function moduleBindings(text) {
  const out = new Map();
  if (typeof text !== 'string' || !text) return out;
  const mod = (m) => m.replace(/^node:/, '');
  for (const m of text.matchAll(REQ_DEFAULT)) out.set(m[1], mod(m[2]));
  for (const m of text.matchAll(IMP_TS_EQ)) out.set(m[1], mod(m[2]));
  for (const m of text.matchAll(IMP_NS)) out.set(m[1], mod(m[2]));
  for (const m of text.matchAll(IMP_DEFAULT)) out.set(m[1], mod(m[2]));
  for (const m of text.matchAll(IMP_DEFAULT_AND_NAMED)) { out.set(m[1], mod(m[3])); for (const n of _namedLocals(m[2], /\s+as\s+/)) out.set(n, mod(m[3])); }
  for (const m of text.matchAll(REQ_DESTRUCT)) for (const n of _namedLocals(m[1], ':')) out.set(n, mod(m[2]));
  for (const m of text.matchAll(IMP_NAMED)) for (const n of _namedLocals(m[1], /\s+as\s+/)) out.set(n, mod(m[2]));
  return out;
}

// { base, prop } of a call's callee: `cp.execSync` -> { base: 'cp', baseModule: null, prop: 'execSync' }, `exec` -> { base: null, prop: 'exec' },
// `require('child_process').exec` -> { baseModule: 'child_process', prop: 'exec' }.
function calleeShape(callee) {
  if (typeof callee === 'string') {
    const segs = callee.split('.');
    return { base: segs.length > 1 ? segs[0] : null, baseModule: null, prop: segs[segs.length - 1] };
  }
  if (!callee || typeof callee !== 'object') return { base: null, baseModule: null, prop: null };
  if (callee.kind === 'ident') return { base: null, baseModule: null, prop: callee.name };
  if (callee.kind === 'member') {
    let o = callee.object;
    while (o && o.kind === 'member') o = o.object;
    const reqMod = o && o.kind === 'call' && o.callee && o.callee.kind === 'ident' && o.callee.name === 'require'
      && o.args && o.args[0] && o.args[0].kind === 'literal' ? String(o.args[0].value).replace(/^node:/, '') : null;
    return { base: o && o.kind === 'ident' ? o.name : null, baseModule: reqMod, prop: typeof callee.prop === 'string' ? callee.prop : null, depth: callee.object && callee.object.kind === 'member' ? 2 : 1 };
  }
  return { base: null, baseModule: null, prop: null };
}

const PROCESS_MODULE = /^(?:child_process|execa|cross-spawn|shelljs|spawn-sync|execa\/.*)$/;
const VM_MODULE = /^(?:vm|vm2|isolated-vm)$/;
const TEMPLATE_MODULE = /^(?:handlebars|hbs|ejs|pug|nunjucks|mustache|lodash\.template)$/;
const GLOBAL_OBJECT = /^(?:window|globalThis|global|self)$/;
// The sink call is the API its class names, not a same-named method of something else (a regex's `.exec`, a socket's `.setTimeout`,
// a schema validator's `.compile`, a local function named `execute`), and the tainted argument is the operand that class is about.
export function sinkPlausible(finding, cls, bindings = new Map()) {
  const c = calleeShape(finding && finding.callee);
  const moduleOf = (name) => (name ? bindings.get(name) || null : null);
  const shape = (finding && finding._argShape) || null;
  switch (cls) {
    case 'cmd': {
      if (c.baseModule) return PROCESS_MODULE.test(c.baseModule);
      if (c.base) return PROCESS_MODULE.test(moduleOf(c.base) || '');
      return PROCESS_MODULE.test(moduleOf(c.prop) || '');
    }
    case 'code': {
      if (c.prop === 'eval' || c.prop === 'Function') return !c.base || GLOBAL_OBJECT.test(c.base);
      if (c.prop === 'setTimeout' || c.prop === 'setInterval') return (!c.base || GLOBAL_OBJECT.test(c.base)) && !!shape && shape.composite;
      const m = c.baseModule || moduleOf(c.base) || moduleOf(c.prop);
      if (m && (VM_MODULE.test(m) || TEMPLATE_MODULE.test(m))) return true;
      return c.base === 'vm';
    }
    case 'sql': return !!c.base || !!c.baseModule || (c.depth || 0) > 0;
    case 'path': return finding.argIndex === 0 || finding.argIndex === 'rhs';
    case 'ssrf': return !shape || shape.leadTainted;
    case 'regex': return !shape || shape.composite;
    default: return true;
  }
}

// ── the judgement ───────────────────────────────────────────────────────────
// Every origin record behind a finding's trace, following interprocedural `from` links.
function rootRecords(trace, depth = 0, out = []) {
  for (const t of trace || []) {
    if (!t) continue;
    if (Array.isArray(t.from) && t.from.length && depth < 8) { rootRecords(t.from, depth + 1, out); continue; }
    out.push(t);
  }
  return out;
}

// Number of calls between the function holding the sink and the exported function a parameter belongs to: 0 when it is the same function,
// 1 when the exported function calls the sink's function directly, null when the chain does not pass through it.
export function callDistance(finding, fnQid) {
  const chain = Array.isArray(finding && finding._hops) && finding._hops.length ? finding._hops : [finding && finding._funcQid];
  const i = chain.indexOf(fnQid);
  return i < 0 ? null : i;
}

// `opts.policy` from createLibraryPolicy, `opts.sanitizerCovers(names, finding)` reports whether an observed sanitizer neutralises the sink's class.
// Returns { library: false } for a finding that does not rest only on caller-controlled parameters (not judged), else { library: true, keep, reason }.
export function judgeLibraryFinding(finding, file, opts = {}) {
  const roots = rootRecords(finding && finding.trace);
  if (!roots.length || !roots.every((r) => r && r.sourceId === LIBRARY_SOURCE_ID)) return { library: false };
  const mode = opts.mode || libraryMode();
  if (mode !== 'narrow') return { library: true, keep: true, reason: 'broad' };
  const cls = sinkClassOf(finding.cwe);
  if (!cls) return { library: true, keep: false, reason: 'sink-class' };
  if (typeof opts.sanitizerCovers === 'function' && Array.isArray(finding._sanitizersOnPath) && finding._sanitizersOnPath.length
    && opts.sanitizerCovers(finding._sanitizersOnPath, finding)) return { library: true, keep: false, reason: 'sanitized' };
  if (!sinkPlausible(finding, cls, opts.policy && opts.policy.bindingsOf ? opts.policy.bindingsOf(file) : new Map())) return { library: true, keep: false, reason: 'sink-shape' };
  const purpose = opts.policy ? opts.policy.purposeOf(file) : new Set();
  if (purpose.has(cls)) return { library: true, keep: false, reason: 'package-purpose' };
  let why = 'param-name';
  for (const r of roots) {
    // The parameter itself: a record copied onto a derived variable (`_inheritSources`) keeps the parameter's own name in `paramName`.
    const pname = r.paramName || r.varName;
    if (isByDesignParamName(pname) || isRoleParamName(pname, cls) || isConfigParamName(pname, cls)) continue;
    const d = callDistance(finding, r.fnQid);
    if (d === null || d > 1) { why = 'call-depth'; continue; }
    return { library: true, keep: true, reason: 'caller-controlled', param: pname, distance: d };
  }
  return { library: true, keep: false, reason: why };
}

// Merge the two engine runs of the narrowed model. `base` is the run with the library source held off, `seeded` the run with it on (its
// library-only findings already judged by the engine, kept ones marked `_librarySource`). Returns `seeded`, filtered in place so the array's
// non-enumerable diagnostics (analysisIncomplete, ...) survive: every finding `base` also has, plus the kept library findings. A finding of
// `base` that the seeded run lost (a deadline, a budget) is added back.
export function mergeLibraryDifferential(base, seeded) {
  const baseIds = new Set((base || []).map((f) => f && f.id));
  const kept = seeded.filter((f) => f && (baseIds.has(f.id) || f._librarySource === true));
  const have = new Set(kept.map((f) => f.id));
  for (const f of base || []) if (f && !have.has(f.id)) { kept.push(f); have.add(f.id); }
  seeded.length = 0;
  seeded.push(...kept);
  return seeded;
}

// Does any function of the project carry the caller-controlled annotation (is there anything for the library source to seed)?
export function hasCallerControlledParams(functions) {
  for (const fn of functions || []) if (Array.isArray(fn && fn.paramAnnotations) && fn.paramAnnotations.some((a) => a && a.decorator === 'js:caller-controlled')) return true;
  return false;
}

// The SAST twin of the engine's caller-controlled source (`sast/js-exec-param-interpolation.js`, parser JS-EXEC) cannot see the manifests;
// under the narrowed model its findings in a package whose own purpose is running commands are removed here, in place.
export function dropLibraryPurposeFindings(findings, maps = {}) {
  if (libraryMode() !== 'narrow' || !Array.isArray(findings) || !findings.length) return findings;
  if (!findings.some((f) => f && f.parser === 'JS-EXEC')) return findings;
  const policy = createLibraryPolicy(maps);
  const keep = findings.filter((f) => !(f && f.parser === 'JS-EXEC' && policy.purposeOf(f.file).has('cmd')));
  findings.length = 0;
  findings.push(...keep);
  return findings;
}
