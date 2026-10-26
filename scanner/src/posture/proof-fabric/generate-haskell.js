// Reproducer generation for Haskell (PRD 1), the third language of `generate.js`. Same contract as JavaScript and Python: a
// DETERMINISTIC proposal built from the flagged file alone, then run through the ordinary runner, oracle, 3-of-3 repetition and
// independent replay. A generated reproducer is a proposal that execution either confirms or does not.
//
// The program is run by GHC's interpreter (`ghc -e`), not compiled. Why: it needs no C compiler and no linker (so no dependence on
// the platform's developer tools), it leaves no object files or binaries to account for, it starts in about half a second where a
// compile-then-run takes a second or more, and there is one process tree to confine instead of a build stage followed by a run
// stage. Interpreted bytecode calls the same installed libraries a compiled program would, so a shell string reaches the same
// `System.Process` either way. The tradeoff is stated, not hidden: a program whose behaviour depends on compiled code (FFI, an
// optimisation-sensitive race) is refused, and `-O` is never in play. A hand-written reproducer may still use `build`/`run` with
// `{{GHC}}` to compile; both paths run under the same sandbox, timeout and output cap.
//
// Two shapes, as in the other languages:
//   script    the file reads `getArgs`: it is run as `:main "<payload>"`, so the payload arrives as the first argument;
//   function  a top-level function around the flagged line that has a type signature of `String`/`FilePath` parameters and an `IO`
//             result: `ghc -e 'fn "<payload>" ...'` loads the module with every top-level name in scope (the module need not export
//             it) and calls it with the payload in every parameter.
//
// Only what the proof environment can load is accepted: the file's imports must be modules of the packages that ship with GHC (the
// global package database, read from the installed GHC) or other `.hs` files in the repository. A web framework, a database binding
// or any Hackage package is refused with the package named where it is known. Template Haskell, quasi-quotes, CPP, the foreign
// function interface and compiler-plugin options are refused too: they run code at load time, before the payload is involved.
//
// Classes, each with an oracle that sees its effect and nothing else:
//   command injection (CWE-78)    a nonce-named canary file the injected command alone could create;
//   path traversal by a WRITE     a file created or changed outside the directory the program writes to (CWE-22);
//   path traversal by a READ      a per-run secret, planted in a file one directory above the program's base directory, appears in the
//                                 program's output (stdout, stderr or, for a function, its printed result). A read whose content never
//                                 reaches the output leaves nothing to see and stays unproven;
//   argument injection (CWE-88)   the called program is replaced by a harness stand-in that acts on one planted option, but only when that
//                                 option is its FIRST argument; the canary exists only if attacker data reached the first position of the
//                                 argument vector. It shows the option position is attacker-controlled, not that the real program has a
//                                 dangerous option, and the generated reproducer says so in its assumptions.
// Refused on purpose, with the construct named and the way to supply a hand-written reproducer: SSRF (no HTTP client ships with GHC), SQL
// (no database binding ships with GHC), deserialization, XSS, code injection, argument injection past the first argument, reads and writes
// whose base directory the file does not state, and any function the proof cannot fill or call. Nothing is executed on a refusal.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseHaskell } from '../../language/haskell-parser.js';
import { validateReproducer } from './reproducer.js';
import { hostTools } from './runner.js';

const MAX_SOURCE = 256 * 1024;
const MAX_FILES = 8;
const fail = (reason, extra = {}) => ({ ok: false, reason, ...extra });

// Well-known packages that are NOT part of a GHC install, by module prefix, so a refusal can name the package to install.
const THIRD_PARTY = [
  ['Web.Scotty', 'scotty'], ['Network.Wai', 'wai'], ['Network.HTTP.Types', 'http-types'], ['Network.HTTP.Client', 'http-client'],
  ['Network.HTTP.Simple', 'http-conduit'], ['Network.HTTP.Conduit', 'http-conduit'], ['Network.Wreq', 'wreq'], ['Network.Socket', 'network'],
  ['Servant', 'servant'], ['Yesod', 'yesod'], ['Snap', 'snap'], ['Happstack', 'happstack-server'], ['Data.Aeson', 'aeson'],
  ['Database.SQLite.Simple', 'sqlite-simple'], ['Database.PostgreSQL.Simple', 'postgresql-simple'], ['Database.Persist', 'persistent'],
  ['Database.MySQL', 'mysql-simple'], ['System.Random', 'random'], ['Data.Vector', 'vector'], ['Data.Hashable', 'hashable'],
  ['Data.HashMap', 'unordered-containers'], ['Control.Lens', 'lens'], ['Test.', 'a test framework'], ['Turtle', 'turtle'],
  ['Shelly', 'shelly'], ['System.Process.Typed', 'typed-process'], ['Conduit', 'conduit'], ['Control.Monad.Logger', 'monad-logger'],
  ['Options.Applicative', 'optparse-applicative'], ['Data.Text.Lazy.Builder', null],
];

const libCache = new Map();
/** The modules the installed GHC exposes from its global package database (what a program can import with no extra packages). */
export function bootModuleSet(ghc) {
  if (libCache.has(ghc)) return libCache.get(ghc);
  let set = null;
  try {
    const r = spawnSync(ghc, ['--print-libdir'], { encoding: 'utf8', timeout: 10_000 });
    const dir = r.status === 0 ? path.join(r.stdout.trim(), 'package.conf.d') : null;
    if (dir && fs.existsSync(dir)) {
      set = new Set();
      for (const f of fs.readdirSync(dir)) {
        if (!f.endsWith('.conf')) continue;
        const text = fs.readFileSync(path.join(dir, f), 'utf8');
        if (/^exposed:\s*False/m.test(text)) continue;
        const m = /^exposed-modules:\s*\n?([\s\S]*?)(?=^\S)/m.exec(text);
        if (!m) continue;
        for (const tok of m[1].split(/[\s,]+/)) if (/^[A-Z][\w']*(?:\.[A-Z][\w']*)*$/.test(tok)) set.add(tok);
      }
      if (!set.has('Prelude')) set = null; // a database that does not even list Prelude was not read correctly
    }
  } catch { set = null; }
  libCache.set(ghc, set);
  return set;
}

function readInside(root, rel) {
  let real; try { real = fs.realpathSync(path.resolve(root, rel)); } catch { return null; }
  const base = fs.realpathSync(root);
  if (!(real === base || real.startsWith(base + path.sep))) return null;
  const st = fs.statSync(real);
  return st.isFile() && st.size <= MAX_SOURCE ? { real, text: fs.readFileSync(real, 'utf8') } : null;
}

/** Split a type on its top-level arrows (arrows inside parentheses or brackets belong to a function-typed argument). */
function splitArrows(type) {
  const parts = []; let depth = 0; let cur = '';
  for (let i = 0; i < type.length; i++) {
    const c = type[i];
    if ('([{'.includes(c)) depth++; else if (')]}'.includes(c)) depth--;
    if (depth === 0 && c === '-' && type[i + 1] === '>') { parts.push(cur.trim()); cur = ''; i++; continue; }
    cur += c;
  }
  parts.push(cur.trim());
  return parts;
}

// Compile-time code execution and options that change what runs before the payload is involved.
function loadTimeHazard(text) {
  if (/\{-#\s*LANGUAGE[^#]*\b(?:TemplateHaskell|TemplateHaskellQuotes|QuasiQuotes|CPP|ForeignFunctionInterface|CApiFFI)\b/i.test(text)) return 'it enables Template Haskell, quasi-quotes, CPP or the foreign function interface, which run or require code at load time';
  if (/\{-#\s*OPTIONS(?:_GHC)?\b[^#]*(?:-fplugin|-pgm|-opt[a-zA-Z]|-F\b|-cpp|-fobject-code)/i.test(text)) return 'its OPTIONS_GHC pragma names a plugin, a preprocessor or an external program';
  if (/^\s*foreign\s+(?:import|export)\b/m.test(text)) return 'it uses the foreign function interface';
  return null;
}

function classify(mod, pkg, boot) {
  if (pkg) return { ok: false, name: String(pkg).replace(/^"|"$/g, '') };
  if (boot.has(mod)) return { ok: true };
  for (const [prefix, name] of THIRD_PARTY) if (mod === prefix || mod.startsWith(prefix.endsWith('.') ? prefix : `${prefix}.`)) return { ok: false, name: name ?? mod };
  return { ok: false, name: mod };
}

// ---------------------------------------------------------------------------------------------------------------- parameter types

const STRING_TYPES = /^(?:String|Prelude\.String|FilePath|System\.IO\.FilePath|\[Char\])$/;
const unparen = (t) => { let x = t.trim(); while (x.startsWith('(') && x.endsWith(')') && splitArrows(x.slice(1, -1)).length === 1 && !x.slice(1, -1).includes(',')) x = x.slice(1, -1).trim(); return x; };

/** What the file means by `Text` and `ByteString` (an import of the real module, not a local type of the same name) and its one-line `type` aliases. */
function typeResolver(info, text) {
  const textQ = new Set(); const bytesQ = new Set(); let textBare = false; let bytesBare = false;
  for (const imp of info.imports ?? []) {
    const isText = /^Data\.Text(?:\.Lazy)?$/.test(imp.module);
    const isBytes = /^Data\.ByteString(?:\.(?:Char8|Lazy|Lazy\.Char8))?$/.test(imp.module);
    if (!isText && !isBytes) continue;
    const bare = !imp.qualified && !imp.hiding && (imp.items == null || imp.items.some((i) => /^(?:Text|ByteString)\b/.test(i)));
    if (isText) { textQ.add(imp.as ?? imp.module); textBare ||= bare; } else { bytesQ.add(imp.as ?? imp.module); bytesBare ||= bare; }
  }
  const localDef = (n) => new RegExp(`^(?:data|newtype)\\s+${n}\\b`, 'm').test(text);
  if (localDef('Text')) textBare = false;
  if (localDef('ByteString')) bytesBare = false;
  const aliases = new Map();
  for (const m of text.matchAll(/^type\s+([A-Z][\w']*)\s*=\s*([^\n=]+?)\s*(?:--.*)?$/gm)) aliases.set(m[1], m[2]);
  const resolve = (t, depth = 0) => {
    const x = unparen(t);
    if (depth < 4 && aliases.has(x)) return resolve(aliases.get(x), depth + 1);
    return x;
  };
  const stringish = (t) => {
    const x = resolve(t);
    if (STRING_TYPES.test(x)) return 'string';
    const q = /^(?:([A-Z][\w.]*)\.)?(Text|ByteString)$/.exec(x);
    if (!q) return null;
    if (q[2] === 'Text') return q[1] ? (textQ.has(q[1]) ? 'overloaded' : null) : (textBare ? 'overloaded' : null);
    return q[1] ? (bytesQ.has(q[1]) ? 'overloaded' : null) : (bytesBare ? 'overloaded' : null);
  };
  /** `{lit}` is the Haskell expression for a value of this type holding `value`, `{needsOverloaded}` whether it relies on OverloadedStrings. */
  const fill = (t, value) => {
    const x = resolve(t);
    const one = stringish(x);
    if (one) return { expr: value, overloaded: one === 'overloaded' };
    const list = /^\[\s*(.+?)\s*\]$/.exec(x);
    if (list) { const e = stringish(list[1]); if (e) return { expr: `[${value}]`, overloaded: e === 'overloaded' }; }
    const maybe = /^Maybe\s+(.+)$/.exec(x);
    if (maybe) { const e = stringish(maybe[1]); if (e) return { expr: `(Just ${value})`, overloaded: e === 'overloaded' }; }
    return null;
  };
  /** The result can be shown by `print` and carries the content a read returned (String, Text, ByteString, lists and Maybe of them). */
  const printable = (t) => {
    const x = resolve(t);
    return !!(stringish(x) || (/^\[\s*(.+?)\s*\]$/.exec(x) && stringish(/^\[\s*(.+?)\s*\]$/.exec(x)[1])) || (/^Maybe\s+(.+)$/.exec(x) && stringish(/^Maybe\s+(.+)$/.exec(x)[1])));
  };
  return { fill, printable, resolve };
}

// ---------------------------------------------------------------------------------------------------------------- path traversal: write or read

const READ_SINK = /\b(?:readFile'?|readFileBinary)\b|\b(?:openFile|withFile|openBinaryFile|withBinaryFile)\b[^\n]*\bReadMode\b/;
const READ_PAYLOAD = '../agentic-proof-secret.txt';
const READ_SECRET_FILE = 'agentic-proof-secret.txt';
const READ_ORACLE = { type: 'file_disclosure', params: { secret: 'file' } };
const WRITE_CONSTRUCTS = 'writeFile, appendFile, copyFile, renameFile, or openFile/withFile in WriteMode/AppendMode';
const READ_CONSTRUCTS = 'readFile, or openFile/withFile in ReadMode';

/** Which path operation the flagged line is: its own line first, then the lines around it. */
function pathKind(sinkLine, around, writeRe) {
  if (writeRe.test(sinkLine)) return 'write';
  if (READ_SINK.test(sinkLine)) return 'read';
  if (writeRe.test(around)) return 'write';
  if (READ_SINK.test(around)) return 'read';
  return null;
}

/**
 * The directories a read is meant to stay under, as far as the source says: a literal that ends in a slash, or sits next to `</>`, or is
 * bound to a name that says directory. The proof creates them (empty) so that `dir/../secret` resolves; a program whose base is not a
 * relative literal cannot be modelled and is refused rather than guessed.
 */
function readBaseDirs(text) {
  const found = [];
  const add = (lit) => {
    if (!lit || lit.startsWith('/') || lit.includes('..') || lit.includes('\\') || /[{}\s:*?"<>|]/.test(lit)) return;
    const seg = lit.split('/').filter(Boolean)[0];
    if (!seg || seg === '.' || ['canary', 'tmp'].includes(seg) || !/^[A-Za-z0-9._-]{1,32}$/.test(seg) || seg.startsWith('__oracle_')) return;
    if (!found.includes(seg)) found.push(seg);
  };
  for (const m of text.matchAll(/"([^"\\\n]+\/)"/g)) add(m[1]);
  for (const m of text.matchAll(/"([^"\\\n]+)"\s*<\/>/g)) add(m[1]);
  for (const m of text.matchAll(/<\/>\s*"([^"\\\n]+)"/g)) add(m[1]);
  for (const m of text.matchAll(/\b[a-z]\w*(?:Dir|Base|Root|Folder|Path|Directory)\w*'?\s*=\s*"([^"\\\n]+)"/gi)) add(m[1]);
  return found.slice(0, 4);
}

// ---------------------------------------------------------------------------------------------------------------- argument injection

// Shells and the tools the proof itself runs are never stood in for: an argument to a shell is command injection (CWE-78), and shadowing
// a toolchain program on PATH would break the proof rather than test the finding.
const NEVER_STAND_IN = new Set(['sh', 'bash', 'dash', 'zsh', 'csh', 'tcsh', 'ksh', 'fish', 'env', 'ghc', 'runghc', 'ghci', 'cc', 'gcc', 'clang', 'c++', 'g++', 'ld', 'as', 'ar', 'make', 'cabal', 'stack', 'nix', 'sudo', 'su', 'ssh', 'xargs', 'chmod', 'touch', 'node', 'python', 'python3']);
const PROCESS_CALL = /\b(callProcess|readProcess|readProcessWithExitCode|spawnProcess|rawSystem|proc)\s+(?:\$\s*)?"([^"\\\s]+)"\s*/;
const STAND_IN = `#!/bin/sh
# Stand-in for the program the code under test calls. It is planted by the proof runner, never by the target.
# It acts on exactly one option, and only when that option is its FIRST argument, by creating the file the option names.
case "$1" in
  --agentic-proof-write=*) : > "\${1#--agentic-proof-write=}" ;;
esac
exit 0
`;
// PATH puts the stand-in directory first and keeps the system and toolchain directories after it
const STAND_IN_PATH = '{{ROOT}}/bin:/opt/ghc/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/homebrew/bin';

/** What stands in first position of the argument vector at the call: a named element, a whole list, a fixed string, or something else. */
function firstArgument(rest) {
  if (rest.startsWith('[')) {
    const inner = rest.slice(1).trimStart();
    if (inner.startsWith('"')) return { kind: 'literal' };
    if (inner.startsWith(']')) return { kind: 'empty' };
    const m = /^([a-z_][\w']*)\s*(?:,|\])/.exec(inner);
    return m ? { kind: 'element', name: m[1] } : { kind: 'complex' };
  }
  if (rest.startsWith('(')) {
    const m = /^\(\s*([a-z_][\w']*)\s*:/.exec(rest);
    return m ? { kind: 'element', name: m[1] } : { kind: 'complex' };
  }
  const m = /^([a-z_][\w']*)\s*(?:$|\)|"|--)/.exec(rest);
  return m ? { kind: 'list', name: m[1] } : { kind: 'complex' };
}

const HINT = 'To prove it anyway, write a reproducer for lang "haskell" (run: ["{{GHC}}", "-ignore-dot-ghci", "-e", "<expression that calls the code>", "<File>.hs"], with an oracle such as command_execution, filesystem_mutation or file_disclosure) and pass it with --reproducer <file>; see the Haskell section of the exploit proof guide. Nothing was executed.';

/** What the flagged line is, in words, for a refusal message. */
function describeLine(finding, root) {
  const src = (() => { try { return readInside(root, String(finding.file)); } catch { return null; } })();
  const line = src ? (src.text.split('\n')[finding.line - 1] ?? '').trim().replace(/\s+/g, ' ').slice(0, 90) : '';
  return line ? `the flagged line \`${line}\`` : 'the flagged code';
}

const REFUSALS = {
  'CWE-89': (what) => `sql-injection: ${what} reaches a database, and GHC ships no database binding, so a program that queries one imports a package outside the proof environment; a program that shells out to the sqlite3 command-line tool depends on a schema, a table and a column count the proof cannot know and a sqlite3 binary this host may not have. A SQL injection is not proven for Haskell.`,
  'CWE-502': (what) => `deserialization: ${what} decodes data, and nothing observable happens when a decoder reads hostile bytes unless a gadget exists in the program; the decoders in common use (aeson, yaml, cereal) are packages outside GHC's own. A deserialization flaw is not proven for Haskell.`,
  'CWE-79': (what) => `cross-site scripting: ${what} builds markup, and the effect is in a browser's DOM, which a command-line run cannot observe. XSS is not proven for Haskell.`,
  'CWE-94': (what) => `code injection: ${what} evaluates code at run time through an interpreter package (hint, plugins) that does not ship with GHC. Code injection is not proven for Haskell.`,
  'CWE-918': (what) => `ssrf: ${what} makes a request, and no HTTP client ships with GHC, so any program that makes one imports a package outside the proof environment. SSRF is not proven for Haskell.`,
  'CWE-1427': (what) => `prompt injection: ${what} builds a model prompt, whose effect needs a model endpoint the proof does not have. Not proven for Haskell.`,
};

/**
 * The reason a Haskell finding of a class this generator does not cover is refused, naming the construct and the way out.
 * @param {{finding: object, root: string, cwe: string|null}} o
 */
export function haskellRefusal({ finding, root, cwe }) {
  const what = describeLine(finding, root);
  const body = REFUSALS[cwe]?.(what) ?? `${cwe ?? 'this class'}: no payload and oracle exist for ${cwe ?? 'it'} in Haskell (${what}). Generated reproducers cover command injection (CWE-78), path traversal by a write or a read (CWE-22) and argument injection into a process call (CWE-88).`;
  return fail(`${body} ${HINT}`);
}

// ---------------------------------------------------------------------------------------------------------------- generation

/** @param {{finding: object, root: string, cls: {name: string, payload: string, oracle: object, network?: string, watch?: object, needsHs?: RegExp}, bootModules?: Set<string>}} o */
export function generateHaskellReproducer(o) {
  const r = generateInner(o);
  if (r.ok || r.reason.includes('Nothing was executed.')) return r;
  return { ...r, reason: `${r.reason.replace(/\.$/, '')}. ${HINT}` };
}

function generateInner({ finding, root, cls, bootModules }) {
  const rel = String(finding.file);
  if (cls.name === 'ssrf') return haskellRefusal({ finding, root, cwe: 'CWE-918' });
  const src = readInside(root, rel);
  if (!src) return fail('the flagged file is missing, outside the repository, or too large');
  const hazard = loadTimeHazard(src.text);
  if (hazard) return fail(`the flagged file is refused: ${hazard}`);
  if (/\{\{[A-Z_]+(?::[a-z0-9_-]{1,32})?\}\}/.test(src.text)) return fail('the flagged file contains text shaped like a proof placeholder ({{NAME}}), which the runner would substitute inside the program');
  const info = parseHaskell(src.text);
  if (!info || info.status !== 'parsed') return fail('the flagged file could not be parsed as Haskell');
  const lines = src.text.split('\n');
  const sinkLine = lines[finding.line - 1] ?? '';
  const around = lines.slice(Math.max(0, finding.line - 3), finding.line + 2).join('\n');

  // the class decides what is planted and what is watched; for a path operation the flagged line decides which of two it is
  let spec = cls;
  let kind = cls.name;
  if (cls.name === 'path-traversal') {
    const k = pathKind(sinkLine, around, cls.needsHs);
    if (!k) return fail(`path-traversal: ${describeLine(finding, root)} is not a write (${WRITE_CONSTRUCTS}) or a read (${READ_CONSTRUCTS}); other file operations (removeFile, createDirectory, listDirectory, doesFileExist, and the like) leave nothing the oracle can observe`);
    if (k === 'read') { kind = 'path-traversal-read'; spec = { name: 'path-traversal-read', payload: READ_PAYLOAD, oracle: READ_ORACLE }; }
  }

  const tools = hostTools();
  const boot = bootModules ?? (tools.ghc ? bootModuleSet(tools.ghc) : null);
  if (!boot) return fail('no working GHC was found to list the modules the proof environment can import (install ghc, or run `agentic-security proof doctor`)');

  // the entry module is placed at its module path so that other modules can import it; Main goes to Main.hs
  const modName = info.module?.name ?? 'Main';
  const entry = `${modName.replaceAll('.', '/')}.hs`;
  const rootReal = fs.realpathSync(root);
  const entryDir = path.dirname(src.real);
  const modRel = modName.replaceAll('.', path.sep);
  const srcRoot = src.real.endsWith(`${modRel}.hs`) ? src.real.slice(0, src.real.length - modRel.length - 3) : `${entryDir}${path.sep}`;
  const searchRoots = [...new Set([srcRoot.replace(/[\\/]$/, ''), ...['src', 'app', 'lib', ''].map((d) => path.join(rootReal, d))])];
  const sources = {}; const external = []; const seen = new Set([modName]);
  let count = 0;
  const visit = (imports) => {
    for (const imp of imports) {
      const mod = imp.module;
      if (seen.has(mod)) continue;
      seen.add(mod);
      let local = null;
      for (const base of searchRoots) { const cand = path.join(base, `${mod.replaceAll('.', '/')}.hs`); const r = readInside(root, path.relative(rootReal, cand)); if (r) { local = r; break; } }
      if (local && !imp.package) {
        if (++count > MAX_FILES) return fail(`the file pulls in more than ${MAX_FILES} repository modules`);
        const dep = parseHaskell(local.text);
        if (!dep || dep.status !== 'parsed') return fail(`the module ${mod} could not be parsed as Haskell`);
        const h = loadTimeHazard(local.text); if (h) return fail(`the module ${mod} is refused: ${h}`);
        if (/\{\{[A-Z_]+(?::[a-z0-9_-]{1,32})?\}\}/.test(local.text)) return fail(`the module ${mod} contains text shaped like a proof placeholder ({{NAME}})`);
        sources[`${mod.replaceAll('.', '/')}.hs`] = path.relative(rootReal, local.real);
        const r = visit(dep.imports ?? []); if (r) return r;
        continue;
      }
      const c = classify(mod, imp.package, boot);
      if (!c.ok) external.push(c.name);
    }
    return null;
  };
  const bad = visit(info.imports ?? []);
  if (bad) return bad;
  if (external.length) return fail(`the flagged code needs ${[...new Set(external)].slice(0, 4).join(', ')}, which is not available in the proof environment; only the packages that ship with GHC and files in the repository can be loaded`, { missing: [...new Set(external)] });
  sources[entry] = rel;

  const assumptions = [];
  const base = { schema: 'agentic-security/reproducer', version: 1, findingId: String(finding.stableId ?? finding.id ?? 'generated'), lang: 'haskell', oracle: spec.oracle, network: spec.network ?? 'none', ...(spec.watch ? { watch: spec.watch } : {}) };
  if (spec.watch) assumptions.push('the write target is assumed to be one directory below the working directory (the payload is ../escaped.txt); if the code uses another base, the proof will not confirm it');
  const ghcRun = (expr, overloaded = false) => ['{{GHC}}', '-ignore-dot-ghci', ...(overloaded ? ['-e', ':set -XOverloadedStrings'] : []), '-e', expr, entry];
  const literal = (s) => JSON.stringify(s); // payloads are fixed strings with no quote or backslash; this is a plain Haskell string literal
  const resolver = typeResolver(info, src.text);

  // what the class plants beside the program
  const extras = { files: {}, build: undefined, env: undefined };
  if (kind === 'path-traversal-read') {
    const dirs = readBaseDirs(src.text);
    if (!dirs.length) return fail(`path-traversal: ${describeLine(finding, root)} reads a path whose base directory is not a relative literal in the file (a path built from getCurrentDirectory, an environment variable, an absolute directory or a configuration value), so the proof cannot plant the file it would escape to`);
    extras.files = { [READ_SECRET_FILE]: '{{SECRET:file}}', ...Object.fromEntries(dirs.map((d) => [`${d}/.keep`, ''])) };
    assumptions.push(`the read is assumed to be confined under ${dirs.map((d) => `"${d}"`).join(' or ')}, one directory below the working directory; the proof plants a file one level up (${READ_PAYLOAD}) and sees it only if it reaches the program's output (stdout, stderr or, for a function, its printed result)`);
  }

  // shape 1: a program that reads its payload from the command line
  const hasMain = (info.functions ?? []).some((f) => f.scope === 'top' && f.name === 'main');
  if (/\bgetArgs\b/.test(src.text) && hasMain) {
    if (kind === 'argument-injection') {
      const call = argumentCall(lines, finding);
      if (!call.ok) return call;
      if (call.first.kind !== 'list' || !new RegExp(`\\b${call.first.name}\\s*<-\\s*getArgs\\b`).test(src.text)) return fail(`argument-injection: the first argument of the call to ${call.exe} is ${describeFirst(call.first)}, and the proof can place the payload only where the whole argument vector comes straight from getArgs (\`args <- getArgs\` then the call with \`args\`)`);
      Object.assign(extras, standIn(call.exe));
      assumptions.push(...standInAssumptions(call.exe));
    }
    assumptions.push('the payload is passed as the first and only command-line argument; a program that expects other arguments will not reach the flagged line');
    const reproducer = { ...base, sources, ...(Object.keys(extras.files).length ? { files: extras.files } : {}), ...(extras.build ? { build: extras.build } : {}), ...(extras.env ? { env: extras.env } : {}), run: ghcRun(`:main ${literal(spec.payload)}`) };
    const errs = validateReproducer(reproducer);
    return errs.length ? fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'script', class: spec.name, entry: rel, line: finding.line, assumptions } };
  }

  // shape 2: a top-level function around the flagged line
  const fn = (info.functions ?? []).filter((f) => f.scope === 'top' && f.name !== 'main' && /^[a-z_][\w']*$/.test(f.name)).find((f) => {
    const end = Math.max(f.span.endLine, ...(f.clauses ?? []).map((c) => c.span?.endLine ?? 0));
    return f.span.startLine <= finding.line && end >= finding.line;
  });
  if (!fn) return fail('the flagged line is not inside a top-level function, and the file does not read getArgs in a main');
  const sig = (info.signatures ?? []).find((s) => s.scope === 'top' && s.names.includes(fn.name));
  if (!sig) return fail(`${fn.name} has no type signature, so the proof cannot tell what to pass it`);
  const sigText = lines.slice(sig.span.startLine - 1, sig.span.endLine).join(' ');
  const m = new RegExp(`${fn.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^:]*::\\s*([\\s\\S]*)$`).exec(sigText);
  if (!m) return fail(`the type signature of ${fn.name} could not be read`);
  const type = m[1].replace(/--.*$/, '').trim();
  if (type.includes('=>') || /\bforall\b/.test(type)) return fail(`${fn.name} is polymorphic or constrained (${type.slice(0, 60)}), so the proof cannot choose its arguments`);
  const parts = splitArrows(type);
  const result = parts[parts.length - 1]; const params = parts.slice(0, -1);
  if (!/^IO\b/.test(result)) return fail(`${fn.name} returns ${result.slice(0, 40)}, not IO, so calling it would not perform the flagged operation`);
  if (!params.length) return fail(`${fn.name} takes no parameters, so the payload has no way in`);
  const resultInner = result.replace(/^IO\s*/, '').trim();
  if (kind === 'path-traversal-read' && resultInner !== '()' && !resolver.printable(resultInner)) return fail(`${fn.name} returns IO ${resultInner.slice(0, 40)}, whose content the proof cannot print; a read is observed only in the output, so the result must be (), String, Text, ByteString or a list or Maybe of them`);

  let payloadFor = () => spec.payload; // which parameters get the payload (all, unless the class says which)
  if (kind === 'argument-injection') {
    const call = argumentCall(lines, finding);
    if (!call.ok) return call;
    const headLine = lines[fn.span.startLine - 1] ?? '';
    const head = new RegExp(`^${fn.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}((?:\\s+[a-z_][\\w']*)*)\\s*(?:=|\\|)`).exec(headLine);
    const names = head ? head[1].trim().split(/\s+/).filter(Boolean) : null;
    if (!names || names.length !== params.length) return fail(`argument-injection: the parameters of ${fn.name} are patterns or the definition is point-free, so the proof cannot tell which parameter reaches the call`);
    if (call.first.kind !== 'element' && call.first.kind !== 'list') return fail(`argument-injection: the first argument of the call to ${call.exe} is ${describeFirst(call.first)}, and the proof can place the payload only where a plain parameter of ${fn.name} stands first in the argument vector`);
    const at = names.indexOf(call.first.name);
    if (at < 0) return fail(`argument-injection: the first argument of the call to ${call.exe} is \`${call.first.name}\`, which is not a parameter of ${fn.name}, so the proof cannot place the payload there`);
    const shape = resolver.fill(params[at], 'x');
    if (!shape) return fail(`${fn.name} takes a parameter of type ${params[at].slice(0, 40)}; only String, FilePath, Text, ByteString and lists or Maybe of them can be filled with a payload`);
    if (call.first.kind === 'list' && !/^\[/.test(shape.expr)) return fail(`argument-injection: ${call.first.name} is passed as the whole argument vector but has type ${params[at].slice(0, 40)}, not a list of strings`);
    if (call.first.kind === 'element' && /^\[/.test(shape.expr)) return fail(`argument-injection: ${call.first.name} is a list but stands as one element of the argument vector`);
    payloadFor = (i) => (i === at ? spec.payload : 'benign');
    Object.assign(extras, standIn(call.exe));
    assumptions.push(...standInAssumptions(call.exe), `the payload is placed in the parameter \`${call.first.name}\` only; the other parameters get the value "benign"`);
  } else assumptions.push('the payload is passed in every parameter (a String has no request-like stand-in), which is an approximation of how the function is really called');

  const filled = [];
  let overloaded = false;
  for (let i = 0; i < params.length; i++) {
    const f = resolver.fill(params[i], literal(payloadFor(i)));
    if (!f) return fail(`${fn.name} takes a parameter of type ${params[i].slice(0, 40)}; only String, FilePath, Text, ByteString and lists or Maybe of them can be filled with a payload`);
    filled.push(f.expr); overloaded ||= f.overloaded;
  }
  if (overloaded) assumptions.push('Text and ByteString arguments are written as string literals under OverloadedStrings, set for the call only, not for the program');
  const tail = kind === 'path-traversal-read' && resultInner !== '()' ? '>>= print' : '>>= \\_ -> return ()';
  const call = `${fn.name} ${filled.join(' ')} ${tail}`;
  const reproducer = { ...base, sources, ...(Object.keys(extras.files).length ? { files: extras.files } : {}), ...(extras.build ? { build: extras.build } : {}), ...(extras.env ? { env: extras.env } : {}), run: ghcRun(call, overloaded) };
  const errs = validateReproducer(reproducer);
  return errs.length ? fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'function', class: spec.name, entry: rel, line: finding.line, function: `${fn.name}(${params.length} ${params.every((p) => STRING_TYPES.test(p.trim())) ? 'String' : params.length === 1 ? 'parameter' : 'parameters'})`, assumptions } };
}

function describeFirst(first) {
  return { literal: 'a fixed string', empty: 'absent (an empty list)', complex: 'an expression the proof cannot read as a plain parameter', element: 'a parameter', list: 'a list' }[first.kind] ?? 'unreadable';
}

/** Find the process call at the flagged line and what stands first in its argument vector. */
function argumentCall(lines, finding) {
  const window = lines.slice(Math.max(0, finding.line - 1), finding.line + 2).join(' ').replace(/\s+/g, ' ');
  const m = PROCESS_CALL.exec(window);
  if (!m) return fail('argument-injection: the flagged line is not a call to callProcess, readProcess, readProcessWithExitCode, spawnProcess, rawSystem or proc with the program named by a string literal, so the proof cannot tell which program receives the arguments');
  const exe = m[2];
  if (NEVER_STAND_IN.has(exe) || !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$/.test(exe)) return fail(`argument-injection: the program is \`${exe}\`, which the proof does not stand in for (a shell, an interpreter or a toolchain program; an argument to a shell is command injection, CWE-78)`);
  const rest = window.slice(m.index + m[0].length).trimStart();
  const first = firstArgument(rest);
  if (first.kind === 'literal' || first.kind === 'empty') return fail(`argument-injection: the first argument of the call to ${exe} is ${describeFirst(first)}, and the proof covers only attacker data in the FIRST position, where every conventional option parser reads a leading dash as an option; later positions depend on the program's own grammar (an option such as -f takes the next word as its value)`);
  return { ok: true, exe, first };
}

/** The stand-in program, its permission and the PATH that finds it. */
function standIn(exe) {
  return { files: { [`bin/${exe}`]: STAND_IN }, build: ['/bin/chmod', '755', `bin/${exe}`], env: { PATH: STAND_IN_PATH } };
}
const standInAssumptions = (exe) => [`the program \`${exe}\` is replaced by a harness stand-in that acts on one planted option when it is the FIRST argument; a confirmation shows attacker data reaches the first argument unseparated and unvalidated, not that the real ${exe} has a dangerous option`];
