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
// Classes: command injection (CWE-78) and path traversal by a write (CWE-22). SSRF (CWE-918) is refused for Haskell on purpose: no
// HTTP client ships with GHC, so a request-making program necessarily imports a package the stdlib-only rule already refuses, and
// nothing could be proven honestly. Nothing is executed on a refusal.
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

/** @param {{finding: object, root: string, cls: {name: string, payload: string, oracle: object, network?: string, watch?: object, needsHs?: RegExp}, bootModules?: Set<string>}} o */
export function generateHaskellReproducer({ finding, root, cls, bootModules }) {
  const rel = String(finding.file);
  if (cls.name === 'ssrf') return fail('ssrf: no HTTP client ships with GHC, so any program that makes a request imports a package outside the proof environment; this class is not proven for Haskell');
  const src = readInside(root, rel);
  if (!src) return fail('the flagged file is missing, outside the repository, or too large');
  const hazard = loadTimeHazard(src.text);
  if (hazard) return fail(`the flagged file is refused: ${hazard}`);
  const info = parseHaskell(src.text);
  if (!info || info.status !== 'parsed') return fail('the flagged file could not be parsed as Haskell');
  const lines = src.text.split('\n');
  const sinkLine = lines[finding.line - 1] ?? '';
  const around = lines.slice(Math.max(0, finding.line - 3), finding.line + 2).join('\n');
  if (cls.needsHs && !cls.needsHs.test(sinkLine) && !cls.needsHs.test(around)) return fail(`${cls.name}: the flagged code is not a write, and this class is only proven for write sinks`);

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
  const base = { schema: 'agentic-security/reproducer', version: 1, findingId: String(finding.stableId ?? finding.id ?? 'generated'), lang: 'haskell', oracle: cls.oracle, network: cls.network ?? 'none', ...(cls.watch ? { watch: cls.watch } : {}) };
  if (cls.watch) assumptions.push('the write target is assumed to be one directory below the working directory (the payload is ../escaped.txt); if the code uses another base, the proof will not confirm it');
  const ghcRun = (expr) => ['{{GHC}}', '-ignore-dot-ghci', '-e', expr, entry];
  const literal = (s) => JSON.stringify(s); // payloads are fixed strings with no quote or backslash; this is a plain Haskell string literal

  // shape 1: a program that reads its payload from the command line
  const hasMain = (info.functions ?? []).some((f) => f.scope === 'top' && f.name === 'main');
  if (/\bgetArgs\b/.test(src.text) && hasMain) {
    assumptions.push('the payload is passed as the first and only command-line argument; a program that expects other arguments will not reach the flagged line');
    const reproducer = { ...base, sources, run: ghcRun(`:main ${literal(cls.payload)}`) };
    const errs = validateReproducer(reproducer);
    return errs.length ? fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'script', class: cls.name, entry: rel, line: finding.line, assumptions } };
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
  const bad2 = params.find((p) => !/^(?:String|FilePath|\[Char\])$/.test(p));
  if (bad2) return fail(`${fn.name} takes a parameter of type ${bad2.slice(0, 40)}; only String and FilePath can be filled with a payload`);
  assumptions.push('the payload is passed in every parameter (a String has no request-like stand-in), which is an approximation of how the function is really called');
  const call = `${fn.name} ${params.map(() => literal(cls.payload)).join(' ')} >>= \\_ -> return ()`;
  const reproducer = { ...base, sources, run: ghcRun(call) };
  const errs = validateReproducer(reproducer);
  return errs.length ? fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'function', class: cls.name, entry: rel, line: finding.line, function: `${fn.name}(${params.length} String)`, assumptions } };
}
