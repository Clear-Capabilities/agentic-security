export const id = 1602;
export const ids = [1602,2199];
export const modules = {

/***/ 31602:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  cmdProof: () => (/* binding */ cmdProof),
  cmdProve: () => (/* binding */ cmdProve),
  resolveReproducer: () => (/* binding */ resolveReproducer)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:os"
var external_node_os_ = __webpack_require__(48161);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
// EXTERNAL MODULE: ./src/posture/proof-fabric/orchestrator.js
var orchestrator = __webpack_require__(3740);
// EXTERNAL MODULE: ./src/posture/proof-fabric/store.js
var store = __webpack_require__(62199);
// EXTERNAL MODULE: ./src/posture/proof-fabric/runner.js + 1 modules
var runner = __webpack_require__(23081);
// EXTERNAL MODULE: ./src/posture/proof-fabric/reproducer.js
var proof_fabric_reproducer = __webpack_require__(37055);
// EXTERNAL MODULE: external "node:module"
var external_node_module_ = __webpack_require__(98995);
// EXTERNAL MODULE: ./node_modules/@babel/parser/lib/index.js
var lib = __webpack_require__(46411);
// EXTERNAL MODULE: external "node:child_process"
var external_node_child_process_ = __webpack_require__(31421);
;// CONCATENATED MODULE: ./src/posture/proof-fabric/generate-python.js
// Reproducer generation for Python (PRD 1), the second language of `generate.js`. Same contract: a DETERMINISTIC proposal built
// from the flagged file alone, then run through the ordinary runner, oracle, 3-of-3 repetition and independent replay. A generated
// reproducer is a proposal that execution either confirms or does not.
//
// Python is parsed by Python itself (`python3 -I -c`, the standard `ast` module, source on stdin, JSON on stdout) with a timeout, so
// the shape rules follow the real grammar. Two shapes, as in JavaScript:
//   script    the file reads `sys.argv[1]`: it is run with the payload as its argument (whether the flagged line is reached is then
//             decided by execution, not assumed);
//   function  a module-level `def` around the flagged line: a generated harness imports the file (never as `__main__`, so its main
//             guard does not run) and calls the function with the payload in every parameter.
// Only the standard library and sibling `.py` files in the flagged file's directory can be satisfied; any other import is refused,
// with the package named. Anything outside returns `{ ok: false }` with the reason, and nothing is executed.





const MAX_SOURCE = 256 * 1024;
const MAX_FILES = 8;
const fail = (reason, extra = {}) => ({ ok: false, reason, ...extra });

const ANALYZER = `
import ast, json, sys
src = sys.stdin.read()
try:
    tree = ast.parse(src)
except SyntaxError as e:
    print(json.dumps({"error": "syntax"})); sys.exit(0)
line = int(sys.argv[1])
imports = []
for n in ast.walk(tree):
    if isinstance(n, ast.Import):
        for a in n.names: imports.append({"module": a.name, "level": 0})
    elif isinstance(n, ast.ImportFrom):
        imports.append({"module": n.module or "", "level": n.level or 0, "names": [a.name for a in n.names]})
fns = []
for n in ast.walk(tree):
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno <= line <= (n.end_lineno or n.lineno):
        args = [a.arg for a in n.args.posonlyargs + n.args.args + n.args.kwonlyargs]
        fns.append({"name": n.name, "start": n.lineno, "end": n.end_lineno, "args": args, "async": isinstance(n, ast.AsyncFunctionDef), "decorated": bool(n.decorator_list), "toplevel": n in tree.body, "defaults": len(n.args.defaults)})
fns.sort(key=lambda f: f["end"] - f["start"])
main_guard = any(isinstance(n, ast.If) and "__name__" in ast.dump(n.test) for n in tree.body)
print(json.dumps({"imports": imports, "functions": fns, "mainGuard": main_guard, "stdlib": sorted(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else None}))
`;

function analyze(text, line) {
  const r = (0,external_node_child_process_.spawnSync)('python3', ['-I', '-c', ANALYZER, String(line)], { input: text, encoding: 'utf8', timeout: 10_000, maxBuffer: 4 * 1024 * 1024 });
  if (r.error || r.status !== 0) return null;
  try { return JSON.parse(r.stdout); } catch { return null; }
}

function readInside(root, rel) {
  let real; try { real = external_node_fs_.realpathSync(external_node_path_.resolve(root, rel)); } catch { return null; }
  const base = external_node_fs_.realpathSync(root);
  if (!(real === base || real.startsWith(base + external_node_path_.sep))) return null;
  const st = external_node_fs_.statSync(real);
  return st.isFile() && st.size <= MAX_SOURCE ? { real, text: external_node_fs_.readFileSync(real, 'utf8') } : null;
}

const HARNESS = (entry, name, args) => `# Generated by the proof fabric from the finding's own evidence. It imports the flagged module (never as __main__) and calls the function.
import importlib.util, sys, asyncio, inspect
payload = sys.argv[1] if len(sys.argv) > 1 else ""
spec = importlib.util.spec_from_file_location("target", ${JSON.stringify(entry)})
mod = importlib.util.module_from_spec(spec)
sys.modules["target"] = mod
spec.loader.exec_module(mod)
fn = getattr(mod, ${JSON.stringify(name)}, None)
if not callable(fn):
    print("the function is not defined at module level", file=sys.stderr); sys.exit(3)
try:
    res = fn(${args.join(', ')})
    if inspect.isawaitable(res): asyncio.run(asyncio.wait_for(res, 5))
except Exception as e:
    print("target raised:", str(e)[:200], file=sys.stderr)
`;

/** @param {{finding: object, root: string, cls: {name: string, payload: string, oracle: object, network?: string, watch?: object, needsPy?: RegExp}}} o */
function generatePythonReproducer({ finding, root, cls }) {
  const rel = String(finding.file);
  const src = readInside(root, rel);
  if (!src) return fail('the flagged file is missing, outside the repository, or too large');
  const info = analyze(src.text, finding.line);
  if (!info || info.error) return fail('the flagged file could not be parsed by Python (is python3 installed and is the file valid Python 3?)');
  const lines = src.text.split('\n');
  const sinkLine = lines[finding.line - 1] ?? '';
  const around = lines.slice(Math.max(0, finding.line - 3), finding.line + 2).join('\n');
  if (cls.needsPy && !cls.needsPy.test(sinkLine) && !cls.needsPy.test(around)) return fail(`${cls.name}: the flagged code is not a write, and this class is only proven for write sinks`);

  const stdlib = new Set(info.stdlib ?? []);
  if (!info.stdlib) return fail('this Python is too old to list its standard library (3.10 or newer is needed), so imports cannot be classified');
  const dir = external_node_path_.dirname(src.real); const rootReal = external_node_fs_.realpathSync(root);
  const sources = {}; const external = [];
  for (const imp of info.imports) {
    const top = imp.module.split('.')[0];
    if (imp.level === 0 && stdlib.has(top)) continue;
    const sibling = imp.level <= 1 ? external_node_path_.join(dir, `${top || (imp.names?.[0] ?? '')}.py`) : null;
    if (sibling && external_node_fs_.existsSync(sibling)) {
      const dep = readInside(root, external_node_path_.relative(rootReal, external_node_fs_.realpathSync(sibling)));
      if (!dep) return fail(`"${top}" is too large or outside the repository`);
      const destRel = external_node_path_.relative(dir, dep.real);
      if (!sources[destRel]) { if (Object.keys(sources).length >= MAX_FILES) return fail(`the file pulls in more than ${MAX_FILES} repository files`); sources[destRel] = external_node_path_.relative(rootReal, dep.real); }
      continue;
    }
    external.push(top || '.'.repeat(imp.level));
  }
  if (external.length) return fail(`the flagged code needs ${[...new Set(external)].slice(0, 4).join(', ')}, which is not available in the proof environment; only the standard library and sibling files in the same directory can be satisfied`);

  const entry = 'target.py';
  sources[entry] = rel;
  const assumptions = [];
  const base = { schema: 'agentic-security/reproducer', version: 1, findingId: String(finding.stableId ?? finding.id ?? 'generated'), lang: 'python', oracle: cls.oracle, network: cls.network ?? 'none', ...(cls.watch ? { watch: cls.watch } : {}) };
  if (cls.watch) assumptions.push('the write target is assumed to be one directory below the working directory (the payload is ../escaped.txt); if the code uses another base, the proof will not confirm it');

  if (/sys\.argv\s*\[\s*1\s*\]/.test(src.text)) {
    const reproducer = { ...base, sources, run: ['{{PYTHON}}', entry, cls.payload] };
    const errs = (0,proof_fabric_reproducer/* validateReproducer */.mC)(reproducer);
    return errs.length ? fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'script', class: cls.name, entry: rel, line: finding.line, assumptions } };
  }
  const fn = info.functions.find((f) => f.toplevel);
  if (!fn) return fail('the flagged line is not inside a module-level function, and the file does not read sys.argv[1]');
  if (fn.decorated) return fail(`${fn.name} is decorated (a web framework route, a cache, a wrapper): calling it directly would not match how it is reached, and the framework is not available`);
  if (!fn.args.length) return fail('the function around the flagged line takes no parameters, so the payload has no way in');
  if (fn.async) assumptions.push('the function is a coroutine; the harness awaits it for at most 5 seconds');
  assumptions.push('the payload is passed in every parameter (a Python parameter has no request-like stand-in), which is an approximation of how the function is really called');
  const harness = HARNESS(entry, fn.name, fn.args.map(() => 'payload'));
  const reproducer = { ...base, sources, files: { 'harness.py': harness }, run: ['{{PYTHON}}', 'harness.py', cls.payload] };
  const errs = (0,proof_fabric_reproducer/* validateReproducer */.mC)(reproducer);
  return errs.length ? fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'function', class: cls.name, entry: rel, line: finding.line, function: `${fn.name}(${fn.args.join(', ')})`, assumptions } };
}

// EXTERNAL MODULE: ./src/language/haskell-parser.js + 1 modules
var haskell_parser = __webpack_require__(99864);
;// CONCATENATED MODULE: ./src/posture/proof-fabric/generate-haskell.js
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







const generate_haskell_MAX_SOURCE = 256 * 1024;
const generate_haskell_MAX_FILES = 8;
const generate_haskell_fail = (reason, extra = {}) => ({ ok: false, reason, ...extra });

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
function bootModuleSet(ghc) {
  if (libCache.has(ghc)) return libCache.get(ghc);
  let set = null;
  try {
    const r = (0,external_node_child_process_.spawnSync)(ghc, ['--print-libdir'], { encoding: 'utf8', timeout: 10_000 });
    const dir = r.status === 0 ? external_node_path_.join(r.stdout.trim(), 'package.conf.d') : null;
    if (dir && external_node_fs_.existsSync(dir)) {
      set = new Set();
      for (const f of external_node_fs_.readdirSync(dir)) {
        if (!f.endsWith('.conf')) continue;
        const text = external_node_fs_.readFileSync(external_node_path_.join(dir, f), 'utf8');
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

function generate_haskell_readInside(root, rel) {
  let real; try { real = external_node_fs_.realpathSync(external_node_path_.resolve(root, rel)); } catch { return null; }
  const base = external_node_fs_.realpathSync(root);
  if (!(real === base || real.startsWith(base + external_node_path_.sep))) return null;
  const st = external_node_fs_.statSync(real);
  return st.isFile() && st.size <= generate_haskell_MAX_SOURCE ? { real, text: external_node_fs_.readFileSync(real, 'utf8') } : null;
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
function generateHaskellReproducer({ finding, root, cls, bootModules }) {
  const rel = String(finding.file);
  if (cls.name === 'ssrf') return generate_haskell_fail('ssrf: no HTTP client ships with GHC, so any program that makes a request imports a package outside the proof environment; this class is not proven for Haskell');
  const src = generate_haskell_readInside(root, rel);
  if (!src) return generate_haskell_fail('the flagged file is missing, outside the repository, or too large');
  const hazard = loadTimeHazard(src.text);
  if (hazard) return generate_haskell_fail(`the flagged file is refused: ${hazard}`);
  const info = (0,haskell_parser/* parseHaskell */.cX)(src.text);
  if (!info || info.status !== 'parsed') return generate_haskell_fail('the flagged file could not be parsed as Haskell');
  const lines = src.text.split('\n');
  const sinkLine = lines[finding.line - 1] ?? '';
  const around = lines.slice(Math.max(0, finding.line - 3), finding.line + 2).join('\n');
  if (cls.needsHs && !cls.needsHs.test(sinkLine) && !cls.needsHs.test(around)) return generate_haskell_fail(`${cls.name}: the flagged code is not a write, and this class is only proven for write sinks`);

  const tools = (0,runner/* hostTools */.qV)();
  const boot = bootModules ?? (tools.ghc ? bootModuleSet(tools.ghc) : null);
  if (!boot) return generate_haskell_fail('no working GHC was found to list the modules the proof environment can import (install ghc, or run `agentic-security proof doctor`)');

  // the entry module is placed at its module path so that other modules can import it; Main goes to Main.hs
  const modName = info.module?.name ?? 'Main';
  const entry = `${modName.replaceAll('.', '/')}.hs`;
  const rootReal = external_node_fs_.realpathSync(root);
  const entryDir = external_node_path_.dirname(src.real);
  const modRel = modName.replaceAll('.', external_node_path_.sep);
  const srcRoot = src.real.endsWith(`${modRel}.hs`) ? src.real.slice(0, src.real.length - modRel.length - 3) : `${entryDir}${external_node_path_.sep}`;
  const searchRoots = [...new Set([srcRoot.replace(/[\\/]$/, ''), ...['src', 'app', 'lib', ''].map((d) => external_node_path_.join(rootReal, d))])];
  const sources = {}; const external = []; const seen = new Set([modName]);
  let count = 0;
  const visit = (imports) => {
    for (const imp of imports) {
      const mod = imp.module;
      if (seen.has(mod)) continue;
      seen.add(mod);
      let local = null;
      for (const base of searchRoots) { const cand = external_node_path_.join(base, `${mod.replaceAll('.', '/')}.hs`); const r = generate_haskell_readInside(root, external_node_path_.relative(rootReal, cand)); if (r) { local = r; break; } }
      if (local && !imp.package) {
        if (++count > generate_haskell_MAX_FILES) return generate_haskell_fail(`the file pulls in more than ${generate_haskell_MAX_FILES} repository modules`);
        const dep = (0,haskell_parser/* parseHaskell */.cX)(local.text);
        if (!dep || dep.status !== 'parsed') return generate_haskell_fail(`the module ${mod} could not be parsed as Haskell`);
        const h = loadTimeHazard(local.text); if (h) return generate_haskell_fail(`the module ${mod} is refused: ${h}`);
        sources[`${mod.replaceAll('.', '/')}.hs`] = external_node_path_.relative(rootReal, local.real);
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
  if (external.length) return generate_haskell_fail(`the flagged code needs ${[...new Set(external)].slice(0, 4).join(', ')}, which is not available in the proof environment; only the packages that ship with GHC and files in the repository can be loaded`, { missing: [...new Set(external)] });
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
    const errs = (0,proof_fabric_reproducer/* validateReproducer */.mC)(reproducer);
    return errs.length ? generate_haskell_fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'script', class: cls.name, entry: rel, line: finding.line, assumptions } };
  }

  // shape 2: a top-level function around the flagged line
  const fn = (info.functions ?? []).filter((f) => f.scope === 'top' && f.name !== 'main' && /^[a-z_][\w']*$/.test(f.name)).find((f) => {
    const end = Math.max(f.span.endLine, ...(f.clauses ?? []).map((c) => c.span?.endLine ?? 0));
    return f.span.startLine <= finding.line && end >= finding.line;
  });
  if (!fn) return generate_haskell_fail('the flagged line is not inside a top-level function, and the file does not read getArgs in a main');
  const sig = (info.signatures ?? []).find((s) => s.scope === 'top' && s.names.includes(fn.name));
  if (!sig) return generate_haskell_fail(`${fn.name} has no type signature, so the proof cannot tell what to pass it`);
  const sigText = lines.slice(sig.span.startLine - 1, sig.span.endLine).join(' ');
  const m = new RegExp(`${fn.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^:]*::\\s*([\\s\\S]*)$`).exec(sigText);
  if (!m) return generate_haskell_fail(`the type signature of ${fn.name} could not be read`);
  const type = m[1].replace(/--.*$/, '').trim();
  if (type.includes('=>') || /\bforall\b/.test(type)) return generate_haskell_fail(`${fn.name} is polymorphic or constrained (${type.slice(0, 60)}), so the proof cannot choose its arguments`);
  const parts = splitArrows(type);
  const result = parts[parts.length - 1]; const params = parts.slice(0, -1);
  if (!/^IO\b/.test(result)) return generate_haskell_fail(`${fn.name} returns ${result.slice(0, 40)}, not IO, so calling it would not perform the flagged operation`);
  if (!params.length) return generate_haskell_fail(`${fn.name} takes no parameters, so the payload has no way in`);
  const bad2 = params.find((p) => !/^(?:String|FilePath|\[Char\])$/.test(p));
  if (bad2) return generate_haskell_fail(`${fn.name} takes a parameter of type ${bad2.slice(0, 40)}; only String and FilePath can be filled with a payload`);
  assumptions.push('the payload is passed in every parameter (a String has no request-like stand-in), which is an approximation of how the function is really called');
  const call = `${fn.name} ${params.map(() => literal(cls.payload)).join(' ')} >>= \\_ -> return ()`;
  const reproducer = { ...base, sources, run: ghcRun(call) };
  const errs = (0,proof_fabric_reproducer/* validateReproducer */.mC)(reproducer);
  return errs.length ? generate_haskell_fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'function', class: cls.name, entry: rel, line: finding.line, function: `${fn.name}(${params.length} String)`, assumptions } };
}

;// CONCATENATED MODULE: ./src/posture/proof-fabric/generate.js
// Reproducer generation from a finding's own evidence (PRD 1: `triage exploit --prove` with no hand-written reproducer).
//
// What this is: a DETERMINISTIC harness builder for the cases where a harness can be built from the source alone. It reads the
// flagged file, finds the function around the flagged line, decides how that function is reached, picks the payload for the
// weakness class, and emits an ordinary reproducer, which then goes through exactly the same runner, oracle, 3-of-3 repetition and
// independent replay as any other. A generated reproducer is not a verdict; it is a proposal that is either confirmed by execution
// or not.
//
// What this is not: a general exploit generator. It handles JavaScript (here), Python (`generate-python.js`) and Haskell (`generate-haskell.js`), and only code the proof environment can actually load:
// the file's imports must be Node built-ins or relative files inside the repository (a package from node_modules is not there in
// the sandbox, so a handler that needs `express` is refused, with the package named). Anything outside that returns `{ ok: false }`
// with the reason, and nothing is executed.
//
// Two shapes:
//   script    the file reads `process.argv[2]`: it is run with the payload as its argument;
//   function  the file exports (or declares at top level and exports) the function around the flagged line: a generated harness
//             loads it and calls it, filling the tainted parameter with the payload. A parameter that is a request-like object
//             (`req`) gets a stand-in whose `body`/`query`/`params` answer every property with the payload.
//
// Weakness classes with a payload and an oracle that can SEE the effect: CWE-78 (a canary file created by the injected command),
// CWE-22 (a write that lands outside the working directory, only for write sinks), CWE-918 (a request reaching the runner's loopback
// listener). Others (injection into a database, deserialization, memory safety) need an environment or a native harness this does not
// build, and are refused by name rather than approximated.








const CLASSES = {
  'CWE-78': { name: 'command-injection', payload: 'x; touch {{CANARY:command}}', oracle: { type: 'command_execution', params: { canary: 'command' } } },
  'CWE-22': { needsPy: /\bopen\s*\([^)]*['"][wax]b?\+?['"]|\.write_(?:text|bytes)\s*\(|\bshutil\.(?:copy|move)/, name: 'path-traversal', payload: '../escaped.txt', oracle: { type: 'filesystem_mutation', params: { canary: 'fs' } }, watch: { fs: 'escaped.txt' }, needsHs: /\b(?:writeFile|appendFile|copyFile|copyFileWithMetadata|renameFile|openBinaryFile)\b|\b(?:openFile|withFile|withBinaryFile)\b[^\n]*\b(?:WriteMode|AppendMode|ReadWriteMode)\b/, needs: /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\b/ },
  'CWE-918': { name: 'ssrf', payload: '{{CALLBACK_URL}}', oracle: { type: 'outbound_callback' }, network: 'callback' },
};
const generate_MAX_SOURCE = 256 * 1024;
const generate_MAX_FILES = 8;
const EXTS = ['', '.js', '.mjs', '.cjs', '/index.js'];
const BUILTINS = new Set(external_node_module_.builtinModules.flatMap((m) => [m, `node:${m}`]));
const MODULE_SYNTAX = /^\s*(?:import\s[^('"]|import\s*['"{*]|export\s)/m;

const generate_fail = (reason, extra = {}) => ({ ok: false, reason, ...extra });
const normCwe = (c) => { const m = /(\d{1,5})/.exec(String(c ?? '')); return m ? `CWE-${Number(m[1])}` : null; };

function inside(root, rel) {
  if (typeof rel !== 'string' || !rel || rel.includes('\0')) return null;
  let real;
  try { real = external_node_fs_.realpathSync(external_node_path_.resolve(root, rel)); } catch { return null; }
  const base = external_node_fs_.realpathSync(root);
  return real === base || real.startsWith(base + external_node_path_.sep) ? real : null;
}

function readSource(root, rel) {
  const real = inside(root, rel);
  if (!real) return null;
  const st = external_node_fs_.statSync(real);
  if (!st.isFile() || st.size > generate_MAX_SOURCE) return null;
  return { real, text: external_node_fs_.readFileSync(real, 'utf8') };
}

function parseSource(text) {
  try { return (0,lib/* parse */.qg)(text, { sourceType: 'unambiguous', errorRecovery: false, plugins: ['topLevelAwait'], allowReturnOutsideFunction: true }); } catch { return null; }
}

function* walk(node, parent = null) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) { for (const n of node) yield* walk(n, parent); return; }
  if (typeof node.type !== 'string') return;
  yield { node, parent };
  for (const [k, v] of Object.entries(node)) if (k !== 'loc' && k !== 'leadingComments' && k !== 'trailingComments' && v && typeof v === 'object') yield* walk(v, node);
}

/** Every module this file loads: built-ins pass, relative files are collected, anything else is a dependency the proof cannot provide. */
function dependencies(ast) {
  const specs = [];
  for (const { node } of walk(ast.program)) {
    if (node.type === 'ImportDeclaration' || ((node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') && node.source)) specs.push(node.source.value);
    else if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require' && node.arguments[0]?.type === 'StringLiteral') specs.push(node.arguments[0].value);
    else if (node.type === 'ImportExpression' && node.source?.type === 'StringLiteral') specs.push(node.source.value);
  }
  return specs;
}

/** Every function that contains the line, innermost first: the flagged call is often inside a callback of the function that can be called. */
function functionsAround(ast, line) {
  const all = [];
  for (const { node, parent } of walk(ast.program)) {
    if (!/^(?:FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ObjectMethod|ClassMethod)$/.test(node.type)) continue;
    if (node.loc && node.loc.start.line <= line && node.loc.end.line >= line) all.push({ node, parent });
  }
  return all.sort((a, b) => (a.node.loc.end.line - a.node.loc.start.line) - (b.node.loc.end.line - b.node.loc.start.line) || (b.node.loc.start.line - a.node.loc.start.line));
}

const paramNames = (fn) => fn.params.map((p) => (p.type === 'Identifier' ? p.name : p.type === 'AssignmentPattern' && p.left.type === 'Identifier' ? p.left.name : null));

/** How the function is reachable from outside: its exported name, or null. */
function exportName(ast, fnInfo) {
  const { node, parent } = fnInfo;
  const idName = node.id?.name ?? (parent?.type === 'VariableDeclarator' && parent.id.type === 'Identifier' ? parent.id.name : null);
  let found = null;
  for (const { node: n } of walk(ast.program)) {
    if (n.type === 'ExportNamedDeclaration' && n.declaration) {
      if (n.declaration === node || (n.declaration.type === 'FunctionDeclaration' && n.declaration.id?.name === idName)) found = { kind: 'named', name: idName };
      if (n.declaration.type === 'VariableDeclaration' && n.declaration.declarations.some((d) => d.init === node)) found = { kind: 'named', name: n.declaration.declarations.find((d) => d.init === node).id.name };
    }
    if (n.type === 'ExportNamedDeclaration' && n.specifiers?.length && idName) for (const s of n.specifiers) if (s.local?.name === idName) found = { kind: 'named', name: s.exported.name };
    if (n.type === 'ExportDefaultDeclaration' && (n.declaration === node || n.declaration?.name === idName)) found = { kind: 'default' };
    if (n.type === 'AssignmentExpression' && n.left.type === 'MemberExpression') {
      const l = n.left; const obj = l.object; const prop = l.property?.name ?? l.property?.value;
      const isModuleExports = obj.type === 'Identifier' && obj.name === 'module' && prop === 'exports';
      if (isModuleExports && (n.right === node || (n.right.type === 'Identifier' && n.right.name === idName))) found = { kind: 'module' };
      if (isModuleExports && n.right.type === 'ObjectExpression') for (const p of n.right.properties) if ((p.value === node || p.value?.name === idName || (p.shorthand && p.key.name === idName)) && p.key) found = { kind: 'named', name: p.key.name ?? p.key.value };
      const isExportsProp = (obj.type === 'Identifier' && obj.name === 'exports') || (obj.type === 'MemberExpression' && obj.object?.name === 'module' && obj.property?.name === 'exports');
      if (isExportsProp && prop && (n.right === node || (n.right.type === 'Identifier' && n.right.name === idName))) found = { kind: 'named', name: prop };
    }
  }
  return found;
}

function harness({ esm, entry, exp, args }) {
  const load = esm ? `const mod = await import('./${entry}');` : `import { createRequire } from 'node:module';\nconst require = createRequire(import.meta.url);\nconst mod = require('./${entry}');`;
  const pick = exp.kind === 'named' ? `mod[${JSON.stringify(exp.name)}] ?? mod.default?.[${JSON.stringify(exp.name)}]` : exp.kind === 'default' ? 'mod.default ?? mod' : 'typeof mod === \'function\' ? mod : mod.default';
  return `// Generated by the proof fabric from the finding's own evidence. It loads the flagged function and calls it with the payload.
${load}
const payload = process.argv[2] ?? '';
const P = new Proxy({}, { get: (_t, k) => (k === Symbol.toPrimitive ? () => payload : k === 'toString' ? () => payload : payload), has: () => true });
const res = new Proxy(function () {}, { get: () => res, apply: () => res });
const fn = ${pick};
if (typeof fn !== 'function') { console.error('the exported value is not a function'); process.exit(3); }
let timer; try { await Promise.race([Promise.resolve(fn(${args.join(', ')})), new Promise((r) => { timer = setTimeout(r, 5000); })]); } catch (e) { console.error('target threw:', String(e && e.message).slice(0, 200)); }
clearTimeout(timer);
`;
}

function generateReproducer({ finding, root }) {
  const cwe = normCwe(finding?.cwe);
  const cls = CLASSES[cwe];
  if (!cls) return generate_fail(`no payload and oracle exist for ${cwe ?? 'this finding'}; supported: ${Object.keys(CLASSES).join(', ')} (others need a database, a deserializer or a native harness)`);
  const rel = String(finding?.file ?? '');
  const isPy = /\.py$/i.test(rel);
  const isHs = /\.hs$/i.test(rel);
  if (!isPy && !isHs && !/\.(?:js|mjs|cjs)$/i.test(rel)) return generate_fail(`no harness builder for ${external_node_path_.extname(rel) || 'this file type'}; JavaScript, Python and Haskell only`);
  if (!Number.isInteger(finding?.line)) return generate_fail('the finding has no line number');
  if (isPy) return generatePythonReproducer({ finding, root, cls });
  if (isHs) return generateHaskellReproducer({ finding, root, cls });
  const src = readSource(root, rel);
  if (!src) return generate_fail('the flagged file is missing, outside the repository, or too large');
  const ast = parseSource(src.text);
  if (!ast) return generate_fail('the flagged file could not be parsed');
  const lines = src.text.split('\n');
  const sinkLine = lines[finding.line - 1] ?? '';
  if (cls.needs && !cls.needs.test(sinkLine) && !cls.needs.test(lines.slice(Math.max(0, finding.line - 3), finding.line + 2).join('\n'))) return generate_fail(`${cls.name}: the flagged code is not a write, and the oracle can only observe a write (a read leaves no trace unless the program prints it)`);

  // dependencies the sandbox can satisfy
  const sources = {}; const external = [];
  const entryDir = external_node_path_.dirname(src.real);
  const rootReal = external_node_fs_.realpathSync(root); // the repository root as the filesystem names it (a temp dir can sit behind a symlink)
  const collect = (realFile, ast0, count) => {
    for (const spec of dependencies(ast0)) {
      if (BUILTINS.has(spec)) continue;
      if (!spec.startsWith('.')) { external.push(spec); continue; }
      let found = null;
      for (const e of EXTS) { const cand = inside(root, external_node_path_.relative(rootReal, external_node_path_.resolve(external_node_path_.dirname(realFile), spec + e))); if (cand && external_node_fs_.statSync(cand).isFile()) { found = cand; break; } }
      if (!found) return generate_fail(`the relative import "${spec}" was not found inside the repository`);
      const destRel = external_node_path_.relative(entryDir, found);
      if (destRel.startsWith('..')) return generate_fail(`"${spec}" lives outside the flagged file's directory, which a proof workspace cannot mirror`);
      if (sources[destRel] || found === src.real) continue;
      if (Object.keys(sources).length >= generate_MAX_FILES) return generate_fail(`the file pulls in more than ${generate_MAX_FILES} repository files`);
      const dep = readSource(root, external_node_path_.relative(rootReal, found));
      if (!dep) return generate_fail(`"${spec}" is too large or unreadable`);
      sources[destRel] = external_node_path_.relative(rootReal, found);
      const depAst = parseSource(dep.text);
      if (!depAst) return generate_fail(`"${spec}" could not be parsed`);
      const r = collect(found, depAst, count + 1); if (r) return r;
    }
    return null;
  };
  const bad = collect(src.real, ast, 0);
  if (bad) return bad;
  if (external.length) return generate_fail(`the flagged code needs ${[...new Set(external)].slice(0, 4).join(', ')}, which is not installed in the proof environment; only Node built-ins and repository files can be loaded`, { missing: [...new Set(external)] });

  const esm = MODULE_SYNTAX.test(src.text) || external_node_path_.extname(rel).toLowerCase() === '.mjs';
  const entry = `target${esm ? '.mjs' : '.cjs'}`;
  sources[entry] = rel;
  const assumptions = [];
  const base = { schema: 'agentic-security/reproducer', version: 1, findingId: String(finding.stableId ?? finding.id ?? 'generated'), lang: 'javascript', oracle: cls.oracle, network: cls.network ?? 'none', ...(cls.watch ? { watch: cls.watch } : {}) };
  if (cls.watch) assumptions.push('the write target is assumed to be one directory below the working directory (the payload is ../escaped.txt); if the code uses another base, the proof will not confirm');

  // shape 1: a script that reads its payload from argv
  if (/process\.argv\s*\[\s*2\s*\]|process\.argv\.slice\(\s*2\s*\)/.test(src.text) && !/\bmodule\.exports\b|^\s*export\s/m.test(src.text)) {
    const reproducer = { ...base, sources, run: ['{{NODE}}', entry, cls.payload] };
    const errs = (0,proof_fabric_reproducer/* validateReproducer */.mC)(reproducer);
    return errs.length ? generate_fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'script', class: cls.name, entry: rel, line: finding.line, assumptions } };
  }

  // shape 2: an exported function around the flagged line
  const candidates = functionsAround(ast, finding.line);
  if (!candidates.length) return generate_fail('the flagged line is not inside a function, and the file does not read its payload from process.argv[2]');
  let around = null; let exp = null;
  for (const c of candidates) { const e = exportName(ast, c); if (e) { around = c; exp = e; break; } }
  if (!around) return generate_fail('the function around the flagged line is not exported, so nothing outside the file can call it');
  const names = paramNames(around.node);
  if (!names.length) return generate_fail('the function around the flagged line takes no parameters, so the payload has no way in');
  const window = lines.slice(Math.max(0, around.node.loc.start.line - 1), Math.min(lines.length, finding.line + 1)).join('\n');
  const requestLike = names.findIndex((n) => n && /^(?:req|request)$/.test(n) && new RegExp(`\\b${n}\\.(?:body|query|params)\\b`).test(sinkLine));
  const direct = requestLike >= 0 ? -1 : names.findIndex((n) => n && new RegExp(`\\b${n}\\b`).test(sinkLine));
  const fallback = direct < 0 && requestLike < 0 ? names.findIndex((n) => n && new RegExp(`\\b${n}\\b`).test(window)) : -1;
  const idx = requestLike >= 0 ? requestLike : direct >= 0 ? direct : fallback;
  if (idx < 0) return generate_fail('none of the function\'s parameters appears in the flagged code, so there is no tainted parameter to fill');
  if (fallback >= 0) assumptions.push(`the tainted parameter "${names[idx]}" was chosen because it appears in the function body near the flagged line, not on the line itself`);
  const args = names.map((_, i) => (i !== idx ? (/^(?:res|response)$/.test(names[i] ?? '') ? 'res' : 'undefined') : requestLike >= 0 ? '{ body: P, query: P, params: P, headers: P, cookies: P }' : 'payload'));
  const files = { 'harness.mjs': harness({ esm, entry, exp, args }) };
  const reproducer = { ...base, sources, files, run: ['{{NODE}}', 'harness.mjs', cls.payload] };
  const errs = (0,proof_fabric_reproducer/* validateReproducer */.mC)(reproducer);
  return errs.length ? generate_fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'function', class: cls.name, entry: rel, line: finding.line, function: names.length ? `${exp.kind === 'named' ? exp.name : exp.kind}(${names.join(', ')})` : exp.kind, taintedParameter: names[idx], requestLike: requestLike >= 0, assumptions } };
}

;// CONCATENATED MODULE: ./src/posture/proof-fabric/cli.js
// CLI surface for the proof fabric: `proof show|replay|doctor`, `triage exploit|validate`. Non-interactive by design: no
// command reads stdin, every run is bounded by the policy timeouts, and a missing reproducer is a typed exit code, not a
// prompt. Exit codes: 0 confirmed/ok, 1 not confirmed (any reason), 4 usage/precondition.











function loadFinding(root, id) {
  const p = (0,state_dir.statePath)(root, 'last-scan.json');
  if (!external_node_fs_.existsSync(p)) return null;
  const last = JSON.parse(external_node_fs_.readFileSync(p, 'utf8'));
  return (last.findings || []).find((f) => f.id === id || f.stableId === id) ?? null;
}

/**
 * The reproducer for a finding: the one the person or agent supplied (or stored), else one built from the finding's own evidence.
 * A generated reproducer is a proposal; it earns nothing until it is executed, and the result says it was generated.
 */
function resolveReproducer(root, finding, flagPath) {
  const supplied = loadReproducer(root, finding.stableId ?? finding.id, flagPath) ?? (finding.stableId && finding.id !== finding.stableId ? loadReproducer(root, finding.id, flagPath) : null);
  if (supplied) return { ...supplied, generated: null };
  const g = generateReproducer({ finding, root });
  if (!g.ok) return { reproducer: null, reason: g.reason };
  return { reproducer: g.reproducer, file: null, generated: g.basis };
}

function loadReproducer(root, id, flagPath) {
  const candidates = [flagPath && external_node_path_.resolve(String(flagPath)), (0,state_dir.statePath)(root, 'reproducers', `${(0,store.findingKey)(id)}.json`)].filter(Boolean);
  for (const c of candidates) {
    try { return { reproducer: JSON.parse(external_node_fs_.readFileSync(c, 'utf8')), file: c }; } catch { /* next */ }
  }
  return null;
}

function formatResult(r) {
  const env = r.environment ? `${r.environment.mode} (${r.environment.assurance} assurance)` : 'none';
  return [
    `Finding: ${r.findingId}`,
    `Evidence: ${r.state}`,
    `Oracle: ${r.oracle}`,
    `Reproductions: ${r.attempts?.successes ?? 0}/${r.attempts?.run ?? 0} (required ${r.attempts?.required})`,
    `Independent replay: ${r.independentReplay?.status ?? 'not-run'}`,
    `Environment: ${env}`,
    `Completeness: ${r.completeness}`,
    `Duration: ${(r.timing.proofMs / 1000).toFixed(1)}s`,
    ...(r.degradation?.length ? [`Degraded: ${r.degradation.join(', ')}`] : []),
    ...(r.note ? [`Note: ${r.note}`] : []),
  ].join('\n');
}

async function cmdProve(args, root, { json = false } = {}) {
  const id = String(args._[2] ?? '');
  if (!id) { console.error('usage: triage exploit <finding-id> --prove [--reproducer file] [--attempts N] [--required N]'); return 4; }
  const finding = loadFinding(root, id);
  if (!finding) { console.error(`Finding ${id} not found in last scan.`); return 4; }
  const loaded = resolveReproducer(root, finding, args.flags.reproducer);
  if (!loaded.reproducer) { console.error(`No reproducer for ${id}, and none could be generated from the finding: ${loaded.reason}. Supply one with --reproducer <file> or place it at .agentic-security/reproducers/. Nothing was executed.`); return 4; }
  if (loaded.generated) console.error(`Generated a reproducer from the finding (${loaded.generated.shape}, ${loaded.generated.class}). It is a proposal: it counts only if executing it confirms the exploit.`);
  const errs = (0,proof_fabric_reproducer/* validateReproducer */.mC)(loaded.reproducer);
  if (errs.length) { console.error(`Invalid reproducer: ${errs.join('; ')}`); return 4; }
  const policy = {};
  if (args.flags.attempts) policy.attempts = Number(args.flags.attempts);
  if (args.flags.required) policy.required = Number(args.flags.required);
  if (args.flags.timeout) policy.timeoutMs = Number(args.flags.timeout) * 1000;
  if (args.flags['require-container']) policy.requireContainer = true;
  const ac = new AbortController();
  const onSig = () => ac.abort();
  process.once('SIGINT', onSig);
  let result;
  try { result = await (0,orchestrator/* proveFinding */.kO)({ finding, reproducer: loaded.reproducer, revision: args.flags.revision ?? null, policy, signal: ac.signal, sourceRoot: root }); } finally { process.off('SIGINT', onSig); }
  const saved = (0,store.saveProof)(root, { ...result, reproducer: loaded.reproducer, ...(loaded.generated ? { generatedFrom: loaded.generated } : {}) });
  // Printed output gets the same secret-scrubbing pass as what is persisted (defense in depth: a free-text reason/note
  // field that captured something from stdout/stderr should never reach a terminal unredacted either).
  if (json || args.flags.json) console.log(JSON.stringify((0,store.scrubDeep)({ ...result, stored: saved.ok ? saved.file : null }), null, 2));
  else { console.log(formatResult(result)); if (!saved.ok) console.log(`(proof not stored: ${saved.reason})`); }
  return result.state === 'EXPLOIT_CONFIRMED' ? 0 : 1;
}

async function cmdProof(args, root) {
  const sub = args._[1];
  if (sub === 'doctor') return doctor(args);
  if (sub === 'generate') {
    const gid = String(args._[2] ?? '');
    const finding = gid ? loadFinding(root, gid) : null;
    if (!finding) { console.error(gid ? `Finding ${gid} not found in last scan.` : 'usage: proof generate <finding-id> [--out file]'); return 4; }
    const g = generateReproducer({ finding, root });
    if (!g.ok) { console.error(`No reproducer could be generated: ${g.reason}`); return 1; }
    const text = JSON.stringify({ ...g.reproducer, findingId: gid }, null, 2);
    if (args.flags.out) { external_node_fs_.writeFileSync(external_node_path_.resolve(String(args.flags.out)), `${text}\n`); console.log(`Wrote ${external_node_path_.resolve(String(args.flags.out))} (${g.basis.shape}, ${g.basis.class}). Nothing was executed.`); } else console.log(text);
    for (const a of g.basis.assumptions) console.error(`assumption: ${a}`);
    return 0;
  }
  const id = String(args._[2] ?? '');
  if (!id) { console.error('usage: proof show <finding-id> | proof replay <finding-id> | proof generate <finding-id> | proof doctor'); return 4; }
  if (sub === 'show') {
    const all = (0,store.listProofs)(root, id);
    if (!all.length) { console.error(`No stored proof for ${id}.`); return 4; }
    const latest = all.find((p) => p.record);
    if (all.some((p) => p.tampered)) console.error(`WARNING: ${all.filter((p) => p.tampered).length} stored record(s) failed their integrity check and are not trusted.`);
    const good = all.find((p) => p.record && !p.tampered);
    if (!good) { console.error('No intact proof record.'); return 1; }
    if (args.flags.json) console.log(JSON.stringify(good.record, null, 2)); else console.log(formatResult(good.record));
    // the detection generated from this finding's proof (detection-and-response loop), when there is one
    try {
      const det = (await __webpack_require__.e(/* import() */ 8551).then(__webpack_require__.bind(__webpack_require__, 58551))).latestRecord(root, id, 'detection');
      if (det && !args.flags.json) console.log(`Detection: ${det.record.ir?.id ?? 'unknown'} (${det.record.validation?.status ?? 'not validated'}${det.record.enabled ? ', enabled' : ''})`);
    } catch { /* the proof output does not depend on it */ }
    void latest;
    return 0;
  }
  if (sub === 'replay') {
    const stored = (0,store.latestProof)(root, id);
    if (!stored?.record?.reproducer) { console.error(`No stored reproducer for ${id}.`); return 4; }
    const tmpDir = external_node_fs_.mkdtempSync(external_node_path_.join(external_node_os_.tmpdir(), 'proof-replay-'));
    const tmp = external_node_path_.join(tmpDir, 'reproducer.json');
    external_node_fs_.writeFileSync(tmp, JSON.stringify(stored.record.reproducer));
    args.flags.reproducer = tmp;
    args._ = ['triage', 'exploit', id];
    try { return await cmdProve(args, root); } finally { external_node_fs_.rmSync(tmpDir, { recursive: true, force: true }); }
  }
  console.error('usage: proof show|replay <finding-id> | proof doctor');
  return 4;
}

function doctor(args) {
  const tools = (0,runner/* hostTools */.qV)();
  const rows = proof_fabric_reproducer/* LANGUAGES */.Yj.map((l) => ({ lang: l, ...(0,runner/* languageSupport */.ql)(l, tools) }));
  const envs = ['javascript', 'python', 'haskell'].map((l) => ({ lang: l, ...(0,runner/* selectEnvironment */.aP)({ lang: l }) }));
  if (args.flags.json) { console.log(JSON.stringify({ tools, languages: rows, environments: envs }, null, 2)); return 0; }
  console.log('Proof fabric doctor');
  for (const r of rows) console.log(`  ${r.lang.padEnd(11)} ${r.supported ? 'supported' : `unsupported (${r.reason})`}`);
  for (const e of envs) console.log(`  environment for ${e.lang}: ${e.mode}, ${e.assurance} assurance${e.reason ? ` (${e.reason})` : ''}${e.containerSkipped ? `; container skipped: ${e.containerSkipped}` : ''}`);
  const usable = envs.some((e) => e.mode !== 'unavailable');
  if (!usable) console.log('  RESULT: no execution environment available; proofs will report blocked, never clean.');
  return usable ? 0 : 1;
}


/***/ }),

/***/ 3740:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   kO: () => (/* binding */ proveFinding)
/* harmony export */ });
/* unused harmony exports independentVerify, applySeverityPolicy, _newRunId */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var _states_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(12090);
/* harmony import */ var _runner_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(23081);
/* harmony import */ var _reproducer_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(37055);
/* harmony import */ var _proof_tier_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(40216);
// Proof orchestration: finding + revision + reproducer + policy -> structured evidence.
//
// Rules that make this safe to trust:
//  * The model may propose a reproducer and select an oracle. The oracle (oracles.js) judges. Never a model.
//  * An attempt that did not complete (timeout, build failure, blocked, unsupported, error) is NOT a negative and NOT a
//    positive: it is degraded evidence, it never advances the state, and it makes the result INCOMPLETE.
//  * EXPLOIT_CONFIRMED needs `required` successes in `attempts` completed attempts AND a pass from an independent
//    verifier that receives only {revision, reproducer, findingId, oracle} in a fresh environment.
//  * "Not reproduced" is reported as such; it is never reported as safe.






const PROOF_POLICY_DEFAULTS = Object.freeze({ attempts: 3, required: 3, independentReplay: true, timeoutMs: 20_000, cpus: 1, memoryMb: 512, network: 'none', requireContainer: false });
const RESULT_SCHEMA = 'agentic-security/proof-result';

function normalizePolicy(p = {}) {
  const x = { ...PROOF_POLICY_DEFAULTS, ...p };
  x.attempts = Math.max(1, Math.min(10, Math.trunc(Number(x.attempts)) || PROOF_POLICY_DEFAULTS.attempts));
  x.required = Math.max(1, Math.min(x.attempts, Math.trunc(Number(x.required)) || x.attempts));
  x.timeoutMs = Math.max(1000, Math.min(120_000, Number(x.timeoutMs) || PROOF_POLICY_DEFAULTS.timeoutMs));
  return x;
}

const summarize = (a) => ({ status: a.status, fired: a.oracle?.fired === true, inconclusive: a.oracle?.inconclusive === true, reason: a.oracle?.reason ?? a.reasons?.[0] ?? null, durationMs: a.durationMs, degraded: a.degraded });

/**
 * Independent verifier. Takes a verifierView ONLY; any extra property (a model's reasoning, prior results) is rejected so
 * the isolation of its inputs is checkable rather than a convention.
 */
async function independentVerify(view, opts = {}) {
  const allowed = new Set(['revision', 'reproducer', 'findingId', 'oracle']);
  const extra = Object.keys(view || {}).filter((k) => !allowed.has(k));
  if (extra.length) return { status: 'rejected', reason: `verifier input must be exactly revision, reproducer, findingId, oracle; got extra: ${extra.join(', ')}` };
  const attempt = await (opts.attemptFn ?? _runner_js__WEBPACK_IMPORTED_MODULE_2__/* .runAttempt */ .Tm)(structuredClone(view.reproducer), { ...opts, preferContainer: opts.preferContainer });
  return { status: attempt.status === 'completed' ? (attempt.oracle?.fired ? 'confirmed' : 'not-reproduced') : 'incomplete', attempt: summarize(attempt), environment: attempt.environment ?? null };
}

/**
 * @param {object} a
 * @param {object} a.finding       the finding (id/stableId, severity, proofTier ...)
 * @param {string} [a.revision]    commit the proof applies to
 * @param {object} a.reproducer    serialized reproducer
 * @param {object} [a.policy]
 * @param {object} [a.deps]        test seams: { attemptFn }
 */
async function proveFinding({ finding, revision = null, reproducer, policy = {}, signal, deps = {}, sourceState = null, sourceRoot = null, overlay = null } = {}) {
  const started = Date.now();
  const pol = normalizePolicy(policy);
  const attemptFn = deps.attemptFn ?? _runner_js__WEBPACK_IMPORTED_MODULE_2__/* .runAttempt */ .Tm;
  const findingId = finding?.stableId ?? finding?.id ?? reproducer?.findingId ?? 'unknown';
  const degradation = [];
  let state = sourceState ?? (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .fromProofTier */ .jn)((0,_proof_tier_js__WEBPACK_IMPORTED_MODULE_4__/* .proofTierOf */ .gx)(finding || {}));
  if (state === 'REPRODUCED') state = 'STATICALLY_CORROBORATED'; // an old single-run marker proof must be re-earned here
  const startState = state;

  const result = (extra) => ({
    schema: RESULT_SCHEMA, version: 1, findingId, revision, startState, state, staticCorroboration: (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .stateRank */ .g3)(startState) >= 1, tier: (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .toProofTier */ .KF)(state),
    oracle: reproducer?.oracle?.type ?? null, policy: pol,
    reproducerDigest: reproducer ? safeDigest(reproducer) : null,
    degradation, timing: { proofMs: Date.now() - started }, ...extra,
  });

  const errs = reproducer ? (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .validateReproducer */ .mC)(reproducer) : ['no reproducer supplied'];
  if (errs.length) { degradation.push('invalid-reproducer'); return result({ completeness: 'INCOMPLETE', outcome: 'invalid-reproducer', reasons: errs, attempts: { required: pol.required, run: 0, successes: 0, incomplete: 0 }, independentReplay: { status: 'not-run' } }); }

  // A valid reproducer is itself the REPRODUCER_GENERATED rung. Static corroboration is recorded, not required: an exploit
  // that reproduces under an independent oracle is deterministic corroboration in its own right, and a pattern-only finding
  // must not be unable to earn proof merely because the taint engine never saw it. The record says which it was.
  const staticCorroboration = (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .stateRank */ .g3)(startState) >= (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .stateRank */ .g3)('STATICALLY_CORROBORATED');
  if (!staticCorroboration) degradation.push('no-static-corroboration');
  state = 'REPRODUCER_GENERATED';

  const attempts = [];
  for (let i = 0; i < pol.attempts; i++) {
    if (signal?.aborted) { degradation.push('cancelled'); break; }
    const a = await attemptFn(structuredClone(reproducer), { limits: { timeoutMs: pol.timeoutMs }, signal, requireContainer: pol.requireContainer, preferContainer: pol.preferContainer, force: pol.force, sourceRoot, overlay });
    attempts.push(a);
    // Stop early once the threshold can no longer be met only if every attempt is a decisive negative; incomplete runs continue.
  }
  const completed = attempts.filter((a) => a.status === 'completed' && !a.oracle?.inconclusive);
  const successes = completed.filter((a) => a.oracle?.fired).length;
  const incomplete = attempts.length - completed.length;
  for (const a of attempts) for (const d of a.degraded || []) if (!degradation.includes(d)) degradation.push(d);
  if (incomplete) degradation.push(`incomplete-attempts:${incomplete}`);
  const env = attempts.find((a) => a.environment)?.environment ?? null;
  const base = {
    environment: env && { mode: env.mode, assurance: env.assurance, backend: env.backend ?? null, note: env.note ?? null },
    build: attempts.some((a) => a.status === 'build-failed') ? 'failed' : attempts.length ? 'ok' : 'not-run',
    attempts: { required: pol.required, run: attempts.length, successes, incomplete, detail: attempts.map(summarize) },
    artifactHashes: { reproducer: safeDigest(reproducer), observations: (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .sha256 */ .sc)((0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .canonicalize */ .dw)(attempts.map((a) => a.observation ?? null))) },
  };

  if (successes > 0) {
    const r = (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .advance */ .np)(state, 'REPRODUCED'); if (r.ok) state = r.state;
  }
  if (!attempts.length) return result({ ...base, completeness: 'INCOMPLETE', outcome: 'not-run', independentReplay: { status: 'not-run' } });
  if (successes === 0) {
    const decisive = completed.length === attempts.length;
    return result({ ...base, completeness: decisive ? 'FULL' : 'INCOMPLETE', outcome: decisive ? 'not-reproduced' : 'inconclusive', note: 'not reproduced is not proof of safety', independentReplay: { status: 'not-run' } });
  }
  if (successes < pol.required || incomplete) {
    return result({ ...base, completeness: incomplete ? 'INCOMPLETE' : 'DEGRADED', outcome: 'reproduced-below-threshold', independentReplay: { status: 'not-run' } });
  }

  let independent = { status: 'skipped' };
  if (pol.independentReplay) {
    independent = await independentVerify((0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .verifierView */ .IW)({ revision, reproducer, findingId, oracle: reproducer.oracle }), { attemptFn, limits: { timeoutMs: pol.timeoutMs }, signal, requireContainer: pol.requireContainer, force: pol.force, sourceRoot, overlay });
    if (independent.status !== 'confirmed') degradation.push(`independent-replay:${independent.status}`);
  } else degradation.push('independent-replay-disabled');
  if (independent.status === 'confirmed') {
    const r = (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .advance */ .np)(state, 'EXPLOIT_CONFIRMED'); if (r.ok) state = r.state;
  }
  const full = state === 'EXPLOIT_CONFIRMED' && base.environment?.assurance !== 'none';
  return result({ ...base, independentReplay: independent, completeness: full ? (base.environment.assurance === 'lower' ? 'DEGRADED' : 'FULL') : 'INCOMPLETE', outcome: full ? 'exploit-confirmed' : 'reproduced-unverified' });
}

const safeDigest = (r) => { try { return (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .reproducerDigest */ .we)(r); } catch { return null; } };

/** Severity policy: optional, never on by default. Returns the finding unchanged unless the policy asks to demote. */
function applySeverityPolicy(finding, evidenceState, policy) {
  const req = policy?.criticalRequires;
  if (!Array.isArray(req) || !req.length || finding?.severity !== 'critical') return finding;
  const ok = req.some((s) => stateRankOf(evidenceState ?? 'CANDIDATE') >= stateRankOf(s));
  return ok ? finding : { ...finding, severity: 'high', severityPolicy: { demotedFrom: 'critical', reason: `critical requires ${req.join(' or ')}; evidence state is ${evidenceState ?? 'CANDIDATE'}` } };
}
const _newRunId = () => randomBytes(6).toString('hex');


/***/ }),

/***/ 12090:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   KF: () => (/* binding */ toProofTier),
/* harmony export */   g3: () => (/* binding */ stateRank),
/* harmony export */   jn: () => (/* binding */ fromProofTier),
/* harmony export */   np: () => (/* binding */ advance)
/* harmony export */ });
/* unused harmony exports EVIDENCE_STATES, COMPLETENESS */
// Evidence state ladder for the Universal Exploit Proof Fabric.
//
// Evidence state is SEPARATE from severity and confidence. It extends, never replaces, the vocabulary that already
// exists: `proof-tier.js` (execution-proven / proof-failed / taint-proven / unproven) and the fix-verify legs
// (`verifiedFull`, `degradedLegs`). `toProofTier` / `fromProofTier` are the explicit bridges.
//
// Transitions are guarded: a state can only be reached from the state directly before it (or by dropping back), so no
// caller can jump a finding to EXPLOIT_CONFIRMED without passing REPRODUCED, or to FIX_VERIFIED without
// FIX_REPLAY_BLOCKED. A degraded or incomplete run NEVER advances a state.
const EVIDENCE_STATES = Object.freeze([
  'CANDIDATE',
  'STATICALLY_CORROBORATED',
  'REPRODUCER_GENERATED',
  'REPRODUCED',
  'EXPLOIT_CONFIRMED',
  'FIX_REPLAY_BLOCKED',
  'FIX_VERIFIED',
]);

const stateRank = (s) => EVIDENCE_STATES.indexOf(s);

const REQUIRES_PREDECESSOR = Object.freeze(Object.fromEntries(EVIDENCE_STATES.map((s, i) => [s, i === 0 ? null : EVIDENCE_STATES[i - 1]])));

/**
 * Advance `from` to `to`. Returns { ok, state, reason }. Moving up requires `to` to be exactly the next rung; moving
 * down or staying is always allowed (evidence can be lost, never invented). Unknown states are rejected.
 */
function advance(from, to) {
  if (!EVIDENCE_STATES.includes(from)) return { ok: false, state: 'CANDIDATE', reason: `unknown current state: ${String(from)}` };
  if (!EVIDENCE_STATES.includes(to)) return { ok: false, state: from, reason: `unknown target state: ${String(to)}` };
  if (stateRank(to) <= stateRank(from)) return { ok: true, state: to, reason: null };
  if (REQUIRES_PREDECESSOR[to] !== from) return { ok: false, state: from, reason: `cannot reach ${to} from ${from}: ${REQUIRES_PREDECESSOR[to]} is required first` };
  return { ok: true, state: to, reason: null };
}

// Bridges to the older vocabulary so existing consumers keep working.
function toProofTier(state) {
  const r = stateRank(state);
  if (r >= stateRank('EXPLOIT_CONFIRMED')) return 'execution-proven';
  if (r >= stateRank('STATICALLY_CORROBORATED')) return 'taint-proven';
  return 'unproven';
}

function fromProofTier(tier) {
  if (tier === 'taint-proven') return 'STATICALLY_CORROBORATED';
  // execution-proven under the older single-run marker path is one run, not the 3/3 + independent replay the fabric
  // requires, so it maps to REPRODUCED and never to EXPLOIT_CONFIRMED.
  if (tier === 'execution-proven') return 'REPRODUCED';
  return 'CANDIDATE';
}

// Completeness vocabulary shared with fix-verify: FULL only when nothing was skipped.
const COMPLETENESS = Object.freeze(['FULL', 'DEGRADED', 'INCOMPLETE']);


/***/ }),

/***/ 62199:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   findingKey: () => (/* binding */ findingKey),
/* harmony export */   latestProof: () => (/* binding */ latestProof),
/* harmony export */   listProofs: () => (/* binding */ listProofs),
/* harmony export */   saveProof: () => (/* binding */ saveProof),
/* harmony export */   scrubDeep: () => (/* binding */ scrubDeep)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(31174);
/* harmony import */ var _encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(39984);
/* harmony import */ var _llm_validator_redact_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(65388);
/* harmony import */ var _reproducer_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(37055);
// Proof artifact store: `.agentic-security/proofs/<findingKey>/<recordDigest>.json`.
//
// Reuses the existing state machinery rather than adding another: `safeWriteState` (refuses unsafe dirs and symlinks),
// `maybeEncryptForWrite` / `maybeDecryptForRead` (the `proofs` artifact is registered `confidential`), retention
// (evidence class) and legal holds (a hold on `proofs` blocks purge). Nothing persisted contains a plaintext credential:
// records are passed through a recursive secret filter first, and the runner never returns its per-run nonce or secrets.







const PROOF_RECORD_SCHEMA = 'agentic-security/proof-record';
const PROOFS_DIR = 'proofs';
const MAX_RECORD_BYTES = 512 * 1024;

const findingKey = (id) => `${String(id).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80)}-${(0,_reproducer_js__WEBPACK_IMPORTED_MODULE_5__/* .sha256 */ .sc)(String(id)).slice(0, 8)}`;

// The shared redactor catches key=value shapes; bare tokens need their own pass, so persisted evidence cannot carry one.
const BARE_SECRET_RES = [
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g, /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, /\bSECRET-[0-9a-f]{24}-[a-z0-9_-]+\b/g,
];
function scrubString(text) {
  let t = String(text);
  try { t = (0,_llm_validator_redact_js__WEBPACK_IMPORTED_MODULE_4__/* .redactSecrets */ .f)(t).text; } catch { return '[unredactable]'; }
  for (const re of BARE_SECRET_RES) t = t.replace(re, '[REDACTED-SECRET]');
  return t;
}

/** Deep-copy `v` with every string passed through the secret redactor. */
function scrubDeep(v) {
  if (typeof v === 'string') return scrubString(v);
  if (Array.isArray(v)) return v.map(scrubDeep);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrubDeep(x)]));
  return v;
}

function recordDigest(record) {
  const { recordDigest: _omit, ...rest } = record;
  return (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_5__/* .sha256 */ .sc)((0,_reproducer_js__WEBPACK_IMPORTED_MODULE_5__/* .canonicalize */ .dw)(rest));
}

function saveProof(scanRoot, record) {
  const safe = scrubDeep(record);
  safe.schema = PROOF_RECORD_SCHEMA;
  safe.recordDigest = recordDigest(safe);
  const text = JSON.stringify(safe, null, 2);
  if (Buffer.byteLength(text) > MAX_RECORD_BYTES) return { ok: false, reason: 'proof record exceeds the size limit' };
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.ensureStateDir)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const enc = (0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__/* .maybeEncryptForWrite */ .v2)(scanRoot, PROOFS_DIR, text);
  if (!enc.ok) return { ok: false, reason: enc.reason };
  const file = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(scanRoot, PROOFS_DIR, findingKey(record.findingId), `${safe.recordDigest}.json`);
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.safeWriteState)(file, enc.content)) return { ok: false, reason: 'state write refused' };
  return { ok: true, file, digest: safe.recordDigest, encrypted: enc.encrypted };
}

function readRecord(file) {
  const text = (0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__.maybeDecryptForRead)(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8'));
  const rec = JSON.parse(text);
  // A record whose content no longer matches its own digest was modified after it was written.
  if (rec.recordDigest !== recordDigest(rec)) return { tampered: true, record: rec };
  return { tampered: false, record: rec };
}

/** Newest-first records for a finding. Tampered records are returned flagged, never silently dropped or trusted. */
function listProofs(scanRoot, findingId) {
  const dir = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(scanRoot, PROOFS_DIR, findingKey(findingId));
  let names = [];
  try { names = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir).filter((n) => n.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const n of names) {
    const f = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, n);
    try { const { tampered, record } = readRecord(f); out.push({ file: f, tampered, record, mtime: node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(f).mtimeMs }); } catch { out.push({ file: f, tampered: true, record: null, mtime: 0 }); }
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

function latestProof(scanRoot, findingId) {
  return listProofs(scanRoot, findingId).find((p) => p.record) ?? null;
}


/***/ })

};
