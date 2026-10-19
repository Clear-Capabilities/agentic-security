// Reproducer generation from a finding's own evidence (PRD 1: `triage exploit --prove` with no hand-written reproducer).
//
// What this is: a DETERMINISTIC harness builder for the cases where a harness can be built from the source alone. It reads the
// flagged file, finds the function around the flagged line, decides how that function is reached, picks the payload for the
// weakness class, and emits an ordinary reproducer, which then goes through exactly the same runner, oracle, 3-of-3 repetition and
// independent replay as any other. A generated reproducer is not a verdict; it is a proposal that is either confirmed by execution
// or not.
//
// What this is not: a general exploit generator. It handles JavaScript (here) and Python (`generate-python.js`), and only code the proof environment can actually load:
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
import fs from 'node:fs';
import path from 'node:path';
import { builtinModules } from 'node:module';
import { parse } from '@babel/parser';
import { validateReproducer } from './reproducer.js';
import { generatePythonReproducer } from './generate-python.js';

const CLASSES = {
  'CWE-78': { name: 'command-injection', payload: 'x; touch {{CANARY:command}}', oracle: { type: 'command_execution', params: { canary: 'command' } } },
  'CWE-22': { needsPy: /\bopen\s*\([^)]*['"][wax]b?\+?['"]|\.write_(?:text|bytes)\s*\(|\bshutil\.(?:copy|move)/, name: 'path-traversal', payload: '../escaped.txt', oracle: { type: 'filesystem_mutation', params: { canary: 'fs' } }, watch: { fs: 'escaped.txt' }, needs: /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\b/ },
  'CWE-918': { name: 'ssrf', payload: '{{CALLBACK_URL}}', oracle: { type: 'outbound_callback' }, network: 'callback' },
};
const MAX_SOURCE = 256 * 1024;
const MAX_FILES = 8;
const EXTS = ['', '.js', '.mjs', '.cjs', '/index.js'];
const BUILTINS = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));
const MODULE_SYNTAX = /^\s*(?:import\s[^('"]|import\s*['"{*]|export\s)/m;

const fail = (reason, extra = {}) => ({ ok: false, reason, ...extra });
const normCwe = (c) => { const m = /(\d{1,5})/.exec(String(c ?? '')); return m ? `CWE-${Number(m[1])}` : null; };

function inside(root, rel) {
  if (typeof rel !== 'string' || !rel || rel.includes('\0')) return null;
  let real;
  try { real = fs.realpathSync(path.resolve(root, rel)); } catch { return null; }
  const base = fs.realpathSync(root);
  return real === base || real.startsWith(base + path.sep) ? real : null;
}

function readSource(root, rel) {
  const real = inside(root, rel);
  if (!real) return null;
  const st = fs.statSync(real);
  if (!st.isFile() || st.size > MAX_SOURCE) return null;
  return { real, text: fs.readFileSync(real, 'utf8') };
}

function parseSource(text) {
  try { return parse(text, { sourceType: 'unambiguous', errorRecovery: false, plugins: ['topLevelAwait'], allowReturnOutsideFunction: true }); } catch { return null; }
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

export function generateReproducer({ finding, root }) {
  const cwe = normCwe(finding?.cwe);
  const cls = CLASSES[cwe];
  if (!cls) return fail(`no payload and oracle exist for ${cwe ?? 'this finding'}; supported: ${Object.keys(CLASSES).join(', ')} (others need a database, a deserializer or a native harness)`);
  const rel = String(finding?.file ?? '');
  const isPy = /\.py$/i.test(rel);
  if (!isPy && !/\.(?:js|mjs|cjs)$/i.test(rel)) return fail(`no harness builder for ${path.extname(rel) || 'this file type'}; JavaScript and Python only`);
  if (!Number.isInteger(finding?.line)) return fail('the finding has no line number');
  if (isPy) return generatePythonReproducer({ finding, root, cls });
  const src = readSource(root, rel);
  if (!src) return fail('the flagged file is missing, outside the repository, or too large');
  const ast = parseSource(src.text);
  if (!ast) return fail('the flagged file could not be parsed');
  const lines = src.text.split('\n');
  const sinkLine = lines[finding.line - 1] ?? '';
  if (cls.needs && !cls.needs.test(sinkLine) && !cls.needs.test(lines.slice(Math.max(0, finding.line - 3), finding.line + 2).join('\n'))) return fail(`${cls.name}: the flagged code is not a write, and the oracle can only observe a write (a read leaves no trace unless the program prints it)`);

  // dependencies the sandbox can satisfy
  const sources = {}; const external = [];
  const entryDir = path.dirname(src.real);
  const rootReal = fs.realpathSync(root); // the repository root as the filesystem names it (a temp dir can sit behind a symlink)
  const collect = (realFile, ast0, count) => {
    for (const spec of dependencies(ast0)) {
      if (BUILTINS.has(spec)) continue;
      if (!spec.startsWith('.')) { external.push(spec); continue; }
      let found = null;
      for (const e of EXTS) { const cand = inside(root, path.relative(rootReal, path.resolve(path.dirname(realFile), spec + e))); if (cand && fs.statSync(cand).isFile()) { found = cand; break; } }
      if (!found) return fail(`the relative import "${spec}" was not found inside the repository`);
      const destRel = path.relative(entryDir, found);
      if (destRel.startsWith('..')) return fail(`"${spec}" lives outside the flagged file's directory, which a proof workspace cannot mirror`);
      if (sources[destRel] || found === src.real) continue;
      if (Object.keys(sources).length >= MAX_FILES) return fail(`the file pulls in more than ${MAX_FILES} repository files`);
      const dep = readSource(root, path.relative(rootReal, found));
      if (!dep) return fail(`"${spec}" is too large or unreadable`);
      sources[destRel] = path.relative(rootReal, found);
      const depAst = parseSource(dep.text);
      if (!depAst) return fail(`"${spec}" could not be parsed`);
      const r = collect(found, depAst, count + 1); if (r) return r;
    }
    return null;
  };
  const bad = collect(src.real, ast, 0);
  if (bad) return bad;
  if (external.length) return fail(`the flagged code needs ${[...new Set(external)].slice(0, 4).join(', ')}, which is not installed in the proof environment; only Node built-ins and repository files can be loaded`, { missing: [...new Set(external)] });

  const esm = MODULE_SYNTAX.test(src.text) || path.extname(rel).toLowerCase() === '.mjs';
  const entry = `target${esm ? '.mjs' : '.cjs'}`;
  sources[entry] = rel;
  const assumptions = [];
  const base = { schema: 'agentic-security/reproducer', version: 1, findingId: String(finding.stableId ?? finding.id ?? 'generated'), lang: 'javascript', oracle: cls.oracle, network: cls.network ?? 'none', ...(cls.watch ? { watch: cls.watch } : {}) };
  if (cls.watch) assumptions.push('the write target is assumed to be one directory below the working directory (the payload is ../escaped.txt); if the code uses another base, the proof will not confirm');

  // shape 1: a script that reads its payload from argv
  if (/process\.argv\s*\[\s*2\s*\]|process\.argv\.slice\(\s*2\s*\)/.test(src.text) && !/\bmodule\.exports\b|^\s*export\s/m.test(src.text)) {
    const reproducer = { ...base, sources, run: ['{{NODE}}', entry, cls.payload] };
    const errs = validateReproducer(reproducer);
    return errs.length ? fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'script', class: cls.name, entry: rel, line: finding.line, assumptions } };
  }

  // shape 2: an exported function around the flagged line
  const candidates = functionsAround(ast, finding.line);
  if (!candidates.length) return fail('the flagged line is not inside a function, and the file does not read its payload from process.argv[2]');
  let around = null; let exp = null;
  for (const c of candidates) { const e = exportName(ast, c); if (e) { around = c; exp = e; break; } }
  if (!around) return fail('the function around the flagged line is not exported, so nothing outside the file can call it');
  const names = paramNames(around.node);
  if (!names.length) return fail('the function around the flagged line takes no parameters, so the payload has no way in');
  const window = lines.slice(Math.max(0, around.node.loc.start.line - 1), Math.min(lines.length, finding.line + 1)).join('\n');
  const requestLike = names.findIndex((n) => n && /^(?:req|request)$/.test(n) && new RegExp(`\\b${n}\\.(?:body|query|params)\\b`).test(sinkLine));
  const direct = requestLike >= 0 ? -1 : names.findIndex((n) => n && new RegExp(`\\b${n}\\b`).test(sinkLine));
  const fallback = direct < 0 && requestLike < 0 ? names.findIndex((n) => n && new RegExp(`\\b${n}\\b`).test(window)) : -1;
  const idx = requestLike >= 0 ? requestLike : direct >= 0 ? direct : fallback;
  if (idx < 0) return fail('none of the function\'s parameters appears in the flagged code, so there is no tainted parameter to fill');
  if (fallback >= 0) assumptions.push(`the tainted parameter "${names[idx]}" was chosen because it appears in the function body near the flagged line, not on the line itself`);
  const args = names.map((_, i) => (i !== idx ? (/^(?:res|response)$/.test(names[i] ?? '') ? 'res' : 'undefined') : requestLike >= 0 ? '{ body: P, query: P, params: P, headers: P, cookies: P }' : 'payload'));
  const files = { 'harness.mjs': harness({ esm, entry, exp, args }) };
  const reproducer = { ...base, sources, files, run: ['{{NODE}}', 'harness.mjs', cls.payload] };
  const errs = validateReproducer(reproducer);
  return errs.length ? fail(`the generated reproducer is invalid: ${errs[0]}`) : { ok: true, reproducer, basis: { shape: 'function', class: cls.name, entry: rel, line: finding.line, function: names.length ? `${exp.kind === 'named' ? exp.name : exp.kind}(${names.join(', ')})` : exp.kind, taintedParameter: names[idx], requestLike: requestLike >= 0, assumptions } };
}
