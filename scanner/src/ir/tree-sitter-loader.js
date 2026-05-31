// Tree-sitter parser loader (roadmap #8) — OPTIONAL, runtime-lazy, degrades.
//
// web-tree-sitter + tree-sitter-wasms are OPTIONAL dependencies (pinned to an
// ABI-matched pair: web-tree-sitter 0.20.8 ↔ tree-sitter-wasms 0.1.13). They
// are NOT bundled into dist (the build marks them `--external`), so the
// committed bundle stays self-contained and small; this loader requires them
// lazily at runtime and returns null when they're absent. That keeps the
// scanner fully bootable offline / without the optional deps — long-tail
// languages simply fall back to the existing pattern detectors.
//
// Long-tail languages this unlocks (no first-class IR parser today):
// rust, solidity, cpp, c, go, swift, dart. (js/ts/py/java/etc. already have
// dedicated IR parsers and don't need this.)

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// language → prebuilt grammar wasm shipped by tree-sitter-wasms.
const GRAMMAR_WASM = {
  rust: 'tree-sitter-rust.wasm',
  solidity: 'tree-sitter-solidity.wasm',
  cpp: 'tree-sitter-cpp.wasm',
  c: 'tree-sitter-c.wasm',
  go: 'tree-sitter-go.wasm',
  swift: 'tree-sitter-swift.wasm',
  dart: 'tree-sitter-dart.wasm',
};

const EXT_TO_LANG = {
  rs: 'rust', sol: 'solidity', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp',
  c: 'c', h: 'c', go: 'go', swift: 'swift', dart: 'dart',
};

export function treeSitterLangOf(file) {
  if (typeof file !== 'string') return null;
  const ext = file.split('.').pop().toLowerCase();
  return EXT_TO_LANG[ext] || null;
}

let _Parser; // undefined = not tried, null = unavailable, fn = the class
let _initPromise = null;
const _langCache = new Map(); // language → Language | null
const _parserCache = new Map(); // language → Parser | null

async function _ensureRuntime() {
  if (_Parser === null) return null;
  if (_Parser) return _Parser;
  try {
    // 0.20 API: the module's default export IS the Parser class.
    const mod = require('web-tree-sitter');
    _Parser = mod && (mod.Parser || mod.default || mod);
    if (!_initPromise) _initPromise = _Parser.init();
    await _initPromise;
    return _Parser;
  } catch {
    _Parser = null; // optional dep absent or failed to init → degrade.
    return null;
  }
}

function _grammarPath(language) {
  const file = GRAMMAR_WASM[language];
  if (!file) return null;
  try { return require.resolve('tree-sitter-wasms/out/' + file); } catch { return null; }
}

// Returns a ready-to-use Parser for `language`, or null if tree-sitter or the
// grammar isn't available. Cached per language. `parser.parse(src)` is then
// synchronous, so callers can parse inside a sync loop after awaiting this.
export async function getParserFor(language) {
  if (_parserCache.has(language)) return _parserCache.get(language);
  const Parser = await _ensureRuntime();
  if (!Parser) { _parserCache.set(language, null); return null; }
  try {
    let Lang = _langCache.get(language);
    if (Lang === undefined) {
      const wasm = _grammarPath(language);
      Lang = wasm ? await Parser.Language.load(wasm) : null;
      _langCache.set(language, Lang);
    }
    if (!Lang) { _parserCache.set(language, null); return null; }
    const p = new Parser();
    p.setLanguage(Lang);
    _parserCache.set(language, p);
    return p;
  } catch {
    _parserCache.set(language, null);
    return null;
  }
}

export async function isTreeSitterAvailable() {
  return (await _ensureRuntime()) != null;
}

// Walk every named node, invoking cb(node). Iterative to avoid deep recursion.
export function walkNamed(root, cb) {
  if (!root) return;
  const stack = [root];
  while (stack.length) {
    const n = stack.pop();
    cb(n);
    for (let i = n.namedChildCount - 1; i >= 0; i--) stack.push(n.namedChild(i));
  }
}

export const _internals = { GRAMMAR_WASM, EXT_TO_LANG, _grammarPath };
