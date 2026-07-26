// AST-backed Python parser — drop-in replacement for parser-py.js.
//
// Shells to `scanner/src/ir/parser-py.helper.py` which uses Python's stdlib
// `ast` module (zero external dependencies, ships with Python 3.8+) to
// produce the same IR shape parser-py.js emits, but computed from a real
// parser rather than a regex-balanced indentation walker.
//
// What this fixes (gaps in the regex parser, by its own admission):
//   - Comprehensions, decorators, match statements, async/await, lambda
//     bodies — all dropped by the regex parser; the AST parser preserves
//     the function records even when the body has constructs we don't
//     fully lower yet.
//   - `def f(x=Foo(1, 2))` and `db.execute(sanitize(x))` — nested parens
//     that the regex parser's call regex rejected.
//   - Walrus `:=`, type hints (`def f(x: List[int]) -> Dict`), PEP-695
//     generics — recognized cleanly by the real parser.
//
// Cost / fallback:
//   - One python3 subprocess per `runScan` (batched: ALL .py files sent in
//     one stdin payload). Not one process per file.
//   - When python3 isn't on PATH, or is too old (< 3.8), or the helper
//     fails — caller falls back to the regex parser (parser-py.js).
//   - Capability probe is cached for the process; we don't re-spawn
//     python3 every scan.
//
// Toggle:
//   AGENTIC_SECURITY_PY_PARSER=cst   → force this path (error if unavailable)
//   AGENTIC_SECURITY_PY_PARSER=regex → force the legacy regex parser
//   AGENTIC_SECURITY_PY_PARSER=auto  → try CST, fall back silently (default)

import * as cp from 'node:child_process';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HELPER_PATH = path.join(HERE, 'parser-py.helper.py');

// Capability probe — cached per-process. Returns:
//   { ok: true, python: '/usr/bin/python3', version: '3.12.2' }   on success
//   { ok: false, reason: '...' }                                   on failure
let _capability = null;

export function probePythonAvailable() {
  if (_capability) return _capability;
  // Try the canonical names in order. macOS / most Linux have python3;
  // some Linuxes only have python. We don't accept python2 (no f-strings).
  for (const bin of ['python3', 'python']) {
    let r;
    try {
      r = cp.spawnSync(bin, ['--version'], { encoding: 'utf8', timeout: 1500 });
    } catch { continue; }
    if (r.status !== 0) continue;
    // Output format: "Python 3.12.2" (or 2.x — reject those).
    const m = /Python\s+(\d+)\.(\d+)\.(\d+)/.exec(r.stdout || r.stderr || '');
    if (!m) continue;
    const major = parseInt(m[1], 10);
    const minor = parseInt(m[2], 10);
    if (major < 3 || (major === 3 && minor < 8)) continue;
    _capability = { ok: true, python: bin, version: `${m[1]}.${m[2]}.${m[3]}` };
    return _capability;
  }
  _capability = { ok: false, reason: 'no-python3-on-path' };
  return _capability;
}

// Single-file shim that matches parser-py.js's signature exactly.
//
// Internally we DON'T spawn a subprocess per file — that would be slow.
// Callers should use parsePythonFilesBatch() to amortize the spawn cost.
// This single-file form is kept for the test harness and for any caller
// that passes one file at a time.
export function parsePythonFile(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return null;
  if (!/\.py$/i.test(file)) return null;
  if (raw.length > 1_000_000) return null;
  const cap = probePythonAvailable();
  if (!cap.ok) return null;
  const out = parsePythonFilesBatch([{ file, content: raw }]);
  if (!out || !out.length) return null;
  return out[0];
}

// Batch entry point. Pass [{file, content}, ...]; receive [{file, functions[], topLevel}, ...].
// Returns null on capability / subprocess failure — caller is expected to
// fall back to the regex parser.
export function parsePythonFilesBatch(entries) {
  if (!Array.isArray(entries) || entries.length === 0) return [];
  const cap = probePythonAvailable();
  if (!cap.ok) return null;
  if (!fs.existsSync(HELPER_PATH)) return null;
  const filtered = entries.filter(e =>
    e && typeof e.file === 'string' && /\.py$/i.test(e.file) &&
    typeof e.content === 'string' && e.content.length <= 1_000_000
  );
  if (filtered.length === 0) return [];
  let payload;
  try { payload = JSON.stringify(filtered); }
  catch { return null; }
  let r;
  try {
    r = cp.spawnSync(cap.python, [HELPER_PATH], {
      input: payload,
      encoding: 'utf8',
      // 10 s for a whole batch. The helper itself processes files in a
      // simple linear loop; on a 100-file repo a single-digit-second
      // budget is plenty. If a customer hits the timeout, the regex
      // parser fallback catches them.
      timeout: 10_000,
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (e) {
    if (process.env.AGENTIC_SECURITY_PY_PARSER_DEBUG === '1') {
      process.stderr.write(`parser-py-cst: spawn failed — ${e.message}\n`);
    }
    return null;
  }
  if (r.status !== 0 || !r.stdout) {
    if (process.env.AGENTIC_SECURITY_PY_PARSER_DEBUG === '1') {
      process.stderr.write(`parser-py-cst: helper exit=${r.status} stderr=${r.stderr || ''}\n`);
    }
    return null;
  }
  let out;
  try { out = JSON.parse(r.stdout); }
  catch (e) {
    if (process.env.AGENTIC_SECURITY_PY_PARSER_DEBUG === '1') {
      process.stderr.write(`parser-py-cst: helper output not JSON — ${e.message}\n`);
    }
    return null;
  }
  return _annotateCalls(out);
}

// Recursively collect every 'call' subexpression inside a lowered expr tree
// (a call's own args can themselves contain calls, e.g. `foo(bar(x))`).
// Mirrors parser-cpp.js's `_collectCallExprs`.
function _collectCallExprs(expr, out) {
  if (!expr || typeof expr !== 'object') return;
  if (expr.kind === 'call') {
    out.push(expr);
    for (const a of expr.args || []) _collectCallExprs(a, out);
    return;
  }
  if (Array.isArray(expr.parts)) for (const p of expr.parts) _collectCallExprs(p, out);
  if (Array.isArray(expr.branches)) for (const b of expr.branches) _collectCallExprs(b, out);
  if (Array.isArray(expr.elements)) for (const e of expr.elements) _collectCallExprs(e, out);
  if (Array.isArray(expr.props)) for (const p of expr.props) _collectCallExprs(p && p.value, out);
  if (expr.left) _collectCallExprs(expr.left, out);
  if (expr.right) _collectCallExprs(expr.right, out);
  if (expr.object) _collectCallExprs(expr.object, out);
}

// Build the `fn.calls` list documented at parser-js.js:19 —
// `[{ site, callee, args, line }]` — from the CFG the helper already
// produced. The helper's wire format is left alone (contract stability);
// this derives `calls` the same way parser-cpp.js's `_callSitesFromCfg`
// does, so a call at statement position (its own 'call' node) or embedded
// in another node's expression — an assignment's RHS (`v = helper(r)`,
// exactly the source-introducing shape the taint engine needs), a
// return/throw value, or an if condition — is all surfaced.
function _callSitesFromCfg(cfg) {
  const sites = [];
  for (const [nodeId, node] of Object.entries((cfg && cfg.nodes) || {})) {
    if (!node) continue;
    let root = null;
    if (node.kind === 'call') root = { kind: 'call', callee: node.callee, args: node.args };
    else if (node.kind === 'assign') root = node.source;
    else if (node.kind === 'return' || node.kind === 'throw') root = node.value;
    else if (node.kind === 'if') root = node.cond;
    if (!root) continue;
    const found = [];
    _collectCallExprs(root, found);
    for (const c of found) {
      sites.push({ site: nodeId, callee: c.callee, args: c.args, line: node.line });
    }
  }
  return sites;
}

// Populate `fn.calls` (post-parse, from the CFG) on every function of every
// file entry the helper returned. Done here rather than in the helper
// itself — see module comment above `_callSitesFromCfg`.
function _annotateCalls(entries) {
  if (!Array.isArray(entries)) return entries;
  for (const entry of entries) {
    if (!entry || !Array.isArray(entry.functions)) continue;
    for (const fn of entry.functions) {
      if (fn && fn.cfg) fn.calls = _callSitesFromCfg(fn.cfg);
    }
  }
  return entries;
}

// Reset the cache — for tests.
export function _resetCapabilityCacheForTests() { _capability = null; }
