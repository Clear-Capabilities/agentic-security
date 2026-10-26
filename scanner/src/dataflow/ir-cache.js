// Cross-scan cache of parsed JavaScript / TypeScript IR (DAG-05, the stage the taint cache does not cover).
//
// The dependency-complete taint cache (incremental-session.js) removes most of the cost of the interprocedural
// engine on a re-scan, and what is left is dominated by parsing every file to IR again. This module keeps one
// record per source file so an unchanged file is read back instead of parsed. It changes the cost of building
// the IR and never its content:
//
//   * A record is keyed by the SHA-256 of the file's path and text, the analyzer/parser digest (a change to any
//     source under ir/, dataflow/, graph/ or language/, or to the bundle, invalidates every record) and the
//     Babel versions the parse ran under. A different file text, parser or toolchain is a miss.
//   * The IR numbers its CFG nodes from a process-global counter (`n123`). A restored file is given fresh ids
//     from the same counter, in the same relative order, so an id is as unique across the process as one the
//     parser made. Ids appear only in the fields remapped below; a file that holds an id anywhere else is
//     never written.
//   * A record is written only after the IR has been checked to survive JSON exactly: anything that would not
//     (an undefined member, a non-finite number, a BigInt, a Map, an object with a foreign prototype, an id
//     held in a field the remap does not know) is not cached, and that file is parsed every scan. Regular
//     expressions, which JSON would turn into `{}`, are recorded by path and rebuilt on load.
//   * Each record carries the SHA-256 of its payload; a truncated, edited or foreign file is a miss, never an
//     error. Writes go to a temp file and are renamed into place.
//
// Scope: JavaScript and TypeScript only (the parser that owns the id counter). Every other language is parsed
// as before. Trust boundary: the same as the rest of the incremental state under .agentic-security/incremental
// (digests detect corruption; they are not a signature, so a hostile working tree that plants a consistent
// record could substitute an IR; a planted record must also match the file's exact text and the analyzer digest).

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createRequire } from 'node:module';

import { reserveNodeIds } from '../ir/parser-js.js';
import { analyzerDigest } from './dep-fingerprint.js';
import { statePath, stateWritesEnabled } from '../posture/state-dir.js';

const IR_CACHE_FORMAT = 'ir-cache/1';
const ID_RE = /^n\d+$/;
const ID_NUM = (s) => Number(s.slice(1));

let _toolchain = null;
function toolchainDigest() {
  if (_toolchain) return _toolchain;
  const parts = [IR_CACHE_FORMAT, analyzerDigest()];
  try {
    const req = createRequire(import.meta.url);
    for (const pkg of ['@babel/core', '@babel/preset-react', '@babel/preset-typescript', '@babel/parser']) {
      try { parts.push(`${pkg}@${req(`${pkg}/package.json`).version}`); } catch { parts.push(`${pkg}@unresolved`); }
    }
  } catch { parts.push('toolchain@unresolved'); }
  _toolchain = crypto.createHash('sha256').update(parts.join('\n')).digest('hex');
  return _toolchain;
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ── id handling ─────────────────────────────────────────────────────────────

/** Every node id of a file's IR, or null when the IR holds something this cache cannot place. */
function fileIds(ir) {
  if (!ir || !Array.isArray(ir.functions)) return null;
  const ids = [];
  for (const fn of ir.functions) {
    if (!fn || !fn.cfg || !fn.cfg.nodes || typeof fn.cfg.nodes !== 'object') return null;
    for (const k of Object.keys(fn.cfg.nodes)) { if (!ID_RE.test(k)) return null; ids.push(k); }
  }
  return ids;
}

/**
 * Give an IR read back from a record new ids. Throws when a reference names an id the file does not define:
 * the caller treats that as a miss.
 */
function remapIds(ir) {
  const ids = fileIds(ir);
  if (!ids) throw new Error('unplaceable ids');
  ids.sort((a, b) => ID_NUM(a) - ID_NUM(b));
  const base = reserveNodeIds(ids.length);
  const map = new Map();
  ids.forEach((id, i) => map.set(id, `n${base + i + 1}`));
  const m = (id) => { const v = map.get(id); if (v === undefined) throw new Error(`dangling id ${id}`); return v; };
  for (const fn of ir.functions) {
    const cfg = fn.cfg;
    cfg.entry = m(cfg.entry);
    cfg.exit = m(cfg.exit);
    const entries = Object.entries(cfg.nodes);
    for (const [k, node] of entries) {
      if (node.id !== k) throw new Error('node id differs from its key');
      node.id = m(node.id);
      if (!Array.isArray(node.succ) || !Array.isArray(node.pred)) throw new Error('node without edges');
      node.succ = node.succ.map(m);
      node.pred = node.pred.map(m);
    }
    cfg.nodes = Object.fromEntries(entries.map(([k, node]) => [m(k), node]));
    fn.returns = (fn.returns || []).map(m);
    for (const c of (fn.calls || [])) c.site = m(c.site);
    for (const list of Object.values(fn.writes || {})) for (const w of list) w.node = m(w.node);
    for (const list of Object.values(fn.reads || {})) { for (let i = 0; i < list.length; i++) list[i] = m(list[i]); }
  }
  return ir;
}

/**
 * The IR as text with every node id replaced by its rank among the file's ids, and regular expressions kept
 * distinct from `{}`. Two IRs that differ only in the ids they were numbered with give the same text. Used by
 * the tests that prove a restored IR equals a fresh parse.
 */
function canonical(ir) {
  const ids = fileIds(ir);
  if (!ids) return null;
  ids.sort((a, b) => ID_NUM(a) - ID_NUM(b));
  const rank = new Map(ids.map((id, i) => [id, `#${i}`]));
  const walk = (v) => {
    if (typeof v === 'string') return rank.has(v) ? rank.get(v) : v;
    if (v instanceof RegExp) return { $re: [v.source, v.flags] };
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const o = {};
      for (const [k, x] of Object.entries(v)) o[rank.has(k) ? rank.get(k) : k] = walk(x);
      return o;
    }
    return v;
  };
  return JSON.stringify(walk(ir));
}

/**
 * One walk over a freshly parsed IR: is it exactly what JSON gives back (plus the regular expressions that are
 * recorded by path), and does every node id sit in a field the remap knows? Returns { regexes } or null.
 * `ids` is the set of the file's node ids.
 */
function analyze(ir, ids) {
  const regexes = [];
  let idLike = 0;
  const trail = [];
  const walk = (v) => {
    switch (typeof v) {
      case 'string': if (ids.has(v)) idLike++; return true;
      case 'boolean': return true;
      case 'number': return Number.isFinite(v);
      case 'object': break;
      default: return false; // undefined, function, symbol, bigint
    }
    if (v === null) return true;
    if (v instanceof RegExp) {
      if (v.lastIndex !== 0) return false;
      regexes.push([trail.slice(), v.source, v.flags]);
      return true;
    }
    if (Array.isArray(v)) {
      if (Object.getPrototypeOf(v) !== Array.prototype) return false;
      for (let i = 0; i < v.length; i++) {
        if (!(i in v)) return false; // a hole
        trail.push(i);
        const ok = walk(v[i]);
        trail.pop();
        if (!ok) return false;
      }
      return true;
    }
    if (Object.getPrototypeOf(v) !== Object.prototype) return false;
    for (const k of Object.keys(v)) {
      if (ids.has(k)) idLike++;
      trail.push(k);
      const ok = walk(v[k]);
      trail.pop();
      if (!ok) return false;
    }
    return Object.getOwnPropertySymbols(v).length === 0;
  };
  if (!walk(ir)) return null;
  // The ids the remap handles: entry, exit, each node's key and id and edges, returns, call sites, writes, reads.
  let known = 0;
  for (const fn of ir.functions) {
    known += 2 + (fn.returns || []).length + (fn.calls || []).length;
    for (const node of Object.values(fn.cfg.nodes)) {
      if (!Array.isArray(node.succ) || !Array.isArray(node.pred)) return null;
      known += 2 + node.succ.length + node.pred.length;
    }
    for (const list of Object.values(fn.writes || {})) known += list.length;
    for (const list of Object.values(fn.reads || {})) known += list.length;
  }
  return idLike === known ? { regexes } : null;
}

/** Put the recorded regular expressions back where JSON left `{}` (before ids are remapped: the paths use the old ids). */
function restoreRegexes(ir, regexes) {
  for (const [trail, source, flags] of regexes) {
    let holder = ir;
    for (let i = 0; i < trail.length - 1; i++) holder = holder[trail[i]];
    holder[trail[trail.length - 1]] = new RegExp(source, flags);
  }
}

// ── the cache ───────────────────────────────────────────────────────────────

/**
 * Open the cache under `<state>/incremental/ir`. `read` / `write` select what it may do (a scan with state
 * writes off still reads). Returns an object with `load`, `store` and `stats`.
 */
export function openIrCache(scanRoot, { read = true, write = stateWritesEnabled() } = {}) {
  const dir = statePath(scanRoot, 'incremental', 'ir');
  const stats = { hits: 0, misses: 0, stored: 0, skipped: 0, rejected: 0, loadMs: 0, storeMs: 0, bytesRead: 0, bytesWritten: 0 };
  let tool = null;
  const keyOf = (file, code) => sha(`${tool || (tool = toolchainDigest())}\0${file}\0${code}`);
  const slotOf = (file) => path.join(dir, `${sha(file).slice(0, 40)}.ir.json`);

  function readRecord(file, key) {
    let text;
    try { text = fs.readFileSync(slotOf(file), 'utf8'); } catch { return null; }
    const nl = text.indexOf('\n');
    if (nl < 0) return { bad: true };
    let head;
    try { head = JSON.parse(text.slice(0, nl)); } catch { return { bad: true }; }
    if (!head || head.format !== IR_CACHE_FORMAT || head.key !== key) return null; // another file text or toolchain: a plain miss
    const payload = text.slice(nl + 1);
    stats.bytesRead += payload.length;
    if (payload.length !== head.bytes || sha(payload) !== head.sha256 || !Array.isArray(head.regexes)) return { bad: true };
    return { payload, regexes: head.regexes };
  }

  function load(file, code) {
    if (!read) return undefined;
    const t0 = performance.now();
    try {
      const key = keyOf(file, code);
      const rec = readRecord(file, key);
      if (!rec) { stats.misses++; return undefined; }
      if (rec.bad) { stats.rejected++; return undefined; }
      const parsed = JSON.parse(rec.payload);
      restoreRegexes(parsed, rec.regexes);
      const ir = remapIds(parsed);
      if (!ir || ir.file !== file || !Array.isArray(ir.functions)) { stats.rejected++; return undefined; }
      stats.hits++;
      return ir;
    } catch {
      stats.rejected++;
      return undefined;
    } finally { stats.loadMs += performance.now() - t0; }
  }

  function store(file, code, ir) {
    if (!write) return false;
    const t0 = performance.now();
    try {
      const ids = fileIds(ir);
      const found = ids ? analyze(ir, new Set(ids)) : null;
      if (!found) { stats.skipped++; return false; }
      const key = keyOf(file, code);
      const payload = JSON.stringify(ir);
      const head = JSON.stringify({ format: IR_CACHE_FORMAT, key, sha256: sha(payload), bytes: payload.length, file, regexes: found.regexes });
      fs.mkdirSync(dir, { recursive: true });
      const slot = slotOf(file);
      const tmp = `${slot}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
      fs.writeFileSync(tmp, `${head}\n${payload}`, { mode: 0o600 });
      fs.renameSync(tmp, slot);
      stats.stored++;
      stats.bytesWritten += payload.length;
      return true;
    } catch {
      stats.skipped++;
      return false;
    } finally { stats.storeMs += performance.now() - t0; }
  }

  return { load, store, stats: () => ({ ...stats }), dir };
}

export const _internals = { remapIds, canonical, fileIds, analyze, restoreRegexes, toolchainDigest };
