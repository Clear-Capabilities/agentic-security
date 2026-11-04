//
// lineage-source-catalog.js — JavaScript data collection points that are
// lineage sources but NOT taint sources (GA plan, GA-03.1: "address
// source-category omissions without broadening the main taint catalog
// incorrectly").
//
// Four of the fourteen reachable `SOURCE_CATEGORIES` had no `language: 'js'`
// entry in `dataflow/catalog.js` at all: `cli-argument` (only `py-sys-argv`
// and the argparse entries), `http-upload` (only Django and Symfony),
// `storage-read` (only `py-open-read` and the C `read`/`fread`/`fgets`
// entries) and `user-input` (only `py-input`, `gets`, `scanf`). The lineage
// corpus therefore could not mint a source node for any of them from a
// JavaScript fixture, and the four corpus entries that name them were
// written in Python syntax on purpose, as a disclosed limitation.
//
// Why these entries live HERE and not in `dataflow/catalog.js`'s `CATALOG`:
// that catalog is the taint engine's source list, and every entry in it
// becomes an attacker-controlled input for every SAST and taint finding the
// engine emits. A file's contents (`fs.readFileSync`) and a console prompt
// (`prompt()`, `readlineSync.question()`) are places personal data ENTERS a
// program, which is what a lineage graph records, but treating them as
// attacker-controlled would turn every configuration read into a taint
// source and flood the SAST output with findings nobody asked for. The
// Data Flow Explorer already keeps a second, isolated catalog for the same
// reason (`dataflow/privacy-catalog.js`, never merged into `CATALOG`); this
// module follows that precedent on the source side. `test/lineage/
// lineage-source-catalog.test.js` pins that `dataflow/catalog.js`'s own
// `matchSource` returns null for every shape listed here, so adding an
// entry here can never widen the taint engine by accident.
//
// Reuse boundary: imports nothing from `dataflow/`. The matcher below is a
// deliberately small structural match over the parser's expression shape
// (`ident`/`member`/`call`), not a copy of `catalog.js`'s index machinery;
// an entry that needs receiver types, keyword arguments or a language family
// other than JavaScript belongs in the main catalog, with the taint
// consequences weighed there.

import { reclassifySource } from './source-registry.js';

const JS_FILE = /\.(?:[cm]?js|jsx|tsx?)$/i;

/**
 * Each entry mirrors the main catalog's source shape (`kind`, `id`,
 * `language`, `framework`, `match`, `label`, `provenance`) so
 * `reclassifySource` reads it unchanged: `provenance` is the key the
 * registry's `PROVENANCE_MAP` resolves to a `SOURCE_CATEGORIES` value.
 * `lineageOnly: true` is the marker a reader greps for; nothing consults it.
 */
export const LINEAGE_SOURCE_CATALOG = Object.freeze([
  {
    kind: 'source', id: 'js-process-argv', language: 'js', framework: 'node', lineageOnly: true,
    match: { type: 'member', object: 'process', prop: 'argv' }, label: 'process.argv', provenance: 'cli',
    why: 'a positional command-line argument; the value is whatever the operator typed, not attacker-controlled in the taint sense, so it is a collection point for lineage only',
  },
  {
    kind: 'source', id: 'js-multer-req-file', language: 'js', framework: 'express', lineageOnly: true,
    match: { type: 'member', object: 'req', prop: 'file' }, label: 'req.file', provenance: 'upload',
    why: 'the single uploaded file multer attaches to the request (name, type, buffer, path)',
  },
  {
    kind: 'source', id: 'js-multer-req-files', language: 'js', framework: 'express', lineageOnly: true,
    match: { type: 'member', object: 'req', prop: 'files' }, label: 'req.files', provenance: 'upload',
    why: 'the uploaded files multer attaches to the request, keyed by field name',
  },
  {
    kind: 'source', id: 'js-fs-readFileSync', language: 'js', framework: 'node', lineageOnly: true,
    match: { type: 'call', callee: 'readFileSync' }, label: 'fs.readFileSync()', provenance: 'file-read',
    why: 'the contents of a file; the callback form `fs.readFile(p, cb)` delivers its contents to a callback and is not seeded (its path argument is already a sink in the main catalog)',
  },
  {
    kind: 'source', id: 'js-window-prompt', language: 'js', framework: 'browser', lineageOnly: true,
    match: { type: 'call', callee: 'prompt', bare: true }, label: 'prompt()', provenance: 'stdin',
    why: 'text a person typed into the browser prompt dialog; only the bare global, never `x.prompt()` (inquirer and friends return a promise of an answers object)',
  },
  {
    kind: 'source', id: 'js-readline-sync-question', language: 'js', framework: 'node', lineageOnly: true,
    match: { type: 'call', callee: 'question', receiver: 'readlineSync' }, label: 'readlineSync.question()', provenance: 'stdin',
    why: 'text a person typed at the console; the readline module\'s own `rl.question(q, cb)` delivers the answer to a callback and is not seeded',
  },
]);

/** The receiver chain of a member-call callee, outermost first (`a.b.c()` -> ['a', 'b']). */
function receiverSegments(callee) {
  const segs = [];
  let cur = callee && callee.kind === 'member' ? callee.object : null;
  let depth = 0;
  while (cur && depth++ < 8) {
    if (cur.kind === 'ident') { segs.unshift(cur.name); break; }
    if (cur.kind === 'member') { if (typeof cur.prop === 'string') segs.unshift(cur.prop); cur = cur.object; continue; }
    break;
  }
  return segs;
}

function calleeName(callee) {
  if (!callee) return null;
  if (typeof callee === 'string') return callee.slice(callee.lastIndexOf('.') + 1);
  if (callee.kind === 'ident') return callee.name ?? null;
  if (callee.kind === 'member') return typeof callee.prop === 'string' ? callee.prop : null;
  return null;
}

function entryMatches(entry, expr) {
  const m = entry.match;
  if (m.type === 'member') {
    return expr.kind === 'member' && expr.object?.kind === 'ident' && expr.object.name === m.object && expr.prop === m.prop;
  }
  if (m.type === 'call') {
    if (expr.kind !== 'call') return false;
    if (calleeName(expr.callee) !== m.callee) return false;
    if (m.bare) return expr.callee && expr.callee.kind === 'ident';
    if (m.receiver) return receiverSegments(expr.callee).includes(m.receiver);
    return true;
  }
  return false;
}

/**
 * The lineage-only counterpart of `dataflow/catalog.js`'s `matchSource`:
 * returns the first catalog entry whose `match` fits `expr`, or null.
 * Gated to JavaScript and TypeScript files (an entry here is JavaScript by
 * construction); a missing `file` is permissive, matching `matchSource`.
 * Never throws on a malformed expression.
 */
export function matchLineageSource(expr, file) {
  if (!expr || typeof expr !== 'object') return null;
  if (file && !JS_FILE.test(file)) return null;
  for (const entry of LINEAGE_SOURCE_CATALOG) {
    if (entryMatches(entry, expr)) return entry;
  }
  return null;
}

/** The registry decision for every entry, computed once: proves at load time that each `provenance` resolves. */
export const LINEAGE_SOURCE_DECISIONS = Object.freeze(Object.fromEntries(
  LINEAGE_SOURCE_CATALOG.map((e) => {
    const d = reclassifySource(e);
    if (!d || !d.category || d.coverageStatus === 'unsupported') {
      throw new Error(`lineage-source-catalog: ${e.id} has a provenance (${e.provenance}) the source registry cannot classify`);
    }
    return [e.id, d];
  }),
));
