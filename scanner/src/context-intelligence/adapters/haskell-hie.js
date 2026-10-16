//
// Optional compiler-semantic metadata: a READ-ONLY importer for a Haskell declaration/reference export (`hie-export/1`).
//
// What this is and is not:
//   * It imports an export that already exists. It never runs GHC, `hiedb`, Cabal or Stack, never builds, and never
//     executes anything from the repository (no Template Haskell, no custom Setup, no plugins). A later explicit
//     metadata-build command would need a sandbox proof that does not exist in this build, so there is none.
//   * `hie-export/1` is the interchange format DCI defines for the data GHC's `-fwrite-ide-info` / `hiedb` hold
//     (declarations with exact spans, and references between them). Producing it from `.hie` files is a separate,
//     explicit, operator step documented in docs/guides/context-intelligence.md; the binary `.hie` files themselves
//     are not parsed here.
//   * The export is untrusted input. It must name the compiler and tool, and it must carry the SHA-256 of every source
//     file it describes; a file whose current hash differs makes the whole adapter DEGRADE (the static graph is kept and
//     the mismatch is reported). Paths must be repository-relative and may not escape; sizes are capped.
//   * Compiler facts are merged as additional, provenance-tagged evidence. A static edge is never silently overwritten:
//     an unresolved static call that the compiler resolves is marked superseded (and counted as closed by the compiler);
//     a static edge that DISAGREES with the compiler stays, and both are flagged as a conflict, which keeps the bundle
//     partial.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { hashOf, safeRelPath, sha256 } from '../canonical.js';

export const HIE_EXPORT_SCHEMA = 'hie-export/1';
export const HIE_EXPORT_FILE = 'hie-export.json';
const LIMITS = Object.freeze({ maxBytes: 16 * 1024 * 1024, maxDecls: 200000, maxRefs: 1000000, maxName: 300 });
const SUPPORTED_COMPILER = /^ghc$/i;

function degrade(reason, detail) { return { status: 'degraded', reason, detail: detail || null, declarations: [], references: [] }; }

/**
 * Load and validate an export. Returns { status: 'ok'|'degraded'|'off', ... }. Never throws, never reads outside the
 * repository, and treats ANY validation failure as a degradation of the adapter, not of the scan.
 */
export function loadHieMetadata(rootReal, hieDir, { fileContents }) {
  if (!hieDir) return { status: 'off', reason: 'no-directory-configured', declarations: [], references: [] };
  const dirRel = safeRelPath(hieDir);
  if (!dirRel) return degrade('unsafe-directory');
  const abs = path.join(rootReal, dirRel, HIE_EXPORT_FILE);
  let text;
  try {
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink() || !st.isFile()) return degrade('not-a-regular-file');
    if (st.size > LIMITS.maxBytes) return degrade('too-large');
    const real = fs.realpathSync(abs);
    if (real !== rootReal && !real.startsWith(rootReal + path.sep)) return degrade('escapes-root');
    text = fs.readFileSync(abs, 'utf8');
  } catch (e) {
    return degrade(e && e.code === 'ENOENT' ? 'export-not-found' : 'unreadable');
  }
  let doc;
  try { doc = JSON.parse(text); } catch { return degrade('invalid-json'); }
  if (!doc || doc.schemaVersion !== HIE_EXPORT_SCHEMA) return degrade('unsupported-schema-version', String(doc && doc.schemaVersion));
  if (!doc.compiler || !SUPPORTED_COMPILER.test(String(doc.compiler.name || '')) || typeof doc.compiler.version !== 'string') return degrade('compiler-not-identified');
  if (!doc.tool || typeof doc.tool.name !== 'string' || typeof doc.tool.version !== 'string') return degrade('tool-not-identified');
  if (!Array.isArray(doc.files) || !Array.isArray(doc.declarations) || !Array.isArray(doc.references)) return degrade('malformed');
  if (doc.declarations.length > LIMITS.maxDecls || doc.references.length > LIMITS.maxRefs) return degrade('over-size-limit');

  // source snapshot match: every file the export describes must be byte-identical to what is being analysed
  const stale = [];
  const described = new Set();
  for (const f of doc.files) {
    const rel = safeRelPath(String(f && f.path));
    if (!rel || rel !== f.path) return degrade('unsafe-path-in-export', String(f && f.path).slice(0, 80));
    described.add(rel);
    if (typeof fileContents[rel] !== 'string') { stale.push(`${rel}:missing`); continue; }
    if (sha256(fileContents[rel]) !== f.sha256) stale.push(`${rel}:hash-differs`);
  }
  if (stale.length) return degrade('source-snapshot-mismatch', stale.slice(0, 10).join(', '));

  const declarations = [];
  for (const d of doc.declarations) {
    const rel = safeRelPath(String(d && d.file));
    if (!rel || !described.has(rel) || typeof d.name !== 'string' || d.name.length > LIMITS.maxName) return degrade('malformed-declaration');
    const total = fileContents[rel].split('\n').length;
    if (![d.startLine, d.endLine].every(Number.isInteger) || d.startLine < 1 || d.endLine < d.startLine || d.endLine > total) return degrade('declaration-span-out-of-range', `${rel}:${d.name}`);
    declarations.push({ name: d.name, file: rel, startLine: d.startLine, endLine: d.endLine });
  }
  const references = [];
  for (const r of doc.references) {
    if (!r || typeof r.from !== 'string' || typeof r.to !== 'string' || r.from.length > LIMITS.maxName || r.to.length > LIMITS.maxName || !Number.isInteger(r.line)) return degrade('malformed-reference');
    references.push({ from: r.from, to: r.to, line: r.line });
  }
  declarations.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.startLine - b.startLine || (a.name < b.name ? -1 : 1));
  references.sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : 0) || a.line - b.line || (a.to < b.to ? -1 : 1));
  return { status: 'ok', tool: doc.tool, compiler: doc.compiler, declarations, references, exportHash: hashOf({ declarations, references }) };
}

function uncorroboratedReferences(graph, references, fileContents) {
  const byName = new Map();
  for (const sym of graph.symbols) {
    if (sym.kind !== 'function' || sym.id.includes('::<anon>@')) continue;
    if (!byName.has(sym.name)) byName.set(sym.name, []);
    byName.get(sym.name).push(sym);
  }
  const bad = [];
  for (const r of references) {
    const owners = byName.get(r.from) || [];
    if (owners.length !== 1) continue; // an ambiguous or unknown name is already counted as unmatched and adds nothing
    const sym = owners[0];
    const text = fileContents[sym.file];
    const callee = String(r.to).split(/[.:]/).pop();
    const lineText = typeof text === 'string' ? text.split('\n')[r.line - 1] : undefined;
    const inside = r.line >= sym.startLine && r.line <= sym.endLine;
    if (!inside || lineText === undefined || !callee || !lineText.includes(callee)) bad.push(`${r.from}->${r.to}@${r.line}`);
  }
  return bad;
}

/**
 * Merge an imported export into the static graph. Returns { graph, semantic } where `semantic` carries the provenance
 * and the static-versus-compiler difference report.
 */
export function mergeHieIntoGraph(graph, meta, fileContents) {
  if (meta.status !== 'ok') {
    return { graph, semantic: { source: ['static-ir'], status: meta.status, reason: meta.reason || null, detail: meta.detail || null, diff: null } };
  }
  // The export is untrusted even when its file hashes match: it is checked into the repository it describes. A reference
  // is accepted only if the line it names, inside the declaration it names, actually mentions the callee. One that does
  // not degrades the whole import, so a crafted export cannot add edges that the source does not contain.
  const uncorroborated = uncorroboratedReferences(graph, meta.references, fileContents || {});
  if (uncorroborated.length) {
    return { graph, semantic: { source: ['static-ir'], status: 'degraded', reason: 'reference-not-in-source', detail: uncorroborated.slice(0, 5).join(', '), diff: null } };
  }
  const idsByName = new Map();
  for (const s of graph.symbols) {
    if (s.kind !== 'function' || s.id.includes('::<anon>@')) continue;
    if (!idsByName.has(s.name)) idsByName.set(s.name, []);
    idsByName.get(s.name).push(s.id);
  }
  const edges = graph.edges.map(e => ({ ...e }));
  const diff = { newSymbols: [], newEdges: 0, resolvedUnknowns: 0, conflicts: [], remainingMaterialUnknowns: 0, unmatchedReferences: 0 };

  // declarations the static pass never saw are reported (not added: DCI has no source-hash-verified span for them
  // beyond what the export says, and an export-only symbol would be an unverified span)
  const known = new Set(graph.symbols.map(s => `${s.file}\0${s.name}`));
  for (const d of meta.declarations) if (!known.has(`${d.file}\0${d.name}`)) diff.newSymbols.push(`${d.file}::${d.name}`);

  for (const r of meta.references) {
    const from = (idsByName.get(r.from) || [])[0];
    const to = (idsByName.get(r.to) || [])[0];
    if (!from || !to || (idsByName.get(r.from) || []).length !== 1 || (idsByName.get(r.to) || []).length !== 1) { diff.unmatchedReferences++; continue; }
    const same = edges.filter(e => e.from === from && e.line === r.line);
    const agree = same.find(e => e.to === to);
    if (agree) continue; // static already has it: nothing to add
    const conflicting = same.find(e => e.to && e.to !== to && e.calleeName.split(/[.:]/).pop() === r.to.split(/[.:]/).pop());
    if (conflicting) {
      conflicting.conflict = true;
      diff.conflicts.push({ from, line: r.line, static: conflicting.to, compiler: to });
      edges.push({ from, to, line: r.line, calleeName: r.to, kind: 'call', resolver: 'compiler-enriched', conditionality: 'unknown', resolution: 'compiler', confidence: 'high', unresolvedReason: null, candidates: [], conflict: true });
      diff.newEdges++;
      continue;
    }
    const unresolved = same.find(e => !e.to && (e.calleeName.split(/[.:]/).pop() === r.to.split(/[.:]/).pop()));
    if (unresolved) { unresolved.superseded = true; diff.resolvedUnknowns++; }
    edges.push({ from, to, line: r.line, calleeName: r.to, kind: 'call', resolver: 'compiler-enriched', conditionality: unresolved ? unresolved.conditionality : 'unknown', resolution: 'compiler', confidence: 'high', unresolvedReason: null, candidates: [], conflict: false });
    diff.newEdges++;
  }
  edges.sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : 0) || (a.line - b.line) || (a.calleeName < b.calleeName ? -1 : a.calleeName > b.calleeName ? 1 : 0) || ((a.to || '') < (b.to || '') ? -1 : 1));
  diff.remainingMaterialUnknowns = edges.filter(e => !e.to && !e.superseded && e.confidence === 'low').length;
  const body = { schemaVersion: graph.schemaVersion, snapshotHash: graph.snapshotHash, symbols: graph.symbols, edges, imports: graph.imports, semantic: { exportHash: meta.exportHash, compiler: meta.compiler, tool: meta.tool } };
  return {
    graph: { ...body, hash: hashOf(body) },
    semantic: { source: ['static-ir', 'hie-import'], status: 'ok', compiler: meta.compiler, tool: meta.tool, exportHash: meta.exportHash, diff },
  };
}
