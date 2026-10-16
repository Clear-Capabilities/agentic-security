#!/usr/bin/env node
// Prioritised root-cause backlog (E0-06).
//   node backlog.mjs --render   write docs/engineering-excellence/PRIORITY_BACKLOG.md and backlog.json
//   node backlog.mjs --check    verify every item has an upstream source and an owner task; exit 1 otherwise
//
// Score = independent examples affected x exploit impact x confidence / effort.
//   examples   counted from the repository's own root-cause record of independent misses (docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md),
//              or 0 when the item has no independent example (it is then ranked on a floor of 1 and labelled so)
//   impact     1 to 5 from the CWE class table below: fixed here so the ranking cannot be tuned item by item
//   confidence 0.9 when a reproducer (a named failing entry or test) exists, 0.6 when the cause is established from a trace, 0.3 for a hypothesis
//   effort     S=1, M=3, L=8, as declared on the item with its reason
// Nothing here is a measurement of the current engine: the example counts come from an archived run of an older engine and say where
// to look first, not how accurate anything is today.
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { atomicWriteFile, atomicWriteJson, nowIso } from '../loop-engineering/lib/util.mjs';
import { REPO_ROOT } from './lib/model.mjs';

const DATA = (root) => join(root, 'scripts', 'engineering-excellence', 'data', 'backlog.items.json');
const OUT = (root) => join(root, 'docs', 'engineering-excellence');

// Exploit impact by weakness class. One table, applied to every item through its `cwes`; the highest class listed wins.
export const IMPACT = Object.freeze({
  'CWE-89': 5, 'CWE-78': 5, 'CWE-94': 5, 'CWE-95': 5, 'CWE-88': 5, 'CWE-502': 5, 'CWE-918': 4, 'CWE-22': 4, 'CWE-23': 4, 'CWE-59': 4, 'CWE-61': 4, 'CWE-73': 4,
  'CWE-639': 5, 'CWE-862': 5, 'CWE-863': 5, 'CWE-284': 4, 'CWE-285': 4, 'CWE-434': 4, 'CWE-346': 3, 'CWE-384': 4, 'CWE-79': 3, 'CWE-200': 3, 'CWE-204': 2,
  'CWE-20': 3, 'CWE-436': 3, 'CWE-444': 3, 'CWE-668': 3, 'CWE-1321': 3, 'CWE-367': 3, 'CWE-400': 2, 'CWE-407': 2, 'CWE-834': 2, 'CWE-1333': 2, 'CWE-184': 2, 'CWE-488': 3,
});
export const CONFIDENCE = Object.freeze({ reproducer: 0.9, trace: 0.6, hypothesis: 0.3 });
export const EFFORT = Object.freeze({ S: 1, M: 3, L: 8 });

/** The independent misses recorded in the root-cause document: [{ id, language, cwe, category, subcategory, fixStatus }]. */
export function parseRootCause(markdown) {
  const out = [];
  for (const line of String(markdown).split('\n')) {
    if (!line.startsWith('| GHSA-')) continue;
    const p = line.trim().replace(/^\||\|$/g, '').split('|').map((x) => x.trim());
    out.push({ id: p[0], language: p[1], cwe: p[2], category: p[3], subcategory: p[4], fixStatus: p[5], evidence: p.slice(6).join('|') });
  }
  return out;
}

export function loadItems(root = REPO_ROOT) {
  return JSON.parse(readFileSync(DATA(root), 'utf8'));
}

/** Resolve entry-id prefixes ("GHSA-2364") to the full ids in the record. Returns { ids, unresolved }. */
export function resolvePrefixes(prefixes, misses) {
  const ids = []; const unresolved = [];
  for (const pre of prefixes || []) {
    const hit = misses.filter((m) => m.id === pre || m.id.startsWith(`${pre}-`));
    if (hit.length === 1) ids.push(hit[0].id); else unresolved.push(`${pre} (${hit.length} matches)`);
  }
  return { ids, unresolved };
}

export function scoreItem(item, misses) {
  const wanted = new Set(item.cwes || []);
  let matching = [];
  if (item.evidenceRegex) matching = misses.filter((m) => new RegExp(item.evidenceRegex, 'i').test(m.evidence));
  else matching = misses.filter((m) => wanted.has(m.cwe) && (!item.categories || item.categories.includes(m.subcategory || m.category)));
  const examples = item.examplesOverride ?? matching.length;
  const impact = Math.max(1, ...(item.cwes || []).map((c) => IMPACT[c] || 1), item.impact || 1);
  const confidence = CONFIDENCE[item.evidenceKind];
  const effortWeight = EFFORT[item.effort];
  const effective = Math.max(examples, 1);
  const named = resolvePrefixes(item.reproducerPrefixes, misses);
  return { examples, reproducerIds: named.ids.length ? named.ids : matching.map((m) => m.id).slice(0, 8), unresolvedReproducers: named.unresolved, impact, confidence, effortWeight, score: Math.round(((effective * impact * confidence) / effortWeight) * 100) / 100 };
}

export function build(root = REPO_ROOT) {
  const doc = loadItems(root);
  const rcPath = join(root, 'docs', 'INDEPENDENT_POPULATION_ROOT_CAUSE.md');
  const misses = existsSync(rcPath) ? parseRootCause(readFileSync(rcPath, 'utf8')) : [];
  const tasks = JSON.parse(readFileSync(join(root, 'scripts', 'engineering-excellence', 'tasks.json'), 'utf8')).tasks;
  const taskIds = new Set(tasks.map((t) => t.id));
  const items = doc.items.map((it) => {
    const s = scoreItem(it, misses);
    const problems = [];
    if (!it.sources?.length) problems.push('no upstream source');
    for (const src of it.sources || []) if (!existsSync(join(root, src.split('#')[0]))) problems.push(`source does not exist: ${src}`);
    if (!it.ownerTask || !taskIds.has(it.ownerTask)) problems.push(`owner task ${it.ownerTask} is not in the manifest`);
    if (!(it.evidenceKind in CONFIDENCE)) problems.push(`evidenceKind ${it.evidenceKind} is not one of ${Object.keys(CONFIDENCE).join(', ')}`);
    if (!(it.effort in EFFORT)) problems.push(`effort ${it.effort} is not S, M or L`);
    if (it.evidenceKind === 'reproducer' && !(it.reproducer || s.reproducerIds.length)) problems.push('a reproducer item names no reproducer');
    for (const u of s.unresolvedReproducers) problems.push(`reproducer entry not found in the root-cause record: ${u}`);
    if (it.evidenceKind === 'hypothesis' && !it.hypothesis) problems.push('a hypothesis item states no hypothesis');
    if (it.evidenceKind === 'trace' && !it.trace) problems.push('a trace item states no trace');
    return { ...it, ...s, problems };
  }).sort((a, b) => b.score - a.score || (a.id < b.id ? -1 : 1));
  const byLang = {};
  for (const m of misses) byLang[m.language] = (byLang[m.language] || 0) + 1;
  const byCat = {};
  for (const m of misses) { const k = `${m.category}${m.subcategory ? `/${m.subcategory}` : ''}`; byCat[k] = (byCat[k] || 0) + 1; }
  return { schemaVersion: 1, generatedAt: nowIso(), independentMisses: { count: misses.length, byLanguage: byLang, byCategory: byCat, source: 'docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md', engineVersion: '0.137.1 (archived; not the current engine)' }, formula: 'examples x impact x confidence / effort', items };
}

export function renderMarkdown(b) {
  const L = [];
  L.push('# Priority backlog', '');
  L.push('> Generated by `node scripts/engineering-excellence/backlog.mjs --render` from `scripts/engineering-excellence/data/backlog.items.json` and the repository\'s root-cause record. Score = independent examples affected x exploit impact x confidence / effort. The example counts come from an archived run of an older engine; they say where to look first, not how accurate anything is today.', '');
  L.push(`Independent misses on record: **${b.independentMisses.count}** (${Object.entries(b.independentMisses.byLanguage).map(([k, v]) => `${k} ${v}`).join(', ')}). Categories: ${Object.entries(b.independentMisses.byCategory).map(([k, v]) => `${k} ${v}`).join('; ')}.`, '');
  L.push('| # | Item | Score | Examples | Impact | Confidence | Effort | Evidence | Owner task |', '|---|---|---|---|---|---|---|---|---|');
  b.items.forEach((it, i) => L.push(`| ${i + 1} | ${it.title} | ${it.score} | ${it.examples} | ${it.impact} | ${it.confidence} | ${it.effort} (${it.effortWeight}) | ${it.evidenceKind} | ${it.ownerTask} |`));
  L.push('');
  for (const [i, it] of b.items.entries()) {
    L.push(`## ${i + 1}. ${it.title}`, '');
    L.push(it.summary, '');
    L.push(`- Owner task: \`${it.ownerTask}\`; effort ${it.effort}: ${it.effortReason}`);
    L.push(`- Evidence (${it.evidenceKind}): ${it.evidenceKind === 'hypothesis' ? it.hypothesis : [it.trace, it.reproducer, it.reproducerIds.length ? `independent entries ${it.reproducerIds.join(', ')}` : null].filter(Boolean).join('; ')}`);
    L.push(`- Sources: ${it.sources.map((s) => `\`${s}\``).join(', ')}`);
    if (it.problems.length) L.push(`- **Problems:** ${it.problems.join('; ')}`);
    L.push('');
  }
  return L.join('\n');
}

export function render(root = REPO_ROOT) {
  const b = build(root);
  mkdirSync(OUT(root), { recursive: true });
  atomicWriteJson(join(OUT(root), 'backlog.json'), b);
  atomicWriteFile(join(OUT(root), 'PRIORITY_BACKLOG.md'), renderMarkdown(b) + '\n', 0o644);
  return b;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const a = process.argv.slice(2);
  const root = a.includes('--root') ? resolve(a[a.indexOf('--root') + 1]) : REPO_ROOT;
  try {
    const b = a.includes('--render') ? render(root) : build(root);
    const bad = b.items.filter((i) => i.problems.length);
    for (const i of bad) console.error(`${i.id}: ${i.problems.join('; ')}`);
    console.log(`backlog: ${b.items.length} items, ${b.independentMisses.count} independent misses on record, ${bad.length} item(s) with problems`);
    process.exit(bad.length ? 1 : 0);
  } catch (e) { console.error(`backlog failed: ${e.message}`); process.exit(2); }
}
