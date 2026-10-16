#!/usr/bin/env node
// Renders docs/engineering-excellence/RUNTIME_PROVENANCE_AUDIT.md from runtime-integration.json and checks that every cited entry point is real (E5-01).
//   node runtime-audit.mjs            validate and write the document
//   node runtime-audit.mjs --check    validate, and fail when the document is stale
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../..');
const JSON_FILE = path.join(REPO, 'docs/engineering-excellence/runtime-integration.json');
const DOC = path.join(REPO, 'docs/engineering-excellence/RUNTIME_PROVENANCE_AUDIT.md');

export function validate(doc) {
  const problems = [];
  const vocab = new Set(doc.identityVocabulary);
  const ids = new Set();
  for (const a of doc.areas) {
    if (ids.has(a.id)) problems.push(`duplicate area ${a.id}`); ids.add(a.id);
    for (const e of a.entryPoints) {
      const f = path.join(REPO, e.file);
      if (!fs.existsSync(f)) { problems.push(`${a.id}: ${e.file} does not exist`); continue; }
      const text = fs.readFileSync(f, 'utf8');
      for (const s of e.symbols) if (!new RegExp(`\\b${s}\\b`).test(text)) problems.push(`${a.id}: ${s} does not occur in ${e.file}`);
    }
    for (const k of [...a.carries, ...a.missing]) if (!vocab.has(k)) problems.push(`${a.id}: '${k}' is not in the identity vocabulary`);
    const both = a.carries.filter((k) => a.missing.includes(k));
    if (both.length) problems.push(`${a.id}: ${both.join(', ')} listed as both carried and missing`);
    for (const k of vocab) if (!a.carries.includes(k) && !a.missing.includes(k)) problems.push(`${a.id}: '${k}' is neither carried nor missing`);
  }
  const cids = new Set();
  for (const c of doc.conflicts) {
    if (cids.has(c.id)) problems.push(`duplicate conflict ${c.id}`); cids.add(c.id);
    if (!['resolved', 'decided'].includes(c.status)) problems.push(`${c.id}: status must be resolved or decided`);
    if (!c.resolution) problems.push(`${c.id}: no resolution`);
    if (c.status === 'decided' && !/^E\d-\d\d$/.test(c.closedBy || '')) problems.push(`${c.id}: a decided conflict names the task that implements it`);
  }
  return problems;
}

export function render(doc) {
  const L = ['# Runtime and deployment provenance: integration audit (E5-01)', '', 'Generated from `docs/engineering-excellence/runtime-integration.json` by `node scripts/engineering-excellence/runtime-audit.mjs`. Every entry point below was checked to exist. The identity columns say what each source can and cannot tie to a deployed build.', ''];
  L.push('## Identity each source carries', '', `| Source | ${doc.identityVocabulary.join(' | ')} |`, `|---|${doc.identityVocabulary.map(() => '---').join('|')}|`);
  for (const a of doc.areas) L.push(`| ${a.title} | ${doc.identityVocabulary.map((k) => (a.carries.includes(k) ? 'carries' : '-')).join(' | ')} |`);
  L.push('', 'Read the table for what is missing: no runtime source carries a commit, a build hash or an image digest, which is why an observation cannot yet be said to corroborate a finding about a particular build (E5-02).', '');
  for (const a of doc.areas) {
    L.push(`## ${a.title}`, '');
    L.push('Entry points: ' + a.entryPoints.map((e) => `\`${e.file}\` (${e.symbols.map((s) => '`' + s + '`').join(', ')})`).join('; '), '');
    L.push(`- Carries: ${a.carries.join(', ') || 'none'}. Missing: ${a.missing.join(', ') || 'none'}.`);
    L.push(`- Matching: ${a.matching}.`, `- Evidence level: ${a.evidenceLevel}.`, `- When something is not observed: ${a.notObserved}.`, `- Retention and privacy: ${a.retention}.`, '');
  }
  L.push('## Source of truth', '', '| Question | Canonical answer | Rule |', '|---|---|---|');
  for (const s of doc.sourceOfTruth) L.push(`| ${s.question} | ${s.canonical} | ${s.rule} |`);
  L.push('', '## Conflicts', '', '| Id | Status | Conflict | Resolution |', '|---|---|---|---|');
  for (const c of doc.conflicts) L.push(`| ${c.id} | ${c.status}${c.status === 'resolved' ? ` in ${c.resolvedIn}` : ` (implemented by ${c.closedBy})`} | ${c.summary} | ${c.resolution} |`);
  L.push('', '## Not determined', '', ...doc.unknowns.map((u) => `- ${u}`), '');
  return L.join('\n');
}

function main() {
  const doc = JSON.parse(fs.readFileSync(JSON_FILE, 'utf8'));
  const problems = validate(doc);
  if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
  const text = render(doc);
  if (process.argv.includes('--check')) { if (fs.readFileSync(DOC, 'utf8') !== text) { console.error('RUNTIME_PROVENANCE_AUDIT.md is stale'); process.exit(1); } console.log('runtime audit matches'); return; }
  fs.writeFileSync(DOC, text);
  console.log(`wrote audit: ${doc.areas.length} sources, ${doc.conflicts.length} conflicts (${doc.conflicts.filter((c) => c.status === 'resolved').length} resolved here, ${doc.conflicts.filter((c) => c.status === 'decided').length} decided)`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
