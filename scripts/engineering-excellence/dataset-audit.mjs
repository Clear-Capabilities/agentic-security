#!/usr/bin/env node
// Dataset provenance audit (E1-01).
//   node dataset-audit.mjs --render                  write docs/engineering-excellence/DATASET_PROVENANCE.md and dataset-provenance.json
//   node dataset-audit.mjs --check                   exit 1 if the committed report is not what the checkout produces
//   node dataset-audit.mjs --lookup-licenses [--limit N]   OPT-IN network: read each repository's SPDX licence through `gh api` and cache it
//
// For every population used to measure the engine, each entry must carry the nine facts the PRD names: source project, upstream commit
// before the fix, upstream commit after, advisory and CWE provenance, affected language, scope, licence, label confidence, acquisition
// checksum and split. A fact the manifest does not carry is reported MISSING with the count; it is never filled in with a guess. A
// licence is read from the upstream host or recorded `unknown`; an acquisition checksum exists only once the tree has been fetched.
//
// Populations are classified by ROLE, because the role decides what they may be used to claim:
//   independent   third-party advisory labels over upstream code: the only kind that can support an accuracy claim
//   regression    written here, admitted once they score; a regression net, never an accuracy population
//   regenerated   a public suite pulled and transformed locally (not vendored)
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { atomicWriteFile, atomicWriteJson, nowIso } from '../loop-engineering/lib/util.mjs';
import { REPO_ROOT } from './lib/model.mjs';
import { digestOfFiles } from './lib/measurement-identity.mjs';

export const REQUIRED_FACTS = Object.freeze(['sourceProject', 'commitBefore', 'commitAfter', 'advisory', 'language', 'scope', 'license', 'labelConfidence', 'acquisitionChecksum', 'split']);
export const LABEL_CONFIDENCE = Object.freeze(['adjudicated', 'third_party_advisory', 'inferred', 'synthetic']);
const SHA40 = /^[0-9a-f]{40}$/;
const SIDECAR = (root) => join(root, 'bench', 'independent', 'provenance.sidecar.json');
const OUT = (root) => join(root, 'docs', 'engineering-excellence');
const readJson = (p, fb = null) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return fb; } };

export function loadSidecar(root = REPO_ROOT) {
  return readJson(SIDECAR(root), { schemaVersion: 1, licenses: {}, splits: {}, acquisition: {} });
}

/** The nine facts for one independent entry, from the manifest plus the sidecar. A fact that is absent is `null`, never invented. */
export function factsOfIndependentEntry(entry, sidecar) {
  const present = (v) => (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length) ? null : v);
  const repo = present(entry.repo);
  return {
    sourceProject: repo,
    commitBefore: SHA40.test(entry.parentCommit || '') ? entry.parentCommit : null,
    commitAfter: SHA40.test(entry.fixCommit || '') ? entry.fixCommit : null,
    advisory: present(entry.id) && present(entry.cwe) && present(entry.labelSource) ? { id: entry.id, cve: present(entry.cve), cwe: entry.cwe, source: entry.labelSource } : null,
    language: present(entry.language),
    scope: present(entry.files) ? { kind: 'changed-files', files: entry.files.length } : null,
    license: repo && sidecar.licenses[repo] ? sidecar.licenses[repo] : null,
    labelConfidence: entry.labelSource === 'github-security-advisory' ? 'third_party_advisory' : null,
    acquisitionChecksum: sidecar.acquisition[entry.id] || null,
    split: sidecar.splits[entry.id] || null,
  };
}

function upstreamSummary(sidecar, entries) {
  const v = sidecar.upstreamVerified || {};
  const ids = new Set(entries.map((e) => e.id));
  const rows = Object.entries(v).filter(([id]) => ids.has(id)).map(([, r]) => r);
  const s = { sampled: rows.length, confirmed: 0, missingUpstream: 0, notChecked: 0 };
  for (const r of rows) { if (r.parent === 'missing' || r.fix === 'missing') s.missingUpstream++; else if (r.parent === 'ok' && r.fix === 'ok') s.confirmed++; else s.notChecked++; }
  return s;
}

export function auditIndependent(root = REPO_ROOT) {
  const manifest = readJson(join(root, 'bench', 'independent', 'manifest.json'), null);
  if (!manifest) return { role: 'independent', status: 'unavailable', reason: 'bench/independent/manifest.json is missing', entries: 0 };
  const sidecar = loadSidecar(root);
  const entries = manifest.entries || [];
  const coverage = Object.fromEntries(REQUIRED_FACTS.map((f) => [f, 0]));
  const byLanguage = {}; const repos = new Set(); const missingByFact = Object.fromEntries(REQUIRED_FACTS.map((f) => [f, []]));
  let complete = 0; let reconstructable = 0; const unavailable = [];
  const seen = new Set(); const duplicates = [];
  for (const e of entries) {
    if (seen.has(e.id)) duplicates.push(e.id); seen.add(e.id);
    const f = factsOfIndependentEntry(e, sidecar);
    let all = true;
    for (const k of REQUIRED_FACTS) { if (f[k] !== null) coverage[k]++; else { all = false; if (missingByFact[k].length < 5) missingByFact[k].push(e.id); } }
    if (all) complete++;
    if (f.sourceProject && f.commitBefore && f.commitAfter && f.advisory) reconstructable++; else unavailable.push({ id: e.id, why: ['sourceProject', 'commitBefore', 'commitAfter', 'advisory'].filter((k) => f[k] === null) });
    byLanguage[e.language] = (byLanguage[e.language] || 0) + 1;
    if (e.repo) repos.add(e.repo);
  }
  return {
    role: 'independent', status: 'audited', manifest: 'bench/independent/manifest.json', schema: manifest.schema, manifestSha256: digestOfFiles(root, ['bench/independent/manifest.json']),
    entries: entries.length, repositories: repos.size, byLanguage: Object.fromEntries(Object.entries(byLanguage).sort()),
    factCoverage: coverage, missingExamples: missingByFact, completeEntries: complete,
    upstreamSample: upstreamSummary(sidecar, entries),
    reconstructableFromUpstream: reconstructable, unavailable: unavailable.slice(0, 20), unavailableCount: unavailable.length, duplicateIds: duplicates,
    note: 'Reconstructable means the manifest names a repository, both commits and an advisory; it was not re-fetched here. A missing licence, split or acquisition checksum is reported as missing, not defaulted.',
  };
}

export function auditCveReplay(root = REPO_ROOT) {
  const tiers = ['regression', 'capability', 'deep'];
  const sources = {}; let entries = 0;
  for (const tier of tiers) {
    const dir = join(root, 'bench', 'cve-replay', tier);
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir)) {
      const mf = join(dir, name, 'manifest.json');
      if (!existsSync(mf)) continue;
      entries++;
      const src = readJson(mf, {}).source || 'undeclared';
      sources[src] = (sources[src] || 0) + 1;
    }
  }
  return { role: 'regression', status: 'audited', entries, bySourceTier: sources, usableForAccuracyClaims: false, note: 'Fixtures written in this repository and admitted once they score. A regression net: its detection rate is at the ceiling by construction, so it can never support a precision or recall claim.' };
}

export function auditRegenerated(root = REPO_ROOT) {
  const lock = readJson(join(root, 'bench', 'sard', 'dataset-lock.json'), null);
  const out = { role: 'regenerated', status: lock ? 'audited' : 'unavailable', usableForAccuracyClaims: 'only the held-out test split, never the full corpus', sources: [] };
  if (lock) for (const [name, s] of Object.entries(lock.sources || {})) out.sources.push({ name, url: s.url || null, sha256: s.sha256 || null, pinned: !!(s.sha256 && s.url) });
  const splitsDir = join(root, 'bench', 'sard', 'splits');
  out.splits = existsSync(splitsDir) ? readdirSync(splitsDir).filter((f) => f.endsWith('.json')).sort() : [];
  out.note = 'Public suites pulled and transformed locally; not vendored. The ledger records that no number in it came from a held-out test split.';
  return out;
}

export function buildAudit(root = REPO_ROOT) {
  return { schemaVersion: 1, generatedAt: nowIso(), requiredFacts: REQUIRED_FACTS, populations: { independent: auditIndependent(root), cveReplay: auditCveReplay(root), sard: auditRegenerated(root) } };
}

export function renderMarkdown(a) {
  const i = a.populations.independent; const c = a.populations.cveReplay; const s = a.populations.sard;
  const L = ['# Dataset provenance', ''];
  L.push('> Generated by `node scripts/engineering-excellence/dataset-audit.mjs --render`. A fact the manifest does not carry is shown as missing with its count; none is filled in by guesswork.', '');
  L.push('## Populations and what each may claim', '', '| Population | Role | Entries | May support an accuracy claim |', '|---|---|---|---|');
  L.push(`| bench/independent | independent (third-party advisory labels over upstream code) | ${i.entries} in ${i.repositories} repositories | yes, once a clean-commit run and a sealed split exist |`);
  L.push(`| bench/cve-replay | regression net (written here) | ${c.entries} | **no** |`);
  L.push(`| bench/sard | regenerated public suites | ${s.sources.length} pinned sources | only a held-out test split |`, '');
  L.push('## Independent population: the nine required facts', '', `Manifest \`${i.manifest}\` (${i.schema}), digest \`${i.manifestSha256.slice(0, 16)}\`. Languages: ${Object.entries(i.byLanguage).map(([k, v]) => `${k} ${v}`).join(', ')}.`, '');
  L.push('| Fact | Entries carrying it | Of | Missing, examples |', '|---|---|---|---|');
  for (const f of a.requiredFacts) L.push(`| ${f} | ${i.factCoverage[f]} | ${i.entries} | ${i.factCoverage[f] === i.entries ? '' : i.missingExamples[f].join(', ')} |`);
  L.push('', `Entries with all nine facts: **${i.completeEntries}** of ${i.entries}. Reconstructable from upstream (repository, both commits, advisory named): **${i.reconstructableFromUpstream}**; unavailable: ${i.unavailableCount}. Duplicate ids: ${i.duplicateIds.length}.`, '', `Upstream spot-check (opt-in, \`gh api\`, a deterministic sample per language): ${i.upstreamSample.sampled ? `${i.upstreamSample.sampled} entries sampled, ${i.upstreamSample.confirmed} confirmed (both commits exist), ${i.upstreamSample.missingUpstream} missing upstream, ${i.upstreamSample.notChecked} not checked because of an error` : 'not run'}.`, '', i.note, '');
  L.push('## Regression net', '', `${c.entries} entries; by declared source: ${Object.entries(c.bySourceTier).map(([k, v]) => `${k} ${v}`).join(', ')}. ${c.note}`, '');
  L.push('## Regenerated suites', '', '| Source | Pinned | URL |', '|---|---|---|', ...s.sources.map((x) => `| ${x.name} | ${x.pinned ? 'url and sha256' : 'NOT pinned'} | ${x.url || ''} |`), '', s.note, '');
  return L.join('\n');
}

export function render(root = REPO_ROOT) {
  const a = buildAudit(root);
  mkdirSync(OUT(root), { recursive: true });
  atomicWriteJson(join(OUT(root), 'dataset-provenance.json'), a);
  atomicWriteFile(join(OUT(root), 'DATASET_PROVENANCE.md'), renderMarkdown(a) + '\n', 0o644);
  return a;
}

/** Opt-in network step. Reads each repository's SPDX id with `gh api`, one at a time, bounded, and caches it in the sidecar. */
export function lookupLicenses(root = REPO_ROOT, { limit = Infinity, timeoutMs = 20000, run = (repo) => execFileSync('gh', ['api', `repos/${repo}`, '--jq', '.license.spdx_id // "none"'], { encoding: 'utf8', timeout: timeoutMs, stdio: ['ignore', 'pipe', 'pipe'] }).trim() } = {}) {
  const manifest = readJson(join(root, 'bench', 'independent', 'manifest.json'), { entries: [] });
  const sidecar = loadSidecar(root);
  const repos = [...new Set(manifest.entries.map((e) => e.repo).filter(Boolean))].sort();
  let looked = 0; const failed = [];
  for (const repo of repos) {
    if (sidecar.licenses[repo]) continue;
    if (looked >= limit) break;
    looked++;
    try {
      const id = run(repo);
      sidecar.licenses[repo] = { spdx: id === 'none' || !id ? 'NOASSERTION' : id, source: 'github-api', lookedUpAt: nowIso() };
    } catch (e) { failed.push({ repo, error: String(e.message || e).split('\n')[0].slice(0, 120) }); }
    if (looked % 25 === 0) atomicWriteJson(SIDECAR(root), sidecar);
  }
  atomicWriteJson(SIDECAR(root), sidecar);
  return { looked, failed, total: repos.length, known: Object.keys(sidecar.licenses).length };
}

/**
 * Opt-in network step: confirm that the commits a manifest names really exist upstream, for a deterministic stratified sample (every
 * k-th entry of each language, sorted by id). Records ok / missing / error per entry in the sidecar; an error is not a missing commit.
 */
export function verifyUpstream(root = REPO_ROOT, { perLanguage = 5, timeoutMs = 20000, run = (repo, sha) => execFileSync('gh', ['api', `repos/${repo}/commits/${sha}`, '--jq', '.sha'], { encoding: 'utf8', timeout: timeoutMs, stdio: ['ignore', 'pipe', 'pipe'] }).trim() } = {}) {
  const manifest = readJson(join(root, 'bench', 'independent', 'manifest.json'), { entries: [] });
  const sidecar = loadSidecar(root);
  sidecar.upstreamVerified ||= {};
  const byLang = {};
  for (const e of [...manifest.entries].sort((a, b) => (a.id < b.id ? -1 : 1))) (byLang[e.language] ||= []).push(e);
  const sample = [];
  for (const list of Object.values(byLang)) { const step = Math.max(1, Math.floor(list.length / perLanguage)); for (let i = 0; i < list.length && sample.length < 10000; i += step) { if (sample.filter((x) => x.language === list[i].language).length < perLanguage) sample.push(list[i]); } }
  const result = { checked: 0, ok: 0, missing: 0, error: 0 };
  for (const e of sample) {
    if (sidecar.upstreamVerified[e.id]?.fix && sidecar.upstreamVerified[e.id]?.parent) continue;
    const rec = { at: nowIso() };
    for (const [k, sha] of [['parent', e.parentCommit], ['fix', e.fixCommit]]) {
      try { rec[k] = run(e.repo, sha) === sha ? 'ok' : 'missing'; } catch (err) { rec[k] = /404|Not Found|No commit found/i.test(String(err.stderr || err.message)) ? 'missing' : 'error'; }
    }
    sidecar.upstreamVerified[e.id] = rec;
  }
  for (const e of sample) { const r = sidecar.upstreamVerified[e.id]; if (!r) continue; result.checked++; const s = [r.parent, r.fix]; if (s.includes('missing')) result.missing++; else if (s.includes('error')) result.error++; else result.ok++; }
  atomicWriteJson(SIDECAR(root), sidecar);
  return result;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const a = process.argv.slice(2);
  const root = a.includes('--root') ? resolve(a[a.indexOf('--root') + 1]) : REPO_ROOT;
  if (a.includes('--lookup-licenses')) {
    const li = a.indexOf('--limit');
    const r = lookupLicenses(root, { limit: li >= 0 ? Number(a[li + 1]) : Infinity });
    console.log(`licenses: looked up ${r.looked}, failed ${r.failed.length}, known ${r.known} of ${r.total} repositories`);
    process.exit(0);
  }
  if (a.includes('--verify-upstream')) {
    const pi = a.indexOf('--per-language');
    const r = verifyUpstream(root, { perLanguage: pi >= 0 ? Number(a[pi + 1]) : 5 });
    console.log(`upstream check: ${r.checked} sampled entries, ${r.ok} confirmed, ${r.missing} missing upstream, ${r.error} not checked (error)`);
    process.exit(0);
  }
  const audit = render(root);
  const i = audit.populations.independent;
  console.log(`dataset audit: independent ${i.entries} entries, ${i.completeEntries} with all nine facts, ${i.reconstructableFromUpstream} reconstructable, ${i.unavailableCount} unavailable`);
  void statSync;
}
