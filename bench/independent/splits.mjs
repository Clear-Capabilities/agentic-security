#!/usr/bin/env node
// Frozen, leakage-safe splits for the independent population (E1-02).
//   node bench/independent/splits.mjs --build     write bench/independent/splits.json from the manifest (refuses to overwrite a frozen file)
//   node bench/independent/splits.mjs --extend    add entries new to the manifest without moving any recorded entry
//   node bench/independent/splits.mjs --verify    recompute and compare; exit 1 on any difference or any group that straddles two splits
//   node bench/independent/splits.mjs --legacy    measure the leakage of the older per-id held-out slice (runner.mjs isHeldOut)
//
// WHY THE OLDER SLICE IS NOT ENOUGH. `isHeldOut(id)` in runner.mjs hashes the ENTRY id, so advisories of one repository land on both sides.
// Measured on the 1004-entry manifest at the time this file was written: 91 repositories straddle it, and 533 entries sit in such a
// repository (Flowise alone has 5 held-out and 20 development entries). Detector work tuned on the development entries of a project
// leaks straight into its held-out entries. That slice is therefore DEMOTED to development use and never quoted as held-out.
//
// THE NEW SPLIT. Entries are grouped with the same transitive relation the evaluation protocol uses (same upstream project, same advisory
// or CVE id, same commit), and each WHOLE group is assigned to development (60%), validation (20%) or sealed (20%) by a salted hash of
// the group's anchor. The assignment is written down and hashed; later runs read the file and never recompute it, so a growing manifest
// cannot move an entry. A time dimension is not applied: the manifest carries no advisory publication date (only the time the entry was
// mined), and a split on mining time would say nothing about code. That limit is recorded in the file.
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { groupTargets, normalizeUpstream } from '../../scanner/src/posture/evaluation/grouping.js';
import { digestOf } from '../../scanner/src/posture/assurance/identity.js';
import { atomicWriteJson } from '../../scripts/loop-engineering/lib/util.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const SPLITS_FILE = join(HERE, 'splits.json');
export const MANIFEST_FILE = join(HERE, 'manifest.json');
export const SEALED_LEDGER = join(HERE, 'sealed-ledger.jsonl');
export const SPLIT_NAMES = Object.freeze(['dev', 'validation', 'sealed']);
export const ALGORITHM = 'grouped-hash-3way/1';
export const DEFAULT_FRACTIONS = Object.freeze({ dev: 0.6, validation: 0.2, sealed: 0.2 });
export const DEFAULT_SALT = 'agentic-security/independent-population/splits/v1';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

export function targetsOf(entries) {
  return entries.map((e) => ({ id: e.id, upstream: e.repo, advisoryIds: [e.id, e.cve].filter(Boolean), preCommit: e.parentCommit, postCommit: e.fixCommit }));
}

/** The group's anchor: the normalised upstream project when every member shares one, otherwise the smallest member id. */
function anchorOf(group, upstreamOf) {
  const ups = new Set(group.members.map((m) => upstreamOf.get(m)).filter(Boolean));
  return ups.size === 1 ? [...ups][0] : group.members[0];
}

function sideOf(anchor, salt, fractions) {
  const u = createHash('sha256').update(`${salt}|${anchor}`).digest().readUInt32BE(0) / 0x100000000;
  if (u < fractions.sealed) return 'sealed';
  if (u < fractions.sealed + fractions.validation) return 'validation';
  return 'dev';
}

export function assign(entries, { salt = DEFAULT_SALT, fractions = DEFAULT_FRACTIONS, frozen = null } = {}) {
  const targets = targetsOf(entries);
  const upstreamOf = new Map(targets.map((t) => [t.id, normalizeUpstream(t.upstream)]));
  const { groups } = groupTargets(targets);
  const assignment = {}; const quarantined = [];
  for (const g of groups) {
    const known = new Set(g.members.map((m) => frozen?.assignment?.[m]).filter(Boolean));
    let side;
    if (known.size > 1) { for (const m of g.members) if (!frozen.assignment[m]) quarantined.push({ id: m, reason: `joins recorded entries that are in different splits (${[...known].join(', ')})` }); }
    if (known.size === 1) side = [...known][0];
    else if (known.size === 0) side = sideOf(anchorOf(g, upstreamOf), salt, fractions);
    for (const m of g.members) {
      if (frozen?.assignment?.[m]) assignment[m] = frozen.assignment[m];
      else if (side) assignment[m] = side;
    }
  }
  return { assignment, groups, quarantined };
}

export function countsOf(assignment) {
  const c = Object.fromEntries(SPLIT_NAMES.map((s) => [s, 0]));
  for (const s of Object.values(assignment)) c[s]++;
  return c;
}

export function protocolHashOf({ algorithm, salt, fractions, manifestSha256, assignment }) {
  return digestOf({ algorithm, salt, fractions, manifestSha256, assignment: digestOf(assignment) });
}

export function buildSplits(manifestText, { salt = DEFAULT_SALT, fractions = DEFAULT_FRACTIONS, frozen = null } = {}) {
  const manifest = JSON.parse(manifestText);
  const manifestSha256 = sha256(manifestText);
  const { assignment, groups, quarantined } = assign(manifest.entries, { salt, fractions, frozen });
  const counts = countsOf(assignment);
  return {
    schema: 'agentic-security/independent-splits@1', algorithm: ALGORITHM, salt, fractions,
    manifestSha256, entries: manifest.entries.length, groups: groups.length, counts, quarantined,
    languageSplitCounts: languageCounts(manifest.entries, assignment),
    limits: ['No time split: the manifest has no advisory publication date, only the time each entry was mined.', 'Groups are formed from upstream project, advisory or CVE id and commit identity; a fork that this manifest does not name as a fork is not linked.'],
    protocolHash: protocolHashOf({ algorithm: ALGORITHM, salt, fractions, manifestSha256, assignment }),
    assignment: Object.fromEntries(Object.entries(assignment).sort(([a], [b]) => (a < b ? -1 : 1))),
  };
}

function languageCounts(entries, assignment) {
  const out = {};
  for (const e of entries) { const s = assignment[e.id]; if (!s) continue; ((out[e.language] ||= Object.fromEntries(SPLIT_NAMES.map((n) => [n, 0])))[s])++; }
  return Object.fromEntries(Object.entries(out).sort());
}

/** Groups whose members span more than one split. Empty means the split is leakage-safe. */
export function straddlingGroups(entries, assignment) {
  const { groups } = groupTargets(targetsOf(entries));
  return groups.filter((g) => new Set(g.members.map((m) => assignment[m]).filter(Boolean)).size > 1);
}

/** Repository-level leakage of an arbitrary per-entry membership function (used on the older per-id slice). */
export function repositoryLeakage(entries, sideFn) {
  const by = {};
  for (const e of entries) { const r = (by[e.repo] ||= new Set()); r.add(sideFn(e)); }
  const straddling = Object.entries(by).filter(([, s]) => s.size > 1).map(([r]) => r).sort();
  const inStraddling = entries.filter((e) => straddling.includes(e.repo)).length;
  return { repositories: Object.keys(by).length, straddlingRepositories: straddling.length, entriesInStraddlingRepositories: inStraddling, examples: straddling.slice(0, 5) };
}

export function loadSplits(file = SPLITS_FILE) { return existsSync(file) ? readJson(file) : null; }

/** Recompute and compare. Returns a list of problems; empty means the file is exactly what the manifest and its recorded assignment imply. */
export function verifySplits(manifestText, splits) {
  const problems = [];
  if (!splits) return ['splits.json does not exist'];
  const manifest = JSON.parse(manifestText);
  const ids = new Set(manifest.entries.map((e) => e.id));
  for (const id of Object.keys(splits.assignment)) if (!ids.has(id)) problems.push(`splits.json assigns ${id}, which is not in the manifest`);
  const unassigned = manifest.entries.filter((e) => !splits.assignment[e.id]).map((e) => e.id);
  if (unassigned.length) problems.push(`${unassigned.length} manifest entries have no split (run --extend): ${unassigned.slice(0, 3).join(', ')}`);
  if (splits.manifestSha256 === sha256(manifestText)) {
    const fresh = buildSplits(manifestText, { salt: splits.salt, fractions: splits.fractions });
    if (JSON.stringify(fresh.assignment) !== JSON.stringify(splits.assignment)) problems.push('the recorded assignment differs from a fresh computation');
  }
  const expected = protocolHashOf({ algorithm: splits.algorithm, salt: splits.salt, fractions: splits.fractions, manifestSha256: splits.manifestSha256, assignment: splits.assignment });
  if (expected !== splits.protocolHash) problems.push('the protocol hash does not match the recorded assignment (the file was edited)');
  const straddle = straddlingGroups(manifest.entries.filter((e) => splits.assignment[e.id]), splits.assignment);
  if (straddle.length) problems.push(`${straddle.length} group(s) span more than one split, e.g. ${straddle[0].members.slice(0, 3).join(', ')}`);
  return problems;
}

// ---- sealed access ledger ----------------------------------------------------------------------------------------------------

/** Every scoring pass over the sealed split is appended here. The ledger is local evidence; the release check compares it with the claims made. */
export function recordSealedAccess({ protocolHash, runId, reason, engineVersion = null, ledger = SEALED_LEDGER }) {
  if (!reason || String(reason).length < 10) throw new Error('a sealed access needs a stated reason');
  mkdirSync(dirname(ledger), { recursive: true });
  appendFileSync(ledger, `${JSON.stringify({ at: new Date().toISOString(), protocolHash, runId, reason: String(reason).slice(0, 300), engineVersion })}\n`, { mode: 0o600 });
}

export function sealedAccessCount(ledger = SEALED_LEDGER) {
  if (!existsSync(ledger)) return 0;
  return readFileSync(ledger, 'utf8').split('\n').filter(Boolean).length;
}

/** Which entries a run may score. Sealed entries need an explicit, recorded `final` declaration. */
export function selectEntries(entries, splits, wanted, { final = false, runId = null, reason = null, ledger = SEALED_LEDGER } = {}) {
  if (!splits) throw new Error('splits.json is required to select a split');
  if (!SPLIT_NAMES.includes(wanted)) throw new Error(`unknown split ${wanted}`);
  if (wanted === 'sealed') {
    if (!final) throw new Error('the sealed split may only be scored by a run declared final');
    recordSealedAccess({ protocolHash: splits.protocolHash, runId, reason, ledger });
  }
  return entries.filter((e) => splits.assignment[e.id] === wanted);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const a = process.argv.slice(2);
  const manifestText = readFileSync(MANIFEST_FILE, 'utf8');
  const frozen = loadSplits();
  if (a.includes('--legacy')) {
    const { isHeldOut } = await import('./runner.mjs');
    const entries = JSON.parse(manifestText).entries;
    const l = repositoryLeakage(entries, (e) => (isHeldOut(e.id) ? 'held-out' : 'dev'));
    console.log(JSON.stringify({ heldOutEntries: entries.filter((e) => isHeldOut(e.id)).length, ...l }, null, 2));
  } else if (a.includes('--verify')) {
    const p = verifySplits(manifestText, frozen);
    for (const x of p) console.error(`splits: ${x}`);
    if (!p.length) console.log(`splits: ${frozen.entries} entries, ${frozen.groups} groups, counts ${JSON.stringify(frozen.counts)}, protocol ${frozen.protocolHash.slice(0, 20)}, no group straddles`);
    process.exit(p.length ? 1 : 0);
  } else if (a.includes('--extend')) {
    if (!frozen) { console.error('no splits.json to extend; run --build'); process.exit(1); }
    const next = buildSplits(manifestText, { salt: frozen.salt, fractions: frozen.fractions, frozen });
    next.legacyHoldout = frozen.legacyHoldout;
    for (const id of Object.keys(frozen.assignment)) if (next.assignment[id] !== frozen.assignment[id]) { console.error(`refusing: ${id} would move`); process.exit(1); }
    atomicWriteJson(SPLITS_FILE, next);
    console.log(`extended: ${next.entries} entries (${next.quarantined.length} quarantined)`);
  } else if (a.includes('--build')) {
    if (frozen) { console.error('splits.json already exists and is frozen; use --extend, or deliberately create a successor protocol'); process.exit(1); }
    const s = buildSplits(manifestText);
    const { isHeldOut } = await import('./runner.mjs');
    const entries = JSON.parse(manifestText).entries;
    s.legacyHoldout = {
      source: 'bench/independent/runner.mjs#isHeldOut', fraction: 0.2, heldOutEntries: entries.filter((e) => isHeldOut(e.id)).length,
      ...repositoryLeakage(entries, (e) => (isHeldOut(e.id) ? 'held-out' : 'dev')),
      status: 'demoted_to_development',
      reason: 'it assigns by entry id, so advisories of one repository land on both sides; development work on a project leaks into its held-out entries. It is kept for continuity of past development numbers and is never quoted as held-out.',
    };
    atomicWriteJson(SPLITS_FILE, s);
    console.log(`built: ${s.entries} entries in ${s.groups} groups; ${JSON.stringify(s.counts)}; protocol ${s.protocolHash}`);
  } else { console.error('usage: splits.mjs --build | --extend | --verify | --legacy'); process.exit(2); }
}
void resolve;
