// Cross-run discovery memory — PRD Phase 3 / C4.
//
// WHAT WAS MISSING
// ----------------
// `judge.js` dedupes a hunt against `last-scan.json` and the triage ledger, so
// it knows what the RULE ENGINE found and what a human dismissed. It has never
// known what a PREVIOUS HUNT found. Two consequences, both bad:
//
//   1. Every run re-proposes, re-confirms and re-refutes the same candidates.
//      That is three LLM calls per candidate per run, spent to rediscover
//      something already judged — the exact waste the Phase 0 budget exists to
//      bound, being incurred deliberately.
//   2. A second run cannot be *additive*. Without a record of what was already
//      examined, "hunt again" means "hunt the same thing again" rather than
//      "hunt what we missed".
//
// This is that record. It turns a sequence of independent runs into a campaign.
//
// WHAT IS AND IS NOT REMEMBERED
// -----------------------------
// Remembered: every candidate ever JUDGED, with the verdict and the run that
// produced it. Also every focus area ever hunted, so coverage can become a plan
// instead of a report.
//
// NOT remembered: refuted candidates as if they were settled forever. A
// refutation is a majority opinion from three prompts on one day, not a proof.
// It suppresses re-reporting, and `--forget-refuted` exists precisely because a
// verdict made by a weaker model, or before a sanitiser was removed, must be
// re-openable. A memory you cannot clear is a memory that eventually lies.
//
// THE PRECEDENT THIS FOLLOWS
// --------------------------
// `judge.js` deliberately suppresses only `fp` triage verdicts and re-reports
// `tp` ones, because a prior true positive that is still in the code is still a
// bug. The same asymmetry holds here: a candidate previously judged FRESH is
// re-reported (it was never fixed), while one previously REFUTED is held back
// until something changes.

import * as fs from 'node:fs';
import * as path from 'node:path';

import { stateWritesEnabled } from '../posture/state-dir.js';
const MEMORY_SCHEMA = 'agentic-security/discovery-memory@1';
export const MEMORY_FILE = path.join('.agentic-security', 'discovery-memory.json');

function emptyMemory() {
  return { schema: MEMORY_SCHEMA, runs: 0, candidates: {}, areas: {} };
}

/** A stable identity for a candidate across runs. */
export function memoryKey(candidate) {
  // Location + family, matching judge.js's PRIMARY duplicate key. Deliberately
  // NOT stableId: that is location-fuzzy by design and collides across distinct
  // findings in one file, which is tolerable for a single scan's dedupe and
  // corrosive when it accumulates across every run ever made.
  const file = candidate?.file ?? '?';
  const line = candidate?.line ?? '?';
  const family = candidate?.family ?? candidate?.lens ?? '?';
  return `${file}:${line}:${family}`;
}

/** Read the memory. Anything unreadable or unrecognised yields an empty one. */
export function loadMemory(scanRoot) {
  try {
    const doc = JSON.parse(fs.readFileSync(path.join(scanRoot, MEMORY_FILE), 'utf8'));
    if (doc?.schema !== MEMORY_SCHEMA) return emptyMemory();
    return { ...emptyMemory(), ...doc };
  } catch {
    // A corrupt memory must degrade to "remember nothing", never to a crash and
    // never to a partially-trusted record. Re-hunting is cheap next to acting on
    // a half-read ledger.
    return emptyMemory();
  }
}

/** Persist. Failure is non-fatal — the run still produced its report. */
export function saveMemory(scanRoot, memory) {
  try {
    const p = path.join(scanRoot, MEMORY_FILE);
    if (!stateWritesEnabled()) return;
  fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(memory, null, 2) + '\n');
    return true;
  } catch {
    return false;
  }
}

/**
 * Should this candidate be held back because a previous run already judged it?
 *
 * Only a REFUTED verdict suppresses. Everything else — fresh, duplicate,
 * suppressed-by-triage — is re-evaluated, because those states are about the
 * code and the code may have changed.
 */
export function previouslyRefuted(memory, candidate) {
  const rec = memory?.candidates?.[memoryKey(candidate)];
  return Boolean(rec && rec.verdict === 'refuted');
}

/** Fold this run's outcome into the memory. Returns a NEW memory object. */
export function rememberRun(memory, { fresh = [], refutedCandidates = [], areas = [], at }) {
  const next = {
    ...emptyMemory(),
    ...memory,
    candidates: { ...(memory?.candidates || {}) },
    areas: { ...(memory?.areas || {}) },
  };
  next.runs = (memory?.runs || 0) + 1;
  const stamp = at || new Date().toISOString();

  for (const f of fresh) {
    next.candidates[memoryKey(f)] = { verdict: 'fresh', run: next.runs, at: stamp };
  }
  for (const c of refutedCandidates) {
    next.candidates[memoryKey(c)] = { verdict: 'refuted', run: next.runs, at: stamp };
  }
  for (const a of areas) {
    const prev = next.areas[a.id] || { hunts: 0 };
    next.areas[a.id] = {
      label: a.label,
      hunts: prev.hunts + (a.hunted ? 1 : 0),
      lastRun: a.hunted ? next.runs : (prev.lastRun ?? null),
      files: a.files ?? prev.files ?? null,
    };
  }
  return next;
}

/**
 * Turn the memory into a PLAN: which areas have never been successfully hunted.
 *
 * This is the half that makes a second run additive rather than repetitive. A
 * coverage report says what happened; this says what to do next.
 */
export function nextWavePlan(memory, areas) {
  const unhunted = [];
  const stale = [];
  for (const a of areas || []) {
    const rec = memory?.areas?.[a.id];
    if (!rec || rec.hunts === 0) unhunted.push(a.label || a.id);
    else if (rec.lastRun !== memory.runs) stale.push(a.label || a.id);
  }
  return {
    unhunted,
    stale,
    // Stated as a sentence because this lands in a report a human reads, and
    // "3 areas" without saying which ones is not actionable.
    summary: unhunted.length
      ? `${unhunted.length} focus area(s) have NEVER been successfully hunted: ${unhunted.slice(0, 5).join(', ')}` +
        (unhunted.length > 5 ? `, +${unhunted.length - 5} more` : '')
      : 'every focus area has been hunted at least once',
  };
}

/** Drop refuted verdicts so they can be re-examined. */
export function forgetRefuted(memory) {
  const candidates = {};
  for (const [k, v] of Object.entries(memory?.candidates || {})) {
    if (v?.verdict !== 'refuted') candidates[k] = v;
  }
  return { ...emptyMemory(), ...memory, candidates };
}
