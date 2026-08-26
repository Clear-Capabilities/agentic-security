// Retention policy: default and maximum TTL by artifact class (assurance-
// hardening PRD FR-702).
//
// "Enforce default and maximum TTL by artifact class | Expired caches,
// scans, evidence, tickets, and backups are purged or archived according
// to policy."
//
// TWO NUMBERS PER CLASS, ON PURPOSE
// --------------------------------------------------------------------------
// `defaultDays` is what applies when nobody configures anything — a
// reasonable, disclosed starting point, not a regulatory citation (an
// operator with a real compliance regime should configure their own via
// the policy file below). `maxDays` is a CEILING an operator's own
// configuration cannot exceed: the literal "default AND maximum" wording
// asks for both a floor-free default and a hard cap, not just a knob. An
// operator who wants indefinite retention for `evidence` for their own
// audit reasons should say so in their own retention program — this
// module will not silently allow a TTL past its built-in ceiling for a
// class, because "TTL" than can be configured to "never" is not a TTL.
//
// PURGE, NOT ARCHIVE
// --------------------------------------------------------------------------
// The acceptance criterion allows either. This implements PURGE (delete)
// only — the simpler, safer, and more directly verifiable of the two.
// "Archive" implies a defined export format and destination, which is
// FR-706's own separate scope (manifest-based export); an operator who
// wants to archive before purging already has the tool for it once FR-706
// exists, or can back up `.agentic-security/` by their own means before
// running the enforcement command.
//
// WHICH ARTIFACTS THIS APPLIES TO
// --------------------------------------------------------------------------
// Only 'generated' artifacts carrying a `retentionClass` in
// artifact-registry.js — deliberately a SUBSET of all generated artifacts
// (see that module's own header for which ones were left classless and
// why). An 'operator-config' artifact is NEVER touched by this module,
// regardless of age, matching FR-703's own "reset preserves operator-
// authored configuration" precedent.

import * as fs from 'node:fs';
import * as yaml from '../util/yaml.js';
import { statePath, stateDir } from './state-dir.js';
import { listArtifactsWithRetentionClass } from './artifact-registry.js';
import { loadLegalHolds, isUnderHold } from './legal-hold.js';

const POLICY_FILE = 'retention-policy.yml';
const MS_PER_DAY = 24 * 60 * 60 * 1000;

// Engineering defaults, not a regulatory claim — see the header above.
export const RETENTION_DEFAULTS = {
  cache: { defaultDays: 7, maxDays: 30 },
  scan: { defaultDays: 90, maxDays: 365 },
  evidence: { defaultDays: 365, maxDays: 1095 },
  ticket: { defaultDays: 180, maxDays: 730 },
  backup: { defaultDays: 30, maxDays: 180 },
};

/**
 * Load an operator's `.agentic-security/retention-policy.yml`. Never
 * throws — a missing or malformed file degrades to "no overrides," the
 * same no-op-until-configured convention this repo uses for every other
 * policy surface. Shape:
 *   cache: { defaultDays: 3 }
 *   evidence: { defaultDays: 730 }
 * A class not mentioned, or a file not present at all, uses
 * RETENTION_DEFAULTS unmodified.
 */
export function loadRetentionPolicy(scanRoot) {
  if (!scanRoot) return null;
  let fp;
  try { fp = statePath(scanRoot, POLICY_FILE); } catch { return null; }
  let raw;
  try { raw = fs.readFileSync(fp, 'utf8'); } catch { return null; }
  try {
    const doc = yaml.load(raw);
    if (!doc || typeof doc !== 'object') return null;
    return doc;
  } catch { return null; }
}

/**
 * The TTL (in days) actually in effect for a class, after applying any
 * operator override and clamping it to the class's own maxDays — an
 * override CANNOT raise retention past the ceiling, only lower it (or
 * leave it at the default). An unrecognised class (should not happen —
 * only artifact-registry.js's own 5 named classes are ever passed in)
 * degrades to null, meaning "not subject to a TTL."
 */
export function effectiveTtlDays(retentionClass, policy) {
  const bounds = RETENTION_DEFAULTS[retentionClass];
  if (!bounds) return null;
  const override = policy?.[retentionClass]?.defaultDays;
  if (typeof override === 'number' && Number.isFinite(override) && override >= 0) {
    return Math.min(override, bounds.maxDays);
  }
  return bounds.defaultDays;
}

/**
 * Which registered, retention-classed artifacts under `scanRoot`'s state
 * dir are currently past their effective TTL. Never throws — a missing
 * state dir or an artifact that does not exist on disk is simply absent
 * from the result, not an error.
 *
 * @returns {Array<{name: string, isDir: boolean, retentionClass: string,
 *   ageDays: number, ttlDays: number}>}
 */
export function findExpiredArtifacts(scanRoot, { now = Date.now() } = {}) {
  const dir = stateDir(scanRoot);
  let dirExists = true;
  try { fs.accessSync(dir); } catch { dirExists = false; }
  if (!dirExists) return [];
  const policy = loadRetentionPolicy(scanRoot);
  // FR-707: an artifact under an active legal hold is NEVER reported as
  // expired, regardless of TTL — checked here (not just in cmdReset) so
  // any future caller of this function inherits the same guarantee.
  const holds = loadLegalHolds(scanRoot);
  const expired = [];
  for (const artifact of listArtifactsWithRetentionClass()) {
    const ttlDays = effectiveTtlDays(artifact.retentionClass, policy);
    if (ttlDays === null) continue;
    if (isUnderHold(artifact.name, holds, now)) continue;
    const p = `${dir}/${artifact.name}`;
    let st;
    try { st = fs.statSync(p); } catch { continue; } // not present — nothing to expire
    const ageDays = (now - st.mtimeMs) / MS_PER_DAY;
    if (ageDays > ttlDays) {
      expired.push({ name: artifact.name, isDir: st.isDirectory(), retentionClass: artifact.retentionClass, ageDays, ttlDays });
    }
  }
  return expired;
}
