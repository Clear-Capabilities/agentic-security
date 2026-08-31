//
// transit-protection.js — Milestone 2, Sub-project B ("transit protection
// analyzer", FR-401), increments 1 (plumbing skeleton) and 2 (verdict
// computation).
//
// Increment 1 shipped the ONLY thing it needed: running the already-shipped
// `crypto-protocol.js` whole-file/whole-repo TLS/cipher detector over every
// file's raw source text and returning a real, inspectable
// `Map<file, findings[]>`.
//
// Increment 2 (this addition) adds the real per-site verdict function,
// `resolveTransitProtectionForSite(site, transitEvidenceByFile)` — the
// `opts.resolveTransitProtection` hook `graph-builder.js` now composes into
// `edge.protection.transit`. See DESIGN_TRANSIT_PROTECTION.md's new §6 for
// the corrected hook point, the window constant, the `external-api`-only
// filter, and the decision table this function implements.
//
// Reuse boundary: this module imports ONLY `scanCryptoProtocol` from
// `../sast/crypto-protocol.js` — never `dataflow/engine.js`, never any
// other `src/lineage/` module. It still does NOT decide which graph EDGE a
// finding belongs to on its own — `resolveTransitProtectionForSite` takes a
// `site` (the same per-call-site object `graph-builder.js`'s edge-
// construction loop already has in scope) and a pre-computed
// `Map<file, findings[]>`, so the correlation itself is a pure, local
// (file, line)-proximity check, never a re-scan.
//
// `scanCryptoProtocol` itself already degrades gracefully and for free:
// `AGENTIC_SECURITY_NO_CRYPTO_PROTO=1` disables it (returns `[]`), and it
// silently returns `[]` for a file over 500KB or with no crypto-relevant
// content (`_isCryptoRelevant`) — both inherited here, not re-implemented.
//

import { scanCryptoProtocol } from '../sast/crypto-protocol.js';

// Increment 2 (DESIGN_TRANSIT_PROTECTION.md §6): a disclosed, deliberately
// NOT-calibrated starting value — no real fixture corpus exists yet to tune
// this against. A TLS-config object (`{ rejectUnauthorized: false }`) is
// often on the same line as, or a few lines before, the network call it
// configures; 10 lines is a generous but bounded window, following this
// package's own established line-window correlation precedent (measured
// directly: `engine.js`'s `dropGuardedFindings` and several other
// detectors use windows like `-2/+3`, `-2/+4`, `+10`, each independently
// chosen for its own correlation) — this constant is a NEW, independently
// chosen value for THIS correlation, not copied from any one of those.
export const TRANSIT_PROTECTION_WINDOW_LINES = 10;

// The two crypto-protocol.js families this increment's correlation cares
// about — confirmed against that module's own `EMITS` export and its
// `detectTlsNoVerify`/`detectTlsMinVersion` functions' own `_shape(...)`
// calls (`family: 'crypto-tls-no-verify'` / `family: 'crypto-tls-version'`).
const TRANSIT_FINDING_FAMILIES = new Set(['crypto-tls-no-verify', 'crypto-tls-version']);

/**
 * Increment 2's real verdict function — the `opts.resolveTransitProtection`
 * hook `graph-builder.js` (via `coverage.js`'s default wiring) applies once
 * per site, at the exact edge-construction point that already reads
 * `site.destination`. `site` is one entry from `enumerateSinkSites`'s
 * `sites[]` (post any `opts.resolveSiteDecision`/`opts.resolveDestination`
 * overrides — this function reads `site.decision`/`site.destination`, both
 * already resolved by the time it runs). `transitEvidenceByFile` is the
 * SAME `Map<file, findings[]>` `scanTransitEvidence` returns — computed
 * exactly once, by the caller (`index.js`), never re-derived here from raw
 * file text.
 *
 * A deliberate, narrow first slice (DESIGN_TRANSIT_PROTECTION.md §6):
 * `category !== 'external-api'` returns `undefined` immediately —
 * `webhook`/`email`/`sms`/`push-notification`/`analytics`/`monitoring`/
 * `collaboration`/`ai-*` are all real, plausible "also network" categories
 * (named in this file's own §4 candidate list) but widening the filter is
 * separate, deliberate, deferred scope, not silently included or excluded
 * here.
 *
 * Decision table (checked in order):
 *   1. A literal `http://` destination -> `{verdict: 'unprotected', evidenceGrade: 'code'}`
 *      unconditionally — the scheme itself is the evidence, no correlation
 *      needed.
 *   2. A `crypto-tls-no-verify`/`crypto-tls-version` finding in the site's
 *      own file within `TRANSIT_PROTECTION_WINDOW_LINES` lines of the site's
 *      own line -> `{verdict: 'unprotected', evidenceGrade: 'code'}` — this
 *      OVERRIDES a literal `https://` scheme: a plain scheme is never
 *      sufficient evidence of protection once a nearby finding says
 *      verification was disabled (AC-04's own core property).
 *   3. A literal `https://` destination with no such nearby finding ->
 *      `{verdict: 'protected', evidenceGrade: 'code'}`.
 *   4. Anything else (a dynamic/unresolved destination, or a resolved
 *      destination this function has no scheme opinion about) -> `undefined`
 *      — the HONEST answer: `emptyProtection()`'s own default
 *      (`not_assessed`/`none`) already means exactly that, so this function
 *      correctly declines to overwrite it rather than manufacturing a
 *      fabricated verdict that implies more analysis happened than
 *      actually did.
 *
 * Never throws on a malformed `site`/`transitEvidenceByFile` — mirrors this
 * package's own established defensiveness (`detectUnresolvedDestination`,
 * `resolveDestination`).
 */
export function resolveTransitProtectionForSite(site, transitEvidenceByFile) {
  if (!site || site.decision?.category !== 'external-api') return undefined;

  const dest = site.destination;
  const raw = dest?.resolutionStatus === 'literal' ? dest.literalValue : null;

  if (typeof raw === 'string' && raw.startsWith('http://')) {
    return { verdict: 'unprotected', evidenceGrade: 'code' };
  }

  const findings = transitEvidenceByFile?.get(site.file) ?? [];
  const nearby = findings.some((f) =>
    TRANSIT_FINDING_FAMILIES.has(f.family)
    && typeof site.line === 'number' && typeof f.line === 'number'
    && Math.abs(f.line - site.line) <= TRANSIT_PROTECTION_WINDOW_LINES);
  if (nearby) return { verdict: 'unprotected', evidenceGrade: 'code' };

  if (typeof raw === 'string' && raw.startsWith('https://')) {
    return { verdict: 'protected', evidenceGrade: 'code' };
  }

  return undefined;
}

/**
 * Runs `scanCryptoProtocol` over every file in `fileContents`, collecting
 * any non-empty result into a `Map<file, findings[]>`. Never throws — a
 * per-file detector failure is swallowed (treated as "no findings for that
 * file") rather than aborting the whole scan, matching this package's own
 * "best-effort, never an uncaught throw" convention for optional analysis
 * (see `index.js`'s `buildLineageGraph`).
 *
 * @param {Record<string,string>} [fileContents] `{path: rawSourceString}`,
 *   the same shape `runFullScan` already threads to every other whole-file
 *   scanner. A non-string value at a given key is skipped, not coerced.
 * @returns {Map<string, object[]>} file -> non-empty findings array. A file
 *   with zero findings (including one `scanCryptoProtocol` itself judged
 *   not crypto-relevant, or skipped for size) has NO entry — never an
 *   entry with an empty array.
 */
export function scanTransitEvidence(fileContents) {
  const byFile = new Map();
  for (const [file, raw] of Object.entries(fileContents ?? {})) {
    if (typeof raw !== 'string') continue;
    let findings;
    try {
      findings = scanCryptoProtocol(file, raw);
    } catch {
      findings = [];
    }
    if (findings.length) byFile.set(file, findings);
  }
  return byFile;
}
