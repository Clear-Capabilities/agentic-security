//
// transit-protection.js — Milestone 2, Sub-project B ("transit protection
// analyzer", FR-401), increment 1 (plumbing skeleton).
//
// Implements the ONLY real logic this increment ships: running the
// already-shipped `crypto-protocol.js` whole-file/whole-repo TLS/cipher
// detector over every file's raw source text and returning a real,
// inspectable `Map<file, findings[]>`. See DESIGN_TRANSIT_PROTECTION.md for
// the full isolation decision, the `fileContents` plumbing path, and the
// named-but-not-yet-used candidate "network" category list.
//
// Reuse boundary: this module imports ONLY `scanCryptoProtocol` from
// `../sast/crypto-protocol.js` — never `dataflow/engine.js`, never any
// other `src/lineage/` module. It does NOT join a finding to any specific
// graph edge and does NOT write to `edge.protection.transit` — that
// file+line correlation join is explicitly deferred to a future increment
// (B2), per the scoping doc's Finding 2/Recommended increment breakdown.
//
// `scanCryptoProtocol` itself already degrades gracefully and for free:
// `AGENTIC_SECURITY_NO_CRYPTO_PROTO=1` disables it (returns `[]`), and it
// silently returns `[]` for a file over 500KB or with no crypto-relevant
// content (`_isCryptoRelevant`) — both inherited here, not re-implemented.
//

import { scanCryptoProtocol } from '../sast/crypto-protocol.js';

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
