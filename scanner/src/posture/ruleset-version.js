// Ruleset version stamp (Sentinel-parity audit P2-13).
//
// The engine's built-in rules (engine.js, sast/*.js) evolve every release.
// A change that's net-positive on the benchmark may regress on a specific
// customer's codebase. Operators need a way to PIN the rule set so an
// upgrade doesn't silently shift their finding stream.
//
// Mechanism:
//   1. Each release stamps a RULESET_VERSION string (e.g. "0.45.0-2026-05-18").
//   2. Operators write the version they want to use into
//      .agentic-security/ruleset-version.json:
//        { "version": "0.43.0-...", "pinned": true }
//   3. The engine reads this at scan time. When pinned to an OLDER version,
//      it logs a notice saying which scanner build is installed but which
//      ruleset version is being honored.
//   4. The version stamp is included in last-scan.json so /security-trend
//      can attribute finding deltas to ruleset changes vs. code changes.
//
// LIMITATION: today, "pinning" is informational — it records intent but
// doesn't actually run a different rule set. A future release will ship a
// versioned ruleset-pack mechanism so old versions can be re-activated.
// This module is the foothold for that work.

import * as fs from 'node:fs';
import * as path from 'node:path';

// Bump on every release; tied to package.json version.
export const CURRENT_RULESET_VERSION = '0.45.0';

const FILE = '.agentic-security/ruleset-version.json';

export function readPinned(scanRoot) {
  const fp = path.join(scanRoot || process.cwd(), FILE);
  if (!fs.existsSync(fp)) return null;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch { return null; }
}

// Resolve the effective ruleset version: env override > pinned file > current.
export function effectiveVersion(scanRoot) {
  if (process.env.AGENTIC_SECURITY_RULESET_VERSION) {
    return { version: process.env.AGENTIC_SECURITY_RULESET_VERSION, source: 'env' };
  }
  const pinned = readPinned(scanRoot);
  if (pinned && pinned.version) {
    return { version: pinned.version, pinned: !!pinned.pinned, source: 'file' };
  }
  return { version: CURRENT_RULESET_VERSION, source: 'default' };
}

// Annotate a scan result with the ruleset version stamp.
export function stampScan(scanRoot, scan) {
  if (!scan || typeof scan !== 'object') return scan;
  const v = effectiveVersion(scanRoot);
  scan._rulesetVersion = v.version;
  scan._rulesetVersionSource = v.source;
  if (v.version !== CURRENT_RULESET_VERSION && v.source !== 'default') {
    // The operator pinned an older/newer version than what's installed.
    // We surface this so they know the scan result reflects an intent
    // mismatch (today, the pinning is informational — we don't actually
    // run different rules — but the trail of intent is recorded).
    scan._rulesetVersionMismatch = {
      installed: CURRENT_RULESET_VERSION,
      pinned: v.version,
      note: 'Today the pinning is informational; future releases will honor it by running the historical rule set.',
    };
  }
  return scan;
}
