// Seed the engine's disk-backed OSV cache so an SCA test is HERMETIC.
//
// Why this exists: `queryOSV` populates `scan.supplyChain` by POSTing to
// https://api.osv.dev/v1/querybatch, falling back to whatever is on disk under
// `<home>/.claude/agentic-security/osv-cache/`. A test that asserts on
// `vulnerable_dep` entries therefore passes on a developer machine with a warm
// cache and FAILS offline or on a cold CI runner — and this project's root
// CLAUDE.md explicitly designs the pre-push gate around "an offline developer
// must still be able to push". Seeding every key the scan will look up means it
// never reaches the network and returns the same entries on every machine.
//
// Note `{ network: false }` is NOT a substitute: neither runScan.js nor
// engine.js reads an `opts.network` flag, so passing it does nothing at all.
//
// The key scheme mirrors engine.js exactly (see its `sessionStorage` shim and
// `_cacheKeyPath`): the string that gets hashed is `'osv_' + key`, sha256, hex,
// plus `.json`, and the file holds the JSON-stringified value. The two key
// shapes queryOSV uses are `comp:<OSV_ECO>:<name>:<version>` -> array of vuln
// ids, and `vuln:<id>` -> the NORMALIZED vuln object queryOSV caches (not the
// raw OSV API payload — engine.js stores its own reduced shape).

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

export function osvCacheDir(home) {
  return path.join(home, '.claude', 'agentic-security', 'osv-cache');
}

function keyPath(home, key) {
  const hash = crypto.createHash('sha256').update('osv_' + key).digest('hex');
  return path.join(osvCacheDir(home), hash + '.json');
}

export function seedOsvKey(home, key, value) {
  const p = keyPath(home, key);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(value));
}

/**
 * Seed one component -> one advisory. `ecosystem` is the OSV name
 * (npm, PyPI, Maven, …), not engine.js's internal key.
 */
export function seedAdvisory(home, { ecosystem, name, version, id, description, fixedVersions = [], severity = 'high' }) {
  seedOsvKey(home, `comp:${ecosystem}:${name}:${version}`, [id]);
  // `aliases` is deliberately EMPTY: a CVE alias would send _enrichWithEPSS to
  // the network for that CVE, reintroducing exactly the dependency this module
  // exists to remove. AGENTIC_SECURITY_OFFLINE=1 covers EPSS and KEV as well,
  // but not needing it is better than relying on it.
  seedOsvKey(home, `vuln:${id}`, {
    id, description, fixedVersions, aliases: [],
    osvVulnFunctions: [], severity, cvssVector: null, hasKnownAttackRef: false,
  });
}
