// CISA KEV enrichment — unit test for _enrichWithKEV.
//
// Strategy: stub _osvCacheGet/_osvCacheSet by pre-priming the on-disk cache
// blob with a fake KEV catalog before the engine import resolves. This avoids
// any network fetch during the test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

// Prime the cache file directly. The engine's disk cache path is derived from
// sha256 of the cache key.
const CACHE_DIR = path.join(os.homedir(), '.claude', 'agentic-security', 'osv-cache');
const cacheKeyPath = (k) => path.join(CACHE_DIR, crypto.createHash('sha256').update('osv_'+k).digest('hex') + '.json');
fs.mkdirSync(CACHE_DIR, { recursive: true });

const fakeCatalog = {
  ts: Date.now(),
  byCve: {
    'CVE-2024-99999': {
      dateAdded: '2024-09-01',
      ransomwareCampaign: true,
      vendor: 'TestVendor',
      product: 'TestProduct',
      vuln: 'Test KEV vuln',
      action: 'Apply patch',
      dueDate: '2024-09-30',
    },
  },
};
fs.writeFileSync(cacheKeyPath('kev:catalog'), JSON.stringify(fakeCatalog));

// Force the engine to use the cached catalog without network, by setting the
// OFFLINE env var. The cache returns the fake catalog as long as TTL hasn't
// expired (we just wrote it).
process.env.AGENTIC_SECURITY_OFFLINE = '0';

const { _enrichWithKEV } = await import('../src/engine.js');

test('KEV enrichment marks listed CVEs as weaponized', async () => {
  const sc = [
    { name: 'pkg-a', version: '1.0.0', ecosystem: 'npm', cveAliases: ['CVE-2024-99999'] },
    { name: 'pkg-b', version: '2.0.0', ecosystem: 'npm', cveAliases: ['CVE-2024-00001'] }, // not in KEV
    { name: 'pkg-c', version: '3.0.0', ecosystem: 'npm', cveAliases: [] },                  // no CVE
  ];
  const out = await _enrichWithKEV(sc);
  assert.equal(out[0].kev, true);
  assert.equal(out[0].weaponized, true);
  assert.equal(out[0].kevDateAdded, '2024-09-01');
  assert.equal(out[0].kevRansomware, true);
  assert.equal(out[1].kev, false);
  assert.equal(out[1].weaponized, false);
  assert.equal(out[2].kev, false);
});
