// posture/epss.js — enrichWithEPSS is the live path wired into
// bin/agentic-security.js (`await enrichWithEPSS(scan)`, run after
// runScan() completes). Zero existing test coverage before this file:
// test/sca-batch.test.js only exercises engine.js's separate, internal
// _enrichWithEPSS (which sets epssScore/epssPercentile but never
// exploitedNow) — a different implementation entirely.
//
// Stage 4 correctness audit: enrichWithEPSS's CVE extraction (`cvesIn`)
// recognizes `finding.cve` (string), `finding.cves` (array),
// `finding.vulnerabilities[].id/.aliases`, or a CVE- pattern embedded in
// `title`/`description`/`vuln` text — but NOT `finding.cveAliases`, the
// actual field name every SCA finding in this codebase uses (src/sca/
// CLAUDE.md's documented finding shape: `cveAliases: ['CVE-…']`;
// report/index.js's normalizeFindings carries it through under the same
// name). A real SCA finding has no `.cve`/`.cves`/`.vulnerabilities` at
// all, so enrichWithEPSS finds zero CVEs on it, never fetches EPSS data,
// and `exploitedNow` never gets set — regardless of any pipeline-ordering
// concern, this field-name mismatch is the actual blocker.
//
// CVE ids are namespaced per-run (like test/sca-batch.test.js) so a cached
// disk entry from a prior run of this file can never mask a fetch that
// should have happened — fetchEPSS caches by CVE list at
// ~/.claude/agentic-security/epss-cache/ with a 24h TTL and no test hook
// to bypass it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

const RUN_ID = `${Date.now()}${process.pid}`.slice(-9);
function cveId(seq) { return `CVE-9999-${RUN_ID}${String(seq).padStart(2, '0')}`; }
const CVE_HIGH = cveId(1);
const CVE_LOW = cveId(2);

let fetchCalls = [];
globalThis.fetch = async (url) => {
  fetchCalls.push(String(url));
  if (String(url).includes(CVE_HIGH)) {
    return { ok: true, json: async () => ({ data: [{ cve: CVE_HIGH, epss: '0.02', percentile: '0.97' }] }) };
  }
  return { ok: true, json: async () => ({ data: [{ cve: CVE_LOW, epss: '0.001', percentile: '0.10' }] }) };
};

const { enrichWithEPSS } = await import('../src/posture/epss.js');

test('enrichWithEPSS finds CVEs via cveAliases (the actual SCA finding field name) and sets exploitedNow', async () => {
  fetchCalls = [];
  const finding = { id: 'f1', severity: 'low', cveAliases: [CVE_HIGH] };
  const scan = { findings: [finding], supplyChain: [] };
  const { decorated, exploitedNow } = await enrichWithEPSS(scan);
  assert.equal(fetchCalls.length, 1, 'expected enrichWithEPSS to actually fetch EPSS data for the cveAliases CVE');
  assert.equal(decorated, 1);
  assert.equal(exploitedNow, 1);
  assert.equal(finding.exploitedNow, true, `expected exploitedNow to be set on the finding; got ${JSON.stringify(finding)}`);
  assert.equal(finding.epssPercentile, 0.97);
});

test('enrichWithEPSS: a finding with only a low-percentile cveAliases CVE is decorated but not marked exploitedNow', async () => {
  const finding = { id: 'f2', severity: 'medium', cveAliases: [CVE_LOW] };
  const scan = { findings: [finding], supplyChain: [] };
  const { decorated, exploitedNow } = await enrichWithEPSS(scan);
  assert.equal(decorated, 1);
  assert.equal(exploitedNow, 0);
  assert.notEqual(finding.exploitedNow, true);
});

test('cleanup: remove epss-cache entries this file wrote', () => {
  const cacheDir = path.join(os.homedir(), '.claude', 'agentic-security', 'epss-cache');
  for (const key of [[CVE_HIGH].join(','), [CVE_LOW].join(',')]) {
    const fp = path.join(cacheDir, crypto.createHash('sha256').update(key).digest('hex') + '.json');
    try { fs.unlinkSync(fp); } catch {}
  }
});
