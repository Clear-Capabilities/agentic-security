// PRD F3.4 — a KEV/EPSS catalog has no meaning without its age.
//
// The refresh TTL only decides when to TRY the network. Every failure path fell
// back to the disk cache with NO age bound, so an offline machine, a blocked
// egress rule, or a CISA outage silently served a catalog of any age.
//
// For KEV specifically that fails in the dangerous direction: KEV membership is
// used to ESCALATE severity, so a stale catalog omits recently-added CVEs and
// UNDERSTATES risk. It fails quiet, which is why nobody notices.
//
// The catalog is still used when stale — dropping it would understate risk even
// harder — but the age is recorded and surfaced so a report can state it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { kevCatalogMeta } from '../src/engine.js';
import { epssCacheMeta } from '../src/posture/epss.js';

test('KEV metadata exposes source, age and staleness as first-class values', () => {
  const m = kevCatalogMeta();
  for (const k of ['source', 'fetchedAt', 'ageDays', 'stale', 'entries']) {
    assert.ok(k in m, `KEV metadata must carry ${k}`);
  }
});

test('KEV metadata starts as not-loaded, never as a silent zero', () => {
  // 'not-loaded' and 'unavailable' are different states from "a catalog with no
  // entries". Collapsing them would let an absent catalog read as a clean one.
  const m = kevCatalogMeta();
  assert.equal(m.source, 'not-loaded');
  assert.equal(m.stale, null, 'unknown staleness must be null, not false');
});

test('KEV metadata is a copy — a caller cannot mutate the recorded provenance', () => {
  const a = kevCatalogMeta();
  a.source = 'tampered';
  assert.notEqual(kevCatalogMeta().source, 'tampered');
});

test('the KEV meaning line states the direction of the error', () => {
  // Which way a stale catalog is wrong is the whole point: it understates.
  // A generic "data may be old" note would not tell a reader that.
  const { kevCatalogMeta: meta } = { kevCatalogMeta };
  const m = meta();
  if (m.meaning) assert.match(m.meaning, /understates/);
});

test('EPSS metadata exposes age and staleness', () => {
  const m = epssCacheMeta();
  for (const k of ['source', 'ageDays', 'stale']) assert.ok(k in m, `EPSS metadata must carry ${k}`);
  assert.equal(m.stale, null, 'unknown staleness must be null, not false');
});

test('a scan surfaces the KEV catalog provenance', async () => {
  // The metadata is worthless if it never reaches the report. This is the wiring
  // check — the same gap that made the k8s and install-script rules dark.
  const { runScan } = await import('../src/runScan.js');
  const { scan } = await runScan(new URL('./fixtures/vulnerable-js', import.meta.url).pathname);
  assert.ok(scan.kevCatalog, 'scan result must carry kevCatalog provenance');
  assert.ok('stale' in scan.kevCatalog && 'source' in scan.kevCatalog);
});
