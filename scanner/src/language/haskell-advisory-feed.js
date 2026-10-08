// Live Hackage advisory feed (HS-009 follow-on). The matching logic in haskell-sca.js takes records from its caller and never fetches;
// this module is the caller that can. It turns the OSV `Hackage` ecosystem (HSEC advisories and their aliases) into the same
// hash-recorded snapshot the loader already verifies, and writes it where only the operator can: the per-user configuration
// directory. A scanned project cannot supply or alter it (see trusted-inputs.js).
//
// Contract, in the order it matters:
//   * Opt in. Nothing here touches the network unless AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1, and never when
//     AGENTIC_SECURITY_OFFLINE=1. An operator-pinned snapshot (AGENTIC_SECURITY_HACKAGE_ADVISORIES) always wins: it is not refreshed over.
//   * Coverage is recorded, not assumed. The snapshot lists each package it actually queried and when. A package that was not queried,
//     or whose query failed part-way, is NOT covered, and the matcher reports it `feed-incomplete` (unknown), never `no-advisories` (clean).
//   * Failure degrades, it does not abort. An unreachable feed leaves the previous snapshot in place and the scan runs on it, with its age
//     disclosed; with no previous snapshot the scan reports `feed-unavailable`, exactly as before this module existed.
//   * Everything from the wire is untrusted: ids and package names are validated before they are placed in a URL or a path, sizes are
//     bounded, and a record that does not parse as an OSV record is dropped and counted.

import { mkdirSync, readFileSync, writeFileSync, renameSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { buildSnapshot, loadAdvisorySnapshot } from './haskell-sca.js';
import { operatorConfigDir } from './trusted-inputs.js';

export const FEED_ENV = 'AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE';
export const PINNED_ENV = 'AGENTIC_SECURITY_HACKAGE_ADVISORIES';
export const SNAPSHOT_FILE = 'hackage-advisories.json';
export const OSV_BASE = 'https://api.osv.dev';

const DEFAULTS = Object.freeze({
  ttlMs: 24 * 3600 * 1000,       // a covered package is not queried again inside this window
  timeoutMs: 8000,
  concurrency: 10,
  batchSize: 500,
  maxPackages: 500,
  maxRecordBytes: 1 << 20,
  maxSnapshotRecords: 20000,
});

const NAME_OK = /^[A-Za-z0-9][A-Za-z0-9-]{0,127}$/;   // Hackage package names
const ID_OK = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$/;   // HSEC-2023-0001, GHSA-..., CVE-...

let last = null;
/** What the most recent refresh in this process did, so a "no feed" reason can say why. */
export const getLastRefresh = () => last;
export const _resetLastRefresh = () => { last = null; };

export function liveFeedEnabled(env = process.env) {
  return env[FEED_ENV] === '1' && env.AGENTIC_SECURITY_OFFLINE !== '1';
}

export function snapshotPath(env = process.env, dir = null) {
  return join(dir || operatorConfigDir(env), SNAPSHOT_FILE);
}

function readCurrent(path, maxAgeDays) {
  let raw;
  try { raw = JSON.parse(readFileSync(path, 'utf8')); } catch { return { records: new Map(), covered: {}, problem: null }; }
  // Integrity first: a cache whose records do not match their own hashes is discarded, not repaired.
  const r = loadAdvisorySnapshot(raw, { maxAgeDays });
  if (!r.ok) return { records: new Map(), covered: {}, problem: `the cached snapshot was discarded: ${r.reason}` };
  const covered = raw.covered && typeof raw.covered === 'object' ? { ...raw.covered } : {};
  return { records: new Map(raw.records.map((x) => [x.id, x])), covered, problem: null };
}

async function getJson(fetchImpl, url, init, timeoutMs, maxBytes) {
  const resp = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  if (!resp || resp.status !== 200) throw new Error(`HTTP ${resp ? resp.status : 'none'}`);
  const text = await resp.text();
  if (Buffer.byteLength(text) > maxBytes) throw new Error('response too large');
  return JSON.parse(text);
}

async function pool(items, limit, worker) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await worker(items[k], k); }
  }));
  return out;
}

/**
 * Refresh the operator's Hackage advisory snapshot for the given package names.
 * Never throws. Returns a plain result describing what happened; the snapshot file is only rewritten when something changed.
 *
 * @param {string[]} names Hackage package names the scan is about to evaluate
 * @param {{env?: object, fetchImpl?: Function, now?: number, dir?: string, ttlMs?: number, timeoutMs?: number}} [opts]
 */
export async function refreshHackageAdvisories(names, opts = {}) {
  const env = opts.env || process.env;
  const cfg = { ...DEFAULTS, ...Object.fromEntries(Object.entries(opts).filter(([k]) => k in DEFAULTS)) };
  const now = opts.now ?? Date.now();
  const done = (r) => { last = { ...r, at: new Date(now).toISOString() }; return last; };

  if (env[PINNED_ENV]) return done({ status: 'pinned-snapshot-in-use', detail: `${PINNED_ENV} names an operator snapshot; it is used as given and is not refreshed` });
  if (env[FEED_ENV] !== '1') return done({ status: 'disabled', detail: `set ${FEED_ENV}=1 to fetch Hackage advisories from the OSV feed` });
  if (env.AGENTIC_SECURITY_OFFLINE === '1') return done({ status: 'offline', detail: 'AGENTIC_SECURITY_OFFLINE=1: no advisory data was fetched' });

  const wanted = [...new Set((names || []).filter((n) => typeof n === 'string' && NAME_OK.test(n)))].sort().slice(0, cfg.maxPackages);
  if (!wanted.length) return done({ status: 'nothing-to-do', detail: 'no Hackage packages to look up' });

  const path = snapshotPath(env, opts.dir);
  const cur = readCurrent(path, 36500);
  const need = wanted.filter((n) => { const t = Date.parse(cur.covered[n]); return !Number.isFinite(t) || now - t > cfg.ttlMs || t > now + 3600000; });
  if (!need.length) return done({ status: 'current', detail: `${wanted.length} package(s) covered within the last ${Math.round(cfg.ttlMs / 3600000)}h; no request made`, packages: wanted.length, requested: 0 });

  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') return done({ status: 'failed', detail: 'no fetch implementation is available in this runtime' });

  const failures = [];
  const ok = new Set();           // packages whose whole answer was obtained
  const refs = new Map();         // package -> [{id, modified}]
  // 1. which advisories does OSV hold for each package?
  for (let i = 0; i < need.length; i += cfg.batchSize) {
    const chunk = need.slice(i, i + cfg.batchSize);
    try {
      const data = await getJson(fetchImpl, `${OSV_BASE}/v1/querybatch`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: chunk.map((name) => ({ package: { name, ecosystem: 'Hackage' } })) }),
      }, cfg.timeoutMs, 8 << 20);
      const results = Array.isArray(data && data.results) ? data.results : [];
      chunk.forEach((name, k) => {
        const res = results[k];
        if (!res || typeof res !== 'object') { failures.push(`${name}: no result`); return; }
        if (res.next_page_token) { failures.push(`${name}: more advisories than one page; not treated as covered`); return; }
        refs.set(name, (Array.isArray(res.vulns) ? res.vulns : []).filter((v) => v && typeof v.id === 'string' && ID_OK.test(v.id)).map((v) => ({ id: v.id, modified: v.modified || null })));
      });
    } catch (e) { for (const n of chunk) failures.push(`${n}: ${String((e && e.message) || e).slice(0, 80)}`); }
  }

  // 2. fetch the records that are new or newer than the cached copy
  const toFetch = new Map();
  for (const list of refs.values()) for (const { id, modified } of list) {
    const have = cur.records.get(id);
    if (!have || (modified && have.modified && Date.parse(modified) > Date.parse(have.modified)) || (modified && !have.modified)) toFetch.set(id, modified);
  }
  const fetched = new Map();
  const badIds = new Set();
  await pool([...toFetch.keys()], cfg.concurrency, async (id) => {
    try {
      const rec = await getJson(fetchImpl, `${OSV_BASE}/v1/vulns/${encodeURIComponent(id)}`, {}, cfg.timeoutMs, cfg.maxRecordBytes);
      if (!rec || typeof rec !== 'object' || rec.id !== id) throw new Error('not the requested record');
      fetched.set(id, rec);
    } catch (e) { badIds.add(id); failures.push(`${id}: ${String((e && e.message) || e).slice(0, 80)}`); }
  });

  // 3. a package is covered only if every advisory it references is in hand
  const records = new Map(cur.records);
  for (const [id, rec] of fetched) records.set(id, rec);
  const covered = { ...cur.covered };
  const iso = new Date(now).toISOString();
  let newlyCovered = 0;
  for (const [name, list] of refs) {
    if (list.some((v) => badIds.has(v.id) || !records.has(v.id))) continue;
    covered[name] = iso; ok.add(name); newlyCovered++;
  }
  const uncovered = need.filter((n) => !ok.has(n));

  if (!ok.size && !fetched.size) {
    return done({ status: 'failed', detail: `the OSV feed could not be read (${failures.slice(0, 2).join('; ') || 'no response'}); ${cur.records.size ? 'the previous snapshot is used and its age is disclosed' : 'no advisory data is available'}`, packages: wanted.length, requested: need.length, uncovered, failures: failures.slice(0, 10), cacheProblem: cur.problem });
  }
  if (records.size > cfg.maxSnapshotRecords) return done({ status: 'failed', detail: `the snapshot would exceed ${cfg.maxSnapshotRecords} records; refusing to write it`, packages: wanted.length, requested: need.length, uncovered });

  // 4. write the snapshot atomically, readable by the operator only
  const snap = buildSnapshot([...records.values()].sort((a, b) => (a.id < b.id ? -1 : 1)), iso);
  snap.covered = Object.fromEntries(Object.entries(covered).sort(([a], [b]) => (a < b ? -1 : 1)));
  try {
    const dir = opts.dir || operatorConfigDir(env);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(snap), { mode: 0o600 });
    try { chmodSync(tmp, 0o600); } catch { /* best effort on filesystems without modes */ }
    renameSync(tmp, path);
  } catch (e) {
    return done({ status: 'failed', detail: `the snapshot could not be written: ${e.code || e.message}`, packages: wanted.length, requested: need.length, uncovered });
  }
  return done({
    status: uncovered.length ? 'partial' : 'refreshed',
    detail: `${newlyCovered} package(s) covered, ${fetched.size} advisory record(s) fetched${uncovered.length ? `; ${uncovered.length} package(s) NOT covered (${uncovered.slice(0, 3).join(', ')}${uncovered.length > 3 ? ', ...' : ''}) and will be reported as unknown` : ''}`,
    packages: wanted.length, requested: need.length, fetched: fetched.size, records: records.size, uncovered, failures: failures.slice(0, 10), path, cacheProblem: cur.problem,
  });
}

/**
 * The scan-health view of this feed, in the shape language/assurance.js takes for an optional mode: `selected` is whether the operator
 * opted in, `result` is what the refresh did (absent when none happened, which assurance reports as "selected but did not run").
 * Outcomes that mean the feed answered are `ok`; a partial refresh is `partial` (some packages stay unknown) and is not dressed as success.
 */
export function liveFeedOptionalState(env = process.env, refresh = getLastRefresh()) {
  if (env[FEED_ENV] !== '1') return { selected: false };
  if (!refresh) return { selected: true, result: undefined };
  const ok = new Set(['refreshed', 'current', 'nothing-to-do']);
  if (ok.has(refresh.status)) return { selected: true, result: { status: 'ok' } };
  if (refresh.status === 'partial') return { selected: true, result: { status: 'partial', reason: refresh.detail } };
  if (refresh.status === 'failed') return { selected: true, result: { status: 'failed', reason: refresh.detail } };
  return { selected: true, result: { status: refresh.status, ran: false, reason: refresh.detail } };
}
