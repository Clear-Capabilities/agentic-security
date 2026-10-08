// Live advisory feed for the upstream software inside a Nix closure (NIX-009 follow-on).
//
// OSV has no nixpkgs ecosystem, so the Hackage approach (ask OSV by ecosystem and package name) does not carry over. The source used
// here is the NVD CVE API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0), queried by CPE vendor:product, because a nixpkgs
// package declares its upstream identity as a CPE in meta.identifiers and NVD is the one public, machine-readable feed keyed by it.
// What it can and cannot answer is stated in docs/guides/nix-nixos.md: an identity that has no CPE (a purl or a source URL alone) is
// not something this feed is keyed by, so it is reported unknown, never clean.
//
// Contract (the same as haskell-advisory-feed.js, in the order it matters):
//   * Opt in. Nothing here touches the network unless AGENTIC_SECURITY_NIX_ADVISORIES_LIVE=1, and never when AGENTIC_SECURITY_OFFLINE=1.
//     An operator-pinned snapshot (AGENTIC_SECURITY_NIX_ADVISORIES) is used as given and is never refreshed over. A hand-written
//     nix-advisories.json in the operator configuration directory is never overwritten either.
//   * Coverage is recorded, not assumed. The snapshot lists every vendor:product it fully read and when. One it did not read, or read
//     only in part, is NOT covered and the matcher reports it unknown.
//   * Failure degrades. An unreachable or throttling feed leaves the previous snapshot in place; the scan runs on it with its age stated.
//   * Everything from the wire is untrusted: the identity is validated before it reaches a URL, responses are size-capped, a record
//     that does not name the requested product is dropped, and a cache whose records fail their own hashes is discarded.
//   * Rate limits. NVD allows 5 requests per rolling 30 seconds without an API key and 50 with one (a key is free; set
//     AGENTIC_SECURITY_NVD_API_KEY). Requests are spaced to stay under that, a throttling response stops the run instead of retrying,
//     and the number of requests per scan is capped, so a large closure fills in over several scans rather than hammering the service.

import { mkdirSync, readFileSync, writeFileSync, renameSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { operatorConfigDir } from './trusted-inputs.js';

export const FEED_ENV = 'AGENTIC_SECURITY_NIX_ADVISORIES_LIVE';
export const PINNED_ENV = 'AGENTIC_SECURITY_NIX_ADVISORIES';
export const KEY_ENV = 'AGENTIC_SECURITY_NVD_API_KEY';
export const SNAPSHOT_FILE = 'nix-advisories.json';
export const SNAPSHOT_SCHEMA = 'nix-advisories-live/1';
export const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

const DEFAULTS = Object.freeze({
  ttlMs: 24 * 3600 * 1000,        // a covered identity is not queried again inside this window
  timeoutMs: 20000,
  maxProducts: 60,                // identities considered per scan
  maxRequestsKeyless: 20,         // about 2 minutes at the keyless spacing
  maxRequestsKeyed: 120,
  intervalKeylessMs: 6500,        // 5 per 30 s, with margin
  intervalKeyedMs: 700,           // 50 per 30 s, with margin
  pageSize: 2000,                 // the NVD maximum
  maxPages: 3,
  maxResponseBytes: 32 << 20,
  maxSnapshotRecords: 30000,
});

const PART = /^[a-z0-9][a-z0-9_.+~-]{0,63}$/;       // a CPE vendor or product, in the lowercase form NVD uses; no colon, slash, quote or escape
const CVE_ID = /^CVE-\d{4}-\d{4,12}$/;
const VERSION_OK = /^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$/;
const KEY_OK = /^[0-9a-fA-F-]{20,64}$/;

/** 'vendor:product' from a full CPE 2.3 string, a {vendor, product} / {cpe} object, or a key already in that form; null if it cannot be made safely. */
export function cpeKey(x) {
  let v = null; let p = null;
  if (x && typeof x === 'object') {
    if (typeof x.vendor === 'string' && typeof x.product === 'string') { v = x.vendor; p = x.product; }
    else if (typeof x.cpe === 'string') return cpeKey(x.cpe);
    else return null;
  } else if (typeof x === 'string') {
    if (x.startsWith('cpe:2.3:')) { const parts = x.split(':'); if (parts.length < 5) return null; v = parts[3]; p = parts[4]; }
    else { const parts = x.split(':'); if (parts.length !== 2) return null; [v, p] = parts; }
  } else return null;
  v = v.toLowerCase(); p = p.toLowerCase();
  return PART.test(v) && PART.test(p) ? `${v}:${p}` : null;
}
export const validCpeKey = (k) => typeof k === 'string' && cpeKey(k) === k;

let last = null;
/** What the most recent refresh in this process did, so a "no feed" reason can say why. */
export const getLastRefresh = () => last;
export const _resetLastRefresh = () => { last = null; };

export function liveFeedEnabled(env = process.env) {
  return env[FEED_ENV] === '1' && env.AGENTIC_SECURITY_OFFLINE !== '1';
}
export function snapshotPath(env = process.env, dir = null) { return join(dir || operatorConfigDir(env), SNAPSHOT_FILE); }

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

/**
 * Validate a snapshot written by this module. Returns {ok:true, records, covered, generatedAt} or {ok:false, reason}.
 * `foreign` marks a parseable file that is not ours (a hand-written operator snapshot): not an error, and never overwritten.
 */
export function loadLiveSnapshot(raw) {
  if (!raw || typeof raw !== 'object' || raw.schema !== SNAPSHOT_SCHEMA) return { ok: false, foreign: true, reason: 'not a live-feed snapshot' };
  if (!Array.isArray(raw.records) || !raw.recordHashes || typeof raw.recordHashes !== 'object') return { ok: false, reason: 'the snapshot has no record list or no record hashes' };
  for (const rec of raw.records) {
    if (!rec || typeof rec.id !== 'string' || !CVE_ID.test(rec.id)) return { ok: false, reason: 'a record has no valid identifier' };
    if (raw.recordHashes[rec.id] !== sha256(JSON.stringify(rec))) return { ok: false, reason: `record ${rec.id} does not match its recorded hash` };
  }
  const covered = {};
  if (!raw.covered || typeof raw.covered !== 'object' || Array.isArray(raw.covered)) return { ok: false, reason: 'the coverage table is missing or malformed' };
  for (const [k, t] of Object.entries(raw.covered)) { if (!validCpeKey(k) || !Number.isFinite(Date.parse(t))) return { ok: false, reason: 'the coverage table has a malformed entry' }; covered[k] = t; }
  return { ok: true, records: raw.records, covered, generatedAt: typeof raw.generatedAt === 'string' ? raw.generatedAt : null };
}

function readCurrent(path) {
  let raw;
  try { raw = JSON.parse(readFileSync(path, 'utf8')); } catch (e) { return { records: new Map(), covered: {}, problem: e && e.code === 'ENOENT' ? null : 'the cached snapshot was unreadable and was discarded', foreign: false }; }
  const r = loadLiveSnapshot(raw);
  if (r.foreign) return { records: new Map(), covered: {}, problem: null, foreign: true };
  if (!r.ok) return { records: new Map(), covered: {}, problem: `the cached snapshot was discarded: ${r.reason}`, foreign: false };
  return { records: new Map(r.records.map((x) => [x.id, x])), covered: r.covered, problem: null, foreign: false };
}

const splitCpe = (s) => s.split(/(?<!\\):/);
const isoOrNull = (t) => {
  if (typeof t !== 'string') return null;
  const ms = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(t) ? t : `${t}Z`);   // NVD timestamps carry no zone and are UTC
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
};

/**
 * One NVD CVE object -> an OSV-style record limited to the requested vendor:product, or null when the record does not name it
 * (or is rejected, or carries nothing usable). Only `vulnerable` matches of the requested product are read; operating-system or
 * hardware conditions on a combined configuration are NOT evaluated (see the guide).
 * A start bound that is exclusive is carried as an `introduced_excluding` event, which the Nix matcher understands.
 */
export function nvdToOsv(cve, key) {
  if (!cve || typeof cve !== 'object' || typeof cve.id !== 'string' || !CVE_ID.test(cve.id)) return null;
  if (typeof cve.vulnStatus === 'string' && /^rejected$/i.test(cve.vulnStatus)) return null;
  const ranges = []; const versions = [];
  for (const cfg of Array.isArray(cve.configurations) ? cve.configurations : []) {
    for (const node of Array.isArray(cfg && cfg.nodes) ? cfg.nodes : []) {
      if (node && node.negate === true) continue;
      for (const m of Array.isArray(node && node.cpeMatch) ? node.cpeMatch : []) {
        if (!m || m.vulnerable !== true || typeof m.criteria !== 'string' || !m.criteria.startsWith('cpe:2.3:')) continue;
        const parts = splitCpe(m.criteria);
        if (parts.length < 6 || !['a', 'o', '*'].includes(parts[2]) || `${parts[3]}:${parts[4]}` !== key) continue;
        const ver = parts[5]; const upd = parts[6];
        if (ver === '*') {
          const s1 = m.versionStartIncluding; const s2 = m.versionStartExcluding; const e1 = m.versionEndIncluding; const e2 = m.versionEndExcluding;
          if ([s1, s2, e1, e2].some((x) => x !== undefined && (typeof x !== 'string' || !VERSION_OK.test(x)))) continue;
          const events = [];
          if (s1) events.push({ introduced: s1 }); else if (s2) events.push({ introduced_excluding: s2 }); else events.push({ introduced: '0' });
          if (e2) events.push({ fixed: e2 }); else if (e1) events.push({ last_affected: e1 });
          ranges.push({ type: 'ECOSYSTEM', events });
        } else if (ver !== '-' && ver !== '?') {
          const v = upd && upd !== '*' && upd !== '-' ? `${ver}-${upd}` : ver;
          if (VERSION_OK.test(v)) versions.push(v);
        }
      }
    }
  }
  if (!ranges.length && !versions.length) return null;
  const desc = (Array.isArray(cve.descriptions) ? cve.descriptions : []).find((d) => d && d.lang === 'en' && typeof d.value === 'string');
  const refs = (Array.isArray(cve.references) ? cve.references : []).map((r) => r && r.url).filter((u) => typeof u === 'string' && /^https?:\/\//.test(u) && u.length <= 300).slice(0, 5);
  return {
    id: cve.id, aliases: [], summary: desc ? desc.value.slice(0, 400) : '', published: isoOrNull(cve.published), modified: isoOrNull(cve.lastModified),
    affected: [{ package: { ecosystem: 'NVD-CPE', name: key.split(':')[1], cpe: key }, ranges, versions }],
    references: refs.map((url) => ({ type: 'WEB', url })), database_specific: { source: 'nvd-cve-2.0' },
  };
}

const sleepReal = (ms) => new Promise((r) => setTimeout(r, ms));

async function getJson(fetchImpl, url, headers, timeoutMs, maxBytes) {
  const resp = await fetchImpl(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
  if (!resp) throw Object.assign(new Error('no response'), { http: 0 });
  if (resp.status !== 200) throw Object.assign(new Error(`HTTP ${resp.status}`), { http: resp.status });
  const text = await resp.text();
  if (Buffer.byteLength(text) > maxBytes) throw new Error('response too large');
  return JSON.parse(text);
}

/**
 * Refresh the operator's Nix advisory snapshot for the given CPE identities ('vendor:product' keys or anything cpeKey accepts).
 * Never throws. Returns a plain result; the snapshot file is rewritten only when something was read.
 *
 * @param {Array<string|object>} identities
 * @param {{env?: object, fetchImpl?: Function, now?: number, dir?: string, sleep?: Function}} [opts]
 */
export async function refreshNixAdvisories(identities, opts = {}) {
  const env = opts.env || process.env;
  const cfg = { ...DEFAULTS, ...Object.fromEntries(Object.entries(opts).filter(([k]) => k in DEFAULTS)) };
  const now = opts.now ?? Date.now();
  const done = (r) => { last = { ...r, at: new Date(now).toISOString() }; return last; };

  if (env[PINNED_ENV]) return done({ status: 'pinned-snapshot-in-use', detail: `${PINNED_ENV} names an operator snapshot; it is used as given and is not refreshed` });
  if (env[FEED_ENV] !== '1') return done({ status: 'disabled', detail: `set ${FEED_ENV}=1 to fetch advisories for the closure's upstream software from the NVD` });
  if (env.AGENTIC_SECURITY_OFFLINE === '1') return done({ status: 'offline', detail: 'AGENTIC_SECURITY_OFFLINE=1: no advisory data was fetched' });

  const all = (identities || []).map(cpeKey);
  const invalid = all.filter((k) => !k).length;
  const wanted = [...new Set(all.filter(Boolean))].sort().slice(0, cfg.maxProducts);
  if (!wanted.length) return done({ status: 'nothing-to-do', detail: invalid ? `${invalid} identity value(s) were not valid CPE vendor:product names and were not queried` : 'the closure declares no CPE identity to look up', invalid });

  const path = snapshotPath(env, opts.dir);
  const cur = readCurrent(path);
  if (cur.foreign) return done({ status: 'operator-snapshot-in-use', detail: `${path} is an operator-written snapshot; it is used as given and the live feed does not overwrite it` });
  const need = wanted.filter((k) => { const t = Date.parse(cur.covered[k]); return !Number.isFinite(t) || now - t > cfg.ttlMs || t > now + 3600000; });
  if (!need.length) return done({ status: 'current', detail: `${wanted.length} identity(ies) covered within the last ${Math.round(cfg.ttlMs / 3600000)}h; no request made`, identities: wanted.length, requested: 0 });

  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') return done({ status: 'failed', detail: 'no fetch implementation is available in this runtime' });
  const sleep = opts.sleep || sleepReal;
  const apiKey = typeof env[KEY_ENV] === 'string' && KEY_OK.test(env[KEY_ENV]) ? env[KEY_ENV] : null;
  const keyNote = env[KEY_ENV] && !apiKey ? ` (${KEY_ENV} is set but is not a valid key; it was ignored)` : '';
  const headers = { 'User-Agent': 'agentic-security-advisory-feed', Accept: 'application/json', ...(apiKey ? { apiKey } : {}) };
  const interval = apiKey ? cfg.intervalKeyedMs : cfg.intervalKeylessMs;
  const maxRequests = apiKey ? cfg.maxRequestsKeyed : cfg.maxRequestsKeyless;

  let requests = 0; let throttled = false; let dropped = 0;
  const failures = []; const fresh = new Map();      // key -> Map(cveId -> record)
  const request = async (url) => { if (requests > 0) await sleep(interval); requests++; return getJson(fetchImpl, url, headers, cfg.timeoutMs, cfg.maxResponseBytes); };

  for (const key of need) {
    if (throttled) { failures.push(`${key}: not queried (the service signalled a rate limit)`); continue; }
    if (requests >= maxRequests) { failures.push(`${key}: not queried (per-scan request cap of ${maxRequests} reached; a later scan will cover it)`); continue; }
    const recs = new Map();
    try {
      let start = 0; let total = null; let seen = 0;
      for (let page = 0; page < cfg.maxPages; page++) {
        if (page > 0 && requests >= maxRequests) throw new Error('per-scan request cap reached part-way through this identity');
        const url = `${NVD_BASE}?virtualMatchString=${encodeURIComponent(`cpe:2.3:*:${key}`)}&resultsPerPage=${cfg.pageSize}&startIndex=${start}`;
        const data = await request(url);
        if (!data || typeof data !== 'object' || !Array.isArray(data.vulnerabilities) || !Number.isInteger(data.totalResults) || data.totalResults < 0 || data.startIndex !== start) throw new Error('the response is not a CVE 2.0 page for this request');
        if (total === null) { total = data.totalResults; if (total > cfg.pageSize * cfg.maxPages) throw new Error(`${total} CVEs name this product, more than the ${cfg.pageSize * cfg.maxPages} this feed reads; not treated as covered`); }
        else if (data.totalResults !== total) throw new Error('the result set changed while it was being read');
        for (const v of data.vulnerabilities) {
          const rec = nvdToOsv(v && v.cve, key);
          if (rec) recs.set(rec.id, rec); else dropped++;
        }
        seen += data.vulnerabilities.length; start += data.vulnerabilities.length;
        if (seen >= total || !data.vulnerabilities.length) break;
      }
      if (seen < total) throw new Error('the result set was not read to the end');
      fresh.set(key, recs);
    } catch (e) {
      const http = e && e.http;
      if (http === 403 || http === 429 || http === 503) throttled = true;
      failures.push(`${key}: ${String((e && e.message) || e).slice(0, 100)}`);
    }
  }

  const uncovered = need.filter((k) => !fresh.has(k));
  if (!fresh.size) return done({ status: 'failed', detail: `the NVD feed could not be read (${failures.slice(0, 2).join('; ') || 'no response'}); ${cur.records.size ? 'the previous snapshot is used and its age is disclosed' : 'no advisory data is available'}${keyNote}`, identities: wanted.length, requested: need.length, requests, uncovered, failures: failures.slice(0, 10), throttled, cacheProblem: cur.problem });

  // merge: for each fully read identity, replace what the cache held for it and keep everything else
  const records = new Map([...cur.records].map(([id, r]) => [id, { ...r, affected: [...(r.affected || [])] }]));
  for (const [key, recs] of fresh) {
    for (const [id, r] of [...records]) { r.affected = r.affected.filter((a) => !(a.package && a.package.cpe === key)); if (!r.affected.length) records.delete(id); }
    for (const [id, rec] of recs) {
      const have = records.get(id);
      if (have) have.affected.push(...rec.affected); else records.set(id, rec);
    }
  }
  if (records.size > cfg.maxSnapshotRecords) return done({ status: 'failed', detail: `the snapshot would exceed ${cfg.maxSnapshotRecords} records; refusing to write it`, identities: wanted.length, requested: need.length, uncovered });
  const covered = { ...cur.covered };
  const iso = new Date(now).toISOString();
  for (const k of fresh.keys()) covered[k] = iso;

  const sorted = [...records.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
  const snap = {
    schema: SNAPSHOT_SCHEMA, source: 'nvd-cve-2.0', generatedAt: iso, records: sorted,
    recordHashes: Object.fromEntries(sorted.map((r) => [r.id, sha256(JSON.stringify(r))])),
    covered: Object.fromEntries(Object.entries(covered).sort(([a], [b]) => (a < b ? -1 : 1))),
  };
  try {
    const dir = opts.dir || operatorConfigDir(env);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(snap), { mode: 0o600 });
    try { chmodSync(tmp, 0o600); } catch { /* best effort on filesystems without modes */ }
    renameSync(tmp, path);
  } catch (e) {
    return done({ status: 'failed', detail: `the snapshot could not be written: ${e.code || e.message}`, identities: wanted.length, requested: need.length, uncovered });
  }
  return done({
    status: uncovered.length ? 'partial' : 'refreshed',
    detail: `${fresh.size} identity(ies) covered in ${requests} request(s)${uncovered.length ? `; ${uncovered.length} NOT covered (${uncovered.slice(0, 3).join(', ')}${uncovered.length > 3 ? ', ...' : ''}) and will be reported as unknown` : ''}${throttled ? '; the service signalled a rate limit and the run stopped' : ''}${apiKey ? '' : `; no ${KEY_ENV} set (keyless limit: 5 requests per 30 s)`}${keyNote}`,
    identities: wanted.length, requested: need.length, requests, records: records.size, dropped, uncovered, failures: failures.slice(0, 10), throttled, path, cacheProblem: cur.problem,
  });
}
