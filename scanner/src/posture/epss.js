// EPSS exploit-prediction enrichment.
//
// EPSS (Exploit Prediction Scoring System, FIRST.org) gives every CVE a
// probability of being exploited in the next 30 days plus a percentile rank.
// Layered on top of CISA KEV, this lets us distinguish "theoretical" CVEs
// from those attackers are actively weaponizing.
//
// Decoration shape (added to each SCA finding with a CVE):
//   epssScore: 0.92345   (this comment previously said `epss:`; the code has
//                         always written `epssScore` — the comment was wrong,
//                         not the code)
//   epssPercentile: 0.987
//   exploitedNow: true   ← percentile >= 0.95
//
// ⚠ engine.js ALSO sets f.epssScore/f.epssPercentile directly (around line
// 6451), independently of this module's fetchEPSS/decorate path — two
// implementations of the same decoration. This module's own `fetchEPSS` has
// no in-tree caller (allowlisted in no-dead-modules.test.js as future-public
// API); the live path is the one in engine.js. Worth consolidating, not
// resolved here.
//
// Source: https://api.first.org/data/v1/epss?cve=CVE-...,CVE-...
// Cached on disk: ~/.claude/agentic-security/epss-cache/<sha256>.json
// 24-hour TTL. Falls back gracefully when offline.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';

const CACHE_DIR = path.join(os.homedir(), '.claude', 'agentic-security', 'epss-cache');
const TTL_MS = 24 * 60 * 60 * 1000;
const EXPLOITED_NOW_THRESHOLD = 0.95; // percentile

function ensureCache() { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); } catch {} }
function cachePath(cveListKey) {
  const h = crypto.createHash('sha256').update(cveListKey).digest('hex');
  return path.join(CACHE_DIR, h + '.json');
}

function readCache(key) {
  const fp = cachePath(key);
  if (!fs.existsSync(fp)) return null;
  try {
    const stat = fs.statSync(fp);
    if (Date.now() - stat.mtimeMs > TTL_MS) return null;
    return JSON.parse(fs.readFileSync(fp, 'utf8'));
  } catch { return null; }
}

function writeCache(key, data) {
  ensureCache();
  try { fs.writeFileSync(cachePath(key), JSON.stringify(data)); } catch {}
}

// Returns Map<CVE, {epss: number, percentile: number}> for the supplied CVE IDs.
// Batched in groups of 100 to keep URLs short.
export async function fetchEPSS(cveIds) {
  const out = new Map();
  if (!cveIds || cveIds.length === 0) return out;
  if (process.env.AGENTIC_SECURITY_OFFLINE === '1') {
    // Try cache anyway — return whatever we have.
    const k = [...cveIds].sort().join(',');
    const c = readCache(k);
    if (c) for (const [cve, v] of Object.entries(c)) out.set(cve, v);
    return out;
  }
  const unique = [...new Set(cveIds)].filter(c => /^CVE-\d{4}-\d{4,}$/i.test(c));
  if (!unique.length) return out;

  const cached = readCache([...unique].sort().join(','));
  if (cached) {
    for (const [cve, v] of Object.entries(cached)) out.set(cve, v);
    return out;
  }

  const fresh = {};
  for (let i = 0; i < unique.length; i += 100) {
    const batch = unique.slice(i, i + 100);
    const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(batch.join(','))}`;
    try {
      const res = await fetch(url, { headers: { 'User-Agent': 'agentic-security' } });
      if (!res.ok) continue;
      const body = await res.json();
      for (const row of (body.data || [])) {
        const epss = parseFloat(row.epss);
        const percentile = parseFloat(row.percentile);
        if (Number.isFinite(epss) && Number.isFinite(percentile)) {
          const v = { epss, percentile };
          out.set(row.cve, v);
          fresh[row.cve] = v;
        }
      }
    } catch { /* network error → caller continues without enrichment */ }
  }
  if (Object.keys(fresh).length) writeCache([...unique].sort().join(','), fresh);
  return out;
}

// Extract CVE IDs from a finding regardless of where they live in the schema.
function cvesIn(finding) {
  const found = new Set();
  if (typeof finding.cve === 'string') found.add(finding.cve.toUpperCase());
  if (Array.isArray(finding.cves)) for (const c of finding.cves) found.add(String(c).toUpperCase());
  if (Array.isArray(finding.vulnerabilities)) {
    for (const v of finding.vulnerabilities) {
      if (typeof v.id === 'string' && v.id.startsWith('CVE-')) found.add(v.id.toUpperCase());
      if (Array.isArray(v.aliases)) for (const a of v.aliases) {
        if (typeof a === 'string' && a.startsWith('CVE-')) found.add(a.toUpperCase());
      }
    }
  }
  // Fallback: scan title/description for CVE refs.
  for (const k of ['title', 'description', 'vuln']) {
    const v = finding[k];
    if (typeof v === 'string') {
      const m = v.match(/\bCVE-\d{4}-\d{4,}\b/gi);
      if (m) for (const c of m) found.add(c.toUpperCase());
    }
  }
  return [...found];
}

// Decorate every SCA finding (and any other finding with a CVE) in place.
// Returns { decorated, exploitedNow }.
export async function enrichWithEPSS(scan) {
  const buckets = ['supplyChain', 'findings'];
  const allCves = new Set();
  for (const b of buckets) {
    for (const f of (scan[b] || [])) {
      for (const c of cvesIn(f)) allCves.add(c);
    }
  }
  if (allCves.size === 0) return { decorated: 0, exploitedNow: 0 };

  const epssMap = await fetchEPSS([...allCves]);
  let decorated = 0, exploitedNow = 0;

  for (const b of buckets) {
    for (const f of (scan[b] || [])) {
      const cves = cvesIn(f);
      let bestEpss = 0, bestPct = 0, bestCve = null;
      for (const c of cves) {
        const v = epssMap.get(c);
        if (v && v.epss > bestEpss) { bestEpss = v.epss; bestPct = v.percentile; bestCve = c; }
      }
      if (bestCve) {
        f.epssScore = bestEpss;
        f.epssPercentile = bestPct;
        f.epssCve = bestCve;
        if (bestPct >= EXPLOITED_NOW_THRESHOLD) {
          f.exploitedNow = true;
          exploitedNow++;
          // Bump severity one notch for actively-exploited CVEs (medium → high → critical).
          if (f.severity === 'medium') f.severity = 'high';
          else if (f.severity === 'high') f.severity = 'critical';
          if (!Array.isArray(f.tags)) f.tags = [];
          if (!f.tags.includes('exploited-now')) f.tags.push('exploited-now');
        }
        decorated++;
      }
    }
  }
  return { decorated, exploitedNow };
}
