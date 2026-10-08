// Draws the adjudication sample from results.json, deterministically (seeded), so the draw is reproducible and not cherry-picked.
// Strata (quota): affected-resolved, affected-declared, possibly-affected, not-affected, unknown, ghc-component:*. At most MAX_PER_PROJECT rows
// per project, identical (project, package, version-or-range, advisory, status) rows collapsed. Prints the sample with the advisory's
// affected events (from the records the feed fetched) for the adjudicator to read; it assigns NO verdicts.
// Usage: node bench/live-feed/sample.mjs [--seed N] [--records records.json] > sample.json
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
const SEED = Number(opt('seed', 20261007));
const QUOTA = { 'affected-resolved': 7, 'affected-declared': 3, 'possibly-affected': 10, 'not-affected': 8, unknown: 4, ghc: 8 };
const MAX_PER_PROJECT = 3;

function rng(seed) { let a = seed >>> 0; return () => { a += 0x6D2B79F5; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const rand = rng(SEED);

const results = JSON.parse(readFileSync(join(HERE, 'results.json'), 'utf8'));
const records = existsSync(opt('records', '')) ? JSON.parse(readFileSync(opt('records'), 'utf8')) : {};
const stratum = (r) => (r.status.startsWith('ghc-component') ? 'ghc' : r.status === 'affected' ? (r.version ? 'affected-resolved' : 'affected-declared') : r.status);

const pool = {};
const seen = new Set();
for (const p of Object.values(results.projects)) {
  for (const r of (p.statuses && p.statuses.rows) || []) {
    const key = [p.id, r.name, r.version || r.declaredRange || '', r.advisory, r.status].join('|');
    if (seen.has(key)) continue; seen.add(key);
    (pool[stratum(r)] ||= []).push({ project: p.id, package: r.name, version: r.version || null, declaredRange: r.declaredRange || null, advisory: r.advisory, status: r.status, reason: r.reason });
  }
}
const shuffle = (a) => { const b = [...a]; for (let i = b.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [b[i], b[j]] = [b[j], b[i]]; } return b; };
const perProject = {};
const sample = [];
for (const [s, n] of Object.entries(QUOTA)) {
  let taken = 0;
  // prefer projects not yet represented, so the sample spreads across projects
  const cand = shuffle(pool[s] || []).sort((a, b) => (perProject[a.project] || 0) - (perProject[b.project] || 0));
  for (const c of cand) {
    if (taken >= n) break;
    if ((perProject[c.project] || 0) >= MAX_PER_PROJECT) continue;
    perProject[c.project] = (perProject[c.project] || 0) + 1; taken++;
    const rec = records[c.advisory];
    sample.push({ stratum: s, ...c, summary: rec ? rec.summary : null, affectedEvents: rec ? rec.affected.filter((a) => a.package.name === c.package).map((a) => a.ranges.map((r) => r.events)) : null });
  }
}
process.stdout.write(`${JSON.stringify({ seed: SEED, quota: QUOTA, maxPerProject: MAX_PER_PROJECT, poolSizes: Object.fromEntries(Object.entries(pool).map(([k, v]) => [k, v.length])), sample }, null, 1)}\n`);
