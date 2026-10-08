#!/usr/bin/env node
// Live Hackage advisory feed measurement harness. Needs the network; it is NOT part of `npm test` or any gate.
//
//   node bench/live-feed/run.mjs fetch  [--cache DIR]                       download + verify every corpus tarball
//   node bench/live-feed/run.mjs plan  [--cabal-dir DIR]                    generate cabal plans for the cabal-plan entries (needs cabal + an updated index)
//   node bench/live-feed/run.mjs scan   [--only id,id] [--limit N] ...      run the live / warm / offline scans, write results
//   node bench/live-feed/run.mjs sample [--records FILE]                    draw the (seeded) adjudication sample
//   node bench/live-feed/run.mjs report                                      (re)build RESULTS.md from results.json + adjudication.json
//
// Everything third-party (tarballs, extracted trees, per-run operator config, scan output) lives under the cache/work directories,
// by default under the OS temp dir, never in the repository. See README.md for the exact procedure.
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, statSync, readdirSync } from 'node:fs';
import { tmpdir, loadavg, cpus } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');
const SCANNER = join(REPO, 'scanner');
const UA = 'agentic-security-live-feed-bench/1 (+https://github.com/Clear-Capabilities/agentic-security; ross@clearcapabilities.com)';
const corpus = JSON.parse(readFileSync(join(HERE, 'corpus.json'), 'utf8'));

const argv = process.argv.slice(2);
const cmd = argv[0];
const opt = (name, dflt = null) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true) : dflt; };
const CACHE = resolve(opt('cache', process.env.LIVE_FEED_CACHE || join(tmpdir(), 'agentic-security-live-feed', 'cache')));
const WORK = resolve(opt('work', process.env.LIVE_FEED_WORK || join(tmpdir(), 'agentic-security-live-feed', 'work')));
const CABAL_DIR = resolve(opt('cabal-dir', process.env.LIVE_FEED_CABAL_DIR || join(tmpdir(), 'agentic-security-live-feed', 'cabal')));
const TIMEOUT_MS = Number(opt('timeout-min', 20)) * 60000;
const RESULTS = resolve(opt('results', join(HERE, 'results.json')));

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const selected = () => {
  let list = corpus.projects;
  const only = opt('only'); if (only && only !== true) { const s = new Set(String(only).split(',')); list = list.filter((p) => s.has(p.id)); }
  const limit = Number(opt('limit', 0)); if (limit) list = list.slice(0, limit);
  const except = opt('except'); if (except && except !== true) { const s = new Set(String(except).split(',')); list = list.filter((p) => !s.has(p.id)); }
  const done = opt('done'); if (done && done !== true) { const have = new Set(); for (const f of String(done).split(',')) { try { for (const [id, r] of Object.entries(JSON.parse(readFileSync(resolve(f), 'utf8')).projects)) if (!r.error) have.add(id); } catch { /* missing file: nothing done */ } } list = list.filter((p) => !have.has(p.id)); }
  const shard = opt('shard'); if (shard && shard !== true) { const [k, n] = String(shard).split('/').map(Number); list = list.filter((_, i) => i % n === k); }
  return list;
};
const tarball = (p) => join(CACHE, `${p.tarballId || p.id}.tar.gz`);

// ── fetch ────────────────────────────────────────────────────────────────────
async function fetchAll() {
  mkdirSync(CACHE, { recursive: true });
  const seen = new Set();
  let bad = 0;
  for (const p of selected()) {
    const file = tarball(p);
    if (seen.has(file)) continue; seen.add(file);
    if (!existsSync(file)) {
      const r = await fetch(p.source.url, { headers: { 'User-Agent': UA }, redirect: 'follow', signal: AbortSignal.timeout(300000) });
      if (r.status !== 200) { console.log(`FAIL ${p.id}: HTTP ${r.status}`); bad++; continue; }
      writeFileSync(file, Buffer.from(await r.arrayBuffer()));
      await sleep(500);
    }
    const got = sha256(readFileSync(file));
    if (got !== p.sha256) { console.log(`MISMATCH ${p.id}: corpus ${p.sha256} downloaded ${got}`); bad++; } else console.log(`ok ${p.id}`);
  }
  if (bad) { console.log(`${bad} problem(s)`); process.exitCode = 1; }
}

// ── scan ─────────────────────────────────────────────────────────────────────
function extract(p) {
  const dir = join(WORK, p.id, 'src');
  if (existsSync(join(dir, '.extracted'))) return dir;
  rmSync(join(WORK, p.id), { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  execFileSync('tar', ['-xzf', tarball(p), '--strip-components=1', '-C', dir], { stdio: 'pipe' });
  writeFileSync(join(dir, '.extracted'), '');
  return dir;
}

function makePlan(p, dir) {
  if (p.resolution !== 'cabal-plan') return null;
  if (opt('regen-plan')) rmSync(join(dir, 'dist-newstyle'), { recursive: true, force: true });
  if (existsSync(join(dir, 'dist-newstyle/cache/plan.json'))) return { ok: true, cached: true };
  if (!existsSync(join(CABAL_DIR, 'packages'))) return { ok: false, error: `no cabal package index under ${CABAL_DIR}; run: CABAL_DIR=${CABAL_DIR} cabal update` };
  const t0 = Date.now();
  // Tests and benchmarks are enabled so their dependencies are resolved too; if that does not solve, fall back to the default plan.
  let last = null;
  for (const extra of [['--enable-tests', '--enable-benchmarks'], []]) {
    last = spawnSync('cabal', ['build', '--dry-run', 'all', ...extra, `--index-state=${corpus.indexState}`, '--offline'], { cwd: dir, env: { ...process.env, CABAL_DIR }, encoding: 'utf8', timeout: 300000 });
    if (last.status === 0 && existsSync(join(dir, 'dist-newstyle/cache/plan.json'))) return { ok: true, ms: Date.now() - t0, testsAndBenchmarks: extra.length > 0, error: null };
    rmSync(join(dir, 'dist-newstyle'), { recursive: true, force: true });
  }
  return { ok: false, ms: Date.now() - t0, error: String(last.stderr || last.stdout || last.error || '').split('\n').slice(0, 6).join(' | ').slice(0, 400) };
}

async function runCli(dir, { xdg, home, extraArgs = [], env = {}, out }) {
  mkdirSync(xdg, { recursive: true }); mkdirSync(home, { recursive: true });
  const reqLog = `${out}.requests.jsonl`;
  rmSync(reqLog, { force: true }); rmSync(out, { force: true });
  const load1 = Number(loadavg()[0].toFixed(1));
  const t0 = Date.now();
  const inner = [process.execPath, '--import', join(HERE, 'request-log.mjs'), join(SCANNER, 'bin/agentic-security.js'), 'scan', dir, '--format', 'json', '--output', out, ...extraArgs];
  // /usr/bin/time reports the child's CPU seconds, which (unlike wall time) does not inflate when the machine is busy.
  const timer = process.platform === 'darwin' && existsSync('/usr/bin/time') ? ['/usr/bin/time', '-p'] : (process.platform === 'linux' && existsSync('/usr/bin/time') ? ['/usr/bin/time', '-p'] : null);
  const argvFull = timer ? [...timer, ...inner] : inner;
  // Async + its own process group, so a timeout kills the scan AND its worker processes (spawnSync's timeout would kill only the timer wrapper).
  const r = await new Promise((done) => {
    const child = spawn(argvFull[0], argvFull.slice(1), { env: { ...process.env, HOME: home, XDG_CONFIG_HOME: xdg, LIVE_FEED_REQUEST_LOG: reqLog, ...env }, detached: true, stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = ''; let timedOut = false;
    child.stderr.on('data', (d) => { if (stderr.length < 1 << 20) stderr += d; });
    const killer = setTimeout(() => { timedOut = true; try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ } }, TIMEOUT_MS);
    child.on('close', (status, signal) => { clearTimeout(killer); done({ status, signal, stderr, error: timedOut ? { code: 'ETIMEDOUT' } : null }); });
  });
  const wallMs = Date.now() - t0;
  let cpuMs = null;
  { const u = /user\s+([\d.]+)/.exec(String(r.stderr || '')); const y = /sys\s+([\d.]+)/.exec(String(r.stderr || '')); if (u && y) cpuMs = Math.round((Number(u[1]) + Number(y[1])) * 1000); }
  const requests = existsSync(reqLog) ? readFileSync(reqLog, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
  let scan = null; let parseError = null;
  try { scan = JSON.parse(readFileSync(out, 'utf8')); } catch (e) { parseError = String(e.message).slice(0, 120); }
  return { load1, wallMs, cpuMs, exit: r.status, signal: r.signal, timedOut: r.error && r.error.code === 'ETIMEDOUT', stderrTail: String(r.stderr || '').replace(/\n?(real|user|sys)\s+[\d.]+/g, '').slice(-300), requests, scan, parseError };
}

const isOsv = (r) => /^https:\/\/api\.osv\.dev\//.test(r.url);
function summariseRequests(reqs) {
  const osv = reqs.filter(isOsv);
  // Only requests the request logger attributed to the Hackage feed count as "the feed": the scanner's ordinary npm / PyPI / Maven
  // lookups share api.osv.dev, and are reported separately.
  const feed = osv.filter((r) => r.feed === true);
  const batches = feed.filter((r) => /\/v1\/querybatch$/.test(r.url));
  const vulns = feed.filter((r) => /\/v1\/vulns\//.test(r.url));
  const span = feed.length ? Math.max(...feed.map((r) => r.t1)) - Math.min(...feed.map((r) => r.t0)) : 0;
  return {
    total: reqs.length,
    feedRequests: feed.length,
    osvRequests: osv.length,
    osvOtherEcosystemRequests: osv.length - feed.length,
    otherHosts: [...new Set(reqs.filter((r) => !isOsv(r)).map((r) => { try { return new URL(r.url).host; } catch { return '?'; } }))],
    otherRequests: reqs.length - osv.length,
    batchQueries: batches.length,
    batchStatuses: count(batches.map((r) => r.status ?? 'error')),
    packagesQueried: batches.reduce((n, r) => n + ((r.batch && r.batch.queried) || 0), 0),
    packagesWithAdvisories: batches.reduce((n, r) => n + ((r.batch && r.batch.withVulns) || 0), 0),
    nextPageTokens: batches.reduce((n, r) => n + ((r.batch && r.batch.nextPage) || 0), 0),
    recordRequests: vulns.length,
    recordsFetched: vulns.filter((r) => r.status === 200).length,
    recordFailures: vulns.filter((r) => r.status !== 200).map((r) => ({ id: r.url.split('/').pop(), status: r.status, error: r.error || null })),
    lookupSpanMs: span,
    lookupSumRequestMs: feed.reduce((n, r) => n + (r.t1 - r.t0), 0),
  };
}
const count = (arr) => arr.reduce((m, k) => { m[k] = (m[k] || 0) + 1; return m; }, {});

function summariseScan(c) {
  const s = c.scan;
  const base = { load1: c.load1, wallMs: c.wallMs, cpuMs: c.cpuMs, exit: c.exit, timedOut: !!c.timedOut, signal: c.signal || null, parseError: c.parseError, requests: summariseRequests(c.requests) };
  if (!s) return { ...base, stderrTail: c.stderrTail };
  const hk = (s.findings || []).filter((f) => f.ecosystem === 'hackage');
  const lc = s.scanHealth && s.scanHealth.languageCoverage;
  return {
    ...base,
    engineDurationMs: s.durationMs ?? null,
    filesScanned: s.scanned ?? null,
    scanHealth: { status: s.scanHealth && s.scanHealth.status, conditions: (s.scanHealth && s.scanHealth.conditions) || [], hackageLiveMode: lc && lc.optionalModes && lc.optionalModes['hackage-live'] || null, scaCapability: lc && lc.capabilities && lc.capabilities.haskell && lc.capabilities.haskell.sca || null },
    hackageFindingsInScanJson: hk.length,
    hackageFindingFieldsPresent: hk.length ? { matchStatus: 'matchStatus' in hk[0], declaredRange: 'declaredRange' in hk[0], reason: 'matchReason' in hk[0] } : null,
  };
}

function evalStatuses(dir, xdg, home, env = {}) {
  const r = spawnSync(process.execPath, [join(HERE, 'eval-statuses.mjs'), SCANNER, dir], { env: { ...process.env, HOME: home, XDG_CONFIG_HOME: xdg, ...env }, encoding: 'utf8', maxBuffer: 1 << 28, timeout: 300000 });
  try { return JSON.parse(r.stdout); } catch { return { error: String(r.stderr || r.error || 'no output').slice(0, 400) }; }
}

function reducedTree(dir, p) {
  const out = join(WORK, p.id, 'src-reduced');
  rmSync(out, { recursive: true, force: true });
  const keep = /(?:^|\/)(?:[^/]+\.cabal|cabal\.project(?:\.[a-z]+)?|package\.yaml|stack\.yaml(?:\.lock)?|dist-newstyle\/cache\/plan\.json)$/;
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      if (['.git', 'node_modules', '.agentic-security', '.stack-work'].includes(name)) continue;
      const f = join(d, name); const rel = f.slice(dir.length + 1);
      let st; try { st = statSync(f); } catch { continue; }
      if (st.isDirectory()) walk(f);
      else if (keep.test(rel) && st.size < 20 * 1024 * 1024) { mkdirSync(dirname(join(out, rel)), { recursive: true }); writeFileSync(join(out, rel), readFileSync(f)); }
    }
  };
  walk(dir);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'Main.hs'), 'module Main where\nmain :: IO ()\nmain = pure ()\n');
  return out;
}

async function scanAll() {
  mkdirSync(WORK, { recursive: true });
  const home = join(WORK, 'home');            // isolated HOME: the KEV/EPSS caches and any operator state land here, never in the real one
  const prior = existsSync(RESULTS) ? JSON.parse(readFileSync(RESULTS, 'utf8')) : { projects: {} };
  const results = { ...prior, projects: { ...prior.projects } };
  const list = selected();
  for (const [i, p] of list.entries()) {
    if (opt('resume') && results.projects[p.id] && !results.projects[p.id].error) { console.log(`[${i + 1}/${list.length}] ${p.id}: kept`); continue; }
    const t0 = Date.now();
    console.log(`[${i + 1}/${list.length}] ${p.id}`);
    const rec = { id: p.id, name: p.name, version: p.version, kind: p.kind, resolution: p.resolution };
    try {
      if (!existsSync(tarball(p))) throw new Error(`tarball not in cache (${tarball(p)}); run fetch`);
      if (sha256(readFileSync(tarball(p))) !== p.sha256) throw new Error('tarball sha256 does not match corpus.json');
      const dir = extract(p);
      rec.plan = makePlan(p, dir);
      const live = { AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE: '1' };
      const phases = async (scanDir, tag) => {
        const xdgCold = join(WORK, p.id, `xdg-live${tag}`);
        rmSync(xdgCold, { recursive: true, force: true });
        const cold = await runCli(scanDir, { xdg: xdgCold, home, env: live, out: join(WORK, p.id, `cold${tag}.json`) });
        const out = { cold: summariseScan(cold) };
        // The feed lookup runs near the END of a scan (after file analysis), so a scan killed by the budget never reached it.
        if (cold.timedOut) return { ...out, timedOut: true };
        out.statuses = evalStatuses(scanDir, xdgCold, home);
        out.snapshotBytes = (() => { try { return statSync(join(xdgCold, 'agentic-security', 'hackage-advisories.json')).size; } catch { return null; } })();
        if (!opt('skip-repeats')) {
          out.warm = summariseScan(await runCli(scanDir, { xdg: xdgCold, home, env: live, out: join(WORK, p.id, `warm${tag}.json`) }));
          const off1 = join(WORK, p.id, `xdg-off1${tag}`); rmSync(off1, { recursive: true, force: true });
          out.offlineFlag = summariseScan(await runCli(scanDir, { xdg: off1, home, env: live, extraArgs: ['--no-network'], out: join(WORK, p.id, `off-flag${tag}.json`) }));
          const off2 = join(WORK, p.id, `xdg-off2${tag}`); rmSync(off2, { recursive: true, force: true });
          out.offlineEnv = summariseScan(await runCli(scanDir, { xdg: off2, home, env: { ...live, AGENTIC_SECURITY_OFFLINE: '1' }, out: join(WORK, p.id, `off-env${tag}.json`) }));
        }
        return out;
      };
      let r = await phases(dir, '');
      if (r.timedOut) {
        // Fall back to a manifests-only copy of the same project (every Cabal / Stack / project file, any plan, one stub module): the
        // feed lookup, its coverage, the TTL behaviour and the offline guarantees are identical, but the scan time is NOT the real project's.
        rec.fullScanTimedOut = { budgetMin: TIMEOUT_MS / 60000, wallMs: r.cold.wallMs, cpuMs: r.cold.cpuMs, requestsBeforeKill: r.cold.requests.total };
        r = await phases(reducedTree(dir, p), '-reduced');
        rec.reducedTree = true;
      }
      Object.assign(rec, r);
    } catch (e) { rec.error = String((e && e.message) || e).slice(0, 400); }
    rec.harnessMs = Date.now() - t0;
    results.projects[p.id] = rec;
    results.meta = { ...(results.meta || {}), updatedAt: new Date().toISOString(), cpus: cpus().length, platform: `${process.platform}-${process.arch}`, node: process.version };
    writeFileSync(RESULTS, JSON.stringify(results, null, 1));
    if (!opt('keep-work')) { for (const f of readdirSync(join(WORK, p.id))) if (/\.json$|\.jsonl$/.test(f)) rmSync(join(WORK, p.id, f), { force: true }); }
    await sleep(Number(opt('pause-ms', 300)));
  }
}

function mergeResults() {
  const files = argv.slice(1).filter((a) => /\.json$/.test(a) && resolve(a) !== RESULTS && existsSync(resolve(a)));
  const merged = { meta: {}, projects: {} };
  for (const f of files) { const r = JSON.parse(readFileSync(resolve(f), 'utf8')); merged.meta = { ...merged.meta, ...r.meta }; Object.assign(merged.projects, r.projects); }
  const order = new Map(corpus.projects.map((p, i) => [p.id, i]));
  merged.projects = Object.fromEntries(Object.entries(merged.projects).sort(([a], [b]) => (order.get(a) ?? 1e9) - (order.get(b) ?? 1e9)));
  writeFileSync(RESULTS, JSON.stringify(merged, null, 1));
  console.log(`merged ${Object.keys(merged.projects).length} project(s) into ${RESULTS}`);
}

// Re-evaluates every project's statuses against the snapshot its cold scan wrote, with the code as it is NOW. Used after a matcher fix:
// the scan-time statuses are kept as `statusesAtScan`, so the effect of the fix is visible rather than silently replacing the old numbers.
function reevalAll() {
  const home = join(WORK, 'home');
  const results = JSON.parse(readFileSync(RESULTS, 'utf8'));
  for (const p of Object.values(results.projects)) {
    if (!p.statuses || p.statuses.error) continue;
    const tag = p.reducedTree ? '-reduced' : '';
    const dir = p.reducedTree ? join(WORK, p.id, 'src-reduced') : join(WORK, p.id, 'src');
    const xdg = join(WORK, p.id, `xdg-live${tag}`);
    if (!existsSync(dir) || !existsSync(xdg)) { console.log(`${p.id}: tree or snapshot missing, kept`); continue; }
    const now = evalStatuses(dir, xdg, home);
    if (now.error) { console.log(`${p.id}: ${now.error}`); continue; }
    p.statusesAtScan = p.statusesAtScan || p.statuses;
    p.statuses = now;
    console.log(`${p.id}: ${JSON.stringify(now.statusRows)}`);
  }
  results.meta = { ...(results.meta || {}), reevaluatedAt: new Date().toISOString() };
  writeFileSync(RESULTS, JSON.stringify(results, null, 1));
}

async function planOnly() {
  mkdirSync(WORK, { recursive: true });
  for (const p of selected().filter((x) => x.resolution === 'cabal-plan')) {
    const dir = extract(p);
    const r = makePlan(p, dir);
    console.log(p.id, r.ok ? `plan ok (${r.ms ?? 'cached'} ms)` : `plan FAILED: ${r.error}`);
  }
}

if (cmd === 'fetch') await fetchAll();
else if (cmd === 'plan') await planOnly();
else if (cmd === 'merge') mergeResults();
else if (cmd === 'sample') process.exitCode = spawnSync(process.execPath, [join(HERE, 'sample.mjs'), ...argv.slice(1)], { stdio: 'inherit' }).status;
else if (cmd === 'reeval') reevalAll();
else if (cmd === 'scan') await scanAll();
else if (cmd === 'report') { const { buildReport } = await import('./report.mjs'); await buildReport({ HERE, corpus }); }
else { console.log('usage: run.mjs fetch|scan|report  (see README.md)'); process.exitCode = 2; }
