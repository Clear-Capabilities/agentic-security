// Builds RESULTS.md and the `summary` block of results.json from results.json + adjudication.json. Pure formatting and arithmetic over what
// run.mjs recorded; it measures nothing itself. Run: node bench/live-feed/run.mjs report
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const q = (arr, p) => { if (!arr.length) return null; const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };
const med = (a) => q(a, 0.5);
const sec = (ms) => (ms == null ? 'n/a' : (ms / 1000).toFixed(1));
const sum = (a) => a.reduce((n, x) => n + (x || 0), 0);

export function buildReport({ HERE, corpus }) {
  const results = JSON.parse(readFileSync(join(HERE, 'results.json'), 'utf8'));
  const adjPath = join(HERE, 'adjudication.json');
  const adj = existsSync(adjPath) ? JSON.parse(readFileSync(adjPath, 'utf8')) : null;
  const byId = new Map(corpus.projects.map((p) => [p.id, p]));
  const all = Object.values(results.projects);
  const ok = all.filter((p) => !p.error && p.cold && p.statuses && !p.statuses.error);
  const failed = all.filter((p) => !ok.includes(p));
  const repo = resolve(HERE, '..', '..');
  const git = (...a) => { try { return execFileSync('git', a, { cwd: repo, encoding: 'utf8' }).trim(); } catch { return 'unknown'; } };
  const scannerVersion = JSON.parse(readFileSync(join(repo, 'scanner/package.json'), 'utf8')).version;

  // ── aggregates ─────────────────────────────────────────────────────────────
  const rowsAll = ok.flatMap((p) => (p.statuses.rows || []).map((r) => ({ ...r, project: p.id })));
  const statusTotals = {};
  for (const p of ok) for (const [k, v] of Object.entries(p.statuses.statusRows || {})) statusTotals[k] = (statusTotals[k] || 0) + v;
  const pkgs = ok.map((p) => p.statuses.uniquePackages || 0);
  const queried = ok.map((p) => p.cold.requests.packagesQueried);
  const uncovered = ok.map((p) => (p.statuses.uncoveredNames || []).length);
  const cold = ok.map((p) => p.cold);
  const summary = {
    projectsInCorpus: corpus.projects.length, projectsMeasured: ok.length, projectsFailed: failed.map((p) => ({ id: p.id, error: p.error || (p.statuses && p.statuses.error) || 'no result' })),
    byResolution: ok.reduce((m, p) => { m[p.resolution] = (m[p.resolution] || 0) + 1; return m; }, {}),
    packages: { total: sum(pkgs), median: med(pkgs), max: Math.max(0, ...pkgs), queriedTotal: sum(queried), uncoveredTotal: sum(uncovered), projectsWithUncovered: uncovered.filter((x) => x > 0).length },
    coldLookupMs: { median: med(cold.map((c) => c.requests.lookupSpanMs)), p90: q(cold.map((c) => c.requests.lookupSpanMs), 0.9), max: Math.max(0, ...cold.map((c) => c.requests.lookupSpanMs)) },
    coldWallMs: { median: med(cold.map((c) => c.wallMs)), p90: q(cold.map((c) => c.wallMs), 0.9), max: Math.max(0, ...cold.map((c) => c.wallMs)) },
    coldCpuMs: { median: med(cold.map((c) => c.cpuMs).filter((x) => x != null)), p90: q(cold.map((c) => c.cpuMs).filter((x) => x != null), 0.9) },
    requests: { feedTotal: sum(cold.map((c) => c.requests.feedRequests)), osvOtherEcosystem: sum(cold.map((c) => c.requests.osvOtherEcosystemRequests)), batches: sum(cold.map((c) => c.requests.batchQueries)), recordsFetched: sum(cold.map((c) => c.requests.recordsFetched)), recordFailures: sum(cold.map((c) => c.requests.recordFailures.length)), nextPageTokens: sum(cold.map((c) => c.requests.nextPageTokens)), nonOsvHosts: [...new Set(cold.flatMap((c) => c.requests.otherHosts))] },
    warm: (() => { const w = ok.filter((p) => p.warm); return { measured: w.length, projectsWithFeedRequests: w.filter((p) => p.warm.requests.feedRequests > 0).length, feedRequests: sum(w.map((p) => p.warm.requests.feedRequests)), medianWallMs: med(w.map((p) => p.warm.wallMs)), medianCpuMs: med(w.map((p) => p.warm.cpuMs).filter((x) => x != null)) }; })(),
    offline: ['offlineFlag', 'offlineEnv'].reduce((m, k) => { const w = ok.filter((p) => p[k]); m[k] = { measured: w.length, projectsWithAnyRequest: w.filter((p) => p[k].requests.total > 0).length, totalRequests: sum(w.map((p) => p[k].requests.total)), healthPartial: w.filter((p) => p[k].scanHealth && p[k].scanHealth.status === 'partial').length, exitCodes: w.reduce((c, p) => { c[p[k].exit] = (c[p[k].exit] || 0) + 1; return c; }, {}) }; return m; }, {}),
    coldHealth: ok.reduce((m, p) => { const s = p.cold.scanHealth && p.cold.scanHealth.status; m[s] = (m[s] || 0) + 1; return m; }, {}),
    hackageLiveModeReported: ok.reduce((m, p) => { const s = p.cold.scanHealth && p.cold.scanHealth.hackageLiveMode && p.cold.scanHealth.hackageLiveMode.status; m[s] = (m[s] || 0) + 1; return m; }, {}),
    advisoryRowsByStatus: statusTotals,
    packageBuckets: ok.reduce((m, p) => { for (const [k, v] of Object.entries(p.statuses.packages || {})) m[k] = (m[k] || 0) + v; return m; }, {}),
    findingsInScanJson: sum(ok.map((p) => p.cold.hackageFindingsInScanJson || 0)),
  };

  // ── adjudication ───────────────────────────────────────────────────────────
  let adjSummary = null;
  if (adj) {
    const items = adj.items;
    const verdictCount = (xs) => xs.reduce((m, i) => { m[i.verdict] = (m[i.verdict] || 0) + 1; return m; }, {});
    const claims = items.filter((i) => ['affected', 'possibly-affected', 'ghc-component:affected', 'ghc-component:possibly-affected'].includes(i.status));
    const decided = claims.filter((i) => i.verdict !== 'cannot-tell');
    const correct = decided.filter((i) => i.verdict === 'correct').length;
    adjSummary = { n: items.length, byVerdict: verdictCount(items), byStatus: items.reduce((m, i) => { (m[i.status] ||= []).push(i); return m; }, {}), claims: claims.length, decided: decided.length, correct };
    adjSummary.byStatus = Object.fromEntries(Object.entries(adjSummary.byStatus).map(([k, v]) => [k, verdictCount(v)]));
    return finish({ HERE, results, summary, adj, adjSummary, ok, failed, byId, git, scannerVersion, corpus });
  }
  return finish({ HERE, results, summary, adj, adjSummary, ok, failed, byId, git, scannerVersion, corpus });
}

async function finish(ctx) {
  const { HERE, results, summary, adj, adjSummary, ok, failed, byId, git, scannerVersion, corpus } = ctx;
  const { clopperPearson } = await import(pathToFileURL(join(HERE, '..', '..', 'scanner/src/language/support-registry.js')).href);
  if (adjSummary) {
    const { decided, correct } = adjSummary;
    const ci = clopperPearson(correct, decided);
    adjSummary.precision = { correct, decided, rate: decided ? correct / decided : null, ci95: ci ? [Number(ci[0].toFixed(4)), Number(ci[1].toFixed(4))] : null, method: 'Clopper-Pearson exact, two-sided 95%, over affected/possibly-affected claims whose verdict is not cannot-tell' };
    const stat = adj.items;
    const dec = stat.filter((i) => i.verdict !== 'cannot-tell');
    const cs = dec.filter((i) => i.verdict === 'correct').length;
    const ci2 = clopperPearson(cs, dec.length);
    adjSummary.statusCorrectness = { correct: cs, decided: dec.length, ci95: ci2 ? [Number(ci2[0].toFixed(4)), Number(ci2[1].toFixed(4))] : null, note: 'every sampled row, every status, judged on whether the status it was given is the right one' };
  }
  const meta = { date: new Date().toISOString().slice(0, 10), commit: git('rev-parse', 'HEAD'), branch: git('rev-parse', '--abbrev-ref', 'HEAD'), scannerVersion, ...(results.meta || {}), indexState: corpus.indexState };
  const out = { ...results, meta, summary: { ...summary, adjudication: adjSummary } };
  writeFileSync(join(HERE, 'results.json'), JSON.stringify(out, null, 1));

  const L = [];
  const row = (...c) => `| ${c.join(' | ')} |`;
  const sm = summary;
  L.push('# Live Hackage advisory feed: measured against real projects and real OSV', '');
  L.push(`Generated by \`node bench/live-feed/run.mjs report\` from \`results.json\` (${meta.updatedAt || meta.date}) and \`adjudication.json\`. Procedure: \`README.md\`.`, '');
  L.push('| | |', '|---|---|');
  L.push(row('Date of the run', meta.date), row('Scanner version', scannerVersion), row('Commit (harness + fixes)', `\`${meta.commit.slice(0, 12)}\` on \`${meta.branch}\`` + ' (the working tree may have been dirty during the run: see "Limits")'));
  L.push(row('Node / platform', `${meta.node || '?'} / ${meta.platform || '?'}, ${meta.cpus || '?'} CPUs`), row('Cabal index-state used for plans', corpus.indexState), row('Projects in corpus', sm.projectsInCorpus), row('Projects measured', sm.projectsMeasured));
  L.push(row('Resolution kinds measured', Object.entries(sm.byResolution).map(([k, v]) => `${k} ${v}`).join(', ')), '');
  if (sm.projectsFailed.length) { L.push('Projects that produced no usable result:', ''); for (const f of sm.projectsFailed) L.push(`- \`${f.id}\`: ${f.error}`); L.push(''); }

  L.push('## Headline numbers', '');
  L.push(`* Packages looked up (unique per project, summed): **${sm.packages.total}**; median ${sm.packages.median} per project, max ${sm.packages.max}. The cold scans' OSV batch queries named ${sm.packages.queriedTotal} package slots in total.`);
  L.push(`* Not covered by the feed after the cold scan: **${sm.packages.uncoveredTotal}** package(s) across ${sm.packages.projectsWithUncovered} project(s).`);
  L.push(`* Hackage-feed requests on the cold scans: ${sm.requests.feedTotal} (${sm.requests.batches} batch queries, ${sm.requests.recordsFetched} records fetched, ${sm.requests.recordFailures} record failures, ${sm.requests.nextPageTokens} next-page tokens). Other requests those scans made, not the feed: ${sm.requests.osvOtherEcosystem} api.osv.dev requests for other ecosystems (the scanner's ordinary npm / PyPI / Maven checks) and hosts ${sm.requests.nonOsvHosts.join(', ') || 'none'}.`);
  L.push(`* Lookup step (first OSV request to last OSV response): median ${sec(sm.coldLookupMs.median)} s, p90 ${sec(sm.coldLookupMs.p90)} s, max ${sec(sm.coldLookupMs.max)} s.`);
  L.push(`* Whole cold scan, wall: median ${sec(sm.coldWallMs.median)} s, p90 ${sec(sm.coldWallMs.p90)} s, max ${sec(sm.coldWallMs.max)} s. CPU (user+sys): median ${sec(sm.coldCpuMs.median)} s, p90 ${sec(sm.coldCpuMs.p90)} s. **The machine was heavily loaded by unrelated processes (see the load column), so wall time is an upper bound and CPU time is the steadier figure.**`);
  L.push(`* Second scan inside the TTL: ${sm.warm.feedRequests} Hackage-feed requests across ${sm.warm.measured} projects (${sm.warm.projectsWithFeedRequests} projects made any). Median wall ${sec(sm.warm.medianWallMs)} s, CPU ${sec(sm.warm.medianCpuMs)} s.`);
  for (const [k, label] of [['offlineFlag', '`--no-network`'], ['offlineEnv', '`AGENTIC_SECURITY_OFFLINE=1`']]) {
    const o = sm.offline[k];
    L.push(`* Offline, ${label} (live opt-in still set): ${o.totalRequests} requests of any kind across ${o.measured} projects (${o.projectsWithAnyRequest} projects made any); \`scanHealth.status\` partial in ${o.healthPartial}/${o.measured}; exit codes ${JSON.stringify(o.exitCodes)}.`);
  }
  L.push(`* Cold-scan \`scanHealth.status\`: ${JSON.stringify(sm.coldHealth)}. The \`hackage-live\` optional mode as reported by the scan: ${JSON.stringify(sm.hackageLiveModeReported)}.`);
  L.push(`* Advisory-by-component rows by status (every pair the matcher decided, summed): ${Object.entries(sm.advisoryRowsByStatus).sort(([, a], [, b]) => b - a).map(([k, v]) => `${k} ${v}`).join(', ')}.`);
  L.push(`* Package buckets: ${Object.entries(sm.packageBuckets).map(([k, v]) => `${k} ${v}`).join(', ')}.`, '');

  L.push('## Per project', '');
  L.push('Load = 1-minute load average when the cold scan started. Lookup = span of the Hackage-feed requests. Statuses count advisory-by-component rows: aff = affected, poss = possibly-affected, nA = not-affected, unk = unknown, ghc = any ghc-component:* row (compiler-provided packages, evaluated separately). Warm columns are Hackage-feed requests; offline columns are requests of ANY kind / scan health.', '');
  L.push(row('project', 'res', 'pkgs', 'uncov', 'feed req (batch/rec)', 'lookup s', 'cold wall s', 'cold cpu s', 'load', 'warm feed req', 'warm wall s', 'off flag req/health', 'off env req/health', 'aff', 'poss', 'nA', 'unk', 'ghc', 'cold health'));
  L.push(row(...Array(19).fill('---')));
  for (const p of ok) {
    const s = p.statuses.statusRows || {}; const c = p.cold; const rq = c.requests;
    const ghc = Object.entries(s).filter(([k]) => k.startsWith('ghc-component')).reduce((n, [, v]) => n + v, 0);
    L.push(row(`\`${p.id}\``, p.resolution, p.statuses.uniquePackages, (p.statuses.uncoveredNames || []).length, `${rq.feedRequests} (${rq.batchQueries}/${rq.recordRequests})`, sec(rq.lookupSpanMs), sec(c.wallMs), sec(c.cpuMs), c.load1, p.warm ? p.warm.requests.feedRequests : 'n/a', p.warm ? sec(p.warm.wallMs) : 'n/a',
      p.offlineFlag ? `${p.offlineFlag.requests.total}/${p.offlineFlag.scanHealth ? p.offlineFlag.scanHealth.status : 'n/a'}` : 'n/a', p.offlineEnv ? `${p.offlineEnv.requests.total}/${p.offlineEnv.scanHealth ? p.offlineEnv.scanHealth.status : 'n/a'}` : 'n/a',
      s.affected || 0, s['possibly-affected'] || 0, s['not-affected'] || 0, s.unknown || 0, ghc, c.scanHealth ? c.scanHealth.status : 'n/a'));
  }
  L.push('');
  const unc = ok.filter((p) => (p.statuses.uncoveredNames || []).length);
  L.push('## Uncovered packages', '');
  if (!unc.length) L.push('Every package in every measured project was covered by the feed after its cold scan.');
  else for (const p of unc) L.push(`- \`${p.id}\`: ${p.statuses.uncoveredNames.join(', ')} (record failures: ${JSON.stringify(p.cold.requests.recordFailures)}; next-page tokens: ${p.cold.requests.nextPageTokens})`);
  L.push('');

  if (adj && adjSummary) {
    L.push('## Adjudicated sample', '');
    L.push(`**These verdicts were assigned by the model that ran this harness (${adj.assessor}), not by a human.** Each row was judged by reading the advisory's affected ranges and text (from the record the feed fetched) against the project's resolved version or declared range. ${adj.sampling}`, '');
    const p = adjSummary.precision;
    L.push(`**Precision of the sample:** ${p.correct}/${p.decided} affected or possibly-affected claims judged correct${p.decided ? ` (${(100 * p.rate).toFixed(1)}%)` : ''}, Clopper-Pearson 95% interval [${p.ci95 ? p.ci95.join(', ') : 'n/a'}]. Rows judged cannot-tell are excluded from the denominator and listed.`, '');
    L.push(`**Status correctness over every sampled row (all statuses):** ${adjSummary.statusCorrectness.correct}/${adjSummary.statusCorrectness.decided}, 95% interval [${adjSummary.statusCorrectness.ci95 ? adjSummary.statusCorrectness.ci95.join(', ') : 'n/a'}].`, '');
    L.push(`Verdicts by status: ${JSON.stringify(adjSummary.byStatus)}.`, '');
    L.push(row('#', 'project', 'package', 'resolved / declared', 'advisory', 'status given', 'verdict', 'reason'), row(...Array(8).fill('---')));
    adj.items.forEach((i, k) => L.push(row(k + 1, `\`${i.project}\``, i.package, i.versionOrRange, i.advisory, i.status, i.verdict, String(i.reason).replace(/\|/g, '/'))));
    L.push('');
  }

  if (results.limits || (adj && adj.limits)) { L.push('## Limits', ''); for (const l of [...(adj ? adj.limits || [] : []), ...(results.limits || [])]) L.push(`- ${l}`); L.push(''); }
  writeFileSync(join(HERE, 'RESULTS.md'), `${L.join('\n')}\n`);
  console.log(`wrote RESULTS.md and results.json summary (${ok.length} projects, ${failed.length} failed)`);
}
