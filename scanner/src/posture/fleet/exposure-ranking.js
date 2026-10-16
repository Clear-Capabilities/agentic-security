// Fleet exposure ranking (E7-06): which findings matter most across many repositories and services, and WHY, without collapsing the reasons into one number.
//
// A single risk score hides what it is made of. This ranking keeps five things apart and shows each:
//   impact          what is lost if it is exploited: severity, the classes of data on the path (card numbers, health data), how many services the path crosses
//   exposure        who can reach it: a route of a public service, a route of an internal service, a path from nothing, or unknown
//   exploitability  how likely and how well shown: an execution proof, a known-exploited listing, a taint path, a pattern match; runtime evidence counts only while it is FRESH
//   confidence      how sure we are of the path itself: whether the chain is made of named, declared links or inferred ones
//   coverage        how complete the picture is: scan health of the repositories on the path, and repositories of the fleet that were not scanned at all
// Coverage is reported beside the rest and never folded into them: an incomplete picture is a caveat on the ranking, not a reason to rank something lower.
//
// PRIORITY is read from a fixed table of those tiers (`PRIORITY_RULES`), top to bottom, first match wins, so any finding's priority can be traced to the rule that
// gave it. Ties are broken by the tiers in a fixed order, then by id, so the order is deterministic.
//
// NEGATIVE CONTROLS built in: runtime evidence older than the freshness window does not raise exploitability and is listed as stale; a finding that arrives through
// a library only counts for a path whose library step is marked vulnerable for that very package (a dependency on a version outside the advisory range, or on a
// different package, excludes it and says so); a path is followed only along links that exist in the service graph, so a same-named route in another service is
// never reached.
const TIER = Object.freeze({ none: 0, unknown: 0, low: 1, medium: 2, high: 3, critical: 4 });
const SENSITIVE = new Set(['payment-card', 'health', 'phi', 'pii', 'credentials', 'financial']);
const SEVERITY = Object.freeze({ info: 'low', low: 'low', medium: 'medium', high: 'high', critical: 'critical' });

/** The pre-registered priority table. First matching rule wins; each names the tiers it needs. */
export const PRIORITY_RULES = Object.freeze([
  { id: 'P0-proven-public-sensitive', priority: 'P0', when: (t) => t.impact >= TIER.high && t.exposure === 'public' && t.exploitability >= TIER.high && t.confidence >= TIER.medium },
  { id: 'P0-critical-public', priority: 'P0', when: (t) => t.impact >= TIER.critical && t.exposure === 'public' && t.exploitability >= TIER.medium && t.confidence >= TIER.medium },
  { id: 'P1-high-public', priority: 'P1', when: (t) => t.impact >= TIER.high && t.exposure === 'public' && t.exploitability >= TIER.medium },
  { id: 'P1-proven-internal', priority: 'P1', when: (t) => t.impact >= TIER.high && t.exposure === 'internal' && t.exploitability >= TIER.high },
  { id: 'P2-reachable', priority: 'P2', when: (t) => (t.exposure === 'public' || t.exposure === 'internal') && t.impact >= TIER.medium },
  { id: 'P3-exposure-unknown', priority: 'P3', when: (t) => t.exposure === 'unknown' && t.impact >= TIER.high },
  { id: 'P4-not-reached', priority: 'P4', when: () => true },
]);
const PRIORITY_ORDER = ['P0', 'P1', 'P2', 'P3', 'P4'];
const tierName = (n) => Object.keys(TIER).find((k) => TIER[k] === n && k !== 'unknown') || 'none';
const daysBetween = (a, b) => (a - b) / 86400000;

/**
 * @param {object} o
 * @param {{nodes:object[], edges:object[]}} o.graph from buildServiceChainGraph
 * @param {{route:string, service:string, repo:string, sink:string, steps:object[], confidence:number, repos:string[], dataClassifications:string[], crossesServices:boolean, throughLibrary:object[]}[]} o.chains from findChains
 * @param {object[]} o.findings { id, repo, sinkRef:{repo, qid, kind}, severity, proofTier, kev, epss, viaLibrary:{package}, runtime:{observedAt, corroboration}, scanHealth:'complete'|'partial'|... }
 * @param {Object<string,{exposure:'public'|'internal'}>} o.services keyed by service name
 * @param {string[]} [o.fleet] every repository of the fleet, so unscanned ones are counted
 * @param {string[]} [o.scanned] the repositories that were scanned
 * @param {number} o.now
 * @param {number} [o.freshnessDays] runtime evidence older than this is stale (default 14)
 */
export function rankFleetExposure({ graph, chains, findings, services = {}, fleet = [], scanned = null, now, freshnessDays = 14 }) {
  const byRepoSink = new Map();
  for (const c of chains || []) {
    const sinkStep = c.steps[c.steps.length - 1];
    const node = (graph.nodes || []).find((n) => n.id === (sinkStep && sinkStep.to));
    if (!node) continue;
    const key = `${node.repo}|${node.id.split(':sink:')[1] || ''}`;
    (byRepoSink.get(key) || byRepoSink.set(key, []).get(key)).push(c);
  }
  // a repository counts as scanned when the caller says so, or, failing that, when some finding of it carries a scan health
  const scannedRepos = new Set(scanned || (findings || []).filter((f) => f.scanHealth).map((f) => f.repo));
  const ranked = []; const excluded = [];
  for (const f of findings || []) {
    const ref = f.sinkRef || {};
    const key = `${ref.repo}|${ref.qid}#${ref.kind}`;
    let cands = byRepoSink.get(key) || [];
    const dropped = [];
    if (f.viaLibrary) {
      const keep = cands.filter((c) => c.throughLibrary.some((l) => l.package === f.viaLibrary.package && l.vulnerable === true));
      for (const c of cands) if (!keep.includes(c)) dropped.push({ route: c.route, reason: c.throughLibrary.some((l) => l.package === f.viaLibrary.package) ? `the dependency on ${f.viaLibrary.package} is outside the advisory range` : `the path does not use ${f.viaLibrary.package}` });
      cands = keep;
      if (!keep.length && dropped.length) { excluded.push({ id: f.id, reason: dropped[0].reason, paths: dropped.length }); continue; }
    }
    const factors = [];
    // ---- exposure
    let exposure = 'none'; let entry = null;
    if (cands.length) {
      const exposures = cands.map((c) => (services[c.service] ? services[c.service].exposure : 'unknown'));
      exposure = exposures.includes('public') ? 'public' : exposures.includes('internal') ? 'internal' : 'unknown';
      // the entry that explains the exposure: the most certain path among those that give it
      entry = cands.filter((c) => (services[c.service] ? services[c.service].exposure : 'unknown') === exposure).sort((a, b) => b.confidence - a.confidence)[0] || cands[0];
      factors.push({ dimension: 'exposure', value: exposure, because: `${cands.length} path(s) reach it from a route; the entry service${cands.length > 1 ? 's are' : ' is'} ${[...new Set(cands.map((c) => c.service))].join(', ')} (${exposure})` });
    } else factors.push({ dimension: 'exposure', value: ref.repo ? 'none' : 'unknown', because: ref.repo ? 'no path from any route in the service graph reaches this sink' : 'the finding does not say which sink it is, so no path can be looked for' });
    if (!cands.length && !ref.repo) exposure = 'unknown'; else if (!cands.length) exposure = 'none';
    // ---- impact
    const classes = [...new Set(cands.flatMap((c) => c.dataClassifications))].sort();
    const sev = SEVERITY[f.severity] || 'low';
    let impact = TIER[sev];
    if (classes.some((c) => SENSITIVE.has(c))) { impact = Math.min(TIER.critical, impact + 1); factors.push({ dimension: 'impact', value: tierName(impact), because: `severity ${f.severity}; the path carries ${classes.filter((c) => SENSITIVE.has(c)).join(', ')}, which raises it one tier` }); }
    else factors.push({ dimension: 'impact', value: tierName(impact), because: `severity ${f.severity}${classes.length ? `; data on the path: ${classes.join(', ')} (not rated sensitive)` : '; no data classification on the path'}` });
    if (cands.some((c) => c.crossesServices)) factors.push({ dimension: 'impact', value: 'info', because: 'the path crosses services, so a compromise is not contained to the entry service' });
    // ---- exploitability
    let exploit = f.proofTier === 'execution-proven' ? TIER.high : f.kev ? TIER.high : (typeof f.epss === 'number' && f.epss >= 0.5) ? TIER.high : f.proofTier === 'taint-proven' ? TIER.medium : TIER.low;
    factors.push({ dimension: 'exploitability', value: tierName(exploit), because: f.proofTier === 'execution-proven' ? 'a proof of concept ran and showed the effect' : f.kev ? 'listed as known exploited' : (typeof f.epss === 'number' && f.epss >= 0.5) ? `EPSS ${f.epss}` : f.proofTier === 'taint-proven' ? 'a taint path was found by static analysis; nothing was executed' : 'a pattern match; no path or proof' });
    if (f.runtime && f.runtime.observedAt) {
      const age = daysBetween(now, Date.parse(f.runtime.observedAt));
      if (!(age >= 0)) factors.push({ dimension: 'exploitability', value: 'info', because: 'runtime evidence is dated in the future and is ignored' });
      else if (age > freshnessDays) factors.push({ dimension: 'exploitability', value: 'info', stale: true, because: `runtime evidence is ${Math.floor(age)} days old, past the ${freshnessDays}-day window: stale, so it does not raise anything` });
      else if (f.runtime.corroboration === 'corroborated') { exploit = Math.min(TIER.critical, exploit + 1); factors.push({ dimension: 'exploitability', value: tierName(exploit), because: `observed by a matched build ${Math.floor(age)} day(s) ago: raises it one tier` }); }
      else factors.push({ dimension: 'exploitability', value: 'info', because: 'seen at runtime but not tied to this build: noted, not counted' });
    }
    // ---- confidence
    const conf = entry ? entry.confidence : 0;
    const confidence = !entry ? TIER.unknown : conf >= 0.7 ? TIER.high : conf >= 0.5 ? TIER.medium : TIER.low;
    factors.push({ dimension: 'confidence', value: entry ? tierName(confidence) : 'unknown', because: entry ? `the best path has confidence ${entry.confidence} (product of its links; named links 0.9, inferred 0.7 and below)` : 'there is no path to judge' });
    // ---- coverage (reported, never merged)
    const reposOnPath = new Set(cands.flatMap((c) => c.repos));
    const unscanned = [...reposOnPath].filter((r) => fleet.length && !scannedRepos.has(r));
    const coverage = { scanHealth: f.scanHealth || 'unknown', reposOnPath: [...reposOnPath].sort(), unscannedReposOnPath: unscanned.sort(), complete: (f.scanHealth === 'complete') && unscanned.length === 0 };
    factors.push({ dimension: 'coverage', value: coverage.complete ? 'complete' : 'incomplete', because: coverage.complete ? 'the scan of this repository was complete and every repository on the path was scanned' : `scan health ${coverage.scanHealth}${unscanned.length ? `; not scanned: ${unscanned.join(', ')}` : ''}` });
    const tiers = { impact, exposure, exploitability: exploit, confidence };
    const rule = PRIORITY_RULES.find((r) => r.when(tiers));
    ranked.push({ id: f.id, repo: ref.repo || f.repo || null, priority: rule.priority, rule: rule.id, tiers: { impact: tierName(impact), exposure, exploitability: tierName(exploit), confidence: entry ? tierName(confidence) : 'unknown' }, coverage, entryRoute: entry ? entry.route : null, paths: cands.length, droppedPaths: dropped, factors, _sort: [PRIORITY_ORDER.indexOf(rule.priority), -impact, -(exposure === 'public' ? 2 : exposure === 'internal' ? 1 : 0), -exploit, -confidence, String(f.id)] });
  }
  ranked.sort((a, b) => { for (let i = 0; i < a._sort.length; i++) { if (a._sort[i] < b._sort[i]) return -1; if (a._sort[i] > b._sort[i]) return 1; } return 0; });
  for (const r of ranked) delete r._sort;
  const byPriority = Object.fromEntries(PRIORITY_ORDER.map((p) => [p, ranked.filter((r) => r.priority === p).length]));
  return { ranked, excluded, summary: { findings: (findings || []).length, ranked: ranked.length, excluded: excluded.length, byPriority, incompleteCoverage: ranked.filter((r) => !r.coverage.complete).length } };
}
