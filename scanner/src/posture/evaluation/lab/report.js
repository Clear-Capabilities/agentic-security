// Eval Lab reports (PRD 6): quality + proof + remediation + cost + latency + repeatability for each arm, and the metric the
// product is for, intelligence per dollar. Pure: no fs, no clock.
//
// Rules that keep the numbers honest:
//   * a mean over fewer than three runs is printed with "not representative"; one lucky run is never a headline;
//   * every spread (stdev, range, 95% interval) sits beside the mean it qualifies;
//   * a dollar figure divides by MEASURED spend only, and when any attempt's cost is unknown the figure says so instead of
//     treating unknown as free; a deterministic arm has no model cost, so a per-dollar figure for it is `n/a`, not infinite;
//   * a quantity that was not measured is `n/a` (null), never 0;
//   * the leakage audit and any incompleteness appear in the header of every format.
import { summarize, pct } from './stats.js';

export const REPORT_SCHEMA = 'agentic-security/eval-lab-report';
export const REPORT_FORMATS = Object.freeze(['json', 'csv', 'md', 'html', 'chart']);

const pick = (rs, task, path) => rs.map((r) => path.reduce((o, k) => (o == null ? null : o[k]), r.scores[task] ?? null));

const METRICS = {
  detect: [['precision', ['precision']], ['recall', ['recall']], ['f1', ['f1']], ['macroF1', ['macroF1']], ['localizationAccuracy', ['localizationAccuracy']], ['completion', ['completion']]],
  falsify: [['balancedAccuracy', ['balancedAccuracy']], ['falseRefutationRate', ['falseRefutationRate']], ['falseConfirmationRate', ['falseConfirmationRate']]],
  exploit: [['pocGenerationSuccess', ['pocGenerationSuccess']], ['reproductionRate', ['reproductionRate']], ['confirmationRate', ['confirmationRate']], ['falseConfirmationRate', ['falseConfirmationRate']]],
  patch: [['validPatchRate', ['validPatchRate']], ['exploitBlockedRate', ['exploitBlockedRate']], ['testPreservationRate', ['testPreservationRate']], ['regressionRate', ['regressionRate']]],
};

/** The one number a task is judged by when ranking or routing. Defined once, here. */
export const PRIMARY = Object.freeze({ detect: 'f1', falsify: 'balancedAccuracy', exploit: 'confirmationRate', patch: 'validPatchRate' });

function recallAtBudget(run, armId, repeat, budgetUsd) {
  const mine = run.attempts.filter((a) => a.armId === armId && a.repeat === repeat && a.task === 'detect');
  if (!mine.length) return null;
  if (mine.some((a) => a.usage?.usd == null)) return { value: null, reason: 'some attempts have unknown cost' };
  const positives = mine.filter((a) => a.entryKind === 'vulnerable');
  if (!positives.length) return null;
  const res = run.results.find((r) => r.armId === armId && r.repeat === repeat);
  const hit = new Set((res.scores.detect.misses ?? []).map((m) => m.entryId));
  let spent = 0; let found = 0;
  for (const a of mine) { // attempts are in dataset order within a repeat
    spent += a.usage.usd;
    if (spent > budgetUsd) break;
    if (a.entryKind === 'vulnerable' && a.status === 'completed' && !hit.has(a.entryId)) found++;
  }
  return { value: found / positives.length, spentUsd: spent, budgetUsd };
}

export function summarizeRun(run, { budgetUsd = 10 } = {}) {
  const arms = run.arms.map((arm) => {
    const rs = run.results.filter((r) => r.armId === arm.id);
    const tasks = {};
    for (const [task, metrics] of Object.entries(METRICS)) {
      if (!rs.some((r) => r.scores[task])) continue;
      tasks[task] = Object.fromEntries(metrics.map(([name, path]) => [name, summarize(pick(rs, task, path))]));
    }
    const usdPerRepeat = rs.map((r) => (r.economics.attemptsWithUnknownCost > 0 ? null : r.economics.usdMeasured));
    const econ = {
      usd: summarize(usdPerRepeat), latencyMedianMs: summarize(rs.map((r) => r.economics.latencyMs.median)), latencyP95Ms: summarize(rs.map((r) => r.economics.latencyMs.p95)),
      inputTokens: summarize(rs.map((r) => (r.economics.tokensUnknownAttempts > 0 ? null : r.economics.inputTokens))), outputTokens: summarize(rs.map((r) => (r.economics.tokensUnknownAttempts > 0 ? null : r.economics.outputTokens))),
      timeouts: rs.reduce((s, r) => s + r.economics.timeouts, 0), failures: rs.reduce((s, r) => s + r.economics.failures, 0), unknownCostAttempts: rs.reduce((s, r) => s + r.economics.attemptsWithUnknownCost, 0),
    };
    const usdTotal = usdPerRepeat.every((x) => x != null) && usdPerRepeat.length ? usdPerRepeat.reduce((a, b) => a + b, 0) : null;
    const modelCost = arm.kind === 'model';
    const per = (count) => (!modelCost ? { value: null, reason: 'no model cost' } : usdTotal == null ? { value: null, reason: 'cost unknown for some attempts' } : usdTotal === 0 ? { value: null, reason: 'zero measured spend' } : { value: count / usdTotal * 100, perRun: count / rs.length });
    const sum = (task, key) => rs.reduce((s, r) => s + (r.scores[task]?.counts?.[key] ?? 0), 0);
    const ipd = {
      confirmedVulnerabilitiesPer100Usd: tasks.exploit ? per(sum('exploit', 'confirmedVuln')) : { value: null, reason: 'exploit task not run' },
      verifiedFixesPer100Usd: tasks.patch ? per(sum('patch', 'validStrict')) : { value: null, reason: 'patch task not run' },
      truePositivesPer100Usd: tasks.detect ? per(sum('detect', 'tp')) : { value: null, reason: 'detect task not run' },
      recallAtBudget: tasks.detect ? { budgetUsd, perRepeat: rs.map((r) => recallAtBudget(run, arm.id, r.repeat, budgetUsd)), summary: summarize(rs.map((r) => recallAtBudget(run, arm.id, r.repeat, budgetUsd)?.value ?? null)) } : null,
    };
    const dollarsPer = {
      truePositive: tasks.detect && modelCost && usdTotal != null && sum('detect', 'tp') > 0 ? usdTotal / sum('detect', 'tp') : null,
      confirmedExploit: tasks.exploit && modelCost && usdTotal != null && sum('exploit', 'confirmedVuln') > 0 ? usdTotal / sum('exploit', 'confirmedVuln') : null,
      verifiedFix: tasks.patch && modelCost && usdTotal != null && sum('patch', 'validStrict') > 0 ? usdTotal / sum('patch', 'validStrict') : null,
    };
    const primary = Object.fromEntries(Object.entries(tasks).map(([t, m]) => [t, m[PRIMARY[t]]]));
    return { id: arm.id, kind: arm.kind, model: arm.model, runs: rs.length, tasks, economics: econ, intelligencePerDollar: ipd, dollarsPer, primary };
  });
  return {
    schema: REPORT_SCHEMA, version: 1, runId: run.runId, runDigest: run.digest,
    header: { scannerCommit: run.scanner?.commit ?? null, scannerVersion: run.scanner?.version ?? null, datasetId: run.dataset.id, datasetVersion: run.dataset.version, datasetHash: run.dataset.hash, split: run.dataset.split, models: run.arms.filter((a) => a.model).map((a) => `${a.model.provider}/${a.model.id}${a.model.local ? ' (local)' : ''}`), config: run.config, machine: run.machine, startedAt: run.startedAt, finishedAt: run.finishedAt },
    leakageAudit: run.leakageAudit, complete: run.complete, incompleteReasons: run.incompleteReasons, arms,
    notes: arms.some((a) => Object.values(a.primary).some((s) => s && !s.representative)) ? ['At least one figure rests on fewer than three runs and is marked not representative.'] : [],
  };
}

const fmt = (s, kind = 'pct') => {
  if (!s || s.mean == null) return 'n/a';
  const base = kind === 'pct' ? pct(s.mean) : kind === 'usd' ? `$${s.mean.toFixed(4)}` : kind === 'ms' ? `${Math.round(s.mean)}ms` : String(s.mean);
  const spread = s.stdev == null ? '' : ` ±${kind === 'pct' ? pct(s.stdev) : kind === 'usd' ? `$${s.stdev.toFixed(4)}` : kind === 'ms' ? `${Math.round(s.stdev)}ms` : s.stdev.toFixed(2)}`;
  return `${base}${spread}${s.representative ? '' : ' (not representative)'}`;
};
const money = (x) => (x == null ? 'n/a' : x === 0 ? '$0.00' : x < 0.01 ? `$${x.toFixed(4)}` : `$${x.toFixed(2)}`);

export function toMarkdown(rep) {
  const h = rep.header;
  const L = [`# Eval Lab report ${rep.runId}`, '',
    `* Scanner: ${h.scannerVersion ?? 'unknown'} @ ${h.scannerCommit ? h.scannerCommit.slice(0, 12) : 'unknown commit'}`,
    `* Dataset: ${h.datasetId} ${h.datasetVersion} (${h.split}), hash ${String(h.datasetHash).slice(-16)}`,
    `* Models: ${h.models.length ? h.models.join(', ') : 'none (deterministic only)'}`,
    `* Config: tasks ${h.config.tasks.join(', ')}; repeats ${h.config.repeats}; timeout ${h.config.timeoutMs}ms; budget ${h.config.budgetUsd ?? 'none'}`,
    `* Machine: ${h.machine.platform}/${h.machine.arch}, ${h.machine.cpus} cpus, ${h.machine.memoryGb} GB, node ${h.machine.node}`,
    `* Run: ${h.startedAt} to ${h.finishedAt}`,
    `* Leakage audit: ${rep.leakageAudit.status} (${rep.leakageAudit.usable}/${rep.leakageAudit.entries} entries usable; comments ${rep.leakageAudit.stripComments ? 'stripped' : 'kept'})`,
    ...(rep.complete ? [] : [`* **INCOMPLETE**: ${rep.incompleteReasons.join('; ')}`]), ''];
  for (const task of Object.keys(METRICS)) {
    const present = rep.arms.filter((a) => a.tasks[task]);
    if (!present.length) continue;
    const cols = METRICS[task].map(([n]) => n);
    L.push(`## ${task}`, '', `| arm | runs | ${cols.join(' | ')} |`, `|---|---|${cols.map(() => '---').join('|')}|`);
    for (const a of present) L.push(`| ${a.id} | ${a.runs} | ${cols.map((c) => fmt(a.tasks[task][c])).join(' | ')} |`);
    L.push('');
  }
  L.push('## Cost, speed and reliability', '', '| arm | spend per run | median latency | p95 latency | timeouts | failures | unknown-cost attempts |', '|---|---|---|---|---|---|---|');
  for (const a of rep.arms) L.push(`| ${a.id} | ${a.kind === 'deterministic' ? 'no model cost' : fmt(a.economics.usd, 'usd')} | ${fmt(a.economics.latencyMedianMs, 'ms')} | ${fmt(a.economics.latencyP95Ms, 'ms')} | ${a.economics.timeouts} | ${a.economics.failures} | ${a.economics.unknownCostAttempts} |`);
  L.push('', '## Intelligence per dollar', '', '| arm | confirmed vulnerabilities / $100 | verified fixes / $100 | true positives / $100 | recall at fixed budget |', '|---|---|---|---|---|');
  for (const a of rep.arms) {
    const i = a.intelligencePerDollar; const cell = (x) => (x?.value == null ? `n/a (${x?.reason ?? 'not measured'})` : x.value.toFixed(1));
    const rb = i.recallAtBudget; L.push(`| ${a.id} | ${cell(i.confirmedVulnerabilitiesPer100Usd)} | ${cell(i.verifiedFixesPer100Usd)} | ${cell(i.truePositivesPer100Usd)} | ${rb ? `${fmt(rb.summary)} at $${rb.budgetUsd}` : 'n/a'} |`);
  }
  L.push('', '## Dollars per outcome', '', '| arm | per true positive | per confirmed exploit | per verified fix |', '|---|---|---|---|');
  for (const a of rep.arms) L.push(`| ${a.id} | ${money(a.dollarsPer.truePositive)} | ${money(a.dollarsPer.confirmedExploit)} | ${money(a.dollarsPer.verifiedFix)} |`);
  if (rep.notes.length) L.push('', ...rep.notes.map((n) => `> ${n}`));
  return `${L.join('\n')}\n`;
}

function toCsv(rep) {
  const q = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const rows = [['arm', 'kind', 'task', 'metric', 'n', 'mean', 'stdev', 'min', 'max', 'ci95_low', 'ci95_high', 'representative']];
  for (const a of rep.arms) {
    for (const [task, ms] of Object.entries(a.tasks)) for (const [name, s] of Object.entries(ms)) rows.push([a.id, a.kind, task, name, s.n, s.mean, s.stdev, s.min, s.max, s.ci95?.low, s.ci95?.high, s.representative]);
    for (const [name, s] of [['usd', a.economics.usd], ['latencyMedianMs', a.economics.latencyMedianMs], ['latencyP95Ms', a.economics.latencyP95Ms]]) rows.push([a.id, a.kind, 'economics', name, s.n, s.mean, s.stdev, s.min, s.max, s.ci95?.low, s.ci95?.high, s.representative]);
  }
  return `${rows.map((r) => r.map(q).join(',')).join('\n')}\n`;
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export function toHtml(rep) {
  const md = toMarkdown(rep).split('\n');
  const out = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Eval Lab report</title><style>body{font:14px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;margin:.5rem 0 1.5rem}td,th{border:1px solid #8884;padding:.25rem .6rem;text-align:left}h1,h2{margin-top:1.5rem}blockquote{border-left:3px solid #c80;margin:1rem 0;padding:.1rem 1rem}</style></head><body>'];
  let table = null; let list = false;
  const closeList = () => { if (list) { out.push('</ul>'); list = false; } };
  for (const line of md) {
    if (line.startsWith('|')) {
      closeList();
      const cells = line.split('|').slice(1, -1).map((c) => c.trim());
      if (cells.every((c) => /^-+$/.test(c))) continue;
      if (!table) { table = true; out.push(`<table><thead><tr>${cells.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>`); } else out.push(`<tr>${cells.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`);
      continue;
    }
    if (table) { out.push('</tbody></table>'); table = null; }
    if (line.startsWith('# ')) { closeList(); out.push(`<h1>${esc(line.slice(2))}</h1>`); } else if (line.startsWith('## ')) { closeList(); out.push(`<h2>${esc(line.slice(3))}</h2>`); } else if (line.startsWith('* ')) { if (!list) { out.push('<ul>'); list = true; } out.push(`<li>${esc(line.slice(2).replace(/\*\*/g, ''))}</li>`); } else if (line.startsWith('> ')) { closeList(); out.push(`<blockquote>${esc(line.slice(2))}</blockquote>`); } else if (line.trim()) { closeList(); out.push(`<p>${esc(line)}</p>`); }
  }
  closeList(); if (table) out.push('</tbody></table>');
  out.push('</body></html>');
  return `${out.join('\n')}\n`;
}

/** Chart-ready series: one point per arm and metric, with the error bar the repeats support. */
export function toChartData(rep) {
  const series = [];
  for (const a of rep.arms) for (const [task, ms] of Object.entries(a.tasks)) for (const [metric, s] of Object.entries(ms)) {
    if (s.mean == null) continue;
    series.push({ arm: a.id, task, metric, value: s.mean, low: s.ci95?.low ?? null, high: s.ci95?.high ?? null, n: s.n, representative: s.representative });
  }
  const scatter = rep.arms.filter((a) => a.economics.usd.mean != null).flatMap((a) => Object.entries(a.primary).filter(([, s]) => s?.mean != null).map(([task, s]) => ({ arm: a.id, task, costUsd: a.economics.usd.mean, quality: s.mean, representative: s.representative })));
  return { schema: 'agentic-security/eval-lab-chart-data', version: 1, runId: rep.runId, series, qualityVsCost: scatter };
}

export function renderReport(rep, format) {
  if (format === 'json') return `${JSON.stringify(rep, null, 2)}\n`;
  if (format === 'csv') return toCsv(rep);
  if (format === 'md') return toMarkdown(rep);
  if (format === 'html') return toHtml(rep);
  if (format === 'chart') return `${JSON.stringify(toChartData(rep), null, 2)}\n`;
  throw new Error(`unknown report format: ${format}`);
}

