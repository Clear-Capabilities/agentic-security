// From measured runs to the table the router reads (PRD 6, requirement 7). One entry per (model, task, dataset): the task's
// primary quality with its spread and run count, the MEDIAN cost and latency of a single task call, where the evidence came from,
// and whether the model is local. Only model arms appear; the deterministic baseline is a comparison point, not a routing choice.
// Pure.
import { summarize, median } from './stats.js';
import { PRIMARY } from './report.js';

const SCOREBOARD_SCHEMA = 'agentic-security/model-scoreboard';
export const ROUTER_TASK_OF = Object.freeze({ hunt: 'detect', falsification: 'falsify', 'exploit-generation': 'exploit', 'patch-generation': 'patch' });
const EVAL_TASK_OF_ROUTER = Object.fromEntries(Object.entries(ROUTER_TASK_OF).map(([k, v]) => [v, k]));

const primaryValue = (score, evalTask) => {
  const s = score?.[PRIMARY[evalTask]];
  return typeof s === 'number' && Number.isFinite(s) ? s : null;
};

export function scoreboardFromRun(run, armDefs = []) {
  const entries = [];
  for (const arm of run.arms.filter((a) => a.model)) {
    const def = armDefs.find((d) => d.id === arm.id);
    const rs = run.results.filter((r) => r.armId === arm.id);
    for (const evalTask of ['detect', 'falsify', 'exploit', 'patch']) {
      if (!rs.some((r) => r.scores[evalTask])) continue;
      const q = summarize(rs.map((r) => primaryValue(r.scores[evalTask], evalTask)));
      const calls = run.attempts.filter((a) => a.armId === arm.id && a.task === evalTask && a.status !== 'skipped-budget');
      const costs = calls.map((a) => a.usage?.usd);
      const costKnown = costs.length > 0 && costs.every((x) => x != null);
      entries.push({
        model: `${arm.model.provider}/${arm.model.id}`, armId: arm.id, local: arm.model.local, endpoint: def?.model?.endpoint ?? null,
        routerTask: EVAL_TASK_OF_ROUTER[evalTask], evalTask, datasetHash: run.dataset.hash, datasetId: run.dataset.id,
        quality: { mean: q.mean, stdev: q.stdev, ci95: q.ci95, n: q.n, representative: q.representative, metric: PRIMARY[evalTask] },
        medianCostUsd: costKnown ? median(costs) : null, costKnown,
        medianLatencyMs: median(calls.map((a) => a.usage?.latencyMs)),
        failures: calls.filter((a) => a.status !== 'completed').length, calls: calls.length,
        evidence: { runId: run.runId, runDigest: run.digest, measuredAt: run.finishedAt },
      });
    }
  }
  return entries;
}

/** Merge a run's entries into a scoreboard document; a newer entry for the same (model, task, dataset) replaces the older. */
export function mergeScoreboard(existing, entries) {
  const key = (e) => `${e.model}|${e.routerTask}|${e.datasetHash}`;
  const map = new Map((existing?.entries ?? []).map((e) => [key(e), e]));
  for (const e of entries) map.set(key(e), e);
  return { schema: SCOREBOARD_SCHEMA, version: 1, updatedAt: new Date().toISOString(), entries: [...map.values()].sort((a, b) => key(a).localeCompare(key(b))) };
}
