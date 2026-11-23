// Replaying a frozen Eval Lab run (contract-driven verification, C-AC05).
//
// A stored run records what it was: the dataset hash, every arm's configuration digest, the frozen configuration (tasks, repeats,
// timeout, budget, matcher version and tolerance, stability policy, prompt versions) and the scanner and machine it ran on. A replay
// re-runs exactly that, and says how far the result can be expected to match:
//
//   refused       the dataset or an arm is not the one the run recorded (hash or configuration digest differs). Nothing is run.
//   reproduced    every deterministic arm detected the same defects the same number of times, and scored the same.
//   diverged      a deterministic arm did not (the entries are listed). With an unchanged scanner and dataset this is a defect.
//   limited       a model arm cannot be replayed exactly: a provider without an immutable model version, or sampling the lab does
//                 not control. Its agreement with the frozen run is reported per defect as a description, never as a verdict.
//
// Environment differences (scanner commit, a dirty tree, Node, platform) are listed; a deterministic divergence under a different
// scanner is expected and labelled so, not hidden.
import { digestOf } from '../../assurance/identity.js';

const FROZEN_KEYS = ['tasks', 'repeats', 'timeoutMs', 'budgetUsd', 'lineTolerance', 'matcherVersion', 'stabilityPolicy', 'promptVersions'];

/** Can `arms` and `dataset` replay `frozen`? Returns `{ ok, reasons, config }`; `config` holds the runEval arguments to use. */
export function replayPlan(frozen, { dataset, arms }) {
  const reasons = [];
  if (!frozen?.runId || !frozen?.config || !Array.isArray(frozen?.arms)) return { ok: false, reasons: ['not a stored lab run'] };
  if (dataset?.hash !== frozen.dataset?.hash) reasons.push(`the dataset hash ${String(dataset?.hash).slice(-12)} is not the frozen run's ${String(frozen.dataset?.hash).slice(-12)}`);
  const byId = new Map((arms || []).map((a) => [a.id, a]));
  for (const rec of frozen.arms) {
    const a = byId.get(rec.id);
    if (!a) { reasons.push(`arm ${rec.id} is not in the arms file`); continue; }
    if (digestOf({ ...a, adapter: { ...a.adapter } }) !== rec.configDigest) reasons.push(`arm ${rec.id} is configured differently from the frozen run`);
  }
  for (const a of arms || []) if (!frozen.arms.some((r) => r.id === a.id)) reasons.push(`arm ${a.id} was not in the frozen run`);
  const c = frozen.config;
  return { ok: reasons.length === 0, reasons, config: { tasks: c.tasks, repeats: c.repeats, concurrency: c.concurrency ?? 2, timeoutMs: c.timeoutMs, budgetUsd: c.budgetUsd ?? null, stabilityPolicy: c.stabilityPolicy } };
}

const perDefectOf = (run, armId) => new Map((run.stability?.arms || []).find((a) => a.armId === armId)?.perDefect.map((d) => [d.entryId, d]) ?? []);
const scoresOf = (run, armId) => (run.results || []).filter((r) => r.armId === armId).sort((a, b) => a.repeat - b.repeat).map((r) => r.scores);

/** Compare a replayed run with the frozen one. */
export function compareReplay(frozen, replayed) {
  const env = [];
  for (const [k, a, b] of [['scanner.commit', frozen.scanner?.commit, replayed.scanner?.commit], ['scanner.dirty', frozen.scanner?.dirty, replayed.scanner?.dirty], ['scanner.version', frozen.scanner?.version, replayed.scanner?.version], ['machine.node', frozen.machine?.node, replayed.machine?.node], ['machine.platform', frozen.machine?.platform, replayed.machine?.platform]]) {
    if (JSON.stringify(a ?? null) !== JSON.stringify(b ?? null)) env.push({ field: k, frozen: a ?? null, replay: b ?? null });
  }
  const configDiff = FROZEN_KEYS.filter((k) => JSON.stringify(frozen.config?.[k] ?? null) !== JSON.stringify(replayed.config?.[k] ?? null));
  const arms = [];
  for (const rec of frozen.arms) {
    const f = perDefectOf(frozen, rec.id); const r = perDefectOf(replayed, rec.id);
    const entries = [...new Set([...f.keys(), ...r.keys()])].sort();
    const rows = entries.map((id) => ({ entryId: id, frozen: f.get(id)?.detected ?? null, replay: r.get(id)?.detected ?? null, scheduled: f.get(id)?.scheduled ?? null }));
    const differing = rows.filter((x) => x.frozen !== x.replay);
    if (rec.kind === 'deterministic') {
      const sameScores = JSON.stringify(scoresOf(frozen, rec.id)) === JSON.stringify(scoresOf(replayed, rec.id));
      arms.push({ armId: rec.id, kind: rec.kind, status: !differing.length && sameScores ? 'reproduced' : 'diverged', differing, sameScores });
    } else {
      const why = [];
      if (!rec.model?.version) why.push('the provider exposes no immutable model version');
      if (!rec.model?.local) why.push('a hosted provider may change behind the same name');
      why.push('model sampling is not controlled by the lab');
      const agree = rows.filter((x) => x.frozen === x.replay).length;
      arms.push({ armId: rec.id, kind: rec.kind, status: 'limited', why, agreement: { defects: rows.length, sameCount: agree }, differing, note: 'descriptive only; agreement between two samples is not evidence that either is right' });
    }
  }
  const det = arms.filter((a) => a.kind === 'deterministic');
  const status = det.some((a) => a.status === 'diverged') ? 'diverged' : det.length ? (arms.some((a) => a.status === 'limited') ? 'reproduced-deterministic-limited-model' : 'reproduced') : 'limited';
  return {
    schema: 'agentic-security/eval-replay', frozenRunId: frozen.runId, replayRunId: replayed.runId, status, arms,
    configDifferences: configDiff, environmentDifferences: env,
    note: env.some((e) => e.field.startsWith('scanner.')) ? 'the scanner differs from the frozen run; a deterministic divergence is then expected and is a change of engine, not of the run' : null,
  };
}
