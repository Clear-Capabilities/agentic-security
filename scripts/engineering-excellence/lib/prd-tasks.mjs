// Task manifest generation from the Engineering Excellence master PRD.
//
// The PRD is the source of the task list: every `**E<n>-<nn> - Title.** ... **Accept:** ...` paragraph in the epic sections is one
// task. Nothing here invents a task or a dependency the document does not support; the dependency edges below are written out by hand
// (and justified in docs/engineering-excellence/DECISIONS.md) because the PRD states them only at epic level.

export const EPICS = Object.freeze([
  { id: 'E0', title: 'Baseline, compatibility and execution infrastructure', priority: 'P0' },
  { id: 'E1', title: 'Genuine independent accuracy and anti-overfitting', priority: 'P0' },
  { id: 'E2', title: 'Semantic IR, interprocedural taint and real-world detection', priority: 'P0' },
  { id: 'E3', title: 'Unified exploit and functional fix verification', priority: 'P0' },
  { id: 'E4', title: 'Production-grade Deterministic Context Intelligence', priority: 'P1' },
  { id: 'E5', title: 'Runtime, deployment and exploitability corroboration', priority: 'P1' },
  { id: 'E6', title: 'Reliable, efficient, maintainable, hardened engine', priority: 'P1' },
  { id: 'E7', title: 'Auditable enterprise assurance, governance and explainability', priority: 'P2' },
  { id: 'E8', title: 'Integration, distribution and production-readiness', priority: 'P0' },
]);

// Weight of a task in the program percentage: P0 counts three times a P2 task.
export const PRIORITY_WEIGHT = Object.freeze({ P0: 3, P1: 2, P2: 1 });

// `requires` blocks a task until every listed task is verified. `informedBy` is shown, never blocks: it records "work from the E1 miss
// clusters" style guidance without making a task wait on an external corpus that may legitimately stay unmeasured.
// The E0 exit gate ("inventory, baseline and status observer work before any epic is marked in progress") is encoded by every
// non-E0 task requiring E0-01, E0-02 and E0-05.
const E0_GATE = ['E0-01', 'E0-02', 'E0-05'];
export const DEPENDENCIES = Object.freeze({
  'E0-01': { requires: [] },
  'E0-02': { requires: ['E0-01'] },
  'E0-03': { requires: ['E0-01'] },
  'E0-04': { requires: [] },
  'E0-05': { requires: ['E0-04'] },
  'E0-06': { requires: ['E0-02'], informedBy: ['E1-05'] },

  'E1-01': { requires: E0_GATE },
  'E1-02': { requires: ['E1-01'] },
  'E1-03': { requires: ['E1-02'] },
  'E1-04': { requires: ['E1-03'] },
  'E1-05': { requires: ['E1-04'] },
  'E1-06': { requires: ['E1-02'] },
  'E1-07': { requires: ['E1-03', 'E1-04'] },
  'E1-08': { requires: ['E1-07'] },

  'E2-01': { requires: E0_GATE },
  'E2-02': { requires: ['E2-01'], informedBy: ['E1-05'] },
  'E2-03': { requires: ['E2-02'] },
  'E2-04': { requires: ['E2-02'] },
  'E2-05': { requires: ['E2-03'] },
  'E2-06': { requires: ['E2-02'], informedBy: ['E1-05'] },
  'E2-07': { requires: ['E2-04'] },
  'E2-08': { requires: ['E2-02'], informedBy: ['E1-05'] },
  'E2-09': { requires: ['E2-06', 'E1-02'] },

  'E3-01': { requires: E0_GATE },
  'E3-02': { requires: ['E3-01'] },
  'E3-03': { requires: ['E3-02'] },
  'E3-04': { requires: ['E3-03'] },
  'E3-05': { requires: ['E3-03'] },
  'E3-06': { requires: ['E3-03'] },
  'E3-07': { requires: ['E3-03'] },
  'E3-08': { requires: ['E3-04', 'E3-05'] },

  'E4-01': { requires: E0_GATE },
  'E4-02': { requires: ['E4-01'] },
  'E4-03': { requires: ['E4-02', 'E2-02'] },
  'E4-04': { requires: ['E4-03'] },
  'E4-05': { requires: ['E4-01'] },
  'E4-06': { requires: ['E4-04', 'E1-02'] },
  'E4-07': { requires: ['E4-04', 'E3-03'] },

  'E5-01': { requires: E0_GATE },
  'E5-02': { requires: ['E5-01'] },
  'E5-03': { requires: ['E5-01'] },
  'E5-04': { requires: ['E5-02', 'E5-03', 'E2-01'] },
  'E5-05': { requires: ['E5-04'] },
  'E5-06': { requires: ['E5-01'] },
  'E5-07': { requires: ['E5-04'] },

  'E6-01': { requires: E0_GATE },
  'E6-02': { requires: ['E6-01'] },
  'E6-03': { requires: ['E6-01'] },
  'E6-04': { requires: ['E6-03'] },
  'E6-05': { requires: ['E6-01'] },
  'E6-06': { requires: ['E6-01'] },
  'E6-07': { requires: ['E6-01'] },
  'E6-08': { requires: ['E6-01', 'E6-04'] },

  'E7-01': { requires: E0_GATE },
  'E7-02': { requires: ['E7-01'] },
  'E7-03': { requires: ['E7-01'] },
  'E7-04': { requires: ['E7-01'] },
  'E7-05': { requires: ['E7-01'] },
  'E7-06': { requires: ['E7-01', 'E5-06'] },
  'E7-07': { requires: ['E7-03'] },
  'E7-08': { requires: ['E7-03', 'E7-04', 'E7-05'] },

  'E8-01': { requires: E0_GATE },
  'E8-02': { requires: ['E8-01'] },
  'E8-03': { requires: ['E8-01'] },
  'E8-04': { requires: ['E8-01'] },
  'E8-05': { requires: ['E8-01'] },
  'E8-06': { requires: ['E8-03', 'E8-04', 'E8-05'] },
});

const TASK_RE = /^\*\*(E\d-\d\d) — ([^*]+?)\.\*\*\s*([\s\S]*?)$/;

function splitAccept(body) {
  const at = body.indexOf('**Accept:**');
  if (at < 0) return { description: body.trim(), acceptance: '' };
  return { description: body.slice(0, at).trim(), acceptance: body.slice(at + '**Accept:**'.length).trim() };
}

/** Every task paragraph in the PRD, in document order. Throws when a task id repeats or a task has no acceptance text. */
export function parseTasks(prdText) {
  const lines = String(prdText).split('\n');
  const found = [];
  for (const line of lines) {
    const m = TASK_RE.exec(line);
    if (!m) continue;
    const { description, acceptance } = splitAccept(m[3]);
    found.push({ id: m[1], title: m[2].trim(), description, acceptance });
  }
  const seen = new Set();
  for (const t of found) {
    if (seen.has(t.id)) throw new Error(`task ${t.id} appears twice in the PRD`);
    seen.add(t.id);
    if (!t.acceptance) throw new Error(`task ${t.id} has no Accept: clause`);
  }
  return found;
}

/** The exit-gate sentence of each epic (`**E1 exit gate:** ...`). */
export function parseExitGates(prdText) {
  const gates = {};
  for (const line of String(prdText).split('\n')) {
    const m = /^\*\*(E\d) exit gate:\*\*\s*(.+)$/.exec(line);
    if (m) gates[m[1]] = m[2].trim();
  }
  return gates;
}

export function buildManifest(prdText, { prdSha256 = null, prdName = 'AGENTIC_SECURITY_ENGINEERING_EXCELLENCE_MASTER.prd' } = {}) {
  const parsed = parseTasks(prdText);
  const gates = parseExitGates(prdText);
  const epicOf = (id) => EPICS.find((e) => e.id === id.slice(0, 2));
  const tasks = parsed.map((t) => {
    const epic = epicOf(t.id);
    if (!epic) throw new Error(`task ${t.id} belongs to no known epic`);
    const dep = DEPENDENCIES[t.id];
    if (!dep) throw new Error(`task ${t.id} has no dependency entry`);
    const n = t.id.slice(3);
    return {
      id: t.id,
      title: t.title,
      epic: epic.id,
      priority: epic.priority,
      weight: PRIORITY_WEIGHT[epic.priority],
      requires: [...dep.requires],
      informedBy: [...(dep.informedBy || [])],
      description: t.description,
      acceptance: t.acceptance,
      expectedTests: [`scanner/test/engineering-excellence/${epic.id.toLowerCase()}-${n}*.test.js`],
    };
  });
  for (const id of Object.keys(DEPENDENCIES)) if (!tasks.some((t) => t.id === id)) throw new Error(`dependency table names ${id}, which the PRD does not define`);
  const ids = new Set(tasks.map((t) => t.id));
  for (const t of tasks) for (const r of [...t.requires, ...t.informedBy]) if (!ids.has(r)) throw new Error(`${t.id} depends on unknown task ${r}`);
  assertAcyclic(tasks);
  return {
    schemaVersion: 1,
    program: 'agentic-security-engineering-excellence',
    source: { file: prdName, sha256: prdSha256 },
    epics: EPICS.map((e) => ({ ...e, exitGate: gates[e.id] || null, taskCount: tasks.filter((t) => t.epic === e.id).length })),
    tasks,
  };
}

export function assertAcyclic(tasks) {
  const state = new Map();
  const byId = new Map(tasks.map((t) => [t.id, t]));
  const visit = (id, trail) => {
    if (state.get(id) === 2) return;
    if (state.get(id) === 1) throw new Error(`dependency cycle: ${[...trail, id].join(' -> ')}`);
    state.set(id, 1);
    for (const r of byId.get(id).requires) visit(r, [...trail, id]);
    state.set(id, 2);
  };
  for (const t of tasks) visit(t.id, []);
}
