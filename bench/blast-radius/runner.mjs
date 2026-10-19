#!/usr/bin/env node
// Differential bench for blast-radius assessment (computeImpactAssessment).
//
//   node bench/blast-radius/runner.mjs                 print the table
//   node bench/blast-radius/runner.mjs --check         compare to BASELINE.json for EQUALITY; exit 1 on any difference
//   node bench/blast-radius/runner.mjs --update-baseline
//
// What it measures: whether the assessment agrees with an independent reference on seeded graphs. The reference is written here, from the
// documented meaning of each target kind (docs/security-graph/blast-radius.md), and shares no code with the engine or the Explorer's graph
// helpers:
//   node target         the node, everything reachable downstream by directed edges, everything that reaches it upstream; the edges leaving the
//                       downstream set and entering the upstream set; the data classes of every flow that uses one of those edges
//   edge/flow/data      only the flows that carry it: their endpoints, their edges and those edges' endpoints, and the data classes they carry,
//                       never a sibling flow that merely shares a node
//   unknown id          empty, never a phantom node
// What it does not measure: whether a graph is a faithful picture of a program. The graphs are generated, so this is agreement with a
// specification, not recall against real code; the coverage limitation every real assessment carries says the same.
//
// The generator is a fixed-seed PRNG, so the bench is deterministic. Equality gate: a difference in either direction fails until the
// baseline is updated on purpose.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeImpactAssessment, } from '../../scanner/src/lineage/impact-engine.js';
import { validateImpactAssessment } from '../../scanner/src/lineage/impact-assessment.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASELINE = path.join(HERE, 'BASELINE.json');
const GRAPHS = 300;
const CLASSES = ['PII', 'CREDENTIALS', 'PCI', 'PHI', 'FINANCIAL'];

function prng(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

export function makeGraph(seed) {
  const r = prng(seed);
  const int = (lo, hi) => lo + Math.floor(r() * (hi - lo + 1));
  const nodes = Array.from({ length: int(4, 12) }, (_, i) => ({ id: `node:svc:n${i}`, coverageStatus: r() < 0.8 ? 'modeled' : 'partial' }));
  const edges = [];
  const nEdges = int(3, nodes.length * 2);
  for (let i = 0; i < nEdges; i++) {
    const from = nodes[int(0, nodes.length - 1)].id;
    const to = nodes[int(0, nodes.length - 1)].id;
    edges.push({ id: `edge:e${i}`, from, to, coverageStatus: 'modeled' });
  }
  const dataElements = Array.from({ length: int(1, 4) }, (_, i) => ({ id: `data:d${i}`, dataClasses: Array.from(new Set(Array.from({ length: int(1, 2) }, () => CLASSES[int(0, CLASSES.length - 1)]))) }));
  const flows = [];
  for (let i = 0; i < int(1, 5); i++) {
    const own = edges.filter(() => r() < 0.35);
    if (!own.length) own.push(edges[int(0, edges.length - 1)]);
    flows.push({
      id: `flow:f${i}`, source: own[0].from, sink: own[own.length - 1].to,
      edgeIds: own.map(e => e.id),
      dataElementIds: dataElements.filter(() => r() < 0.5).map(d => d.id),
    });
  }
  const recipientProfiles = Array.from({ length: int(0, 3) }, (_, i) => ({ id: `recipient:r${i}`, contributingGraphIds: nodes.filter(() => r() < 0.3).map(n => n.id) }));
  return { graphId: `graph:bench-${seed}`, nodes, edges, flows, dataElements, recipientProfiles, coverage: { languages: [{ language: 'js', tier: 'partial', irTaintRecallPct: 58 }] } };
}

// ---------------------------------------------------------------------------- the reference (independent of the engine)
function closure(start, step) {
  const seen = new Set([start]);
  const todo = [start];
  while (todo.length) for (const n of step(todo.pop())) if (!seen.has(n)) { seen.add(n); todo.push(n); }
  return seen;
}

export function reference(g, target) {
  const edgeById = new Map(g.edges.map(e => [e.id, e]));
  const nodeIds = new Set(g.nodes.map(n => n.id));
  const classesOf = (flows) => [...new Set(flows.flatMap(f => f.dataElementIds.flatMap(id => (g.dataElements.find(d => d.id === id)?.dataClasses) || [])))].sort();
  let nodes = new Set(), edges = new Set(), classes = [];
  if (target.startsWith('node:')) {
    if (nodeIds.has(target)) {
      const down = closure(target, n => g.edges.filter(e => e.from === n).map(e => e.to));
      const up = closure(target, n => g.edges.filter(e => e.to === n).map(e => e.from));
      nodes = new Set([...down, ...up]);
      for (const e of g.edges) if (down.has(e.from) || up.has(e.to)) edges.add(e.id);
      classes = classesOf(g.flows.filter(f => f.edgeIds.some(id => edges.has(id))));
    }
  } else {
    const carries = target.startsWith('flow:') ? f => f.id === target : target.startsWith('edge:') ? f => f.edgeIds.includes(target) : f => f.dataElementIds.includes(target);
    const flows = g.flows.filter(carries);
    for (const f of flows) {
      for (const n of [f.source, f.sink]) nodes.add(n);
      for (const id of f.edgeIds) { const e = edgeById.get(id); if (e) { edges.add(id); nodes.add(e.from); nodes.add(e.to); } }
    }
    if (target.startsWith('edge:') && edgeById.has(target)) { const e = edgeById.get(target); edges.add(target); nodes.add(e.from); nodes.add(e.to); }
    classes = classesOf(flows);
    nodes = new Set([...nodes].filter(n => nodeIds.has(n)));
  }
  const recipients = g.recipientProfiles.filter(rp => rp.contributingGraphIds.some(id => nodes.has(id))).map(rp => rp.id).sort();
  return { nodes: [...nodes].sort(), edges: [...edges].sort(), classes, recipients };
}

/** Which parts of an assessment agree with the reference. Exported so a test can prove a perturbed assessment is caught. */
export function compare(a, ref) {
  return {
    nodes: JSON.stringify(a.affectedNodeIds) === JSON.stringify(ref.nodes),
    edges: JSON.stringify(a.affectedEdgeIds) === JSON.stringify(ref.edges),
    classes: JSON.stringify(a.affectedDataClasses) === JSON.stringify(ref.classes),
    recipients: JSON.stringify(a.affectedRecipientProfileIds) === JSON.stringify(ref.recipients),
  };
}

function targetsOf(g) {
  return [
    ...g.nodes.map(n => n.id), ...g.edges.map(e => e.id), ...g.flows.map(f => f.id), ...g.dataElements.map(d => d.id),
    'node:svc:missing', 'edge:missing', 'flow:missing', 'data:missing',
  ];
}

export function measure() {
  const total = { graphs: GRAPHS, targets: 0, nodesAgree: 0, edgesAgree: 0, classesAgree: 0, recipientsAgree: 0, schemaValid: 0, phantomNodes: 0, disclosesCoverage: 0 };
  const byKind = {};
  const disagreements = [];
  for (let seed = 1; seed <= GRAPHS; seed++) {
    const g = makeGraph(seed);
    for (const t of targetsOf(g)) {
      const a = computeImpactAssessment(g, t, { generatedAt: '2026-01-01T00:00:00.000Z' });
      const ref = reference(g, t);
      const kind = t.split(':')[0];
      const k = (byKind[kind] ||= { targets: 0, agree: 0 });
      total.targets++; k.targets++;
      const ok = compare(a, ref);
      if (ok.nodes) total.nodesAgree++;
      if (ok.edges) total.edgesAgree++;
      if (ok.classes) total.classesAgree++;
      if (ok.recipients) total.recipientsAgree++;
      if (ok.nodes && ok.edges && ok.classes && ok.recipients) k.agree++;
      else if (disagreements.length < 5) disagreements.push({ seed, target: t, got: { n: a.affectedNodeIds, e: a.affectedEdgeIds, c: a.affectedDataClasses }, want: ref });
      if (validateImpactAssessment(a).valid) total.schemaValid++;
      const real = new Set(g.nodes.map(n => n.id));
      if (a.affectedNodeIds.some(n => !real.has(n))) total.phantomNodes++;
      if (a.coverageLimitations.some(l => l.startsWith('js: coverage tier'))) total.disclosesCoverage++;
    }
  }
  return { schema: 'blast-radius/v1', total, byKind, disagreements };
}

function main() {
  const args = process.argv.slice(2);
  const m = measure();
  const t = m.total;
  const pc = (a) => `${a}/${t.targets} = ${(100 * a / t.targets).toFixed(2)}%`;
  console.log(`blast-radius: ${t.graphs} seeded graphs, ${t.targets} targets (nodes, edges, flows, data elements, and ids that do not exist)`);
  console.log(`  affected nodes agree        ${pc(t.nodesAgree)}`);
  console.log(`  affected edges agree        ${pc(t.edgesAgree)}`);
  console.log(`  data classes agree          ${pc(t.classesAgree)}`);
  console.log(`  recipient profiles agree    ${pc(t.recipientsAgree)}`);
  console.log(`  records pass the schema     ${pc(t.schemaValid)}`);
  console.log(`  phantom nodes reported      ${t.phantomNodes}  (must be 0)`);
  console.log(`  coverage limit disclosed    ${pc(t.disclosesCoverage)}`);
  for (const [k, v] of Object.entries(m.byKind)) console.log(`  ${k.padEnd(6)} fully agree ${v.agree}/${v.targets}`);
  for (const d of m.disagreements) console.log('  DISAGREEMENT', JSON.stringify(d));
  const recorded = { ...m, disagreements: undefined };
  if (args.includes('--update-baseline')) { fs.writeFileSync(BASELINE, JSON.stringify(recorded, null, 2) + '\n'); console.log(`wrote ${path.relative(process.cwd(), BASELINE)}`); return 0; }
  if (args.includes('--check')) {
    const base = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
    if (JSON.stringify(base) !== JSON.stringify(JSON.parse(JSON.stringify(recorded)))) {
      console.error('blast-radius check FAILED: the result differs from BASELINE.json (a drop is a regression; a rise is an unrecorded change).');
      console.error('  If the change is deliberate: node bench/blast-radius/runner.mjs --update-baseline, and say why in the commit.');
      return 1;
    }
    console.log('blast-radius check ok: identical to BASELINE.json');
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(main());
