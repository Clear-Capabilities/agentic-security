// Privacy lineage: field-to-sink expectations, scored separately from every security layer. A security finding never stands in
// for a privacy measurement and a taint metric is never reported as a privacy metric.
import { prf } from '../../../scanner/src/language/accuracy.js';
import { buildProjectIR } from '../../../scanner/src/ir/index.js';
import { buildLineageGraph } from '../../../scanner/src/lineage/index.js';
import { readJson, source } from '../lib.mjs';

function flowsOf(files) {
  const { perFile, callGraph } = buildProjectIR(files);
  const r = buildLineageGraph(callGraph, { perFile, fileContents: files, repository: 'measure', deterministic: true });
  if (r.status !== 'complete') return { failed: true, flows: [] };
  const els = Object.fromEntries(r.graph.dataElements.map((e) => [e.id, e]));
  const nodes = Object.fromEntries(r.graph.nodes.map((n) => [n.id, n]));
  return { failed: false, flows: r.graph.flows.map((f) => ({ fields: f.dataElementIds.map((i) => els[i].name), sink: nodes[f.sink], protection: f.protectionSummary, handling: f.handling })) };
}

export async function runPrivacy({ split, eco }) {
  const cs = readJson('labels/privacy.json').filter((c) => c.ecosystem === eco && c.split === split);
  let tp = 0, fp = 0, fn = 0, tn = 0, failed = 0;
  const byKind = {}; const misses = []; const strays = [];
  for (const c of cs) {
    const r = flowsOf({ [c.path]: source(`privacy-${eco}`, c.id, c.path) });
    if (r.failed) failed++;
    // predicted: the labeled field reaches a sink UNPROTECTED (a protected or absent flow is "no flow")
    const predicted = r.flows.some((f) => f.fields.includes(c.field) && f.protection !== 'protected' && f.handling !== 'hashed' && f.handling !== 'masked');
    const want = c.expected === 'flow';
    const k = (byKind[c.kind] ||= { tp: 0, fp: 0, fn: 0, tn: 0 });
    if (want && predicted) { tp++; k.tp++; } else if (want && !predicted) { fn++; k.fn++; misses.push(c.id); } else if (!want && predicted) { fp++; k.fp++; strays.push(c.id); } else { tn++; k.tn++; }
  }
  const m = prf(tp, fp, fn);
  return { cases: cs.length, positives: tp + fn, negatives: fp + tn, tp, fp, fn, tn, lineageFailures: failed, precision: m.precision, recall: m.recall, f1: m.f1, byKind, misses: misses.slice(0, 20), strays: strays.slice(0, 20) };
}
