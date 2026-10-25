// False source attribution scoring for bench/dag.
//
// A reported flow names the source field(s) it carries. It is a FALSE SOURCE
// ATTRIBUTION when the field it reports is not the field the hand label says
// reaches that sink (typically a sibling field of the same object), or when no
// field reaches that sink at all (a spurious flow). The three outcomes are kept
// apart, with denominators, because "wrong sibling" and "nothing flows" are
// different defects.
//
// Controlled fixture. A reported flow is EXAMINED when some positive flow label
// names a source file the flow's source locations include. An examined flow is
// CORRECT when one of its fields is a positive label's field for that file and
// the label's sink kind matches the flow's (a flow into an unresolved sink is
// judged on the field alone); otherwise it is a FALSE attribution (sibling or
// spurious field). Independently, a reported flow that matches a
// NEGATIVE label (the field the label says must not reach a sink, with its
// source kind when the label names one) is counted under `negativeLabelHits`.
//
// Natural code. labels/real-flows.json holds a verdict per reported flow.
//
// Neither is a recall measure: a flow the scanner did not report is not
// examined here (see the recall columns for that).

const sinkMatches = (flow, kind) => !kind || flow.sinkKind === kind || flow.sinkSub === kind;

export function scoreFixtureAttribution(labelsDoc, flows) {
  const positives = labelsDoc.labels.filter((l) => l.type === 'flow' && l.verdict === 'positive');
  const negatives = labelsDoc.labels.filter((l) => l.type === 'flow' && l.verdict === 'negative');
  const rows = [];
  let unexamined = 0;
  for (const f of flows) {
    const scope = positives.filter((p) => !p.sourceFile || f.files.includes(p.sourceFile));
    if (!scope.length) { unexamined += 1; continue; }
    // An unresolved sink cannot contradict a label's sink kind, so only the field is judged there.
    const ok = scope.some((p) => f.fields.includes(p.field) && (f.sinkKind === 'unresolved' || sinkMatches(f, p.sinkKind)));
    rows.push({ fields: f.fields, files: f.files, sinkKind: f.sinkKind, sinkSub: f.sinkSub, outcome: ok ? 'correct' : 'false', expected: [...new Set(scope.map((p) => p.field))].sort() });
  }
  const negativeLabelHits = [];
  for (const n of negatives) {
    const hit = flows.some((f) => f.fields.includes(n.field) && (!n.sourceKind || f.sourceKind === n.sourceKind));
    negativeLabelHits.push({ id: n.id, hit });
  }
  // Positive labels with no matching reported flow: the field is missing, so a
  // sibling field may be standing in for it (counted, not scored as misattribution).
  const missingPositive = positives.filter((p) => !flows.some((f) => (f.sinkKind === 'unresolved' || sinkMatches(f, p.sinkKind)) && f.fields.includes(p.field) && (!p.sourceFile || f.files.includes(p.sourceFile)))).map((p) => p.id);
  return {
    flowsReported: flows.length, examined: rows.length, unexamined,
    correct: rows.filter((r) => r.outcome === 'correct').length,
    falseAttributions: rows.filter((r) => r.outcome === 'false').length,
    negativeLabels: negatives.length, negativeLabelHits: negativeLabelHits.filter((x) => x.hit).length,
    missingPositive, rows, negativeRows: negativeLabelHits,
  };
}

export function scoreRealAttribution(labelDoc, unitId, flows) {
  const labels = labelDoc.labels.filter((l) => l.unit === unitId);
  const out = { flowsReported: flows.length, labeled: 0, unlabeled: 0, correct: 0, wrongField: 0, spurious: 0, sourceKindMismatch: 0, rows: [] };
  for (const f of flows) {
    const first = [...f.sources].sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1))[0];
    const lab = first && labels.find((l) => l.file === first.file && l.line === first.line && f.fields.includes(l.field));
    if (!lab) { out.unlabeled += 1; out.rows.push({ file: first ? first.file : null, line: first ? first.line : null, field: f.fields[0], outcome: 'unlabeled' }); continue; }
    out.labeled += 1;
    let outcome;
    if (lab.verdict === 'no-flow') outcome = 'spurious';
    else if (f.fields.length === 1 && f.fields[0] === lab.expectedField) outcome = 'correct';
    else outcome = 'wrong-field';
    if (outcome === 'correct') out.correct += 1; else if (outcome === 'spurious') out.spurious += 1; else out.wrongField += 1;
    const kindWrong = !!lab.expectedSourceKind && f.sourceKind !== lab.expectedSourceKind;
    if (kindWrong) out.sourceKindMismatch += 1;
    out.rows.push({ id: lab.id, outcome, sourceKindMismatch: kindWrong, reportedSourceKind: f.sourceKind });
  }
  return out;
}
