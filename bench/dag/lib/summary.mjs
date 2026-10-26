// Markdown summary for a bench/dag run. Every rate is printed with its
// numerator and denominator; a rate with a zero denominator prints "n/a".
const frac = (n, d) => (d ? `${(Math.round((n / d) * 1000) / 10).toFixed(1)}% (${n}/${d})` : 'n/a (0)');
const num = (v) => (v === null || v === undefined ? 'n/a' : String(v));
const table = (head, rows) => [`| ${head.join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r.join(' | ')} |`)].join('\n');

function labelCell(a) {
  return `TP ${a.TP} FP ${a.FP} FN ${a.FN} TN ${a.TN} (excluded ${a.excluded})`;
}

export function renderSummary(out, manifest, { realLabels, fixtureLabelsDoc }) {
  const L = [];
  const p = (s = '') => L.push(s);
  p('# bench/dag results');
  p();
  p(`Commit \`${out.commit.slice(0, 12)}\`${out.worktreeDirty ? ' (worktree had uncommitted changes)' : ''}, mode **${out.env.mode}**, reps ${out.env.reps}, wall clock ${out.wallClockSeconds}s, ${out.env.platform}, ${out.env.cpus} CPUs, ${out.env.memGb} GB, Node ${out.env.node}. Generated ${out.generatedAt}.`);
  p();
  p('Timing and memory below are raw measurements from this host and are not part of the equality check. Everything else is deterministic and is what `--check` compares.');
  p();

  p('## Per-language results (natural code)');
  p();
  const langs = Object.keys(out.languages);
  p(table(
    ['Language', 'Units (ok/total)', 'Files', 'Labeled sample', 'Precision', 'Recall', 'Graph completion rate', 'Truncated query rate', 'p50 / p95 ms (n)', 'Peak RSS MB'],
    langs.map((l) => {
      const x = out.languages[l];
      return [l, `${x.unitsOk}/${x.units}`, x.files, labelCell(x.labels),
        x.labels.precision === null ? 'n/a' : frac(x.labels.TP, x.labels.precisionDenominator),
        x.labels.recall === null ? 'n/a' : frac(x.labels.TP, x.labels.recallDenominator),
        frac(x.unitsGraphComplete, x.unitsWithGraph), frac(x.truncatedQueries, x.queryDenominator),
        `${num(x.timeMs.p50)} / ${num(x.timeMs.p95)} (${x.timeMs.samples})`, num(x.peakRssMb)];
    })));
  p();
  p('Denominators. Precision = TP / (TP + FP) over labeled sites the scanner reported on. Recall = TP / (TP + FN) over labeled positive sites. Completion rate = units whose lineage graph reports status `complete` over units that produced a graph. Truncated query rate = path queries that hit a budget over call-statement sink sites (the number of path queries the graph builder issues; the builder does not export a separate query count, so this denominator is an approximation, stated here rather than hidden). p95 over a small number of units is close to the maximum; with `--reps` it is over repeated samples of the same units, not over more projects.');
  p();

  p('Line-precise view (a finding without a line number is NOT credited to any label, so only line-level matches count as reported):');
  p();
  p(table(['Language', 'Labeled sample', 'Precision', 'Recall'], langs.map((l) => {
    const a = out.languages[l].labelsLineOnly;
    return [l, labelCell(a), a.precision === null ? 'n/a' : frac(a.TP, a.precisionDenominator), a.recall === null ? 'n/a' : frac(a.TP, a.recallDenominator)];
  })));
  p();

  p('## Held-out subset');
  p();
  p('A label is held out when the first byte of sha256(label id) is divisible by 3. The split depends on the id only. The benchmark itself never tunes the scanner. The scanner precision changes recorded in docs/implementation-status/dag-improvements.md were diagnosed from the labeled false-positive sites of BOTH columns (the baseline lists every site), so for those changes the held-out column is not held out; what guards against fitting is that each change is a general rule with a both-directions test in bench/mutation and the recall gates unchanged. Anyone who tunes further should leave the held-out subset alone. Disclosure: the same person wrote every label and chose negatives after looking at which sites the scanner reported on, so even the held-out subset is not independent of the labeller.');
  p();
  p(table(['Language', 'Development', 'Held-out'], langs.map((l) => {
    const x = out.languages[l];
    const f = (a) => `${labelCell(a)}; P ${a.precision === null ? 'n/a' : frac(a.TP, a.precisionDenominator)}; R ${a.recall === null ? 'n/a' : frac(a.TP, a.recallDenominator)}`;
    return [l, f(x.labelsDevelopment), f(x.labelsHeldOut)];
  })));
  p();

  p('## Labeled sample by class');
  p();
  const byClass = {};
  for (const r of out.labelRows) {
    const k = `${r.language}/${r.class}`;
    (byClass[k] ||= []).push(r);
  }
  p(table(['Language / class', 'TP', 'FP', 'FN', 'TN'], Object.keys(byClass).sort().map((k) => {
    const c = { TP: 0, FP: 0, FN: 0, TN: 0, excluded: 0 };
    for (const r of byClass[k]) c[r.outcome]++;
    return [k, c.TP, c.FP, c.FN, c.TN];
  })));
  p();
  p(`File-level credits (a finding without a line number credited to every same-class label in its file): ${out.labelRows.filter((r) => r.fileLevel).length} of ${out.labelRows.length} scored labels.`);
  p();

  p('## Controlled multi-service fixture');
  p();
  p('Authored for this benchmark, HTTP api to queue worker to storage to HTTP reporting. Reported separately from natural-code metrics. Labels live outside the scanned tree and the sources carry no labels or comments.');
  p();
  p(table(['Label', 'Type', 'Verdict', 'Construct', 'Outcome'], out.fixtureRows.map((r) => [r.id, r.type, r.verdict, r.construct, r.outcome + (r.type === 'flow' && r.outcome === 'TP' ? (r.sinkMatch ? ' (sink kind matches)' : ' (reached, sink kind differs)') : '')])));
  p();
  const fx = { TP: 0, FP: 0, FN: 0, TN: 0 };
  for (const r of out.fixtureRows) fx[r.outcome]++;
  p(`Fixture totals: TP ${fx.TP} FP ${fx.FP} FN ${fx.FN} TN ${fx.TN}. Recall ${frac(fx.TP, fx.TP + fx.FN)}, precision ${frac(fx.TP, fx.TP + fx.FP)}. ${fx.FN} missed positives are scanner gaps (for example boundary handoffs the lineage graph does not join), recorded rather than hidden.`);
  p();

  p('## Synthetic injected mutants (verdict flips, not natural-code metrics)');
  p();
  p(table(['Mutant', 'Kind', 'Base reported', 'After reported', 'Expected after', 'Correct', 'Flipped'], out.mutantRows.map((r) => r.status === 'ok'
    ? [r.id, r.kind, r.baseReported, r.afterReported, r.expectedReported, r.correct ? 'yes' : 'NO', r.flipped ? 'yes' : 'no']
    : [r.id, r.kind, r.status, '', '', '', ''])));
  p();
  const ok = out.mutantRows.filter((r) => r.status === 'ok');
  p(`Correct after mutation: ${frac(ok.filter((r) => r.correct).length, ok.length)}. Expected flips achieved: ${frac(ok.filter((r) => r.flipExpected && r.flipped).length, ok.filter((r) => r.flipExpected).length)}. A mutant whose base verdict already equals the expected one cannot show a flip and is counted only under "correct".`);
  p();

  p('## Incremental reuse');
  p();
  const inc = Object.entries(out.incremental);
  if (inc.length) {
    p(table(['Unit', 'Summary units', 'Restorable', 'Changed files', 'Changed units', 'Reused', 'Invalidated', 'Warm/cold parity', 'Cold ms', 'Warm ms', 'Warm after edit ms', 'Cold after edit ms'], inc.map(([id, r]) => r.status !== 'ok'
      ? [id, r.status, r.reason || '', '', '', '', '', '', '', '', '', '']
      : [id, r.summaryUnits, r.restorableEmptyEntryUnits, r.changedFiles, r.changedUnits, r.reusedUnits, r.invalidatedUnits, r.parity.equal ? `equal (${r.parity.warmFindings} findings)` : `DIFFERS (+${r.parity.onlyWarm}/-${r.parity.onlyCold})`, r.timesMs.cold, r.timesMs.warm, r.timesMs.warmAfterEdit, r.timesMs.coldAfterEdit])));
    p();
    p('Counts are persisted summary units (functions the taint engine analysed), selected with the engine\'s own `diffFileHashes` and `pickReusableSummaries`; the edit appends one function to one JS file. Parity compares the findings of an incremental warm scan with a cold scan of the same edited tree.');
  } else p('Not run.');
  p();

  renderEvidence(out, p);

  p('## Synthetic graph families (SCC computation)');
  p();
  const syn = Object.entries(out.synthetic);
  p(table(['Family / nodes', 'Edges', 'SCCs', 'Largest SCC', 'Matches construction', 'verifyScc', 'SCC ms', 'Peak RSS MB'], syn.map(([id, r]) => r.status === 'error' || r.status === 'timeout'
    ? [id, r.status, r.error || '', '', '', '', '', '']
    : [id, r.observed.edgeCount, r.observed.sccCount, r.observed.largestScc, r.matchesExpected ? 'yes' : 'NO', r.verifyScc === null ? 'skipped' : r.verifyScc ? 'ok' : 'FAIL', r.timesMs.scc, r.peakRssMb])));
  p();
  p(`Seeded generators (seed fixed in run.mjs); every graph carries a SHA-256 digest of its edge list in the baseline. Largest size this run: ${out.env.syntheticMaxNodes.toLocaleString('en-US')} nodes (host memory permitting). These measure \`src/graph/scc.js\` on call-graph-shaped inputs; they do not run the taint engine on a million-node program.`);
  p();

  p('## Units');
  p();
  p(table(['Unit', 'Language', 'Status', 'Files', 'Findings', 'Graph nodes / edges / flows', 'Graph status', 'ms (median)', 'Peak RSS MB'], Object.values(out.units).map((r) => r.status !== 'ok'
    ? [r.id, r.language, r.status + (r.reason ? `: ${r.reason}` : ''), '', '', '', '', '', '']
    : [r.id, r.language, 'ok', r.files, (r.findings || []).length, r.graph ? `${r.graph.nodes} / ${r.graph.edges} / ${r.graph.flowCount}` : 'no graph', r.graph ? r.graph.completion.status : 'n/a', num(pctMedian(r.msSamples)), r.peakRssMb])));
  p();

  p('## Pinned projects');
  p();
  p(table(['Project', 'Commit', 'License', 'Resolved this run'], manifest.projects.map((x) => [x.id, x.commit.slice(0, 12), x.license, (out.manifestPins.find((m) => m.id === x.id) || {}).resolved ? 'yes' : 'no'])));
  p();

  p('## Limitations');
  p();
  for (const s of [
    `The labeled sample is ${realLabels.length} hand labels across ${manifest.projects.length} projects, chosen by reading sink sites. It is a sample, not a census: recall is over the positives the labeller found, not over every vulnerability in the projects.`,
    'Negatives were mostly chosen at sites the scanner had reported on, with a smaller number of unreported sinks added as true negatives. Precision is therefore a statement about the labeled flagged sites, not a population false-positive rate.',
    'Natural vulnerable examples are scarce. Most positives are example-app patterns (reflected parameters, Referer redirects) and framework weaknesses (fast hash, non-cryptographic session ids), not exploitable production bugs.',
    'Labels were written by one person who saw the scanner output. The held-out subset is a discipline for future tuning, not independent ground truth.',
    'Line-less structural findings are credited at file granularity (reported above).',
    'Evidence replay, false source attribution and call/return realizability are measured in the sections above on the JS/TS units, the multi-service fixture and the call/return fixture only. Haskell and Nix units are not part of these measurements.',
    'The real-flow attribution labels (labels/real-flows.json) were written after listing the flows the scanner reported, so they judge those flows and are not independent of it.',
    'Haskell and Nix are analysed statically and never built or evaluated. Nix selections are bounded subsets (see the manifest for roots and exclusions); the Nix numbers say nothing about the rest of nixpkgs or Home Manager.',
    'Single run per unit by default; p50/p95 are over units (or over repeated samples with --reps) on one host. They are not a reference-host performance claim.',
    'Synthetic families exercise the SCC computation only. They are not a substitute for a SBOM or conformance program for Haskell or Nix.',
  ]) p(`- ${s}`);
  p();
  return L.join('\n') + '\n';
}

function renderEvidence(out, p) {
  const ev = out.evidenceReplay;
  p('## Evidence replay (witness bundles)');
  p();
  if (ev.status !== 'measured') { p(`Status: **${ev.status}**. ${ev.reason || ''}`); p(); return; }
  p('For each sink with a reconstructed witness, up to 60 per unit (sinks in id order, a path that crosses a call boundary preferred), a bundle is built from the real hop stream with `buildWitnessBundle`, signed with an ephemeral Ed25519 key, and replayed offline with `verifyWitness` against the exact artifacts (graph, provenance export, source blobs). Replay success is replayed / built. The bundles are built in-process from `runFieldIdentityAnalysis` with `recordHop`, the same way the witness-bundle tests do; a scan does not persist the hop stream, so there is no `attest --witness` path to measure.');
  p();
  const units = Object.entries(out.evidence).filter(([, r]) => r.status === 'ok');
  p(table(['Unit', 'Sinks with a path', 'Bundles attempted', 'Build refused', 'Built', 'Replayed', 'Replay failed', 'Built across a call boundary', 'Replayed across a call boundary', 'Complete overall'], units.map(([id, r]) => {
    const w = r.witness;
    return [id, w.sinksWithPaths, w.bundlesAttempted, w.buildRefused, w.built, frac(w.replayed, w.built), w.replayFailed, w.builtCrossScope, frac(w.replayedCrossScope, w.builtCrossScope), frac(w.completeBundles, w.built)];
  }).concat([['**all**', ev.sinksWithPaths, ev.bundlesAttempted, ev.buildRefused, ev.built, frac(ev.replayed, ev.built), ev.replayFailed, ev.builtCrossScope, frac(ev.replayedCrossScope, ev.builtCrossScope), frac(ev.completeBundles, ev.built)]])));
  p();
  const failCodes = {};
  for (const [, r] of units) for (const [c, n] of Object.entries(r.witness.replayFailureCodes)) failCodes[c] = (failCodes[c] || 0) + n;
  const refused = {};
  for (const [, r] of units) for (const [c, n] of Object.entries(r.witness.buildRefusedReasons)) refused[c] = (refused[c] || 0) + n;
  p(`Replay failure codes: ${Object.keys(failCodes).length ? Object.entries(failCodes).map(([c, n]) => `${c} x${n}`).join(', ') : 'none'}. Build refusals: ${Object.keys(refused).length ? Object.entries(refused).map(([c, n]) => `${c} x${n}`).join(', ') : 'none'}.`);
  p();
  p('Tamper rejection, on the first 40 replayable bundles of each unit. The unmodified bundle replaying (above) is the control for each row.');
  p();
  const names = { 'edge-altered-resigned': 'a recorded edge changed and the bundle re-signed (only replay can catch it)', 'edge-altered-unsigned': 'a recorded edge changed, signature left alone', 'source-blob-altered': 'a bound source file altered', 'graph-altered': 'the graph artifact replaced by a different graph' };
  p(table(['Tamper', 'Rejected'], Object.entries(ev.tamper).map(([k, v]) => [names[k], frac(v.rejected, v.attempted)])));
  p();
  p('A rejection rate is over the tamper kinds listed. It says nothing about tamper kinds not tried (a changed transfer model, a swapped provenance export with a consistent digest).');
  p();

  p('## False source attribution');
  p();
  p('A reported flow is a false attribution when the source field it names is not the field the hand label says reaches that sink. Definitions and the labelling method are in `lib/attribution.mjs` and `labels/real-flows.json`. This is not a recall measure: a flow the scanner did not report is not examined.');
  p();
  const fx = out.attribution && out.attribution.fixture;
  if (fx) {
    p(`Controlled multi-service fixture: ${fx.flowsReported} flows reported, ${fx.examined} examined (the flow's source file is the source file of a positive flow label), ${fx.unexamined} not examined. Correct: ${frac(fx.correct, fx.examined)}. False attributions (sibling or spurious field): ${frac(fx.falseAttributions, fx.examined)}. Reported flows matching a negative label (a field that must not reach that sink): ${frac(fx.negativeLabelHits, fx.negativeLabels)} of the negative labels. Positive labels with no matching reported flow: ${fx.missingPositive.length}${fx.missingPositive.length ? ` (${fx.missingPositive.join(', ')})` : ''}.`);
    p();
    p('Limit: two of the three reported flows end in the same unresolved sink, so the fixture cannot tell the `note` flow from the `qty` flow by sink; it can only catch a field that no positive label for that file names.');
    p();
    p(table(['Reported fields', 'Sink', 'Source files', 'Positive-label fields for that source file', 'Outcome'], fx.rows.map((r) => [r.fields.join(', '), `${r.sinkKind}/${r.sinkSub}`, r.files.join(', '), r.expected.join(', '), r.outcome])));
    p();
  }
  const realIds = Object.keys((out.attribution && out.attribution.real) || {});
  if (realIds.length) {
    const rr = realIds.map((id) => out.attribution.real[id]);
    const t = (f) => rr.reduce((a, x) => a + x[f], 0);
    p(table(['Natural unit', 'Flows reported', 'Labeled', 'Unlabeled', 'Correct field', 'Wrong (sibling) field', 'Spurious (no flow)', 'Source kind differs from label'], realIds.map((id, i) => {
      const x = rr[i];
      return [id, x.flowsReported, x.labeled, x.unlabeled, frac(x.correct, x.labeled), frac(x.wrongField, x.labeled), frac(x.spurious, x.labeled), frac(x.sourceKindMismatch, x.labeled)];
    }).concat([['**all**', t('flowsReported'), t('labeled'), t('unlabeled'), frac(t('correct'), t('labeled')), frac(t('wrongField'), t('labeled')), frac(t('spurious'), t('labeled')), frac(t('sourceKindMismatch'), t('labeled'))]])));
    p();
    p('The two lib roots report no flows, so they contribute no denominator. Eleven flows is a small sample; one spurious flow moves the rate by nine points.');
    p();
  }

  p('## Call/return realizability of reconstructed witnesses');
  p();
  p('Every sink with a reconstructed witness is queried in a version 1 store (the default) and a version 2 store (`correlationVersion: 2`) built from the same seeds. Each returned witness is walked source to sink by a checker that does not use invocation ids: a return edge must come back through the call site, caller activation and callee activation last entered. A witness that does not is impossible. A witness that begins inside a callee and returns to its caller has an unmatched return, which is realizable and not counted. Cap: 2000 sinks per store (not reached).');
  p();
  const crUnits = Object.entries(out.evidence).filter(([, r]) => r.status === 'ok');
  const crRow = (id, r) => {
    const a = r.callReturn.v1; const b = r.callReturn.v2;
    return [id, `${a.sinks} / ${b.sinks}`, `${a.paths} / ${b.paths}`, `${a.pathsWithCallOrReturn} / ${b.pathsWithCallOrReturn}`, frac(a.impossible, a.pathsWithCallOrReturn), frac(b.impossible, b.pathsWithCallOrReturn), b.balancingPrunedEdges, b.unbalancedTerminals, b.contextWidenedPaths];
  };
  p(table(['Unit', 'Sinks v1 / v2', 'Witnesses v1 / v2', 'Crossing a call boundary v1 / v2', 'Impossible v1', 'Impossible v2', 'v2 mismatched edges pruned', 'v2 unbalanced-call terminals', 'v2 context-widened'], crUnits.map(([id, r]) => crRow(id, r))));
  p();
  const tot = (v, f) => crUnits.reduce((a, [, r]) => a + r.callReturn[v][f], 0);
  p(`All units: impossible witnesses v1 ${frac(tot('v1', 'impossible'), tot('v1', 'pathsWithCallOrReturn'))}, v2 ${frac(tot('v2', 'impossible'), tot('v2', 'pathsWithCallOrReturn'))} (denominator: witnesses that cross at least one call or return edge). Natural units with a nonzero denominator in either version: ${crUnits.filter(([id, r]) => !id.startsWith('fixture/') && (r.callReturn.v1.pathsWithCallOrReturn + r.callReturn.v2.pathsWithCallOrReturn) > 0).map(([id]) => id).join(', ') || 'none'}; every other natural unit shows n/a (nothing crosses a call boundary), so it says nothing about the versions. The v1 and v2 stores enumerate their sinks independently (version 2 value-versions its nodes), so the sink counts can differ.`);
  p();
}

function pctMedian(a) {
  if (!a || !a.length) return null;
  const s = [...a].sort((x, y) => x - y);
  return s[Math.floor((s.length - 1) / 2)];
}
