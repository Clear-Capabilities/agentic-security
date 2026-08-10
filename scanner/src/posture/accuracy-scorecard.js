// Accuracy scorecard (roadmap R3) — aggregation + rendering.
//
// WHY THIS LIVES IN src/posture/ RATHER THAN ENTIRELY IN scripts/:
// every figure this project publishes has to be re-derivable and testable.
// The aggregation and the rendering are pure functions of their inputs, so
// they belong where the unit-test suite already runs (tests execute against
// `src/` directly). The thin driver at `scripts/scorecard.mjs` does the
// impure half — running the corpus, running the self-scan, reading the
// bundle hash and the git commit — and hands the results here. That split is
// what makes the "hand-computed fixture" test in
// `test/accuracy-scorecard.test.js` possible at all.
//
// INTEGRITY CONTRACT (the reason the item exists — read before editing):
//   · Nothing here invents a rate. Every rate is carried as {n, d} and
//     rendered through formatRate(), which always prints the numerator and
//     the denominator alongside the percentage. A denominator of 0 renders
//     "0/0 (n/a)" — never 0% and never 100%.
//   · Entries the run could not score (parser unavailable, scan error) are
//     removed from every denominator AND disclosed by name. Scoring them
//     either way would manufacture a number out of an environment fault.
//   · No F1 is emitted. F1 needs a precision measured over a labelled
//     real-world population; this corpus is curated known-vulnerable
//     fixtures and their fixed counterparts, so its "precision" would be
//     computed over a denominator that does not mean what the word implies.
//     See renderScorecardMarkdown()'s methodology section.
//   · Output is a deterministic function of the inputs apart from one
//     timestamp line (TIMESTAMP_MARKER), so the document regenerates
//     byte-identically on an unchanged tree.

// The single line of the rendered document that is permitted to vary between
// two runs on an unchanged tree. Tests and the regeneration check key on it.
export const TIMESTAMP_MARKER = 'Generated (UTC)';

/**
 * Render a rate with its raw counts. This is the ONLY sanctioned way to put a
 * percentage into the scorecard: a bare percentage with no visible
 * denominator is exactly the kind of unfalsifiable claim this document exists
 * to avoid.
 */
export function formatRate(n, d) {
  if (!d) return `${n}/${d} (n/a)`;
  return `${n}/${d} (${((n / d) * 100).toFixed(1)}%)`;
}

function emptyBucket(key) {
  return { key, entries: 0, detection: { n: 0, d: 0 }, silence: { n: 0, d: 0 } };
}

function accumulate(bucket, status) {
  bucket.entries++;
  if (status.includes('pre:TP')) { bucket.detection.n++; bucket.detection.d++; }
  else if (status.includes('pre:FN')) { bucket.detection.d++; }
  if (status.includes('post:TN')) { bucket.silence.n++; bucket.silence.d++; }
  else if (status.includes('post:FP')) { bucket.silence.d++; }
}

function sliceBy(scored, key) {
  const map = new Map();
  for (const d of scored) {
    const k = d[key] || 'unknown';
    if (!map.has(k)) map.set(k, emptyBucket(k));
    accumulate(map.get(k), d.status);
  }
  // Sorted by key so the document is stable across runs.
  return [...map.values()].sort((a, b) => a.key.localeCompare(b.key));
}

/**
 * Aggregate the per-entry detail records emitted by the corpus runner.
 *
 * Input records: { cve, tier, cwe, language, status, error? } where status is
 * the runner's own string form, e.g. "pre:TP post:TN", "pre:FN", "env-error".
 */
export function aggregateCorpus(detail) {
  const all = [...(detail || [])];
  const notScored = all
    .filter(d => !d.status || !d.status.startsWith('pre:'))
    .map(d => ({ cve: d.cve, tier: d.tier || null, language: d.language || null, status: d.status || 'unknown', error: d.error || null }))
    .sort((a, b) => String(a.cve).localeCompare(String(b.cve)));
  const scored = all.filter(d => d.status && d.status.startsWith('pre:'));

  const overall = emptyBucket('overall');
  for (const d of scored) accumulate(overall, d.status);

  return {
    totalEntries: all.length,
    scoredEntries: scored.length,
    notScored,
    overall: { detection: overall.detection, silence: overall.silence },
    byLanguage: sliceBy(scored, 'language'),
    byCwe: sliceBy(scored, 'cwe'),
    byTier: sliceBy(scored, 'tier'),
  };
}

/**
 * Build the machine-readable scorecard model. `inputs`:
 *   provenance   { engineVersion, bundleSha256, commit, nodeVersion, generatedAt }
 *   corpusDetail per-entry records from a corpus run performed THIS run
 *   selfScan     { targets: {name:{total,byFile}}, polyglot: {total,byLanguage} }
 *                — measured THIS run
 *   committed    { corpusBaseline, proofCorpus } — read from committed files,
 *                labelled as such in the output, never used to derive a rate
 */
export function buildScorecard(inputs) {
  const corpus = aggregateCorpus(inputs.corpusDetail);
  const selfScan = inputs.selfScan || {};
  const targets = {};
  for (const k of Object.keys(selfScan.targets || {}).sort()) {
    targets[k] = { total: selfScan.targets[k].total, byFile: selfScan.targets[k].byFile || {} };
  }
  const committed = inputs.committed || {};
  const proof = committed.proofCorpus || null;
  return {
    schema: 'agentic-security/accuracy-scorecard@1',
    provenance: { ...inputs.provenance },
    methodology: {
      population: 'curated known-vulnerable fixtures (pre/) and their fixed counterparts (post/)',
      detectionRateMeans: 'share of known-vulnerable fixtures where the expected finding fired',
      silenceRateMeans: 'share of fixed counterparts where the same finding correctly did not fire',
      notGeneralRecall: true,
      notGeneralFalsePositiveRate: true,
      f1Emitted: false,
      // Was: "no labelled real-world population is available". That stopped
      // being true when bench/independent/ was built, and a stale justification
      // is worse than none — it argues against a measurement that now exists.
      // No F1 is emitted FOR THE CURATED CORPUS, and the reason is narrower:
      // its `post/` fixtures are authored here to be silent, so its precision
      // denominator describes fixture design rather than engine behaviour.
      // F1 over the independent population IS reported, in its own section.
      f1OmissionReason: 'the curated corpus authors both its vulnerable and its fixed fixtures, so an F1 over it would measure fixture design, not accuracy; F1 over the labelled third-party population is reported separately from bench/independent/RESULT.json',
    },
    corpus: {
      measuredThisRun: true,
      totalEntries: corpus.totalEntries,
      scoredEntries: corpus.scoredEntries,
      notScored: corpus.notScored,
      overall: corpus.overall,
      byLanguage: corpus.byLanguage,
      byCwe: corpus.byCwe,
      byTier: corpus.byTier,
    },
    selfScan: { measuredThisRun: true, targets, polyglot: selfScan.polyglot || { total: 0, byLanguage: {} } },
    committedInputs: {
      corpusBaseline: committed.corpusBaseline
        ? { source: 'bench/cve-replay/corpus-baseline.json', generatedAt: committed.corpusBaseline.generatedAt, total: committed.corpusBaseline.total, passing: committed.corpusBaseline.passing }
        : null,
      independent: committed.independent
        ? {
          source: 'bench/independent/RESULT.json',
          measuredAt: committed.independent.measuredAt || null,
          engineVersion: committed.independent.engineVersion || null,
          population: committed.independent.population || null,
          overall: committed.independent.overall || null,
          wide: committed.independent.wide || null,
          byLanguage: committed.independent.byLanguage || null,
        }
        : null,
      proofCorpus: proof
        ? {
          source: 'bench/proof-corpus/results/summary.json',
          bundleSha: proof.bundleSha || null,
          targetCount: proof.targetCount ?? null,
          ok: proof.ok ?? null,
          failed: proof.failed ?? null,
          targets: (proof.targets || []).map(t => ({
            id: t.id, commit: t.commit, status: t.status,
            filesInScope: t.coverage?.totals?.inScope ?? null,
            filesParsed: t.coverage?.totals?.parsed ?? null,
            determinismChecked: t.determinism?.checked ?? null,
            determinismIdentical: t.determinism?.identical ?? null,
            resultsEmitted: t.determinism?.results ?? null,
          })).sort((a, b) => String(a.id).localeCompare(String(b.id))),
        }
        : null,
    },
  };
}

function rateRow(r) {
  return `| ${r.key} | ${r.entries} | ${formatRate(r.detection.n, r.detection.d)} | ${formatRate(r.silence.n, r.silence.d)} |`;
}

/** Render the human-readable scorecard. Deterministic apart from one line. */
export function renderScorecardMarkdown(m) {
  const p = m.provenance || {};
  const c = m.corpus;
  const L = [];
  L.push('# Accuracy scorecard');
  L.push('');
  L.push('Generated by `npm run scorecard`. Every figure below comes from a run');
  L.push('performed by that command, except where a line is explicitly labelled');
  L.push('*committed artifact* — those carry the timestamp and commit of the run');
  L.push('that produced them.');
  L.push('');
  L.push('## Provenance');
  L.push('');
  L.push('| Field | Value |');
  L.push('| --- | --- |');
  L.push(`| Engine version | ${p.engineVersion || 'unknown'} |`);
  L.push(`| Bundle SHA-256 | \`${p.bundleSha256 || 'unknown'}\` |`);
  L.push(`| Commit | \`${p.commit || 'unknown'}\` |`);
  if (p.worktreeClean !== undefined) {
    L.push(`| Worktree at measurement time | ${p.worktreeClean ? 'clean' : 'DIRTY — the commit above does not fully describe what was measured'} |`);
  }
  L.push(`| Node | ${p.nodeVersion || 'unknown'} |`);
  L.push(`| Corpus entries | ${c.totalEntries} (${c.scoredEntries} scored) |`);
  L.push(`| ${TIMESTAMP_MARKER} | ${p.generatedAt || 'unknown'} |`);
  L.push('');
  L.push('## What these numbers are, and what they are not');
  L.push('');
  L.push('The population is a curated corpus of known-vulnerable code fixtures');
  L.push('(`pre/`) each paired with its fixed counterpart (`post/`). Two rates are');
  L.push('reported, always with their raw numerator and denominator:');
  L.push('');
  L.push('- **Detection rate** — of the vulnerable fixtures, the share where the');
  L.push('  expected finding fired. This is **not** general-purpose recall against');
  L.push('  real-world code: the corpus is curated, each entry was added because it');
  L.push('  represents a class worth covering, and nothing here samples the');
  L.push('  distribution of vulnerabilities in arbitrary repositories.');
  L.push('- **Correct-silence rate** — of the fixed counterparts, the share where');
  L.push('  the same finding correctly did not fire. This is **not** a general');
  L.push('  false-positive rate: the denominator is one narrowly-scoped fixed file');
  L.push('  per entry, not a population of real code in which any rule could');
  L.push('  misfire.');
  L.push('');
  L.push('The corpus is also **gated**: an entry is admitted only once it scores');
  L.push('detected-on-`pre` and silent-on-`post`, and a committed baseline fails the');
  L.push('build on any drift. A detection rate at the ceiling is therefore expected');
  L.push('by construction — it is evidence that nothing regressed, not evidence that');
  L.push('there is no headroom. What moves it is adding entries for classes not yet');
  L.push('covered, which is why the corpus size is reported alongside the rate.');
  L.push('');
  L.push('**No F1 is reported, deliberately.** An F1 requires a precision measured');
  L.push('over a labelled real-world population. This project does not have one, so');
  L.push('a precision computed from the corpus alone would divide by a denominator');
  L.push('that does not describe the population the word implies. The precision-side');
  L.push('signal reported instead is the self-scan section below: exact finding');
  L.push('counts on this repository\'s own non-fixture source, where every count is');
  L.push('reviewed by hand and any movement is a real change. Publishing a number we');
  L.push('cannot defend would cost more credibility than the number is worth.');
  L.push('');
  L.push('## Corpus results (measured this run)');
  L.push('');
  L.push('| Population | Detected / correctly silent |');
  L.push('| --- | --- |');
  L.push(`| Vulnerable fixtures (\`pre/\`) — detection | ${formatRate(c.overall.detection.n, c.overall.detection.d)} |`);
  L.push(`| Fixed counterparts (\`post/\`) — correct silence | ${formatRate(c.overall.silence.n, c.overall.silence.d)} |`);
  L.push('');
  if (c.notScored.length) {
    const word = c.notScored.length === 1 ? 'entry' : 'entries';
    L.push('**' + c.notScored.length + ' corpus ' + word + ' could not be scored.** Excluded from every');
    L.push('denominator above rather than counted as a miss:');
    L.push('');
    for (const n of c.notScored) {
      const why = n.error ? ' — ' + n.error : '';
      L.push('- `' + n.cve + '` (' + (n.language || 'unknown') + '): ' + n.status + why);
    }
    L.push('');
  } else {
    L.push('All corpus entries scored; no entry was excluded.');
    L.push('');
  }
  L.push('### By language');
  L.push('');
  L.push('| Language | Entries | Detection (`pre/`) | Correct silence (`post/`) |');
  L.push('| --- | --- | --- | --- |');
  for (const r of c.byLanguage) L.push(rateRow(r));
  L.push('');
  L.push('### By CWE');
  L.push('');
  L.push('| CWE | Entries | Detection (`pre/`) | Correct silence (`post/`) |');
  L.push('| --- | --- | --- | --- |');
  for (const r of c.byCwe) L.push(rateRow(r));
  L.push('');
  L.push('### By corpus tier');
  L.push('');
  L.push('| Tier | Entries | Detection (`pre/`) | Correct silence (`post/`) |');
  L.push('| --- | --- | --- | --- |');
  for (const r of c.byTier) L.push(rateRow(r));
  L.push('');
  L.push('## Precision-side signal: self-scan (measured this run)');
  L.push('');
  L.push('The engine scanned its own repository. These are absolute finding');
  L.push('counts, not a rate — there is no labelled ground truth over this code,');
  L.push('so no precision figure is derived from it. What it supports is a');
  L.push('movement claim: any change in these counts between releases is a real');
  L.push('change in what the engine reports on unchanged code.');
  L.push('');
  L.push('**The two halves are not the same kind of evidence, so they are not');
  L.push('reported together.** `hooks/` and `scripts/` were reviewed by hand,');
  L.push('finding by finding. `scanner/src` was not: it is the engine itself, at a');
  L.push('scale no one has read line by line, and a scanner\'s own source contains');
  L.push('sink patterns as DATA — rule tables, catalogs, remediation strings — so a');
  L.push('large share of its findings are self-referential rather than defects.');
  L.push('Treat it as a tripwire, never as a quality figure.');
  L.push('');
  // Split deliberately. Both halves used to sit under a single "hand-reviewed"
  // sentence; when `scanner/src` was added to the gate its 594 findings
  // inherited a review claim that was true of 48 findings and false of these.
  // Widening a gate must not silently upgrade what its numbers assert.
  const REVIEWED = new Set(['hooks', 'scripts']);
  const entries = Object.entries(m.selfScan.targets);
  const reviewed = entries.filter(([k]) => REVIEWED.has(k));
  const unreviewed = entries.filter(([k]) => !REVIEWED.has(k));

  L.push('### Hand-reviewed targets');
  L.push('');
  L.push('| Target | Findings |');
  L.push('| --- | --- |');
  for (const [k, v] of reviewed) L.push(`| \`${k}\` | ${v.total} |`);
  L.push(`| \`polyglot\` fixture (expected 0) | ${m.selfScan.polyglot.total} |`);
  L.push('');
  if (unreviewed.length) {
    L.push('### Drift tripwire — NOT hand-reviewed, NOT a precision signal');
    L.push('');
    L.push('| Target | Findings |');
    L.push('| --- | --- |');
    for (const [k, v] of unreviewed) L.push(`| \`${k}\` | ${v.total} |`);
    L.push('');
    L.push('These counts exist so that a rule which starts firing somewhere new is');
    L.push('visible per file. Nobody has adjudicated them, and quoting the total as');
    L.push('a false-positive count would be wrong in both directions.');
    L.push('');
  }
  L.push('Per-file counts are in `docs/scorecard.json`.');
  L.push('');
  const ind = m.committedInputs.independent;
  if (ind && ind.overall) {
    L.push('## Independent evaluation population — the number that matters');
    L.push('');
    L.push('Everything above is a **regression net**: its fixtures and its labels are both');
    L.push('written here, which is why its detection rate sits at the ceiling by');
    L.push('construction. `bench/independent/` is the other instrument — real upstream code');
    L.push('at the commit where a vulnerability really existed, with the CWE assigned by a');
    L.push('public advisory database rather than by this project.');
    L.push('');
    L.push(`**Measured ${ind.measuredAt} on engine ${ind.engineVersion}, ` +
      `n=${ind.population?.scoredEntries}, ${ind.population?.unscored} unscored** ` +
      '(*committed artifact*, `' + ind.source + '` — read, not re-run: scoring takes ~32 minutes).');
    L.push('');
    L.push('| | Advisory-local (**the claim**) | Wide (diagnostic) |');
    L.push('| --- | --- | --- |');
    L.push(`| Precision | **${formatRate(ind.overall.precision?.n, ind.overall.precision?.d)}** | ${formatRate(ind.wide?.precision?.n, ind.wide?.precision?.d)} |`);
    L.push(`| Recall | **${formatRate(ind.overall.recall?.n, ind.overall.recall?.d)}** | ${formatRate(ind.wide?.recall?.n, ind.wide?.recall?.d)} |`);
    L.push(`| F1 | **${ind.overall.f1 === null || ind.overall.f1 === undefined ? 'n/a' : ind.overall.f1.toFixed(3)}** | ${ind.wide?.f1 === null || ind.wide?.f1 === undefined ? 'n/a' : ind.wide.f1.toFixed(3)} |`);
    L.push('');
    if (ind.byLanguage) {
      L.push('| Language | n | Recall | Precision |');
      L.push('| --- | --- | --- | --- |');
      for (const [k, v] of Object.entries(ind.byLanguage)) {
        L.push(`| ${k} | ${v.entries} | ${formatRate(v.recall?.n, v.recall?.d)} | ${formatRate(v.precision?.n, v.precision?.d)} |`);
      }
      L.push('');
    }
    L.push('**Quote the advisory-local column.** "Wide" scores the same scans without');
    L.push('restricting findings to the files the advisory\'s fix commit touched — it asks');
    L.push('only whether the CWE appeared *anywhere* in the package. Over scopes holding up');
    L.push('to 1740 findings that is close to asking whether the codebase contains the bug');
    L.push('class at all, a question with a much easier yes. It is kept because it is the');
    L.push('only way to tell whether a change moved the engine or moved the benchmark.');
    L.push('');
    L.push('Against ~100% on the curated corpus above. **That gap is the most useful number');
    L.push('in this document**, and publishing it is the point of the exercise. The figure');
    L.push('went DOWN when the benchmark was corrected, and is published that way.');
    L.push('');
  }
  L.push('## Committed artifacts referenced (not re-run by this command)');
  L.push('');
  const cb = m.committedInputs.corpusBaseline;
  if (cb) {
    L.push(`- **Corpus baseline** (*committed artifact*, \`${cb.source}\`, generated ${cb.generatedAt}):`);
    L.push(`  ${cb.passing}/${cb.total} entries recorded as passing. The gate`);
    L.push('  `npm run bench:cve-replay:check` fails the build on any drift from it.');
    L.push('  The rates above are computed from this run, not from this file.');
  }
  const pc = m.committedInputs.proofCorpus;
  if (pc) {
    L.push(`- **Third-party repository run** (*committed artifact*, \`${pc.source}\`,`);
    L.push(`  bundle \`${pc.bundleSha}\`): ${pc.ok}/${pc.targetCount} targets completed.`);
    L.push('  Reported for scale and parse coverage only — these repositories have no');
    L.push('  vulnerability ground truth, so no accuracy rate is derived from them.');
    L.push('');
    L.push('| Repository | Commit | Status | Files parsed / in scope | Results emitted | Deterministic re-run |');
    L.push('| --- | --- | --- | --- | --- | --- |');
    for (const t of pc.targets) {
      const det = t.determinismChecked ? (t.determinismIdentical ? 'identical' : 'checked, not byte-identical') : 'not checked';
      L.push(`| ${t.id} | \`${String(t.commit || '').slice(0, 12)}\` | ${t.status} | ${formatRate(t.filesParsed ?? 0, t.filesInScope ?? 0)} | ${t.resultsEmitted ?? 'n/a'} | ${det} |`);
    }
  }
  L.push('');
  L.push('## Reproducing any figure here');
  L.push('');
  L.push('| Figure | Command |');
  L.push('| --- | --- |');
  L.push('| Detection / correct-silence, and every slice | `node bench/cve-replay/runner.mjs --json` |');
  L.push('| Corpus drift gate | `npm run bench:cve-replay:check` |');
  L.push('| Self-scan counts | `node bench/self-scan/measure.mjs --json` |');
  L.push('| Self-scan drift gate | `npm run bench:self-scan:check` |');
  L.push('| This whole document | `npm run scorecard` |');
  L.push('');
  L.push('Running `npm run scorecard` twice on an unchanged tree produces an');
  L.push('identical document apart from the generated-timestamp row above.');
  L.push('');
  return L.join('\n');
}
