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
 * Build the { byLanguage: [{language, taint:{n,d}}] } shape for one
 * taintByLanguage/totalByLanguage pair. Sorted by language so the rendered
 * document is stable run-to-run, matching every other byX array here.
 *
 * A language present in `total` but absent from `taint` reports n:0 — a real
 * measured zero. A language absent from BOTH is simply not included in the
 * output at all, so "measured zero" and "not measured on this subset" never
 * collapse into the same row (see the deepTierOnly caller below).
 */
function taintRateByLanguage(taintByLanguage, totalByLanguage) {
  const langs = Object.keys(totalByLanguage || {}).sort();
  return langs.map(language => ({
    language,
    taint: { n: (taintByLanguage || {})[language] || 0, d: totalByLanguage[language] },
  }));
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
 *   provenance   { engineVersion, bundleSha256, commit, nodeVersion, generatedAt,
 *                  corpusVersion?, scope? } — the last two are FR-901's
 *                  "corpus version" and "scope" fields; optional so a
 *                  caller with no corpus baseline to hash still gets a
 *                  valid scorecard rather than a thrown error.
 *   corpusDetail per-entry records from a corpus run performed THIS run
 *   selfScan     { targets: {name:{total,byFile}}, polyglot: {total,byLanguage} }
 *                — measured THIS run
 *   committed    { corpusBaseline, proofCorpus } — read from committed files,
 *                labelled as such in the output, never used to derive a rate
 *   scan         optional — a scan-shaped object (`{findings, secrets,
 *                supplyChain}`, trimmed to just those arrays) from a run over
 *                a full (non-shallow) Git clone, used ONLY to compute
 *                provenanceCoverage below. `scripts/scorecard.mjs` passes
 *                `selfScan.provenanceScan` — the self-scan harness
 *                (bench/self-scan/measure.mjs) already runs a real
 *                `runScan()` over this project's own full git clone with
 *                provenance resolution on by default, so this reuses that
 *                run's already-computed `findingProvenance` rather than
 *                performing a second scan. Still optional: a caller with no
 *                such scan renders "not measured this run" rather than a
 *                fabricated rate. See PRD Success Metrics.
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
    // PRD Success Metrics: "Provenance coverage >=95% complete or uncommitted
    // for P0-supported findings in full Git clones." `inputs.scan` is
    // optional (see the JSDoc above) — absent when no caller yet supplies a
    // real scan, in which case this reports "not measured" rather than a
    // fabricated 0/0.
    provenanceCoverage: inputs.scan
      ? { measuredThisRun: true, ...computeProvenanceCoverage(inputs.scan) }
      : { measuredThisRun: false },
    taintRecall: (() => {
      const lr = inputs.layerRecall;
      if (!lr) {
        return { measuredThisRun: false, wholeCorpus: { entriesScored: 0, byLanguage: [] }, deepTierOnly: { entriesScored: 0, byLanguage: [] } };
      }
      const deep = lr.deepTier || { entriesScored: 0, taintByLanguage: {}, totalByLanguage: {} };
      return {
        measuredThisRun: true,
        wholeCorpus: {
          entriesScored: lr.entriesScored || 0,
          byLanguage: taintRateByLanguage(lr.taintByLanguage, lr.totalByLanguage),
        },
        deepTierOnly: {
          entriesScored: deep.entriesScored || 0,
          byLanguage: taintRateByLanguage(deep.taintByLanguage, deep.totalByLanguage),
        },
      };
    })(),
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
          // FR-904: "rule authors cannot optimize against the full scored
          // population" — bench/independent/runner.mjs's T0.7 already
          // computes a deterministic (id-hashed) held-out slice, scored
          // separately and never tuned against, but the published scorecard
          // used to report only the merged `overall` figures, so the one
          // number this requirement is actually about never reached a
          // release artifact anyone reads. Passed through unmodified —
          // absent (null) on any committed RESULT.json predating T0.7.
          heldOut: committed.independent.heldOut || null,
          development: committed.independent.development || null,
        }
        : null,
      // FR-905: "publish false-positive adjudication and coverage
      // methodology." Three of the four named categories were already
      // published (unsupported cases via population.unscored above; the
      // qualitative FP/unlabeled-output methodology in
      // bench/independent/README.md's "Honest limits" section) — this is
      // the fourth: WHY a false negative is a false negative, broken down
      // by mechanism (bench/independent/why-missed.mjs). Read from a
      // committed file for the same reason `independent` above is — the
      // full population's diagnostic run is measured in minutes, far too
      // long to sit inside `npm run scorecard`. Absent (null) until
      // why-missed.mjs has been run at least once and its summary
      // committed.
      whyMissed: committed.whyMissed
        ? {
          source: 'bench/independent/why-missed-summary.json',
          measuredAt: committed.whyMissed.measuredAt || null,
          scope: committed.whyMissed.scope || null,
          total: committed.whyMissed.total ?? null,
          skipped: committed.whyMissed.skipped ?? null,
          byBucket: committed.whyMissed.byBucket || null,
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

// PRD Success Metrics: "Provenance coverage >=95% complete or uncommitted
// for P0-supported findings in full Git clones." P0-supported scope per
// the PRD's own Release Scope table: code (SAST), secrets, IaC/config,
// direct dependency findings. Secrets now get real origin resolution
// (Task 11 -- `engine.js` calls `annotateGitProvenance` on `scan.secrets`
// with a real per-pattern-backfilled stableId, the same as SAST findings),
// so this metric no longer has a structural reason to read lower for the
// secrets share of the denominator than for any other P0-scoped channel.
export function computeProvenanceCoverage(scan) {
  const p0Findings = [
    ...(scan.findings || []),
    ...(scan.secrets || []),
    ...(scan.supplyChain || []).filter((s) => s.type === 'vulnerable_dep' && s.isDirect),
  ];
  const d = p0Findings.length;
  const n = p0Findings.filter((f) => {
    const status = f.findingProvenance?.status;
    return status === 'complete' || status === 'uncommitted';
  }).length;
  return { n, d };
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
  // FR-901: "Published results identify engine version, corpus version,
  // commit, scope, and date" — corpusVersion (a content hash, independent
  // of the engine's own commit) and scope (what was actually measured)
  // close the two named fields the rows above didn't already cover.
  if (p.corpusVersion) L.push(`| Corpus version | \`${p.corpusVersion}\` |`);
  if (p.scope) L.push(`| Scope | ${p.scope} |`);
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
  L.push('## Taint-layer recall by language');
  L.push('');
  L.push('Two views of the same layer-recall instrument, because reporting only the');
  L.push('first would silently overstate taint capability and reporting only the');
  L.push('second would understate coverage of what the corpus actually contains:');
  L.push('');
  L.push('- **Whole corpus** — diagnostic only. The large majority of this corpus is');
  L.push('  caught by the pattern/structural layers without needing taint at all, so a language\'s');
  L.push('  rate here is diluted by every entry that never exercised the taint');
  L.push('  engine. A language reading near-zero here is not necessarily a taint');
  L.push('  defect — see `docs/METRICS.md`.');
  L.push('- **Deep-tier only (the taint-shaped subset)** — the number to quote for');
  L.push('  taint capability. Every entry in this bucket is required, before it can');
  L.push('  be committed, to be provably invisible with the deep engine off and');
  L.push('  detected with it on (`bench/cve-replay/CONTRIBUTING.md`, "deep/" tier).');
  L.push('  A language absent from this table has no deep-tier entry yet — that is');
  L.push('  "not yet measured", never "zero capability".');
  L.push('');
  L.push('**No taint-specific precision percentage is reported here, deliberately —');
  L.push('same reasoning as the corpus-wide F1 omission above.** A precision figure');
  L.push('needs a labelled population containing both true and false positives; this');
  L.push('section\'s denominator is all-vulnerable by construction (`pre/` fixtures),');
  L.push('so it cannot supply one. The false-positive side is instrumented instead as');
  L.push('a gate, not a rate: `bench/self-scan/fixtures/polyglot/` carries one');
  L.push('untainted, negative-control fixture per language, covering eight of the');
  L.push('nine first-class languages (C/C++ has no fixture in this set yet), and');
  L.push('`bench:self-scan:check`\'s existing exact per-file drift gate fails the');
  L.push('build the moment any of them stops reading zero. See the self-scan section');
  L.push('below for current counts.');
  L.push('');
  L.push('### Whole corpus (diagnostic)');
  L.push('');
  L.push(`Entries scored: ${m.taintRecall.wholeCorpus.entriesScored}`);
  L.push('');
  L.push('| Language | IR-TAINT recall |');
  L.push('| --- | --- |');
  for (const r of m.taintRecall.wholeCorpus.byLanguage) {
    L.push(`| ${r.language} | ${formatRate(r.taint.n, r.taint.d)} |`);
  }
  L.push('');
  L.push('### Deep-tier only — taint-shaped subset (headline)');
  L.push('');
  L.push(`Entries scored: ${m.taintRecall.deepTierOnly.entriesScored}`);
  L.push('');
  if (m.taintRecall.deepTierOnly.byLanguage.length) {
    L.push('| Language | IR-TAINT recall |');
    L.push('| --- | --- |');
    for (const r of m.taintRecall.deepTierOnly.byLanguage) {
      L.push(`| ${r.language} | ${formatRate(r.taint.n, r.taint.d)} |`);
    }
  } else {
    L.push('No deep-tier entries scored this run.');
  }
  L.push('');
  // INTEGRITY CONTRACT above requires unmeasured things "disclosed by name",
  // not just described generically — so name the languages that are present
  // in the whole-corpus view but have no deep-tier entry at all, rather than
  // leaving that as an unnamed implication of the two tables above.
  const deepLangs = new Set(m.taintRecall.deepTierOnly.byLanguage.map(r => r.language));
  const notYetMeasured = m.taintRecall.wholeCorpus.byLanguage
    .map(r => r.language)
    .filter(l => !deepLangs.has(l))
    .sort();
  if (notYetMeasured.length) {
    L.push(`Not yet measured on this subset: ${notYetMeasured.join(', ')}`);
    L.push('');
  }
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
  if (m.provenanceCoverage && m.provenanceCoverage.measuredThisRun) {
    L.push('## Provenance coverage');
    L.push('');
    L.push('PRD Success Metric: **>=95% of P0-scoped findings (SAST + secrets + direct**');
    L.push('**dependency findings) resolve to `complete` or `uncommitted` git provenance**');
    L.push('in a full (non-shallow) clone. Transitive dependency findings are excluded —');
    L.push('the PRD\'s Release Scope table names direct dependency findings only.');
    L.push('');
    L.push('| P0-scoped findings — complete/uncommitted provenance |');
    L.push('| --- |');
    L.push(`| ${formatRate(m.provenanceCoverage.n, m.provenanceCoverage.d)} |`);
    L.push('');
    L.push('Secrets, SAST, and direct-dependency findings all resolve through the same');
    L.push('git-origin resolution pipeline, so a gap in this rate reflects the clone');
    L.push('itself (shallow history, uncommitted lines the pipeline could not blame) —');
    L.push('not a channel this measurement structurally cannot yet cover.');
    L.push('');
  }
  // PRD F12.6 — the honest scorecard publishes the LIMITS too, not only the
  // rates. Three claims this project makes are only meaningful with their
  // caveat attached, and each caveat was invisible before this section:
  //   proof coverage  — "provable" means provable by a JAVASCRIPT-ONLY harness
  //   calibration     — the confidence surface is currently UNVERIFIED
  //   compliance      — most controls are backed by weak or unmeasured detectors
  // Publishing a rate without its ceiling is how a number comes to mean
  // whatever the reader assumes.
  if (m.limits) {
    L.push('## Stated limits — what these capabilities cannot do');
    L.push('');
    if (m.limits.proof) {
      const pc = m.limits.proof;
      L.push('### Execution proof coverage, with its ceiling');
      L.push('');
      L.push('| Bucket | Share of all findings |');
      L.push('| --- | --- |');
      L.push(`| Provable (a proof class exists) | ${pc.provable.n}/${pc.total} |`);
      L.push(`| Declined on purpose, reason stated | ${pc.indeterminate.n}/${pc.total} |`);
      L.push(`| No proof class yet (backlog) | ${pc.unclassified.n}/${pc.total} |`);
      L.push(`| **Out of harness scope (not JavaScript)** | **${pc.outOfScope.n}/${pc.total}** |`);
      L.push('');
      L.push(`**The ceiling.** The in-process proof harness only loads JavaScript. Of ${pc.total} findings`);
      L.push(`measured on the CVE corpus, ${pc.reachable.n} are reachable by it at all. Proof coverage is`);
      L.push(`**${pc.provable.n}/${pc.total}** of ALL findings and **${pc.provable.n}/${pc.reachable.n}** of the reachable ones.`);
      L.push('Both are given because they differ by a lot, and a reader shown only one will');
      L.push('draw the wrong conclusion in whichever direction that one flatters.');
      L.push('');
      L.push('Adding more proof classes does not move the ceiling. A Python or Java finding is');
      L.push('not backlog — it is unreachable by this harness at any effort.');
      L.push('');
    }
    if (m.limits.calibration) {
      L.push('### Confidence calibration');
      L.push('');
      L.push(`**${m.limits.calibration}**`);
      L.push('');
      L.push('Every finding carries a confidence number. That number is a claim about how');
      L.push('often the engine is right, and it is only worth what the evidence behind it is');
      L.push('worth. `calibration-seed.json` is FITTING data, so measuring against it would');
      L.push('reproduce the error it was fitted to. The release gate fails on this by default;');
      L.push('a dated waiver is what currently allows a release, and it expires.');
      L.push('');
    }
    if (m.limits.compliance) {
      const c = m.limits.compliance;
      L.push('### Compliance control strength');
      L.push('');
      L.push(`Of ${c.total} bundled controls, **${c.partiallyEvidenced} are backed by a detector that is weak or was never`);
      L.push('measured against an independent corpus**, and are flagged `partiallyEvidenced`.');
      L.push(`A further **${c.notCodeTestable} are organisational or artifact-existence only** and can never`);
      L.push('read as evidenced by a scanner. A control appearing in a coverage map is not a');
      L.push('statement that the control is satisfied.');
      L.push('');
    }
  }

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
    // population.unscored is an array of {id, reason} (bench/independent/runner.mjs) —
    // render its count, not the array itself (Array#toString would stringify to
    // "[object Object],[object Object]" or blank for an empty array, both silently
    // wrong on the line this section calls "the number that matters"). Tolerates a
    // bare number too, for any already-committed artifact predating this fix.
    const unscoredList = ind.population?.unscored;
    const unscoredCount = Array.isArray(unscoredList) ? unscoredList.length
      : (typeof unscoredList === 'number' ? unscoredList : 0);
    L.push(`**Measured ${ind.measuredAt} on engine ${ind.engineVersion}, ` +
      `n=${ind.population?.scoredEntries}, ${unscoredCount} unscored** ` +
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
    // FR-904 (assurance-hardening PRD): "rule authors cannot optimize
    // against the full scored population." T0.7's held-out slice is a
    // no-op section (silently omitted) on a RESULT.json predating it —
    // never a fabricated 0/0 row pretending to be data.
    if (ind.heldOut && ind.development) {
      L.push('### Held-out slice — never tuned against');
      L.push('');
      L.push('`bench/independent/runner.mjs` splits the population by a deterministic hash of');
      L.push('each entry\'s id (T0.7) — a fixed 20% held-out slice, stable across runs and');
      L.push('population growth, that detector development never sees scored results for.');
      L.push('This is the number that answers whether the figures above reflect genuine');
      L.push('accuracy or tuning against the population being measured.');
      L.push('');
      L.push('| | Held-out (never tuned against) | Development |');
      L.push('| --- | --- | --- |');
      L.push(`| Entries | ${ind.heldOut.entries} | ${ind.development.entries} |`);
      L.push(`| Precision | ${formatRate(ind.heldOut.localized?.precision?.n, ind.heldOut.localized?.precision?.d)} | ${formatRate(ind.development.localized?.precision?.n, ind.development.localized?.precision?.d)} |`);
      L.push(`| Recall | ${formatRate(ind.heldOut.localized?.recall?.n, ind.heldOut.localized?.recall?.d)} | ${formatRate(ind.development.localized?.recall?.n, ind.development.localized?.recall?.d)} |`);
      const heldF1 = ind.heldOut.localized?.f1;
      const devF1 = ind.development.localized?.f1;
      L.push(`| F1 | ${heldF1 === null || heldF1 === undefined ? 'n/a' : heldF1.toFixed(3)} | ${devF1 === null || devF1 === undefined ? 'n/a' : devF1.toFixed(3)} |`);
      L.push('');
    }
    // FR-905: the 4th named category ("missed findings" methodology) —
    // WHY a false negative is a false negative, broken down by mechanism.
    // Omitted entirely (not a fabricated zero row) until why-missed.mjs has
    // been run and its summary committed.
    const wm = m.committedInputs.whyMissed;
    if (wm) {
      L.push('### Missed findings — why, not just how many');
      L.push('');
      L.push(`**Measured ${wm.measuredAt}** (*committed artifact*, \`${wm.source}\`) — ` +
        `${wm.total} false negative(s) diagnosed${wm.skipped ? `, ${wm.skipped} skipped (not fetched)` : ''}.`);
      L.push('');
      L.push('Each is classified into exactly one mechanism: does something fire and get');
      L.push('suppressed (by an ignore pragma, a sanitizer, a custom rule, or the');
      L.push('guard-recognition window), does a finding land on the wrong file or CWE, or');
      L.push('does nothing fire at all. This is the difference the raw recall number above');
      L.push('cannot show by itself — "this shape does not occur in these real advisories"');
      L.push('and "a real detection was masked downstream" look identical as one number and');
      L.push('very different once broken down this way.');
      L.push('');
      if (wm.byBucket && Object.keys(wm.byBucket).length) {
        L.push('| Mechanism | Count |');
        L.push('| --- | --- |');
        for (const [bucket, count] of Object.entries(wm.byBucket).sort((a, b) => b[1] - a[1])) {
          L.push(`| ${bucket} | ${count} |`);
        }
        L.push('');
      }
    }
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
  L.push('| Independent population (read, not re-run — ~32 minutes) | `npm run bench:independent` |');
  L.push('| Missed-findings mechanism breakdown (read, not re-run) | `npm run bench:independent:why-missed -- --all` |');
  L.push('| This whole document | `npm run scorecard` |');
  L.push('');
  L.push('Running `npm run scorecard` twice on an unchanged tree produces an');
  L.push('identical document apart from the generated-timestamp row above.');
  L.push('');
  return L.join('\n');
}
