// PRD Epic 7.2 — head-to-head comparison scoring.
//
// WHY THIS SHIPS WITHOUT A SINGLE PARTICIPANT NAME IN IT. A benchmark whose
// competitors are hard-coded by the vendor being measured is marketing with a
// methodology section. This repository publishes the HARNESS and the answer
// key; the operator supplies the participants. Nothing here — no constant, no
// default config, no example — names any tool, and the report renders whatever
// labels the operator chose. That is not a limitation working around a rule; a
// comparison anyone can re-run against tools of their own choosing is the only
// kind worth publishing, and the only kind a reader has reason to believe.
//
// THE ONE FAILURE MODE THIS MODULE EXISTS TO PREVENT. Two tools scored over
// different subsets of a corpus are not comparable, and the difference is
// invisible in the output: a tool that crashed on the 40 hardest entries and
// was scored over the remaining 170 looks like it beat one that completed all
// 210. So every rate here is computed over the INTERSECTION of entries every
// participant completed, that intersection is reported alongside each
// participant's own completion count, and a participant that completed nothing
// in common with the others is refused rather than shown with an empty score.
//
// MATCHING IS CWE-ONLY, ON PURPOSE. Our own corpus entries carry a `vuln_match`
// phrase in this engine's wording; scoring an external tool against our
// phrasing would score it on vocabulary. CWE is the one identifier every
// participant can be expected to emit, so it is the only key used, and it is
// applied identically to every participant including this engine. A participant
// that reports no CWE at all is scored as reporting nothing — stated in the
// output rather than silently counted as a miss.

/** Verdict for one participant on one corpus entry. */
export const OUTCOMES = Object.freeze(['tp', 'fn', 'fp', 'tn']);

function _cweSet(findings) {
  const s = new Set();
  for (const f of findings || []) {
    const raw = f && (f.cwe ?? f.CWE ?? f.ruleId ?? '');
    for (const m of String(raw).matchAll(/CWE[-_ ]?(\d+)/gi)) s.add(`CWE-${m[1]}`);
  }
  return s;
}

/**
 * Score one participant over the entries it completed.
 *
 * @param {object[]} entries  [{id, cwe}]
 * @param {object}   results  entryId -> {pre: findings[], post: findings[]} | {error}
 */
export function scoreParticipant(entries, results) {
  const per = new Map();
  let noCwe = 0;
  for (const e of entries) {
    const r = results?.[e.id];
    if (!r || r.error || !Array.isArray(r.pre) || !Array.isArray(r.post)) continue;

    const want = String(e.cwe || '').toUpperCase();
    const pre = _cweSet(r.pre);
    const post = _cweSet(r.post);
    if (!pre.size && (r.pre || []).length) noCwe++;

    // pre/ is the vulnerable tree: reporting the CWE is a true positive.
    // post/ is the fixed tree: reporting it again is a false positive.
    per.set(e.id, {
      detected: pre.has(want),
      falsePositive: post.has(want),
    });
  }
  return { per, completed: per.size, noCwe };
}

function _rates(tp, fn, fp, tn) {
  const precision = tp + fp > 0 ? tp / (tp + fp) : null;
  const recall = tp + fn > 0 ? tp / (tp + fn) : null;
  const f1 = precision !== null && recall !== null && precision + recall > 0
    ? (2 * precision * recall) / (precision + recall) : null;
  return { tp, fn, fp, tn, precision, recall, f1 };
}

/**
 * Compare every participant over the entries ALL of them completed.
 *
 * @param {object[]} entries       [{id, cwe}]
 * @param {object[]} participants  [{id, results}]
 * @returns {object} {ok, reason?, intersection, scores[], skippedEntries[]}
 */
export function compareParticipants(entries, participants) {
  if (!Array.isArray(entries) || !entries.length) return { ok: false, reason: 'no corpus entries' };
  if (!Array.isArray(participants) || participants.length < 2) {
    return { ok: false, reason: 'a comparison needs at least two participants' };
  }

  const scored = participants.map((p) => ({ ...p, ...scoreParticipant(entries, p.results) }));

  // The intersection. This is the whole point: rates over anything else are
  // rates over different exams.
  let common = null;
  for (const s of scored) {
    const ids = new Set(s.per.keys());
    common = common === null ? ids : new Set([...common].filter((id) => ids.has(id)));
  }
  if (!common || common.size === 0) {
    return {
      ok: false,
      reason: 'no corpus entry was completed by every participant — there is nothing they can be compared on',
      completion: Object.fromEntries(scored.map((s) => [s.id, s.completed])),
    };
  }

  const scores = scored.map((s) => {
    let tp = 0, fn = 0, fp = 0, tn = 0;
    for (const id of common) {
      const v = s.per.get(id);
      if (v.detected) tp++; else fn++;
      if (v.falsePositive) fp++; else tn++;
    }
    return {
      id: s.id,
      ...(_rates(tp, fn, fp, tn)),
      completed: s.completed,
      notCompleted: entries.length - s.completed,
      noCwe: s.noCwe,
    };
  });

  return {
    ok: true,
    corpusSize: entries.length,
    intersection: common.size,
    // Named so a reader can check the exam rather than trust the grade.
    scoredEntryIds: [...common].sort(),
    scores: scores.sort((a, b) => (b.f1 ?? -1) - (a.f1 ?? -1)),
  };
}

const pct = (v) => (v === null || v === undefined ? 'n/a' : `${(v * 100).toFixed(1)}%`);

/** Markdown. Discloses the exam before the grades, never after. */
export function renderComparison(cmp) {
  if (!cmp || !cmp.ok) {
    return `# Comparison\n\nNOT SCORED: ${cmp?.reason || 'unknown reason'}\n`;
  }
  const out = [];
  out.push('# Head-to-head comparison');
  out.push('');
  out.push(`Scored over the **${cmp.intersection} of ${cmp.corpusSize}** corpus entries that *every*`);
  out.push('participant completed. Entries any participant failed to complete are excluded from');
  out.push('every score, including this engine\'s — a rate computed over a different subset is a');
  out.push('rate for a different exam.');
  out.push('');
  out.push('Matching is by CWE only. Participants report findings in their own vocabulary, so');
  out.push('scoring against any one tool\'s phrasing would measure vocabulary rather than');
  out.push('detection. The same rule is applied to every participant.');
  out.push('');
  out.push('| Participant | F1 | Precision | Recall | TP | FN | FP | Corpus completed |');
  out.push('|---|---|---|---|---|---|---|---|');
  for (const s of cmp.scores) {
    out.push(`| ${s.id} | ${pct(s.f1)} | ${pct(s.precision)} | ${pct(s.recall)} | ${s.tp} | ${s.fn} | ${s.fp} | ${s.completed}/${cmp.corpusSize} |`);
  }
  out.push('');
  const incomplete = cmp.scores.filter((s) => s.notCompleted > 0);
  if (incomplete.length) {
    out.push('## Entries not completed');
    out.push('');
    out.push('A participant that could not run on an entry is UNSCORED there, never scored as a');
    out.push('miss. Counting a crash as a false negative would penalise a tool for a harness');
    out.push('problem; counting it as a pass would reward it for one.');
    out.push('');
    for (const s of incomplete) out.push(`- **${s.id}** — ${s.notCompleted} entr(y/ies) not completed`);
    out.push('');
  }
  const noCwe = cmp.scores.filter((s) => s.noCwe > 0);
  if (noCwe.length) {
    out.push('## Findings carrying no CWE');
    out.push('');
    for (const s of noCwe) {
      out.push(`- **${s.id}** — ${s.noCwe} entr(y/ies) where findings were reported but none carried a CWE,`);
      out.push('  so they could not be matched. This depresses that participant\'s recall for a');
      out.push('  reporting-format reason rather than a detection one.');
    }
    out.push('');
  }
  return out.join('\n') + '\n';
}
