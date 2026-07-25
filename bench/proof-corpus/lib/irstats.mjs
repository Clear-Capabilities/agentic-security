// Reader for the scanner's IR parse-coverage sidecar.
//
// Turns the raw counts written by scanner/src/ir/ir-stats.js into the
// percentages the scorecard reports. Kept separate from the writer so the
// bench can read sidecars produced by an older scanner build.

import * as fs from 'node:fs';

export function readIrStats(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

// A language with zero files in scope has no coverage figure at all, which is
// a different statement from 0% coverage. Keeping that distinction is what
// stops the scorecard claiming "0% Ruby" for a repo containing no Ruby.
function _pct(parsed, inScope) {
  if (!inScope) return null;
  return Math.round((parsed / inScope) * 100);
}

export function coverageSummary(stats) {
  const languages = (stats && stats.languages) || {};
  const byLanguage = {};
  for (const name of Object.keys(languages).sort()) {
    const l = languages[name] || {};
    const inScope = l.inScope || 0;
    const parsed = l.parsed || 0;
    byLanguage[name] = {
      inScope,
      parsed,
      functions: l.functions || 0,
      pct: _pct(parsed, inScope),
    };
  }

  const t = (stats && stats.totals) || {};
  const cg = (stats && stats.callGraph) || {};
  return {
    byLanguage,
    totals: {
      inScope: t.inScope || 0,
      parsed: t.parsed || 0,
      pct: _pct(t.parsed || 0, t.inScope || 0),
    },
    callGraph: {
      functions: cg.functions || 0,
      edges: cg.edges || 0,
      resolvedEdges: cg.resolvedEdges || 0,
      unresolvedEdges: cg.unresolvedEdges || 0,
    },
  };
}
