// IR parse-coverage instrumentation (proof-corpus Phase 0). Default OFF.
//
// Answers one question the scanner could not previously answer: for each
// language, how many of the files we claim to support did we actually turn
// into IR? That is the difference between recognising an extension and
// supporting a language, and it is the headline metric of the proof corpus
// bench (docs/PROOF_CORPUS_PRD.md §5.4).
//
// Enable by setting AGENTIC_SECURITY_IR_STATS to an output path. The sidecar
// deliberately contains NO timestamp so two runs over identical input produce
// byte-identical output and the bench can diff them.

import * as fs from 'node:fs';
import * as path from 'node:path';

// Mirrors the dispatch in ./index.js. When a language is added there, add it
// here or its files silently report as out of scope.
//
// C/C++ is intentionally present even though ./index.js does NOT yet dispatch
// it: that is the point. It reports inScope>0 / parsed=0 today, which is the
// baseline the C++ parser workstream is measured against.
const EXT_TO_LANG = {
  js: 'javascript', jsx: 'javascript', ts: 'javascript', tsx: 'javascript',
  mjs: 'javascript', cjs: 'javascript',
  py: 'python',
  java: 'java',
  cs: 'csharp',
  kt: 'kotlin',
  go: 'go',
  php: 'php', phtml: 'php',
  rb: 'ruby',
  c: 'cpp', cc: 'cpp', cpp: 'cpp', cxx: 'cpp',
  h: 'cpp', hh: 'cpp', hpp: 'cpp', hxx: 'cpp',
};

// Cap the per-language failure list so a multi-million-line repo can't write a
// gigabyte sidecar. The counts stay exact; only the sample is truncated.
const _MAX_FAILURES_LISTED = 200;

export function languageOfFile(file) {
  if (typeof file !== 'string') return null;
  const dot = file.lastIndexOf('.');
  if (dot < 0 || dot === file.length - 1) return null;
  return EXT_TO_LANG[file.slice(dot + 1).toLowerCase()] || null;
}

export function collectIrStats(fileContents, perFile, callGraph) {
  const languages = {};
  const ir = perFile || {};
  const failuresByLang = {};

  for (const file of Object.keys(fileContents || {})) {
    const lang = languageOfFile(file);
    if (!lang) continue;
    if (!languages[lang]) {
      languages[lang] = { inScope: 0, parsed: 0, functionless: 0, functions: 0, failures: [] };
      failuresByLang[lang] = [];
    }
    const bucket = languages[lang];
    bucket.inScope++;
    const rec = ir[file];
    // "parsed" means an IR record exists for the file — the parser returned
    // something — independent of whether that file happens to declare any
    // functions. A file with zero functions (an `__init__.py`, a constants
    // module) is NOT a parse failure; it is parsed-but-functionless. Only the
    // absence of an IR record at all is a genuine parse failure.
    if (rec) {
      bucket.parsed++;
      const fnCount = Array.isArray(rec.functions) ? rec.functions.length : 0;
      bucket.functions += fnCount;
      if (fnCount === 0) bucket.functionless++;
    } else {
      failuresByLang[lang].push(file);
    }
  }

  // Sort then truncate — a stable sample rather than whichever files happened
  // to be enumerated first.
  for (const [lang, list] of Object.entries(failuresByLang)) {
    list.sort();
    languages[lang].failures = list.slice(0, _MAX_FAILURES_LISTED);
  }

  const edges = (callGraph && Array.isArray(callGraph.edges)) ? callGraph.edges : [];
  const resolvedEdges = edges.filter(e => e && e.callee).length;
  const fnMap = callGraph && callGraph.functions;
  const cgFunctions = fnMap && typeof fnMap.size === 'number'
    ? fnMap.size
    : (fnMap ? Object.keys(fnMap).length : 0);

  const totals = { inScope: 0, parsed: 0, functions: 0 };
  for (const b of Object.values(languages)) {
    totals.inScope += b.inScope;
    totals.parsed += b.parsed;
    totals.functions += b.functions;
  }

  // Rebuild the languages object in sorted key order so JSON.stringify is stable.
  const sortedLanguages = {};
  for (const k of Object.keys(languages).sort()) sortedLanguages[k] = languages[k];

  return {
    languages: sortedLanguages,
    callGraph: {
      functions: cgFunctions,
      edges: edges.length,
      resolvedEdges,
      unresolvedEdges: edges.length - resolvedEdges,
    },
    totals,
  };
}

export function irStatsTarget() {
  const v = process.env.AGENTIC_SECURITY_IR_STATS;
  return (typeof v === 'string' && v.length > 0) ? v : null;
}

export function writeIrStats(target, stats) {
  const dir = path.dirname(target);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(target, JSON.stringify(stats, null, 2) + '\n', 'utf8');
}

export const _internals = { EXT_TO_LANG, _MAX_FAILURES_LISTED };
