#!/usr/bin/env node
// Before/after harness for the two engine recall gaps.
//
// Defect 1: a sink call on an assignment's right-hand side is never matched,
// so `const out = exec(tainted)` is silent while `exec(tainted)` is not.
// Defect 2: every catalog entry declared match.type:'global' is unreachable
// from matchSource(), which kills PHP's $_GET family among others.
//
// Committed rather than ad-hoc so the before and after runs are identical.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../../scanner/src/runScan.js';
import { CATALOG, matchSource } from '../../scanner/src/dataflow/catalog.js';

async function scanSnippet(filename, src) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'engine-recall-'));
  try {
    fs.writeFileSync(path.join(dir, filename), src);
    const { scan } = await runScan(dir);
    const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
    return {
      total: all.length,
      irTaint: all.filter(f => /^IR-TAINT/.test(f.parser || '')).length,
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// Identical taint flow; the only difference is where the sink call sits.
const STATEMENT = `const { exec } = require('child_process');
function h(req) { return req.query.c; }
function f(req) { const c = h(req); exec(c); }
module.exports = { f };
`;

const ASSIGNMENT = `const { exec } = require('child_process');
function h(req) { return req.query.c; }
function f(req) { const c = h(req); const out = exec(c); return out; }
module.exports = { f };
`;

// Probe filename per catalog dialect, so a `js`- or `rb`-tagged global entry
// isn't tested against a `.php` file and rejected by _languageAllowed() for
// the wrong reason (extension mismatch vs. the real defect, which is that
// match.type:'global' entries aren't indexed at all — see below). Falls back
// to `a.<language>` for any dialect not listed here.
const PROBE_FILE_BY_LANG = {
  js: 'a.js', py: 'a.py', cs: 'a.cs', kt: 'a.kt', go: 'a.go',
  php: 'a.php', rb: 'a.rb', java: 'a.java', cpp: 'a.cpp',
};

function probeFileFor(language) {
  return PROBE_FILE_BY_LANG[language] || `a.${language}`;
}

function globalSourceReach({ verbose = false } = {}) {
  const globals = CATALOG.filter(e => e && e.match && e.match.type === 'global');
  const byLanguage = {};
  let reachable = 0;
  const probes = [];
  for (const e of globals) {
    byLanguage[e.language] = (byLanguage[e.language] || 0) + 1;
    const file = probeFileFor(e.language);
    const asIdent = matchSource({ kind: 'ident', name: e.match.name }, file);
    const asMemberRoot = matchSource(
      { kind: 'member', object: { kind: 'ident', name: e.match.name }, prop: 'x' }, file);
    const hit = (asIdent && asIdent.id === e.id) || (asMemberRoot && asMemberRoot.id === e.id);
    if (hit) reachable++;
    probes.push({ id: e.id, language: e.language, file, reachable: !!hit });
  }
  if (verbose) {
    for (const p of probes) {
      process.stderr.write(`  global-probe id=${p.id} language=${p.language} file=${p.file} reachable=${p.reachable}\n`);
    }
  }
  return { total: globals.length, reachable, byLanguage, probes };
}

async function main() {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

  const out = {
    assignSink: {
      statement: await scanSnippet('app.js', STATEMENT),
      assignment: await scanSnippet('app.js', ASSIGNMENT),
    },
    globalSources: globalSourceReach({ verbose: process.argv.includes('--verbose') }),
  };
  // `probes` is diagnostic (per-entry probe filename + hit), not part of the
  // committed `{ assignSink, globalSources: { total, reachable, byLanguage } }`
  // interface — kept off stdout by default, dumped with --show-probes.
  const probes = out.globalSources.probes;
  delete out.globalSources.probes;

  if (process.argv.includes('--json')) process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  else {
    const a = out.assignSink;
    process.stdout.write(`assign-sink  statement: total=${a.statement.total} irTaint=${a.statement.irTaint}\n`);
    process.stdout.write(`assign-sink  assignment: total=${a.assignment.total} irTaint=${a.assignment.irTaint}\n`);
    const g = out.globalSources;
    process.stdout.write(`global-sources reachable=${g.reachable}/${g.total} ${JSON.stringify(g.byLanguage)}\n`);
  }
  if (process.argv.includes('--show-probes')) {
    for (const p of probes) {
      process.stdout.write(`  probe id=${p.id} language=${p.language} file=${p.file} reachable=${p.reachable}\n`);
    }
  }
  return 0;
}

main().then(c => process.exit(c)).catch(e => {
  process.stderr.write(`fatal: ${e && e.stack}\n`);
  process.exit(2);
});
