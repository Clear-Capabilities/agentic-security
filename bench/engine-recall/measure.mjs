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

function globalSourceReach() {
  const globals = CATALOG.filter(e => e && e.match && e.match.type === 'global');
  const byLanguage = {};
  let reachable = 0;
  for (const e of globals) {
    byLanguage[e.language] = (byLanguage[e.language] || 0) + 1;
    const asIdent = matchSource({ kind: 'ident', name: e.match.name }, 'a.php');
    const asMemberRoot = matchSource(
      { kind: 'member', object: { kind: 'ident', name: e.match.name }, prop: 'x' }, 'a.php');
    if ((asIdent && asIdent.id === e.id) || (asMemberRoot && asMemberRoot.id === e.id)) reachable++;
  }
  return { total: globals.length, reachable, byLanguage };
}

async function main() {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

  const out = {
    assignSink: {
      statement: await scanSnippet('app.js', STATEMENT),
      assignment: await scanSnippet('app.js', ASSIGNMENT),
    },
    globalSources: globalSourceReach(),
  };

  if (process.argv.includes('--json')) process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  else {
    const a = out.assignSink;
    process.stdout.write(`assign-sink  statement: total=${a.statement.total} irTaint=${a.statement.irTaint}\n`);
    process.stdout.write(`assign-sink  assignment: total=${a.assignment.total} irTaint=${a.assignment.irTaint}\n`);
    const g = out.globalSources;
    process.stdout.write(`global-sources reachable=${g.reachable}/${g.total} ${JSON.stringify(g.byLanguage)}\n`);
  }
  return 0;
}

main().then(c => process.exit(c)).catch(e => {
  process.stderr.write(`fatal: ${e && e.stack}\n`);
  process.exit(2);
});
