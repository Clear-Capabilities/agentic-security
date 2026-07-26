#!/usr/bin/env node
// Before/after harness for the engine-reconnect work.
//
// Scans three minimal fixtures in which a taint source sits in one function and
// the sink in another. Such a flow is undetectable without interprocedural
// analysis, so the `interprocedural` count is the number this whole phase is
// judged on. Committed rather than ad-hoc so the "before" and "after" runs are
// the same measurement.

import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../scanner/src/runScan.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANGS = [
  { id: 'js', dir: 'fixtures/js' },
  { id: 'python', dir: 'fixtures/py' },
  { id: 'cpp', dir: 'fixtures/cpp' },
];

// A finding counts as interprocedural when its reported line is the SINK line
// and the taint originated in a different function. The engine labels IR-derived
// findings with parser 'IR-TAINT'; anything else came from a syntactic rule and
// does not demonstrate the engine working.
function classify(scan) {
  const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
  const irTaint = all.filter(f => (f.parser || '') === 'IR-TAINT');
  return { total: all.length, irTaint: irTaint.length, interprocedural: irTaint.length };
}

async function main() {
  const json = process.argv.includes('--json');
  // Deep mode is what builds IR at all for an in-process caller.
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

  const perLanguage = {};
  for (const l of LANGS) {
    const { scan } = await runScan(path.join(HERE, l.dir));
    perLanguage[l.id] = classify(scan);
  }

  const { scan: san } = await runScan(path.join(HERE, 'fixtures/js'));
  const sanitizedDemoted = [...(san.findings || [])]
    .filter(f => f.sanitized === true || f.provenClean === true).length;

  const out = { perLanguage, sanitizedDemoted };
  if (json) process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  else {
    for (const [k, v] of Object.entries(perLanguage)) {
      process.stdout.write(`${k}: total=${v.total} irTaint=${v.irTaint} interprocedural=${v.interprocedural}\n`);
    }
    process.stdout.write(`sanitizedDemoted=${sanitizedDemoted}\n`);
  }
  return 0;
}

main().then(c => process.exit(c)).catch(e => {
  process.stderr.write(`fatal: ${e && e.stack}\n`);
  process.exit(2);
});
