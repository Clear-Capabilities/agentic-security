#!/usr/bin/env node
// Precision harness — this repository scans itself.
//
// Phase 1 introduced six false high-severity findings on this repo's own code
// and they survived several task reviews before anyone measured them by hand.
// This makes that measurement cheap, repeatable and gateable.
//
// Per-FILE counts, not one total: a finding moving between files matters even
// when the total is unchanged.
//
// Coverage note (Phase 2 / task 3, 2026-07-26): `hooks/` and `scripts/` are
// JS/Python only, so they cannot detect a precision change in any other
// language's interprocedural analysis. `fixtures/polyglot/` is the only part
// of this bench that can, and only for the languages it contains a genuine
// caller->callee chain for: each of `app.go`, `App.cs`, `App.kt`, `app.php`
// is a two-function `identity(x) -> emit()` chain where the callee returns
// its argument and the caller passes the result to a sink, with the value
// originating from a hardcoded local literal (not argv/env/network/request)
// — so the correct polyglot total is 0, and a nonzero result there is a real
// false positive on an interprocedural chain over untainted data, not noise
// to tune away. `app.js`/`app.py`/`app.rb` remain single-function, sink-only
// fixtures (no caller), so this bench still cannot see an interprocedural
// change in JS/Python/Ruby, and it has no fixture at all for Java (Task 7).
// Do not over-trust a 0 here as proof nothing moved outside what's listed.

import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../scanner/src/runScan.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const TARGETS = ['hooks', 'scripts'];

function countByFile(scan) {
  const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
  const byFile = {};
  for (const f of all) byFile[f.file] = (byFile[f.file] || 0) + 1;
  const sorted = {};
  for (const k of Object.keys(byFile).sort()) sorted[k] = byFile[k];
  return { total: all.length, byFile: sorted };
}

async function main() {
  // Deep mode is what the CLI uses outside CI, so measure what users get.
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

  const targets = {};
  for (const t of TARGETS) {
    const { scan } = await runScan(path.join(REPO, t));
    targets[t] = countByFile(scan);
  }

  const { scan: poly } = await runScan(path.join(HERE, 'fixtures', 'polyglot'));
  const byLanguage = {};
  for (const f of [...(poly.findings || []), ...(poly.logicVulns || [])]) {
    const ext = (f.file || '').split('.').pop().toLowerCase();
    byLanguage[ext] = (byLanguage[ext] || 0) + 1;
  }

  const out = { targets, polyglot: { total: Object.values(byLanguage).reduce((a, b) => a + b, 0), byLanguage } };
  if (process.argv.includes('--json')) process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  else {
    for (const [t, v] of Object.entries(targets)) process.stdout.write(`${t}: ${v.total}\n`);
    process.stdout.write(`polyglot: ${out.polyglot.total} ${JSON.stringify(byLanguage)}\n`);
  }
  return 0;
}

main().then(c => process.exit(c)).catch(e => {
  process.stderr.write(`fatal: ${e && e.stack}\n`);
  process.exit(2);
});
