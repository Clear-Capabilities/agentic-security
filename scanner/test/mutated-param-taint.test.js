// Stage 3 correctness audit (detection depth): mutated-parameter taint
// propagation (dataflow/CLAUDE.md's FR-SEM-2, "applyAtCallSite") was
// unconditionally inert for JS/TS. Root cause: parser-js.js's `fn.params`
// was an array of `{name, kind}` objects, but every consumer that matches
// against it — access-paths.js's `isCoveredBy` (`typeof path === 'string'`
// guard fails on an object and returns false), summaries.js's
// `paramNames.indexOf(paramName)`, and the k=2 `new Set(fn.params)` build —
// assumes plain strings, per the documented IR contract. A parameter could
// never register in `_mutatedParamsOut`, so `applyAtCallSite` always saw an
// empty `mutatedParams` set and never propagated anything back to the
// caller. Fixed in parser-js.js (fn.params now emits strings).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-mutparam-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('a helper that reassigns its own param propagates taint back to the caller\'s argument variable', async () => {
  const dir = mkTmp('reassign', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
function replaceAll(target, source) { target = source; }
app.get('/run', (req, res) => {
  const body = req.body;
  let cfg;
  replaceAll(cfg, body);
  cp.exec(cfg);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    `expected cp.exec(cfg) to fire via mutated-param propagation from replaceAll(), got IR-TAINT findings: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});
