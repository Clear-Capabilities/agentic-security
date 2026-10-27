// PRD R2 (docs/DETECTION_GAP_REMEDIATION_PRD.md): runTaintEngine's dead-code
// severity demotion read `e.to` off call-graph edges (edges carry `.callee`)
// and called `.size` on `callersOf` values (plain Arrays, no `.size`). Both
// mismatches mean `calledQids` was always effectively empty, so every
// function whose name didn't match /handler|route|controller|middleware|
// endpoint/i — including a function that IS genuinely called by another
// function — was silently marked `_inDeadCode` and demoted one severity
// notch (critical->high, high->medium, medium->low, low->info).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { mkTestTmp } from './helpers/tmp.js';

function mkTmp(files) {
  const dir = mkTestTmp('as-deadcode-sev-');
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('a function with a real recorded caller is not demoted as dead code, even under a non-handler-shaped name', async () => {
  // The finding is attributed to whichever function's own body contains the
  // complete source-to-sink flow (here, `runShellCommand` itself, via a
  // self-contained process.env source) — NOT to a route/framework callback,
  // which the call graph cannot see as "called" at all (app.get's argument
  // invocation isn't modeled), and NOT to top-level module code, which has
  // no caller by definition. `dispatch` gives `runShellCommand` a real,
  // call-graph-visible caller, which is exactly the population this bug hid.
  const dir = mkTmp({
    'app.js': `
const cp = require('child_process');
function runShellCommand() {
  const secret = process.env.SECRET_CMD;
  cp.exec(secret);
}
function dispatch() { runShellCommand(); }
dispatch();
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding, got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
  const f = irFindings[0];
  assert.equal(f._inDeadCode, undefined, 'runShellCommand IS called by dispatch — it must not be marked dead code');
  assert.equal(f.severity, 'critical', `severity must not be demoted for a genuinely-called function, got ${f.severity}`);
});

test('a function with NO recorded caller is still demoted as dead code (mechanism still works)', async () => {
  const dir = mkTmp({
    'app.js': `
const cp = require('child_process');
function trulyUnusedHelper() {
  const secret = process.env.SECRET_CMD;
  cp.exec(secret);
}
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding, got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
  assert.equal(irFindings[0]._inDeadCode, true, 'trulyUnusedHelper has no callers — dead-code demotion must still fire');
});

test('a <module>-scoped finding is exempt from dead-code demotion — module code has no caller by construction', async () => {
  // A flat top-level script has no recorded caller for its synthetic
  // <module> function (nothing "calls" module scope), so before this fix
  // it fell into the same demotion the handler/route/controller/middleware/
  // endpoint regex was added to prevent for real entry points.
  const dir = mkTmp({
    'app.js': `
const cp = require('child_process');
const secret = process.env.SECRET_CMD;
cp.exec(secret);
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding, got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
  const f = irFindings[0];
  assert.equal(f._inDeadCode, undefined, '<module>-scoped code has no caller by construction — it must not be marked dead code');
  assert.equal(f.severity, 'critical', `severity must not be demoted for module-scope code, got ${f.severity}`);
});

test('the dead-code demotion records the severity the finding would have had (a demotion nobody can see is indistinguishable from a finding that was never that serious)', async () => {
  const dir = mkTmp({
    'app.js': `
const cp = require('child_process');
function trulyUnusedHelper() {
  const secret = process.env.SECRET_CMD;
  cp.exec(secret);
}
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const f = (scan.findings || []).filter((x) => x.parser === 'IR-TAINT')[0];
  assert.ok(f, 'an IR-TAINT finding');
  assert.equal(f._inDeadCode, true);
  assert.equal(f.severity, 'high', 'one notch down from critical');
  assert.equal(f.originalSeverity, 'critical', 'the severity before the demotion is kept');
  // a finding that is NOT demoted records nothing
  const live = mkTmp({ 'app.js': "const cp = require('child_process');\nfunction run() { cp.exec(process.env.SECRET_CMD); }\nfunction go() { run(); }\ngo();\n" });
  const g = ((await runScan(live, { deep: true, deepInCi: true })).scan.findings || []).filter((x) => x.parser === 'IR-TAINT')[0];
  assert.ok(g);
  assert.equal(g.originalSeverity, undefined);
});

test('the Haskell carve-out stays: an exported Haskell function with no caller is not demoted by the neutral dead-code pass', async () => {
  const dir = mkTmp({
    'Svc.hs': 'module Svc (unpackIt) where\n\nimport System.Process\n\nunpackIt :: String -> IO ()\nunpackIt name = callCommand ("tar xf " ++ name ++ " -C /srv/data")\n',
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const f = (scan.findings || []).filter((x) => x.parser === 'IR-TAINT' && /\.hs$/.test(x.file || ''))[0];
  assert.ok(f, 'a Haskell IR-TAINT finding');
  assert.equal(f._inDeadCode, undefined, 'an exported function is reachable from outside the analysed files');
  assert.equal(f.severity, 'critical');
});
