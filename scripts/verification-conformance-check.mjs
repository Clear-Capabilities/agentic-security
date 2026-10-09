#!/usr/bin/env node
// X-208 release gate: every registered oracle adapter must pass the conformance contract.
//
//   node scripts/verification-conformance-check.mjs                 # static contract + pinned fixtures + execution
//   node scripts/verification-conformance-check.mjs --static        # no execution (cheap; any host)
//   node scripts/verification-conformance-check.mjs --require-execution
//   node scripts/verification-conformance-check.mjs --update-pins   # re-pin fixtures and adapter logic, deliberately
//   node scripts/verification-conformance-check.mjs --adapters <module.mjs>   # check another adapter list (tests, contributors)
//
// Exit: 0 every adapter conforms / 1 an adapter does not (or a required execution did not run) / 2 bad arguments.
//
// WHAT FAILS THE GATE: an adapter without a known class scope, without resource budgets under the ceilings, without a negative
// control (and its fixture on disk), or without verifier-side evidence logic bound by a digest; fixtures or adapter logic that
// moved since they were pinned; a registry that leaves an advertised class unserved; and, where execution runs, any wrong state
// mapping, accepted tamper, missing receipt, uncancellable run or non-reproducing replay.
//
// WHERE EXECUTION CANNOT RUN (the trust boundary needs a host where its controls are proved; Linux enforcement is not verified
// by this build) the gate says so and the execution section is `not-run`, never `passed`. It still enforces everything static.
// Pass --require-execution to fail instead of reporting it: use it on a host that is expected to run the boundary.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', 'scanner');
const mod = (rel) => import(pathToFileURL(path.join(SCANNER, 'src', rel)).href);

const argv = process.argv.slice(2);
const flag = (f) => argv.includes(f);
const value = (f) => { const i = argv.indexOf(f); return i === -1 ? null : argv[i + 1]; };
const known = new Set(['--static', '--require-execution', '--update-pins', '--adapters', '--json']);
for (const a of argv) if (a.startsWith('--') && !known.has(a)) { console.error(`unknown flag ${a}`); process.exit(2); }
if (flag('--adapters') && !value('--adapters')) { console.error('--adapters needs a module path'); process.exit(2); }

const conf = await mod('posture/oracles/conformance.js');
const { listOracles } = await mod('posture/oracles/registry.js');

let adapters = listOracles();
if (value('--adapters')) {
  const m = await import(pathToFileURL(path.resolve(value('--adapters'))).href);
  adapters = m.adapters || m.default;
  if (!Array.isArray(adapters)) { console.error('the adapters module must export an array named `adapters`'); process.exit(2); }
}

if (flag('--update-pins')) {
  const pins = { schema: 'agentic-security/oracle-conformance-pins', schemaVersion: '1.0.0', adapters: {} };
  for (const a of [...adapters].sort((x, y) => x.id.localeCompare(y.id))) pins.adapters[a.id] = conf.computePins(a, SCANNER);
  fs.writeFileSync(path.join(SCANNER, conf.PINS_FILE), JSON.stringify(pins, null, 2) + '\n');
  console.log(`pinned ${adapters.length} adapter(s) to ${conf.PINS_FILE}`);
  process.exit(0);
}

// A harness process this run left behind is a cancellation failure: only ours or orphaned ones count.
const harnessProcesses = () => String(spawnSync('ps', ['-A', '-o', 'ppid=,command='], { encoding: 'utf8' }).stdout)
  .split('\n').filter((l) => l.includes('__oracle_harness') && [1, process.pid].includes(Number(l.trim().split(/\s+/)[0]))).length;

const report = await conf.checkConformance(adapters, {
  scannerRoot: SCANNER, execute: !flag('--static'), requireExecution: flag('--require-execution'), harnessProcesses,
});

if (flag('--json')) {
  console.log(JSON.stringify(report, null, 2));
} else {
  for (const r of report.adapters) {
    console.log(`${r.ok ? 'ok  ' : 'FAIL'} ${r.id} (${r.class}) execution: ${r.execution}${r.executionReason ? ` [${r.executionReason}]` : ''}`);
    for (const c of r.checks) if (!c.ok) console.log(`       ${c.check}: ${c.detail}`);
  }
  for (const p of report.registryProblems) console.log(`FAIL registry: ${p}`);
  console.log(report.ok
    ? `verification conformance: ${report.adapters.length} adapter(s) conform${report.executionRan ? '' : ` (static contract and pins only; ${flag('--static') ? 'execution was not requested' : 'execution did not run on this host'})`}`
    : 'verification conformance: FAILED');
}
process.exit(report.ok ? 0 : 1);
