#!/usr/bin/env node
// Held-out invariant scenario ablation driver (X-408): `npm run bench:invariant-ablation -- <command>`.
//
//   run [--json] [--fixtures <dir>] [--no-source]
//                   run source-only, inferred-contract and approved-contract over the frozen SYNTHETIC benchmark and print
//                   precision, recall (with intervals), unique findings, scenario cost and the per-class claims. Executes
//                   fixtures through the trust boundary; where it cannot run, every class reads UNMEASURED. `--no-source`
//                   skips the (slow) engine scan and reports the baseline arm as unavailable.
//   verify          check the benchmark against its pin (fast, executes nothing). Exit 0 intact, 1 changed.
//   pin             write a new pin after a DELIBERATE benchmark change. Not part of any gate.
//
// Every figure is flagged synthetic: authored and labelled by the tooling's developers, no independent adjudication, no
// real-world claim. Exit codes: 0 ok, 1 failed or changed, 2 usage.
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBenchmark, pinBenchmark, runInvariantAblation, renderAblation } from '../scanner/src/posture/evaluation/invariant-ablation.js';
import { resolveAssuranceConfig } from '../scanner/src/posture/assurance/config.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (n) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : undefined; };
const has = (n) => argv.includes(`--${n}`);
const dir = path.resolve(flag('fixtures') || path.join(HERE, '..', 'scanner', 'test', 'fixtures', 'invariant-benchmark'));

async function main() {
  if (cmd === 'pin') { console.log(JSON.stringify(pinBenchmark(dir))); return 0; }
  const loaded = loadBenchmark(dir);
  if (!loaded.ok) { console.error(`benchmark NOT intact:\n  ${loaded.errors.join('\n  ')}`); return 1; }
  if (cmd === 'verify') { console.log(`benchmark intact: v${loaded.benchmark.version}, ${loaded.benchmark.cases.length} synthetic cases, ${loaded.benchmark.manifestHash}`); return 0; }
  if (cmd !== 'run') { console.error('Usage: invariant-ablation.mjs <run [--json] [--no-source] | verify | pin>'); return 2; }

  const config = resolveAssuranceConfig({ env: {}, overrides: { features: { 'invariant-scenarios': true, 'verification-oracles': true } } });
  const sourceAnalyzer = has('no-source') ? async () => { throw new Error('the source-only arm was skipped (--no-source)'); } : undefined;
  // The fixtures are not commits of this repository: the revision they are bound to is the frozen manifest's own digest.
  const commit = loaded.benchmark.manifestHash.slice('sha256:'.length, 'sha256:'.length + 40);
  const report = await runInvariantAblation({ benchmark: loaded.benchmark, commit, config, sourceAnalyzer });
  if (has('json')) console.log(JSON.stringify(report, null, 2));
  else console.log(renderAblation(report).join('\n'));
  return 0;
}

main().then((c) => process.exit(c), (e) => { console.error(e?.stack || e); process.exit(1); });
