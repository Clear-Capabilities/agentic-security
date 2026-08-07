#!/usr/bin/env node
// R4 — cross-machine determinism probe.
//
// Scans a committed, dependency-free fixture and prints the run attestation
// digest. Two machines running this at the same commit must print the same
// digest; the `determinism-cross-machine` CI job runs it on several OS/Node
// combinations and fails if any digest differs.
//
// WHY A DEDICATED SCRIPT rather than the CLI's `--deterministic` path: that
// flag requires a rules lockfile, which lives under gitignored state and so
// cannot be committed alongside the fixture. This script pins the same inputs
// directly and calls the SAME `computeRunAttestation` the CLI calls, over the
// SAME `normalizeFindings` output the CLI attests.
//
// WHY THE COMPARISON IS BETWEEN LIVE RUNS, not against a committed reference
// digest: a checked-in digest would have to be regenerated on every commit
// that legitimately changes a finding, which turns a determinism gate into a
// chore and trains people to refresh it without reading it. Comparing two live
// runs of the same commit has no such drift — it tests exactly the property
// claimed ("same input, different machine, same answer") and nothing else.
//
// FIXTURE CONSTRAINTS (see bench/determinism/fixture/app.js): no dependencies,
// no network, no timestamps, no randomness. An SCA finding would depend on the
// OSV/KEV cache and would report a network difference as a determinism
// failure.

import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..');
const FIXTURE = path.join(REPO, 'bench', 'determinism', 'fixture');

const require = createRequire(import.meta.url);
const PKG_VERSION = require(path.join(REPO, 'scanner', 'package.json')).version;

const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
const { normalizeFindings } = await import(path.join(REPO, 'scanner', 'src', 'report', 'index.js'));
const { computeRunAttestation } = await import(path.join(REPO, 'scanner', 'src', 'posture', 'attestation.js'));

const { scan } = await runScan(FIXTURE);
const findings = normalizeFindings(scan);

const att = computeRunAttestation({
  findings,
  engineVersion: PKG_VERSION,
  // Pinned rather than read from install-local state: the ruleset version and
  // the bundle hash are per-install facts, and letting them vary would make a
  // difference in local state look like a determinism failure. The property
  // under test is that the same SOURCE yields the same FINDINGS everywhere.
  rulesetVersion: 'fixture-pinned',
  bundleSha: 'fixture-pinned',
  root: FIXTURE,
  sign: false,
});

// A digest over zero findings is identical on every machine for the wrong
// reason. Fail loudly rather than reporting a vacuous pass.
if (att.findingCount === 0) {
  process.stderr.write(
    'ERROR: the determinism fixture produced NO findings. An empty finding set '
    + 'makes every machine agree trivially, which is not evidence of anything. '
    + 'Fix the fixture or the detectors before trusting this job.\n',
  );
  process.exit(2);
}

const out = {
  digest: att.digest,
  findingCount: att.findingCount,
  engineVersion: att.engineVersion,
  canonicalisation: att.canonicalisation,
  platform: `${process.platform}-${process.arch}`,
  nodeVersion: process.version,
};

if (process.argv.includes('--json')) {
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
} else {
  process.stdout.write(`digest:       ${out.digest}\n`);
  process.stdout.write(`findingCount: ${out.findingCount}\n`);
  process.stdout.write(`platform:     ${out.platform}  node ${out.nodeVersion}\n`);
}
