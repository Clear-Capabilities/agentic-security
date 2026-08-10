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

// STATE_SEAM_COMPLETION_PRD M3 — must run BEFORE the first scan. An earlier
// revision inserted this after the last top-level `const`, which in this file
// is the line that performs the scan — so it ran too late and the fixture was
// still littered. Placement, not presence, is what mattered.
const { disableStateWrites } = await import('../bench/_lib/tree-integrity.mjs');
await disableStateWrites();

// TWO fixtures, deliberately. The first version of this gate attested only the
// dependency-free JS fixture, whose findings come entirely from regex and
// structural detectors — the layer that essentially cannot vary between
// machines. Adversarial review caught that: the gate proved determinism over
// the subset chosen for having no variance, which is close to proving nothing.
//
// `fixture-deep` exercises the layers that genuinely could differ: the
// interprocedural taint engine (iteration order over Maps/Sets, cross-file
// walk) and the Python parser (stdlib `ast` subprocess vs. the regex fallback).
// The Python case is pointed: the two parsers produce different `parser`
// attribution, and `attestation.js` excludes `parser` from canonicalisation for
// that reason — so this fixture asks the sharper question of whether the
// FINDINGS agree even when the machinery underneath them may not.
//
// A per-fixture digest, not one combined one, so a divergence names the layer.
const FIXTURES = [
  { name: 'basic', dir: FIXTURE, deep: false },
  { name: 'deep', dir: path.join(REPO, 'bench', 'determinism', 'fixture-deep'), deep: true },
];

async function attestFixture({ dir, deep }) {
  const saved = { d: process.env.AGENTIC_SECURITY_DEEP, c: process.env.AGENTIC_SECURITY_DEEP_IN_CI };
  if (deep) {
    // Both are required: the engine auto-disables deep mode under CI unless the
    // second is set too, and a silent fall back to the syntactic layer would
    // make this fixture agree for the wrong reason.
    process.env.AGENTIC_SECURITY_DEEP = '1';
    process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  }
  try {
    const { scan } = await runScan(dir);
    return normalizeFindings(scan);
  } finally {
    if (deep) {
      if (saved.d === undefined) delete process.env.AGENTIC_SECURITY_DEEP;
      else process.env.AGENTIC_SECURITY_DEEP = saved.d;
      if (saved.c === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
      else process.env.AGENTIC_SECURITY_DEEP_IN_CI = saved.c;
    }
  }
}

const digests = {};
const findingCounts = {};
const parsers = {};
for (const f of FIXTURES) {
  const found = await attestFixture(f);
  const a = computeRunAttestation({
    findings: found,
    engineVersion: PKG_VERSION,
    rulesetVersion: 'fixture-pinned',
    bundleSha256: 'fixture-pinned',
    root: f.dir,
    sign: false,
  });
  digests[f.name] = a.digest;
  findingCounts[f.name] = a.findingCount;
  // Recorded so a reader can confirm the deep fixture really went through the
  // taint engine rather than silently falling back to the syntactic layer.
  parsers[f.name] = [...new Set(found.map(x => x.parser).filter(Boolean))].sort();
}

const findings = await attestFixture(FIXTURES[0]);


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
for (const [name, n] of Object.entries(findingCounts)) {
  if (n === 0) {
    process.stderr.write(
      `ERROR: determinism fixture '${name}' produced NO findings. An empty finding set makes every `
      + 'machine agree trivially, which is not evidence of anything. Fix the fixture or the '
      + 'detectors before trusting this job.\n',
    );
    process.exit(2);
  }
}

// The deep fixture must actually reach the taint engine. If it degrades to the
// syntactic layer the digests would still match across machines — for the wrong
// reason, and the gate would be back to proving nothing.
if (!parsers.deep.includes('IR-TAINT')) {
  process.stderr.write(
    `ERROR: the deep determinism fixture did not produce any IR-TAINT finding (parsers: `
    + `${parsers.deep.join(', ') || 'none'}). It has fallen back to the syntactic layer, so it is no `
    + 'longer testing the layer it exists to test.\n',
  );
  process.exit(2);
}

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
  digests,
  findingCounts,
  parsers,
  engineVersion: att.engineVersion,
  canonicalisation: att.canonicalisation,
  platform: `${process.platform}-${process.arch}`,
  nodeVersion: process.version,
};

if (process.argv.includes('--json')) {
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
} else {
  for (const name of Object.keys(digests)) {
    process.stdout.write(`${name.padEnd(6)} digest: ${digests[name]}  (${findingCounts[name]} findings, ${parsers[name].join('/')})\n`);
  }
  process.stdout.write(`platform:     ${out.platform}  node ${out.nodeVersion}\n`);
}
