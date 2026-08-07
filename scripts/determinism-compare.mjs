#!/usr/bin/env node
// R4 — compare the run attestations produced by every machine in the matrix.
//
// Fails unless all of them carry the same digest. Deliberately strict about
// what counts as a comparison at all: this is the whole evidence for a
// cross-machine claim, so a job that silently compared one file to itself, or
// zero files to each other, would manufacture a green check out of nothing.
//
//   - fewer than two attestations           -> FAIL (nothing was compared)
//   - two attestations from the same machine -> FAIL (not cross-machine)
//   - any digest differs                     -> FAIL (the actual regression)
//   - a zero-finding digest                  -> FAIL (vacuous agreement)
//
// Usage: node scripts/determinism-compare.mjs <dir-of-attestation-json>

import * as fs from 'node:fs';
import * as path from 'node:path';

const dir = process.argv[2];
if (!dir) {
  console.error('usage: determinism-compare.mjs <dir>');
  process.exit(2);
}

function fail(msg) {
  console.error(`\n✗ DETERMINISM CHECK FAILED\n  ${msg}\n`);
  process.exit(1);
}

let files;
try {
  files = fs.readdirSync(dir).filter(f => f.endsWith('.json')).sort();
} catch (e) {
  fail(`could not read ${dir}: ${e.message}`);
}

const runs = [];
for (const f of files) {
  try {
    const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    if (!j || typeof j.digest !== 'string') {
      fail(`${f} carries no digest — a malformed attestation is not a passing one`);
    }
    runs.push({ file: f, ...j });
  } catch (e) {
    fail(`${f} did not parse: ${e.message}`);
  }
}

console.log('=== run attestations ===');
for (const r of runs) {
  console.log(`  ${r.platform}  node ${r.nodeVersion}  findings=${r.findingCount}  ${r.digest}`);
}

if (runs.length < 2) {
  fail(
    `only ${runs.length} attestation(s) found in ${dir}. A cross-machine claim needs at least two. `
    + 'An upload that silently failed must not read as agreement.',
  );
}

const platforms = new Set(runs.map(r => r.platform));
if (platforms.size < 2) {
  fail(
    `all ${runs.length} attestations came from the same platform (${[...platforms].join(', ')}). `
    + 'That is a repeatability check, not a cross-machine one.',
  );
}

const zero = runs.find(r => !r.findingCount);
if (zero) {
  fail(`${zero.file} reports 0 findings — every machine agrees on an empty set, which proves nothing.`);
}

const digests = new Set(runs.map(r => r.digest));
if (digests.size > 1) {
  fail(
    `machines disagree — ${digests.size} distinct digests across ${runs.length} runs. `
    + 'The same commit produced different findings on different machines.',
  );
}

const canon = new Set(runs.map(r => r.canonicalisation));
if (canon.size > 1) {
  fail(`attestations used different canonicalisations (${[...canon].join(', ')}) — the digests are not comparable.`);
}

console.log(
  `\n✓ VERIFIED: ${runs.length} runs across ${platforms.size} platforms `
  + `(${[...platforms].join(', ')}) produced the identical digest ${runs[0].digest} `
  + `over ${runs[0].findingCount} findings.\n`,
);
