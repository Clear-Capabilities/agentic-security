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
  const per = r.digests
    ? Object.entries(r.digests).map(([k, v]) => `${k}=${v.slice(0, 12)}`).join(' ')
    : `${r.digest}`;
  console.log(`  ${r.platform}  node ${r.nodeVersion}  ${per}`);
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

// Compare PER FIXTURE. One combined digest would say "the machines disagree"
// without saying which layer diverged, and the whole reason a second fixture
// exists is that the interesting divergence lives in the taint engine and the
// Python parser rather than in the regex detectors.
const fixtureNames = [...new Set(runs.flatMap(r => Object.keys(r.digests || {})))].sort();
if (!fixtureNames.length) {
  fail('no per-fixture digests found — these attestations predate the multi-fixture gate and cannot be compared');
}
for (const name of fixtureNames) {
  const missing = runs.filter(r => !r.digests || !r.digests[name]);
  if (missing.length) {
    fail(`fixture '${name}' is missing from ${missing.map(m => m.platform).join(', ')} — nothing to compare for it`);
  }
  const d = new Set(runs.map(r => r.digests[name]));
  if (d.size > 1) {
    const detail = runs.map(r => `${r.platform}=${r.digests[name].slice(0, 12)}`).join(' ');
    fail(
      `fixture '${name}': machines disagree — ${d.size} distinct digests across ${runs.length} runs (${detail}). `
      + 'The same commit produced different findings on different machines.',
    );
  }
  const counts = new Set(runs.map(r => r.findingCounts?.[name]));
  if (counts.size > 1) {
    fail(`fixture '${name}': finding counts differ across machines (${[...counts].join(', ')})`);
  }
  if (runs.some(r => !r.findingCounts?.[name])) {
    fail(`fixture '${name}' reports 0 findings — every machine agrees on an empty set, which proves nothing.`);
  }
}

// The deep fixture is only worth anything if it actually reached the taint
// engine on EVERY machine. A host where it silently degraded to the syntactic
// layer would agree with the others for the wrong reason.
for (const r of runs) {
  const p = r.parsers?.deep;
  if (p && !p.includes('IR-TAINT')) {
    fail(
      `on ${r.platform} the deep fixture produced no IR-TAINT finding (parsers: ${p.join(', ') || 'none'}) — `
      + 'it degraded to the syntactic layer there, so its agreement is not evidence about the taint engine.',
    );
  }
}

const canon = new Set(runs.map(r => r.canonicalisation));
if (canon.size > 1) {
  fail(`attestations used different canonicalisations (${[...canon].join(', ')}) — the digests are not comparable.`);
}

console.log(
  `\n✓ VERIFIED: ${runs.length} runs across ${platforms.size} platforms `
  + `(${[...platforms].join(', ')}) agreed on every fixture:\n`
  + fixtureNames.map(n =>
    `    ${n.padEnd(6)} ${runs[0].digests[n]} over ${runs[0].findingCounts[n]} findings`
    + `${runs[0].parsers?.[n] ? ` [${runs[0].parsers[n].join('/')}]` : ''}`).join('\n')
  + '\n',
);
