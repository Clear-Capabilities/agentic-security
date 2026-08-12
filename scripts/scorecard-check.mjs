#!/usr/bin/env node
// Release gate: refuses to publish when the committed accuracy scorecard
// does not describe the release being published.
//
// DELIBERATE DESIGN DECISION — DO NOT REPLACE THIS WITH REGENERATION:
// this script CHECKS the committed docs/SCORECARD.md + docs/scorecard.json;
// it never regenerates them. Regenerating automatically at publish time
// would publish accuracy figures that no human reviewed, and would let the
// committed artifact silently diverge from what a person actually looked
// at before shipping. The entire value of the scorecard is that its numbers
// were reviewed by a human before being committed — `npm run scorecard`
// (scripts/scorecard.mjs) is that human-in-the-loop step, run separately,
// on purpose. If this gate fails, the fix is to run that command, read the
// numbers, and commit them — not to make the gate do it for you.
//
// What is checked, and why:
//   · docs/scorecard.json provenance.engineVersion must equal the version in
//     scanner/package.json. This is the release-relevant check: a version
//     bump with no matching scorecard run means the published figures
//     describe a previous release.
//   · docs/scorecard.json / docs/SCORECARD.md missing or unparseable → fail.
//   · docs/scorecard.json corpus.totalEntries must equal the number of entries
//     actually on disk. This closes a real hole: the version check alone let a
//     scorecard reporting 200 entries pass while the corpus held 210, because
//     entries had been added without a version bump. The corpus is the
//     population every corpus figure is computed over, so a scorecard
//     describing a different population is not stale in a cosmetic way — its
//     denominators are wrong.
//
// What is a WARNING, not a failure, and why:
//   · docs/scorecard.json provenance.bundleSha256 vs. the current
//     scanner/dist/agentic-security.mjs.sha256. The bundle hash changes on
//     every source edit during ordinary development — failing the build on
//     that would block every unrelated PR that touches scanner/src, not
//     just releases. The version check above is the one that actually gates
//     a release; the bundle-SHA check is a soft nudge printed to stderr so a
//     maintainer notices the scorecard predates the last build, without
//     blocking anything.
//
// Usage: node scripts/scorecard-check.mjs   (exit 0 pass / 1 fail)

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

const REMEDY = 'Run `npm run scorecard`, review the numbers, and commit the result.';

/**
 * Pure decision function — no I/O. Exported so tests can exercise the
 * staleness logic directly on constructed inputs rather than shelling out.
 *
 * @param {object} args
 * @param {string} args.pkgVersion - version from scanner/package.json
 * @param {object|null} args.scorecardJson - parsed docs/scorecard.json, or
 *   null if missing/unreadable/unparseable
 * @param {boolean} args.scorecardMdPresent - whether docs/SCORECARD.md exists
 * @param {string|null} args.currentBundleSha256 - sha256 of the current
 *   built bundle, or null if the bundle hasn't been built
 * @returns {{ ok: boolean, errors: string[], warnings: string[] }}
 */
export function evaluateScorecardFreshness({
  pkgVersion,
  scorecardJson,
  scorecardMdPresent,
  currentBundleSha256,
  actualCorpusEntries = null,
}) {
  const errors = [];
  const warnings = [];

  if (!scorecardMdPresent) {
    errors.push(`docs/SCORECARD.md is missing. ${REMEDY}`);
  }

  if (!scorecardJson || typeof scorecardJson !== 'object') {
    errors.push(`docs/scorecard.json is missing or unparseable. ${REMEDY}`);
  } else {
    const engineVersion = scorecardJson.provenance && scorecardJson.provenance.engineVersion;
    if (!engineVersion) {
      errors.push(`docs/scorecard.json has no provenance.engineVersion. ${REMEDY}`);
    } else if (engineVersion !== pkgVersion) {
      errors.push(
        `docs/scorecard.json describes engine version ${engineVersion}, but ` +
        `scanner/package.json is at ${pkgVersion} — the committed scorecard is stale. ${REMEDY}`
      );
    } else if (
      currentBundleSha256 &&
      scorecardJson.provenance.bundleSha256 &&
      scorecardJson.provenance.bundleSha256 !== currentBundleSha256
    ) {
      warnings.push(
        'docs/scorecard.json bundleSha256 does not match the current built bundle ' +
        '(scanner/dist/agentic-security.mjs) — expected on ordinary source edits; ' +
        `re-run \`npm run scorecard\` before release if this persists at publish time.`
      );
    }
  }

  // A scorecard that could not score every corpus entry is an INCOMPLETE
  // measurement, and publishing it would present a partial result as an
  // authoritative one. The generator deliberately still writes it — excluding
  // an unscoreable entry from the denominator and naming it is the honest thing
  // to do while iterating — but a release must not ship it.
  //
  // This is nearly always transient and environmental (a language helper
  // exceeding its budget on a loaded machine), which is exactly why it must
  // block: it means the published figure would silently depend on how busy the
  // machine was when someone last ran it.
  const corpus = scorecardJson && scorecardJson.corpus;

  // The corpus is the POPULATION every corpus rate is computed over. A
  // scorecard describing a different population has wrong denominators, not
  // merely a stale timestamp — so this is an error, not a warning. Skipped
  // when the count could not be determined, because guessing would be worse
  // than not checking.
  if (corpus && actualCorpusEntries != null) {
    const declared = corpus.totalEntries;
    if (declared !== actualCorpusEntries) {
      errors.push(
        `docs/scorecard.json was measured over ${declared} corpus entries, but ${actualCorpusEntries} ` +
        'are present on disk. Every corpus rate in the scorecard is computed over that population, ' +
        `so the published denominators describe a corpus that no longer exists. ${REMEDY}`
      );
    }
  }

  // The independent-population section — docs/SCORECARD.md's own words,
  // "the number that matters" — is read from a committed artifact
  // (bench/independent/RESULT.json) rather than regenerated by `npm run
  // scorecard`, since scoring it takes ~32 minutes; a release does not
  // re-run it every time. That's WHY this is a warning, not an error like
  // the primary provenance.engineVersion check above (which IS regenerated
  // on every scorecard run, so staleness there really does mean "forgot to
  // re-run"): the independent figures can legitimately lag several releases
  // behind. But nothing was checking it AT ALL before this — a release
  // could ship quoting an F1/precision/recall measured against an engine
  // version arbitrarily far in the past with zero signal to a maintainer.
  const independent = scorecardJson && scorecardJson.committedInputs && scorecardJson.committedInputs.independent;
  if (independent && independent.engineVersion && independent.engineVersion !== pkgVersion) {
    warnings.push(
      `docs/scorecard.json's independent-population section ("the number that matters") was measured ` +
      `on engine ${independent.engineVersion}, but scanner/package.json is at ${pkgVersion}. This is ` +
      'expected to lag (the independent eval takes ~32 minutes and is not re-run every release) — ' +
      `but if it has been many releases, re-run \`npm run bench:independent\` and commit the refreshed RESULT.json.`
    );
  }

  const notScored = (corpus && Array.isArray(corpus.notScored)) ? corpus.notScored : [];
  if (notScored.length) {
    const named = notScored
      .map((n) => `${n.cve || '(unnamed)'}${n.error ? ` — ${n.error}` : ''}`)
      .join('; ');
    errors.push(
      `docs/scorecard.json scored only ${corpus.scoredEntries}/${corpus.totalEntries} corpus ` +
      `entries; ${notScored.length} could not be scored: ${named}. An incomplete measurement ` +
      'must not be published as an accuracy figure. Remedy: re-run `npm run scorecard` — these ' +
      'failures are usually a language helper exceeding its time budget under load, so raising ' +
      'the relevant *_TIMEOUT_MS budget and re-running normally yields a full score.'
    );
  }

  return { ok: errors.length === 0, errors, warnings };
}

function readJsonIfPresent(absPath) {
  try {
    return JSON.parse(fs.readFileSync(absPath, 'utf8'));
  } catch {
    return null;
  }
}

// Count the corpus the same way the runner enumerates it: a directory is an
// entry iff it carries a manifest.json. Counting directories alone would
// drift from the runner's own definition and could disagree with it.
// Exported so release-check.mjs's scorecardFacts() reuses this exact
// definition rather than growing a second, possibly-drifting count.
export function countCorpusEntries(repoRoot) {
  try {
    let n = 0;
    for (const tier of ['regression', 'capability', 'deep']) {
      const dir = path.join(repoRoot, 'bench', 'cve-replay', tier);
      for (const e of fs.readdirSync(dir)) {
        if (fs.existsSync(path.join(dir, e, 'manifest.json'))) n++;
      }
    }
    return n;
  } catch {
    return null; // corpus unreadable — skip the check rather than guess
  }
}

function main() {
  const pkg = readJsonIfPresent(path.join(REPO, 'scanner', 'package.json'));
  const pkgVersion = pkg && pkg.version;

  const scorecardJson = readJsonIfPresent(path.join(REPO, 'docs', 'scorecard.json'));
  // Deliberately a single read inside try/catch rather than an
  // existsSync-then-read: the check-then-use form is a TOCTOU pattern this
  // project's own engine flags (see scripts/scorecard.mjs's readJsonIfPresent
  // for the same precedent). We only need presence, not content, so the read
  // result is discarded.
  let scorecardMdPresent = false;
  try {
    fs.readFileSync(path.join(REPO, 'docs', 'SCORECARD.md'), 'utf8');
    scorecardMdPresent = true;
  } catch { /* missing/unreadable — treated as absent */ }

  let currentBundleSha256 = null;
  try {
    const raw = fs.readFileSync(
      path.join(REPO, 'scanner', 'dist', 'agentic-security.mjs.sha256'), 'utf8');
    currentBundleSha256 = raw.trim().split(/\s+/)[0] || null;
  } catch { /* bundle not built — nothing to compare against, not an error here */ }

  const actualCorpusEntries = countCorpusEntries(REPO);

  if (!pkgVersion) {
    process.stderr.write('✗ scorecard-check: could not read scanner/package.json version\n');
    process.exit(1);
  }

  const result = evaluateScorecardFreshness({
    actualCorpusEntries,
    pkgVersion,
    scorecardJson,
    scorecardMdPresent,
    currentBundleSha256,
  });

  for (const w of result.warnings) process.stderr.write(`⚠ ${w}\n`);
  for (const e of result.errors) process.stderr.write(`✗ ${e}\n`);

  if (result.ok) {
    process.stderr.write(`✓ docs/SCORECARD.md + docs/scorecard.json match engine version ${pkgVersion}\n`);
    process.exit(0);
  }
  process.exit(1);
}

// Only run as a CLI gate when invoked directly — importing this module (as
// the test suite does, to exercise evaluateScorecardFreshness() directly)
// must not trigger I/O or process.exit().
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
