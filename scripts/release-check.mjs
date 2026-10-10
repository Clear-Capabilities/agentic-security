#!/usr/bin/env node
// Pre-publish release gate — everything that must be true before a version
// goes out the door, checked in one place, with a named remedy per failure.
//
// WHY THIS EXISTS
// ---------------
// A release is not one artifact, it is a set of artifacts that must agree:
// five files carrying the version string, two changelogs, a built bundle
// and its hash sidecar, a committed accuracy scorecard, three gates, and a
// commit that the public can actually fetch. Historically the failure mode
// was never "the code was wrong" — it was a half-done release: the version
// bumped in four of five places, a changelog entry written for the previous
// number, a bundle rebuilt but not committed. Each of those ships silently.
// This gate makes each of them a named, remediable failure.
//
// TWO DESIGN RULES, BOTH LEARNED THE HARD WAY
// -------------------------------------------
//  1. An unverifiable check is NOT a satisfied check. If the hosted-CI
//     status cannot be read — no forge CLI on PATH, not authenticated, API
//     unreachable — that check FAILS. It does not warn-and-continue. The
//     only way past it is `--allow-unverified-ci`, which a human types
//     deliberately and which prints a loud banner naming exactly what went
//     unproven. A gate that degrades to a pass under adverse conditions is
//     decoration.
//  2. The fast path must never be the publish path. `--fast` skips the
//     slow gates (checks 6-8, and check 11 which is a registry round-trip)
//     so a maintainer can iterate; the
//     `prepublishOnly` wiring in scanner/package.json calls this script
//     with NO flags, so publishing always runs the full set. If you are
//     tempted to put `--fast` in prepublishOnly, the correct fix is to make
//     the slow gates faster.
//
// WHY REMOTE CI IS THE HEART OF IT (check 10)
// -------------------------------------------
// Local green on one platform is not proof the release works. This project
// has shipped a change that was green on the maintainer's machine and red
// on the hosted Linux runner. Checks 6-8 prove "it works here"; check 10
// proves "it works where everyone else runs it", for the exact commit being
// published. That is the difference between a test run and a release gate.
//
// Usage:
//   node scripts/release-check.mjs                      # full gate
//   node scripts/release-check.mjs --fast               # skip the slow checks
//   node scripts/release-check.mjs --allow-unverified-ci
//   node scripts/release-check.mjs --group <name>       # one named group (see RELEASE_GROUPS)
//   node scripts/release-check.mjs --only id,id         # exactly these checks
//   node scripts/release-check.mjs --group tests --shard 2/4   # one shard of the test suite
// Exit: 0 all planned checks passed / 1 one or more failed / 2 bad arguments.
//
// PARTIAL RUNS (the hosted release workflow runs the gate as parallel jobs)
// -------------------------------------------------------------------------
// --group, --only and --shard each run a SUBSET of the checks. A subset run
// fails closed exactly like a full run (any failing check exits 1), but it is
// labelled as partial in its header and its final line, and it NEVER prints the
// full-gate success line: only a run that executed every planned check may say
// "Release gate passed". The workflow's publish job depends on every group, so
// the union of the partial runs is the full gate. RELEASE_GROUPS names the
// groups; the group called `rest` is computed as the COMPLEMENT of the named
// ones, so a newly added check lands in `rest` and runs by default instead of
// being silently dropped.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { evaluateScorecardFreshness, countCorpusEntries } from './scorecard-check.mjs';
import { runDependencyCurrencyCheck } from './dependency-currency.mjs';
import { runPackageContentsCheck } from './package-contents-check.mjs';
import { signLastScan } from '../scanner/src/posture/integrity.js';
import { computeRunAttestation, verifyRunAttestation } from '../scanner/src/posture/attestation.js';
import {
  gatherKeyParts, computeVerdictKey, loadCache, recordVerdict,
  evaluateCachedVerdict, renderProvenance, cachingDisabled,
} from './gate-verdict-cache.mjs';
import { runCalibrationHoldoutCheck } from './calibration-holdout-check.mjs';
import { runIndependentPopulationGate } from './independent-population-gate.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const SCANNER = path.join(REPO, 'scanner');

// The forge CLI is invoked by name only, always through spawnSync with an
// argv array (never a shell string), so no input can ever be interpreted as
// a command. Kept as a constant so the "which external tool" decision is in
// exactly one place.
const FORGE_CLI = 'gh';

// ---------------------------------------------------------------------------
// Check registry. Order is the printed order and the execution order; `slow`
// marks the three gates `--fast` skips. `remedy` is what a human should do.
// ---------------------------------------------------------------------------

export const CHECKS = [
  {
    id: 'working-tree-clean',
    title: 'Working tree clean',
    slow: false,
    remedy: 'Commit or stash every change (including untracked files) before publishing.',
  },
  {
    id: 'version-consistency',
    title: 'Version string consistent across all release artifacts',
    slow: false,
    remedy: 'Set the same version in scanner/package.json, .claude-plugin/plugin.json, ' +
      '.claude-plugin/marketplace.json (BOTH occurrences), gemini-extension.json, CLAUDE.md and README.md.',
  },
  {
    id: 'changelog-entry',
    title: 'Changelog entry exists for this version',
    slow: false,
    remedy: 'Add a `## <version> — <title>` section to CHANGELOG.md and scanner/CHANGELOG.md.',
  },
  {
    id: 'completion-declared',
    title: 'A release with unfinished requirements says so, naming each one',
    slow: false,
    remedy: 'docs/completion-status.json lists requirements that are not verified. Either finish them, or put a "Partial release" paragraph naming every remaining ID in this version\'s CHANGELOG.md section and keep the README status block (node scripts/render-language-docs.mjs) in step.',
  },
  {
    id: 'doc-links',
    title: 'User-facing doc links resolve (README, docs/, commands/, skills/, agents/)',
    slow: false,
    remedy: 'Run `node scripts/check-doc-drift.mjs --gate` and fix or remove each dangling link it lists.',
  },
  {
    id: 'bundle-integrity',
    title: 'Built bundle matches its SHA-256 sidecar',
    slow: false,
    remedy: 'Run `npm run build` in scanner/ and commit both dist/agentic-security.mjs ' +
      'and dist/agentic-security.mjs.sha256.',
  },
  {
    id: 'scorecard-freshness',
    title: 'Committed accuracy scorecard describes this version',
    slow: false,
    remedy: 'Run `npm run scorecard`, review the numbers, and commit the result.',
  },
  {
    // R4 correctness follow-up: computeRunAttestation is genuinely wired
    // (bin/agentic-security.js, every scan), but nothing ever exercised
    // verifyRunAttestation — a broken canonicalisation or signing change
    // could ship and nobody would notice until a third party tried to
    // verify a shipped attestation and it silently failed. Round-trips a
    // synthetic finding set through compute-then-verify (must pass) and a
    // mutated copy (must fail) — proves the subsystem still does what it
    // claims, in both directions, before every release.
    id: 'attestation-self-check',
    title: 'Run-attestation compute/verify round-trip holds',
    slow: false,
    remedy: 'Run `node --test scanner/test/attestation.test.js` and fix the ' +
      'canonicalisation or signing code — see scanner/src/posture/attestation.js.',
  },
  {
    // Stage 6 correctness follow-up: build-catalog.py --check exists
    // specifically to catch controls.json drifting from the source
    // spreadsheet, and it works (verified by running it), but nothing
    // automated ever called it — a spreadsheet edit with no matching
    // controls.json regeneration could ship silently.
    // Generalized from a single hardcoded script to every generated catalog:
    // a second one (NIST SP 800-171 Rev. 3) landed, and a gate that names one
    // script by path silently stops covering the rest.
    id: 'nist-catalog-freshness',
    title: 'Generated NIST control catalogs match their sources',
    slow: false,
    remedy: 'Run the named build-catalog.py to regenerate its controls.json from the ' +
      'updated source, then commit the result. For 800-171 the source is both the CSV ' +
      'export and code-testability.json — a control with no rating fails the build.',
  },
  {
    // Adversarial premortem P0.2 (2026-09-07): code-testability.json's 97
    // hand-authored ratings shipped through the same single-author,
    // no-second-review process that produced six false SAST findings in
    // this repo's own history (see bench/self-scan/check.mjs's own header).
    // That incident got a permanent gate; this one, until now, did not.
    id: 'nist-800-171-labels',
    title: 'NIST 800-171 codeTestable ratings match a reviewed anchor set',
    slow: false,
    remedy: 'Run `npm run bench:nist-800-171-labels:check` in scanner/ and read which ' +
      'anchor drifted. If the drift is a deliberate, reviewed correction, update ' +
      'bench/nist-800-171-labels/GOLDEN.json to match and record why in its `why` field.',
  },
  {
    id: 'package-contents',
    title: 'Package contents match the committed expectation',
    // Local: one npm pack --dry-run and a git ls-files call, no network. Cheap
    // enough to run even under --fast, and it is the only check that examines
    // the artifact itself rather than the source that produces it.
    slow: false,
    remedy: 'Compare the printed diff against scanner/expected-package-manifest.json. Fix ' +
      '`files` in scanner/package.json or remove the stray path; only update the committed ' +
      'expectation file if the new shape is an intended, reviewed change to what ships.',
  },
  {
    id: 'test-suite',
    title: 'Full test suite passes',
    slow: true,
    remedy: 'Run `npm test` in scanner/ and fix the failures.',
  },
  {
    id: 'corpus-gate',
    title: 'CVE-replay corpus baseline holds',
    slow: true,
    remedy: 'Run `npm run bench:cve-replay:check` in scanner/ and resolve the drift ' +
      '(fix the regression, or re-baseline only if the change is intended).',
  },
  {
    id: 'self-scan-gate',
    title: 'Self-scan precision baseline holds',
    slow: true,
    remedy: 'Run `npm run bench:self-scan:check` in scanner/ and fix the code that ' +
      'changed detection behaviour on this repository.',
  },
  {
    // M2 (Stage-0 audit, 2026): built with both-direction verification
    // recorded, but unreachable from every gate including this one — a
    // repo-wide grep found `bench:mutation:check` only in package.json and
    // documentation. A publish could ship a detector that keys on syntax
    // rather than semantics with nothing to catch it.
    id: 'mutation-gate',
    title: 'Metamorphic + adversarial mutation gate holds',
    slow: true,
    remedy: 'Run `npm run bench:mutation:check` in scanner/ — a detector is keying ' +
      'on syntax rather than semantics. See the printed case for which mutant flipped.',
  },
  {
    // M2 Sub-project H, increment 1 (Decision 2's false-protected release
    // gate, transit/atRest only — see docs/superpowers/plans/
    // 2026-08-31-data-flow-explorer-m2-subproject-h1-plan.md). Mirrors
    // mutation-gate's own dual release-check/pre-push wiring.
    id: 'protection-verdict-gate',
    title: 'False-protected release gate holds (transit/atRest verdicts)',
    slow: true,
    remedy: 'Run `npm run bench:protection-verdict:check` in scanner/ — a protection ' +
      'verdict is asserting `protected` without real evidence. See the printed case for ' +
      'which mutant failed to flip.',
  },
  {
    id: 'layer-recall-gate',
    title: 'Per-layer, per-language taint recall baseline holds',
    slow: true,
    remedy: 'Run `npm run bench:layer-recall:check` in scanner/ and inspect which ' +
      "language's taint-layer recall regressed — see docs/METRICS.md.",
  },
  {
    id: 'language-support-gate',
    title: 'Haskell/Nix support registry matches the stored measurement',
    slow: true,
    remedy: 'Run `npm run bench:language-support:check` in scanner/. To change a number, re-measure and promote it deliberately ' +
      '(bench/language-support/promote.mjs); never edit docs/language-support.json by hand.',
  },
  {
    // FR-906 (assurance-hardening PRD): the performance half of "add
    // performance, memory, determinism, and fault-injection gates." The
    // measurement (bench/ttff/runner.mjs, PRD F11.2) already existed and
    // was already gateable (`--check` against a committed baseline) — it
    // was simply never wired into a release gate. Wired here rather than
    // rebuilt.
    id: 'ttff-gate',
    title: 'Time-to-first-finding baseline holds',
    slow: true,
    remedy: 'Run `npm run bench:ttff:check` in scanner/ — if the regression is a real, ' +
      'accepted cost, re-baseline deliberately with `npm run bench:ttff:update-baseline` ' +
      'and say why in the commit.',
  },
  {
    // FR-906: the memory half. bench/memory/runner.mjs is new this cycle —
    // no prior memory-budget measurement existed anywhere in this repo to
    // reuse — built to the exact same baseline/regression-factor/--check
    // shape bench/ttff/runner.mjs already established, not a new design.
    id: 'memory-gate',
    title: 'Peak memory (RSS) baseline holds',
    slow: true,
    remedy: 'Run `npm run bench:memory:check` in scanner/ — if the regression is a real, ' +
      'accepted cost, re-baseline deliberately with `npm run bench:memory:update-baseline` ' +
      'and say why in the commit.',
  },
  {
    // Finding Provenance M2: bench/provenance/runner.mjs measures the real,
    // observed overhead the provenance pipeline adds to a scan, built to the
    // same baseline/regression-factor/--check shape as ttff-gate/memory-gate
    // above. It existed and was already gateable but was never wired into a
    // release gate — per this repo's own standard ("an unrunnable check is a
    // FAILURE, never a skip"), an unwired gate isn't a gate. Wired here
    // rather than rebuilt.
    id: 'provenance-gate',
    title: 'Finding provenance overhead baseline holds',
    slow: true,
    remedy: 'Run `npm run bench:provenance:check` in scanner/ — if the regression is a real, ' +
      'accepted cost, re-baseline deliberately with `npm run bench:provenance:update-baseline` ' +
      'and say why in the commit.',
  },
  {
    // X-208: the oracle conformance contract. Rejects an adapter that lacks class scope, resource budgets, negative controls or
    // verifier-side evidence logic, fixtures or adapter logic that moved since they were pinned, and (where the trust boundary
    // can run) any wrong state mapping, accepted tamper, uncancellable run or non-reproducing replay. On a host that cannot run
    // the boundary the execution half is reported not-run, never passed; the static half is always enforced.
    id: 'verification-conformance-gate',
    title: 'Every registered verification oracle conforms (class scope, budgets, negative controls, evidence receipts)',
    slow: true,
    remedy: 'Run `npm run verification:conformance:check` in scanner/ and fix the adapter named. To change a pinned fixture or ' +
      'adapter logic deliberately, re-pin with `node scripts/verification-conformance-check.mjs --update-pins` and say why in the commit.',
  },
  {
    // REL-001: the new assurance suites plus the existing controller, smoke, build/bundle-source, documentation, scorecard and
    // Haskell/Nix/core-language compatibility checks, run against ONE exact commit (scripts/release-closure.mjs). The local gate
    // holds only when every locally runnable step passes with no skip, the tree is clean and the record binds suite versions and
    // logs to the commit. A step only hosted CI can satisfy (a GHC toolchain, a NixOS host) is reported NOT COUNTED and never
    // passes here; the record then stays not publishable until the same commit is attested remotely.
    id: 'release-closure-gate',
    title: 'Release closure holds against this exact commit (new suites, controller, smoke, bundle-source, docs, scorecard, compatibility)',
    slow: true,
    remedy: 'Run `npm run release:closure:check` in scanner/ and fix the step named. A step reported NOT COUNTED needs its hosted CI job ' +
      '(see the message) green for this commit; it is never satisfied by this machine skipping it.',
  },
  {
    id: 'calibration-holdout',
    title: 'Confidence surface verified on held-out data',
    slow: false,
    remedy: 'Add a held-out labelled set at bench/calibration-holdout/labels.jsonl, or ' +
      'record a dated waiver in .calibration-waiver.json. An unverified confidence ' +
      'surface is not a calibrated one.',
  },
  {
    id: 'independent-population-gate',
    title: 'Independent-population precision/recall/F1 holds at or above baseline',
    slow: false,
    remedy: 'Run `node scripts/independent-population-gate.mjs` for the failing detail, ' +
      'then either fix the regression, run `node scripts/independent-population-gate.mjs ' +
      '--update-baseline` if the drop is understood and intended, or record a dated ' +
      'exception in .independent-population-waiver.json.',
  },
  {
    id: 'head-pushed',
    title: 'HEAD exists on origin/main',
    slow: false,
    remedy: 'Push the release commit to origin/main so the published artifact ' +
      'corresponds to public source.',
  },
  {
    id: 'remote-ci-green',
    title: 'Hosted CI is green for HEAD',
    slow: false,
    remedy: 'Wait for hosted CI to finish and go green for this exact commit. If the ' +
      'forge CLI is unavailable, authenticate it — or pass --allow-unverified-ci ' +
      'deliberately, accepting that hosted CI went unproven.',
  },
  {
    id: 'dependency-currency',
    title: 'Dependencies free of advisories and on their latest versions',
    // Slow: two registry round-trips per package tree, four in all. --fast is
    // for local iteration; prepublishOnly passes no flags, so a publish always
    // runs this. See scripts/dependency-currency.mjs for the full rationale.
    slow: true,
    remedy: 'Upgrade the named packages. A known vulnerability at moderate severity or ' +
      'above can never be waived. An upgrade that is verifiably unsafe goes in ' +
      '.dependency-holds.json with a reason and a reviewBy date; an expired, stale or ' +
      'unjustified hold fails too. If the registry was unreachable, the check is ' +
      'unverified — restore access and re-run.',
  },
];

/** Ids of the checks a run with these options will actually execute. */
export function plannedCheckIds({ fast = false } = {}) {
  return CHECKS.filter(c => !(fast && c.slow)).map(c => c.id);
}

// ---------------------------------------------------------------------------
// Groups. The hosted release workflow runs one job per group (and one per test
// shard), in parallel. Timings behind the split, from the v0.158.0 release run:
// test-suite 14.9 min (sharded further, see --shard); provenance 2.4, self-scan
// 2.3, cve-replay 2.0, layer-recall 1.9, memory 1.2, ttff 0.2; everything else
// under a minute each. The slowest benches sit in different groups.
//
// Only the NAMED groups are listed. `rest` is every planned check not named
// here (see `resolveGroups`), so adding a check to CHECKS without touching this
// table runs it in `rest`; it can never fall out of the release.
// ---------------------------------------------------------------------------
/**
 * Which closure script this environment can honestly run. The hosted runner is Linux, where the trust boundary is unverified and the
 * execution suites correctly skip (a skip is a gap, never a pass), so the full closure can never hold there: it runs the static half
 * (plan, wiring, files). The full closure is established on a host that can run the boundary, by the release orchestrator's verify step,
 * which refuses to tag a commit unless it held.
 */
export function closureGateScript(env = process.env) {
  return env.GITHUB_ACTIONS === 'true' ? 'release:closure:static' : 'release:closure:check';
}
export const HOSTED_CLOSURE_NOTE = 'hosted runner: only the static closure (plan, wiring, files) was checked. The execution closure needs a host that can run the trust boundary, which this Linux runner cannot yet; it is established by the release orchestrator\'s verify step before a tag is created, and is NOT claimed by this leg.';

export const RELEASE_GROUPS = {
  tests: ['test-suite'],
  'benches-a': ['provenance-gate', 'corpus-gate', 'ttff-gate'],
  'benches-b': ['self-scan-gate', 'layer-recall-gate', 'memory-gate', 'verification-conformance-gate'],
  closure: ['release-closure-gate'],
};

/** Every group name a run may select, `rest` included. */
export function groupNames() {
  return [...Object.keys(RELEASE_GROUPS), 'rest'];
}

/** { name: [ids] } for every group, with `rest` computed as the complement of the named groups. */
export function resolveGroups() {
  const named = new Set(Object.values(RELEASE_GROUPS).flat());
  return { ...RELEASE_GROUPS, rest: plannedCheckIds().filter((id) => !named.has(id)) };
}

/**
 * Parse the partial-run flags. Returns { error } for anything malformed; never
 * guesses. `--shard` is only meaningful for the test suite, so it is refused
 * when the selection does not include `test-suite` (a shard flag that silently
 * does nothing would look like a sharded run and prove nothing).
 */
export function parseSelection(argv, { fast = false } = {}) {
  const val = (flag) => {
    const i = argv.indexOf(flag);
    if (i === -1) return { present: false };
    const v = argv[i + 1];
    if (!v || v.startsWith('--')) return { present: true, missing: true };
    return { present: true, value: v };
  };
  const group = val('--group');
  const only = val('--only');
  const shard = val('--shard');
  for (const [flag, v] of [['--group', group], ['--only', only], ['--shard', shard]]) {
    if (v.missing) return { error: `${flag} needs a value` };
  }
  if (group.present && only.present) return { error: '--group and --only are mutually exclusive' };

  let shardSpec = null;
  if (shard.present) {
    const m = /^(\d+)\/(\d+)$/.exec(shard.value);
    if (!m || Number(m[1]) < 1 || Number(m[2]) < 1 || Number(m[1]) > Number(m[2])) {
      return { error: `--shard "${shard.value}" is invalid: expected i/N with 1 <= i <= N` };
    }
    shardSpec = shard.value;
  }

  const planned = plannedCheckIds({ fast });
  let ids = planned;
  let label = null;
  if (group.present) {
    const groups = resolveGroups();
    if (!Object.hasOwn(groups, group.value)) {
      return { error: `unknown group "${group.value}"; groups are: ${groupNames().join(', ')}` };
    }
    ids = groups[group.value].filter((id) => planned.includes(id));
    label = `group ${group.value}`;
  } else if (only.present) {
    const wanted = only.value.split(',').map((x) => x.trim()).filter(Boolean);
    const known = new Set(CHECKS.map((c) => c.id));
    const unknown = wanted.filter((id) => !known.has(id));
    if (!wanted.length || unknown.length) {
      return { error: `unknown check id(s) for --only: ${unknown.join(', ') || '(none given)'}` };
    }
    ids = planned.filter((id) => wanted.includes(id));
    label = `only ${wanted.join(',')}`;
  }
  if (shardSpec) {
    if (!ids.includes('test-suite')) {
      return { error: '--shard only applies to the test-suite check, which this selection does not run' };
    }
    label = `${label ? `${label}, ` : ''}shard ${shardSpec}`;
  }
  if (!ids.length) return { error: 'the selection matches no planned check; refusing to report a vacuous pass' };
  const partial = ids.length !== planned.length || Boolean(shardSpec);
  return { ids, label, shard: shardSpec, partial };
}

function result(errors = [], warnings = [], extra = {}) {
  return { ok: errors.length === 0, errors, warnings, ...extra };
}

// ---------------------------------------------------------------------------
// Pure decision functions. No I/O — every one takes already-gathered facts so
// the tests can exercise them on constructed inputs.
// ---------------------------------------------------------------------------

/** Check 1. `porcelain` is the raw output of `git status --porcelain`. */
export function evaluateWorkingTree({ porcelain }) {
  if (porcelain == null) {
    return result(['Could not read git status — cannot prove the working tree is clean. ' +
      'Run this from inside the repository.']);
  }
  const entries = porcelain.split('\n').map(l => l.trim()).filter(Boolean);
  if (entries.length === 0) return result();
  const shown = entries.slice(0, 20).join('\n    ');
  const more = entries.length > 20 ? `\n    … and ${entries.length - 20} more` : '';
  return result([
    `Working tree is not clean (${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}):` +
    `\n    ${shown}${more}\n  Remedy: commit or stash every change (including untracked files) ` +
    'before publishing.',
  ]);
}

const VERSION_RE = String.raw`(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`;

/**
 * Pull every version string a given release artifact is supposed to carry.
 * Deliberately per-file regexes rather than a generic scan: a generic
 * "find something that looks like a semver" would match dependency ranges in
 * package.json and badge URLs for unrelated things in README.md, and would
 * then report agreement or disagreement about the wrong strings.
 */
export function extractVersionsFromSource(label, content) {
  if (typeof content !== 'string') return [];
  const all = (re) => [...content.matchAll(re)].map(m => m[1]);
  if (label.endsWith('package.json') || label.endsWith('plugin.json') || label.endsWith('gemini-extension.json')) {
    // Top-level "version" only — the first occurrence in these files.
    const m = content.match(new RegExp(String.raw`"version"\s*:\s*"${VERSION_RE}"`));
    return m ? [m[1]] : [];
  }
  if (label.endsWith('marketplace.json')) {
    // Every occurrence: this file carries the version twice (metadata block
    // and plugin entry) and bumping only one is the classic half-done bump.
    return all(new RegExp(String.raw`"version"\s*:\s*"${VERSION_RE}"`, 'g'));
  }
  if (label.endsWith('CLAUDE.md')) {
    return all(new RegExp(String.raw`\*\*Version:\*\*\s*${VERSION_RE}`, 'g'));
  }
  if (label.endsWith('README.md')) {
    return all(new RegExp(String.raw`badge/version-${VERSION_RE}-`, 'g'));
  }
  return [];
}

/** Check 2. `sources` is [{ label, versions: string[] }]. */
export function evaluateVersionConsistency({ sources }) {
  const errors = [];
  const missing = sources.filter(s => !s.versions || s.versions.length === 0);
  for (const s of missing) {
    errors.push(`${s.label}: no version string found — cannot confirm it was bumped. ` +
      'Remedy: make sure the file still carries the version in the expected form.');
  }
  const present = sources.filter(s => s.versions && s.versions.length > 0);
  if (present.length === 0) {
    return result(errors.concat('No version string found in any release artifact.'), [], { version: null });
  }
  // The canonical version is scanner/package.json's when available — that is
  // what npm actually publishes; everything else must agree with it.
  const canonicalSource = present.find(s => s.label.endsWith('scanner/package.json')) || present[0];
  const canonical = canonicalSource.versions[0];
  for (const s of present) {
    for (const v of s.versions) {
      if (v !== canonical) {
        errors.push(`${s.label}: version ${v} does not match ${canonicalSource.label}'s ` +
          `${canonical}. Remedy: bump every occurrence to ${canonical}.`);
      }
    }
  }
  return result(errors, [], { version: canonical });
}

/**
 * Check 3. `changelogs` is [{ label, content: string|null, remedy? }].
 *
 * Both changelogs are checked, but they are not the same kind of file: the
 * root one is authored by a human, the scanner-side one is a generated copy
 * that ships inside the published package. A missing entry in the generated
 * copy means the copy is stale, not that someone forgot to write release
 * notes — so callers can supply a per-file `remedy` that says so.
 */
/**
 * A release must not read as complete when requirements are open. `status` is docs/completion-status.json (null when absent).
 * Pure: the caller supplies the texts.
 */
export function evaluateCompletionDeclared({ version, status, changelogText, readmeText }) {
  if (!status || !Array.isArray(status.remaining) || status.remaining.length === 0) return result();
  const errors = [];
  const ids = status.remaining.map((r) => r.id);
  const m = new RegExp(`^## ${String(version).replace(/\./g, '\\.')}\\b[\\s\\S]*?(?=^## |$(?![\\s\\S]))`, 'm').exec(changelogText || '');
  const section = m ? m[0] : '';
  if (!section) errors.push(`CHANGELOG.md has no section for ${version}`);
  else {
    if (!/Partial release/.test(section)) errors.push(`${ids.length} requirement(s) are unverified (${ids.join(', ')}) but the ${version} changelog section does not say "Partial release"`);
    for (const id of ids) if (!section.includes(id)) errors.push(`the ${version} changelog section does not name the open requirement ${id}`);
  }
  for (const id of ids) if (!(readmeText || '').includes(id)) errors.push(`README.md does not name the open requirement ${id} (run node scripts/render-language-docs.mjs)`);
  return result(errors);
}

export function evaluateChangelogs({ version, changelogs }) {
  const errors = [];
  // Anchored heading match with a boundary so 1.2.30 never satisfies 1.2.3.
  const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const headingRe = new RegExp(String.raw`^#{1,3}\s+v?${escaped}(?![\w.-])`, 'm');
  const defaultRemedy = `add a \`## ${version} — <title>\` section describing this release.`;
  for (const { label, content, remedy } of changelogs) {
    if (typeof content !== 'string') {
      errors.push(`${label} is missing or unreadable — cannot confirm a ${version} entry exists. ` +
        `Remedy: ${remedy || defaultRemedy}`);
      continue;
    }
    if (!headingRe.test(content)) {
      errors.push(`${label} has no entry for ${version}. Remedy: ${remedy || defaultRemedy}`);
    }
  }
  return result(errors);
}

/** Check 4. Both hashes are hex strings, or null when unreadable. */
export function evaluateBundleIntegrity({ bundleSha256, sidecarSha256 }) {
  const errors = [];
  if (!bundleSha256) {
    errors.push('scanner/dist/agentic-security.mjs is missing or unreadable. ' +
      'Remedy: run `npm run build` in scanner/.');
  }
  if (!sidecarSha256) {
    errors.push('scanner/dist/agentic-security.mjs.sha256 is missing or unreadable — the ' +
      'bundle cannot be verified. Remedy: run `npm run build` in scanner/ and commit the sidecar.');
  }
  if (bundleSha256 && sidecarSha256 && bundleSha256 !== sidecarSha256) {
    errors.push('Bundle does not match its SHA-256 sidecar.\n' +
      `    bundle : ${bundleSha256}\n    sidecar: ${sidecarSha256}\n` +
      '  Remedy: run `npm run build` in scanner/ and commit both files together.');
  }
  return result(errors);
}

/** Check 9. `remoteRefsContainingHead` from `git branch -r --contains HEAD`. */
export function evaluateHeadPushed({ headSha, remoteRefsContainingHead }) {
  if (!Array.isArray(remoteRefsContainingHead)) {
    return result([`Could not determine whether ${headSha} exists on any remote branch. ` +
      'Remedy: check `git fetch origin` succeeds, then re-run.']);
  }
  if (remoteRefsContainingHead.includes('origin/main')) return result();
  const seen = remoteRefsContainingHead.length
    ? ` (it is on: ${remoteRefsContainingHead.join(', ')})`
    : '';
  return result([
    `HEAD ${headSha} is not on origin/main${seen} — publishing would ship code that is ` +
    'not public. Remedy: push the release commit to origin/main first.',
  ]);
}

const CI_OK_CONCLUSIONS = new Set(['success', 'neutral', 'skipped']);

/**
 * Split observed check runs into the ones that gate a release and the ones that
 * only inform it. PRD R2.
 *
 * An UNCLASSIFIED check is treated as BLOCKING and warned about. A job nobody
 * tiered is a job nobody thought about, and defaulting it to informational would
 * let a new correctness gate silently stop gating.
 */
// Reuse the existing per-install HMAC rather than a second key mechanism. An
// unsignable cache is unverifiable, loadCache discards it, and the checks run.
function cacheSigner(body) { try { return signLastScan(body); } catch { return null; } }

/** The committed blocking/informational classification (PRD R2), or null. */
export const CHECK_TIERS_FILE = '.github/required-checks.json';

export function readCheckTiers(repo = REPO) {
  // A missing or unreadable file yields null, and `evaluateRemoteCi` then treats
  // every check as blocking — the pre-R2 behaviour. Failing to read the tier
  // list must never be the thing that lets a red check through.
  const raw = readTextOrNull(path.join(repo, CHECK_TIERS_FILE));
  if (!raw) return null;
  try {
    const doc = JSON.parse(raw);
    if (!Array.isArray(doc?.blocking) || !Array.isArray(doc?.informational)) return null;
    // `self` is optional: an older file without it simply classifies nothing as self.
    return { blocking: doc.blocking, informational: doc.informational, self: Array.isArray(doc.self) ? doc.self : [] };
  } catch {
    return null;
  }
}

export function partitionCheckRuns(checkRuns, tiers) {
  const blocking = new Set(tiers?.blocking || []);
  const informational = new Set(tiers?.informational || []);
  // The job the gate is running inside. Excluded entirely — see `self` in
  // .github/required-checks.json. It cannot report a conclusion until the gate
  // it contains has already passed, so requiring it is a deadlock, and trusting
  // it would be trusting a check that has not run.
  const selfChecks = new Set(tiers?.self || []);
  const out = { blocking: [], informational: [], unclassified: [], self: [] };
  for (const run of checkRuns || []) {
    if (selfChecks.has(run.name)) out.self.push(run);
    else if (informational.has(run.name)) out.informational.push(run);
    else if (blocking.has(run.name)) out.blocking.push(run);
    else { out.unclassified.push(run); out.blocking.push(run); }
  }
  return out;
}

/**
 * Check 10. `checkRuns` is [{ name, status, conclusion }] or null if unread.
 *
 * `tiers` is the parsed .github/required-checks.json. When it is absent every
 * check is blocking — the pre-R2 behaviour — because a missing classification
 * must never be the thing that lets a red check through.
 */
export function evaluateRemoteCi({
  cliAvailable, authenticated, checkRuns, allowUnverified = false, headSha = 'HEAD', tiers = null,
}) {
  const errors = [];
  const warnings = [];
  const unverifiable = (reason) => {
    if (allowUnverified) {
      warnings.push(`UNVERIFIED: hosted CI status for ${headSha} was NOT checked (${reason}). ` +
        'This release is being published without proof that it builds anywhere but this machine.');
      return result([], warnings);
    }
    return result([`${reason} — hosted CI for ${headSha} is unverifiable, which is not the same ` +
      'as green. Remedy: authenticate the forge CLI, or pass --allow-unverified-ci deliberately.'], warnings);
  };

  if (!cliAvailable) return unverifiable('the forge CLI is not available on PATH');
  if (!authenticated) return unverifiable('the forge CLI is not authenticated');
  if (!Array.isArray(checkRuns)) return unverifiable('the hosted CI status query failed');

  if (checkRuns.length === 0) {
    errors.push(`No hosted CI check runs were reported for ${headSha} — nothing has proved this ` +
      'commit green. Remedy: confirm the workflows triggered for this commit.');
  }
  const split = partitionCheckRuns(checkRuns, tiers);

  for (const run of split.unclassified) {
    warnings.push(`Hosted CI check "${run.name}" is not listed in .github/required-checks.json ` +
      'and is being treated as BLOCKING. Classify it deliberately.');
  }

  for (const run of split.blocking) {
    if (run.status !== 'completed') {
      errors.push(`Hosted CI check "${run.name}" is ${run.status}, not completed. ` +
        'Remedy: wait for it to finish.');
    } else if (!CI_OK_CONCLUSIONS.has(run.conclusion)) {
      errors.push(`Hosted CI check "${run.name}" concluded ${run.conclusion}. ` +
        'Remedy: fix it and push again before publishing.');
    }
  }

  // Informational checks never gate — but a FAILING one is reported loudly. The
  // point of the tier is that a trend job does not block a release, not that a
  // trend regression becomes invisible. Pending ones are silent: waiting on a
  // benchmark is the normal state and is exactly what R2 stopped blocking on.
  for (const run of split.informational) {
    if (run.status === 'completed' && !CI_OK_CONCLUSIONS.has(run.conclusion)) {
      warnings.push(`INFORMATIONAL hosted CI check "${run.name}" concluded ${run.conclusion}. ` +
        'This does NOT block the release, but it is a trend regression — investigate it.');
    }
  }

  return result(errors, warnings);
}

/** Checks 6-8: a gated command is satisfied only by a literal exit code 0. */
export function evaluateCommandGate({ label, exitCode }) {
  if (exitCode === 0) return result();
  if (exitCode == null) {
    return result([`\`${label}\` could not be run — an unrunnable gate is not a passing gate.`]);
  }
  return result([`\`${label}\` exited ${exitCode}.`]);
}

/**
 * Check: run-attestation compute/verify round-trip. Pure — no I/O, no
 * network, no filesystem. A synthetic finding set stands in for a real
 * scan; the point is proving the SUBSYSTEM (canonicalisation + digest +
 * comparison) still agrees with itself, not attesting anything about this
 * repository's own findings (that already happens on every real scan).
 */
export function evaluateAttestationSelfCheck() {
  const base = { engineVersion: 'release-check-selftest', rulesetVersion: '1', bundleSha: 'deadbeef' };
  const findings = [
    { id: 'a', severity: 'high', file: 'x.js', line: 1, cwe: 'CWE-89', vuln: 'SQLi' },
    { id: 'b', severity: 'medium', file: 'y.js', line: 2, cwe: 'CWE-79', vuln: 'XSS' },
  ];
  const attestation = computeRunAttestation({ ...base, findings });
  const roundTrip = verifyRunAttestation(attestation, { ...base, findings });
  if (!roundTrip.ok) {
    return result([`compute→verify round-trip failed on an unmodified finding set: ${roundTrip.reason}`]);
  }
  // The other direction: a changed finding set MUST fail verification, or
  // the digest isn't actually binding to finding content.
  const mutated = verifyRunAttestation(attestation, { ...base, findings: findings.slice(0, 1) });
  if (mutated.ok) {
    return result(['verifyRunAttestation accepted a mutated finding set against an unchanged ' +
      'attestation — the digest is not actually binding to finding content.']);
  }
  return result();
}

// ---------------------------------------------------------------------------
// I/O layer. Everything below gathers facts and hands them to the functions
// above; none of it makes a pass/fail decision of its own.
// ---------------------------------------------------------------------------

function readTextOrNull(absPath) {
  // Single read inside try/catch rather than existsSync-then-read: the
  // check-then-use form is a TOCTOU pattern this project's own engine flags.
  try {
    return fs.readFileSync(absPath, 'utf8');
  } catch {
    return null;
  }
}

function readBytesOrNull(absPath) {
  try {
    return fs.readFileSync(absPath);
  } catch {
    return null;
  }
}

function run(cmd, args, opts = {}) {
  // Always argv-array, never a shell string.
  const r = spawnSync(cmd, args, { encoding: 'utf8', shell: false, ...opts });
  return { status: r.error ? null : r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function gitOut(args) {
  const r = run('git', args, { cwd: REPO });
  return r.status === 0 ? r.stdout : null;
}

const VERSION_FILES = [
  'scanner/package.json',
  '.claude-plugin/plugin.json',
  '.claude-plugin/marketplace.json',
  'gemini-extension.json',
  'CLAUDE.md',
  'README.md',
];

// scanner/CHANGELOG.md is gitignored and regenerated from the root copy by
// scripts/sync-scanner-changelog.mjs — it is the copy that actually ships
// inside the published package, which is exactly why it is checked here too:
// publishing a package whose bundled release notes predate the release is
// the same class of half-done release as a half-bumped version string.
// prepublishOnly runs the sync BEFORE this gate so the check sees the fresh
// copy; if it is stale here, the sync did not run.
const CHANGELOG_FILES = [
  { rel: 'CHANGELOG.md' },
  {
    rel: 'scanner/CHANGELOG.md',
    remedy: 'this file is generated — run `node scripts/sync-scanner-changelog.mjs` ' +
      '(after adding the entry to the root CHANGELOG.md).',
  },
];

function gatherVersionSources() {
  return VERSION_FILES.map(rel => ({
    label: rel,
    versions: extractVersionsFromSource(rel, readTextOrNull(path.join(REPO, rel))),
  }));
}

function bundleHashes() {
  const bundle = readBytesOrNull(path.join(SCANNER, 'dist', 'agentic-security.mjs'));
  const sidecarRaw = readTextOrNull(path.join(SCANNER, 'dist', 'agentic-security.mjs.sha256'));
  return {
    bundleSha256: bundle ? crypto.createHash('sha256').update(bundle).digest('hex') : null,
    sidecarSha256: sidecarRaw ? (sidecarRaw.trim().split(/\s+/)[0] || null) : null,
  };
}

export function scorecardFacts(version) {
  const scorecardRaw = readTextOrNull(path.join(REPO, 'docs', 'scorecard.json'));
  let scorecardJson = null;
  try {
    scorecardJson = scorecardRaw === null ? null : JSON.parse(scorecardRaw);
  } catch {
    scorecardJson = null;
  }
  return {
    pkgVersion: version,
    scorecardJson,
    scorecardMdPresent: readTextOrNull(path.join(REPO, 'docs', 'SCORECARD.md')) !== null,
    currentBundleSha256: bundleHashes().sidecarSha256,
    // M3: without this the corpus-population drift check inside
    // evaluateScorecardFreshness is silently inert on the release path —
    // it only ever fired via scorecard-check.mjs's own standalone CLI,
    // which nothing on the publish path invokes.
    actualCorpusEntries: countCorpusEntries(REPO),
  };
}

function runNpmGate(script, env = {}) {
  const label = `npm run ${script}`;
  process.stderr.write(`  running ${label} (this is one of the slow gates) …\n`);
  const r = run('npm', ['run', script], { cwd: SCANNER, stdio: 'inherit', env: { ...process.env, ...env } });
  return evaluateCommandGate({ label, exitCode: r.status });
}

function remoteRefsContainingHead() {
  const out = gitOut(['branch', '-r', '--contains', 'HEAD']);
  if (out === null) return null;
  return out.split('\n')
    .map(l => l.trim().replace(/^\*\s*/, ''))
    .filter(Boolean)
    .filter(l => !l.includes('->'));
}

function remoteCiFacts(headSha) {
  const version = run(FORGE_CLI, ['--version']);
  if (version.status !== 0) return { cliAvailable: false, authenticated: false, checkRuns: null };
  const auth = run(FORGE_CLI, ['auth', 'status']);
  if (auth.status !== 0) return { cliAvailable: true, authenticated: false, checkRuns: null };
  const api = run(FORGE_CLI, [
    'api', `repos/{owner}/{repo}/commits/${headSha}/check-runs`,
    '--jq', '[.check_runs[] | {name, status, conclusion}]',
  ], { cwd: REPO });
  if (api.status !== 0) return { cliAvailable: true, authenticated: true, checkRuns: null };
  try {
    const parsed = JSON.parse(api.stdout);
    return {
      cliAvailable: true,
      authenticated: true,
      checkRuns: Array.isArray(parsed) ? parsed : null,
    };
  } catch {
    return { cliAvailable: true, authenticated: true, checkRuns: null };
  }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

// `overrides` maps a check id to a replacement evaluator and `out` is the report
// stream; both exist so the tests can drive a real run (selection, labelling,
// exit code) without spawning the slow gates. The CLI passes neither.
export function main(argv, { overrides = {}, out = process.stderr } = {}) {
  const fast = argv.includes('--fast');
  const allowUnverified = argv.includes('--allow-unverified-ci');
  const selection = parseSelection(argv, { fast });
  if (selection.error) {
    out.write(`release-check: ${selection.error}\n`);
    return 2;
  }
  const planned = new Set(selection.ids);
  const fullPlanned = plannedCheckIds({ fast });
  const partial = selection.partial;
  const shard = selection.shard;

  const headSha = (gitOut(['rev-parse', 'HEAD']) || '').trim() || 'unknown';
  const versionSources = gatherVersionSources();
  const versionResult = evaluateVersionConsistency({ sources: versionSources });
  const version = versionResult.version;

  // PRD R1 — this gate is the CONSUMER of the verdict cache. The pre-push gate
  // ran these same three checks on this same commit minutes ago; re-deriving
  // them is ~290s of work on byte-identical inputs. See
  // scripts/gate-verdict-cache.mjs for the key and the safety rules.
  const cacheCtx = (() => {
    if (cachingDisabled(argv)) return { enabled: false, records: {}, key: null, why: '--no-cache' };
    const parts = gatherKeyParts({ repo: REPO });
    const key = computeVerdictKey(parts);
    if (!key) return { enabled: false, records: {}, key: null, why: 'a cache-key input could not be read' };
    const cache = loadCache(REPO, { signer: cacheSigner });
    return { enabled: true, key, commitSha: parts.commitSha, records: cache.records, rejected: cache.rejected };
  })();
  // NOTE: deliberately NOT written here. `out` is initialised further down, and
  // this line only executes when the cache is rejected — so a straight
  // out.write() at this point was a latent ReferenceError that fired only on the
  // tamper/corruption path, i.e. exactly the path that has to work. Deferred to
  // the reporting section below.

  // Only the three slow, inputs-determined gates. Everything else is either
  // sub-second or inspects live state that is not in the key.
  const CACHEABLE = new Set(['test-suite', 'corpus-gate', 'self-scan-gate']);
  const cachedProvenance = new Map();

  const results = new Map();
  const evaluate = (id, realFn) => {
    if (!planned.has(id)) return;
    const fn = overrides[id] || realFn;
    // A sharded test-suite verdict covers a fraction of the suite, so it must
    // neither be read from nor written to the cache (it would otherwise be
    // recorded as the whole suite passing for this key).
    const cacheable = CACHEABLE.has(id) && !(id === 'test-suite' && shard);
    if (cacheCtx.enabled && cacheable) {
      const rec = cacheCtx.records[id];
      const verdict = evaluateCachedVerdict({ record: rec, key: cacheCtx.key, checkId: id });
      if (verdict.usable) {
        cachedProvenance.set(id, renderProvenance(rec));
        results.set(id, { ok: true, errors: [], warnings: [] });
        return;
      }
    }
    const startedCheck = Date.now();
    const r = fn();
    if (r?.ok && cacheCtx.enabled && cacheable) {
      recordVerdict(REPO, {
        checkId: id, key: cacheCtx.key, commitSha: cacheCtx.commitSha,
        by: 'release-check', durationMs: Date.now() - startedCheck,
      }, { signer: cacheSigner });
    }
    results.set(id, r);
  };

  evaluate('working-tree-clean', () =>
    evaluateWorkingTree({ porcelain: gitOut(['status', '--porcelain']) }));

  evaluate('version-consistency', () => versionResult);

  evaluate('changelog-entry', () => {
    if (!version) {
      return result(['Cannot check changelog entries: no version could be determined. ' +
        'Remedy: fix the version-consistency check first.']);
    }
    return evaluateChangelogs({
      version,
      changelogs: CHANGELOG_FILES.map(({ rel, remedy }) => ({
        label: rel,
        remedy,
        content: readTextOrNull(path.join(REPO, rel)),
      })),
    });
  });

  evaluate('completion-declared', () => {
    if (!version) return result(['Cannot check the completion declaration: no version could be determined.']);
    let status = null;
    try { status = JSON.parse(readTextOrNull(path.join(REPO, 'docs', 'completion-status.json')) || 'null'); } catch { return result(['docs/completion-status.json is not valid JSON']); }
    return evaluateCompletionDeclared({ version, status, changelogText: readTextOrNull(path.join(REPO, 'CHANGELOG.md')), readmeText: readTextOrNull(path.join(REPO, 'README.md')) });
  });

  evaluate('doc-links', () => {
    const r = run('node', [path.join(REPO, 'scripts', 'check-doc-drift.mjs'), '--gate'], { cwd: REPO });
    return evaluateCommandGate({ label: 'node scripts/check-doc-drift.mjs --gate', exitCode: r.status });
  });

  evaluate('bundle-integrity', () => evaluateBundleIntegrity(bundleHashes()));

  evaluate('scorecard-freshness', () => {
    if (!version) return result(['Cannot check the scorecard: no version could be determined.']);
    return evaluateScorecardFreshness(scorecardFacts(version));
  });

  evaluate('attestation-self-check', () => evaluateAttestationSelfCheck());

  evaluate('nist-catalog-freshness', () => {
    // Every generated control catalog, not just the first one. Each exits 0 when
    // the committed catalog matches its source, 1 when stale, and 2 when the
    // check could not run at all — an unverifiable check is a failure, not a
    // skip, so evaluateCommandGate treats any non-zero as failing.
    const catalogs = [
      'scripts/nist-compliance/build-catalog.py',
      'scripts/nist-800-171/build-catalog.py',
    ];
    for (const rel of catalogs) {
      const r = run('python3', [path.join(REPO, rel), '--check'], { cwd: REPO });
      const verdict = evaluateCommandGate({ label: `python3 ${rel} --check`, exitCode: r.status });
      if (!verdict.ok) return verdict;
    }
    return evaluateCommandGate({ label: `${catalogs.length} catalogs checked`, exitCode: 0 });
  });

  evaluate('nist-800-171-labels', () => {
    const r = run('node', [path.join(REPO, 'bench', 'nist-800-171-labels', 'check.mjs')], { cwd: REPO });
    return evaluateCommandGate({ label: 'node bench/nist-800-171-labels/check.mjs', exitCode: r.status });
  });

  evaluate('package-contents', () => runPackageContentsCheck(REPO));

  evaluate('test-suite', () => runNpmGate('test', shard ? { AGENTIC_SECURITY_TEST_SHARD: shard } : {}));
  evaluate('corpus-gate', () => runNpmGate('bench:cve-replay:check'));
  evaluate('self-scan-gate', () => runNpmGate('bench:self-scan:check'));
  evaluate('mutation-gate', () => runNpmGate('bench:mutation:check'));
  evaluate('protection-verdict-gate', () => runNpmGate('bench:protection-verdict:check'));
  evaluate('layer-recall-gate', () => runNpmGate('bench:layer-recall:check'));
  evaluate('language-support-gate', () => runNpmGate('bench:language-support:check'));
  evaluate('ttff-gate', () => runNpmGate('bench:ttff:check'));
  evaluate('memory-gate', () => runNpmGate('bench:memory:check'));
  evaluate('provenance-gate', () => runNpmGate('bench:provenance:check'));
  evaluate('verification-conformance-gate', () => runNpmGate('verification:conformance:check'));
  evaluate('release-closure-gate', () => {
    const script = closureGateScript();
    const r = runNpmGate(script);
    return script === 'release:closure:static' ? { ...r, warnings: [...(r.warnings || []), HOSTED_CLOSURE_NOTE] } : r;
  });

  evaluate('calibration-holdout', () => {
    const r = runCalibrationHoldoutCheck(REPO);
    return { ok: r.ok, errors: r.ok ? [] : [r.detail], warnings: r.warnings || [], detail: r.detail };
  });

  evaluate('independent-population-gate', () => {
    const r = runIndependentPopulationGate(REPO);
    return { ok: r.ok, errors: r.ok ? [] : [r.detail], warnings: r.warnings || [], detail: r.detail };
  });

  evaluate('head-pushed', () =>
    evaluateHeadPushed({ headSha, remoteRefsContainingHead: remoteRefsContainingHead() }));

  evaluate('remote-ci-green', () =>
    evaluateRemoteCi({ ...remoteCiFacts(headSha), allowUnverified, headSha, tiers: readCheckTiers() }));

  evaluate('dependency-currency', () => {
    process.stderr.write('  querying the package registry for advisories and newer ' +
      'versions (this is one of the slow gates) …\n');
    return runDependencyCurrencyCheck(REPO);
  });

  // ---- summary ----
  out.write(`\n${'='.repeat(64)}\n`);
  out.write(`Release gate — version ${version || '(undetermined)'} @ ${headSha.slice(0, 12)}` +
    `${fast ? '  [--fast: slow gates skipped]' : ''}\n`);
  if (partial) {
    out.write(`PARTIAL RUN, NOT THE FULL GATE: ${selection.label || 'selection'}: ` +
      `${planned.size} of ${CHECKS.length} checks\n`);
  }
  out.write(`${'='.repeat(64)}\n`);

  if (cacheCtx.rejected) {
    out.write(`  (verdict cache discarded: ${cacheCtx.rejected} — every check was run)\n`);
  }

  const failed = [];
  for (const check of CHECKS) {
    const r = results.get(check.id);
    if (!r) {
      // Outside the selection of a partial run: another job owns it, and the
      // header already says how many checks this run covers.
      if (partial && fullPlanned.includes(check.id)) continue;
      out.write(`SKIP  ${check.title}  (--fast)\n`);
      continue;
    }
    out.write(`${r.ok ? 'PASS' : 'FAIL'}  ${check.title}\n`);
    // A reused verdict always says so. Skipping work silently would make a
    // green gate indistinguishable from a gate that never ran.
    if (cachedProvenance.has(check.id)) out.write(`      ↳ ${cachedProvenance.get(check.id)}\n`);
    for (const w of r.warnings || []) out.write(`      ⚠ ${w}\n`);
    for (const e of r.errors || []) out.write(`      ✗ ${e}\n`);
    if (!r.ok) failed.push({ ...check, errors: r.errors || [] });
  }

  const unverifiedWarnings = [...results.values()]
    .flatMap(r => r.warnings || []).filter(w => w.startsWith('UNVERIFIED'));
  if (unverifiedWarnings.length) {
    out.write(`\n${'!'.repeat(64)}\n`);
    out.write('!! RELEASING WITH AN UNVERIFIED CHECK — --allow-unverified-ci was passed.\n');
    for (const w of unverifiedWarnings) out.write(`!! ${w}\n`);
    out.write(`${'!'.repeat(64)}\n`);
  }

  if (failed.length === 0 && partial) {
    // Deliberately a different sentence from the full-gate line below: a partial
    // pass proves only its own checks, and must never be mistaken for the whole.
    out.write(`\n✓ Partial run passed (${selection.label || 'selection'}: ${results.size} of ${CHECKS.length} checks). ` +
      'This is NOT the full release gate; every other group must pass too.\n');
    return 0;
  }

  if (failed.length === 0) {
    out.write(`\n✓ Release gate passed (${results.size}/${CHECKS.length} checks run).` +
      `${fast ? ' NOTE: --fast was used; this is not a publish-grade run.' : ''}\n`);
    return 0;
  }

  out.write(`\n✗ Release gate FAILED${partial ? ` (partial run: ${selection.label || 'selection'})` : ''} — ${failed.length} check(s) did not pass:\n`);
  // Repeat WHY each check failed, not just what to do about it. The detail is
  // printed inline above, but npm surfaces only the tail of a failed
  // prepublishOnly, so a summary carrying "commit your changes" without naming
  // the offending paths sends the reader hunting for a dirty file they cannot
  // see. Indent-preserving: the evaluators embed newlines in their messages.
  for (const c of failed) {
    out.write(`   · ${c.title}\n`);
    const errors = c.errors || [];
    for (const e of errors) out.write(`     ${String(e).replace(/\n/g, '\n     ')}\n`);
    // Several evaluators already end their message with their own "Remedy:"
    // line. Printing the registry's remedy underneath it too says the same
    // thing twice, which reads like two different instructions.
    if (!errors.some(e => /\bRemedy:/i.test(String(e)))) {
      out.write(`     remedy: ${c.remedy}\n`);
    }
  }
  return 1;
}

// Only gate when invoked directly — importing this module (as the test suite
// does, to exercise the decision functions) must not run commands or exit.
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.exit(main(process.argv.slice(2)));
