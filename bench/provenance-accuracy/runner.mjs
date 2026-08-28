// Known-origin accuracy corpus + gate.
//
// WHAT THIS MEASURES. The Finding Provenance PRD's own Success Metrics table
// (docs, section 10) names a launch target this repository has never actually
// measured before this bench existed: "Known-origin accuracy >=98% exact
// commit accuracy on a labeled historical fixture corpus." Every other
// provenance test asks "does the pipeline return SOME terminal status
// without throwing" (see `TERMINAL_STATUSES` in
// scanner/test/dataflow/provenance-pipeline-integration.test.js) or exercises
// one module in isolation. None of them assert the actual commit SHA a real
// end-to-end scan attributes is the SHA that genuinely introduced the finding.
// This corpus is a labeled answer key for that specific claim.
//
// HOW IT SCORES. Each fixture in fixtures/ builds a small, self-contained git
// history via `createGitFixture()` — the same helper the provenance unit-test
// suite uses pervasively — with a documented TRUE origin commit (or, for the
// two classes where "true origin" is not the right question at all, a
// documented terminal status instead — see EXPECT_KINDS below). Every fixture
// is scored through the REAL `runScan` -> `annotateGitProvenance` pipeline,
// never a mocked resolver: this is what "exercises the actual shipped code
// path" means in the task brief, and it is why a fixture failing here is
// evidence about the shipped engine, not about a test double.
//
// EXIT-CODE CONTRACT. Same shape as this repo's other baseline-gated
// benches — bench/layer-recall/runner.mjs's plain 0/1 for clean/drift, widened
// with bench/cve-replay/runner.mjs's third class (that file's own
// `ENV_ERROR_EXIT`) for "this fixture could not be scored at all", which is a
// DIFFERENT fact than "the engine got the wrong answer" and must never be
// silently folded into either a pass or a regression:
//   0 — clean (matches the committed baseline, or --update-baseline wrote one)
//   1 — accuracy drift: a previously-passing fixture now fails, a new fixture
//       was added already failing, or a baselined fixture disappeared
//   2 — usage error (bad flags, or --check with no baseline on disk yet)
//   3 — environment error: a fixture's own build() threw, or the scan/subprocess
//       produced zero or more-than-one matching finding — the fixture is
//       UNSCOREABLE this run, which is not the same claim as "wrong answer"
//
// GATING PHILOSOPHY: a FLOOR, not layer-recall's equality gate. layer-recall
// deliberately fails on improvement too, and says exactly why in its own
// header: a stale published table sat wrong for weeks because nothing ever
// forced a human to notice the number had moved. That risk is specific to a
// hand-maintained prose table (docs/METRICS.md) that can silently disagree
// with a live number. This corpus has no such sibling document — its only
// published number is the one --check itself computes — so there is nothing
// for an unrecorded improvement to leave stale. Regression-only floor gating
// is what every OTHER baselined bench in this repo does (cve-replay, ttff,
// memory, the provenance-overhead bench), and per-fixture drift classification
// (REGRESSED / NEW ENTRY FAILING / BASELINE ENTRY MISSING) is lifted directly
// from bench/cve-replay/runner.mjs's own `--check-baseline` logic, reused
// rather than reinvented.
//
// Usage:
//   node runner.mjs                    # human-readable run, always exits 0
//   node runner.mjs --check            # gate (see exit codes above)
//   node runner.mjs --update-baseline  # record current per-fixture verdicts

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as cp from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');
const FIXTURES_DIR = path.join(HERE, 'fixtures');
const BASELINE_PATH = path.join(HERE, 'BASELINE.json');
const SCA_HELPER = path.join(HERE, 'sca-scan-helper.mjs');

const USAGE_ERROR_EXIT = 2;
const ENV_ERROR_EXIT = 3;

const { createGitFixture } = await import(path.join(REPO, 'scanner', 'test', 'helpers', 'build-git-fixture.js'));
const { seedAdvisory } = await import(path.join(REPO, 'scanner', 'test', 'helpers', 'seed-osv-cache.js'));
const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
const { disableStateWrites } = await import(path.join(REPO, 'bench', '_lib', 'tree-integrity.mjs'));

await disableStateWrites();

const SAST_CHANNELS = ['findings', 'secrets', 'logicVulns'];

/** The scoring modes a fixture's `expect` field can declare. */
const EXPECT_KINDS = new Set(['commit', 'partial', 'uncommitted']);

function loadFixtureFiles() {
  return fs.readdirSync(FIXTURES_DIR)
    .filter((f) => f.endsWith('.mjs'))
    .sort()
    .map((f) => path.join(FIXTURES_DIR, f));
}

function sastLocatorMatches(f, locator) {
  if (locator.file != null && f.file !== locator.file) return false;
  if (locator.line != null && f.line !== locator.line && f.sink?.line !== locator.line) return false;
  if (locator.cwe != null && f.cwe !== locator.cwe) return false;
  if (locator.vuln != null) {
    const ok = locator.vuln instanceof RegExp ? locator.vuln.test(f.vuln || '') : f.vuln === locator.vuln;
    if (!ok) return false;
  }
  return true;
}

function scaLocatorMatches(e, locator) {
  if (e.type !== 'vulnerable_dep') return false;
  if (locator.name != null && e.name !== locator.name) return false;
  if (locator.isDirect != null && e.isDirect !== locator.isDirect) return false;
  return true;
}

/**
 * Score one resolved finding/entry against its fixture's declared expectation.
 * `expect: 'commit'` requires BOTH a `complete` terminal status AND an exact
 * SHA match — a lucky commit match under a `partial`/uncertain status is not
 * "exact commit accuracy" in the PRD's sense, it is a coincidence the engine
 * itself did not stand behind (PRD Scenario definition of "false certainty":
 * the corpus must never credit the engine for a right answer it did not
 * actually verify).
 */
function scoreExpectation(manifest, findingProvenance, trueOrigin) {
  const fp = findingProvenance || {};
  const expect = manifest.expect || 'commit';
  if (expect === 'commit') {
    const got = fp.findingOrigin?.commit || null;
    const pass = fp.status === 'complete' && !!trueOrigin && got === trueOrigin;
    return {
      pass,
      detail: { expectedCommit: trueOrigin, gotStatus: fp.status || null, gotCommit: got },
    };
  }
  if (expect === 'partial') {
    // Scenario F (shallow clone): the correct behaviour is DECLINING to claim
    // a verified origin, not naming a specific SHA — see the task brief and
    // fixtures/shallow-clone-partial.mjs for the full reasoning.
    return { pass: fp.status === 'partial', detail: { gotStatus: fp.status || null } };
  }
  if (expect === 'uncommitted') {
    return { pass: fp.status === 'uncommitted', detail: { gotStatus: fp.status || null } };
  }
  throw new Error(`fixture ${manifest.id}: unknown expect kind ${JSON.stringify(expect)}`);
}

function unpackBuildResult(built) {
  if (typeof built === 'string') return { commit: built, root: null, cleanup: null };
  if (built && typeof built === 'object') {
    return { commit: built.commit ?? null, root: built.root || null, cleanup: built.cleanup || null };
  }
  return { commit: null, root: null, cleanup: null };
}

async function scoreSastFixture(manifest) {
  const fx = createGitFixture();
  let extraCleanup = null;
  try {
    const built = await manifest.build(fx);
    const { commit: trueOrigin, root: rootOverride, cleanup } = unpackBuildResult(built);
    extraCleanup = cleanup;
    const root = rootOverride || fx.root;

    const { scan } = await runScan(root, { network: false });
    const candidates = SAST_CHANNELS.flatMap((ch) => (Array.isArray(scan[ch]) ? scan[ch] : []));
    const matches = candidates.filter((f) => sastLocatorMatches(f, manifest.finding));

    if (matches.length !== 1) {
      return {
        id: manifest.id, verdict: 'env-error',
        reason: `expected exactly 1 matching finding, got ${matches.length} (locator: ${JSON.stringify(manifest.finding)})`,
      };
    }
    const { pass, detail } = scoreExpectation(manifest, matches[0].findingProvenance, trueOrigin);
    return { id: manifest.id, verdict: pass ? 'pass' : 'fail', detail };
  } catch (e) {
    return { id: manifest.id, verdict: 'env-error', reason: String((e && e.stack) || e) };
  } finally {
    try { extraCleanup && extraCleanup(); } catch { /* best-effort */ }
    fx.cleanup();
  }
}

async function scoreScaFixture(manifest) {
  const fx = createGitFixture();
  let home = null;
  try {
    const built = await manifest.build(fx);
    const { commit: trueOrigin } = unpackBuildResult(built);

    home = fs.mkdtempSync(path.join(os.tmpdir(), 'as-provenance-accuracy-home-'));
    seedAdvisory(home, manifest.sca);

    const r = cp.execFileSync(process.execPath, [SCA_HELPER, fx.root], {
      encoding: 'utf8', timeout: 120000,
      env: {
        ...process.env, HOME: home,
        AGENTIC_SECURITY_OFFLINE: '1', AGENTIC_SECURITY_NO_STATE: '1',
      },
    });
    const supplyChain = JSON.parse(r);
    const matches = supplyChain.filter((e) => scaLocatorMatches(e, manifest.finding));

    if (matches.length !== 1) {
      return {
        id: manifest.id, verdict: 'env-error',
        reason: `expected exactly 1 matching supplyChain entry, got ${matches.length}`,
      };
    }
    const { pass, detail } = scoreExpectation(manifest, matches[0].findingProvenance, trueOrigin);
    return { id: manifest.id, verdict: pass ? 'pass' : 'fail', detail };
  } catch (e) {
    return { id: manifest.id, verdict: 'env-error', reason: String((e && e.stack) || e) };
  } finally {
    if (home) { try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* best-effort */ } }
    fx.cleanup();
  }
}

async function scoreFixture(manifest) {
  if (!EXPECT_KINDS.has(manifest.expect || 'commit')) {
    return { id: manifest.id, verdict: 'env-error', reason: `unknown expect kind ${JSON.stringify(manifest.expect)}` };
  }
  return manifest.kind === 'sca' ? scoreScaFixture(manifest) : scoreSastFixture(manifest);
}

// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
const CHECK = argv.includes('--check');
const UPDATE = argv.includes('--update-baseline');
if (CHECK && UPDATE) {
  console.error('✗ pass only one of --check / --update-baseline');
  process.exit(USAGE_ERROR_EXIT);
}

const fixtureFiles = loadFixtureFiles();
if (fixtureFiles.length === 0) {
  console.error(`✗ no fixtures found under ${path.relative(process.cwd(), FIXTURES_DIR)}`);
  process.exit(USAGE_ERROR_EXIT);
}

const results = [];
for (const file of fixtureFiles) {
  const mod = await import(file);
  const manifest = mod.manifest;
  if (!manifest || !manifest.id) {
    console.error(`✗ ${path.basename(file)} does not export a manifest with an id`);
    process.exit(USAGE_ERROR_EXIT);
  }
  process.stderr.write(`  scoring ${manifest.id}...\r`);
  const result = await scoreFixture(manifest);
  results.push({ ...result, description: manifest.description || '', scenario: manifest.scenario || '' });
}
process.stderr.write(' '.repeat(60) + '\r');

const envErrors = results.filter((r) => r.verdict === 'env-error');
const scoreable = results.filter((r) => r.verdict !== 'env-error');
const passing = scoreable.filter((r) => r.verdict === 'pass');
const n = passing.length;
const d = scoreable.length;

console.log('\nKnown-origin accuracy — provenance-accuracy corpus\n');
const pad = (s, w) => String(s).padEnd(w);
const trunc = (s, w) => (String(s).length > w ? String(s).slice(0, w - 1) + '…' : String(s));
console.log(pad('fixture', 28) + pad('scenario', 46) + 'verdict');
console.log('-'.repeat(84));
for (const r of results) {
  const verdictLabel = r.verdict === 'pass' ? 'PASS' : r.verdict === 'fail' ? 'FAIL' : 'ENV-ERROR';
  console.log(pad(r.id, 28) + pad(trunc(r.scenario, 44), 46) + verdictLabel);
  if (r.verdict === 'fail' && r.detail) console.log(`    ${JSON.stringify(r.detail)}`);
  if (r.verdict === 'env-error' && r.reason) console.log(`    ${r.reason.split('\n')[0]}`);
}
console.log('-'.repeat(84));
console.log(`\n  known-origin accuracy: ${n}/${d} scoreable fixtures matched their documented ground truth`);
if (envErrors.length) {
  console.log(`  ${envErrors.length} fixture(s) UNSCOREABLE this run (excluded from n/d — see ENV-ERROR rows above)`);
}

if (UPDATE) {
  if (envErrors.length) {
    console.error(`\n✗ ENVIRONMENT ERROR (${envErrors.length}) — refusing to write a baseline from an incomplete run:`);
    for (const r of envErrors) console.error(`  · ${r.id}: ${r.reason}`);
    process.exit(ENV_ERROR_EXIT);
  }
  const entries = {};
  for (const r of results) entries[r.id] = r.verdict;
  const baseline = {
    schema: 'provenance-accuracy/v1',
    generatedAt: new Date().toISOString().slice(0, 10),
    matched: n,
    scoreable: d,
    totalFixtures: results.length,
    entries: Object.fromEntries(Object.entries(entries).sort(([a], [b]) => a.localeCompare(b))),
  };
  fs.writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + '\n');
  console.log(`\n✓ baseline written: ${n}/${d} → ${path.relative(process.cwd(), BASELINE_PATH)}`);
  process.exit(0);
}

if (!CHECK) process.exit(0);

// --check: environment errors short-circuit BEFORE any drift is computed,
// exactly as bench/cve-replay/runner.mjs's --check-baseline does — an entry
// with no verdict this run must never silently read as a pass OR a fail.
if (envErrors.length) {
  console.error(`\n✗ ENVIRONMENT ERROR (${envErrors.length}) — cannot evaluate the gate:`);
  for (const r of envErrors) console.error(`  · ${r.id}: ${r.reason}`);
  process.exit(ENV_ERROR_EXIT);
}

if (!fs.existsSync(BASELINE_PATH)) {
  console.error(`\n✗ no baseline at ${path.relative(process.cwd(), BASELINE_PATH)} — run with --update-baseline first.`);
  process.exit(USAGE_ERROR_EXIT);
}
const base = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
const now = Object.fromEntries(results.map((r) => [r.id, r.verdict]));

const regressed = [];
const newFailing = [];
const missing = [];
const improved = [];
for (const [id, wasVerdict] of Object.entries(base.entries || {})) {
  if (!(id in now)) { missing.push(id); continue; }
  const nowVerdict = now[id];
  if (wasVerdict === 'pass' && nowVerdict === 'fail') regressed.push(id);
  else if (wasVerdict === 'fail' && nowVerdict === 'pass') improved.push(id);
}
for (const [id, nowVerdict] of Object.entries(now)) {
  if (!(id in (base.entries || {})) && nowVerdict === 'fail') newFailing.push(id);
}

if (regressed.length || newFailing.length || missing.length) {
  console.error('\n✗ known-origin accuracy DRIFTED from the baseline:');
  if (regressed.length) console.error(`  REGRESSED (baselined pass, now fails): ${regressed.join(', ')}`);
  if (newFailing.length) console.error(`  NEW FIXTURE FAILING (added without confirming it scores correctly): ${newFailing.join(', ')}`);
  if (missing.length) console.error(`  BASELINED FIXTURE MISSING: ${missing.join(', ')}`);
  console.error('\n  Fix the regression, or re-baseline deliberately if the change is intended.');
  process.exit(1);
}

if (improved.length) {
  console.log(`\n  note: ${improved.length} fixture(s) newly pass their ground truth (${improved.join(', ')}).`);
  console.log('  Consider `node runner.mjs --update-baseline` to record the improvement.');
}
console.log(`\n✓ known-origin accuracy matches or exceeds the baseline (${n}/${d}, baseline ${base.matched}/${base.scoreable})`);
