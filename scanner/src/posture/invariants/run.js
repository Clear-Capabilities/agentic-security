// Run an invariant's scenarios and classify what they found (X-403, X-404, X-402).
//
// The one orchestration over the pieces: generate the bounded scenarios (`scenarios.js`), replay each through the business-state
// oracle (`runScenario`, so every run is pinned by a replay manifest, executed only through the trust boundary, and receipted by
// the verifier domain), then classify each settled run against the signed approval ledger (`lifecycle.js`). A violation of an
// approved contract is the only thing that may gate; a violation of a proposed one is a candidate, reported separately.
//
// With the `invariant-scenarios` feature off, or no fixture, nothing is generated and nothing executes. Every non-ok status is
// returned with its reason; a scenario that could not be built is listed as unsupported, never counted as checked.
import { generateScenarios, runScenario, exerciseOf } from './scenarios.js';
import { classifyViolation, violationReport } from './lifecycle.js';
import { shrinkScenario } from './shrink.js';

/**
 * @param {object} p
 * @param {object} p.invariant  a valid invariant document
 * @param {object} p.fixture    { files } of the disposable fixture
 * @param {string} p.commit     exact commit id the fixture belongs to
 * @param {object} [p.ledger]   the signed approval ledger (without one, every violation is a candidate)
 * @param {object} [p.config]   assurance config
 * @param {number} [p.seed]
 * @param {object} [p.bounds]
 * @param {object} [p.signer]   ledger signer (test seam)
 * @param {object} [p.runOptions] oracle runner seams (test)
 * @param {object|boolean} [p.shrink] shrink each confirmed violation within this budget (`true` for the default); additive, off by default
 */
export async function verifyInvariant(p) {
  const gen = generateScenarios(p.invariant, { fixture: p.fixture, config: p.config, seed: p.seed, bounds: p.bounds });
  if (gen.status !== 'ok') return { status: gen.status, reason: gen.reason, errors: gen.errors, results: [], unsupported: gen.unsupported, report: violationReport([]) };
  const results = [];
  for (const scenario of gen.scenarios) {
    const run = await runScenario(scenario, { fixture: p.fixture, commit: p.commit, config: p.config, runOptions: p.runOptions });
    const classification = classifyViolation({ invariant: p.invariant, ledger: p.ledger, run, signer: p.signer });
    const shrunk = p.shrink && run.outcome === 'confirmed'
      ? await shrinkScenario(scenario, { fixture: p.fixture, commit: p.commit, config: p.config, budget: p.shrink === true ? undefined : p.shrink, runOptions: p.runOptions })
      : null;
    results.push({
      scenarioId: scenario.id, kind: scenario.kind, limits: scenario.limits, determinism: scenario.determinism, exercise: exerciseOf(scenario),
      status: run.status, outcome: run.outcome, reason: run.record?.reason ?? run.errors?.[0]?.message ?? null,
      recordId: run.record?.id ?? null, receipt: run.receipt ?? null, manifestId: run.manifestId ?? null, report: run.report ?? null, classification,
      ...(shrunk ? { shrink: shrunk } : {}),
    });
  }
  return { status: 'ok', results, unsupported: gen.unsupported, bounds: gen.bounds, report: violationReport(results) };
}
