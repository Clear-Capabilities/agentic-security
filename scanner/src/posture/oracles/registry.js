// The oracle registry and its manifest (X-202).
//
// The registry is built once, at module load, from the static adapter list and
// frozen. There is no registration function: a candidate worker (or anything at
// run time) cannot add, replace or edit an adapter, which is half of "workers
// cannot alter adapter logic". The other half is the harness digest check in
// `runOracle`.
//
// `oracleManifest()` is the machine-readable description X-208 gates a release on:
// per adapter, its class, declared prerequisites, platforms (with an honest status
// per platform), budgets, negative controls, fixture locations, limitations and
// the logic digest a replay manifest pins. It contains no function bodies and no
// host details, and its order is fixed, so it is byte-stable across runs.
import { ADAPTERS } from './adapters.js';
import { PREREQUISITES, ORACLE_CLASSES, validateOracleSpec } from './oracle.js';
import { SCENARIO_CLASSES, UNSUPPORTED_NON_TAINT, NON_TAINT_SCHEMA, scenarioClassReportLines } from './scenario-classes.js';

const BY_ID = new Map(ADAPTERS.map((a) => [a.id, a]));
if (BY_ID.size !== ADAPTERS.length) throw new Error('duplicate oracle adapter id');

export function getOracle(id) {
  return typeof id === 'string' && BY_ID.has(id) ? BY_ID.get(id) : null;
}

export function listOracles() {
  return [...ADAPTERS].sort((a, b) => a.id.localeCompare(b.id));
}

export const MANIFEST_SCHEMA = 'agentic-security/oracle-manifest';

/** The manifest entry for one adapter: data only. */
export function manifestEntry(a) {
  return {
    id: a.id, class: a.class, version: a.version, logicDigest: a.logicDigest, description: a.description,
    prerequisites: a.prerequisites.map((id) => ({ id, description: PREREQUISITES[id].description })),
    platforms: a.platforms, budgets: a.budgets, requiresFeature: a.requiresFeature ?? null,
    negativeControls: a.negativeControls, fixtures: a.fixtures, limitations: a.limitations,
    receipts: 'issued by the verifier domain only (runOracle); a caller-supplied receipt is not valid',
  };
}

// X-205: the supported-class manifest for non-taint vulnerabilities. Each class names the adapter that executes it, whether
// that adapter was reused, its fixtures and the user-visible report text (prerequisites, platforms, limitations).
function scenarioClassEntries(adapters) {
  return SCENARIO_CLASSES.map((c) => {
    const a = adapters.find((x) => x.id === c.adapterId) || null;
    return {
      id: c.id, title: c.title, claim: c.claim, oracle: c.adapterId, adapterReuse: c.adapterReuse,
      requires: c.requires, limitations: c.limitations, fixtures: c.fixtures,
      prerequisites: a ? a.prerequisites.map((id) => ({ id, description: PREREQUISITES[id].description })) : [],
      platforms: a ? a.platforms : null,
      report: scenarioClassReportLines(c, a),
    };
  });
}

export function oracleManifest(adapters = listOracles()) {
  const entries = adapters.map(manifestEntry);
  return {
    schema: MANIFEST_SCHEMA, schemaVersion: '1.0.0',
    classes: [...ORACLE_CLASSES],
    oracles: entries,
    // Every class the PRD names must have an adapter; a missing one is stated, never implied.
    uncoveredClasses: ORACLE_CLASSES.filter((c) => !adapters.some((a) => a.class === c)),
    problems: [
      ...adapters.flatMap((a) => validateOracleSpec(a).map((p) => `${a.id}: ${p}`)),
      ...SCENARIO_CLASSES.filter((c) => !adapters.some((a) => a.id === c.adapterId)).map((c) => `scenario class ${c.id}: its oracle '${c.adapterId}' is not registered`),
    ],
    nonTaint: {
      schema: NON_TAINT_SCHEMA, schemaVersion: '1.0.0',
      classes: scenarioClassEntries(adapters),
      unsupported: UNSUPPORTED_NON_TAINT.map((u) => ({ id: u.id, cwes: u.cwes, reason: u.reason })),
      rules: ['taint absence never refutes a non-taint hypothesis', 'an unsupported or unrun case is never counted in the trusted-negative denominator'],
    },
  };
}
