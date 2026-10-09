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
    platforms: a.platforms, budgets: a.budgets,
    negativeControls: a.negativeControls, fixtures: a.fixtures, limitations: a.limitations,
    receipts: 'issued by the verifier domain only (runOracle); a caller-supplied receipt is not valid',
  };
}

export function oracleManifest(adapters = listOracles()) {
  const entries = adapters.map(manifestEntry);
  return {
    schema: MANIFEST_SCHEMA, schemaVersion: '1.0.0',
    classes: [...ORACLE_CLASSES],
    oracles: entries,
    // Every class the PRD names must have an adapter; a missing one is stated, never implied.
    uncoveredClasses: ORACLE_CLASSES.filter((c) => !adapters.some((a) => a.class === c)),
    problems: adapters.flatMap((a) => validateOracleSpec(a).map((p) => `${a.id}: ${p}`)),
  };
}
