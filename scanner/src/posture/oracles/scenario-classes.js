// Non-taint vulnerability classes and the rules for judging them (X-205).
//
// A taint engine answers "does attacker data reach a dangerous call". Several
// defect classes have no such flow: a missing tenant check, a privileged action
// open to a lower role, a workflow step that can be skipped, a request whose
// effect repeats when it is delivered again, an unbounded work parameter. A
// source-to-sink analysis finding nothing says NOTHING about them, so this module
// states three things, each with a test:
//
//   1. WHICH classes are supported (`SCENARIO_CLASSES`), and for each one the
//      adapter that executes it, what the requester must supply, the fixtures that
//      prove it works in both directions, and the limitations a reader must see.
//      Where an existing adapter already covers a class it is REUSED, and the
//      entry says so (`adapterReuse`); only replay/idempotency needed a new one.
//   2. That taint absence NEVER refutes one of these hypotheses
//      (`judgeNonTaintHypothesis`): without an executed oracle of the class's own
//      adapter the outcome is `not-run`, never `refuted`.
//   3. Which results may count as a trusted negative (`trustedNegativeDenominator`):
//      only a decided result from an executed oracle with proven preconditions.
//      Unsupported, not-run, inconclusive, error, static-only and model-only results
//      are listed explicitly and excluded; they cannot be counted as "checked and
//      clean".
//
// This module is pure data and pure functions: it imports no adapter and runs
// nothing, so `oracle.js` and `registry.js` can both depend on it.

export const NON_TAINT_SCHEMA = 'agentic-security/non-taint-classes';

const FIXTURE_ROOT = 'test/fixtures/non-taint';

export const SCENARIO_CLASSES = Object.freeze([
  Object.freeze({
    id: 'tenant-authorization',
    title: 'Tenant authorization',
    adapterId: 'authorization-decision', adapterReuse: true,
    claim: 'an actor from one tenant is allowed to read or change another tenant\'s resource',
    cwes: ['CWE-639', 'CWE-566', 'CWE-863', 'CWE-862', 'CWE-285', 'CWE-284'],
    families: ['idor', 'authz', 'missing-authz', 'broken-access-control', 'tenant-isolation'],
    requires: ['an exported decision function taking the actor and the resource (or ids that resolve to them)', 'one control case the function must allow (the owner) and one attack case it must deny (another tenant)'],
    limitations: ['asserts the decision function in isolation; a route or middleware that enforces the check elsewhere is not exercised', 'the scenario names which actors should be denied: the oracle does not infer tenancy rules', 'row-level checks inside a database query are not observed'],
    fixtures: { dir: `${FIXTURE_ROOT}/tenant-authorization`, positive: 'positive', negative: 'negative', scenario: 'scenario.json' },
  }),
  Object.freeze({
    id: 'privileged-action',
    title: 'Privileged action',
    adapterId: 'authorization-decision', adapterReuse: true,
    claim: 'a lower-privileged actor is allowed to perform an action reserved for a higher role',
    cwes: ['CWE-269', 'CWE-250', 'CWE-266', 'CWE-267'],
    families: ['privilege-escalation', 'privileged-action', 'missing-role-check'],
    requires: ['an exported decision function taking the actor and the action', 'one control case with the privileged role (must be allowed) and one attack case with an ordinary role (must be denied)'],
    limitations: ['asserts the decision function in isolation; role checks enforced only by a gateway or framework guard are not exercised', 'a thrown error is not read as a denial', 'role and permission grants stored outside the function are not observed'],
    fixtures: { dir: `${FIXTURE_ROOT}/privileged-action`, positive: 'positive', negative: 'negative', scenario: 'scenario.json' },
  }),
  Object.freeze({
    id: 'workflow-order',
    title: 'Workflow order',
    adapterId: 'state-transition', adapterReuse: true,
    claim: 'a step that must follow another can be performed first (for example a refund before approval)',
    cwes: ['CWE-841', 'CWE-840', 'CWE-696'],
    families: ['workflow', 'business-logic', 'state-machine', 'workflow-order'],
    requires: ['an exported factory returning a machine with `send(event)` and a `state`', 'a legal event sequence with its expected final state, an attack sequence and the forbidden state'],
    limitations: ['covers one factory and finite event lists; it is not a model checker', 'durable effects outside the machine object (a database row, a queued job) are not observed', 'the forbidden state is stated by the scenario: business rules are not inferred'],
    fixtures: { dir: `${FIXTURE_ROOT}/workflow-order`, positive: 'positive', negative: 'negative', scenario: 'scenario.json' },
  }),
  Object.freeze({
    id: 'replay-idempotency',
    title: 'Replay and idempotency',
    adapterId: 'replay-idempotency', adapterReuse: false,
    claim: 'delivering the same request again repeats its side effect (a double charge, a double credit)',
    cwes: ['CWE-294', 'CWE-837', 'CWE-841'],
    families: ['replay', 'idempotency', 'replay-attack', 'duplicate-submission'],
    requires: ['an exported factory that receives a recording stand-in for the effect and returns a request handler', 'a request, a distinct request and a delivery count'],
    limitations: ['deliveries are sequential: a race between concurrent deliveries is not exercised', 'deduplication kept in an external store is not observed, only the handler the factory returns', 'code that imports its effect directly instead of receiving it is not covered'],
    fixtures: { dir: `${FIXTURE_ROOT}/replay-idempotency`, positive: 'positive', negative: 'negative', scenario: 'scenario.json' },
  }),
  Object.freeze({
    id: 'resource-exhaustion',
    title: 'Bounded resource exhaustion',
    adapterId: 'parser-resource', adapterReuse: true,
    claim: 'a bounded hostile parameter makes the code exceed its time or output budget (an uncapped page size, an unbounded loop)',
    cwes: ['CWE-400', 'CWE-770', 'CWE-789', 'CWE-405', 'CWE-834'],
    families: ['resource-exhaustion', 'dos', 'denial-of-service', 'unbounded-loop'],
    requires: ['an exported function taking one string', 'a benign input it must finish and a hostile input described as a unit repeated at most 65536 times'],
    limitations: ['the hostile input is bounded and the run is cut at the supervisor deadline: this shows a budget was exceeded, not how large the blow-up is', 'memory is not measured', 'distributed or network-level exhaustion, and exhaustion that needs a populated datastore, are not exercised'],
    fixtures: { dir: `${FIXTURE_ROOT}/resource-exhaustion`, positive: 'positive', negative: 'negative', scenario: 'scenario.json' },
  }),
]);

// Non-taint classes this build recognises and does NOT execute. A finding that maps here is `unsupported`,
// stated by name, and never counted as checked.
export const UNSUPPORTED_NON_TAINT = Object.freeze([
  Object.freeze({ id: 'concurrent-race', cwes: ['CWE-362', 'CWE-367'], reason: 'a race needs concurrent scheduling; the adapters deliver sequentially, so no verdict about a race can be formed' }),
  Object.freeze({ id: 'cross-site-request-forgery', cwes: ['CWE-352'], reason: 'needs a browser and a session; no adapter exercises one' }),
  Object.freeze({ id: 'authentication-throttling', cwes: ['CWE-307', 'CWE-799'], reason: 'needs a stateful attempt counter over time and a populated store; the adapters bound a single input, not a campaign' }),
]);

const BY_ID = new Map(SCENARIO_CLASSES.map((c) => [c.id, c]));

export function scenarioClassesForAdapter(adapterId) { return SCENARIO_CLASSES.filter((c) => c.adapterId === adapterId); }

/**
 * The lines a user reads about one class: what it asserts, what the requester must supply (prerequisites), the platform
 * statement and every limitation. A report that shows a class shows these with it.
 * @param {object} cls  a SCENARIO_CLASSES entry
 * @param {object} [adapter] the executing adapter (prerequisites and platform statements are taken from it)
 */
export function scenarioClassReportLines(cls, adapter = null) {
  const lines = [`${cls.title} (${cls.id}): ${cls.claim}.`];
  lines.push(`  oracle: ${cls.adapterId}${cls.adapterReuse ? ' (an existing adapter, reused for this class)' : ' (added for this class)'}`);
  lines.push(`  prerequisites: ${[...cls.requires, ...(adapter ? adapter.prerequisites.map((p) => `host: ${p}`) : [])].join('; ')}`);
  if (adapter) lines.push(`  platforms: macOS ${adapter.platforms.darwin.status}, Linux ${adapter.platforms.linux.status}, Windows ${adapter.platforms.win32.status}`);
  for (const l of cls.limitations) lines.push(`  limitation: ${l}`);
  lines.push('  not established: a clean result covers only the declared scenario; it is not proof the class is absent from the code.');
  return lines;
}

// ------------------------------------------------------------------ classification

const cweOf = (f) => String(f?.cwe || '').toUpperCase().replace(/^CWE[-_ ]?/, 'CWE-');
const familyOf = (f) => String(f?.family || '').toLowerCase();

/**
 * Which non-taint class, supported or not, does this finding belong to? `null` when it is not a recognised non-taint
 * hypothesis (then nothing in this module applies). An explicit `finding.scenarioClass` wins over CWE and family.
 * @returns {null | { classId: string, supported: boolean, title: string, reason?: string }}
 */
export function nonTaintClassOf(finding) {
  if (!finding || typeof finding !== 'object') return null;
  if (typeof finding.scenarioClass === 'string') {
    const c = BY_ID.get(finding.scenarioClass);
    if (c) return { classId: c.id, supported: true, title: c.title };
  }
  const cwe = cweOf(finding);
  const fam = familyOf(finding);
  for (const u of UNSUPPORTED_NON_TAINT) {
    if (u.cwes.includes(cwe) || fam === u.id) return { classId: u.id, supported: false, title: u.id.replace(/-/g, ' '), reason: u.reason };
  }
  for (const c of SCENARIO_CLASSES) {
    if (c.cwes.includes(cwe) || c.families.includes(fam)) return { classId: c.id, supported: true, title: c.title };
  }
  return null;
}

// ------------------------------------------------------------------ judging a non-taint hypothesis

/**
 * Judge a non-taint hypothesis from what is actually known about it.
 *
 * The rule: absence of a taint flow is not evidence about these classes, so it is never an input to a refutation. An
 * outcome of `refuted` needs an EXECUTED oracle result from the class's own adapter with proven preconditions; anything
 * else is `not-run` (a supported class nobody ran), `unsupported` (a class this build cannot execute) or the oracle's own
 * `confirmed`/`inconclusive`/`error`.
 *
 * @param {object} args
 * @param {object} args.finding
 * @param {object} [args.taint]        static taint evidence, for example `{ clean: true }`; recorded, never used to refute
 * @param {object} [args.oracleResult] `{ outcome, oracleId, preconditionsValid }` from a run of an oracle adapter
 * @returns {{ nonTaint: boolean, classId?: string, supported?: boolean, outcome?: string, reason?: string, taintAbsenceUsed: false }}
 */
export function judgeNonTaintHypothesis({ finding, taint = null, oracleResult = null } = {}) {
  const cls = nonTaintClassOf(finding);
  if (!cls) return { nonTaint: false, taintAbsenceUsed: false };
  const taintNote = taint && taint.clean === true
    ? ' No source-to-sink flow was found, and that says nothing about this class: it is not a refutation.'
    : '';
  if (!cls.supported) {
    return { nonTaint: true, classId: cls.classId, supported: false, outcome: 'unsupported', taintAbsenceUsed: false,
      reason: `${cls.title} is a non-taint class this build does not execute: ${cls.reason}.${taintNote}` };
  }
  const own = BY_ID.get(cls.classId);
  const r = oracleResult && typeof oracleResult === 'object' ? oracleResult : null;
  const decisive = r && r.oracleId === own.adapterId && ['confirmed', 'refuted', 'inconclusive', 'error'].includes(r.outcome);
  if (!decisive) {
    return { nonTaint: true, classId: cls.classId, supported: true, outcome: 'not-run', taintAbsenceUsed: false,
      reason: `no executed ${own.adapterId} oracle result exists for this ${cls.title.toLowerCase()} hypothesis, so it stays unrefuted.${taintNote}` };
  }
  if (r.outcome === 'refuted' && r.preconditionsValid !== true) {
    return { nonTaint: true, classId: cls.classId, supported: true, outcome: 'inconclusive', taintAbsenceUsed: false,
      reason: `the ${own.adapterId} oracle did not show its preconditions held, so its negative result is not a refutation.${taintNote}` };
  }
  return { nonTaint: true, classId: cls.classId, supported: true, outcome: r.outcome, taintAbsenceUsed: false,
    reason: `decided by the executed ${own.adapterId} oracle.${taintNote}` };
}

// ------------------------------------------------------------------ the trusted-negative denominator

const ORACLE_IDS = new Set(SCENARIO_CLASSES.map((c) => c.adapterId));

function whyExcluded(rec) {
  if (!rec || typeof rec !== 'object') return 'malformed';
  if (rec.outcome === 'unsupported') return 'unsupported';
  if (rec.outcome === 'not-run') return 'not-run';
  if (rec.outcome === 'inconclusive') return 'inconclusive';
  if (rec.outcome === 'error') return 'error';
  if (rec.outcome !== 'confirmed' && rec.outcome !== 'refuted') return 'not-decided';
  if (!rec.oracle || rec.oracle.kind !== 'runtime-replay') return 'no-executed-oracle';
  if (!ORACLE_IDS.has(rec.oracle.id)) return 'oracle-not-in-supported-class-manifest';
  if (!rec.preconditions || rec.preconditions.valid !== true) return 'preconditions-not-proved';
  if (!Array.isArray(rec.evidence) || !rec.evidence.some((e) => e && e.kind === 'trusted-runtime-proof')) return 'no-trusted-runtime-proof';
  return null;
}

/**
 * The trusted-negative denominator over verification records: the decided results (`confirmed` or `refuted`) of an
 * executed oracle of an advertised class with proven preconditions and trusted runtime proof. Everything else is listed
 * with the reason it is excluded; an unsupported or unrun case can never be counted as a negative.
 */
export function trustedNegativeDenominator(records) {
  const list = Array.isArray(records) ? records : [];
  let trustedNegatives = 0;
  let trustedPositives = 0;
  const excluded = [];
  for (const rec of list) {
    const why = whyExcluded(rec);
    if (why) { excluded.push({ id: rec && rec.id ? String(rec.id) : null, outcome: rec && rec.outcome ? String(rec.outcome) : null, reason: why }); continue; }
    if (rec.outcome === 'refuted') trustedNegatives++; else trustedPositives++;
  }
  return {
    denominator: trustedNegatives + trustedPositives, trustedNegatives, trustedPositives,
    excluded, unsupported: excluded.filter((e) => e.reason === 'unsupported'),
    total: list.length,
  };
}
