// Attack coverage and the enforced-mode release gate (X-508.AC02, X-508.AC03).
//
// The adversarial corpus (test/capabilities/adversarial/) is a REGRESSION corpus:
// a list of concrete escape attempts that must keep failing. This module turns the
// results of a run into two things.
//
//   buildAttackCoverage    what was attempted, per attack class, on which platform
//                          and backend, with the known limits stated beside it.
//                          It says what the corpus covered; it never says the
//                          sandbox is secure.
//   enforcedModeReleaseGate  the decision a release takes from those results: any
//                          mandatory fixture that leaked a canary or errored, a
//                          mandatory class with no case, or (for enforced mode) a
//                          mandatory execution case that did not run, BLOCKS.
//
// Passing the corpus proves that these attempts were stopped on this backend in
// this run. It does not prove that no other attempt succeeds.
export const ATTACK_CLASSES = Object.freeze([
  'prompt-injection', 'malicious-build-script', 'secret-read', 'network-exfiltration', 'tool-confusion',
  'descendant-escape', 'verifier-tampering', 'delegation-escalation', 'receipt-tampering',
]);

// `known-limit`: the attempt reproduced a limit that is DOCUMENTED (KNOWN_LIMITS), with
// confinement still holding (no canary left its place). Only a non-mandatory case
// may end this way; it is reported, never counted as blocked.
export const OUTCOMES = Object.freeze(['blocked', 'leaked', 'error', 'skipped', 'known-limit']);
const COUNTER = Object.freeze({ blocked: 'blocked', leaked: 'leaked', error: 'error', skipped: 'skipped', 'known-limit': 'knownLimit' });

export const KNOWN_LIMITS = Object.freeze([
  'The corpus is a fixed list of attempts. A pass shows those attempts were stopped; it is not a proof that the sandbox is secure against all attempts.',
  'Linux is unverified from this workspace: no Linux outcome is asserted by any case, and enforced mode is advertised for Linux only.',
  'Descendant exec calls are not allowlisted; descendants inherit file and network confinement and are terminated with the task.',
  'A process that double-forks and calls setsid between two supervisor sweeps can outlive a task.',
  'HTTPS to a declared destination is an opaque tunnel: its payload is not inspected.',
  'The mediation proxy accepts connections from any local process, and forwards only to the declared destinations.',
  'Tool and delegation checks are policy at the tool boundary (in-process); only the runner enforces.',
  'Process-count caps are not asserted on any backend.',
]);

/**
 * @param {Array<{id:string, class:string, mandatory?:boolean, execution?:boolean, outcome:string, note?:string}>} results
 * @param {{platform:string, backend:string|null, level:string}} env  what the run observed
 */
export function buildAttackCoverage(results, { platform, backend, level } = {}) {
  const classes = Object.fromEntries(ATTACK_CLASSES.map((c) => [c, { cases: 0, blocked: 0, leaked: 0, error: 0, skipped: 0, knownLimit: 0 }]));
  const unknown = [];
  for (const r of results) {
    const c = classes[r.class];
    if (!c) { unknown.push(r.id); continue; }
    c.cases += 1;
    if (OUTCOMES.includes(r.outcome)) c[COUNTER[r.outcome]] += 1; else c.error += 1;
  }
  const totals = { cases: 0, blocked: 0, leaked: 0, error: 0, skipped: 0, knownLimit: 0 };
  for (const c of Object.values(classes)) for (const k of Object.keys(totals)) totals[k] += c[k];
  return Object.freeze({
    schema: 'agentic-security/attack-coverage', version: 1,
    platform: platform ?? process.platform, backend: backend ?? null, level: level ?? 'none',
    classes, totals,
    uncoveredClasses: ATTACK_CLASSES.filter((c) => classes[c].cases === 0),
    unknownClassCases: unknown,
    platforms: { linux: 'unverified' },
    knownLimits: KNOWN_LIMITS,
    claim: 'regression corpus: these attempts were attempted and their outcomes recorded; this is not evidence of a universally secure sandbox',
    cases: results.map((r) => ({ id: r.id, class: r.class, mandatory: r.mandatory !== false, execution: r.execution === true, outcome: r.outcome, ...(r.note ? { note: String(r.note).slice(0, 200) } : {}) })),
  });
}

/**
 * The release decision. `block` is true when anything mandatory failed;
 * `enforcedModeReleasable` is true only when nothing blocks AND the run reached
 * the `enforced` level with every mandatory execution case actually executed.
 */
export function enforcedModeReleaseGate(coverage) {
  const reasons = [];
  const mandatory = coverage.cases.filter((c) => c.mandatory);
  for (const c of mandatory) {
    if (c.outcome === 'leaked') reasons.push(`mandatory fixture leaked: ${c.id}`);
    else if (c.outcome === 'error') reasons.push(`mandatory fixture errored: ${c.id}`);
  }
  for (const cls of coverage.uncoveredClasses) reasons.push(`no fixture covers the attack class: ${cls}`);
  if (coverage.unknownClassCases.length) reasons.push(`fixtures with an unknown attack class: ${coverage.unknownClassCases.join(', ')}`);
  const block = reasons.length > 0;
  const skippedMandatory = mandatory.filter((c) => c.outcome === 'skipped');
  const notes = [];
  if (coverage.level !== 'enforced') notes.push(`backend level is '${coverage.level}', not 'enforced': this run cannot release enforced mode`);
  const limits = coverage.cases.filter((c) => c.outcome === 'known-limit');
  if (limits.length) notes.push(`${limits.length} documented limit(s) reproduced on this backend, with confinement holding: ${limits.map((c) => c.id).join(', ')}`);
  if (skippedMandatory.length) notes.push(`${skippedMandatory.length} mandatory case(s) did not execute: ${skippedMandatory.map((c) => c.id).join(', ')}`);
  return Object.freeze({
    block, reasons, notes,
    enforcedModeReleasable: !block && coverage.level === 'enforced' && skippedMandatory.length === 0,
  });
}
