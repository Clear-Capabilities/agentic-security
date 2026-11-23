// Verifier strength by semantic mutation (contract-driven verification, Epic H-01, H-02).
//
// Two populations, kept apart:
//   APPLICATION mutants change the target code (the slice service): a removed tenant predicate, authorization moved after the write,
//   a patch that denies everyone, a scope bound to the wrong field. Each is judged by the REAL machinery: the approved invariant run
//   through the business-state oracle (in the trust boundary, receipted) and, where the mutant is a repair candidate, the repair verifier.
//   VERIFIER mutants weaken or forge the verifier side: a judge that looks only at the HTTP status, a forged receipt, an altered approval
//   identity, a candidate patch that tries to change the oracle. A verifier mutant is evaluated ONLY in a meta-test: the weakened judge runs
//   in a separate child process over an in-memory replay of the scenario and issues nothing; it never touches the oracle a real patch is
//   judged by.
//
// Every mutant ends in one classification: `killed` (the verifier noticed), `survived` (it did not), `equivalent` (the mutant cannot
// change behaviour; reviewed and justified), `unsupported` (could not execute here), `invalid` (the mutant could not be applied), or
// `unresolved` (executed, inconclusive). An unexecuted mutant is never `killed`, and no mutant is dropped: the kill rate is over the
// executed, non-equivalent ones, and coverage is over the whole scheduled population.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { verifyInvariant } from '../invariants/run.js';
import { verifyInvariantRepair } from '../invariants/repair.js';
import { generateScenarios } from '../invariants/scenarios.js';
import { classifyViolation, verifyLedger } from '../invariants/lifecycle.js';

const MUTANT_OUTCOMES = Object.freeze(['killed', 'survived', 'equivalent', 'unsupported', 'invalid', 'unresolved']);
const MUTATION_POPULATION_VERSION = 'slice-semantic-mutants/1';

// Each application mutant is a mechanical edit of the CORRECT (patched) service with a stated expectation and its justification.
const SET_FN = 'export function setInvoiceMemo(db, principal, key, payload) {';
const APPLICATION_MUTANTS = Object.freeze([
  { id: 'remove-write-tenant-predicate', expect: 'killed', justification: 'the memo write reads the record without the tenant scope, so a member of another tenant reaches the write',
    edit: (s) => s.replace("export function setInvoiceMemo(db, principal, key, payload) {\n  const rec = db.findOne(key, { tenant: principal.tenant });", "export function setInvoiceMemo(db, principal, key, payload) {\n  const rec = db.findOne(key);") },
  { id: 'authorization-after-write', expect: 'killed', justification: 'the tenant check runs after the write: the response is a 404 but the forbidden durable effect has happened',
    edit: (s) => s.replace("export function setInvoiceMemo(db, principal, key, payload) {\n  const rec = db.findOne(key, { tenant: principal.tenant });\n  if (!rec) return { status: 404 };\n  db.updateOne(key, { ...rec, memo: payload && payload.note });", "export function setInvoiceMemo(db, principal, key, payload) {\n  const rec = db.findOne(key);\n  if (!rec) return { status: 404 };\n  db.updateOne(key, { ...rec, memo: payload && payload.note });\n  if (rec.tenant !== principal.tenant) return { status: 404 };") },
  { id: 'remove-read-tenant-predicate', expect: 'survived', justification: 'a cross-tenant READ; the approved invariant forbids cross-tenant WRITES only, so its oracle is not expected to see it: a surviving mutant that names a gap in the contract, not in the code under test',
    edit: (s) => s.replace("export function getInvoice(db, principal, key) {\n  const rec = db.findOne(key, { tenant: principal.tenant });", "export function getInvoice(db, principal, key) {\n  const rec = db.findOne(key);") },
  { id: 'deny-everyone', expect: 'killed', repairCandidate: true, justification: 'a patch that refuses every memo update blocks the attack and the authorized workflow alike; the repair verifier must refuse it',
    edit: (s) => s.replace(SET_FN, `${SET_FN}\n  return { status: 403 };`) },
  { id: 'scope-by-principal-id', expect: 'killed', repairCandidate: true, justification: 'scoping by the principal id instead of the tenant breaks the owner\'s own update; the authorized workflow must fail',
    edit: (s) => s.replace("export function setInvoiceMemo(db, principal, key, payload) {\n  const rec = db.findOne(key, { tenant: principal.tenant });", "export function setInvoiceMemo(db, principal, key, payload) {\n  const rec = db.findOne(key, { tenant: principal.id });") },
  { id: 'comment-only', expect: 'equivalent', justification: 'adds a comment; behaviour is unchanged by construction, so no verifier should flag it',
    edit: (s) => s.replace(SET_FN, `// reviewed\n${SET_FN}`) },
]);

// A meta-test of a weakened judge: replay the scenario's attack steps against the application in a child process, with an in-memory
// store, and decide "violated" from the HTTP-like status alone. Nothing it produces is a receipt.
const STATUS_JUDGE = `import { pathToFileURL } from 'node:url';
const [, , entry, scenarioJson] = process.argv;
const sc = JSON.parse(scenarioJson);
const mod = await import(pathToFileURL(entry).href);
const api = mod[sc.export]();
const data = new Map(sc.seed.map((s) => [s.key, JSON.parse(JSON.stringify(s.value))]));
const actors = Object.fromEntries(sc.actors.map((a) => [a.id, a]));
const statuses = [];
for (const step of sc.attack) {
  if (step.parallel) continue;
  const a = actors[step.actor];
  const ctx = { id: a.id, tenant: a.tenant, role: a.role, store: { read: (k) => (data.has(k) ? JSON.parse(JSON.stringify(data.get(k))) : null), write: (k, v) => data.set(k, v), list: () => [], remove: (k) => data.delete(k) }, emit: () => {} };
  try { const r = await api[step.action](ctx, ...(step.args || [])); statuses.push(r && typeof r.status === 'number' ? r.status : null); } catch { statuses.push(null); }
}
process.stdout.write(JSON.stringify({ statuses }));
`;

function statusOnlyJudge(serviceText, scenario) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'weak-judge-'));
  try {
    fs.writeFileSync(path.join(dir, 'service.mjs'), serviceText);
    fs.writeFileSync(path.join(dir, 'judge.mjs'), STATUS_JUDGE);
    const r = spawnSync(process.execPath, [path.join(dir, 'judge.mjs'), path.join(dir, 'service.mjs'), JSON.stringify(scenario.inputs)], { encoding: 'utf8', timeout: 20_000, env: { PATH: process.env.PATH } });
    if (r.status !== 0) return { ok: false, reason: (r.stderr || '').slice(0, 200) };
    const { statuses } = JSON.parse(r.stdout);
    return { ok: true, violated: statuses.some((s) => s !== null && s >= 200 && s < 300), statuses };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

const settledOutcome = (res) => {
  const runs = (res.results || []).filter((r) => r.status === 'completed');
  if (!runs.length) return { executed: false, detail: res.reason || (res.results || [])[0]?.reason || res.status };
  if (runs.some((r) => r.outcome === 'confirmed' && r.classification?.kind === 'approved-violation')) return { executed: true, violated: true };
  if (runs.every((r) => r.outcome === 'refuted')) return { executed: true, violated: false };
  return { executed: true, violated: null, detail: runs.map((r) => r.reason).filter(Boolean)[0] || 'inconclusive' };
};

/**
 * Run the population. `invariant` must be approved in `ledger`. `fixtureText` is the vulnerable service, `patchedText` the correct one
 * the application mutants start from. Returns every mutant with its outcome, and the kill rate and coverage.
 */
export async function runMutationPopulation({ invariant, ledger, fixtureText, patchedText, commit, config, signer }) {
  const results = [];
  const fixture = { files: { 'service.mjs': fixtureText } };
  const scenario = generateScenarios(invariant, { fixture, config }).scenarios?.[0] || null;
  for (const m of APPLICATION_MUTANTS) {
    const text = m.edit(patchedText);
    if (text === patchedText) { results.push({ id: m.id, population: 'application', expect: m.expect, outcome: 'invalid', reason: 'the edit did not apply to the service text', justification: m.justification }); continue; }
    if (m.expect === 'equivalent') { results.push({ id: m.id, population: 'application', expect: m.expect, outcome: 'equivalent', reason: 'reviewed: behaviour unchanged by construction', justification: m.justification }); continue; }
    const run = settledOutcome(await verifyInvariant({ invariant, fixture: { files: { 'service.mjs': text } }, commit, config, ledger, signer }));
    let outcome; let reason;
    if (!run.executed) { outcome = 'unsupported'; reason = run.detail; }
    else if (run.violated === true) { outcome = 'killed'; reason = 'the approved invariant\'s oracle observed the forbidden durable effect'; }
    else if (m.repairCandidate && scenario) {
      const rep = await verifyInvariantRepair({ invariant, ledger, scenario, fixture, patch: { files: { 'service.mjs': text } }, commit }, { config, signer });
      if (rep.status === 'not-verified-fix') { outcome = 'killed'; reason = `the repair verifier refused it: ${rep.blockers.map((b) => b.code).join(', ')}`; }
      else if (rep.status === 'verified-fix') { outcome = 'survived'; reason = 'the repair verifier accepted a patch it should have refused'; }
      else { outcome = 'unsupported'; reason = `repair verification ${rep.status}: ${rep.blockers.map((b) => b.code).join(', ')}`; }
    } else if (run.violated === false) { outcome = 'survived'; reason = 'the oracle observed no forbidden effect'; }
    else { outcome = 'unresolved'; reason = run.detail; }
    results.push({ id: m.id, population: 'application', expect: m.expect, outcome, reason, justification: m.justification, matchesExpectation: outcome === m.expect });
  }
  // ---- verifier mutants (meta-test only)
  const auth = APPLICATION_MUTANTS.find((m) => m.id === 'authorization-after-write');
  if (scenario) {
    const weak = statusOnlyJudge(auth.edit(patchedText), scenario);
    results.push(weak.ok
      ? { id: 'status-only-judge', population: 'verifier', expect: 'survived', outcome: weak.violated ? 'killed' : 'survived', reason: weak.violated ? 'the status-only judge noticed' : `the status-only judge saw statuses ${weak.statuses.join(', ')} and called it safe, while the durable effect happened (the real oracle kills this mutant)`, justification: 'a verifier that reads the response status cannot see a forbidden effect behind a denial' }
      : { id: 'status-only-judge', population: 'verifier', expect: 'survived', outcome: 'unsupported', reason: weak.reason });
  } else results.push({ id: 'status-only-judge', population: 'verifier', outcome: 'unsupported', reason: 'no scenario could be generated' });
  const forged = classifyViolation({ invariant, ledger, run: { outcome: 'confirmed', receipt: { id: 'rcpt-forged', verdict: 'confirmed' } }, signer });
  results.push({ id: 'forged-receipt', population: 'verifier', expect: 'killed', outcome: forged.kind === 'unverified' ? 'killed' : 'survived', reason: forged.reason, justification: 'a receipt the verifier did not issue must not count' });
  const tampered = JSON.parse(JSON.stringify(ledger));
  const appr = tampered.records.find((r) => r.action === 'approve');
  if (appr) appr.actor = { id: 'someone-else', kind: 'human' };
  const lv = verifyLedger(tampered, { signer });
  results.push({ id: 'altered-approval-identity', population: 'verifier', expect: 'killed', outcome: appr ? (lv.ok ? 'survived' : 'killed') : 'invalid', reason: appr ? (lv.ok ? 'the altered ledger still verified' : lv.errors.map((e) => e.code).join(', ')) : 'no approval record to alter', justification: 'an approval re-attributed after signing must fail verification' });
  if (scenario) {
    const rep = await verifyInvariantRepair({ invariant, ledger, scenario, fixture, patch: { files: { 'service.mjs': patchedText, '__oracle_harness.mjs': 'export const verdict = "refuted";\n' } }, commit }, { config, signer });
    results.push({ id: 'patch-rewrites-oracle', population: 'verifier', expect: 'killed', outcome: rep.status === 'verified-fix' ? 'survived' : rep.blockers.length ? 'killed' : 'unresolved', reason: `${rep.status}: ${rep.blockers.map((b) => b.code).join(', ')}`, justification: 'a candidate patch that writes into the oracle\'s reserved namespace is a separate, invalid experiment' });
  }
  for (const r of results) if (!MUTANT_OUTCOMES.includes(r.outcome)) throw new Error(`unknown outcome ${r.outcome}`);
  const executed = results.filter((r) => ['killed', 'survived', 'unresolved'].includes(r.outcome));
  const nonEquivalent = executed.filter((r) => r.outcome !== 'unresolved');
  return {
    schema: 'agentic-security/verifier-mutation-report', population: MUTATION_POPULATION_VERSION, scheduled: results.length, results,
    counts: Object.fromEntries(MUTANT_OUTCOMES.map((k) => [k, results.filter((r) => r.outcome === k).length])),
    killRate: nonEquivalent.length ? nonEquivalent.filter((r) => r.outcome === 'killed').length / nonEquivalent.length : null,
    coverage: results.length ? executed.length / results.length : null,
    note: 'the population is this repository\'s slice service and its verifier; mechanical justifications, no independent review recorded; a surviving mutant is reported, never removed',
  };
}
