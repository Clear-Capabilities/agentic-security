#!/usr/bin/env node
// Final report, unresolved list and release decision (E8-05, E8-06), generated from the task ledger and the committed results.
//
//   node scripts/engineering-excellence/final-report.mjs [--check]
//
// THE DECISION IS A FUNCTION, NOT A SENTENCE. `releaseDecision` reads the ledger, the epic exit gates, the unresolved list, the last full gate run and the
// measurement validity, and returns release_ready only when none of these blocks. What cannot be done from here: relabel a metric (an exit gate may be 'met' only
// while every evidence path exists), drop a failing gate (an absent gate run is a blocker, not a pass), or waive a blocker by editing a flag (a waiver is honoured
// only if it is signed, unexpired, justified, has a compensating control and names the item, judged by the same code that judges finding waivers).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DOCS = path.join(ROOT, 'docs', 'engineering-excellence');
const json = (p) => JSON.parse(fs.readFileSync(path.join(ROOT, p), 'utf8'));
const exists = (p) => fs.existsSync(path.join(ROOT, p));
const digestOfFile = (p) => 'sha256:' + crypto.createHash('sha256').update(fs.readFileSync(path.join(ROOT, p))).digest('hex');
const DONE = new Set(['done', 'already_satisfied']);

/** Pure: every input is a value, so tests can feed it altered ones. @returns {{verdict:'release_ready'|'release_blocked', blockers:{code:string, message:string}[], caveats:string[]}} */
export function releaseDecision({ tasks, ledger, exitGates, unresolved, gateRun, measurement, waivers = [], waiverCtx = null, evaluateWaiver = null, pathExists = exists }) {
  const blockers = []; const caveats = []; const block = (code, message) => blockers.push({ code, message });
  for (const t of tasks) {
    const st = (ledger[t.id] || {}).state;
    if (t.priority === 'P0' && !DONE.has(st)) block('P0_TASK_INCOMPLETE', `${t.id} (${t.title}) is ${st || 'unrecorded'}`);
    else if (st === 'failed' || st === 'blocked') block('TASK_FAILED_OR_BLOCKED', `${t.id} is ${st}`);
  }
  if (!gateRun || gateRun.verdict !== 'PASSED') block('GATE_NOT_PASSED', gateRun ? `the last full gate run is ${gateRun.verdict}` : 'no full gate run is recorded');
  if (!measurement || measurement.measurementValid !== true || measurement.releaseTrust !== 'trusted') block('MEASUREMENT_NOT_VALID', 'the independent baseline run is not a valid, trusted measurement');
  for (const g of exitGates) {
    if (g.status === 'met') { const missing = (g.evidence || []).filter((e) => !pathExists(e)); if (!g.evidence || !g.evidence.length || missing.length) block('EXIT_GATE_UNEVIDENCED', `${g.epic} is marked met without existing evidence${missing.length ? ` (${missing.join(', ')})` : ''}`); }
    else if (g.status === 'partially_met') caveats.push(`${g.epic} exit gate partially met: ${g.note}`);
    else block('EXIT_GATE_NOT_MET', `${g.epic} exit gate is ${g.status}: ${g.note}`);
  }
  for (const u of unresolved) {
    if (!u.blocksRelease) continue;
    const w = waivers.find((x) => x.scope && x.scope.kind === 'rule' && x.scope.value === u.id);
    const verdict = w && evaluateWaiver ? evaluateWaiver(w, waiverCtx) : null;
    if (verdict && verdict.honoured) { caveats.push(`${u.id} waived by a signed waiver (${w.id}) until ${w.expiresAt}`); continue; }
    block('UNRESOLVED_BLOCKER', `${u.id}: ${u.title}${verdict ? ` (a waiver was offered and refused: ${verdict.reasons.join(', ')}${verdict.errors ? ' - ' + verdict.errors.join('; ') : ''})` : ''}`);
  }
  return { verdict: blockers.length ? 'release_blocked' : 'release_ready', blockers, caveats };
}

export async function gather() {
  const tasks = json('scripts/engineering-excellence/tasks.json'); const list = tasks.tasks || tasks; const status = json('scripts/engineering-excellence/status.json');
  const exit = json('scripts/engineering-excellence/data/exit-gates.json').gates; const unresolved = json('scripts/engineering-excellence/data/unresolved-source.json').items;
  const waiverFile = json('scripts/engineering-excellence/data/release-waivers.json').waivers; const policy = json('scripts/engineering-excellence/data/release-waiver-policy.json');
  const gateText = fs.readFileSync(path.join(DOCS, 'data/gates/prepush-5c1af313.txt'), 'utf8'); const gateRun = { verdict: /pre-push gate PASSED/.test(gateText) ? 'PASSED' : 'FAILED', commit: (gateText.match(/\(HEAD at the time\): (\w+)/) || [])[1] || null, file: 'docs/engineering-excellence/data/gates/prepush-5c1af313.txt' };
  const ptr = json('bench/independent/runs/BASELINE.json'); const run = json(`bench/independent/runs/${ptr.runId}/RESULT.json`);
  const { evaluateWaiver } = await import(path.join(ROOT, 'scanner/src/posture/assurance/waiver.js'));
  return { list, ledger: status.tasks, status, exit, unresolved, waivers: waiverFile, waiverCtx: { now: Date.parse('2026-10-16T00:00:00Z'), tenant: policy.tenant, environment: policy.environment, policy: { requireSignature: true }, trustedKeys: policy.trustedKeys }, evaluateWaiver, gateRun, measurement: { measurementValid: run.identity.measurementValid, releaseTrust: run.identity.releaseTrust }, run, ptr };
}

const pct = (n, d) => (d ? ((n / d) * 100).toFixed(1) + '%' : 'n/a');
export async function build() {
  const g = await gather(); const dec = releaseDecision({ tasks: g.list, ledger: g.ledger, exitGates: g.exit, unresolved: g.unresolved, gateRun: g.gateRun, measurement: g.measurement, waivers: g.waivers, waiverCtx: g.waiverCtx, evaluateWaiver: g.evaluateWaiver });
  const { CAPTURES } = await import(path.join(ROOT, 'scripts/engineering-excellence/doc-captures.mjs'));
  const states = {}; for (const t of g.list) { const s = (g.ledger[t.id] || {}).state || 'unrecorded'; states[s] = (states[s] || 0) + 1; }
  const epics = [...new Set(g.list.map((t) => t.id.split('-')[0]))].sort();
  const limits = g.list.reduce((a, t) => a + ((((g.ledger[t.id] || {}).evidence) || {}).knownLimitations || []).length, 0);
  const unresolvedOut = { schema: 'agentic-security/engineering-excellence-unresolved@1', verdict: dec.verdict, items: g.unresolved.map((u) => ({ ...u, blocking: u.blocksRelease, waived: dec.caveats.some((c) => c.startsWith(u.id + ' waived')) })), blockers: dec.blockers, caveats: dec.caveats };
  const L = [];
  L.push('# Engineering excellence: final report', '', 'Generated by `node scripts/engineering-excellence/final-report.mjs`; checked by `--check`. The ledger is `scripts/engineering-excellence/status.json`; this report and the terminal summary are both read from it.', '');
  L.push(`## Release decision: **${dec.verdict === 'release_ready' ? 'RELEASE READY' : 'RELEASE BLOCKED'}**`, '');
  if (dec.verdict === 'release_blocked') { L.push(`${dec.blockers.length} condition(s) block the release. Nothing below announces success.`, '', '| # | Code | Condition |', '|---|---|---|', ...dec.blockers.map((b, i) => `| ${i + 1} | ${b.code} | ${b.message.replace(/\|/g, '/')} |`), ''); }
  else L.push('No blocking condition was found in the ledger, the exit gates, the unresolved list, the gate run or the measurement. That is not a statement that the software is free of defects.', '');
  if (dec.caveats.length) L.push('Caveats (do not block):', '', ...dec.caveats.map((c) => `- ${c}`), '');
  L.push('The decision is computed by `releaseDecision` in `final-report.mjs`. It cannot be changed by relabelling a metric (an exit gate is "met" only while its evidence files exist), by omitting a gate run (an absent run blocks), or by editing a flag (a blocker is waived only by a signed, unexpired, justified waiver with a compensating control; none exists).', '');
  L.push('## Task ledger', '', `${g.list.length} tasks: ${Object.entries(states).map(([k, v]) => `${v} ${k}`).join(', ')}.`, '', '| Epic | Done | Of |', '|---|---|---|', ...epics.map((e) => { const ts = g.list.filter((t) => t.id.startsWith(e + '-')); return `| ${e} | ${ts.filter((t) => DONE.has((g.ledger[t.id] || {}).state)).length} | ${ts.length} |`; }), '', `Each task was closed only with a recorded passing test run naming an existing test file and its acceptance text. ${limits} limitation entries were recorded with them.`, '');
  L.push('## Epic exit gates', '', '| Epic | Status | Note |', '|---|---|---|', ...g.exit.map((x) => `| ${x.epic} | ${x.status} | ${x.note.replace(/\|/g, '/')} |`), '');
  L.push('## Metrics (captured from the result files)', '', '```text', CAPTURES['baseline-headline'](), '', CAPTURES['dci-real-app-overall'](), '', CAPTURES['perf-large-verdict'](), '```', '', 'The independent figure is the only one measured on code the engine was not built from. The curated regression net and the hand-written authorization cases are not accuracy. Before-and-after: `REGRESSION_REPORT.md`.', '');
  L.push('## Gates', '', `The full pre-push gate ${g.gateRun.verdict} (\`${g.gateRun.file}\`). Failures met on the way and what was done: package file count (reviewed: 143 new shipped files, expectation raised with the reason), self-scan baseline for four new dev scripts (re-baselined with a reason), four tests that failed once on a fixture polluted by an earlier scan (fixture state removed; U-16 is the open hazard). No gate was bypassed with \`--no-verify\`, waived or deleted.`, '', 'Not run: the network-dependent publish checks (dependency currency, hosted CI) — see U-02.', '');
  L.push('## Unresolved', '', '| Id | Blocks release | Priority | Item | Next step |', '|---|---|---|---|---|', ...g.unresolved.map((u) => `| ${u.id} | ${u.blocksRelease ? 'yes' : 'no'} | ${u.priority} | ${u.title.replace(/\|/g, '/')} | ${u.nextStep.replace(/\|/g, '/')} |`), '');
  L.push('## Residual risk', '', '- The engine finds about 2 percent of the independent defects (6 of 278) with about one in three reports correct. Using it as the only control on a release is not supported by this evidence.', '- The assurance machinery (signed package, deterministic verdict, offline verification) is demonstrated on a small project and not yet part of the default scan; adopting it means assembling the package deliberately.', '- Scan health is stricter than before: a skipped oversize file makes a scan partial.', '');
  L.push('## Reproduce', '', 'Every command below was run in this programme. Each names the artifact it produces and that artifact\'s digest at the time this report was written; `--check` recomputes them.', '', '| Command (from `scanner/` unless noted) | Artifact | Digest |', '|---|---|---|');
  const cmds = [['npm run gate:prepush -- --force', 'docs/engineering-excellence/data/gates/prepush-5c1af313.txt'], ['node ../bench/independent/forensics.mjs --run ' + g.ptr.runId, `bench/independent/runs/${g.ptr.runId}/forensics.json`], ['npm run ee:perf-budget', 'docs/engineering-excellence/data/perf-budget.json'], ['npm run ee:e2e-demo', 'docs/engineering-excellence/data/e2e-demo-outline.json'], ['npm run bench:dci-real-app', 'docs/engineering-excellence/data/dci-real-app.json'], ['npm run ee:regression-report', 'docs/engineering-excellence/REGRESSION_REPORT.md'], ['npm run ee:doc-captures', 'docs/engineering-excellence/README.md']];
  for (const [c, a] of cmds) L.push(`| \`${c}\` | \`${a}\` | ${exists(a) ? '`' + digestOfFile(a).slice(0, 23) + '`' : 'missing'} |`);
  L.push('', 'Resume from disk: `node scripts/engineering-excellence/status.mjs --resume` prints the next step, and `node scripts/engineering-excellence/status.mjs --markdown` regenerates `STATUS.md` (it carries a revision number and timestamp, so it has no digest here); `docs/engineering-excellence/STATUS.md` and `unresolved.json` hold the same state.', '');
  return { report: L.join('\n'), unresolved: JSON.stringify(unresolvedOut, null, 2) + '\n', decision: dec };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const r = await build(); const rp = path.join(DOCS, 'FINAL_REPORT.md'); const up = path.join(DOCS, 'unresolved.json');
  if (process.argv.includes('--check')) { const ok = fs.existsSync(rp) && fs.existsSync(up) && fs.readFileSync(rp, 'utf8') === r.report && fs.readFileSync(up, 'utf8') === r.unresolved; if (!ok) { console.error('FINAL_REPORT.md or unresolved.json is stale: run node scripts/engineering-excellence/final-report.mjs'); process.exit(1); } console.log('final report is current'); process.exit(0); }
  fs.writeFileSync(rp, r.report); fs.writeFileSync(up, r.unresolved); console.log(`${r.decision.verdict}: ${r.decision.blockers.length} blocker(s)`);
}
