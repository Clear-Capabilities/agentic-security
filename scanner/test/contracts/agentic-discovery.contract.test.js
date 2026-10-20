// Contract test for agentic discovery (docs/reference/agentic-discovery-contract.md).
//
// Recorded model replies (fixtures/model-replay/hunt.json) are played through the real pipeline with an injected model call. The report
// and its coverage block are held to the page's tables in both directions, and the rules the page states are pinned: coverage is part of
// the output, a silent panel never refutes, severity comes from evidence, every budget is reported, and no endpoint means every run degrades.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildProjectIR } from '../../src/ir/index.js';
import { runDiscovery } from '../../src/discovery/index.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { loadReplay, replayPipeline } from '../helpers/model-replay.js';
import { mkTestTmp } from '../helpers/tmp.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const PAGE = readPage('docs/reference/agentic-discovery-contract.md');
const R = loadReplay('hunt');
const FILES = {
  'app.js': "const db=require('./db');\nfunction get(req,res){\n  const q = \"SELECT * FROM t WHERE id=\" + req.query.id;\n  db.query(q);\n}\nmodule.exports={get};\n",
  'db.js': 'exports.query=(q)=>q;\n',
};
const { perFile, callGraph } = buildProjectIR(FILES);
const hunt = async (replies, opts = {}) => {
  const p = replies === null ? { llmInvoke: undefined, calls: {} } : replayPipeline(replies);
  const noEndpoint = replies === null;
  const was = process.env.AGENTIC_SECURITY_LLM_ENDPOINT; if (noEndpoint) delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  try {
    const report = await runDiscovery({ perFileIR: perFile, callGraph, fileContents: FILES }, { llmInvoke: p.llmInvoke, lenses: ['injection'], ...opts });
    return { report, calls: p.calls };
  } finally { if (was !== undefined) process.env.AGENTIC_SECURITY_LLM_ENDPOINT = was; }
};
const kept = { hunter: R.hunter.injection, votes: [R.vote.keep] };

test('contract: the report, its coverage block and a fresh candidate have exactly the documented fields', async () => {
  const { report } = await hunt(kept);
  sameFields(report, fieldsUnder(PAGE, 'Report'), 'report', ['promotions', 'invariantProposals']);
  sameFields(report.coverage, fieldsUnder(PAGE, 'Coverage'), 'coverage');
  sameFields(report.focusAreas[0], ['id', 'label', 'files', 'size'], 'focus area');
  sameFields(report.runs[0], ['focusAreaId', 'lens', 'degraded', 'reason', 'candidateCount'], 'run');
  assert.equal(report.schema, 'agentic-security/discovery@1');
  assert.equal(report.fresh.length, 1);
  sameFields(report.fresh[0].discovery, fieldsUnder(PAGE, 'The `discovery` object'), 'discovery object');
  for (const w of ['focusAreas', 'runs', 'verificationRecords']) assert.ok(PAGE.includes(`\`${w}\``));
});

test('contract: the comparison itself fails when a field is added or dropped', async () => {
  const { report } = await hunt(kept);
  const documented = fieldsUnder(PAGE, 'Coverage');
  assert.throws(() => sameFields({ ...report.coverage, extra: 1 }, documented, 'x'));
  const { llmCalls, ...rest } = report.coverage;
  assert.throws(() => sameFields(rest, documented, 'x'));
  assert.ok(llmCalls >= 0);
});

test('contract: an unconfirmed candidate is low severity, and the verification record is advisory (not-run, never confirmed)', async () => {
  const { report } = await hunt(kept);
  assert.equal(report.fresh[0].severity, 'low');
  assert.equal(report.fresh[0].discovery.confirmation.tier, 'unconfirmed');
  assert.equal(report.coverage.confirmedByTier.unconfirmed, 1);
  assert.equal(report.verificationRecords.length, 1);
  assert.ok(report.coverage.reasons.some(r => /corroborated nothing/.test(r)), 'a run in which nothing was corroborated says so');
});

test('contract: a majority of refuting votes removes the candidate into refutedCandidates, which are raw candidates and not findings', async () => {
  const { report } = await hunt({ hunter: R.hunter.injection, votes: [R.vote.refute] });
  assert.equal(report.fresh.length, 0);
  assert.equal(report.refutedCandidates.length, 1);
  assert.equal(report.refutedCandidates[0].vuln, undefined, 'a refuted candidate has no finding shape');
  assert.equal(report.refutedCandidates[0].severity, undefined);
});

test('contract: a panel that returns no votes never refutes, is counted, and is said out loud', async () => {
  const { report } = await hunt({ hunter: R.hunter.injection, votes: [] });
  assert.equal(report.fresh.length, 1);
  assert.equal(report.coverage.undecidedPanels, 1);
  assert.ok(report.coverage.reasons.some(r => /returned no votes/.test(r)));
});

test('contract: a failed model call is a degraded run with its reason, not a clean result', async () => {
  const { report } = await hunt({ hunter: R.hunter.injection, throwOn: 'hunter' });
  assert.equal(report.coverage.degradedRuns, 1);
  assert.equal(report.coverage.areasHunted, 0);
  assert.equal(report.runs[0].degraded, true);
  assert.match(report.runs[0].reason, /hunter llm call failed/);
  assert.ok(report.coverage.reasons.length >= 1);
  const unparseable = (await hunt({ hunter: 'I could not find anything' })).report;
  assert.equal(unparseable.runs[0].degraded, true);
  assert.match(unparseable.runs[0].reason, /not parseable/);
});

test('contract: no endpoint means every run degrades and the report says so', async () => {
  const { report } = await hunt(null);
  assert.equal(report.coverage.degradedRuns, report.runs.length);
  assert.equal(report.coverage.areasHunted, 0);
  assert.equal(report.fresh.length, 0);
  assert.ok(report.coverage.reasons.some(r => /ENDPOINT not set/.test(r)));
});

test('contract: the call budget, the candidate cap and an unknown lens are each reported, never applied quietly', async () => {
  const budget = (await hunt(kept, { maxLlmCalls: 2 })).report;
  assert.equal(budget.coverage.budgetExhausted, true);
  assert.ok(budget.coverage.reasons.some(r => /RUN INCOMPLETE/.test(r)));
  const capped = (await hunt({ hunter: R.hunter.two, votes: [R.vote.keep] }, { maxCandidates: 1 })).report;
  assert.equal(capped.coverage.candidatesCapped, 1);
  assert.ok(capped.coverage.reasons.some(r => /candidate cap/.test(r)));
  const bad = (await hunt(kept, { lenses: ['nope'] })).report;
  assert.equal(bad.runs.length, 0);
  assert.ok(bad.coverage.reasons.some(r => /unresolved lens key/.test(r)));
  assert.ok(bad.coverage.reasons.some(r => /nothing was hunted/.test(r)));
});

test('contract: a candidate with no file and line is discarded and counted in the reasons', async () => {
  const { report } = await hunt({ hunter: R.hunter['no-location'], votes: [R.vote.keep] });
  assert.equal(report.fresh.length, 0);
  assert.ok(report.coverage.reasons.some(r => /no usable file and line and were discarded/.test(r)));
});

test('contract: with confirmation switched off the report says severity is not evidence-derived', async () => {
  const { report } = await hunt(kept, { confirm: false });
  assert.ok(report.coverage.reasons.some(r => /DISABLED for this run/.test(r)));
});

test('contract: a refuted candidate is remembered and skipped next time, and forgetRefuted examines it again', async () => {
  const scanRoot = mkTestTmp('agsec-hunt-memory-');
  const refuting = { hunter: R.hunter.injection, votes: [R.vote.refute] };
  const first = (await hunt(refuting, { scanRoot })).report;
  assert.equal(first.refutedCandidates.length, 1);
  const second = (await hunt(refuting, { scanRoot })).report;
  assert.equal(second.coverage.rememberedRefutals, 1);
  assert.equal(second.refutedCandidates.length, 0, 'it was skipped, not examined again');
  const third = (await hunt(refuting, { scanRoot, forgetRefuted: true })).report;
  assert.equal(third.coverage.rememberedRefutals, 0);
  assert.equal(third.refutedCandidates.length, 1, 'forgotten, so examined again');
  assert.ok(PAGE.includes('--forget-refuted'));
});

test('contract: the command exits 0 with every run degraded and says so, and exits 2 over the file cap', () => {
  const dir = mkTestTmp('agsec-hunt-contract-');
  fs.writeFileSync(path.join(dir, 'app.js'), FILES['app.js']);
  fs.writeFileSync(path.join(dir, 'db.js'), FILES['db.js']);
  const env = { ...process.env }; delete env.AGENTIC_SECURITY_LLM_ENDPOINT;
  const r = spawnSync(process.execPath, [CLI, 'hunt', dir, '--lens', 'injection', '--no-memory'], { encoding: 'utf8', env, timeout: 120000 });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /EVERY hunter run degraded/);
  const big = mkTestTmp('agsec-hunt-big-');
  for (let i = 0; i < 2001; i++) fs.writeFileSync(path.join(big, `f${i}.js`), `exports.v${i}=${i};\n`);
  assert.equal(spawnSync(process.execPath, [CLI, 'hunt', big, '--no-memory'], { encoding: 'utf8', env, timeout: 120000 }).status, 2);
  for (const code of ['`0`', '`2`']) assert.ok(PAGE.includes(`| ${code} |`));
});
