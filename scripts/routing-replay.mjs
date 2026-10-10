#!/usr/bin/env node
// Offline routing replay reproduction (X-608.AC03): `npm run reproduce:routing` from scanner/, or `node scripts/routing-replay.mjs`.
//
// What this is. A network-free, seconds-long run that anyone with a checkout can repeat. It freezes a task set, pairs the baseline and
// proposed arms from recorded outcomes (no provider is called), judges the PRD section 5 routing gate, builds the replay report and the
// policy card, exports the hash-linked decision receipts, and then runs the CONTROLS that show the measuring path can tell a good result
// from a bad one:
//
//   synthetic-never-passes   a synthetic population must read `unmeasured`, however good its figures
//   gate-discriminates       the gate passes a generated population that meets the criteria and refuses ones that do not
//   cherry-pick              removing the worst pairs after the fact must invalidate the gate
//   dropped-failures         leaving failed outcomes out of the record must invalidate the gate
//   unbounded-replay         a paid replay with no bounded authorization must be refused before any call
//   reproducible             building the report twice must give the same bytes and a verifying receipt chain
//   control-honoured         disabling or pinning adaptive routing must change what routeModelWithPolicy returns
//
// What it is not. Every population here is GENERATED: no model was called and nobody adjudicated anything. It measures nothing about
// routing, claims no cost or quality advantage, and its `pass` in the gate-discriminates control describes the arithmetic, not a model.
//
// `--fault <control>` BREAKS one control's measuring path, to show the script can fail: with a fault injected it must exit 1 and
// name the control. Exit: 0 every control behaved, 1 a control did not, 2 usage.
//
// Options: --json (machine-readable), --receipts <file> (write the exported receipt chain), --fault <control>.

import * as fs from 'node:fs';
import { pairedScenario, CAND } from '../scanner/test/helpers/routing-promotion-fixtures.js';
import { replayPaired, evaluatePromotion } from '../scanner/src/posture/routing/promotion.js';
import { createReceiptLog, exportReceipts, verifyReceiptChain } from '../scanner/src/posture/routing/receipts.js';
import { buildRoutingReplayReport, renderRoutingReport, buildPolicyCard } from '../scanner/src/posture/routing/report.js';
import { resolveRoutingControl } from '../scanner/src/posture/routing/control.js';
import { routeModelWithPolicy, routeModelWithTrust } from '../scanner/src/posture/model-routing.js';
import { resolveAssuranceConfig } from '../scanner/src/posture/assurance/config.js';

const argv = process.argv.slice(2);
const JSON_OUT = argv.includes('--json');
const FAULTS = ['synthetic-never-passes', 'gate-discriminates', 'cherry-pick', 'dropped-failures', 'unbounded-replay', 'reproducible', 'control-honoured'];
const valueOf = (flag) => { const i = argv.indexOf(flag); return i >= 0 ? argv[i + 1] : null; };
const FAULT = valueOf('--fault');
const RECEIPTS_OUT = valueOf('--receipts');
if (FAULT !== null && !FAULTS.includes(FAULT)) { console.error(`usage: --fault <${FAULTS.join('|')}>`); process.exit(2); }
const known = new Set(['--json', '--receipts', '--fault']);
if (argv.some((a, i) => a.startsWith('--') ? !known.has(a) : !['--receipts', '--fault'].includes(argv[i - 1]))) { console.error('usage: routing-replay.mjs [--json] [--receipts <file>] [--fault <control>]'); process.exit(2); }

const CLOCK = () => '1970-01-01T00:00:00.000Z'; // fixed, so the receipts and hashes reproduce byte for byte
const GOOD = { n: 240, cand: { acc: 0.8, costUsd: 0.05, latencyMs: 1000 } };

async function judge(s, { outcomes = s.outcomes, mutateReplay = null, log = null } = {}) {
  const r = await replayPaired({ frozen: s.frozen, shadowRecords: s.shadowRecords, outcomes, log });
  const replay = mutateReplay ? mutateReplay(r) : r;
  return { replay, verdict: evaluatePromotion({ frozen: s.frozen, replay, log }) };
}

async function main() {
  // ---- the real measuring path, on a generated SYNTHETIC population
  const log = createReceiptLog({ now: CLOCK });
  const s = pairedScenario({ ...GOOD, synthetic: FAULT === 'synthetic-never-passes' ? false : true, failEvery: 20 });
  const { replay, verdict } = await judge(s, { log });
  const report = buildRoutingReplayReport({ frozen: s.frozen, replay, verdict, receipts: exportReceipts(log) });
  const card = buildPolicyCard({
    policy: { version: 'policy-1', objective: 'cost', minQualityLower: 0.8, maxIntervalWidth: 0.2, maxEvidenceAgeDays: 90, budget: { remainingUsd: 1 } }, report,
    control: resolveRoutingControl({ env: {}, options: {} }),
  });
  const receipts = exportReceipts(log);
  if (RECEIPTS_OUT) fs.writeFileSync(RECEIPTS_OUT, `${JSON.stringify(receipts, null, 2)}\n`);

  // ---- controls
  const controls = [];
  const control = (name, ok, detail) => controls.push({ name, ok: !!ok, detail });

  control('synthetic-never-passes', verdict.status === 'unmeasured' && verdict.claim.allowed === false, `a synthetic population with passing arithmetic reads '${verdict.status}', claim allowed: ${verdict.claim.allowed}`);

  const logic = async (over) => (await judge(pairedScenario({ ...GOOD, ...over, synthetic: false }))).verdict.status;
  const passes = await logic({});
  const degraded = await logic({ base: { acc: 0.9, costUsd: 0.1, latencyMs: 1000 }, cand: { acc: 0.8, costUsd: 0.02, latencyMs: 1000 } });
  const tooFew = await logic({ n: 120 });
  const faultedPass = FAULT === 'gate-discriminates' ? 'pass' : degraded; // a gate that passed a quality loss would not discriminate
  control('gate-discriminates', passes === 'pass' && faultedPass === 'fail' && tooFew === 'insufficient-population', `meets criteria: ${passes}; quality loss at far lower cost: ${faultedPass}; 120 tasks: ${tooFew}`);

  const failing = pairedScenario({ ...GOOD, synthetic: false, failEvery: 4 });
  const picked = await judge(failing, { mutateReplay: FAULT === 'cherry-pick' ? null : (r) => ({ ...r, pairs: r.pairs.filter((p) => p.proposed.kind !== 'failed') }) });
  control('cherry-pick', picked.verdict.status === 'invalid' && picked.verdict.invalidations.some((i) => i.code === 'replay-edited' || i.code === 'dropped-tasks'), `removing the failed pairs after the fact: ${picked.verdict.status}`);

  const failedIds = new Set(failing.outcomes.filter((o) => o.model === CAND && o.status === 'provider-error').map((o) => o.id));
  const dropped = await judge(failing, { outcomes: FAULT === 'dropped-failures' ? failing.outcomes : failing.outcomes.filter((o) => !failedIds.has(o.id)) });
  control('dropped-failures', dropped.verdict.status === 'invalid' && dropped.verdict.invalidations.some((i) => i.code === 'dropped-tasks'), `failed outcomes left out of the record: ${dropped.verdict.status}`);

  let calls = 0;
  const paid = await replayPaired({
    frozen: s.frozen, shadowRecords: s.shadowRecords, outcomes: [], invoke: async () => { calls += 1; return null; },
    authorization: FAULT === 'unbounded-replay' ? { authorizedBy: 'script', maxCalls: 1, maxUsd: 1, perCallUsdCeiling: 1 } : null,
  });
  control('unbounded-replay', paid.ok === false && paid.code === 'UNBOUNDED_REPLAY' && calls === 0, `a paid replay with no bounded authorization: ${paid.ok ? 'RAN' : paid.code}, ${calls} call(s) made`);

  const again = buildRoutingReplayReport({ frozen: s.frozen, replay, verdict, receipts: exportReceipts(log), generatedAt: FAULT === 'reproducible' ? new Date().toISOString() : null });
  control('reproducible', again.reportHash === report.reportHash && verifyReceiptChain(receipts.receipts).ok, `report hash ${again.reportHash === report.reportHash ? 'identical' : 'DIFFERS'} on a rebuild; receipt chain ${verifyReceiptChain(receipts.receipts).reason}`);

  const config = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_ASSURANCE_MODEL_ROUTING: '1' }, platform: 'linux' });
  const finding = { severity: 'high', cwe: 'CWE-79', file: 'src/a.js', stableId: 'f-1' };
  const plain = routeModelWithTrust(finding, null);
  const off = routeModelWithPolicy(finding, { config, routingOptions: { routing: FAULT === 'control-honoured' ? 'adaptive' : 'disabled' } });
  const pin = routeModelWithPolicy(finding, { config, routingOptions: { routing: 'pin:pinned-model' }, candidates: [], now: '2026-06-01T00:00:00Z' });
  control('control-honoured', off.model === plain.model && !('decision' in off) && off.routingControl?.mode === 'disabled' && pin.model === 'pinned-model' && pin.pinned === true,
    `disabled keeps '${off.model}' (mode ${off.routingControl?.mode ?? 'adaptive'}); pin gives '${pin.model}'`);

  const allOk = controls.every((c) => c.ok);
  const out = {
    synthetic: true, fault: FAULT, note: 'generated population: these figures exercise the routing replay path and measure nothing about routing',
    status: verdict.status, reportHash: report.reportHash, cardHash: card.cardHash, receiptsHead: receipts.headHash, receiptCount: receipts.count,
    denominators: report.denominators, claimsAllowed: report.claims.allowed, controls, allControlsBehaved: allOk,
  };
  if (JSON_OUT) { console.log(JSON.stringify(out, null, 2)); return allOk ? 0 : 1; }
  console.log('ROUTING REPLAY REPRODUCTION (offline, generated population). These figures exercise the path and measure nothing about routing.\n');
  console.log(renderRoutingReport(report));
  console.log(`\nPolicy card ${card.cardHash}; ${receipts.count} receipt(s), head ${receipts.headHash}${RECEIPTS_OUT ? `, written to ${RECEIPTS_OUT}` : ''}\n`);
  console.log('controls:');
  for (const c of controls) console.log(`  ${c.ok ? 'ok  ' : 'FAIL'} ${c.name.padEnd(24)} ${c.detail}`);
  console.log(allOk ? '\nevery control behaved: the routing replay path distinguishes good results from bad ones' : '\nA CONTROL FAILED: the routing replay path cannot be trusted until this is understood');
  return allOk ? 0 : 1;
}

main().then((c) => process.exit(c), (e) => { console.error(e?.stack || e); process.exit(1); });
