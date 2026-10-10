#!/usr/bin/env node
// A bounded local tenant-invariant run (DOC-001.AC02): execute one reviewer-approved tenant-isolation contract against two
// synthetic applications and print what the durable-state assertions found.
//
//   node scripts/tenant-invariant-example.mjs
//
// The two applications are cases of the frozen synthetic benchmark (scanner/test/fixtures/invariant-benchmark/cases): one writes
// another tenant's invoice, the other rejects the write first. Each runs through the trust boundary only (no network,
// workspace-only writes, bounded sequence, requests and wall time). The `invariant-scenarios` and `verification-oracles` features
// are OFF by default; this script turns them on in this one process and nothing else. The contract is approved here by the
// benchmark's own fixture reviewer in a local ledger, which is how the benchmark does it, and is not a real review.
//
// Exit: 0 the defective application violated the contract and the sound one did not / 1 otherwise / 3 this host cannot run the
// trust boundary (stated, never reported as a pass).
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBenchmark } from '../scanner/src/posture/evaluation/invariant-ablation.js';
import { verifyInvariant } from '../scanner/src/posture/invariants/run.js';
import { emptyLedger, recordTransition } from '../scanner/src/posture/invariants/lifecycle.js';
import { resolveAssuranceConfig } from '../scanner/src/posture/assurance/config.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const loaded = loadBenchmark(path.join(HERE, '..', 'scanner', 'test', 'fixtures', 'invariant-benchmark'));
if (!loaded.ok) { console.error(`benchmark NOT intact: ${loaded.errors.join('; ')}`); process.exit(1); }

const config = resolveAssuranceConfig({ env: {}, overrides: { features: { 'invariant-scenarios': true, 'verification-oracles': true } } });
const commit = loaded.benchmark.manifestHash.slice('sha256:'.length, 'sha256:'.length + 40);
const REVIEWER = { id: 'benchmark-fixture-reviewer', kind: 'human' };
const POLICY = { id: 'benchmark-fixture-policy', reviewers: [REVIEWER.id] };

async function run(caseId) {
  const c = loaded.benchmark.cases.find((x) => x.id === caseId);
  const inv = c.contract;
  const proposed = recordTransition(emptyLedger(), { action: 'propose', invariant: inv, actor: { id: 'example-loader', kind: 'code' }, reason: 'synthetic fixture' });
  const approved = recordTransition(proposed.ledger, { action: 'approve', invariantId: inv.id, actor: REVIEWER, reason: 'synthetic fixture contract' }, { policy: POLICY });
  const res = await verifyInvariant({ invariant: inv, fixture: { files: c.files }, commit, config, ledger: approved.ledger });
  return { c, res };
}

let notRun = false;
const verdict = {};
for (const id of ['invoices-cross-tenant-update', 'tickets-tenant-scoped']) {
  const { c, res } = await run(id);
  const results = res.results || [];
  const settled = results.filter((r) => r.status === 'completed');
  if (res.status !== 'ok' || settled.length === 0) { notRun = true; console.log(`${id}: not executed (${res.reason || results[0]?.reason || res.status})`); continue; }
  const violated = results.filter((r) => r.classification?.kind === 'approved-violation');
  verdict[id] = violated.length > 0;
  console.log(`${id} [${c.class}]: ${results.length} bounded scenario(s) run, ${settled.length} settled, ${violated.length} approved violation(s)`);
  for (const r of violated.slice(0, 2)) console.log(`  ${r.kind}: ${String(r.reason).slice(0, 160)}`);
}
if (notRun) { console.log('at least one application was not executed; nothing was verified; this is not a pass'); process.exit(3); }
console.log('scope: these bounded scenarios on these two synthetic applications only; a clean result is not a proof of correctness');
process.exit(verdict['invoices-cross-tenant-update'] === true && verdict['tickets-tenant-scoped'] === false ? 0 : 1);
