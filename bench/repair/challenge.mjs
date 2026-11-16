#!/usr/bin/env node
// The repair challenge gate (verified-remediation PRD FR-08, AC-08.1 to AC-08.5).
//
//   node bench/repair/challenge.mjs                     print the report
//   node bench/repair/challenge.mjs --check             compare with challenge-baseline.json; exit 1 on any drift or any unsafe acceptance
//   node bench/repair/challenge.mjs --update-baseline   record the current outcome (review the diff: a baseline is evidence)
//   --require-execution                                 exit 3 instead of reporting not-run where the trust boundary cannot execute
//
// Every case runs through the real coordinator: plan from the fixture's profile, one candidate (the case's patch) through the scope gate,
// the application oracles in the trust boundary, the central verifier and the sealed set. Scored:
//   unsafe accepted   an ineffective patch promoted to verified-for-contract (must be 0)
//   caught as expected the obligation the case declares independently is among the failing ones (or the scope gate refused it)
//   safe rejected     a legitimate repair not promoted
// Synthetic regression evidence: the cases and the verifier share authors. It is not an accuracy figure.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CASES, APPS } from './challenge-cases.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const BASELINE = process.env.REPAIR_CHALLENGE_BASELINE || path.join(HERE, 'challenge-baseline.json');
const S = path.join(REPO, 'scanner', 'src');
const { planRepair, runRepair } = await import(path.join(S, 'repair', 'coordinator.js'));
const { queueProposer } = await import(path.join(S, 'repair', 'candidates.js'));
const { resolveAssuranceConfig } = await import(path.join(S, 'posture', 'assurance', 'config.js'));
const { snapshotSource } = await import(path.join(S, 'repair', 'contracts.js'));

const argv = process.argv.slice(2);
const known = new Set(['--check', '--update-baseline', '--require-execution', '--json', '--only']);
for (const a of argv) if (a.startsWith('--') && !known.has(a)) { console.error(`unknown flag ${a}`); process.exit(2); }
const only = argv.includes('--only') ? argv[argv.indexOf('--only') + 1] : null;

function setupApp(name) {
  const app = APPS[name];
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `repair-challenge-${name}-`));
  fs.cpSync(path.join(REPO, app.fixture), root, { recursive: true });
  const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
  const p = planRepair({ root, finding: { findingId: `challenge:${name}`, file: profile.application.entry }, family: app.family, profile, profileOrigin: 'repository-file' });
  if (!p.plan) throw new Error(`${name}: the plan failed: ${[...p.problems, ...p.blocked].join('; ')}`);
  return { root, plan: p.plan, profile };
}

export async function runChallenge() {
  const config = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });
  const apps = {}; const rows = [];
  try {
    for (const c of CASES) {
      if (only && c.id !== only) continue;
      apps[c.app] ??= setupApp(c.app);
      const { root, plan } = apps[c.app];
      const original = snapshotSource(root, { application: plan.contract.profile.application }).files;
      const files = c.edit({ ...original });
      if (Object.entries(files).every(([k, v]) => original[k] === v)) throw new Error(`${c.id}: the edit changed nothing`);
      const r = await runRepair({ root, plan, config, proposers: [queueProposer([{ files, strategy: c.shape }], `challenge:${c.id}`)], policy: { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 1, strategiesPerRound: 1 } } });
      const rec = r.record;
      const cand = rec.candidates[0] || null;
      const failed = (cand?.results || []).filter((x) => x.status !== 'passed').map((x) => x.obligation);
      const caughtBy = cand?.status === 'refused' ? 'scope-refusal' : (failed.join(',') || null);
      const accepted = rec.disposition === 'verified-for-contract';
      const expectOk = c.label === 'safe' ? accepted : (!accepted && (c.expect.refused ? caughtBy === 'scope-refusal' : failed.includes(c.expect.obligation)));
      rows.push({ id: c.id, label: c.label, shape: c.shape, disposition: rec.disposition, completion: rec.completion, caughtBy, accepted, asExpected: expectOk, ...(rec.disposition === 'blocked' ? { blockedReason: rec.reasons.join('; ').slice(0, 200) } : {}) });
    }
  } finally {
    for (const a of Object.values(apps)) try { fs.rmSync(a.root, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  const blocked = rows.filter((r) => r.disposition === 'blocked' && r.completion === 'unavailable');
  const summary = {
    cases: rows.length, unsafe: rows.filter((r) => r.label === 'unsafe').length, safe: rows.filter((r) => r.label === 'safe').length,
    unsafeAccepted: rows.filter((r) => r.label === 'unsafe' && r.accepted).length,
    safeRejected: rows.filter((r) => r.label === 'safe' && !r.accepted).length,
    caughtAsExpected: rows.filter((r) => r.label === 'unsafe' && r.asExpected).length,
    notExecuted: blocked.length,
  };
  return { summary, rows, evidence: 'synthetic regression corpus (shared authorship with the verifier); not an independent accuracy measurement' };
}

const res = await runChallenge();
const line = `repair challenge: ${res.summary.cases} cases (unsafe ${res.summary.unsafe}, safe ${res.summary.safe}); unsafe accepted ${res.summary.unsafeAccepted}/${res.summary.unsafe}; caught by the expected obligation ${res.summary.caughtAsExpected}/${res.summary.unsafe}; safe rejected ${res.summary.safeRejected}/${res.summary.safe}; not executed ${res.summary.notExecuted}`;
if (argv.includes('--json')) console.log(JSON.stringify(res, null, 2));
else { for (const r of res.rows) console.log(`${r.asExpected ? 'ok  ' : 'MISS'} ${r.id.padEnd(36)} ${r.label.padEnd(6)} ${r.disposition.padEnd(22)} ${r.caughtBy || ''}${r.blockedReason ? `  (${r.blockedReason})` : ''}`); console.log(line); }
if (res.summary.notExecuted) {
  console.log(`not executed on this host: ${res.summary.notExecuted} case(s) were blocked before execution; this is not a pass`);
  process.exit(argv.includes('--require-execution') ? 3 : 0);
}
const shape = (r) => ({ summary: r.summary, rows: r.rows.map((x) => ({ id: x.id, label: x.label, disposition: x.disposition, caughtBy: x.caughtBy, asExpected: x.asExpected })) });
if (argv.includes('--update-baseline')) {
  fs.writeFileSync(BASELINE, JSON.stringify({ ...shape(res), evidence: res.evidence }, null, 2) + '\n');
  console.log(`wrote ${path.relative(REPO, BASELINE)}`);
} else if (argv.includes('--check')) {
  let base;
  try { base = JSON.parse(fs.readFileSync(BASELINE, 'utf8')); } catch { console.error(`no baseline at ${BASELINE}`); process.exit(1); }
  const now = shape(res);
  const drift = [];
  if (res.summary.unsafeAccepted) drift.push(`${res.summary.unsafeAccepted} unsafe patch(es) accepted`);
  const byId = Object.fromEntries(base.rows.map((r) => [r.id, r]));
  for (const r of now.rows) { const b = byId[r.id]; if (!b) drift.push(`${r.id}: not in the baseline`); else if (JSON.stringify(b) !== JSON.stringify(r)) drift.push(`${r.id}: ${JSON.stringify(b)} -> ${JSON.stringify(r)}`); }
  if (!only) for (const id of Object.keys(byId)) if (!now.rows.some((r) => r.id === id)) drift.push(`${id}: missing`);
  if (drift.length) { console.error(`repair challenge drift:\n  ${drift.join('\n  ')}`); process.exit(1); }
  console.log('repair challenge matches its baseline');
}
