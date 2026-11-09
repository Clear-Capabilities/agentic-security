#!/usr/bin/env node
// The local candidate qualification for the threat-model pilot (PRD FR-08, FR-10, section 6).
//
//   node bench/threat-model-pilot/qualify.mjs [--out <dir>] [--private-key <pem>] [--scope <reconciliation.json>] [--json]
//
// Runs the pilot fixtures now (loopback only, synthetic tenants, no credentials of value), assembles one signed candidate packet per
// deployment identity, recomputes every gate with `release-package qualify`'s logic and writes, per identity, `<id>.packet.json`,
// `<id>.decision.json` and the public key that verifies the packets. G-05 requires staging evidence, so local detection cases are
// reported but never satisfy it. Gates that need a staging deployment, an independently held population or an attested runner stay
// blocked with their reasons: the expected result on a developer host is "not qualified" with G-03 met for the export chain and the
// database search, and the run is a regression check of the fixtures, not a release claim.
//
// Exit codes: 0 every local case met its expectation; 1 a local case was violated or unresolved (a fixture or engine regression);
// 2 a usage problem.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assemblePilotPacket } from '../../scanner/test/fixtures/pilot/assemble-packet.mjs';
import { evaluateCandidate, signCandidatePacket, writeCandidateDecision } from '../../scanner/src/posture/assurance/candidate-qualification.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const REQUIRED_TIERS = { 'G-05': 'staging' };

function parse(argv) {
  const o = { json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
    else if (['--out', '--private-key', '--scope'].includes(a) && argv[i + 1]) o[a.slice(2)] = argv[++i];
    else return { error: `unknown or incomplete argument ${a}` };
  }
  return o;
}

export async function runQualification({ out, privateKey = null, scope = null, now = Date.now() } = {}) {
  const bundle = path.join(ROOT, 'scanner/dist/agentic-security.mjs');
  const scannerBundle = fs.existsSync(bundle) ? `sha256:${crypto.createHash('sha256').update(fs.readFileSync(bundle)).digest('hex')}` : null;
  let key = privateKey; let publicPem;
  if (!key) {
    const kp = crypto.generateKeyPairSync('ed25519');
    key = kp.privateKey.export({ type: 'pkcs8', format: 'pem' });
    publicPem = kp.publicKey.export({ type: 'spki', format: 'pem' });
  } else publicPem = crypto.createPublicKey(key).export({ type: 'spki', format: 'pem' });
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'public.pem'), publicPem);
  const packets = await assemblePilotPacket({ now, scannerBundle });
  const results = {};
  for (const [id, p] of Object.entries(packets)) {
    const packet = {
      ...p,
      ...(scope ? { scope } : {}),
      runner: { attested: false, reason: `${os.platform()} host: this run does not attest the confinement the execution cases need` },
      evaluation: { status: 'unmeasured', reason: 'no independently held labels for this candidate (FR-09)' },
    };
    const signed = signCandidatePacket(packet, key);
    fs.writeFileSync(path.join(out, `${id}.packet.json`), `${JSON.stringify(signed, null, 2)}\n`);
    const decision = evaluateCandidate(signed, { requiredTiers: REQUIRED_TIERS, now });
    writeCandidateDecision(path.join(out, `${id}.decision.json`), decision);
    results[id] = decision;
  }
  const regressions = Object.entries(results).flatMap(([id, d]) => d.cases.filter((c) => c.tier === 'local' && c.outcome !== 'met' && c.outcome !== 'blocked').map((c) => ({ id, caseId: c.caseId, outcome: c.outcome, reason: c.reason })));
  return { out, scannerBundle, results, regressions };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const o = parse(process.argv.slice(2));
  if (o.error) { console.error(o.error); process.exit(2); }
  let privateKey = null; let scope = null;
  try {
    if (o['private-key']) privateKey = fs.readFileSync(path.resolve(o['private-key']), 'utf8');
    if (o.scope) scope = JSON.parse(fs.readFileSync(path.resolve(o.scope), 'utf8'));
  } catch (e) { console.error(`Could not read the input: ${e.message}`); process.exit(2); }
  const out = path.resolve(o.out || fs.mkdtempSync(path.join(os.tmpdir(), 'threat-model-pilot-')));
  const r = await runQualification({ out, privateKey, scope });
  if (o.json) console.log(JSON.stringify({ out: r.out, scannerBundle: r.scannerBundle, regressions: r.regressions, decisions: Object.fromEntries(Object.entries(r.results).map(([k, d]) => [k, { status: d.status, gates: Object.fromEntries(Object.entries(d.gates).map(([g, x]) => [g, x.outcome])), tiers: d.tiers }])) }, null, 2));
  else {
    console.log(`threat-model pilot qualification, scanner bundle ${r.scannerBundle ? r.scannerBundle.slice(0, 19) : 'not built'}; packets in ${r.out}`);
    for (const [id, d] of Object.entries(r.results)) {
      console.log(`${id}: ${d.status} (local ${d.tiers.local}, staging ${d.tiers.staging}, independent ${d.tiers.independent} cases)`);
      for (const [g, x] of Object.entries(d.gates)) console.log(`  ${g} ${x.name}: ${x.outcome}${x.reasons.length ? ` (${x.reasons.join('; ')})` : ''}`);
    }
    for (const x of r.regressions) console.log(`REGRESSION ${x.id} ${x.caseId}: ${x.outcome}, ${x.reason}`);
    console.log(`verify a packet: agentic-security release-package qualify ${path.join(r.out, 'records-service.packet.json')} --public-key ${path.join(r.out, 'public.pem')} --require-tier G-05=staging`);
  }
  process.exit(r.regressions.length ? 1 : 0);
}
