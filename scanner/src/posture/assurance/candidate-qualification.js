// Candidate qualification (threat-model PRD FR-10.1, FR-10.2, section 6 "Candidate release gates").
//
// A release claim is qualified for an EXACT scanner, target artifact, deployment profile, policy and observation window, and only for
// the cases it passes. The packet carries those identities and one record per required case (requirement, gate, expected and observed
// outcome, verdict and reason code, artifact and policy bindings, evidence digests, expiry, owner). The decision is recomputed here from
// the evidence, never read from the packet: a case whose bindings do not match the packet's target, that has expired, whose feed is
// stale or whose legitimate control failed keeps its gate open, and the candidate is qualified only when every required gate is met.
// A higher-level status never inherits a pass from a lower-level one: a gate with no case is unresolved, not met.
//
// Outcome per case: met (the expectation held), violated (it did not), unresolved (evidence missing, stale, expired or differently
// scoped) or blocked (a prerequisite such as an attested runner or an independent population is unavailable). Pure apart from the
// optional signed write, which is atomic.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const CANDIDATE_SCHEMA = 'agentic-security/candidate-packet';
const CANDIDATE_VERSION = 1;
export const GATES = Object.freeze({
  'G-01': 'code regression', 'G-02': 'scan and graph coverage', 'G-03': 'prevention and repair', 'G-04': 'evidence and harness integrity',
  'G-05': 'detection and response', 'G-06': 'independent accuracy', 'G-07': 'operability',
});
const EXPECT = new Set(['positive', 'negative', 'legitimate']);
const DOMAIN = `${CANDIDATE_SCHEMA}@1\n`;
const canon = (v) => {
  if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  // an undefined value is absent, exactly as JSON would carry it, so a packet and its JSON round trip have one digest
  return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
};
export const packetDigest = (p) => `sha256:${crypto.createHash('sha256').update(canon({ ...p, signature: undefined })).digest('hex')}`;

/** Sign a packet with an Ed25519 private key; `verifyCandidatePacket` checks it with the key the caller trusts. */
export function signCandidatePacket(packet, privateKeyPem) {
  const body = { schema: CANDIDATE_SCHEMA, version: CANDIDATE_VERSION, ...packet };
  delete body.signature;
  return { ...body, signature: crypto.sign(null, Buffer.from(DOMAIN + canon(body)), privateKeyPem).toString('base64') };
}
export function verifyCandidatePacket(packet, publicKeyPem) {
  if (!packet || packet.schema !== CANDIDATE_SCHEMA || packet.version !== CANDIDATE_VERSION) return { ok: false, code: 'FORMAT' };
  const { signature, ...body } = packet;
  try { return crypto.verify(null, Buffer.from(DOMAIN + canon(body)), publicKeyPem, Buffer.from(String(signature), 'base64')) ? { ok: true, code: 'VERIFIED' } : { ok: false, code: 'SIGNATURE' }; } catch { return { ok: false, code: 'SIGNATURE' }; }
}

/** Judge one case record against the packet's target. */
function judgeCase(c, packet, now) {
  const t = packet.target || {};
  const miss = [];
  for (const k of ['caseId', 'requirement', 'gate', 'expected', 'verdict', 'owner', 'expires']) if (c[k] === undefined || c[k] === null || c[k] === '') miss.push(k);
  if (miss.length) return { outcome: 'unresolved', reason: `missing ${miss.join(', ')}`, owner: c.owner ?? null };
  if (!GATES[c.gate] || !EXPECT.has(c.expected)) return { outcome: 'unresolved', reason: 'unknown gate or expectation' };
  if (c.blocked) return { outcome: 'blocked', reason: String(c.blocked) };
  if (!(Date.parse(c.expires) > now)) return { outcome: 'unresolved', reason: 'the evidence has expired' };
  if (c.artifactDigest && t.artifactDigest && c.artifactDigest !== t.artifactDigest) return { outcome: 'unresolved', reason: 'the evidence was produced against another artifact' };
  if (c.policyDigest && t.policyDigest && c.policyDigest !== t.policyDigest) return { outcome: 'unresolved', reason: 'the evidence was produced under another policy' };
  if (c.scannerBundle && packet.scanner?.bundleDigest && c.scannerBundle !== packet.scanner.bundleDigest) return { outcome: 'unresolved', reason: 'the evidence came from another scanner bundle' };
  if (c.requiresArtifactBinding !== false && !c.artifactDigest) return { outcome: 'unresolved', reason: 'the evidence is not bound to an artifact' };
  const o = c.observed;
  if (!o || typeof o !== 'object') return { outcome: 'unresolved', reason: 'no observation is recorded' };
  // the observation and the expectation stay separately inspectable; met/violated is derived, not asserted
  const forbidden = o.forbiddenEffect === true; const legit = o.legitimateEffect === true;
  if (c.expected === 'positive') return forbidden ? { outcome: 'met', reason: 'the vulnerable control reproduced the forbidden effect' } : { outcome: 'violated', reason: 'the vulnerable control did not reproduce the effect, so the fixture shows nothing' };
  if (c.expected === 'negative') return forbidden ? { outcome: 'violated', reason: 'the forbidden effect occurred on the fixed artifact' } : { outcome: 'met', reason: 'no forbidden effect' };
  return legit && !forbidden ? { outcome: 'met', reason: 'the legitimate operation succeeded' } : { outcome: 'violated', reason: 'the legitimate operation did not succeed' };
}

/**
 * Recompute every gate from the packet's evidence.
 * @param {object} packet
 * @param {{requiredGates?:string[], requiredCases?:string[], now?:number, maxFeedAgeMs?:number}} o
 * @returns {{status:'qualified'|'not-qualified', gates:object, cases:object[], blockers:object[]}}
 */
export function evaluateCandidate(packet, { requiredGates = Object.keys(GATES), requiredCases = [], now = Date.now(), maxFeedAgeMs = 15 * 60 * 1000 } = {}) {
  const cases = (packet.cases || []).map((c) => ({ caseId: c.caseId ?? null, gate: c.gate ?? null, requirement: c.requirement ?? null, owner: c.owner ?? null, ...judgeCase(c, packet, now) }));
  const blockers = [];
  for (const id of requiredCases) if (!cases.some((c) => c.caseId === id)) { cases.push({ caseId: id, gate: null, outcome: 'unresolved', reason: 'a required case has no record' }); blockers.push({ gate: null, caseId: id, reason: 'missing required case' }); }
  // gate-level evidence that is not a case
  const extra = {};
  if (!packet.scope || packet.scope.status !== 'satisfied') extra['G-02'] = { outcome: 'unresolved', reason: packet.scope ? `the scope reconciliation is ${packet.scope.status}` : 'no scope reconciliation is in the packet' };
  if (!packet.runner || packet.runner.attested !== true) extra['G-04'] = { outcome: 'blocked', reason: packet.runner?.reason || 'the runner did not attest the confinement the execution cases need' };
  const ev = packet.evaluation;
  if (!ev || ev.status !== 'measured') extra['G-06'] = { outcome: 'blocked', reason: ev?.reason || 'independent accuracy is unmeasured for this candidate' };
  else if (ev.meetsFloors !== true) extra['G-06'] = { outcome: 'violated', reason: 'the measured population does not meet the registered floors' };
  for (const f of packet.telemetry?.feeds || []) {
    if (!f.lastHeartbeat || now - Date.parse(f.lastHeartbeat) > maxFeedAgeMs) { extra['G-05'] = { outcome: 'unresolved', reason: `feed ${f.name} is stale or has no heartbeat` }; break; }
  }
  const gates = {};
  for (const g of requiredGates) {
    const mine = cases.filter((c) => c.gate === g);
    const rank = { violated: 3, blocked: 2, unresolved: 1, met: 0 };
    let worst = mine.reduce((w, c) => (rank[c.outcome] > rank[w] ? c.outcome : w), 'met');
    const reasons = mine.filter((c) => c.outcome !== 'met').map((c) => `${c.caseId}: ${c.reason}`);
    if (extra[g]) { if (rank[extra[g].outcome] > rank[worst]) worst = extra[g].outcome; reasons.push(extra[g].reason); }
    // no evidence is not a pass: a gate with no case and no gate-level evidence stays unresolved
    if (!mine.length && !extra[g] && !(g === 'G-02' && packet.scope?.status === 'satisfied') && !(g === 'G-04' && packet.runner?.attested === true) && !(g === 'G-06' && ev?.status === 'measured')) { worst = 'unresolved'; reasons.push('no evidence for this gate'); }
    gates[g] = { name: GATES[g], outcome: worst, reasons };
    if (worst !== 'met') blockers.push({ gate: g, reason: reasons.join('; ') });
  }
  return { status: blockers.length ? 'not-qualified' : 'qualified', scope: packet.target ? { ...packet.target } : null, gates, cases, blockers };
}

/** Write a decision atomically; an identical retried write leaves the same bytes. */
export function writeCandidateDecision(file, decision) {
  const body = `${canon(decision)}\n`;
  try { if (fs.readFileSync(file, 'utf8') === body) return { written: false, unchanged: true }; } catch { /* absent */ }
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`);
  fs.writeFileSync(tmp, body, { mode: 0o644 });
  fs.renameSync(tmp, file);
  return { written: true, unchanged: false };
}
