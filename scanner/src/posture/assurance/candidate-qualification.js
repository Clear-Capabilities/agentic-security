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
//
// Evidence tiers stay separate qualifications (PRD section 1 and section 8). Each case carries `tier`: `local` (loopback fixtures on
// this host, the default), `staging` (the owner-authorized staging deployment) or `independent` (an independently held population or
// reviewer). A gate the caller declares in `requiredTiers` is met only by cases of that tier: local evidence never satisfies a staging
// or independent gate by being more of it. A decision records the target it was computed for, and `revalidateDecision` refuses it for
// any other artifact, policy or scanner bundle, so an upgrade invalidates candidate-bound evidence and a rollback is qualified only by
// the earlier artifact's own unexpired decision (FR-10.4).
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
const TIERS = new Set(['local', 'staging', 'independent']);
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
  if (!packet || packet.schema !== CANDIDATE_SCHEMA) return { ok: false, code: 'FORMAT' };
  // a packet from a newer or older writer is refused by name, never read with this version's meaning
  if (packet.version !== CANDIDATE_VERSION) return { ok: false, code: 'UNSUPPORTED_VERSION', version: packet.version ?? null };
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
  if (c.tier !== undefined && !TIERS.has(c.tier)) return { outcome: 'unresolved', reason: 'unknown evidence tier' };
  if (c.blocked) return { outcome: 'blocked', reason: String(c.blocked) };
  if (!(Date.parse(c.expires) > now)) return { outcome: 'unresolved', reason: 'the evidence has expired' };
  if (c.artifactDigest && t.artifactDigest && c.artifactDigest !== t.artifactDigest) return { outcome: 'unresolved', reason: 'the evidence was produced against another artifact' };
  if (c.policyDigest && t.policyDigest && c.policyDigest !== t.policyDigest) return { outcome: 'unresolved', reason: 'the evidence was produced under another policy' };
  if (c.scannerBundle && packet.scanner?.bundleDigest && c.scannerBundle !== packet.scanner.bundleDigest) return { outcome: 'unresolved', reason: 'the evidence came from another scanner bundle' };
  if (c.requiresArtifactBinding !== false && !c.artifactDigest) return { outcome: 'unresolved', reason: 'the evidence is not bound to an artifact' };
  const o = c.observed;
  if (!o || typeof o !== 'object') return { outcome: 'unresolved', reason: 'no observation is recorded' };
  // the observation and the expectation stay separately inspectable; met/violated is derived, not asserted
  if (c.kind === 'detection') {
    // a detection case judges the signal, not the effect: positive means the rule must fire, negative that it must stay quiet,
    // and an observation that does not say whether the rule fired leaves the case open
    if (typeof o.detected !== 'boolean') return { outcome: 'unresolved', reason: 'the observation does not record whether the detection fired' };
    if (c.expected === 'positive') return o.detected ? { outcome: 'met', reason: 'the detection fired on the reproduced effect' } : { outcome: 'violated', reason: 'the detection missed the reproduced effect' };
    return o.detected ? { outcome: 'violated', reason: 'the detection fired where it must not' } : { outcome: 'met', reason: 'the detection stayed quiet where it must' };
  }
  const forbidden = o.forbiddenEffect === true; const legit = o.legitimateEffect === true;
  if (c.expected === 'positive') return forbidden ? { outcome: 'met', reason: 'the vulnerable control reproduced the forbidden effect' } : { outcome: 'violated', reason: 'the vulnerable control did not reproduce the effect, so the fixture shows nothing' };
  if (c.expected === 'negative') return forbidden ? { outcome: 'violated', reason: 'the forbidden effect occurred on the fixed artifact' } : { outcome: 'met', reason: 'no forbidden effect' };
  return legit && !forbidden ? { outcome: 'met', reason: 'the legitimate operation succeeded' } : { outcome: 'violated', reason: 'the legitimate operation did not succeed' };
}

/**
 * Recompute every gate from the packet's evidence.
 * @param {object} packet
 * @param {{requiredGates?:string[], requiredCases?:string[], requiredTiers?:Object<string,string>, now?:number, maxFeedAgeMs?:number}} o
 * @returns {{status:'qualified'|'not-qualified', gates:object, cases:object[], blockers:object[], tiers:object}}
 */
export function evaluateCandidate(packet, { requiredGates = Object.keys(GATES), requiredCases = [], requiredTiers = {}, now = Date.now(), maxFeedAgeMs = 15 * 60 * 1000 } = {}) {
  const cases = (packet.cases || []).map((c) => ({ caseId: c.caseId ?? null, gate: c.gate ?? null, requirement: c.requirement ?? null, owner: c.owner ?? null, tier: c.tier ?? 'local', ...judgeCase(c, packet, now) }));
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
    const need = requiredTiers[g];
    const ofGate = cases.filter((c) => c.gate === g);
    // a case of another tier is reported, but it cannot meet a gate that names its tier
    const mine = need ? ofGate.filter((c) => c.tier === need) : ofGate;
    const rank = { violated: 3, blocked: 2, unresolved: 1, met: 0 };
    let worst = mine.reduce((w, c) => (rank[c.outcome] > rank[w] ? c.outcome : w), 'met');
    const reasons = mine.filter((c) => c.outcome !== 'met').map((c) => `${c.caseId}: ${c.reason}`);
    if (extra[g]) { if (rank[extra[g].outcome] > rank[worst]) worst = extra[g].outcome; reasons.push(extra[g].reason); }
    // no evidence is not a pass: a gate with no case and no gate-level evidence stays unresolved
    if (need && !mine.length) { worst = rank[worst] > rank.unresolved ? worst : 'unresolved'; reasons.push(`no ${need} evidence for this gate${ofGate.length ? ` (${ofGate.length} case(s) of another tier do not count)` : ''}`); }
    else if (!mine.length && !extra[g] && !(g === 'G-02' && packet.scope?.status === 'satisfied') && !(g === 'G-04' && packet.runner?.attested === true) && !(g === 'G-06' && ev?.status === 'measured')) { worst = 'unresolved'; reasons.push('no evidence for this gate'); }
    gates[g] = { name: GATES[g], outcome: worst, reasons };
    if (worst !== 'met') blockers.push({ gate: g, reason: reasons.join('; ') });
  }
  const tiers = { local: 0, staging: 0, independent: 0 };
  for (const c of cases) if (tiers[c.tier] !== undefined) tiers[c.tier]++;
  return { status: blockers.length ? 'not-qualified' : 'qualified', scope: packet.target ? { ...packet.target } : null, scannerBundle: packet.scanner?.bundleDigest ?? null, packetDigest: packetDigest(packet), gates, cases, blockers, tiers };
}

/**
 * Is a recorded decision still the decision for this target? A decision qualifies only the artifact, policy and scanner bundle it was
 * computed for and only until its earliest case expiry, so an upgrade or policy change invalidates it and a rollback is covered only by
 * the earlier artifact's own decision.
 * @param {object} decision  an `evaluateCandidate` result
 * @param {{artifactDigest?:string, policyDigest?:string, scannerBundle?:string}} target
 */
export function revalidateDecision(decision, target, { packet = null, now = Date.now() } = {}) {
  if (!decision || typeof decision !== 'object' || !decision.scope) return { valid: false, reason: 'no recorded decision scope' };
  if (decision.status !== 'qualified') return { valid: false, reason: 'the recorded decision did not qualify the candidate' };
  if (!target || !target.artifactDigest || decision.scope.artifactDigest !== target.artifactDigest) return { valid: false, reason: 'the artifact differs from the one the decision qualified' };
  if (decision.scope.policyDigest && decision.scope.policyDigest !== target.policyDigest) return { valid: false, reason: 'the deployment policy differs from the one the decision qualified' };
  if (decision.scannerBundle && target.scannerBundle && decision.scannerBundle !== target.scannerBundle) return { valid: false, reason: 'the scanner bundle differs from the one the decision qualified' };
  if (packet) {
    if (packetDigest(packet) !== decision.packetDigest) return { valid: false, reason: 'the packet is not the one the decision was computed from' };
    const soonest = Math.min(...(packet.cases || []).map((c) => Date.parse(c.expires)).filter(Number.isFinite));
    if (Number.isFinite(soonest) && !(soonest > now)) return { valid: false, reason: 'evidence the decision rests on has expired' };
  }
  return { valid: true, reason: 'the decision covers this artifact, policy and scanner bundle' };
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
