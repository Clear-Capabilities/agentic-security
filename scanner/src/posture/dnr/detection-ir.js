// Detection intermediate representation (PRD 7, requirement 1). One IR per confirmed finding; every rendered rule, every
// hunt and every validation is derived from it, so there is exactly one place where the claim "what the exploit looks like"
// is made.
//
// Evidence grounding (requirement 3) is enforced structurally:
//   * the IR is CLOSED-WORLD: `validateDetectionIR` refuses any key it does not list, and none of them can carry an attacker
//     address, a domain, a file hash or a user agent;
//   * every fact that came from somewhere records where (`facts[field] = {source, ref}`), and a fact with no source is not
//     put in the IR at all (it is `null`, and the limitation is stated);
//   * the confidence is computed from the evidence state, never asserted.
import { canonicalize, sha256 } from '../proof-fabric/reproducer.js';
import { stateRank } from '../proof-fabric/states.js';
import { PAYLOAD_CLASSES, classForCwe } from './payload-classes.js';
import { validateAttackFacts, HTTP_METHODS, PARAM_LOCATIONS } from './attack-facts.js';

const DETECTION_IR_SCHEMA = 'agentic-security/detection-ir';
const DETECTION_IR_VERSION = 1;

const IR_KEYS = Object.freeze(['schema', 'version', 'id', 'findingId', 'cwe', 'family', 'attackBehavior', 'endpoint', 'parameter', 'payloadClass', 'affectedOperation', 'processEffect', 'networkEffect', 'dbEffect', 'confidence', 'grounding', 'evidence', 'facts', 'limitations', 'digest']);
const GROUNDING = Object.freeze(['exploit-confirmed', 'reproduced', 'static-only']);

/** "POST /api/export" -> {method, path}; anything else -> null. A finding's own route text is a fact source like any other. */
export function parseRouteText(text) {
  const m = /^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/[A-Za-z0-9/_\-.:{}~%]{0,199})\s*$/.exec(String(text ?? ''));
  return m ? { method: m[1], path: m[2] } : null;
}

function groundingFor(proof) {
  const state = proof?.state ?? null;
  if (state && stateRank(state) >= stateRank('EXPLOIT_CONFIRMED')) return 'exploit-confirmed';
  if (state && stateRank(state) >= stateRank('REPRODUCED')) return 'reproduced';
  return 'static-only';
}

/**
 * Build the IR for one finding. Returns {ok:true, ir} or {ok:false, reason}.
 * A finding with no proof is refused unless `allowUnproven` is set, in which case the IR says so (`grounding: static-only`)
 * and carries a lower confidence. A finding with no recognisable payload class is refused: there is nothing to detect.
 */
export function buildDetectionIR({ finding, proof = null, allowUnproven = false } = {}) {
  if (!finding || typeof finding !== 'object') return { ok: false, reason: 'no finding' };
  const findingId = String(finding.stableId ?? finding.id ?? '');
  if (!findingId) return { ok: false, reason: 'the finding has no stable id' };
  const grounding = groundingFor(proof);
  if (grounding === 'static-only' && !allowUnproven) {
    return { ok: false, reason: `no exploit proof for ${findingId}: prove it first (triage exploit ${findingId} --prove), or pass --allow-unproven to build a lower-confidence detection from the static finding alone` };
  }
  const attack = proof?.reproducer?.attack ?? null;
  const attackErrs = validateAttackFacts(attack);
  if (attackErrs.length) return { ok: false, reason: `the reproducer's attack facts are invalid: ${attackErrs.join('; ')}` };

  const facts = {};
  const evidence = [];
  const limitations = [];
  if (finding.file) evidence.push({ kind: 'finding', ref: `${finding.file}:${finding.line ?? '?'}`, id: findingId });
  if (proof?.recordDigest) evidence.push({ kind: 'proof', ref: `proof:${proof.recordDigest}`, state: proof.state ?? null, oracle: proof.oracle ?? null });
  if (attack) evidence.push({ kind: 'reproducer', ref: `reproducer:${String(proof?.reproducer ? sha256(canonicalize(proof.reproducer)) : '').slice(0, 16)}` });

  // payload class: the reproducer's explicit statement wins, then the finding's CWE
  let payloadClass = null;
  if (attack?.payloadClass) { payloadClass = attack.payloadClass; facts.payloadClass = { source: 'reproducer', ref: 'attack.payloadClass' }; }
  else if (classForCwe(finding.cwe)) { payloadClass = classForCwe(finding.cwe); facts.payloadClass = { source: 'finding', ref: `cwe:${finding.cwe}` }; }
  if (!payloadClass) return { ok: false, reason: `no payload class describes ${finding.cwe || 'this finding'}; a detection would have to guess, and a guessed detection is not generated` };
  const def = PAYLOAD_CLASSES[payloadClass];

  // endpoint: the reproducer's facts, else the finding's own route text
  let endpoint = null;
  if (attack?.method && attack?.path) { endpoint = { method: attack.method, path: attack.path }; facts.endpoint = { source: 'reproducer', ref: 'attack.method+attack.path' }; }
  else {
    const fromFinding = parseRouteText(finding.route ?? finding.endpoint);
    if (fromFinding) { endpoint = fromFinding; facts.endpoint = { source: 'finding', ref: finding.route ? 'route' : 'endpoint' }; }
  }
  if (!endpoint) limitations.push('no endpoint is known for this finding, so no request-level rule is generated; only the payload class is described');

  let parameter = null;
  if (attack?.parameter) { parameter = { name: attack.parameter, location: attack.location }; facts.parameter = { source: 'reproducer', ref: 'attack.parameter' }; }
  else if (payloadClass !== 'auth-bypass') limitations.push('no vulnerable parameter is known, so the payload test is applied to every query and body value of the endpoint');

  let sink = null;
  if (attack?.sink) { sink = attack.sink; facts.sink = { source: 'reproducer', ref: 'attack.sink' }; }
  const affectedOperation = { sink, file: finding.file ? String(finding.file) : null, line: Number.isInteger(finding.line) ? finding.line : null };

  const confidence = Math.max(0.1, Math.min(0.95,
    (grounding === 'exploit-confirmed' ? 0.9 : grounding === 'reproduced' ? 0.7 : 0.4) - (endpoint ? 0 : 0.2) - (parameter || payloadClass === 'auth-bypass' ? 0 : 0.1)));
  if (grounding !== 'exploit-confirmed') limitations.push(grounding === 'reproduced' ? 'the exploit was reproduced but not independently confirmed' : 'the exploit was not executed; this detection rests on static analysis only');

  const ir = {
    schema: DETECTION_IR_SCHEMA, version: DETECTION_IR_VERSION,
    id: '', findingId,
    cwe: finding.cwe ? String(finding.cwe) : null,
    family: finding.family ? String(finding.family) : payloadClass,
    attackBehavior: def.behavior,
    endpoint, parameter, payloadClass, affectedOperation,
    processEffect: def.effects.process ?? 'none', networkEffect: def.effects.network ?? 'none', dbEffect: def.effects.db ?? 'none',
    confidence: Number(confidence.toFixed(2)), grounding, evidence, facts, limitations, digest: '',
  };
  ir.digest = sha256(canonicalize({ ...ir, id: '', digest: '' }));
  ir.id = `det-${ir.digest.slice(0, 12)}`;
  return { ok: true, ir };
}

/** Structural validation of an IR read back from disk or supplied by a caller. Returns a list of problems. */
export function validateDetectionIR(ir) {
  if (!ir || typeof ir !== 'object' || Array.isArray(ir)) return ['detection IR must be an object'];
  const errs = [];
  for (const k of Object.keys(ir)) if (!IR_KEYS.includes(k)) errs.push(`unknown IR field: ${k}`);
  if (ir.schema !== DETECTION_IR_SCHEMA || ir.version !== DETECTION_IR_VERSION) errs.push('unsupported schema or version');
  if (typeof ir.findingId !== 'string' || !ir.findingId) errs.push('findingId required');
  if (!PAYLOAD_CLASSES[ir.payloadClass]) errs.push(`unknown payload class: ${String(ir.payloadClass)}`);
  if (!GROUNDING.includes(ir.grounding)) errs.push('unknown grounding');
  if (ir.endpoint != null) {
    if (!HTTP_METHODS.includes(ir.endpoint.method) || typeof ir.endpoint.path !== 'string') errs.push('endpoint must be {method, path}');
    else if (validateAttackFacts({ method: ir.endpoint.method, path: ir.endpoint.path }).length) errs.push('endpoint path is not a plain URL path');
  }
  if (ir.parameter != null) {
    if (!PARAM_LOCATIONS.includes(ir.parameter.location) || typeof ir.parameter.name !== 'string') errs.push('parameter must be {name, location}');
    else if (validateAttackFacts({ parameter: ir.parameter.name, location: ir.parameter.location }).length) errs.push('parameter name is not a plain name');
  }
  if (typeof ir.confidence !== 'number' || ir.confidence < 0 || ir.confidence > 1) errs.push('confidence must be between 0 and 1');
  if (!Array.isArray(ir.evidence) || !Array.isArray(ir.limitations)) errs.push('evidence and limitations must be lists');
  if (ir.digest && ir.digest !== sha256(canonicalize({ ...ir, id: '', digest: '' }))) errs.push('digest does not match the content');
  return errs;
}
