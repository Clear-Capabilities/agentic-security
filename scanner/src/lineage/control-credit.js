//
// control-credit.js: which controls protect which witness, and which do not (DAG-04, R04.5 / R04.6).
//
// A control earns credit on a witness only when ALL of these hold, each recorded as evidence:
//   * the sanitizer's catalog family matches the SINK family (an HTML encoder does not protect SQL);
//   * the value that reaches the sink is the value the control produced: the control's call sits ON the
//     witness (an edge at its node), its result is what the witness carries, and every later read of the
//     controlled variable sees exactly that definition (reassignment or a merge with another definition
//     voids the credit: stale credit is refused);
//   * nothing later on the same witness reverses it (decoders keyed by family, from sanitizer-gate.js).
//
// What this does NOT establish: that the sanitizer is correct. The family comes from the sanitizer
// catalog, and dominance (a control on every path) is evidence about coverage, never proof of sanitizer
// semantics. Every credit says so (`semanticsProof: false`). An unrecognized call that widened the value
// (an opaque call) makes the witness `unknown`, not `unprotected` and never `protected`.
//
// Control state per witness: 'protected' | 'unprotected' | 'unknown'. `assessAllPathsProtectedWithControls`
// feeds the real states into witness-selection.js `assessAllPathsProtected`, whose rules are unchanged:
// it looks at every enumerated path, refuses on a truncated or resumed query, and one unprotected path
// refutes the claim. An optional independent abstract proof (`abstractControlProof`) can license the claim
// when enumeration was truncated, because it does not depend on which paths were enumerated.

import { CATALOG } from '../dataflow/catalog.js';
import { accessPathOf } from '../dataflow/access-paths.js';
import { familyOfFinding, _reversedOnPath } from '../dataflow/sanitizer-gate.js';
import { computeDominators } from '../ir/ssa.js';
import { computeReachingDefinitions } from './value-versions.js';
import { exprRoots, walkExpr } from './source-seeding.js';
import { assessAllPathsProtected } from './witness-selection.js';
import { recognizeTransformation } from './transform-catalog.js';

export const CONTROL_CREDIT_VERSION = 'control-credit/1';

const CREDIT_LIMITATIONS = Object.freeze([
  'Sanitizer semantics come from the catalog family; correctness of the sanitizer itself is not proven.',
  'Dominance or presence on the path is coverage evidence, not proof that the control neutralizes the sink.',
  'Controls are matched by callee name; a project-local wrapper is an opaque call.',
]);

let _index = null;
/** callee -> list of family sets, one per catalog entry (kept apart so name ambiguity is detectable). */
function sanitizerIndex() {
  if (_index) return _index;
  _index = new Map();
  for (const e of CATALOG) {
    if (!e || e.kind !== 'sanitizer' || e.match?.type !== 'call' || !e.match.callee) continue;
    const fams = Array.isArray(e.appliesTo) ? e.appliesTo : [];
    if (!_index.has(e.match.callee)) _index.set(e.match.callee, []);
    _index.get(e.match.callee).push(new Set(fams));
  }
  return _index;
}

function dotted(callee) {
  if (typeof callee === 'string') return callee;
  if (!callee) return null;
  if (callee.kind === 'ident') return callee.name;
  if (callee.kind === 'member') { const o = dotted(callee.object); return o ? `${o}.${callee.prop}` : callee.prop; }
  return null;
}

/** Names a call may be known by, most specific first. */
export function calleeNames(callee) {
  const full = dotted(callee);
  if (!full) return [];
  const bare = full.split('.').pop();
  return bare === full ? [full] : [full, bare];
}

/**
 * The families a callee neutralizes: { known, families:Set, ambiguous }. `ambiguous` means the callee name
 * is shared by catalog entries that disagree on families (a bare `escape`), so it cannot be credited.
 */
export function controlFamiliesOf(callee) {
  const idx = sanitizerIndex();
  for (const nm of calleeNames(callee)) {
    const sets = idx.get(nm);
    if (!sets) continue;
    const key = (s) => [...s].sort().join(',');
    const distinct = new Set(sets.map(key));
    if (distinct.size > 1) return { known: true, name: nm, families: new Set(sets.flatMap((s) => [...s])), ambiguous: true };
    return { known: true, name: nm, families: new Set(sets[0]), ambiguous: false };
  }
  return { known: false, name: null, families: new Set(), ambiguous: false };
}

/** The sink family for a catalog sink entry (`{ vuln: { cwe, name } }`) or a finding-shaped object. */
export function sinkFamilyOf(x) {
  if (!x) return null;
  const v = x.vuln && typeof x.vuln === 'object' ? x.vuln : x;
  return familyOfFinding({ cwe: v.cwe ?? x.cwe, vuln: typeof v.name === 'string' ? v.name : (typeof x.vuln === 'string' ? x.vuln : ''), family: x.family });
}

function callsAt(node) {
  const calls = [];
  if (!node) return calls;
  for (const root of exprRoots(node)) walkExpr(root, (e) => { if (e.kind === 'call') calls.push(e); });
  if (node.kind === 'call' && node.callee) calls.unshift({ kind: 'call', callee: node.callee, args: node.args ?? [] });
  return calls;
}

const covers = (a, b) => typeof a === 'string' && typeof b === 'string' && (a === b || a.startsWith(`${b}.`) || b.startsWith(`${a}.`));

function argReadsPath(call, fromPath) {
  if (!fromPath) return false;
  let hit = false;
  for (const a of call.args ?? []) {
    walkExpr(a, (e) => { if (!hit && (e.kind === 'ident' || e.kind === 'member')) { const p = e.kind === 'ident' ? e.name : accessPathOf(e); if (covers(p, fromPath)) hit = true; } });
  }
  return hit;
}

const _rdCache = new WeakMap();
function rdOf(fn) {
  const cfg = fn?.cfg;
  if (!cfg) return null;
  let rd = _rdCache.get(cfg);
  if (!rd) { rd = computeReachingDefinitions({ cfg: { entry: cfg.entry, nodes: cfg.nodes }, params: fn.params ?? [] }); _rdCache.set(cfg, rd); }
  return rd;
}

function isWidened(h) {
  return (h.widenReasons ?? []).includes('unresolved-call') || (h.annotations ?? []).some((a) => a.widenReason === 'unresolved-call');
}

/**
 * Judge one witness.
 *
 * @param {object} o
 * @param {object[]} o.hops           `path.hops`, source first
 * @param {(id:string)=>object|null} o.nodeOf  store.getNode (to read each hop's from/to access paths)
 * @param {(qid:string)=>object|null} o.fnOf   IR function lookup
 * @param {string|null} o.sinkFamily  the family of the sink (see sinkFamilyOf), null when unknown
 * @param {boolean} [o.truncated]     the path is incomplete or analysis was cut short
 */
export function creditPath({ hops, nodeOf, fnOf, sinkFamily = null, truncated = false } = {}) {
  const list = Array.isArray(hops) ? hops : [];
  const credits = []; const rejected = []; const opaque = [];
  const pathOf = (id) => nodeOf?.(id)?.path ?? null;

  for (let i = 0; i < list.length; i++) {
    const h = list[i];
    const fn = fnOf?.(h.scope);
    const node = fn?.cfg?.nodes?.[h.siteNodeId];
    if (!node) continue;
    const fromPath = pathOf(h.fromNodeId);
    const calls = callsAt(node);
    let recognizedHere = false;

    for (const c of calls) {
      const fam = controlFamiliesOf(c.callee);
      if (!fam.known) continue;
      recognizedHere = true;
      const where = { edgeId: h.edgeId ?? null, scope: h.scope, nodeId: h.siteNodeId, callee: fam.name, families: [...fam.families].sort() };
      if (!argReadsPath(c, fromPath)) { rejected.push({ ...where, reason: 'value-not-through-control' }); continue; }
      // The control's result must be what the witness carries.
      const viaAssign = node.kind === 'assign' && node.source === c && typeof node.target === 'string';
      const viaSinkArg = node.kind === 'call' && (node.args ?? []).includes(c);
      if (!viaAssign && !viaSinkArg) { rejected.push({ ...where, reason: 'result-not-carried' }); continue; }
      if (fam.ambiguous) { rejected.push({ ...where, reason: 'ambiguous-callee-family' }); opaque.push({ ...where, reason: 'ambiguous-callee-family' }); continue; }
      if (!sinkFamily) { rejected.push({ ...where, reason: 'sink-family-unknown' }); opaque.push({ ...where, reason: 'sink-family-unknown' }); continue; }
      if (!fam.families.has(sinkFamily) && !fam.families.has('*')) { rejected.push({ ...where, reason: 'wrong-family', sinkFamily }); continue; }

      // Value version: later reads of the controlled variable must see exactly this definition.
      let versionOk = true; let versionReason = null;
      if (viaAssign) {
        const T = node.target;
        for (let j = i + 1; j < list.length; j++) {
          const hj = list[j];
          if (hj.scope !== h.scope) continue;
          const fj = pathOf(hj.fromNodeId);
          if (!covers(fj, T)) continue;
          const rd = rdOf(fnOf(hj.scope));
          const vers = rd ? rd.versionsAt(hj.siteNodeId, T) : [];
          if (!vers.includes(h.siteNodeId)) { versionOk = false; versionReason = 'stale-control-version'; break; }
          if (vers.length > 1) { versionOk = false; versionReason = 'merged-with-other-definition'; break; }
        }
      }
      if (!versionOk) { rejected.push({ ...where, reason: versionReason }); if (versionReason === 'merged-with-other-definition') opaque.push({ ...where, reason: versionReason }); continue; }

      // Reversal later on the same witness voids the credit.
      let reversedBy = null;
      for (let j = i + 1; j < list.length && !reversedBy; j++) {
        const nj = fnOf?.(list[j].scope)?.cfg?.nodes?.[list[j].siteNodeId];
        for (const cj of callsAt(nj)) {
          const hit = _reversedOnPath(calleeNames(cj.callee), sinkFamily);
          if (hit) { reversedBy = hit; break; }
        }
      }
      if (reversedBy) { rejected.push({ ...where, reason: `reversed:${reversedBy}` }); continue; }

      credits.push({
        ...where, sinkFamily, valueVersion: viaAssign ? h.siteNodeId : 'at-sink-argument',
        basis: ['catalog-family', 'on-witness', 'value-version'], semanticsProof: false,
      });
    }

    // A parameterized query is the SQL-specific control that is not a call to a sanitizer: the value enters as a
    // bound parameter and never as query text. Credited only for the sql sink family.
    if (sinkFamily === 'sql' && isParameterizedSqlCall(node, fromPath)) {
      credits.push({
        edgeId: h.edgeId ?? null, scope: h.scope, nodeId: h.siteNodeId, callee: 'parameterized-query', families: ['sql'], sinkFamily,
        valueVersion: 'bound-parameter', basis: ['placeholder-binding', 'on-witness'], semanticsProof: false,
      });
    }

    // An unrecognized call that widened the value could be a control; the witness cannot be called unprotected.
    if (!recognizedHere && isWidened(h)) {
      const names = calls.map((c) => dotted(c.callee)).filter(Boolean);
      // A known decoder is not opaque: it is a recognized reversal (and is judged as such above).
      const known = calls.length > 0 && calls.every((c) => controlFamiliesOf(c.callee).known
        || recognizeTransformation(callDescriptor(c.callee))
        || (sinkFamily && _reversedOnPath(calleeNames(c.callee), sinkFamily)));
      if (!known) opaque.push({ edgeId: h.edgeId ?? null, scope: h.scope, nodeId: h.siteNodeId, callees: names, reason: 'opaque-call' });
    }
  }

  let controlState;
  const reasons = [];
  if (credits.length) { controlState = 'protected'; reasons.push('matching-control-on-witness'); }
  else if (opaque.length) { controlState = 'unknown'; reasons.push(...new Set(opaque.map((o) => o.reason))); }
  else if (truncated) { controlState = 'unknown'; reasons.push('witness-incomplete'); }
  else { controlState = 'unprotected'; reasons.push(rejected.length ? [...new Set(rejected.map((r) => r.reason))].sort().join(',') : 'no-control-on-witness'); }
  return {
    version: CONTROL_CREDIT_VERSION, controlState, reasons,
    credits, rejected, opaque, sinkFamily, limitations: [...CREDIT_LIMITATIONS],
  };
}

const PLACEHOLDER_RE = /(\?|\$\d+|:[A-Za-z_]\w*|%s|@[A-Za-z_]\w*)/;

/** `db.query('... WHERE id = ?', [value])`: a literal query text with placeholders, the witness value only in later arguments. */
export function isParameterizedSqlCall(node, fromPath) {
  if (!node || node.kind !== 'call') return false;
  const args = node.args ?? [];
  const text = args[0];
  if (args.length < 2 || !text || text.kind !== 'literal' || typeof text.value !== 'string' || !PLACEHOLDER_RE.test(text.value)) return false;
  return argReadsPath({ args: args.slice(1) }, fromPath);
}

function callDescriptor(callee) {
  if (typeof callee === 'string') return { type: 'call', callee };
  if (!callee) return null;
  if (callee.kind === 'ident') return { type: 'call', callee: callee.name };
  if (callee.kind === 'member' && callee.object?.kind === 'ident') return { type: 'member-call', object: callee.object.name, method: callee.prop };
  if (callee.kind === 'member') return { type: 'call', callee: callee.prop };
  return null;
}

/**
 * An independent, intraprocedural abstract proof that a matching control covers EVERY path to a sink
 * argument: a control assignment dominates the sink node and is the only definition of the variable that
 * reaches it. It does not depend on which witnesses were enumerated. It is still evidence about coverage:
 * the control's correctness comes from the catalog family.
 */
export function abstractControlProof(fn, { sinkNodeId, variable, sinkFamily }) {
  const cfg = fn?.cfg;
  if (!cfg || !sinkFamily || !variable) return { proved: false, reason: 'insufficient-input', semanticsProof: false };
  const nodes = cfg.nodes instanceof Map ? Object.fromEntries(cfg.nodes) : cfg.nodes;
  if (!nodes[sinkNodeId]) return { proved: false, reason: 'unknown-sink-node', semanticsProof: false };
  const dom = computeDominators({ entry: cfg.entry, nodes });
  const rd = rdOf(fn);
  const vers = rd.versionsAt(sinkNodeId, variable);
  if (vers.length !== 1) return { proved: false, reason: 'multiple-reaching-definitions', semanticsProof: false };
  const defId = vers[0];
  const def = nodes[defId];
  if (!def || def.kind !== 'assign' || !dom.get(sinkNodeId)?.has(defId)) return { proved: false, reason: 'definition-does-not-dominate-sink', semanticsProof: false };
  const call = def.source?.kind === 'call' ? def.source : null;
  const fam = call ? controlFamiliesOf(call.callee) : null;
  if (!fam?.known || fam.ambiguous) return { proved: false, reason: 'definition-is-not-a-recognized-control', semanticsProof: false };
  if (!fam.families.has(sinkFamily) && !fam.families.has('*')) return { proved: false, reason: 'wrong-family', semanticsProof: false };
  return {
    proved: true, controlNodeId: defId, callee: fam.name, sinkFamily, basis: ['dominance', 'single-reaching-definition', 'catalog-family'],
    semanticsProof: false, limitations: [...CREDIT_LIMITATIONS, 'Intraprocedural: other functions that reach the same sink are not covered by this proof.'],
  };
}

/**
 * "Every path is protected", answered from real control states (R04.6).
 *
 * @param {object} o
 * @param {object} o.result       the reconstructPaths result
 * @param {object[]} o.enumerated every enumerated path (not just the displayed ones), with `.hops`
 * @param {Map<string,object>|((p:object)=>object)} o.evidenceOf per-path { controlState, feasibility? }
 * @param {object} [o.proof]      abstractControlProof result, an independent licence for the claim
 *
 * Paths whose feasibility is `infeasible-under-model` are excluded from the relevant set and LISTED, so the
 * claim is explicitly scoped to the modeled feasible paths. unknown, unsupported and timeout paths stay
 * relevant: they cannot be dismissed. The claim never rests on the displayed sample.
 */
export function assessAllPathsProtectedWithControls({ result, enumerated, evidenceOf, proof = null }) {
  const get = (p) => (typeof evidenceOf === 'function' ? evidenceOf(p) : evidenceOf?.get?.(p.id)) ?? null;
  const all = Array.isArray(enumerated) ? enumerated : [];
  const excludedInfeasible = []; const relevant = [];
  for (const p of all) {
    const ev = get(p);
    if (ev?.feasibility?.status === 'infeasible-under-model') excludedInfeasible.push({ pathId: p.id, contradiction: ev.feasibility.contradiction ?? null });
    else relevant.push(p);
  }
  const attrsOf = (p) => ({ controlState: get(p)?.controlState ?? 'unknown' });
  const base = assessAllPathsProtected({ result, enumerated: relevant, attrsOf });
  const out = {
    ...base, semanticsVersion: CONTROL_CREDIT_VERSION, claimScope: 'modeled-feasible-paths',
    relevantPathCount: relevant.length, excludedInfeasible, basis: 'enumeration', abstractProof: proof ?? null,
  };
  if (base.holds === false) return out;
  // Enumeration could not establish the claim (truncated, resumed, or unknown states). An independent abstract
  // proof can, because it does not depend on which paths were enumerated. A refutation above always wins.
  if (!base.allowed && proof?.proved) {
    return { ...out, allowed: true, holds: true, basis: 'abstract-proof', reasons: base.reasons.filter((r) => r !== 'refuted-by-unprotected-path'), proofCovers: 'every path to the sink argument within the function' };
  }
  return out;
}
