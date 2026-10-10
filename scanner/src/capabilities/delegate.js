// Delegation under the capability policy (X-505.AC02).
//
// A task that hands work to another agent gives it a CHILD manifest, and a child
// can only be a subset of its parent. `delegate` is the one door:
//
//   1. the parent's own manifest must allow delegation at all, and the delegation
//      depth is read from the manifest chain (every hop must carry a strictly
//      lower `maxDepth`), never from a depth the requester claims
//   2. the request is derived through `deriveChild`: any widening of roots,
//      commands, destinations, tools, limits, delegation, revision or policy
//      version is `SCOPE_EXPANSION` and yields NO manifest (no partial grant)
//   3. tool names are compared exactly, so an alias (another case, a prefix, a
//      namespaced spelling) is a different, undeclared tool and is refused
//   4. a child task id is issued once: asking again with the same id is
//      idempotent when the request is identical and refused when it differs, so
//      a retry with changed instructions cannot swap in a wider grant
//
// What a child is told in prose does not matter to any of this: the manifest is
// derived once, frozen, and bound to the child's own task id, revision, policy
// version and digest.
import { bindManifest, deriveChild } from './manifest.js';
import { mediate } from './recovery.js';
import { reasonText } from './reasons.js';
import { digestOf } from '../posture/assurance/identity.js';

/** Remembers which child ids were issued for which manifest digest. Held by the delegating controller. */
export function createDelegationRegistry() {
  const issued = new Map();
  return Object.freeze({
    get: (id) => issued.get(id) ?? null,
    set: (id, digest) => { issued.set(id, digest); },
    size: () => issued.size,
  });
}

function refuse(code, base) {
  return Object.freeze({
    ok: false, status: 'blocked', code, reason: reasonText(code), child: null, errors: [],
    decision: base?.decision ?? null, proposal: base?.proposal ?? null, missing: base?.missing ?? null,
    attemptsRemaining: base?.attemptsRemaining ?? null,
  });
}

/**
 * @param {{manifest: object, binding: object}} parent   the delegating task's bound manifest
 * @param {object} request     manifest-shaped, `taskId` required (see `deriveChild`)
 * @param {object} o
 * @param {{taskId:string,revision:string,policyVersion:number}} o.binding  identity the caller acts for
 * @param {object} [o.registry]  from `createDelegationRegistry`
 * @param {object} [o.guard]     denial guard (recovery.js)
 */
export function delegate(parent, request, { binding, registry, guard } = {}) {
  // Depth comes from the manifest chain; the request cannot claim a shallower one.
  const m = mediate(parent, { kind: 'delegation', depth: 0, request }, { binding }, { guard });
  if (m.status !== 'ok') return refuse(m.decision.code, m);
  const derived = deriveChild(parent.manifest, request);
  if (!derived.ok) return Object.freeze({ ...refuse('scope-expansion', m), errors: derived.errors.map((e) => ({ code: e.code, path: e.path })) });
  const bound = bindManifest(derived.manifest);
  if (!bound.ok) return Object.freeze({ ...refuse('invalid-manifest', m), errors: bound.errors.map((e) => ({ code: e.code, path: e.path })) });
  if (registry) {
    const prior = registry.get(bound.bound.binding.taskId);
    if (prior !== null && prior !== bound.bound.binding.digest) return refuse('scope-expansion', m);
    registry.set(bound.bound.binding.taskId, bound.bound.binding.digest);
  }
  return Object.freeze({
    ok: true, status: 'ok', code: null, reason: null, errors: [], decision: m.decision,
    child: bound.bound, parentTaskId: parent.binding.taskId, requestDigest: digestOf(request),
  });
}
