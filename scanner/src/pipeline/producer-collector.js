// Producer collector (assurance-hardening PRD, Milestone 1, FR-102).
//
// The one place a "late producer" (see producer-registry.js's header for
// exactly which ones — the cross-language/business-logic/privacy group
// A-03 evidenced) is allowed to append to the shared finding array. Before
// this, each of these ~12 call sites in engine.js did its own
// `try { ...; if (x?.length) finalFindings.push(...x); } catch(_) {}` —
// functionally fine for not crashing the scan, but each one silently
// swallowed a producer exception with no diagnostic (a producer could be
// broken for months and nothing would ever say so) and there was no single
// place enforcing "only a REGISTERED producer may append here."
//
// This does not change engine.js's ~90 core SAST/SCA/secrets detector call
// sites (see producer-registry.js's header for why that is out of scope).

import { isRegisteredProducer } from './producer-registry.js';

/**
 * @param {object[]} finalFindings - mutated in place (push only)
 * @param {Array<{phase:string, err:string}>} diagnostics - mutated in place (push only), same
 *   shape as engine.js's _annotatorErrors so both surfaces read as one list
 * @param {string} producerId - MUST be registered via producer-registry.js's registerProducer()
 * @param {() => (Array|{findings:Array}|null|undefined)} thunk - runs the actual producer;
 *   may return a bare findings array (matches every one of these producers' current shape) or
 *   an object with a .findings array (forward-compatible with a future AnalyzerResult shape)
 * @returns {{status:'completed'|'failed'|'unregistered', count:number}}
 */
export function collectProducerResult(finalFindings, diagnostics, producerId, thunk) {
  if (!isRegisteredProducer(producerId)) {
    const msg = `producer "${producerId}" is not registered — refusing to collect its output`;
    diagnostics.push({ phase: `producer:${producerId}`, err: msg });
    return { status: 'unregistered', count: 0 };
  }
  let result;
  try {
    result = thunk();
  } catch (e) {
    diagnostics.push({ phase: `producer:${producerId}`, err: String((e && e.message) || e) });
    return { status: 'failed', count: 0 };
  }
  const findings = Array.isArray(result) ? result : (Array.isArray(result?.findings) ? result.findings : null);
  if (!findings || !findings.length) return { status: 'completed', count: 0 };
  for (const f of findings) {
    if (f && typeof f === 'object' && f.producerId === undefined) f.producerId = producerId;
  }
  finalFindings.push(...findings);
  return { status: 'completed', count: findings.length };
}
