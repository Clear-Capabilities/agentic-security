// Producer registry (assurance-hardening PRD, Milestone 1, FR-101).
//
// engine.js's core ~90 SAST/SCA/secrets detectors are called synchronously
// inside one large per-file loop and are NOT converted to registry entries
// by this change — that is a much larger, separate undertaking (every one
// of those call sites would need to change shape) and is explicitly out of
// scope here. What this registry DOES cover: the "late producers" that
// append findings AFTER the main per-file loop and AFTER the primary
// enrichment chain has already run once — cross-language taint (5
// boundary types), IaC-reachability, IAM-policy, container-runtime,
// business-logic-v2, specification-drift, concurrency, and privacy-taint.
// These are exactly the producers the PRD's A-03 evidence cites (findings
// that bypass stableId/confidence/calibration because they arrive after
// engine.js's enrichment chain already finished). See
// pipeline/producer-collector.js for how registration is enforced at the
// point findings are actually collected, and pipeline/enrichment-completion.js
// for how any finding that still lacks the standard fields (regardless of
// producer) gets them before the collection is frozen.

const KNOWN_PHASES = Object.freeze(['sast', 'sca', 'secrets', 'cross-language', 'business-logic', 'privacy']);

const _registry = new Map();

/**
 * @param {object} def
 * @param {string} def.id - unique producer id
 * @param {string} def.version - producer version string (semver-ish, not enforced)
 * @param {string} def.phase - one of KNOWN_PHASES
 * @param {string[]} [def.languages] - languages this producer applies to, or [] for language-agnostic
 * @param {string[]} [def.dependsOn] - ids of producers that must be registered (and are logically upstream)
 * @throws on duplicate id, unknown phase, or a dependency cycle
 */
export function registerProducer(def) {
  if (!def || typeof def !== 'object') throw new Error('registerProducer: definition required');
  const { id, version, phase, languages = [], dependsOn = [] } = def;
  if (typeof id !== 'string' || !id) throw new Error('registerProducer: id required');
  if (_registry.has(id)) throw new Error(`registerProducer: duplicate producer id "${id}"`);
  if (typeof version !== 'string' || !version) throw new Error(`registerProducer: "${id}" missing version`);
  if (!KNOWN_PHASES.includes(phase)) {
    throw new Error(`registerProducer: "${id}" has unknown phase "${phase}" — must be one of ${KNOWN_PHASES.join(', ')}`);
  }
  if (!Array.isArray(dependsOn)) throw new Error(`registerProducer: "${id}" dependsOn must be an array`);

  _registry.set(id, { id, version, phase, languages: [...languages], dependsOn: [...dependsOn] });
  const cycle = _findCycle();
  if (cycle) {
    _registry.delete(id); // don't leave the registry in a broken state
    throw new Error(`registerProducer: dependency cycle detected: ${cycle.join(' -> ')}`);
  }
}

/** Topological cycle check over the current registry. Returns the cycle path, or null. */
function _findCycle() {
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map([..._registry.keys()].map(id => [id, WHITE]));
  const path = [];
  function visit(id) {
    color.set(id, GRAY);
    path.push(id);
    const def = _registry.get(id);
    for (const dep of def?.dependsOn || []) {
      if (!_registry.has(dep)) continue; // an unregistered dependency is reported separately, not a cycle
      const c = color.get(dep);
      if (c === GRAY) return [...path.slice(path.indexOf(dep)), dep];
      if (c === WHITE) {
        const found = visit(dep);
        if (found) return found;
      }
    }
    path.pop();
    color.set(id, BLACK);
    return null;
  }
  for (const id of _registry.keys()) {
    if (color.get(id) === WHITE) {
      const found = visit(id);
      if (found) return found;
    }
  }
  return null;
}

export function isRegisteredProducer(id) {
  return _registry.has(id);
}

export function getProducer(id) {
  return _registry.get(id) || null;
}

export function listProducers() {
  return [..._registry.values()];
}

/** Every dependsOn id must itself be a registered producer. For tests/CI, not called at runtime. */
export function validateNoUnregisteredDependencies() {
  const missing = [];
  for (const def of _registry.values()) {
    for (const dep of def.dependsOn) {
      if (!_registry.has(dep)) missing.push(`${def.id} depends on unregistered producer "${dep}"`);
    }
  }
  return missing;
}

// Test-only: reset the module-level registry between test files/cases.
// Never called from production code paths.
export function _resetForTests() {
  _registry.clear();
}

export const KNOWN_PHASES_FOR_TESTS = KNOWN_PHASES;
