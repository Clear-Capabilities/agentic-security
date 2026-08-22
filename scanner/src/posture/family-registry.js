// Producer registry (PRD F10.2) — which detector emits which finding family.
//
// WHY THIS EXISTS
// ---------------
// Compliance controls map to families (`family:sql-injection`). Answering "is
// this control backed by a real detector, and how good is that detector?"
// requires knowing the family vocabulary. Nothing could answer that:
//
//   - A textual search cannot. Detectors set `family` positionally
//     (`_shape(file, line, ruleId, vuln, fam, …)`) or from a rule table
//     (`family: rule.family`), so grepping `family:` misses them entirely. A
//     search-derived list was used once to declare four families "unevidenceable";
//     all four had producers, and 15 working controls were suppressed as a result.
//   - A corpus sweep cannot. It reports only what some fixture triggered — a
//     LOWER BOUND. `k8s-pod-security-privileged` was absent from a 116-root sweep
//     and present in a 331-root one; nothing about the engine changed.
//
// So the detector declares, in the file that emits: `export const EMITS = [...]`.
// Colocation is the point — the rule and its declaration are edited together, and
// the gate below catches the case where they are not.
//
// SCOPE, STATED HONESTLY
// ----------------------
// Registration is per-module and incremental. 287 detector modules exist; the
// ones listed here are registered so far, chosen because they set `family`
// positionally (invisible to every other method) and back compliance mappings.
//
// A module that is registered is held to COMPLETENESS: a scan producing a family
// it did not declare fails the gate. A module that is not registered is not
// silently passing — it is absent, and `test/family-registry.test.js` reports the
// undeclared remainder as a ratchet that must not grow. That is the difference
// between a gate that expands over time and one that gets switched off in week
// two for failing on day one.
import { EMITS as CLOUD_IAM } from '../sast/cloud-iam.js';
import { EMITS as CRYPTO_PROTOCOL } from '../sast/crypto-protocol.js';
import { EMITS as DAPP_FRONTEND } from '../sast/dapp-frontend.js';
import { EMITS as K8S_ADMISSION } from '../sast/k8s-admission.js';
import { EMITS as ML_SUPPLY_CHAIN } from '../sast/ml-supply-chain.js';
import { EMITS as WEB3_ADVANCED } from '../sast/web3-advanced.js';

// module path -> declared families. Path is the identity a human greps for.
export const REGISTERED = Object.freeze({
  'sast/cloud-iam.js': CLOUD_IAM,
  'sast/crypto-protocol.js': CRYPTO_PROTOCOL,
  'sast/dapp-frontend.js': DAPP_FRONTEND,
  'sast/k8s-admission.js': K8S_ADMISSION,
  'sast/ml-supply-chain.js': ML_SUPPLY_CHAIN,
  'sast/web3-advanced.js': WEB3_ADVANCED,
});

// The `parser` field each registered module stamps on its findings. This is how a
// finding is attributed back to its module at runtime.
//
// NOT every parser identifies a module: `REGEX` alone covers 80 distinct
// families, and `STRUCTURAL` covers 23. Those are shared labels, so a module
// using one cannot be registered for completeness until it stamps something
// specific. Only module-specific parsers appear here, and the gate checks
// attribution only for these.
export const PARSER_OF = Object.freeze({
  'sast/cloud-iam.js': 'CLOUD-IAM',
  'sast/crypto-protocol.js': 'CRYPTO-PROTO',
  'sast/dapp-frontend.js': 'DAPP-FRONTEND',
  'sast/k8s-admission.js': 'K8S-ADM',
  'sast/ml-supply-chain.js': 'ML-SUPPLY',
  'sast/web3-advanced.js': 'WEB3-ADV',
});

/** Every family any registered module declares. */
export function declaredFamilies() {
  const out = new Set();
  for (const list of Object.values(REGISTERED)) for (const f of list) out.add(f);
  return out;
}

/** Module paths declaring `family`, or [] if none does. */
export function producersOf(family) {
  return Object.entries(REGISTERED)
    .filter(([, list]) => list.includes(family))
    .map(([mod]) => mod);
}

/** The module registered for `parser`, or null when the parser is not module-specific. */
export function moduleForParser(parser) {
  const hit = Object.entries(PARSER_OF).find(([, p]) => p === parser);
  return hit ? hit[0] : null;
}

/**
 * Families a registered module emitted but never declared — the drift this whole
 * mechanism exists to catch. `findings` is any array carrying {family, parser}.
 */
export function undeclaredFrom(findings) {
  const out = new Map(); // module -> Set(family)
  for (const f of findings || []) {
    if (!f || !f.family || !f.parser) continue;
    const mod = moduleForParser(f.parser);
    if (!mod) continue;                       // parser is not module-specific
    if (REGISTERED[mod].includes(f.family)) continue;
    if (!out.has(mod)) out.set(mod, new Set());
    out.get(mod).add(f.family);
  }
  return out;
}
