// R4 — determinism as a contract.
//
// Determinism has been an implementation property of this engine (stable sorts,
// no Date.now() in ids, `--deterministic`) with no way for a third party to
// VERIFY it. This module turns it into something checkable: a stable digest
// over the finding set, bound to the engine version, ruleset version, and
// bundle hash that produced it.
//
// WHAT THE DIGEST IS INDEPENDENT OF (by construction):
//   - the ORDER findings were emitted in (entries are canonicalised, then sorted)
//   - run ids, timestamps, durations, and every other field not on the
//     identity allowlist below — canonicalisation is an ALLOWLIST, not a
//     denylist, so a new non-deterministic field cannot silently leak in
//   - path separator style, and the absolute prefix when `root` is supplied
//
// WHAT IT IS NOT INDEPENDENT OF (all of these are real differences):
//   - a changed severity, file, line, rule id, cwe, or vuln title
//   - a finding appearing or disappearing (including a duplicate — multiplicity
//     is preserved; two identical findings are not collapsed into one)
//   - the engine version, ruleset version, or bundle sha
//
// WHAT THIS PROVES, AND WHAT IT DOES NOT (read before quoting it at anyone):
//   PROVES — two finding sets carrying the same digest under the same
//   canonicalisation are the same set of findings, modulo emission order and
//   the excluded volatile fields; and (when signed) that the attestation was
//   produced on an install holding this HMAC key.
//   DOES NOT PROVE — cross-machine reproducibility. Nothing here demonstrates
//   that a different host, OS, Node version, or toolchain produces the same
//   finding set; several detectors are environment-sensitive (e.g. the Python
//   AST path is used when python3 is available and falls back to regex when it
//   is not, which can change what is found). Two runs on two machines agreeing
//   would be evidence FOR reproducibility, but that experiment has not been
//   run here and this module does not assert its outcome. The signature is a
//   symmetric per-install HMAC, so it is tamper-evidence for the operator, not
//   third-party non-repudiation.
//
// Identity fields deliberately EXCLUDE `parser` and `family`: `parser` records
// which analysis engine fired, which is environment-sensitive (see the python3
// case above), so including it would make the digest report an environment
// difference as a findings difference. The finding's identity — where it is
// and what it is — is fully captured without it.
//
// SIGNING: reuses `integrity.js`'s per-install HMAC key handling verbatim
// (`signLastScan`, keyed from $AGENTIC_SECURITY_HMAC_KEY or the 0600 key file
// at $XDG_CONFIG_HOME/agentic-security/scan-key). No second key mechanism is
// introduced. `integrity.verifyLastScan` is NOT reused because it verifies a
// body against a sibling `.sig` FILE; an attestation carries its signature
// inline, so verification re-signs and compares in constant time here.
//
// NO THROWING (posture/CLAUDE.md convention): malformed input yields an empty
// canonical set or an `{ok:false, reason}` refusal, never an exception.

import * as crypto from 'node:crypto';
import { signLastScan } from './integrity.js';

export const ATTESTATION_CANONICALISATION = 'agentic-security/run-attestation-canon-v1';

const PROVES =
  'Two finding sets with this digest, under this canonicalisation, are the same findings ' +
  '(same rule id, severity, file, line, cwe, vuln, and multiplicity) produced by the same ' +
  'engine version, ruleset version, and bundle — regardless of emission order.';
const DOES_NOT_PROVE =
  'It does not prove cross-machine reproducibility: this attestation is one run on one machine, ' +
  'nothing here compares a second machine, OS, or Node version, and some detectors are ' +
  'environment-sensitive. That property is tested separately by the determinism-attest / ' +
  'determinism-compare CI jobs, which run the same commit on two operating systems and fail ' +
  'unless the digests match — evidence about the ENGINE, not about this attestation. ' +
  'A signature, when present, is a symmetric per-install HMAC — tamper-evidence for this ' +
  'install, not third-party non-repudiation.';

function _str(v) { return v === undefined || v === null ? '' : String(v); }

// Normalise a file path: separators to '/', drop a supplied absolute root,
// drop a leading './'. Everything else is left alone — guessing at a root we
// were not given would make two genuinely different files collide.
function _normPath(file, root) {
  let p = _str(file).replace(/\\/g, '/');
  if (root) {
    let r = String(root).replace(/\\/g, '/').replace(/\/+$/, '');
    if (r && p.startsWith(r + '/')) p = p.slice(r.length + 1);
    else if (r && p === r) p = '';
  }
  return p.replace(/^\.\//, '');
}

/**
 * The canonical, order-independent representation of a finding set: one
 * tab-joined record per finding over the identity allowlist, sorted.
 * Multiplicity is preserved (duplicates are NOT deduped).
 */
function canonicaliseFindings(findings, { root } = {}) {
  const list = Array.isArray(findings) ? findings : [];
  const rows = [];
  for (const f of list) {
    if (!f || typeof f !== 'object') continue;
    rows.push([
      _str(f.id),
      _str(f.severity),
      _normPath(f.file, root),
      _str(f.line),
      _str(f.cwe),
      _str(f.vuln),
    ].join('\t'));
  }
  return rows.sort();
}

/**
 * Compute the run attestation.
 *
 * @param {object[]} findings     the finding set (any order)
 * @param {string}   engineVersion
 * @param {string}   rulesetVersion
 * @param {string}   bundleSha
 * @param {string}  [root]        scan root, used to relativise absolute paths
 * @param {boolean} [sign]        attach a per-install HMAC over the digest
 */
export function computeRunAttestation({
  findings, engineVersion, rulesetVersion, bundleSha, root, sign = false,
} = {}) {
  const entries = canonicaliseFindings(findings, { root });
  const payload = JSON.stringify({
    canonicalisation: ATTESTATION_CANONICALISATION,
    engineVersion: _str(engineVersion),
    rulesetVersion: _str(rulesetVersion),
    bundleSha: _str(bundleSha),
    findingCount: entries.length,
    entries,
  });
  const digest = crypto.createHash('sha256').update(payload).digest('hex');
  const att = {
    digest,
    algorithm: 'sha256',
    findingCount: entries.length,
    engineVersion: _str(engineVersion),
    rulesetVersion: _str(rulesetVersion),
    bundleSha: _str(bundleSha),
    canonicalisation: ATTESTATION_CANONICALISATION,
    proves: PROVES,
    doesNotProve: DOES_NOT_PROVE,
  };
  if (sign) {
    try {
      att.signature = signLastScan(digest);
      att.signatureScope = 'per-install-hmac';
    } catch { /* signing is best-effort; an unsigned attestation is still valid */ }
  }
  return att;
}

/**
 * Re-derive the attestation from a finding set and compare.
 * @returns {{ok: boolean, reason: string}}
 */
export function verifyRunAttestation(attestation, inputs = {}) {
  if (!attestation || typeof attestation !== 'object') {
    return { ok: false, reason: 'no attestation supplied' };
  }
  if (attestation.canonicalisation !== ATTESTATION_CANONICALISATION) {
    return {
      ok: false,
      reason: `unknown canonicalisation "${_str(attestation.canonicalisation)}" — ` +
              `this build verifies "${ATTESTATION_CANONICALISATION}" only`,
    };
  }
  if (typeof attestation.digest !== 'string' || !/^[0-9a-f]{64}$/.test(attestation.digest)) {
    return { ok: false, reason: 'attestation carries no sha256 digest' };
  }
  for (const k of ['engineVersion', 'rulesetVersion', 'bundleSha']) {
    if (_str(inputs[k]) !== _str(attestation[k])) {
      return { ok: false, reason: `${k} mismatch: attested "${_str(attestation[k])}", got "${_str(inputs[k])}"` };
    }
  }
  const recomputed = computeRunAttestation({
    findings: inputs.findings,
    engineVersion: inputs.engineVersion,
    rulesetVersion: inputs.rulesetVersion,
    bundleSha: inputs.bundleSha,
    root: inputs.root,
  });
  if (recomputed.findingCount !== attestation.findingCount) {
    return {
      ok: false,
      reason: `finding count mismatch: attested ${attestation.findingCount}, got ${recomputed.findingCount}`,
    };
  }
  if (recomputed.digest !== attestation.digest) {
    return { ok: false, reason: 'digest mismatch — the finding set is not the one attested' };
  }
  if (attestation.signature) {
    let expected;
    try { expected = signLastScan(attestation.digest); }
    catch { return { ok: false, reason: 'signature present but no key material available to check it' }; }
    const a = Buffer.from(String(attestation.signature), 'hex');
    const b = Buffer.from(expected, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { ok: false, reason: 'signature does not verify under this install key' };
    }
    return { ok: true, reason: 'digest and per-install signature verify' };
  }
  return { ok: true, reason: 'digest verifies (unsigned attestation)' };
}
