// Promote a finding to execution-proven by running its proof-of-concept inside
// the confined execution sandbox and observing a real effect.
//
// Proof is a file the PoC writes, NOT an exit code: the sandbox cannot reliably
// distinguish "denied" from "ran and exited 0", so exit status is not evidence.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runConfined, sandboxAvailable, detectBackend } from '../sandbox/index.js';
import { attachProofTier, proofTierOf } from './proof-tier.js';

const PROOF_MARKER = 'PROVEN';

function _evidence(over = {}) {
  return {
    tier: 'taint-proven', backend: detectBackend(), ran: false, observed: null,
    reason: null, exitCode: null, timedOut: false, at: new Date().toISOString(), ...over,
  };
}

// A run that never got as far as executing the PoC. `ran:false` for these is
// the whole point: 'proof-failed' asserts "the PoC ran and the predicted effect
// did not appear", which is a triage signal about the FINDING. A sandbox that
// could not start says nothing about the finding at all, and must leave it at
// its static tier rather than manufacturing a failed exploit attempt.
const _DID_NOT_EXECUTE = new Set(['disabled', 'error']);

// Materialise caller-supplied files into the sandbox root so a PoC can import
// the code it is supposed to exploit. Paths are confined to the root: an
// absolute path or one that climbs out is refused rather than clamped, because
// silently rewriting a path would put a file somewhere the caller did not ask
// for and the PoC would then exercise the wrong code.
function _materialise(root, files) {
  for (const [rel, content] of Object.entries(files || {})) {
    if (typeof content !== 'string') continue;
    const abs = path.resolve(root, rel);
    if (abs !== root && !abs.startsWith(root + path.sep)) {
      return `refusing to write '${rel}': it resolves outside the sandbox root`;
    }
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf8');
  }
  return null;
}

/**
 * @param {object} finding    carries `poc: {lang, code}`
 * @param {object} [opts]
 * @param {object} [opts.files]  rel→content written into the sandbox root before
 *   the PoC runs. This is what lets the SAME PoC be run against a candidate
 *   patch: pass the patched contents and a still-`execution-proven` verdict
 *   means the fix did not close the hole.
 */
// How long a proof-of-concept gets to write its marker.
//
// WHY THIS IS GENEROUS, AND WHY THAT IS NEARLY FREE. The budget is only ever
// spent when a PoC is stuck: a working one writes its marker and exits in about
// a second, so raising the ceiling costs nothing in the common path. What a
// tight ceiling DOES cost is correctness — the budget covers spawning a
// confined process and starting a Node runtime inside it, and on a loaded
// machine that alone can eat several seconds. At 10s this timed out under
// ordinary parallel test load and reported "re-verification did not execute",
// which the release gate then surfaced as a failure. The measurement has to be
// of the proof-of-concept, not of how busy the machine happened to be.
//
// A timeout is still never evidence about the finding: `proven` is decided by
// the marker file, and a timed-out run falls back to the finding's static tier
// rather than claiming `proof-failed`. This ceiling only decides how long we
// wait before giving up, not what we conclude.
//
// Override on a slow or heavily-loaded runner, matching the convention used by
// AGENTIC_SECURITY_PY_PROBE_TIMEOUT_MS and AGENTIC_SECURITY_DEEP_TIMEOUT_MS.
export const DEFAULT_PROOF_TIMEOUT_MS =
  Number(process.env.AGENTIC_SECURITY_PROOF_TIMEOUT_MS) > 0
    ? Number(process.env.AGENTIC_SECURITY_PROOF_TIMEOUT_MS)
    : 45000;

export async function proveFinding(finding, { timeoutMs = DEFAULT_PROOF_TIMEOUT_MS, force, files } = {}) {
  const poc = finding?.poc;
  if (!poc?.code) {
    return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: 'no proof-of-concept attached' }));
  }
  if (poc.lang !== 'js') {
    return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: `unsupported poc language: ${poc.lang}` }));
  }
  if (!sandboxAvailable()) {
    return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: 'no confinement primitive available; refusing to execute' }));
  }

  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'proof-')));
  try {
    const badPath = _materialise(root, files);
    if (badPath) {
      return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: badPath }));
    }
    fs.writeFileSync(path.join(root, 'poc.mjs'), poc.code, 'utf8');
    const r = runConfined([process.execPath, 'poc.mjs'], { root, timeoutMs, force });
    const proven = fs.existsSync(path.join(root, PROOF_MARKER));
    const ran = !r.timedOut && !_DID_NOT_EXECUTE.has(r.status);

    return attachProofTier(finding, _evidence({
      tier: proven ? 'execution-proven' : ran ? 'proof-failed' : proofTierOf(finding),
      backend: r.backend,
      ran,
      observed: proven ? `proof marker '${PROOF_MARKER}' written by the proof-of-concept` : null,
      reason: proven ? null
        : r.status === 'error' ? `the confinement sandbox could not start, so the proof-of-concept never executed (${r.backend} backend): ${String(r.stderr || '').trim() || 'no detail reported'}`
        : r.status === 'disabled' ? 'confined execution is disabled; the proof-of-concept was refused and never executed'
        : r.timedOut ? 'proof-of-concept exceeded its time budget'
        : 'proof-of-concept ran but did not demonstrate the predicted effect',
      exitCode: r.exitCode, timedOut: r.timedOut,
    }));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
