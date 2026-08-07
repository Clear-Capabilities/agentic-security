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
export async function proveFinding(finding, { timeoutMs = 10000, force, files } = {}) {
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
