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

export async function proveFinding(finding, { timeoutMs = 10000, force } = {}) {
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
