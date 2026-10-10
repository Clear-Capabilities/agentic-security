'use strict';
// Capability advice for PreToolUse hooks (X-505.AC01). Advisory only: it writes a
// line explaining what the capability policy decides, and it never blocks. The
// runner enforces; a hook explains.
//
// Inert unless the OPERATOR turned the feature on in the environment
// (AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT=1) AND named a manifest file
// (AGENTIC_SECURITY_CAPABILITY_MANIFEST). When either is missing it returns null
// before touching the scanner, so existing hook behaviour is unchanged.
const fs = require('fs');
const path = require('path');

const MAX_MANIFEST_BYTES = 256 * 1024;

function operatorGate(env) {
  const on = /^(1|true)$/i.test(String(env.AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT || ''));
  return on && !!env.AGENTIC_SECURITY_CAPABILITY_MANIFEST;
}

async function loadFacility() {
  const attempts = [
    () => import('@clear-capabilities/agentic-security-scanner/capabilities/index.js'),
    () => import('file://' + path.resolve(__dirname, '..', '..', 'scanner', 'src', 'capabilities', 'index.js')),
  ];
  for (const a of attempts) { try { return await a(); } catch { /* try the next layout */ } }
  return null;
}

/** @returns {Promise<string[]|null>} advisory lines, or null when the hook has nothing to say */
async function capabilityAdvice(evt, env = process.env) {
  if (!operatorGate(env)) return null;
  try {
    const caps = await loadFacility();
    if (!caps) return null;
    if (!caps.featureEnabledByOperator(env)) return null; // kill switches and invalid config end here
    const file = env.AGENTIC_SECURITY_CAPABILITY_MANIFEST;
    // One descriptor for the size check and the read: a stat on the path followed by a second open of the path could be raced.
    let text;
    const fd = fs.openSync(file, 'r');
    try {
      const st = fs.fstatSync(fd);
      if (!st.isFile() || st.size > MAX_MANIFEST_BYTES) return ['agentic-security capability advisory: the manifest file is not usable; no advice given'];
      text = fs.readFileSync(fd, 'utf8');
    } finally { fs.closeSync(fd); }
    const bound = caps.bindManifest(JSON.parse(text));
    if (!bound.ok) return ['agentic-security capability advisory: the manifest is invalid; no advice given'];
    const b = bound.bound.binding;
    // The identity the session claims. An unset claim is the manifest's own.
    const claim = {
      taskId: env.AGENTIC_SECURITY_CAPABILITY_TASK_ID || b.taskId,
      revision: b.revision,
      policyVersion: env.AGENTIC_SECURITY_CAPABILITY_POLICY_VERSION ? Number(env.AGENTIC_SECURITY_CAPABILITY_POLICY_VERSION) : b.policyVersion,
    };
    const adv = caps.adviseToolUse(bound.bound, evt, { binding: claim });
    return adv && adv.lines.length ? adv.lines : null;
  } catch {
    return null; // a hook never fails a tool use because advice could not be computed
  }
}

module.exports = { capabilityAdvice, operatorGate };
