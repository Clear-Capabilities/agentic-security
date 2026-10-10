// One secret scrubber for the capability layer: provider-shaped credentials
// (mcp/redact.js, which is the list the scanner's own detector mirrors), then
// assignment, bearer, connection-string and high-entropy-literal shapes
// (llm-validator/redact.js). Pure. The count is of replacements made, so a
// caller can ask "did this text carry a secret" without keeping the secret.
import { redactSecretShapes } from '../mcp/redact.js';
import { redactSecrets } from '../llm-validator/redact.js';

/**
 * True when the text carries a provider-shaped credential or a quoted credential
 * assignment. The high-entropy-literal heuristic is deliberately NOT used here:
 * an argument list is mostly paths and scripts, and refusing every long quoted
 * path would make the policy unusable. Scrubbing for output and logs (below) is
 * allowed to be broader than refusing an argument.
 */
export function detectSecretShapes(text) {
  return typeof text === 'string' && redactSecretShapes(text).redactions > 0;
}

export function scrubSecretText(text) {
  if (typeof text !== 'string' || !text) return { text: typeof text === 'string' ? text : '', redactions: 0 };
  const a = redactSecretShapes(text);
  let b;
  try { b = redactSecrets(a.text); } catch { return { text: '[unprintable]', redactions: a.redactions + 1 }; }
  return { text: b.text, redactions: a.redactions + b.redactions };
}
