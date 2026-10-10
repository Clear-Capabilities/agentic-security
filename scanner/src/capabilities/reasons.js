// Policy reason codes (X-501.AC03). A decision carries a code from this closed
// table and the fixed sentence beside it, never text built from the request. The
// request (a path, an argument, a host) can carry attacker-chosen content, and a
// decision is logged, put in receipts and shown to a worker, so nothing from the
// request may reach the reason. The only request-derived field of a decision is
// `subject`, which is sanitized and length-capped (`sanitizeSubject`).
import { scrubSecretText } from './secrets.js';

export const REASONS = Object.freeze({
  allowed: 'the action is inside the declared capability scope',
  'no-grant': 'no capability of this kind is declared for the task',
  'binding-mismatch': 'the request is not bound to this task, repository revision and policy version',
  'unknown-action': 'the action kind is not recognized',
  'invalid-manifest': 'the capability manifest is invalid',
  'scope-expansion': 'the request would widen the capability scope granted by the parent task',
  'path-invalid': 'the path is not an absolute, well-formed path',
  'path-traversal': 'the path escapes the declared roots through parent-directory segments',
  'symlink-escape': 'the path resolves outside the declared roots through a symbolic link',
  'outside-roots': 'the path is outside every declared root',
  'protected-path': 'the path is protected from tasks (keys, sealed labels, evidence, credentials)',
  'executable-not-absolute': 'the executable must be an absolute path; names are not resolved through a search path',
  'executable-unresolvable': 'the executable does not exist or is not a regular executable file',
  'executable-in-writable-root': 'the executable lives in a writable root, so the task could replace it',
  'command-not-listed': 'the executable is not a declared command',
  'args-invalid': 'the argument list is not an array of plain strings within the size limits',
  'args-not-permitted': 'the arguments are not permitted for this declared command',
  'secret-in-argument': 'an argument contains secret material; arguments are visible to every process',
  'interpreter-blocked': 'the executable is a shell or language interpreter and is not declared as a scoped interpreter',
  'interpreter-args-unpinned': 'a scoped interpreter must be declared with its exact argument list',
  'host-invalid': 'the destination host is not a well-formed host name or address',
  'port-invalid': 'the destination port is not valid',
  'destination-not-declared': 'the destination is not a declared network destination',
  'port-not-declared': 'the destination host is declared but not on this port',
  'scheme-not-declared': 'the destination is declared but not for this scheme',
  'dns-private-address': 'the host name resolves to a loopback, private, link-local or metadata address that was not declared',
  'dns-changed': 'the host name resolves to addresses outside the pinned set',
  'payload-too-large': 'the outbound payload exceeds the mediated size limit',
  'payload-uninspectable': 'the outbound payload is binary and cannot be filtered for secrets',
  'tool-not-declared': 'the tool is not a declared tool action',
  'delegation-not-allowed': 'the task is not allowed to delegate',
  'delegation-depth': 'the delegation depth limit is reached',
  'resource-limit-exceeded': 'the request exceeds a declared resource limit',
  'tool-unclassified': 'the tool has no declared capability classification, so it cannot be checked and is refused',
  'identity-missing': 'no current task identity is bound to this server, so a mutating or externally communicating tool is refused',
  'identity-spoofed': 'the request names a task identity other than the one this server is bound to',
  'retry-limit': 'the same action was denied the permitted number of times in this policy version and stays blocked',
  'task-halted': 'the task reached its denial budget and is halted until an operator changes the policy',
});

export const REASON_CODES = Object.freeze(Object.keys(REASONS));

export function reasonText(code) {
  return Object.prototype.hasOwnProperty.call(REASONS, code) ? REASONS[code] : REASONS['unknown-action'];
}

/**
 * The one request-derived field of a decision. Control characters are removed,
 * secret-shaped material is redacted and the length is capped, so the field is
 * safe to log and to show to the worker that made the request.
 */
export function sanitizeSubject(value, max = 160) {
  let s = typeof value === 'string' ? value : JSON.stringify(value) ?? '';
  s = s.replace(/[\u0000-\u001f\u007f]/g, ' ');
  try { s = scrubSecretText(s).text; } catch { s = '[unprintable]'; }
  if (s.length > max) s = `${s.slice(0, max)}...`;
  return s || '(empty)';
}
