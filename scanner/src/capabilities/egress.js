// Manifest-aware egress decisions (X-501: manifests are consumed by the egress
// policy). A call to a declared model endpoint must satisfy BOTH the task's
// network grant and the operator's egress policy (egress/policy.js); either one
// denying is a denial, and the result names which one. No payload is involved,
// so the decision is as safe to log as any other.
import { decide } from './decide.js';
import { evaluateEgress } from '../egress/policy.js';

export function evaluateManifestEgress(bound, binding, egressCtx = {}) {
  let u;
  try { u = new URL(String(egressCtx.endpoint)); } catch { u = null; }
  if (!u) return Object.freeze({ allowed: false, by: 'capability-manifest', code: 'host-invalid' });
  const port = u.port ? Number(u.port) : (u.protocol === 'http:' ? 80 : 443);
  const scheme = u.protocol === 'http:' ? 'http' : 'https';
  const d = decide(bound, { kind: 'network', host: u.hostname, port, scheme }, { binding });
  if (d.decision !== 'allow') return Object.freeze({ allowed: false, by: 'capability-manifest', code: d.code });
  const e = evaluateEgress(egressCtx);
  if (!e.allowed) return Object.freeze({ allowed: false, by: 'egress-policy', code: 'egress-denied', policy: e });
  return Object.freeze({ allowed: true, by: null, code: 'allowed', policy: e });
}
