// Operator control over adaptive routing (X-608.AC03): adaptive (default), pinned to one model, or disabled.
//
// Precedence, highest first: explicit options (a CLI flag), then the environment (`AGENTIC_SECURITY_ROUTING`), then the default.
// Values: `adaptive`, `disabled` (the existing capability route, untouched), `pin:<model>` (that model, no optimisation).
// An unreadable value FAILS CLOSED to `disabled` and says so; it never falls through to adaptive.
//
// A pin chooses a model. It does not clear the egress policy: sending a prompt still goes through the guarded adapter, which checks
// the egress policy at call time. `routeModelWithPolicy` (model-routing.js) honours this control.

export const ROUTING_MODES = Object.freeze(['adaptive', 'pinned', 'disabled']);
export const ROUTING_ENV = 'AGENTIC_SECURITY_ROUTING';
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;

function parse(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  const v = String(raw).trim();
  if (v === 'adaptive') return { mode: 'adaptive', pin: null };
  if (v === 'disabled' || v === 'off') return { mode: 'disabled', pin: null };
  if (v.startsWith('pin:')) {
    const model = v.slice(4);
    return MODEL_ID.test(model) ? { mode: 'pinned', pin: model } : { error: `'${v}' does not name a valid model id` };
  }
  return { error: `'${v}' is not one of adaptive, disabled, pin:<model>` };
}

export function resolveRoutingControl({ env = process.env, options = {} } = {}) {
  const candidates = [['option', options?.routing], ['environment', env?.[ROUTING_ENV]]];
  for (const [source, raw] of candidates) {
    const p = parse(raw);
    if (!p) continue;
    if (p.error) return Object.freeze({ mode: 'disabled', pin: null, source, error: p.error, reason: `invalid routing control (${p.error}); adaptive routing is off` });
    return Object.freeze({ ...p, source, error: null, reason: p.mode === 'adaptive' ? 'adaptive routing selected' : p.mode === 'pinned' ? `routing pinned to ${p.pin}` : 'adaptive routing disabled by the operator' });
  }
  return Object.freeze({ mode: 'adaptive', pin: null, source: 'default', error: null, reason: 'default' });
}
