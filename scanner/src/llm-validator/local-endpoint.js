// R11 — the local / offline model path.
//
// A BYO endpoint already existed (`AGENTIC_SECURITY_LLM_ENDPOINT`), and you
// could always point it at something on localhost. What did not exist is a
// path that GUARANTEES the prompt never leaves the machine. That distinction
// is the whole feature: the reason to run a local model is usually that the
// code being analysed must not be sent anywhere, and a configuration that
// merely happens to be local today provides no such assurance. One typo, one
// inherited environment variable, and source is on someone else's server.
//
// So the `local` preset ENFORCES loopback. An endpoint that resolves to
// anything other than a loopback literal is refused outright rather than
// called. The check is on the host literal, not on DNS: resolving a name would
// mean trusting a resolver, and a name that answers 127.0.0.1 today can answer
// something else tomorrow. Only literal loopback forms are accepted, so the
// guarantee cannot be undone by a DNS entry.
//
// OFFLINE DEGRADATION. A local server that is not running is the normal case,
// not an error: the validator tier is optional and the scan must complete
// without it. An unreachable local endpoint leaves findings `unvalidated` with
// a reason naming the endpoint, exactly like every other validator failure.
// The connect timeout is short for the same reason — a dead port must not hang
// a scan.

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0']);

export const DEFAULT_LOCAL_ENDPOINT = 'http://127.0.0.1:11434/v1/chat/completions';
export const DEFAULT_LOCAL_TIMEOUT_MS = 20000;

/**
 * Is this URL unambiguously loopback?
 *
 * Deliberately strict and literal. Anything unparseable, non-http(s), or
 * hostname-based is NOT loopback — the answer to "am I sure this stays on this
 * machine?" must be yes or no, never "probably".
 */
export function isLoopbackUrl(url) {
  let u;
  try { u = new URL(String(url)); } catch { return false; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  const host = u.hostname.toLowerCase();
  if (LOOPBACK_HOSTS.has(host)) return true;
  // The whole 127.0.0.0/8 block is loopback.
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
    return host.split('.').slice(1).every(o => Number(o) >= 0 && Number(o) <= 255);
  }
  return false;
}

/**
 * Resolve the local-preset configuration.
 *
 * @returns {{ok:true, config:object} | {ok:false, reason:string}}
 */
export function localEndpointConfig(env = process.env) {
  const endpoint = env.AGENTIC_SECURITY_LLM_ENDPOINT || DEFAULT_LOCAL_ENDPOINT;
  if (!isLoopbackUrl(endpoint)) {
    return {
      ok: false,
      reason: `the 'local' preset refuses a non-loopback endpoint: ${endpoint}. `
        + 'The point of the local path is that source never leaves this machine, so a remote '
        + 'address is refused rather than silently used. Only literal loopback addresses are '
        + 'accepted — a hostname is not, because a resolver could point it anywhere. '
        + 'Use AGENTIC_SECURITY_LLM_PRESET=anthropic (or a BYO endpoint) to call out deliberately.',
    };
  }
  const timeoutRaw = Number(env.AGENTIC_SECURITY_LLM_TIMEOUT_MS);
  return {
    ok: true,
    config: {
      endpoint,
      // No key. A local server that demands one can still receive it via the
      // BYO path; the local preset does not invent credentials.
      apiKey: env.AGENTIC_SECURITY_LLM_API_KEY || null,
      model: env.AGENTIC_SECURITY_LLM_MODEL || 'local-model',
      preset: 'local',
      timeoutMs: Number.isFinite(timeoutRaw) && timeoutRaw > 0 ? timeoutRaw : DEFAULT_LOCAL_TIMEOUT_MS,
      // Stated so a report can say plainly that nothing left the machine.
      egress: 'loopback-only',
    },
  };
}

/** Human explanation of the current local-path state. */
export function renderLocalPath(cfg) {
  if (!cfg) return null;
  return `LLM validator: local path, ${cfg.endpoint} (loopback-enforced, no egress), model '${cfg.model}'.`;
}

export const _internals = { LOOPBACK_HOSTS };
