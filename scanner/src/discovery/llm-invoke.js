//
// Shared LLM endpoint caller. Both the hunter and the refutation panel need
// the same default endpoint caller when tests don't inject a mock. Two copies
// of a network call is one copy too many — if one path gets fixed and the
// other does not, the bug stays buried in one direction.
//

const DEFAULT_TIMEOUT_MS = 60000;

export async function defaultLlmInvoke(prompt, opts = {}) {
  const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  const res = await fetch(process.env.AGENTIC_SECURITY_LLM_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`llm endpoint returned ${res.status}`);
  const body = await res.json();
  return typeof body === 'string' ? body : (body?.text ?? JSON.stringify(body));
}

export function resolveLlmInvoke(opts = {}) {
  if (opts.llmInvoke) return opts.llmInvoke;
  if (!process.env.AGENTIC_SECURITY_LLM_ENDPOINT) return null;
  return (prompt) => defaultLlmInvoke(prompt, { timeoutMs: opts.timeoutMs });
}
