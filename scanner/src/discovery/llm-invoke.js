//
// Shared LLM endpoint caller. Both the hunter and the refutation panel need
// the same default endpoint caller when tests don't inject a mock. Two copies
// of a network call is one copy too many — if one path gets fixed and the
// other does not, the bug stays buried in one direction.
//

export async function defaultLlmInvoke(prompt) {
  const res = await fetch(process.env.AGENTIC_SECURITY_LLM_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
  if (!res.ok) throw new Error(`llm endpoint returned ${res.status}`);
  const body = await res.json();
  return typeof body === 'string' ? body : (body?.text ?? JSON.stringify(body));
}

export function resolveLlmInvoke(opts = {}) {
  return opts.llmInvoke
    || (process.env.AGENTIC_SECURITY_LLM_ENDPOINT ? defaultLlmInvoke : null);
}
