//
// Shared LLM endpoint caller. Both the hunter and the refutation panel need
// the same default endpoint caller when tests don't inject a mock. Two copies
// of a network call is one copy too many — if one path gets fixed and the
// other does not, the bug stays buried in one direction.
//

const DEFAULT_TIMEOUT_MS = 60000;

export async function defaultLlmInvoke(prompt, opts = {}) {
  const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  // The URL is the operator's own configured endpoint, read from an environment
  // variable they set. Reaching it is this module's entire purpose; no
  // request-controlled input exists anywhere on this path, and an operator who
  // can set this variable can already run code.
  // `opts.endpoint` lets the consensus caller target one specific provider.
  // Absent, it falls back to the single configured endpoint — so the ordinary
  // single-model path is byte-identical to what it was before consensus existed.
  const endpoint = opts.endpoint || process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  const res = await fetch(endpoint, { // agentic-security-ignore: CWE-918
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`llm endpoint returned ${res.status}`);
  const body = await res.json();
  return typeof body === 'string' ? body : (body?.text ?? JSON.stringify(body));
}

// --- PRD Phase 3 / C2: multi-model consensus --------------------------------
//
// One model's opinion is one model's opinion. Asking several INDEPENDENT
// endpoints the same question and keeping only what a majority agree on
// collapses the idiosyncratic failures of any single one — a model that
// hallucinates a sink, or that is simply having a bad day on a prompt shape.
//
// WHY IT LIVES HERE AND NOWHERE ELSE. Every LLM call in the discovery layer
// already funnels through `resolveLlmInvoke`. Consensus is therefore a property
// of the seam, not of the hunter or the panel, and adding a provider cannot
// require touching either.
//
// WHAT CONSENSUS DOES AND DOES NOT MEAN. It reduces variance. It does NOT make
// the answer true — three models can agree and all be wrong, which is precisely
// why the deterministic confirmation gate still runs afterwards and still sets
// severity. Consensus is a noise filter in front of the real check, never a
// replacement for it.
//
// A provider that errors is EXCLUDED from the vote, not counted as dissent —
// the same rule `disprove.js` applies to its voters, for the same reason: an
// outage must never look like disagreement.
// Internal: read by resolveLlmInvoke below. Exporting it with no external
// caller is shipped dead code by the dead-module guard's definition.
const DEFAULT_CONSENSUS_ENV = 'AGENTIC_SECURITY_LLM_ENDPOINTS';

/** Split a comma-separated endpoint list into distinct URLs. */
export function parseEndpoints(raw) {
  return String(raw || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .filter((v, i, a) => a.indexOf(v) === i); // duplicates would fake agreement
}

/**
 * Combine N responses into one, keeping the most common answer.
 *
 * Ties are resolved towards the FIRST endpoint listed, deterministically, rather
 * than arbitrarily — a caller ordering their endpoints by trust should get the
 * behaviour that ordering implies, and a random tie-break would make the whole
 * pipeline non-reproducible.
 */
export function consensusOf(responses) {
  const usable = (responses || []).filter(r => typeof r === 'string' && r.trim());
  if (usable.length === 0) return { value: null, agreement: 0, voters: 0 };
  const counts = new Map();
  for (const r of usable) counts.set(r, (counts.get(r) || 0) + 1);
  let best = usable[0];
  let bestCount = counts.get(best);
  for (const r of usable) {
    const c = counts.get(r);
    if (c > bestCount) { best = r; bestCount = c; }
  }
  return { value: best, agreement: bestCount / usable.length, voters: usable.length };
}

/**
 * An llmInvoke that queries several endpoints and returns the consensus answer.
 * Returns null when no endpoint answered — the callers already treat a null or
 * a throw as degradation, so an all-providers-down run degrades honestly.
 */
function makeConsensusInvoke(endpoints, { timeoutMs } = {}) {
  const list = parseEndpoints(endpoints);
  if (list.length === 0) return null;
  return async (prompt) => {
    const answers = await Promise.all(list.map(async (url) => {
      try { return await defaultLlmInvoke(prompt, { timeoutMs, endpoint: url }); }
      catch { return null; } // excluded from the vote, never counted as dissent
    }));
    const { value } = consensusOf(answers);
    if (value === null) throw new Error('no LLM endpoint answered');
    return value;
  };
}

export function resolveLlmInvoke(opts = {}) {
  // Precedence, most explicit first: an injected callback beats configuration,
  // and a multi-endpoint list beats a single endpoint. A caller who supplied
  // their own function must always get exactly that function.
  if (opts.llmInvoke) return opts.llmInvoke;

  const multi = opts.endpoints || process.env[DEFAULT_CONSENSUS_ENV];
  if (multi) {
    const consensus = makeConsensusInvoke(multi, { timeoutMs: opts.timeoutMs });
    if (consensus) return consensus;
  }

  if (!process.env.AGENTIC_SECURITY_LLM_ENDPOINT) return null;
  return (prompt) => defaultLlmInvoke(prompt, { timeoutMs: opts.timeoutMs });
}
